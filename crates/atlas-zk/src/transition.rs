//! Nativer L2-State-Übergang + Witness-Erzeugung (Phase 1).
//!
//! Dies ist die **Referenzimplementierung**, gegen die der `StateTransitionCircuit`
//! bit-genau erzwungen wird. Pro Transaktion wird der Zustand sequenziell
//! angewendet (zuerst Sender debitieren, dann Empfänger kreditieren) und dabei
//! die komplette Zeugenmenge aufgezeichnet: Pre-/Post-Konten, Authentifizierungs-
//! pfade und die Zwischen-Wurzeln (`root_before → root_mid → root_after`).
//!
//! Der Circuit erzwingt später pro TX:
//!   1. Inklusion des Sender-Blatts unter `root_before`
//!   2. balance_sender ≥ amount + fee  und  tx_nonce == nonce_sender
//!   3. Sender-Update (−(amount+fee), nonce+1) ⇒ `root_mid`
//!   4. Inklusion des Empfänger-Blatts unter `root_mid`
//!      (leer ⇒ Insertion, sonst Update)
//!   5. Empfänger-Update (+amount) ⇒ `root_after`
//!   6. Verkettung: `root_after[i] == root_before[i+1]`, Σ fee == total_fees

use ark_bn254::Fr;
use ark_ec::AffineRepr;
use ark_ed_on_bn254::{EdwardsAffine, Fr as EdFr};
use ark_ff::Zero;
use thiserror::Error;

use crate::account::{Account, AccountTree};
use crate::eddsa::{verify, EddsaKeypair, EddsaPublicKey, EddsaSignature};
use crate::merkle::MerklePath;
use crate::poseidon::hash_many;

/// Die im Circuit (und nativ) signierte Nachricht einer L2-Transaktion:
/// `m = Poseidon(from, to, amount, fee, nonce)`. Bit-genau identisch zur
/// In-Circuit-Berechnung in `state_circuit`.
pub fn tx_message(from: Fr, to: Fr, amount: u128, fee: u128, nonce: u64) -> Fr {
    hash_many(&[from, to, Fr::from(amount), Fr::from(fee), Fr::from(nonce)])
}

/// Native L2-Transaktion (entkoppelt von atlas-core: Adressen als `Fr`).
///
/// Trägt den Baby-Jubjub-Public-Key und die EdDSA-Signatur des Senders. Beide
/// fließen als private Witnesses in den `StateTransitionCircuit` und werden dort
/// erzwungen (`S·B == R + c·A` plus Bindung `from == lower160(Poseidon(A))`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct L2Tx {
    pub from:   Fr,
    pub to:     Fr,
    pub amount: u128,
    pub fee:    u128,
    pub nonce:  u64,
    pub pubkey: EddsaPublicKey,
    pub sig:    EddsaSignature,
}

impl L2Tx {
    /// Baut eine signierte Transaktion: `from` wird an `kp` gebunden
    /// (`from = address_fr(A)`), die Nachricht `Poseidon(from,to,amount,fee,nonce)`
    /// signiert.
    pub fn signed(to: Fr, amount: u128, fee: u128, nonce: u64, kp: &EddsaKeypair) -> Self {
        let from = kp.public().address_fr();
        let m = tx_message(from, to, amount, fee, nonce);
        let sig = kp.sign(m);
        L2Tx { from, to, amount, fee, nonce, pubkey: kp.public(), sig }
    }
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum TransitionError {
    #[error("Sender-Konto existiert nicht")]
    UnknownSender,
    #[error("Selbstüberweisung nicht erlaubt (from == to)")]
    SelfTransfer,
    #[error("unzureichender Saldo: brauche {needed}, habe {have}")]
    InsufficientBalance { needed: u128, have: u128 },
    #[error("falsche Nonce: erwartet {expected}, erhalten {got}")]
    BadNonce { expected: u64, got: u64 },
    #[error("Betrags-Overflow")]
    Overflow,
    #[error("Adresse nicht an Public Key gebunden (from != address(A))")]
    AddressMismatch,
    #[error("ungültige EdDSA-Signatur")]
    SignatureInvalid,
}

/// Zeuge für EINE Transaktion (real oder Padding).
#[derive(Clone, Debug)]
pub struct TxWitness {
    pub is_padding: bool,

    // Transaktionsdaten (vom Circuit in `batch_commitment` gebunden).
    pub from:     Fr,
    pub to:       Fr,
    pub amount:   u128,
    pub fee:      u128,
    pub tx_nonce: u64,

    // EdDSA-Authentifizierung (private Witnesses; Circuit erzwingt
    // `S·B == R + c·A` und `from == lower160(Poseidon(A))`).
    pub pubkey: EddsaPublicKey,
    pub sig:    EddsaSignature,

    // Sender-Zweig (Inklusion gegen `root_before`).
    pub sender_index:   u64,
    pub sender_balance: u128, // pre
    pub sender_nonce:   u64,  // pre
    pub sender_path:    MerklePath,

    // Empfänger-Zweig (Inklusion gegen `root_mid`).
    pub receiver_is_new: bool,
    pub receiver_index:   u64,
    pub receiver_balance: u128, // pre (0 falls neu)
    pub receiver_nonce:   u64,  // pre (0 falls neu)
    pub receiver_path:    MerklePath,

    // Verkettete Wurzeln.
    pub root_before: Fr,
    pub root_mid:    Fr,
    pub root_after:  Fr,
}

impl TxWitness {
    /// Padding-Zeuge: vollständiger No-Op am aktuellen `root`.
    ///
    /// pubkey/R sind der (gültige) Generator und S=0 — der EdDSA-Constraint ist
    /// für Padding-Slots ohnehin konditional abgeschaltet (`enforce=false`), aber
    /// die Kurvenpunkte müssen on-curve sein, damit die `EdwardsVar`-Allokation
    /// nicht selbst scheitert.
    pub fn padding(root: Fr, empty_path: MerklePath) -> Self {
        let dummy_pt = EdwardsAffine::generator();
        TxWitness {
            is_padding: true,
            from: Fr::zero(), to: Fr::zero(), amount: 0, fee: 0, tx_nonce: 0,
            pubkey: EddsaPublicKey(dummy_pt),
            sig: EddsaSignature { r: dummy_pt, s: EdFr::zero() },
            sender_index: 0, sender_balance: 0, sender_nonce: 0,
            sender_path: empty_path.clone(),
            receiver_is_new: false, receiver_index: 0, receiver_balance: 0, receiver_nonce: 0,
            receiver_path: empty_path,
            root_before: root, root_mid: root, root_after: root,
        }
    }
}

/// Zeuge für einen ganzen Batch.
#[derive(Clone, Debug)]
pub struct BatchWitness {
    pub pre_root:   Fr,
    pub post_root:  Fr,
    pub total_fees: u128,
    pub txs:        Vec<TxWitness>,
}

/// Wendet einen Batch nativ auf `tree` an und zeichnet die Zeugen auf.
///
/// Gibt `Err` zurück, sobald eine TX ungültig ist (der Aufrufer/Aggregator muss
/// nur gültige TXs einreichen — Signaturen werden auf nativer Ebene außerhalb
/// dieses Moduls geprüft; siehe Phasen-Plan, v1 = native Signaturprüfung).
pub fn apply_batch(tree: &mut AccountTree, txs: &[L2Tx]) -> Result<BatchWitness, TransitionError> {
    let pre_root = tree.root();
    let mut total_fees: u128 = 0;
    let mut witnesses = Vec::with_capacity(txs.len());

    for tx in txs {
        if tx.from == tx.to {
            return Err(TransitionError::SelfTransfer);
        }

        // ── Authentifizierung (bit-genau zum Circuit) ───────────────────────
        // 1. Adresse an den Public Key binden: from == lower160(Poseidon(A)).
        if tx.from != tx.pubkey.address_fr() {
            return Err(TransitionError::AddressMismatch);
        }
        // 2. EdDSA-Signatur über m = Poseidon(from,to,amount,fee,nonce).
        let m = tx_message(tx.from, tx.to, tx.amount, tx.fee, tx.nonce);
        if !verify(&tx.pubkey, m, &tx.sig) {
            return Err(TransitionError::SignatureInvalid);
        }

        // ── Sender laden & prüfen ────────────────────────────────────────────
        let sender_index = tree.index_of(tx.from).ok_or(TransitionError::UnknownSender)?;
        let sender = tree.account_at(sender_index).expect("Index ohne Konto");
        let debit = tx.amount.checked_add(tx.fee).ok_or(TransitionError::Overflow)?;
        if sender.balance < debit {
            return Err(TransitionError::InsufficientBalance { needed: debit, have: sender.balance });
        }
        if sender.nonce != tx.nonce {
            return Err(TransitionError::BadNonce { expected: sender.nonce, got: tx.nonce });
        }

        let root_before = tree.root();
        let sender_path = tree.path(sender_index);
        let sender_balance_pre = sender.balance;
        let sender_nonce_pre = sender.nonce;

        // ── Sender debitieren ⇒ root_mid ────────────────────────────────────
        let sender_post = Account::new(tx.from, sender.balance - debit, sender.nonce + 1);
        tree.write(sender_index, sender_post);
        let root_mid = tree.root();

        // ── Empfänger laden (ggf. neu) & prüfen ─────────────────────────────
        let receiver_is_new = tree.index_of(tx.to).is_none();
        let receiver_index = tree.ensure(tx.to); // legt bei Bedarf {to,0,0} an
        let receiver = tree.account_at(receiver_index).expect("Index ohne Konto");
        let receiver_balance_pre = receiver.balance;
        let receiver_nonce_pre = receiver.nonce;
        let receiver_path = tree.path(receiver_index);

        // ── Empfänger kreditieren ⇒ root_after ──────────────────────────────
        let new_balance = receiver.balance.checked_add(tx.amount).ok_or(TransitionError::Overflow)?;
        let receiver_post = Account::new(tx.to, new_balance, receiver.nonce);
        tree.write(receiver_index, receiver_post);
        let root_after = tree.root();

        total_fees = total_fees.checked_add(tx.fee).ok_or(TransitionError::Overflow)?;

        witnesses.push(TxWitness {
            is_padding: false,
            from: tx.from, to: tx.to, amount: tx.amount, fee: tx.fee, tx_nonce: tx.nonce,
            pubkey: tx.pubkey, sig: tx.sig,
            sender_index, sender_balance: sender_balance_pre, sender_nonce: sender_nonce_pre, sender_path,
            receiver_is_new, receiver_index,
            receiver_balance: receiver_balance_pre, receiver_nonce: receiver_nonce_pre, receiver_path,
            root_before, root_mid, root_after,
        });
    }

    Ok(BatchWitness {
        pre_root,
        post_root: tree.root(),
        total_fees,
        txs: witnesses,
    })
}

/// Spielt eine Settled-Batch-Calldata OHNE Signaturprüfung ab (Signaturen sind
/// NICHT Teil der Calldata und wurden beim Settlen bereits verifiziert). Führt
/// bit-genau dieselbe Bilanz-/Nonce-Mutation aus wie `apply_batch`, nur ohne die
/// beiden Auth-Checks (Adress-Bindung + EdDSA) und ohne Zeugen-Aufzeichnung.
///
/// Zweck: Aggregator-Resync aus der On-Chain-Calldata (Data Availability) — der
/// Aggregator hält keinen eigenen Persistenz-Layer, sondern rekonstruiert seinen
/// `L2State` beim Start aus den vom Node gelieferten Settled-Batches. Die
/// Funktional-Äquivalenz zu `apply_batch` ist per Test abgesichert.
pub fn replay_batch(
    tree: &mut AccountTree,
    txs: &[(Fr, Fr, u128, u128, u64)],
) -> Result<(), TransitionError> {
    for &(from, to, amount, fee, nonce) in txs {
        if from == to {
            return Err(TransitionError::SelfTransfer);
        }
        let sender_index = tree.index_of(from).ok_or(TransitionError::UnknownSender)?;
        let sender = tree.account_at(sender_index).expect("Index ohne Konto");
        let debit = amount.checked_add(fee).ok_or(TransitionError::Overflow)?;
        if sender.balance < debit {
            return Err(TransitionError::InsufficientBalance { needed: debit, have: sender.balance });
        }
        if sender.nonce != nonce {
            return Err(TransitionError::BadNonce { expected: sender.nonce, got: nonce });
        }
        tree.write(sender_index, Account::new(from, sender.balance - debit, sender.nonce + 1));

        let receiver_index = tree.ensure(to);
        let receiver = tree.account_at(receiver_index).expect("Index ohne Konto");
        let new_balance = receiver.balance.checked_add(amount).ok_or(TransitionError::Overflow)?;
        tree.write(receiver_index, Account::new(to, new_balance, receiver.nonce));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::root_from_path;

    /// Deterministisches Keypair aus einem kleinen Seed (Test-Helfer).
    fn kp(seed: u64) -> EddsaKeypair {
        EddsaKeypair::from_secret(EdFr::from(seed))
    }

    /// Baum mit Alice (= Adresse von `kp(1)`), Startguthaben 1_000_000.
    fn fresh_tree() -> (AccountTree, EddsaKeypair) {
        let alice = kp(1);
        let mut t = AccountTree::new();
        t.register(Account::new(alice.public().address_fr(), 1_000_000, 0));
        (t, alice)
    }

    #[test]
    fn single_transfer_chains_roots() {
        let (mut t, alice) = fresh_tree();
        let a = alice.public().address_fr();
        let bob = kp(2).public().address_fr();
        let txs = [L2Tx::signed(bob, 1000, 10, 0, &alice)];
        let w = apply_batch(&mut t, &txs).expect("gültig");

        assert_eq!(w.total_fees, 10);
        assert_eq!(w.txs.len(), 1);
        let tx = &w.txs[0];
        assert!(tx.receiver_is_new, "Empfänger ist neu");

        // Sender-Inklusion: pre-Blatt unter root_before, post-Blatt unter root_mid.
        let sender_pre = Account::new(a, 1_000_000, 0).leaf_hash();
        let sender_post = Account::new(a, 1_000_000 - 1010, 1).leaf_hash();
        assert_eq!(root_from_path(sender_pre, &tx.sender_path), tx.root_before);
        assert_eq!(root_from_path(sender_post, &tx.sender_path), tx.root_mid);

        // Empfänger-Inklusion: pre-Blatt (leer=0) unter root_mid, post unter root_after.
        let recv_pre = Fr::zero(); // neuer, leerer Slot
        let recv_post = Account::new(bob, 1000, 0).leaf_hash();
        assert_eq!(root_from_path(recv_pre, &tx.receiver_path), tx.root_mid);
        assert_eq!(root_from_path(recv_post, &tx.receiver_path), tx.root_after);

        // Endzustand.
        assert_eq!(t.account_of(a).unwrap().balance, 1_000_000 - 1010);
        assert_eq!(t.account_of(a).unwrap().nonce, 1);
        assert_eq!(t.account_of(bob).unwrap().balance, 1000);
        assert_eq!(w.post_root, t.root());
    }

    #[test]
    fn batch_two_transfers_chain() {
        let (mut t, alice) = fresh_tree();
        let bob_kp = kp(2);
        let bob = bob_kp.public().address_fr();
        let carol = kp(3).public().address_fr();
        // Alice → Bob 5000, dann Bob → Carol 1000 (Bob ist nach TX1 finanziert).
        let txs = [
            L2Tx::signed(bob, 5000, 5, 0, &alice),
            L2Tx::signed(carol, 1000, 2, 0, &bob_kp),
        ];
        let w = apply_batch(&mut t, &txs).expect("gültig");
        assert_eq!(w.total_fees, 7);
        // Verkettung der Wurzeln zwischen den TXs.
        assert_eq!(w.txs[0].root_after, w.txs[1].root_before);
        assert_eq!(t.account_of(bob).unwrap().balance, 5000 - 1002);
        assert_eq!(t.account_of(carol).unwrap().balance, 1000);
    }

    #[test]
    fn rejects_insufficient_balance() {
        let (mut t, alice) = fresh_tree();
        let bob = kp(2).public().address_fr();
        let txs = [L2Tx::signed(bob, 2_000_000, 0, 0, &alice)];
        assert_eq!(apply_batch(&mut t, &txs).unwrap_err(),
            TransitionError::InsufficientBalance { needed: 2_000_000, have: 1_000_000 });
    }

    #[test]
    fn rejects_bad_nonce() {
        let (mut t, alice) = fresh_tree();
        let bob = kp(2).public().address_fr();
        let txs = [L2Tx::signed(bob, 1, 0, 7, &alice)];
        assert_eq!(apply_batch(&mut t, &txs).unwrap_err(),
            TransitionError::BadNonce { expected: 0, got: 7 });
    }

    #[test]
    fn rejects_self_transfer() {
        let (mut t, alice) = fresh_tree();
        let a = alice.public().address_fr();
        let txs = [L2Tx::signed(a, 1, 0, 0, &alice)];
        assert_eq!(apply_batch(&mut t, &txs).unwrap_err(), TransitionError::SelfTransfer);
    }

    #[test]
    fn rejects_unknown_sender() {
        let (mut t, _alice) = fresh_tree();
        let stranger = kp(99);
        let bob = kp(2).public().address_fr();
        let txs = [L2Tx::signed(bob, 1, 0, 0, &stranger)];
        assert_eq!(apply_batch(&mut t, &txs).unwrap_err(), TransitionError::UnknownSender);
    }

    #[test]
    fn rejects_tampered_signature() {
        let (mut t, alice) = fresh_tree();
        let bob = kp(2).public().address_fr();
        let mut tx = L2Tx::signed(bob, 1000, 10, 0, &alice);
        tx.sig.s += EdFr::from(1u64); // manipuliert
        assert_eq!(apply_batch(&mut t, &[tx]).unwrap_err(), TransitionError::SignatureInvalid);
    }

    #[test]
    fn rejects_address_pubkey_mismatch() {
        let (mut t, alice) = fresh_tree();
        let bob = kp(2).public().address_fr();
        let mut tx = L2Tx::signed(bob, 1000, 10, 0, &alice);
        tx.from = kp(5).public().address_fr(); // from passt nicht zum Pubkey (≠ to)
        assert_eq!(apply_batch(&mut t, &[tx]).unwrap_err(), TransitionError::AddressMismatch);
    }
}
