//! Soundness-tragender L2-State-Übergangs-Circuit (Phase 2).
//!
//! Ersetzt das alte `BatchProofCircuit` (das nur ein tautologisches Commitment
//! bewies). Dieser Circuit erzwingt für eine feste Zahl von TX-Slots EXAKT den
//! nativen Übergang aus `transition::apply_batch`:
//!
//! Öffentliche Eingaben (Reihenfolge ist Teil des Beweisformats):
//!   [ pre_state_root, post_state_root, total_fees, batch_commitment ]
//!
//! Pro realem TX-Slot wird erzwungen:
//!   1. Merkle-Inklusion des Sender-Blatts H(from,bal,nonce) unter `cur_root`
//!   2. bal_sender ≥ amount+fee  (Range-Check verhindert Field-Wraparound)
//!   3. tx_nonce == nonce_sender
//!   4. Sender-Update H(from, bal−(amount+fee), nonce+1) ⇒ root_mid
//!   5. Empfänger-Inklusion unter root_mid (leeres Blatt 0 ⇒ Insertion)
//!   6. Empfänger-Update H(to, bal+amount, nonce) ⇒ root_after
//!   7. cur_root ← root_after; Σ fee; Commitment absorbiert (from,to,amount,fee,nonce)
//! Padding-Slots sind vollständige No-Ops (alle Constraints konditional).
//! Am Ende: cur_root == post_state_root, Σ fee == total_fees, Commitment == public.

use ark_bn254::Fr;
use ark_crypto_primitives::sponge::{
    constraints::CryptographicSpongeVar,
    poseidon::{constraints::PoseidonSpongeVar, PoseidonConfig},
};
use ark_ed_on_bn254::constraints::EdwardsVar;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::eddsa::edfr_to_fr;
use crate::eddsa_gadget::eddsa_verify_gadget;
use crate::merkle::DEPTH;
use crate::poseidon::poseidon_config;
use crate::transition::{BatchWitness, TxWitness};

/// L2-Adressen sind die unteren 160 Bit von `Poseidon(A.x, A.y)`.
const ADDRESS_BITS: usize = 160;

/// Beträge/Salden sind auf < 2^120 begrenzt (Range-Check). Das verhindert
/// Field-Wraparound bei `bal − (amount+fee)` und Überlauf bei `bal + amount`,
/// und lässt reichlich Abstand zum 254-Bit-Feld.
const AMOUNT_BITS: usize = 120;

// ── In-Circuit-Poseidon (muss bit-genau zu poseidon.rs passen) ───────────────

fn hash_two_var(
    cfg: &PoseidonConfig<Fr>,
    cs: ConstraintSystemRef<Fr>,
    a: &FpVar<Fr>,
    b: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    let mut sponge = PoseidonSpongeVar::<Fr>::new(cs, cfg);
    sponge.absorb(a)?;
    sponge.absorb(b)?;
    Ok(sponge.squeeze_field_elements(1)?.remove(0))
}

fn hash_three_var(
    cfg: &PoseidonConfig<Fr>,
    cs: ConstraintSystemRef<Fr>,
    a: &FpVar<Fr>,
    b: &FpVar<Fr>,
    c: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    let mut sponge = PoseidonSpongeVar::<Fr>::new(cs, cfg);
    sponge.absorb(a)?;
    sponge.absorb(b)?;
    sponge.absorb(c)?;
    Ok(sponge.squeeze_field_elements(1)?.remove(0))
}

/// Merkle-Wurzel aus Blatt + Indexbits (LSB-first) + Geschwistern.
fn merkle_root_var(
    cfg: &PoseidonConfig<Fr>,
    cs: ConstraintSystemRef<Fr>,
    leaf: &FpVar<Fr>,
    index_bits: &[Boolean<Fr>],
    siblings: &[FpVar<Fr>],
) -> Result<FpVar<Fr>, SynthesisError> {
    let mut cur = leaf.clone();
    for (bit, sib) in index_bits.iter().zip(siblings.iter()) {
        // bit==0: laufendes Element ist linkes Kind; bit==1: rechtes Kind.
        let left = FpVar::conditionally_select(bit, sib, &cur)?;
        let right = FpVar::conditionally_select(bit, &cur, sib)?;
        cur = hash_two_var(cfg, cs.clone(), &left, &right)?;
    }
    Ok(cur)
}

/// Erzwingt 0 ≤ x < 2^n, falls `should`. Die oberen (254−n) Bits müssen 0 sein —
/// ein negatives (field-gewickeltes) Ergebnis hätte gesetzte obere Bits.
fn enforce_lt_pow2(
    x: &FpVar<Fr>,
    n: usize,
    should: &Boolean<Fr>,
) -> Result<(), SynthesisError> {
    let bits = x.to_bits_le()?;
    for b in bits.iter().skip(n) {
        b.conditional_enforce_equal(&Boolean::FALSE, should)?;
    }
    Ok(())
}

// ── Circuit ──────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct StateTransitionCircuit {
    pub pre_root:         Fr,
    pub post_root:        Fr,
    pub total_fees:       Fr,
    pub batch_commitment: Fr,
    /// Genau `batch_size` Slots (reale TXs + Padding).
    pub slots: Vec<TxWitness>,
}

impl StateTransitionCircuit {
    /// Baut den Circuit aus einem nativen `BatchWitness`, aufgefüllt auf
    /// `batch_size` Slots. Liefert auch das native `batch_commitment` und die
    /// öffentlichen Wurzeln, sodass Prover/Verifier dieselben Public-Inputs sehen.
    pub fn from_witness(bw: &BatchWitness, batch_size: usize) -> Self {
        assert!(bw.txs.len() <= batch_size, "mehr TXs als Slots");
        let empty_path = crate::merkle::MerklePath { index: 0, siblings: vec![Fr::from(0u64); DEPTH] };
        let mut slots = bw.txs.clone();
        while slots.len() < batch_size {
            slots.push(TxWitness::padding(bw.post_root, empty_path.clone()));
        }
        StateTransitionCircuit {
            pre_root: bw.pre_root,
            post_root: bw.post_root,
            total_fees: Fr::from(bw.total_fees),
            batch_commitment: compute_batch_commitment(&slots),
            slots,
        }
    }

    /// Dummy-Instanz fester Slotzahl für das Groth16-Setup (Werte irrelevant,
    /// nur die Circuit-FORM zählt).
    pub fn dummy(batch_size: usize) -> Self {
        let empty_path = crate::merkle::MerklePath { index: 0, siblings: vec![Fr::from(0u64); DEPTH] };
        let slots = vec![TxWitness::padding(Fr::from(0u64), empty_path); batch_size];
        StateTransitionCircuit {
            pre_root: Fr::from(0u64),
            post_root: Fr::from(0u64),
            total_fees: Fr::from(0u64),
            batch_commitment: compute_batch_commitment(&slots),
            slots,
        }
    }
}

/// Native Berechnung des Batch-Commitments (muss zur Circuit-Absorption passen).
pub fn compute_batch_commitment(slots: &[TxWitness]) -> Fr {
    let mut inputs = Vec::with_capacity(slots.len() * 5);
    for t in slots {
        inputs.push(t.from);
        inputs.push(t.to);
        inputs.push(Fr::from(t.amount));
        inputs.push(Fr::from(t.fee));
        inputs.push(Fr::from(t.tx_nonce));
    }
    crate::poseidon::hash_many(&inputs)
}

impl ConstraintSynthesizer<Fr> for StateTransitionCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let cfg = poseidon_config();

        // Öffentliche Eingaben.
        let pre_root = FpVar::new_input(cs.clone(), || Ok(self.pre_root))?;
        let post_root = FpVar::new_input(cs.clone(), || Ok(self.post_root))?;
        let total_fees_pub = FpVar::new_input(cs.clone(), || Ok(self.total_fees))?;
        let batch_commitment_pub = FpVar::new_input(cs.clone(), || Ok(self.batch_commitment))?;

        let mut cur_root = pre_root;
        let mut fee_acc = FpVar::<Fr>::zero();

        // Ein Sponge über ALLE Slots für das Batch-Commitment.
        let mut commit_sponge = PoseidonSpongeVar::<Fr>::new(cs.clone(), &cfg);

        for tw in self.slots.iter() {
            let is_real = Boolean::new_witness(cs.clone(), || Ok(!tw.is_padding))?;

            // TX-Daten.
            let from = FpVar::new_witness(cs.clone(), || Ok(tw.from))?;
            let to = FpVar::new_witness(cs.clone(), || Ok(tw.to))?;
            let amount = FpVar::new_witness(cs.clone(), || Ok(Fr::from(tw.amount)))?;
            let fee = FpVar::new_witness(cs.clone(), || Ok(Fr::from(tw.fee)))?;
            let tx_nonce = FpVar::new_witness(cs.clone(), || Ok(Fr::from(tw.tx_nonce)))?;

            // Commitment: für jeden Slot absorbieren (Padding ⇒ Nullen).
            commit_sponge.absorb(&from)?;
            commit_sponge.absorb(&to)?;
            commit_sponge.absorb(&amount)?;
            commit_sponge.absorb(&fee)?;
            commit_sponge.absorb(&tx_nonce)?;

            // Range-Checks der Beträge (nur für reale TXs).
            enforce_lt_pow2(&amount, AMOUNT_BITS, &is_real)?;
            enforce_lt_pow2(&fee, AMOUNT_BITS, &is_real)?;

            // ── EdDSA-Signatur + Adressbindung (Soundness-Kern) ───────────────
            // Nur der Inhaber des privaten Skalars `a` kann eine Signatur über
            // m = Poseidon(from,to,amount,fee,nonce) erzeugen, und die Adresse
            // `from` ist kryptografisch an den Public Key A gebunden. Damit kann
            // ein Aggregator keine unsignierten/fremden Transfers einschleusen.
            let pk_var = EdwardsVar::new_witness(cs.clone(), || Ok(tw.pubkey.0))?;
            let r_var = EdwardsVar::new_witness(cs.clone(), || Ok(tw.sig.r))?;
            let s_var = FpVar::new_witness(cs.clone(), || Ok(edfr_to_fr(tw.sig.s)))?;

            // m = Poseidon(from, to, amount, fee, tx_nonce).
            let m_var = {
                let mut sp = PoseidonSpongeVar::<Fr>::new(cs.clone(), &cfg);
                sp.absorb(&from)?;
                sp.absorb(&to)?;
                sp.absorb(&amount)?;
                sp.absorb(&fee)?;
                sp.absorb(&tx_nonce)?;
                sp.squeeze_field_elements(1)?.remove(0)
            };
            eddsa_verify_gadget(&cfg, cs.clone(), &pk_var, &m_var, &r_var, &s_var, &is_real)?;

            // Bindung: from == lower160(Poseidon(A.x, A.y)).
            let addr_hash = hash_two_var(&cfg, cs.clone(), &pk_var.x, &pk_var.y)?;
            let addr_bits = addr_hash.to_bits_le()?;
            let from_bound = Boolean::le_bits_to_fp_var(&addr_bits[..ADDRESS_BITS])?;
            from_bound.conditional_enforce_equal(&from, &is_real)?;

            // ── Sender ───────────────────────────────────────────────────────
            let sender_bal = FpVar::new_witness(cs.clone(), || Ok(Fr::from(tw.sender_balance)))?;
            let sender_nonce = FpVar::new_witness(cs.clone(), || Ok(Fr::from(tw.sender_nonce)))?;
            enforce_lt_pow2(&sender_bal, AMOUNT_BITS, &is_real)?;

            let sender_bits = bits_of_index(cs.clone(), tw.sender_index)?;
            let sender_sibs = sibling_vars(cs.clone(), &tw.sender_path.siblings)?;

            // pre-Blatt & Inklusion gegen cur_root.
            let sender_leaf_pre = hash_three_var(&cfg, cs.clone(), &from, &sender_bal, &sender_nonce)?;
            let sender_root = merkle_root_var(&cfg, cs.clone(), &sender_leaf_pre, &sender_bits, &sender_sibs)?;
            sender_root.conditional_enforce_equal(&cur_root, &is_real)?;

            // bal ≥ amount+fee  und  tx_nonce == nonce.
            let debit = &amount + &fee;
            let sender_bal_post = &sender_bal - &debit;
            enforce_lt_pow2(&sender_bal_post, AMOUNT_BITS, &is_real)?; // verhindert Underflow
            tx_nonce.conditional_enforce_equal(&sender_nonce, &is_real)?;

            // post-Blatt & root_mid.
            let one = FpVar::<Fr>::one();
            let sender_nonce_post = &sender_nonce + &one;
            let sender_leaf_post = hash_three_var(&cfg, cs.clone(), &from, &sender_bal_post, &sender_nonce_post)?;
            let root_mid = merkle_root_var(&cfg, cs.clone(), &sender_leaf_post, &sender_bits, &sender_sibs)?;

            // ── Empfänger ────────────────────────────────────────────────────
            let recv_is_new = Boolean::new_witness(cs.clone(), || Ok(tw.receiver_is_new))?;
            let recv_bal = FpVar::new_witness(cs.clone(), || Ok(Fr::from(tw.receiver_balance)))?;
            let recv_nonce = FpVar::new_witness(cs.clone(), || Ok(Fr::from(tw.receiver_nonce)))?;
            enforce_lt_pow2(&recv_bal, AMOUNT_BITS, &is_real)?;

            // Neuer Empfänger ⇒ pre-Saldo/Nonce müssen 0 sein.
            let must_zero = is_real.and(&recv_is_new)?;
            recv_bal.conditional_enforce_equal(&FpVar::zero(), &must_zero)?;
            recv_nonce.conditional_enforce_equal(&FpVar::zero(), &must_zero)?;

            let recv_bits = bits_of_index(cs.clone(), tw.receiver_index)?;
            let recv_sibs = sibling_vars(cs.clone(), &tw.receiver_path.siblings)?;

            // pre-Blatt: leerer Slot (0) falls neu, sonst H(to,bal,nonce).
            let recv_leaf_hashed = hash_three_var(&cfg, cs.clone(), &to, &recv_bal, &recv_nonce)?;
            let recv_leaf_pre = FpVar::conditionally_select(&recv_is_new, &FpVar::zero(), &recv_leaf_hashed)?;
            let recv_root = merkle_root_var(&cfg, cs.clone(), &recv_leaf_pre, &recv_bits, &recv_sibs)?;
            recv_root.conditional_enforce_equal(&root_mid, &is_real)?;

            // Credit + Range-Check + post-Blatt + root_after.
            let recv_bal_post = &recv_bal + &amount;
            enforce_lt_pow2(&recv_bal_post, AMOUNT_BITS, &is_real)?;
            let recv_leaf_post = hash_three_var(&cfg, cs.clone(), &to, &recv_bal_post, &recv_nonce)?;
            let root_after = merkle_root_var(&cfg, cs.clone(), &recv_leaf_post, &recv_bits, &recv_sibs)?;

            // cur_root ← (is_padding ? cur_root : root_after); Σ fee.
            cur_root = FpVar::conditionally_select(&is_real, &root_after, &cur_root)?;
            let fee_contrib = FpVar::conditionally_select(&is_real, &fee, &FpVar::zero())?;
            fee_acc = &fee_acc + &fee_contrib;
        }

        // Abschluss-Constraints.
        cur_root.enforce_equal(&post_root)?;
        fee_acc.enforce_equal(&total_fees_pub)?;
        let commitment = commit_sponge.squeeze_field_elements(1)?.remove(0);
        commitment.enforce_equal(&batch_commitment_pub)?;
        Ok(())
    }
}

/// DEPTH Indexbits (LSB-first) als Boolean-Zeugen.
fn bits_of_index(cs: ConstraintSystemRef<Fr>, index: u64) -> Result<Vec<Boolean<Fr>>, SynthesisError> {
    let mut bits = Vec::with_capacity(DEPTH);
    for l in 0..DEPTH {
        let bit = ((index >> l) & 1) == 1;
        bits.push(Boolean::new_witness(cs.clone(), || Ok(bit))?);
    }
    Ok(bits)
}

/// Geschwister-Hashes als FpVar-Zeugen.
fn sibling_vars(cs: ConstraintSystemRef<Fr>, sibs: &[Fr]) -> Result<Vec<FpVar<Fr>>, SynthesisError> {
    sibs.iter().map(|s| FpVar::new_witness(cs.clone(), || Ok(*s))).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_ed_on_bn254::Fr as EdFr;
    use ark_relations::r1cs::ConstraintSystem;
    use crate::account::{Account, AccountTree};
    use crate::eddsa::EddsaKeypair;
    use crate::transition::{apply_batch, L2Tx};

    fn kp(seed: u64) -> EddsaKeypair {
        EddsaKeypair::from_secret(EdFr::from(seed))
    }

    /// Baum mit zwei vorab-geförderten, an echte Pubkeys gebundenen Konten.
    fn tree_with_alice() -> (AccountTree, EddsaKeypair, EddsaKeypair) {
        let alice = kp(1);
        let bob = kp(2);
        let mut t = AccountTree::new();
        t.register(Account::new(alice.public().address_fr(), 1_000_000, 0));
        t.register(Account::new(bob.public().address_fr(), 500, 0));
        (t, alice, bob)
    }

    #[test]
    fn satisfiable_single_transfer() {
        let (mut t, alice, _bob) = tree_with_alice();
        let carol = kp(3).public().address_fr();
        let txs = [L2Tx::signed(carol, 1000, 10, 0, &alice)];
        let bw = apply_batch(&mut t, &txs).unwrap();

        let circuit = StateTransitionCircuit::from_witness(&bw, 4);
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap(), "gültiger Übergang muss erfüllbar sein");
    }

    #[test]
    fn satisfiable_multi_transfer_with_padding() {
        let (mut t, alice, bob) = tree_with_alice();
        let bob_addr = bob.public().address_fr();
        let dave = kp(4).public().address_fr();
        let txs = [
            L2Tx::signed(bob_addr, 5000, 5, 0, &alice),
            L2Tx::signed(dave, 100, 2, 0, &bob),
        ];
        let bw = apply_batch(&mut t, &txs).unwrap();
        let circuit = StateTransitionCircuit::from_witness(&bw, 8);
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn unsound_wrong_post_root_rejected() {
        let (mut t, alice, _bob) = tree_with_alice();
        let carol = kp(3).public().address_fr();
        let txs = [L2Tx::signed(carol, 1000, 10, 0, &alice)];
        let bw = apply_batch(&mut t, &txs).unwrap();
        let mut circuit = StateTransitionCircuit::from_witness(&bw, 4);
        circuit.post_root = Fr::from(123456u64);
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap(), "falsche post_root muss scheitern");
    }

    #[test]
    fn unsound_inflated_fee_rejected() {
        let (mut t, alice, _bob) = tree_with_alice();
        let carol = kp(3).public().address_fr();
        let txs = [L2Tx::signed(carol, 1000, 10, 0, &alice)];
        let bw = apply_batch(&mut t, &txs).unwrap();
        let mut circuit = StateTransitionCircuit::from_witness(&bw, 4);
        circuit.total_fees = Fr::from(9999u64);
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap(), "falsche total_fees müssen scheitern");
    }

    #[test]
    fn unsound_tampered_balance_rejected() {
        let (mut t, alice, _bob) = tree_with_alice();
        let carol = kp(3).public().address_fr();
        let txs = [L2Tx::signed(carol, 1000, 10, 0, &alice)];
        let bw = apply_batch(&mut t, &txs).unwrap();
        let mut circuit = StateTransitionCircuit::from_witness(&bw, 4);
        circuit.slots[0].sender_balance = 9_000_000; // gelogen
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap(), "manipuliertes Sender-Guthaben muss scheitern");
    }

    /// Soundness-Kern: eine im Witness manipulierte Signatur darf den Circuit
    /// NICHT erfüllen — selbst wenn alle Bilanz-/Root-Constraints stimmen.
    #[test]
    fn unsound_tampered_signature_rejected() {
        let (mut t, alice, _bob) = tree_with_alice();
        let carol = kp(3).public().address_fr();
        let txs = [L2Tx::signed(carol, 1000, 10, 0, &alice)];
        let bw = apply_batch(&mut t, &txs).unwrap();
        let mut circuit = StateTransitionCircuit::from_witness(&bw, 4);
        // S verfälschen → S·B != R + c·A.
        circuit.slots[0].sig.s += EdFr::from(1u64);
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap(), "manipulierte Signatur muss scheitern");
    }

    /// Soundness-Kern: ein fremder Public Key (der nicht zu `from` passt) muss
    /// an der Adressbindung scheitern, auch bei valider Signatur über diese Keys.
    #[test]
    fn unsound_foreign_pubkey_rejected() {
        let (mut t, alice, _bob) = tree_with_alice();
        let carol = kp(3).public().address_fr();
        let txs = [L2Tx::signed(carol, 1000, 10, 0, &alice)];
        let bw = apply_batch(&mut t, &txs).unwrap();
        let mut circuit = StateTransitionCircuit::from_witness(&bw, 4);
        // pubkey gegen einen fremden Schlüssel tauschen (from bleibt Alices Adresse).
        let mallory = kp(7);
        circuit.slots[0].pubkey = mallory.public();
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap(), "fremder Pubkey muss an der Adressbindung scheitern");
    }

    #[test]
    fn commitment_matches_native() {
        let (mut t, alice, _bob) = tree_with_alice();
        let carol = kp(3).public().address_fr();
        let txs = [L2Tx::signed(carol, 1000, 10, 0, &alice)];
        let bw = apply_batch(&mut t, &txs).unwrap();
        let circuit = StateTransitionCircuit::from_witness(&bw, 4);
        let native_commit = compute_batch_commitment(&circuit.slots);
        assert_eq!(native_commit, circuit.batch_commitment);
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }
}
