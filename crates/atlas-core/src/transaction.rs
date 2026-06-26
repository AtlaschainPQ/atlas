use serde::{Deserialize, Serialize};
use crate::amount::Amount;
use crate::crypto::{Address, KeyPair, PublicKey, Signature, CryptoError};
use crate::hash::Hash;
use crate::pq_crypto::{PqAddress, PqKeyPair, PqPublicKey, PqSignature, PqError};
use crate::tx_stamp::TxStamp;


/// Eindeutiger Transaktions-ID: Hash der signierten TX-Daten
pub type TxId = Hash;

/// Transaktion in ATLAS
/// Modell: UTXO-ähnlich mit expliziten Inputs/Outputs
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transaction {
    pub version:  u32,
    pub inputs:   Vec<TxInput>,
    pub outputs:  Vec<TxOutput>,
    /// Fee in ATOM (Anteil für Miner/Prover)
    pub fee:      Amount,
    /// Zeitstempel (Millisekunden seit Epoch)
    pub timestamp: u64,
    /// Mini-PoW Spam-Schutz
    pub stamp:    Option<TxStamp>,
    /// Typ der Transaktion
    pub tx_type:  TxType,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum TxType {
    /// Standard Zahlung
    Transfer,
    /// Coinbase (Miner-Reward)
    Coinbase,
    /// Settlement-Batch Einreichung durch Aggregator.
    ///
    /// Trägt einen soundness-tragenden Groth16-State-Transition-Beweis: der
    /// Aggregator beweist, dass `pre_root` durch eine gültige Folge von L2-TX
    /// (jede mit Merkle-Inklusion, Balance-/Nonce-Prüfung) deterministisch zu
    /// `post_root` übergeht und dabei `total_fees` anfallen. Alle Felder sind
    /// öffentliche Eingaben des Beweises — nichts davon kann ohne gültigen
    /// Proof gefälscht werden. Die L2-State-Root-Kette (`pre_root → post_root`)
    /// wird on-chain fortgeschrieben (siehe `BlockHeader::l2_state_root`).
    SettlementBid {
        batch_id:         Hash,
        bid_amount:       Amount,
        /// L2-State-Root VOR diesem Batch (muss an die Chain-L2-Root anschließen).
        pre_root:         Hash,
        /// L2-State-Root NACH diesem Batch.
        post_root:        Hash,
        /// Poseidon-Commitment über die enthaltenen L2-TX (Data-Availability-Bindung).
        batch_commitment: Hash,
        /// Summe der L2-Gebühren dieses Batches in ATOM.
        total_fees:       u128,
        /// Groth16-State-Transition-Beweis (BN254, kompakt ~128 B).
        #[serde(default)]
        proof:            Vec<u8>,
        /// On-Chain Data Availability: die L2-TX-Calldata dieses Batches
        /// (from|to|amount|fee|nonce je 80 B). Der Node prüft, dass sie zum
        /// im Beweis gebundenen `batch_commitment` hasht — damit ist der
        /// L2-Zustand jederzeit von Genesis re-konstruierbar (Escape-Hatch).
        #[serde(default)]
        calldata:         Vec<u8>,
        /// Ablehnungs-Zeugen für Forced-Inclusion-TXs, die gegen den L2-Zustand
        /// dieses Batches (`pre_root`) UNGÜLTIG sind (falsche Nonce, zu wenig
        /// Guthaben, falscher `sender_index`). Der Node verifiziert jeden Zeugen
        /// nativ (Poseidon-Leaf + Merkle-Pfad gegen `pre_root`) — nur so darf
        /// ein Aggregator eine fällige Forced-TX unerfüllt lassen.
        #[serde(default)]
        forced_rejections: Vec<ForcedRejection>,
    },
    /// Forced Inclusion (Zensurresistenz): eine signierte L2-TX wird direkt auf
    /// L1 veröffentlicht. Konsens-Regel: ist der Eintrag älter als
    /// `forced_inclusion_window` Blöcke, MUSS jedes Settlement die ältesten
    /// fälligen Einträge aufnehmen (Calldata) oder per [`ForcedRejection`]
    /// nachweislich ablehnen — sonst ist der Block ungültig. Die Autorisierung
    /// steckt in der EdDSA-Signatur; der L1-Einreicher ist beliebig (Pseudo-
    /// Input + TxStamp, keine L1-UTXOs nötig).
    L2ForcedTx {
        /// L2-Absenderadresse (muss zur EdDSA-Pubkey-Bindung passen).
        from:        [u8; 20],
        /// L2-Empfängeradresse.
        to:          [u8; 20],
        /// Betrag in ATOM.
        amount_atom: u128,
        /// L2-Gebühr in ATOM.
        fee_atom:    u128,
        /// L2-Konto-Nonce des Absenders.
        nonce:       u64,
        /// Komprimierter Baby-Jubjub-EdDSA-Pubkey (32 B).
        pubkey:      [u8; 32],
        /// EdDSA-Signatur (R‖s, 64 B).
        sig:         Vec<u8>,
        /// Index des Absender-Kontos im L2-Account-Baum (vom User aus den
        /// On-Chain-Calldata rekonstruierbar). Bezugspunkt für Rejection-Zeugen;
        /// ein falscher Index macht die TX ablehnbar (User reicht neu ein).
        sender_index: u64,
    },
}

/// Nativer Ablehnungs-Zeuge für eine Forced-Inclusion-TX: beweist gegen den
/// `pre_root` des Settlements, dass die TX nicht anwendbar ist. Der Node prüft
/// `root_from_path(leaf, sender_index, siblings) == pre_root` und dass
/// (a) der Slot leer ist, (b) die Leaf-Adresse nicht `from` ist,
/// (c) die Leaf-Nonce ≠ TX-Nonce ist oder (d) das Guthaben < amount+fee ist.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForcedRejection {
    /// Identifiziert den Queue-Eintrag: (from, nonce) ist pro Queue eindeutig.
    pub from:         [u8; 20],
    pub nonce:        u64,
    /// Leaf-Inhalt am `sender_index` (ignoriert falls `leaf_vacant`).
    pub leaf_address: [u8; 20],
    pub leaf_balance: u128,
    pub leaf_nonce:   u64,
    /// Slot am `sender_index` ist leer (Konto existiert dort nicht).
    pub leaf_vacant:  bool,
    /// Merkle-Geschwister (LSB-first, Baumtiefe Einträge à 32 B).
    pub siblings:     Vec<[u8; 32]>,
}

/// Eintrag der Konsens-geführten Forced-Inclusion-Queue (Teil des Chain-States,
/// Reorg-sicher über Snapshots). Entsteht aus einem on-chain `L2ForcedTx`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForcedQueueEntry {
    pub from:         [u8; 20],
    pub to:           [u8; 20],
    pub amount_atom:  u128,
    pub fee_atom:     u128,
    pub nonce:        u64,
    pub pubkey:       [u8; 32],
    pub sig:          Vec<u8>,
    pub sender_index: u64,
    /// Blockhöhe, in der die Forced-TX on-chain erschien (Fälligkeits-Basis).
    pub seen_height:  u64,
}

/// Signatur-Zeuge: klassisch (ECDSA) oder post-quantum (ML-DSA-65)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Witness {
    /// ECDSA secp256k1 — 64 Bytes Signatur, 33 Bytes Public Key
    Classic {
        sig:    Signature,
        pubkey: PublicKey,
    },
    /// ML-DSA-65 (CRYSTALS-Dilithium3) — 3309 Bytes Sig, 1952 Bytes PK
    Quantum {
        sig:    PqSignature,
        pubkey: PqPublicKey,
    },
}

impl Witness {
    /// Leitet die Adresse aus dem enthaltenen Public Key ab.
    pub fn derived_address(&self) -> DerivedAddress {
        match self {
            Witness::Classic { pubkey, .. } => DerivedAddress::Classic(pubkey.to_address()),
            Witness::Quantum { pubkey, .. } => DerivedAddress::Quantum(pubkey.to_address()),
        }
    }

    /// Verifiziert die Signatur über `message`.
    pub fn verify(&self, message: &[u8]) -> Result<(), WitnessError> {
        match self {
            Witness::Classic { sig, pubkey } => {
                let hash = Hash(message.try_into().unwrap_or([0u8; 32]));
                sig.verify(&hash, pubkey)
                    .map_err(WitnessError::Classic)
            }
            Witness::Quantum { sig, pubkey } => {
                pubkey.verify(message, sig)
                    .map_err(WitnessError::Quantum)
            }
        }
    }

    /// Null-Witness für Coinbase-Inputs
    pub fn zeroed() -> Self {
        Witness::Classic {
            sig:    Signature::zeroed(),
            pubkey: PublicKey::zeroed(),
        }
    }
}

#[derive(Debug)]
pub enum WitnessError {
    Classic(CryptoError),
    Quantum(PqError),
}

impl std::fmt::Display for WitnessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WitnessError::Classic(e) => write!(f, "ECDSA: {}", e),
            WitnessError::Quantum(e) => write!(f, "ML-DSA: {}", e),
        }
    }
}

/// Adresse die aus einem Witness hergeleitet wurde — für Vergleich mit UTXO-Adresse.
#[derive(Debug, PartialEq, Eq)]
pub enum DerivedAddress {
    Classic(Address),
    Quantum(PqAddress),
}

/// Transaktion-Input: referenziert einen unverbrauchten Output (UTXO)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxInput {
    /// Hash der Vorgänger-Transaktion
    pub prev_txid:  TxId,
    /// Index des Outputs in der Vorgänger-TX
    pub prev_index: u32,
    /// Kryptographischer Zeuge (ECDSA oder ML-DSA)
    pub witness:    Witness,
    /// Sequenznummer (für RBF / Timelock)
    pub sequence:   u32,
}

/// Empfänger-Adresse — entweder klassisch oder post-quantum
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutputAddress {
    Classic(Address),
    Quantum(PqAddress),
}

impl OutputAddress {
    pub fn as_classic(&self) -> Option<&Address> {
        if let OutputAddress::Classic(a) = self { Some(a) } else { None }
    }
    pub fn as_quantum(&self) -> Option<&PqAddress> {
        if let OutputAddress::Quantum(a) = self { Some(a) } else { None }
    }
}

impl From<Address> for OutputAddress {
    fn from(a: Address) -> Self { OutputAddress::Classic(a) }
}

impl From<PqAddress> for OutputAddress {
    fn from(a: PqAddress) -> Self { OutputAddress::Quantum(a) }
}

/// Transaktion-Output: legt fest wer wie viel bekommt
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxOutput {
    /// Betrag in ATOM
    pub value:   Amount,
    /// Empfänger-Adresse (klassisch oder PQ)
    pub address: OutputAddress,
}

/// UTXO-Referenz
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OutPoint {
    pub txid:  TxId,
    pub index: u32,
}

impl Transaction {
    /// Berechnet den Transaktions-Hash (über alle signierten Felder)
    pub fn txid(&self) -> TxId {
        let data = self.signing_data();
        Hash::double_sha256(&data)
    }

    /// Daten die signiert werden (ohne Signatur selbst)
    pub fn signing_data(&self) -> Vec<u8> {
        bincode::serialize(&(
            &self.version,
            &self.inputs.iter().map(|i| (&i.prev_txid, i.prev_index, i.sequence)).collect::<Vec<_>>(),
            &self.outputs,
            &self.fee,
            &self.timestamp,
            &self.tx_type,
        )).expect("serialization cannot fail")
    }

    /// Gesamter Output-Betrag
    pub fn total_output(&self) -> Amount {
        self.outputs.iter().fold(Amount::ZERO, |acc, o| acc + o.value)
    }

    /// Ist dies eine Coinbase-Transaktion?
    pub fn is_coinbase(&self) -> bool {
        self.tx_type == TxType::Coinbase
    }

    /// TX-Typen ohne echte UTXO-Inputs (Pseudo-Input, prev_txid=0):
    /// SettlementBid (0xFFFFFFFE) und L2ForcedTx (0xFFFFFFFD). Für sie entfallen
    /// UTXO-Lookup, ECDSA-Witness-Prüfung und Double-Spend-Tracking.
    pub fn has_pseudo_inputs(&self) -> bool {
        matches!(self.tx_type,
            TxType::SettlementBid { .. } | TxType::L2ForcedTx { .. })
    }

    /// Minimale Fee: 10 ATOM (Protokoll-Minimum)
    pub const MIN_FEE_ATOM: u128 = 10;
    /// Maximale Fee: 100 ATOM (Fee-Cap für User-Schutz)
    pub const MAX_FEE_ATOM: u128 = 100;

    pub fn has_valid_fee(&self) -> bool {
        if self.is_coinbase() { return true; }
        self.fee.as_atom() >= Self::MIN_FEE_ATOM
            && self.fee.as_atom() <= Self::MAX_FEE_ATOM
    }

    /// Signiert alle Inputs mit klassischem ECDSA KeyPair.
    pub fn sign(&mut self, keypair: &KeyPair) {
        let hash = self.txid();
        for input in &mut self.inputs {
            if let Ok(sig) = keypair.sign(&hash) {
                input.witness = Witness::Classic {
                    sig,
                    pubkey: keypair.public.clone(),
                };
            }
        }
    }

    /// Signiert alle Inputs mit ML-DSA-65 Post-Quantum KeyPair.
    pub fn sign_quantum(&mut self, keypair: &PqKeyPair) {
        let hash = self.txid();
        for input in &mut self.inputs {
            if let Ok(sig) = keypair.sign(hash.as_bytes()) {
                input.witness = Witness::Quantum {
                    sig,
                    pubkey: keypair.public.clone(),
                };
            }
        }
    }

    /// Erstellt eine vollständig signierte klassische Transfer-Transaktion.
    pub fn new_transfer(
        inputs:  Vec<(Hash, u32)>,
        outputs: Vec<TxOutput>,
        fee:     Amount,
        keypair: &KeyPair,
    ) -> Self {
        let raw_inputs = inputs.into_iter().map(|(prev_txid, prev_index)| {
            TxInput { prev_txid, prev_index, witness: Witness::zeroed(), sequence: 0 }
        }).collect();

        let mut tx = Transaction {
            version:   1,
            inputs:    raw_inputs,
            outputs,
            fee,
            timestamp: current_timestamp_ms(),
            stamp:     None,
            tx_type:   TxType::Transfer,
        };
        tx.sign(keypair);
        tx
    }

    /// Erstellt eine vollständig signierte PQ Transfer-Transaktion.
    pub fn new_transfer_quantum(
        inputs:  Vec<(Hash, u32)>,
        outputs: Vec<TxOutput>,
        fee:     Amount,
        keypair: &PqKeyPair,
    ) -> Self {
        let raw_inputs = inputs.into_iter().map(|(prev_txid, prev_index)| {
            TxInput { prev_txid, prev_index, witness: Witness::zeroed(), sequence: 0 }
        }).collect();

        let mut tx = Transaction {
            version:   1,
            inputs:    raw_inputs,
            outputs,
            fee,
            timestamp: current_timestamp_ms(),
            stamp:     None,
            tx_type:   TxType::Transfer,
        };
        tx.sign_quantum(keypair);
        tx
    }

    /// Erstellt eine Coinbase-Transaktion (Modell A).
    ///
    /// Es gibt **keinen L1-Coin**: die Coinbase-Outputs tragen Wert **0** und
    /// dienen nur als Träger der **L2-Adressen** von Miner/Prover. Der Node
    /// schreibt die Emission (Subsidy + L2-Fees, 70/30) nativ deren L2-Konten gut;
    /// die Beträge rechnet er aus dem Schedule nach (nicht aus der Coinbase →
    /// kein Inflations-Hebel). `_miner_reward`/`_prover_reward` bleiben in der
    /// Signatur (Aufrufer-Kompatibilität), beeinflussen die L1-Outputs aber nicht.
    pub fn new_coinbase(
        height:         u64,
        _miner_reward:  Amount,
        _prover_reward: Amount,
        miner_addr:     Address,
        prover_addr:    Address,
    ) -> Self {
        let mut outputs = vec![
            TxOutput { value: Amount::ZERO, address: OutputAddress::Classic(miner_addr) },
        ];
        if prover_addr != miner_addr {
            outputs.push(TxOutput {
                value:   Amount::ZERO,
                address: OutputAddress::Classic(prover_addr),
            });
        }

        let coinbase_input = TxInput {
            prev_txid:  Hash::zero(),
            prev_index: 0xFFFFFFFF,
            witness:    Witness::zeroed(),
            sequence:   height as u32,
        };

        Transaction {
            version:   1,
            inputs:    vec![coinbase_input],
            outputs,
            fee:       Amount::ZERO,
            timestamp: current_timestamp_ms(),
            stamp:     None,
            tx_type:   TxType::Coinbase,
        }
    }

    /// Erstellt eine SettlementBid-TX (Aggregator reicht einen Settlement-Batch ein).
    ///
    /// Der soundness-tragende State-Transition-Beweis und die L2-State-Roots
    /// werden in der TX selbst getragen. Der Node verifiziert den Beweis beim
    /// Mempool-Eintritt UND erneut bei Block-Anwendung; die L2-State-Root-Kette
    /// wird dabei on-chain fortgeschrieben — von Genesis re-verifizierbar.
    #[allow(clippy::too_many_arguments)]
    pub fn new_settlement_bid(
        batch_id:          Hash,
        aggregator:        Address,
        bid_amount:        Amount,
        pre_root:          Hash,
        post_root:         Hash,
        batch_commitment:  Hash,
        total_fees:        u128,
        proof:             Vec<u8>,
        calldata:          Vec<u8>,
        forced_rejections: Vec<ForcedRejection>,
    ) -> Self {
        // Pseudo-Input: zeigt auf Zero-Hash (kein UTXO verbraucht)
        let bid_input = TxInput {
            prev_txid:  Hash::zero(),
            prev_index: 0xFFFFFFFE,
            witness:    Witness::zeroed(),
            sequence:   0,
        };
        // Marker-Output (kein Wert-Transfer) — registriert den Aggregator
        let proof_output = TxOutput {
            value:   Amount::ZERO,
            address: OutputAddress::Classic(aggregator),
        };
        // Bid-Marker: `bid_amount` ist NUR Metadatum (Settlement-Digest/Auktion).
        // Der Output MUSS wertlos sein — ein wertiger Output ohne echte Inputs
        // wäre ungedeckte Geldschöpfung (Pseudo-Input-TXs durchlaufen keine
        // Werterhaltungsprüfung). Aggregator-Vergütung = prover_share der
        // Coinbase + L2-Gebühren, nie frisch gemintete L1-Coins.
        let bid_output = TxOutput {
            value:   Amount::ZERO,
            address: OutputAddress::Classic(aggregator),
        };

        Transaction {
            version:   1,
            inputs:    vec![bid_input],
            outputs:   vec![proof_output, bid_output],
            fee:       Amount::ZERO,
            timestamp: current_timestamp_ms(),
            stamp:     None,
            tx_type:   TxType::SettlementBid {
                batch_id, bid_amount, pre_root, post_root,
                batch_commitment, total_fees, proof, calldata,
                forced_rejections,
            },
        }
    }

    /// Erstellt eine Forced-Inclusion-TX (signierte L2-TX direkt auf L1).
    ///
    /// Wie `SettlementBid` ohne echte UTXO-Inputs (Pseudo-Input) — Spam-Schutz
    /// über TxStamp + Mindestgebühr. Die Autorisierung der L2-Wirkung liegt
    /// allein in der eingebetteten EdDSA-Signatur, NICHT beim L1-Einreicher
    /// (jeder Helfer kann sie für den User einreichen).
    #[allow(clippy::too_many_arguments)]
    pub fn new_l2_forced_tx(
        from:         [u8; 20],
        to:           [u8; 20],
        amount_atom:  u128,
        fee_atom:     u128,
        nonce:        u64,
        pubkey:       [u8; 32],
        sig:          Vec<u8>,
        sender_index: u64,
    ) -> Self {
        let forced_input = TxInput {
            prev_txid:  Hash::zero(),
            prev_index: 0xFFFFFFFD, // eigener Pseudo-Input-Marker (Bid = 0xFFFFFFFE)
            witness:    Witness::zeroed(),
            sequence:   0,
        };
        // Wertloser Marker-Output: die Block-Validierung verlangt ≥1 Output pro
        // TX. Wert MUSS 0 sein — Pseudo-Inputs decken nichts (siehe Bid-Output).
        let marker_output = TxOutput {
            value:   Amount::ZERO,
            address: OutputAddress::Classic(Address(from)),
        };
        Transaction {
            version:   1,
            inputs:    vec![forced_input],
            outputs:   vec![marker_output],
            fee:       Amount::ZERO,
            timestamp: current_timestamp_ms(),
            stamp:     None,
            tx_type:   TxType::L2ForcedTx {
                from, to, amount_atom, fee_atom, nonce, pubkey, sig, sender_index,
            },
        }
    }
}

pub fn current_timestamp_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coinbase_tx() {
        let miner  = Address([1u8; 20]);
        let prover = Address([2u8; 20]);
        let reward = Amount::from_atl(64);
        let miner_share  = reward * 70 / 100;
        let prover_share = reward * 30 / 100;
        let cb = Transaction::new_coinbase(0, miner_share, prover_share, miner, prover);
        assert!(cb.is_coinbase());
        println!("Coinbase txid: {:?}", cb.txid());
        println!("Total output: {}", cb.total_output());
    }

    #[test]
    fn test_fee_bounds() {
        // 10 ATOM = minimum
        let min = Amount::from_atom(10);
        let max = Amount::from_atom(100);
        assert!(min.as_atom() >= Transaction::MIN_FEE_ATOM);
        assert!(max.as_atom() <= Transaction::MAX_FEE_ATOM);
    }
}
