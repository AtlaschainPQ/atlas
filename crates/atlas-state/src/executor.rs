//! Block-Executor: Wendet State-Transitions an
//!
//! Zustandsmaschine pro Block:
//! 1. Verify PoW         (in consensus)
//! 2. Verify Timestamp   (in consensus)
//! 3. Verify Proof       (ZK-Stub)
//! 4. Apply State Transition ← hier
//! 5. Update Root        ← hier
//! 6. Distribute Rewards ← hier

use atlas_core::block::{Block, BlockHeight};
use atlas_core::hash::Hash;
use atlas_core::amount::Amount;
use atlas_core::transaction::{Transaction, DerivedAddress, OutputAddress};
use atlas_consensus::params::ConsensusParams;
use atlas_consensus::reward::RewardSchedule;
use crate::utxo::{UtxoSet, UtxoError};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use std::sync::Arc;

#[derive(Error, Debug)]
pub enum ExecutionError {
    #[error("UTXO error: {0}")]
    Utxo(#[from] UtxoError),
    #[error("Input/Output value mismatch: inputs={inputs}, outputs={outputs}, fee={fee}")]
    ValueMismatch { inputs: Amount, outputs: Amount, fee: Amount },
    #[error("Block has no transactions (coinbase required)")]
    NoCoinbase,
    #[error("ZK proof verification failed")]
    ZkProofFailed,
    #[error("State root mismatch")]
    StateRootMismatch,
    /// PublicKey in Input passt nicht zur Adresse des referenzierten UTXO
    #[error("Input #{input_index}: public key does not match UTXO owner address")]
    PubkeyAddressMismatch { input_index: usize },
    /// Kryptographische Signatur ungültig (klassisch oder PQ)
    #[error("Input #{input_index}: invalid signature: {reason}")]
    SignatureInvalid { input_index: usize, reason: String },
}

/// Ergebnis der Block-Ausführung
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionResult {
    /// Neuer State-Root (Merkle-Root aller UTXOs)
    pub state_root:     Hash,
    /// Tatsächlich bezahlte Fees
    pub total_fees:     Amount,
    /// Miner-Reward ausgezahlt
    pub miner_reward:   Amount,
    /// Prover-Reward ausgezahlt
    pub prover_reward:  Amount,
    /// Verarbeitete TX-Anzahl
    pub tx_count:       usize,
    /// Verarbeitungszeit (Mikrosekunden)
    pub execution_us:   u64,
}

pub struct BlockExecutor {
    params:  ConsensusParams,
    utxo:    Arc<UtxoSet>,
}

impl BlockExecutor {
    pub fn new(params: ConsensusParams, utxo: Arc<UtxoSet>) -> Self {
        BlockExecutor { params, utxo }
    }

    /// Führt alle Transaktionen eines Blocks aus
    pub fn execute(&self, block: &Block) -> Result<ExecutionResult, ExecutionError> {
        if block.transactions.is_empty() {
            return Err(ExecutionError::NoCoinbase);
        }

        let start    = std::time::Instant::now();
        let height   = block.height();
        let schedule = RewardSchedule::new(&self.params);
        let reward   = schedule.block_reward(height, &block.transactions);

        let mut total_fees = Amount::ZERO;

        // Nicht-Coinbase Transaktionen verarbeiten
        for tx in block.transactions.iter().skip(1) {
            self.execute_tx(tx, height)?;
            total_fees += tx.fee;
        }

        // Coinbase-TX: Outputs hinzufügen (keine Inputs zu verbrauchen)
        let coinbase = &block.transactions[0];
        let cb_txid  = coinbase.txid();
        self.utxo.apply_outputs(cb_txid, coinbase, height);

        // State-Root berechnen (vereinfacht: Hash aller UTXO-Outpoints)
        let state_root = self.compute_state_root();

        let elapsed = start.elapsed().as_micros() as u64;

        Ok(ExecutionResult {
            state_root,
            total_fees,
            miner_reward:  reward.miner_reward,
            prover_reward: reward.prover_reward,
            tx_count:      block.transactions.len(),
            execution_us:  elapsed,
        })
    }

    fn execute_tx(&self, tx: &Transaction, height: BlockHeight) -> Result<(), ExecutionError> {
        // SettlementBid/L2ForcedTx haben Pseudo-Inputs (txid=0) —
        // kein UTXO-Lookup, keine ECDSA-Signaturprüfung, keine Werterhaltung.
        // Sie registrieren nur ggf. Outputs (Aggregator-Bid-Reward).
        if tx.has_pseudo_inputs() {
            let txid = tx.txid();
            self.utxo.apply_outputs(txid, tx, height);
            return Ok(());
        }

        // Inputs verbrauchen — spend_inputs is atomic: either all are removed or none
        let spent = self.utxo.spend_inputs(tx, height, self.params.coinbase_maturity)?;

        // ── Signatur-Verifikation (Classic ECDSA + Quantum ML-DSA) ───────────
        // txid() hasht signing_data() — alles außer Witness-Daten.
        let tx_hash = tx.txid();

        for (i, (input, (_, utxo))) in tx.inputs.iter().zip(spent.iter()).enumerate() {
            // Coinbase-Inputs haben keinen echten Witness → überspringen
            if input.prev_index == 0xFFFF_FFFF && input.prev_txid == Hash::zero() {
                continue;
            }

            // 1. Aus dem Witness abgeleitete Adresse muss mit UTXO-Adresse übereinstimmen
            let derived = input.witness.derived_address();
            let addr_match = match (&derived, &utxo.address) {
                (DerivedAddress::Classic(d), OutputAddress::Classic(u)) => d == u,
                (DerivedAddress::Quantum(d), OutputAddress::Quantum(u)) => d == u,
                _ => false, // Typ-Mismatch
            };
            if !addr_match {
                self.utxo.restore_utxos(&spent);
                return Err(ExecutionError::PubkeyAddressMismatch { input_index: i });
            }

            // 2. Kryptographische Signatur über tx_hash verifizieren
            if let Err(e) = input.witness.verify(tx_hash.as_bytes()) {
                self.utxo.restore_utxos(&spent);
                return Err(ExecutionError::SignatureInvalid {
                    input_index: i,
                    reason:      e.to_string(),
                });
            }
        }

        // ── Werterhaltung ────────────────────────────────────────────────────
        let total_in  = spent.iter().fold(Amount::ZERO, |acc, (_, u)| acc + u.value);
        let total_out = tx.total_output();
        let required  = total_out + tx.fee;

        if total_in != required {
            self.utxo.restore_utxos(&spent);
            return Err(ExecutionError::ValueMismatch {
                inputs:  total_in,
                outputs: total_out,
                fee:     tx.fee,
            });
        }

        // Outputs hinzufügen
        let txid = tx.txid();
        self.utxo.apply_outputs(txid, tx, height);
        Ok(())
    }

    /// State-Root: Hash des sortierten UTXO-Sets
    fn compute_state_root(&self) -> Hash {
        let snapshot = self.utxo.snapshot();
        let mut keys: Vec<_> = snapshot.keys().collect();
        keys.sort_by(|a, b| {
            let a_bytes = [a.txid.as_bytes().as_ref(), &a.index.to_be_bytes()].concat();
            let b_bytes = [b.txid.as_bytes().as_ref(), &b.index.to_be_bytes()].concat();
            a_bytes.cmp(&b_bytes)
        });

        let mut hasher_input = Vec::new();
        for op in keys {
            if let Some(utxo) = snapshot.get(op) {
                hasher_input.extend_from_slice(op.txid.as_bytes());
                hasher_input.extend_from_slice(&op.index.to_be_bytes());
                hasher_input.extend_from_slice(&utxo.value.as_atom().to_be_bytes());
                // Serialize address: 1-byte type tag + 20-byte payload
                match &utxo.address {
                    OutputAddress::Classic(a) => {
                        hasher_input.push(0x01);
                        hasher_input.extend_from_slice(&a.0);
                    }
                    OutputAddress::Quantum(a) => {
                        hasher_input.push(0x02);
                        hasher_input.extend_from_slice(&a.0);
                    }
                }
            }
        }

        Hash::sha256(&hasher_input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use atlas_core::block::Block;
    use atlas_core::crypto::{Address, KeyPair};
    use atlas_core::transaction::{Transaction, TxOutput, OutPoint, OutputAddress};
    use crate::utxo::Utxo;

    fn make_executor() -> (ConsensusParams, Arc<UtxoSet>, BlockExecutor) {
        let params = ConsensusParams::mainnet();
        let utxo   = Arc::new(UtxoSet::new());
        let exec   = BlockExecutor::new(params.clone(), utxo.clone());
        (params, utxo, exec)
    }

    /// Fügt einen UTXO direkt ein (für Tests, ohne echte TX)
    fn insert_utxo(utxo: &UtxoSet, txid: Hash, index: u32, value_atl: u64, address: Address) -> OutPoint {
        let op = OutPoint { txid, index };
        utxo.restore_utxos(&[(op, Utxo {
            value:        Amount::from_atl(value_atl as u128),
            address:      OutputAddress::Classic(address),
            block_height: 0,
            is_coinbase:  false,
        })]);
        op
    }

    #[test]
    fn test_execute_genesis_coinbase() {
        let (_, utxo, executor) = make_executor();
        let miner  = Address([1u8; 20]);
        let prover = Address([2u8; 20]);
        let mut genesis = Block::genesis();

        genesis.transactions.push(Transaction::new_coinbase(
            0,
            Amount::from_atl(44),
            Amount::from_atl(19),
            miner,
            prover,
        ));
        genesis.header.merkle_root = genesis.compute_merkle_root();

        let result = executor.execute(&genesis).unwrap();
        assert_eq!(result.tx_count, 1);
        // Modell A: Die Coinbase trägt KEINEN L1-Wert (Output 0) — die Emission
        // wird auf L2 gutgeschrieben, nicht als L1-UTXO. L1-Balance daher 0.
        assert_eq!(utxo.balance(&miner).as_atl_floor(), 0);
        assert_eq!(utxo.balance(&prover).as_atl_floor(), 0);
    }

    #[test]
    fn test_execute_signed_transfer_succeeds() {
        let (params, utxo, executor) = make_executor();
        let sender   = KeyPair::generate();
        let receiver = KeyPair::generate();

        // UTXO mit 1000 ATOM
        let fee       = params.min_fee_atom;  // 10 ATOM
        let input_val = 1000u128;             // 1000 ATOM
        let out_val   = input_val - fee;      // 990 ATOM

        let fake_txid = Hash::sha256(b"funding_tx");
        let op = {
            let op = atlas_core::transaction::OutPoint { txid: fake_txid, index: 0 };
            utxo.restore_utxos(&[(op, crate::utxo::Utxo {
                value:        Amount::from_atom(input_val),
                address:      OutputAddress::Classic(sender.address),
                block_height: 0,
                is_coinbase:  false,
            })]);
            op
        };

        // Korrekt signierte Transfer-TX: 990 ATOM an receiver, 10 ATOM fee
        let tx = Transaction::new_transfer(
            vec![(fake_txid, 0)],
            vec![TxOutput { value: Amount::from_atom(out_val), address: receiver.address.into() }],
            Amount::from_atom(fee),
            &sender,
        );

        executor.execute_tx(&tx, 1).expect("Signed transfer must succeed");

        // Sender-UTXO verbraucht, Receiver-UTXO erzeugt
        assert!(utxo.get(&op).is_none(), "Spent UTXO must be gone");
        assert_eq!(utxo.balance(&receiver.address).as_atom(), out_val);
    }

    #[test]
    fn test_execute_wrong_key_rejected() {
        let (params, utxo, executor) = make_executor();
        let owner    = KeyPair::generate();
        let attacker = KeyPair::generate();

        let fake_txid = Hash::sha256(b"owner_tx");
        let op = insert_utxo(&utxo, fake_txid, 0, 10, owner.address);
        let before = utxo.len();

        // Angreifer versucht owner's UTXO mit eigenem Schlüssel auszugeben
        let attack_tx = Transaction::new_transfer(
            vec![(fake_txid, 0)],
            vec![TxOutput { value: Amount::from_atl(9), address: attacker.address.into() }],
            Amount::from_atom(params.min_fee_atom),
            &attacker, // falscher Schlüssel
        );
        // attacker.public_key → attacker.address ≠ owner.address → Mismatch
        let err = executor.execute_tx(&attack_tx, 1).unwrap_err();
        assert!(
            matches!(err, ExecutionError::PubkeyAddressMismatch { .. }),
            "Expected PubkeyAddressMismatch, got {:?}", err
        );

        // UTXO muss nach Rollback noch da sein
        assert_eq!(utxo.len(), before);
        assert!(utxo.get(&op).is_some());

        // Zweiter Angriff: korrekter PublicKey aber manipulierte Signatur
        let fake_txid2 = Hash::sha256(b"owner_tx2");
        insert_utxo(&utxo, fake_txid2, 0, 10, owner.address);
        let before2 = utxo.len();

        let mut tampered = Transaction::new_transfer(
            vec![(fake_txid2, 0)],
            vec![TxOutput { value: Amount::from_atl(9), address: attacker.address.into() }],
            Amount::from_atom(params.min_fee_atom),
            &owner, // korrekter Schlüssel...
        );
        // ...aber Outputs manipulieren → txid ändert sich → Signatur ungültig
        tampered.outputs[0].value = Amount::from_atl(10);

        let err2 = executor.execute_tx(&tampered, 1).unwrap_err();
        assert!(
            matches!(err2, ExecutionError::SignatureInvalid { .. }),
            "Expected SignatureInvalid, got {:?}", err2
        );
        assert_eq!(utxo.len(), before2, "Tampered TX must not consume UTXOs");
    }

    #[test]
    fn test_execute_pq_quantum_transfer_succeeds() {
        use atlas_core::pq_crypto::PqKeyPair;
        let (params, utxo, executor) = make_executor();
        let sender   = PqKeyPair::generate().unwrap();
        let receiver = PqKeyPair::generate().unwrap();

        let fee       = params.min_fee_atom;
        let input_val = 1000u128;
        let out_val   = input_val - fee;

        let fund_txid = Hash::sha256(b"pq_funding_tx");
        let op = atlas_core::transaction::OutPoint { txid: fund_txid, index: 0 };
        utxo.restore_utxos(&[(op, crate::utxo::Utxo {
            value:        Amount::from_atom(input_val),
            address:      OutputAddress::Quantum(sender.address),
            block_height: 0,
            is_coinbase:  false,
        })]);

        // Gültige ML-DSA-65-signierte Transfer-TX
        let tx = Transaction::new_transfer_quantum(
            vec![(fund_txid, 0)],
            vec![TxOutput { value: Amount::from_atom(out_val), address: receiver.address.into() }],
            Amount::from_atom(fee),
            &sender,
        );
        executor.execute_tx(&tx, 1).expect("Valid PQ (ML-DSA-65) transfer must succeed");
        assert!(utxo.get(&op).is_none(), "Spent PQ UTXO must be gone");
        assert_eq!(utxo.balance_pq(&receiver.address).as_atom(), out_val);
    }

    #[test]
    fn test_execute_pq_tampered_signature_rejected() {
        use atlas_core::pq_crypto::PqKeyPair;
        let (params, utxo, executor) = make_executor();
        let sender   = PqKeyPair::generate().unwrap();
        let receiver = PqKeyPair::generate().unwrap();
        let fee       = params.min_fee_atom;
        let input_val = 1000u128;
        let out_val   = input_val - fee;

        let fund = Hash::sha256(b"pq_tamper_tx");
        let op = atlas_core::transaction::OutPoint { txid: fund, index: 0 };
        utxo.restore_utxos(&[(op, crate::utxo::Utxo {
            value:        Amount::from_atom(input_val),
            address:      OutputAddress::Quantum(sender.address),
            block_height: 0,
            is_coinbase:  false,
        })]);
        let before = utxo.len();

        // Korrekt signiert, danach Output manipuliert → txid ändert sich → Sig ungültig
        let mut tampered = Transaction::new_transfer_quantum(
            vec![(fund, 0)],
            vec![TxOutput { value: Amount::from_atom(out_val), address: receiver.address.into() }],
            Amount::from_atom(fee),
            &sender,
        );
        tampered.outputs[0].value = Amount::from_atom(out_val + 1);
        let err = executor.execute_tx(&tampered, 1).unwrap_err();
        assert!(matches!(err, ExecutionError::SignatureInvalid { .. }),
            "Tampered PQ tx must be rejected, got {:?}", err);
        assert_eq!(utxo.len(), before, "Tampered PQ tx must not consume UTXOs");
    }

    #[test]
    fn test_execute_pq_wrong_key_rejected() {
        use atlas_core::pq_crypto::PqKeyPair;
        let (params, utxo, executor) = make_executor();
        let owner    = PqKeyPair::generate().unwrap();
        let attacker = PqKeyPair::generate().unwrap();
        let fee       = params.min_fee_atom;
        let input_val = 1000u128;
        let out_val   = input_val - fee;

        let fund = Hash::sha256(b"pq_wrongkey_tx");
        let op = atlas_core::transaction::OutPoint { txid: fund, index: 0 };
        utxo.restore_utxos(&[(op, crate::utxo::Utxo {
            value:        Amount::from_atom(input_val),
            address:      OutputAddress::Quantum(owner.address),
            block_height: 0,
            is_coinbase:  false,
        })]);
        let before = utxo.len();

        // Angreifer signiert owner's UTXO mit eigenem PQ-Schlüssel → Adress-Mismatch
        let attack = Transaction::new_transfer_quantum(
            vec![(fund, 0)],
            vec![TxOutput { value: Amount::from_atom(out_val), address: attacker.address.into() }],
            Amount::from_atom(fee),
            &attacker,
        );
        let err = executor.execute_tx(&attack, 1).unwrap_err();
        assert!(matches!(err, ExecutionError::PubkeyAddressMismatch { .. }),
            "PQ tx signed with wrong key must be rejected, got {:?}", err);
        assert_eq!(utxo.len(), before, "Rejected PQ tx must not consume UTXOs");
        assert!(utxo.get(&op).is_some(), "Owner UTXO must survive rejected attack");
    }

    #[test]
    fn test_execute_value_mismatch_rolls_back_utxos() {
        let (params, utxo, executor) = make_executor();
        let sender = KeyPair::generate();
        let other  = Address([8u8; 20]);

        // Insert a non-coinbase UTXO owned by the keypair
        let fake_txid = Hash::sha256(b"fake_tx");
        let op = insert_utxo(&utxo, fake_txid, 0, 10, sender.address);
        let before = utxo.len();

        // TX: 100 ATL ausgeben von einem 10 ATL UTXO — korrekte Signatur, falsche Werte
        let bad_tx = Transaction::new_transfer(
            vec![(fake_txid, 0)],
            vec![TxOutput { value: Amount::from_atl(100), address: other.into() }],
            Amount::from_atom(params.min_fee_atom),
            &sender,
        );

        let err = executor.execute_tx(&bad_tx, 1).unwrap_err();
        assert!(matches!(err, ExecutionError::ValueMismatch { .. }),
            "Expected ValueMismatch, got {:?}", err);

        // UTXO nach Rollback wiederhergestellt
        assert_eq!(utxo.len(), before);
        assert!(utxo.get(&op).is_some());
    }

    #[test]
    fn test_state_root_deterministic() {
        let (_, _, executor) = make_executor();
        let miner  = Address([1u8; 20]);
        let prover = Address([2u8; 20]);
        let mut genesis = Block::genesis();
        genesis.transactions.push(Transaction::new_coinbase(
            0, Amount::from_atl(44), Amount::from_atl(19), miner, prover,
        ));
        genesis.header.merkle_root = genesis.compute_merkle_root();
        executor.execute(&genesis).unwrap();

        let root1 = executor.compute_state_root();
        let root2 = executor.compute_state_root();
        assert_eq!(root1, root2, "State root must be deterministic");
    }
}
