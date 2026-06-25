//! Block- und Transaktions-Validierung
//!
//! Zustandsmaschine pro Block:
//! 1. Verify PoW
//! 2. Verify Timestamp
//! 3. Verify Proof
//! 4. Apply State Transition
//! 5. Update Root
//! 6. Distribute Rewards

use atlas_core::block::{Block, BlockHeader};
use atlas_core::hash::Hash;
use atlas_core::transaction::{OutPoint, Transaction};
use atlas_core::amount::Amount;
use crate::params::ConsensusParams;
use crate::reward::RewardSchedule;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum ValidationError {
    // Block-Fehler
    #[error("Block height mismatch: expected {expected}, got {got}")]
    HeightMismatch { expected: u64, got: u64 },
    #[error("Previous hash mismatch")]
    PrevHashMismatch,
    #[error("Merkle root mismatch: computed {computed:?}, header {header:?}")]
    MerkleRootMismatch { computed: Hash, header: Hash },
    #[error("Timestamp too far in future: {timestamp}, max allowed: {max}")]
    TimestampTooFuture { timestamp: u64, max: u64 },
    #[error("Timestamp not after parent: {timestamp} <= {parent}")]
    TimestampNotAfterParent { timestamp: u64, parent: u64 },
    #[error("PoW hash does not meet target")]
    PoWFailed,
    #[error("Too many transactions: {count} > {max}")]
    TooManyTransactions { count: usize, max: usize },
    #[error("Too many settlement batches: {count} > {max}")]
    TooManyBatches { count: u8, max: u8 },
    #[error("Block has no coinbase transaction")]
    MissingCoinbase,
    #[error("Coinbase is not the first transaction")]
    CoinbaseNotFirst,
    #[error("Multiple coinbase transactions in block")]
    MultipleCoinbase,
    #[error("Coinbase reward exceeds maximum: {reward} > {max_allowed}")]
    CoinbaseOverpay { reward: Amount, max_allowed: Amount },
    #[error("Wrong block version: {0}")]
    WrongVersion(u32),

    // Transaktions-Fehler
    #[error("Transaction has no inputs")]
    TxNoInputs,
    #[error("Transaction has no outputs")]
    TxNoOutputs,
    #[error("Transaction fee below minimum: {fee} < {min}")]
    FeeTooLow { fee: u128, min: u128 },
    #[error("Transaction fee above cap: {fee} > {max}")]
    FeeAboveCap { fee: u128, max: u128 },
    #[error("Transaction stamp invalid")]
    InvalidStamp,
    #[error("Transaction stamp missing")]
    MissingStamp,
    #[error("Double spend detected: {0:?}")]
    DoubleSpend(OutPoint),
    #[error("Output value overflow")]
    OutputOverflow,
    #[error("Checkpoint mismatch: {0}")]
    CheckpointMismatch(String),
    #[error("ZK proof invalid: {0}")]
    ZkProofInvalid(String),
}

pub struct BlockValidator<'a> {
    params: &'a ConsensusParams,
}

impl<'a> BlockValidator<'a> {
    pub fn new(params: &'a ConsensusParams) -> Self {
        BlockValidator { params }
    }

    /// Validiert den Header eines Nicht-Genesis-Blocks
    pub fn validate_header(
        &self,
        header:   &BlockHeader,
        parent:   &BlockHeader,
        now_secs: u64,
    ) -> Result<(), ValidationError> {
        if header.version == 0 {
            return Err(ValidationError::WrongVersion(header.version));
        }

        // Höhe muss exakt 1 mehr als Parent sein
        let expected_height = parent.height + 1;
        if header.height != expected_height {
            return Err(ValidationError::HeightMismatch {
                expected: expected_height,
                got:      header.height,
            });
        }

        // Vorgänger-Hash
        if header.prev_hash != parent.hash() {
            return Err(ValidationError::PrevHashMismatch);
        }

        // Timestamp: nicht zu weit in der Zukunft
        let max_time = now_secs.saturating_add(self.params.max_future_time_secs);
        if header.timestamp > max_time {
            return Err(ValidationError::TimestampTooFuture {
                timestamp: header.timestamp,
                max:       max_time,
            });
        }

        // Timestamp: muss strikt nach Parent liegen
        if header.timestamp <= parent.timestamp {
            return Err(ValidationError::TimestampNotAfterParent {
                timestamp: header.timestamp,
                parent:    parent.timestamp,
            });
        }

        Ok(())
    }

    /// Validiert alle Transaktionen im Block (strukturell, ohne UTXO-Lookups)
    pub fn validate_transactions(&self, block: &Block) -> Result<(), ValidationError> {
        if block.transactions.is_empty() {
            return Err(ValidationError::MissingCoinbase);
        }
        if block.transactions.len() > self.params.max_txs_per_block {
            return Err(ValidationError::TooManyTransactions {
                count: block.transactions.len(),
                max:   self.params.max_txs_per_block,
            });
        }

        // Erste TX muss Coinbase sein
        if !block.transactions[0].is_coinbase() {
            return Err(ValidationError::CoinbaseNotFirst);
        }

        // Keine weiteren Coinbase-TXs
        let extra_coinbases = block.transactions[1..].iter()
            .filter(|tx| tx.is_coinbase())
            .count();
        if extra_coinbases > 0 {
            return Err(ValidationError::MultipleCoinbase);
        }

        // Coinbase-Reward darf Maximum nicht überschreiten
        let schedule        = RewardSchedule::new(self.params);
        let expected_reward = schedule.block_reward(block.height(), &block.transactions);
        let coinbase_total  = block.transactions[0].total_output();
        if coinbase_total > expected_reward.total {
            return Err(ValidationError::CoinbaseOverpay {
                reward:      coinbase_total,
                max_allowed: expected_reward.total,
            });
        }

        // Normale Transaktionen validieren
        let mut seen_outpoints = std::collections::HashSet::new();
        for tx in block.transactions[1..].iter() {
            self.validate_tx(tx, &mut seen_outpoints)?;
        }

        Ok(())
    }

    fn validate_tx(
        &self,
        tx:             &Transaction,
        seen_outpoints: &mut std::collections::HashSet<OutPoint>,
    ) -> Result<(), ValidationError> {
        if tx.inputs.is_empty()  { return Err(ValidationError::TxNoInputs); }
        if tx.outputs.is_empty() { return Err(ValidationError::TxNoOutputs); }

        let fee = tx.fee.as_atom();
        if fee < self.params.min_fee_atom {
            return Err(ValidationError::FeeTooLow { fee, min: self.params.min_fee_atom });
        }
        if fee > self.params.max_fee_atom {
            return Err(ValidationError::FeeAboveCap { fee, max: self.params.max_fee_atom });
        }

        // TX-Stamp ist Pflicht für alle Nicht-Coinbase Transaktionen
        match &tx.stamp {
            None        => return Err(ValidationError::MissingStamp),
            Some(stamp) => {
                if !stamp.quick_verify(&tx.txid()) {
                    return Err(ValidationError::InvalidStamp);
                }
            }
        }

        // Double-Spend innerhalb desselben Blocks
        // SettlementBid/L2ForcedTx haben Pseudo-Inputs (txid=0) →
        // kein UTXO-Lookup nötig, kein Double-Spend-Check zwischen ihnen
        if !tx.has_pseudo_inputs() {
            for input in &tx.inputs {
                let op = OutPoint { txid: input.prev_txid, index: input.prev_index };
                if !seen_outpoints.insert(op) {
                    return Err(ValidationError::DoubleSpend(op));
                }
            }
        }

        // Output-Overflow-Check
        let mut total_out = Amount::ZERO;
        for output in &tx.outputs {
            total_out = total_out.checked_add(output.value)
                .map_err(|_| ValidationError::OutputOverflow)?;
        }

        Ok(())
    }

    /// Vollständige Block-Validierung (Header + Transaktionen + Merkle Root + Batches)
    pub fn validate_block(
        &self,
        block:    &Block,
        parent:   &BlockHeader,
        now_secs: u64,
    ) -> Result<(), ValidationError> {
        self.validate_header(&block.header, parent, now_secs)?;
        self.validate_transactions(block)?;

        // Merkle Root verifizieren
        let computed_merkle = block.compute_merkle_root();
        if computed_merkle != block.header.merkle_root {
            return Err(ValidationError::MerkleRootMismatch {
                computed: computed_merkle,
                header:   block.header.merkle_root,
            });
        }

        // Batch-Limit
        if block.header.batch_count > self.params.max_batches_per_block {
            return Err(ValidationError::TooManyBatches {
                count: block.header.batch_count,
                max:   self.params.max_batches_per_block,
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use atlas_core::block::Block;
    use atlas_core::crypto::Address;
    use atlas_core::amount::Amount;
    use atlas_core::transaction::Transaction;

    fn make_validator() -> (ConsensusParams, BlockValidator<'static>) {
        let params = Box::leak(Box::new(ConsensusParams::mainnet()));
        let v = BlockValidator::new(params);
        (ConsensusParams::mainnet(), v)
    }

    #[test]
    fn test_validate_header_height_mismatch() {
        let (_, validator) = make_validator();
        let genesis  = Block::genesis();
        let mut next = Block::genesis();
        next.header.height = 5; // falsch, muss 1 sein
        next.header.prev_hash = genesis.hash();
        next.header.timestamp = genesis.header.timestamp + 1;
        let err = validator.validate_header(&next.header, &genesis.header, u64::MAX);
        assert!(matches!(err, Err(ValidationError::HeightMismatch { expected: 1, got: 5 })));
    }

    #[test]
    fn test_validate_header_prev_hash_mismatch() {
        let (_, validator) = make_validator();
        let genesis = Block::genesis();
        let mut next = Block::genesis();
        next.header.height    = 1;
        next.header.prev_hash = Hash::sha256(b"wrong"); // falscher prev_hash
        next.header.timestamp = genesis.header.timestamp + 1;
        assert!(matches!(
            validator.validate_header(&next.header, &genesis.header, u64::MAX),
            Err(ValidationError::PrevHashMismatch)
        ));
    }

    #[test]
    fn test_validate_header_future_timestamp() {
        let (_, validator) = make_validator();
        let genesis = Block::genesis();
        let mut next = Block::genesis();
        next.header.height    = 1;
        next.header.prev_hash = genesis.hash();
        next.header.timestamp = genesis.header.timestamp + 1;
        // now_secs sehr weit in der Vergangenheit → Block liegt in Zukunft
        let err = validator.validate_header(&next.header, &genesis.header, 0);
        assert!(matches!(err, Err(ValidationError::TimestampTooFuture { .. })));
    }

    #[test]
    fn test_validate_header_timestamp_not_after_parent() {
        let (_, validator) = make_validator();
        let genesis = Block::genesis();
        let mut next = Block::genesis();
        next.header.height    = 1;
        next.header.prev_hash = genesis.hash();
        next.header.timestamp = genesis.header.timestamp; // gleich, nicht danach
        let err = validator.validate_header(&next.header, &genesis.header, u64::MAX);
        assert!(matches!(err, Err(ValidationError::TimestampNotAfterParent { .. })));
    }

    #[test]
    fn test_validate_block_missing_coinbase() {
        let (_, validator) = make_validator();
        let genesis = Block::genesis();
        let mut next = Block {
            header:       genesis.header.clone(),
            transactions: vec![], // keine Coinbase!
            agg_proof:    vec![],
        };
        next.header.height    = 1;
        next.header.prev_hash = genesis.hash();
        next.header.timestamp = genesis.header.timestamp + 1;
        next.header.merkle_root = next.compute_merkle_root();
        let err = validator.validate_block(&next, &genesis.header, u64::MAX);
        assert!(matches!(err, Err(ValidationError::MissingCoinbase)));
    }

    #[test]
    fn test_validate_block_coinbase_overpay() {
        let (_, validator) = make_validator();
        let genesis   = Block::genesis();
        let miner     = Address([1u8; 20]);
        let prover    = Address([2u8; 20]);
        // Coinbase zahlt 1000 ATL, erlaubt wäre 64 ATL
        let coinbase = Transaction::new_coinbase(1, Amount::from_atl(999), Amount::from_atl(1), miner, prover);
        let mut next = Block {
            header:       genesis.header.clone(),
            transactions: vec![coinbase],
            agg_proof:    vec![],
        };
        next.header.height    = 1;
        next.header.prev_hash = genesis.hash();
        next.header.timestamp = genesis.header.timestamp + 1;
        next.header.merkle_root = next.compute_merkle_root();
        let err = validator.validate_block(&next, &genesis.header, u64::MAX);
        assert!(matches!(err, Err(ValidationError::CoinbaseOverpay { .. })));
    }

    #[test]
    fn test_validate_block_merkle_root_mismatch() {
        let (_, validator) = make_validator();
        let genesis   = Block::genesis();
        let miner     = Address([1u8; 20]);
        let prover    = Address([2u8; 20]);
        let coinbase  = Transaction::new_coinbase(1, Amount::from_atl(44), Amount::from_atl(19), miner, prover);
        let mut next  = Block {
            header:       genesis.header.clone(),
            transactions: vec![coinbase],
            agg_proof:    vec![],
        };
        next.header.height    = 1;
        next.header.prev_hash = genesis.hash();
        next.header.timestamp = genesis.header.timestamp + 1;
        next.header.merkle_root = Hash::sha256(b"wrong"); // absichtlich falsch
        let err = validator.validate_block(&next, &genesis.header, u64::MAX);
        assert!(matches!(err, Err(ValidationError::MerkleRootMismatch { .. })));
    }

    #[test]
    fn test_validate_block_valid_coinbase_only() {
        let (_, validator) = make_validator();
        let genesis  = Block::genesis();
        let miner    = Address([1u8; 20]);
        let prover   = Address([2u8; 20]);
        let coinbase = Transaction::new_coinbase(1, Amount::from_atl(44), Amount::from_atl(19), miner, prover);
        let mut next = Block {
            header:       genesis.header.clone(),
            transactions: vec![coinbase],
            agg_proof:    vec![],
        };
        next.header.height      = 1;
        next.header.prev_hash   = genesis.hash();
        next.header.timestamp   = genesis.header.timestamp + 1;
        next.header.merkle_root = next.compute_merkle_root();
        assert!(
            validator.validate_block(&next, &genesis.header, u64::MAX).is_ok(),
            "Valid block with coinbase should pass validation"
        );
    }
}
