//! TRIAD Verifier (Rust — Source of Truth)
//!
//! Rust entscheidet über Gültigkeit.
//! C++ liefert nur Mining-Kandidaten.
//! Diese Trennung ist die "Determinism Firewall".

use atlas_core::hash::Hash;
use atlas_core::block::BlockHeader;
use crate::dataset::{Dataset, DatasetConfig};
use crate::epoch::{EpochSeed, Epoch};
use crate::miner::TriadMiner;
use crate::network_entropy::NetworkEntropy;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum VerifyError {
    #[error("Block hash does not meet target difficulty")]
    DifficultyNotMet,
    #[error("Mix hash mismatch: expected {expected:?}, got {got:?}")]
    MixHashMismatch { expected: Hash, got: Hash },
    #[error("Wrong epoch: block epoch {block_epoch}, expected {expected}")]
    WrongEpoch { block_epoch: u32, expected: u32 },
    #[error("Dataset not available for epoch {0}")]
    DatasetUnavailable(u32),
}

pub struct TriadVerifier {
    dataset: Dataset,
    entropy: NetworkEntropy,
}

impl TriadVerifier {
    pub fn new(epoch_seed: &EpochSeed, entropy: NetworkEntropy, test_mode: bool) -> Self {
        let config = if test_mode {
            DatasetConfig::test()
        } else {
            DatasetConfig::production()
        };
        TriadVerifier {
            dataset: Dataset::new_for_verification(epoch_seed, config),
            entropy,
        }
    }

    /// Verifiziert einen Block vollständig
    /// O(ACCESSES) — sehr schnell, kein volles Dataset nötig
    pub fn verify(
        &self,
        header:   &BlockHeader,
        nonce:    u64,
        mix_hash: &Hash,
    ) -> Result<Hash, VerifyError> {
        let expected_epoch = Epoch::from_height(header.height).number;
        if header.epoch != expected_epoch {
            return Err(VerifyError::WrongEpoch {
                block_epoch: header.epoch,
                expected:    expected_epoch,
            });
        }

        let item_count = self.dataset.config.item_count;
        let prefix     = header.mining_prefix();

        // Use self.dataset — no new Dataset allocation per verify call
        let (block_hash, computed_mix) =
            TriadMiner::compute_hash(&self.dataset, &prefix, nonce, item_count);

        // Mix-Hash verifizieren
        if &computed_mix != mix_hash {
            return Err(VerifyError::MixHashMismatch {
                expected: computed_mix,
                got:      *mix_hash,
            });
        }

        // Netzwerk-Entropie mischen
        let final_hash = self.entropy.mix_with_header(&block_hash);

        // Difficulty prüfen
        let target = header.target();
        if !final_hash.meets_target(&target) {
            return Err(VerifyError::DifficultyNotMet);
        }

        Ok(final_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use atlas_core::block::Block;

    #[test]
    fn test_verifier_wrong_epoch_rejected() {
        let seed     = EpochSeed::for_epoch(0);
        let entropy  = NetworkEntropy::new();
        let verifier = TriadVerifier::new(&seed, entropy, true);

        let mut header = Block::genesis().header;
        header.epoch  = 99; // wrong epoch for height 0
        let mix_hash   = Hash::zero();
        let err = verifier.verify(&header, 0, &mix_hash).unwrap_err();
        assert!(matches!(err, VerifyError::WrongEpoch { .. }));
    }

    #[test]
    fn test_verifier_accepts_valid_hash() {
        use crate::miner::TriadMiner;
        use std::sync::{Arc, atomic::AtomicBool};

        let seed     = EpochSeed::for_epoch(0);
        let verifier = TriadVerifier::new(&seed, NetworkEntropy::new(), true);

        // Miner and verifier share the same epoch/config
        let miner = TriadMiner::new(
            Dataset::new_for_verification(&seed, DatasetConfig::test()),
            NetworkEntropy::new(),
        );

        // 0x200fffff encodes target[0..3] = [0x0f, 0xff, 0xff, 0] — easy enough for a unit test
        let mut header = Block::genesis().header;
        header.bits    = 0x200f_ffff;
        let target     = header.target();

        let stop   = Arc::new(AtomicBool::new(false));
        let result = miner.mine(&header, &target, 0, &stop)
            .expect("Should find a solution with easy target");

        // The verifier must accept exactly what the miner produced
        let verified = verifier.verify(&header, result.nonce, &result.mix_hash);
        assert!(verified.is_ok(), "Verifier must accept miner result: {:?}", verified);
    }

    #[test]
    fn test_verifier_mix_hash_mismatch() {
        let seed     = EpochSeed::for_epoch(0);
        let entropy  = NetworkEntropy::new();
        let verifier = TriadVerifier::new(&seed, entropy, true);
        let header   = Block::genesis().header;
        let wrong_mix = Hash::sha256(b"wrong");
        let err = verifier.verify(&header, 0, &wrong_mix).unwrap_err();
        assert!(matches!(err, VerifyError::MixHashMismatch { .. }));
    }
}
