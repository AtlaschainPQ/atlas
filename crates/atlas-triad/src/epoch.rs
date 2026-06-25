//! Epoch-Management für TRIAD
//!
//! Alle 2016 Blöcke (~2 Wochen) rotiert das Dataset.
//! Die Rotation erneuert: Dataset, Permutation, Seeds, Cache-Tabellen.

use atlas_core::hash::Hash;
use serde::{Deserialize, Serialize};

/// Epochen-Länge in Blöcken (~2 Wochen bei 10-min Blockzeit)
pub const EPOCH_LENGTH: u64 = 2016;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EpochSeed {
    pub epoch:       u32,
    /// Deterministic seed aus Block-Hashes berechnet
    pub seed_hash:   Hash,
    /// Permutations-Seed (für Dataset-Shuffle)
    pub permutation: Hash,
    /// Cache-Seed (für Lookup-Tabellen)
    pub cache_seed:  Hash,
}

impl EpochSeed {
    /// Berechnet den EpochSeed für eine gegebene Epoch
    pub fn for_epoch(epoch: u32) -> Self {
        // Seed wird durch wiederholtes Hashing der Epochen-Nummer erzeugt
        let epoch_bytes = epoch.to_le_bytes();
        let seed_hash = Hash::sha256(&[
            b"ATLAS-TRIAD-v1:epoch:",
            epoch_bytes.as_ref(),
        ].concat());

        // Permutation: Hash des Seeds mit einem anderen Prefix
        let permutation = Hash::sha256(&[
            b"ATLAS-TRIAD-v1:perm:",
            seed_hash.as_bytes().as_ref(),
        ].concat());

        // Cache-Seed: Hash von Seed + Permutation
        let cache_input = [seed_hash.as_bytes().as_ref(), permutation.as_bytes().as_ref()].concat();
        let cache_seed  = Hash::sha256(&cache_input);

        EpochSeed { epoch, seed_hash, permutation, cache_seed }
    }

    /// Aktualisiert den Seed durch einen neuen Block-Hash (Kettenentropie)
    pub fn update_with_block(&mut self, block_hash: &Hash) {
        let input = [
            self.seed_hash.as_bytes().as_ref(),
            block_hash.as_bytes().as_ref(),
        ].concat();
        self.seed_hash = Hash::sha256(&input);
    }
}

#[derive(Clone, Debug)]
pub struct Epoch {
    pub number:    u32,
    pub seed:      EpochSeed,
    pub start_block: u64,
}

impl Epoch {
    pub fn from_height(height: u64) -> Self {
        let number = (height / EPOCH_LENGTH) as u32;
        Epoch {
            number,
            seed: EpochSeed::for_epoch(number),
            start_block: number as u64 * EPOCH_LENGTH,
        }
    }

    pub fn is_rotation_block(height: u64) -> bool {
        height.is_multiple_of(EPOCH_LENGTH) && height > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_epoch_rotation() {
        let e0 = Epoch::from_height(0);
        let e1 = Epoch::from_height(EPOCH_LENGTH);
        assert_eq!(e0.number, 0);
        assert_eq!(e1.number, 1);
        assert_ne!(e0.seed.seed_hash, e1.seed.seed_hash);
    }

    #[test]
    fn test_deterministic_seed() {
        let s1 = EpochSeed::for_epoch(42);
        let s2 = EpochSeed::for_epoch(42);
        assert_eq!(s1.seed_hash, s2.seed_hash);
        assert_eq!(s1.permutation, s2.permutation);
    }
}
