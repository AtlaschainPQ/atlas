//! TRIAD Mining-Kern (Rust-Implementierung)
//!
//! In Produktion: C++ Engine übernimmt den inner loop via FFI.
//! Rust verifiziert immer das Ergebnis — Determinism Firewall.

use atlas_core::hash::Hash;
use atlas_core::block::BlockHeader;
use sha2::{Sha256, Digest};
use sha3::Sha3_256;
use crate::dataset::{Dataset, ACCESSES, ITEM_SIZE};
use crate::network_entropy::NetworkEntropy;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Ergebnis eines erfolgreichen Mining-Vorgangs
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MineResult {
    pub nonce:       u64,
    pub block_hash:  Hash,
    pub mix_hash:    Hash,
    pub hashrate:    f64, // Hashes/Sekunde
}

pub struct TriadMiner {
    dataset:  Dataset,
    entropy:  NetworkEntropy,
}

impl TriadMiner {
    pub fn new(dataset: Dataset, entropy: NetworkEntropy) -> Self {
        TriadMiner { dataset, entropy }
    }

    /// Hauptfunktion: Mining mit TRIAD Algorithmus
    /// stop_flag: kann von außen gesetzt werden um Mining zu stoppen
    pub fn mine(
        &self,
        header:     &BlockHeader,
        target:     &[u8; 32],
        start_nonce: u64,
        stop_flag:  &Arc<AtomicBool>,
    ) -> Option<MineResult> {
        let item_count = self.dataset.config.item_count;
        let prefix     = header.mining_prefix();
        let start      = std::time::Instant::now();
        let mut hashes = 0u64;

        let mut nonce = start_nonce;
        loop {
            if stop_flag.load(Ordering::Relaxed) { return None; }

            let (block_hash, mix_hash) = self.triad_hash(&prefix, nonce, item_count);

            // Netzwerk-Entropie mischen
            let final_hash = self.entropy.mix_with_header(&block_hash);

            if final_hash.meets_target(target) {
                let elapsed   = start.elapsed().as_secs_f64();
                let hashrate   = if elapsed > 0.0 { hashes as f64 / elapsed } else { 0.0 };
                return Some(MineResult {
                    nonce,
                    block_hash: final_hash,
                    mix_hash,
                    hashrate,
                });
            }

            hashes += 1;
            nonce   = nonce.wrapping_add(1);
            if nonce == start_nonce { return None; } // overflow
        }
    }

    /// TRIAD Hash für einen Nonce
    /// Memory Bandwidth × Cache Dependency × Diffusion
    pub fn triad_hash(
        &self,
        header_prefix: &[u8],
        nonce:         u64,
        item_count:    usize,
    ) -> (Hash, Hash) {
        Self::compute_hash(&self.dataset, header_prefix, nonce, item_count)
    }

    /// Pure dataset-independent TRIAD computation.
    /// Called by both TriadMiner and TriadVerifier to avoid code duplication
    /// and to allow the verifier to use its pre-built dataset without creating a new one.
    pub fn compute_hash(
        dataset:       &Dataset,
        header_prefix: &[u8],
        nonce:         u64,
        item_count:    usize,
    ) -> (Hash, Hash) {
        // Step 1: Seed from header prefix + nonce
        let seed = {
            let mut data = header_prefix.to_vec();
            data.extend_from_slice(&nonce.to_le_bytes());
            Sha256::digest(&data)
        };

        // Step 2: Initial mix from seed (64 bytes: SHA256 || SHA3-256)
        let mut mix = [0u8; ITEM_SIZE];
        mix[..32].copy_from_slice(&seed);
        let h2 = Sha3_256::digest(seed);
        mix[32..].copy_from_slice(&h2);

        // Step 3: Memory-hard dataset lookups (data-dependent access pattern)
        for i in 0..ACCESSES {
            let idx_raw = u64::from_le_bytes(mix[..8].try_into().unwrap()) as usize;
            let idx     = (idx_raw ^ (i * 0x9e3779b9)) % item_count;

            let dataset_item = dataset.get_item(idx);

            // FNV-like XOR-mix
            for j in 0..ITEM_SIZE {
                mix[j] = mix[j].wrapping_mul(0xfe).wrapping_add(dataset_item[j]);
            }

            // Periodic SHA round for diffusion
            if i % 8 == 7 {
                let h = Sha256::digest(&mix[..32]);
                mix[..32].copy_from_slice(&h);
            }
        }

        let mix_hash = Hash::sha256(&mix);

        // Step 4: Final hash = double-SHA256(seed || mix_hash)
        let mut final_input = [0u8; 64];
        final_input[..32].copy_from_slice(&seed);
        final_input[32..].copy_from_slice(mix_hash.as_bytes());
        let block_hash = Hash::double_sha256(&final_input);

        (block_hash, mix_hash)
    }

    /// Batch-Mining auf mehreren Threads (Rayon)
    pub fn mine_parallel(
        &self,
        header:     &BlockHeader,
        target:     &[u8; 32],
        thread_count: usize,
        stop_flag:  Arc<AtomicBool>,
    ) -> Option<MineResult> {
        let result = Arc::new(parking_lot::Mutex::new(None::<MineResult>));
        let nonce_range = u64::MAX / thread_count as u64;

        std::thread::scope(|s| {
            for t in 0..thread_count {
                let start_nonce = t as u64 * nonce_range;
                let stop = stop_flag.clone();
                let result = result.clone();
                s.spawn(move || {
                    if let Some(r) = self.mine(header, target, start_nonce, &stop) {
                        stop.store(true, Ordering::Relaxed);
                        *result.lock() = Some(r);
                    }
                });
            }
        });

        Arc::try_unwrap(result).ok()?.into_inner()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::epoch::EpochSeed;
    use crate::dataset::{DatasetConfig, DATASET_ITEM_COUNT_TEST};
    use atlas_core::block::Block;

    #[test]
    fn test_triad_hash_deterministic() {
        let seed    = EpochSeed::for_epoch(0);
        let config  = DatasetConfig::test();
        let dataset = Dataset::new_for_verification(&seed, config);
        let entropy = NetworkEntropy::new();
        let miner   = TriadMiner::new(dataset, entropy);
        let prefix  = b"test_header_prefix".to_vec();

        let (h1, _) = miner.triad_hash(&prefix, 42, DATASET_ITEM_COUNT_TEST);
        let (h2, _) = miner.triad_hash(&prefix, 42, DATASET_ITEM_COUNT_TEST);
        assert_eq!(h1, h2, "TRIAD must be deterministic");
    }

    #[test]
    fn test_mine_low_difficulty() {
        let seed    = EpochSeed::for_epoch(0);
        let config  = DatasetConfig::test();
        let dataset = Dataset::new_for_verification(&seed, config);
        let entropy = NetworkEntropy::new();
        let miner   = TriadMiner::new(dataset, entropy);
        let genesis  = Block::genesis();
        let stop     = Arc::new(AtomicBool::new(false));

        // Sehr niedriges Target für schnellen Test: nur 4 führende Null-Bits
        let mut easy_target = [0xffu8; 32];
        easy_target[0] = 0x0f;

        let result = miner.mine(&genesis.header, &easy_target, 0, &stop);
        assert!(result.is_some(), "Should find solution with easy target");
        println!("Found nonce: {:?}", result.map(|r| r.nonce));
    }
}
