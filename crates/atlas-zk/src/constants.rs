//! MiMC-7 Rundkonstanten — deterministisch aus SHA-256 generiert.
//! Seed: "ATLAS-MiMC-7-v1-round-<i>" für Runde i.
//! Die Konstanten sind öffentlich und nicht geheim.

use ark_bn254::Fr;
use ark_ff::PrimeField;
use sha2::{Sha256, Digest};

pub const MIMC_ROUNDS: usize = 110;

pub fn mimc_constants() -> Vec<Fr> {
    (0..MIMC_ROUNDS).map(|i| {
        let mut h = Sha256::new();
        h.update(b"ATLAS-MiMC-7-v1-round-");
        h.update((i as u64).to_le_bytes());
        let bytes = h.finalize();
        Fr::from_le_bytes_mod_order(&bytes)
    }).collect()
}
