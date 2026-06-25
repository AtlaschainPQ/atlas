//! TX-Stamp: Mini Proof-of-Work pro Transaktion
//!
//! Ziel: 20–50 ms auf Consumer-Hardware
//! Verifikation: nahezu kostenlos (einzelner Hash-Check)
//! Spam-Schutz ohne hohe Gebühren

use serde::{Deserialize, Serialize};
use thiserror::Error;
use crate::hash::Hash;

/// Standard Schwierigkeit: erste N Bits müssen 0 sein
/// 16 Bits → ~65.536 Hashversuche im Schnitt (~20-50ms bei modernem CPU)
pub const TX_STAMP_DIFFICULTY_BITS: u32 = 16;

#[derive(Error, Debug)]
pub enum StampError {
    #[error("Stamp difficulty not met: got {got} leading zeros, need {need}")]
    DifficultyNotMet { got: u32, need: u32 },
    #[error("Stamp nonce exhausted after {0} attempts")]
    NonceExhausted(u64),
}

/// Mini-PoW Stempel für jede Transaktion
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxStamp {
    /// Nonce die Schwierigkeit erfüllt
    pub nonce: u64,
    /// Difficulty in führenden Null-Bits
    pub difficulty: u32,
    /// Resultierender Hash (zur schnellen Verifikation gecacht)
    pub hash: Hash,
}

impl TxStamp {
    /// Berechnet den Stamp-Hash: SHA256(tx_hash || nonce_le)
    fn compute_hash(tx_hash: &Hash, nonce: u64) -> Hash {
        let mut data = [0u8; 40];
        data[..32].copy_from_slice(&tx_hash.0);
        data[32..].copy_from_slice(&nonce.to_le_bytes());
        Hash::sha256(&data)
    }

    /// Mined den Stamp (sucht Nonce die difficulty erfüllt)
    pub fn mine(tx_hash: &Hash, difficulty: u32) -> Result<Self, StampError> {
        for nonce in 0u64..=u64::MAX {
            let hash = Self::compute_hash(tx_hash, nonce);
            if hash.leading_zeros() >= difficulty {
                return Ok(TxStamp { nonce, difficulty, hash });
            }
        }
        // Erreichbar nur wenn u64-Raum erschöpft — praktisch unmöglich
        Err(StampError::NonceExhausted(u64::MAX))
    }

    /// Verifiziert den Stamp vollständig in O(1)
    pub fn verify(&self, tx_hash: &Hash) -> Result<(), StampError> {
        let computed = Self::compute_hash(tx_hash, self.nonce);
        // Gecachten Hash prüfen
        if computed != self.hash {
            return Err(StampError::DifficultyNotMet { got: 0, need: self.difficulty });
        }
        let leading = computed.leading_zeros();
        if leading < self.difficulty {
            return Err(StampError::DifficultyNotMet { got: leading, need: self.difficulty });
        }
        Ok(())
    }

    /// Schnellverifikation: nur Hash prüfen, kein Neuberechnen des gecachten Werts
    pub fn quick_verify(&self, tx_hash: &Hash) -> bool {
        let computed = Self::compute_hash(tx_hash, self.nonce);
        computed == self.hash && computed.leading_zeros() >= self.difficulty
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stamp_mine_and_verify() {
        let tx_hash = Hash::sha256(b"test transaction data");
        let stamp = TxStamp::mine(&tx_hash, 12).expect("Mining failed");
        assert!(stamp.verify(&tx_hash).is_ok());
        assert!(stamp.quick_verify(&tx_hash));
        assert!(stamp.hash.leading_zeros() >= 12);
        println!("Stamp nonce: {}, leading zeros: {}", stamp.nonce, stamp.hash.leading_zeros());
    }

    #[test]
    fn test_stamp_tamper_detection() {
        let tx_hash = Hash::sha256(b"real transaction");
        let other   = Hash::sha256(b"other transaction");
        let stamp   = TxStamp::mine(&tx_hash, 12).unwrap();
        // Stamp für andere TX ungültig
        assert!(stamp.verify(&other).is_err());
        assert!(!stamp.quick_verify(&other));
    }

    #[test]
    fn test_stamp_wrong_nonce_detected() {
        let tx_hash = Hash::sha256(b"test");
        let stamp   = TxStamp::mine(&tx_hash, 10).unwrap();
        // Manipulierter Stamp
        let tampered = TxStamp { nonce: stamp.nonce + 1, ..stamp.clone() };
        assert!(tampered.verify(&tx_hash).is_err());
    }

    #[test]
    fn test_stamp_hash_consistency() {
        // verify() und quick_verify() müssen identisch urteilen
        let tx_hash = Hash::sha256(b"consistency test");
        let stamp   = TxStamp::mine(&tx_hash, 10).unwrap();
        assert_eq!(
            stamp.verify(&tx_hash).is_ok(),
            stamp.quick_verify(&tx_hash),
        );
    }
}
