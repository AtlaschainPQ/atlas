use std::fmt;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

pub const ZERO_HASH: Hash = Hash([0u8; 32]);

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    pub fn zero() -> Self { ZERO_HASH }

    pub fn is_zero(&self) -> bool { self.0 == [0u8; 32] }

    /// SHA-256(SHA-256(data)) — Bitcoin-style double hash
    pub fn double_sha256(data: &[u8]) -> Self {
        let first  = Sha256::digest(data);
        let second = Sha256::digest(first);
        Hash(second.into())
    }

    /// Single SHA-256
    pub fn sha256(data: &[u8]) -> Self {
        Hash(Sha256::digest(data).into())
    }

    /// BLAKE3 — für TRIAD interne Berechnungen
    pub fn blake3(data: &[u8]) -> Self {
        Hash(*blake3::hash(data).as_bytes())
    }

    pub fn as_bytes(&self) -> &[u8; 32] { &self.0 }

    pub fn as_hex(&self) -> String { hex::encode(self.0) }

    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(s)?;
        if bytes.len() != 32 {
            return Err(hex::FromHexError::InvalidStringLength);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Hash(arr))
    }

    /// Zählt führende Null-Bits (für Difficulty-Check)
    pub fn leading_zeros(&self) -> u32 {
        let mut count = 0u32;
        for byte in &self.0 {
            let z = byte.leading_zeros();
            count += z;
            if z < 8 { break; }
        }
        count
    }

    /// Vergleiche mit Target: true wenn hash <= target (big-endian)
    pub fn meets_target(&self, target: &[u8; 32]) -> bool {
        self.0 <= *target
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &self.as_hex()[..16])
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash({})", self.as_hex())
    }
}

impl Default for Hash {
    fn default() -> Self { ZERO_HASH }
}

/// Berechnet den Merkle-Root aus einer Liste von Hashes
/// Leere Liste → ZERO_HASH; einzelner Hash → selbst
pub fn merkle_root(hashes: &[Hash]) -> Hash {
    if hashes.is_empty() {
        return ZERO_HASH;
    }
    if hashes.len() == 1 {
        return hashes[0];
    }

    let mut layer = hashes.to_vec();
    while layer.len() > 1 {
        if !layer.len().is_multiple_of(2) {
            layer.push(*layer.last().unwrap());
        }
        layer = layer.chunks(2).map(|pair| {
            let mut data = [0u8; 64];
            data[..32].copy_from_slice(&pair[0].0);
            data[32..].copy_from_slice(&pair[1].0);
            Hash::double_sha256(&data)
        }).collect();
    }
    layer[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_leading_zeros() {
        let mut h = ZERO_HASH;
        h.0[0] = 0x0f;
        assert_eq!(h.leading_zeros(), 4);

        h.0[0] = 0x00;
        h.0[1] = 0x80;
        assert_eq!(h.leading_zeros(), 8);

        // Alle Nullen = 256 führende Nullbits
        assert_eq!(ZERO_HASH.leading_zeros(), 256);
    }

    #[test]
    fn test_merkle_root_single() {
        let h = Hash::sha256(b"test");
        assert_eq!(merkle_root(&[h]), h);
    }

    #[test]
    fn test_merkle_root_empty() {
        assert_eq!(merkle_root(&[]), ZERO_HASH);
    }

    #[test]
    fn test_merkle_root_two() {
        let h1 = Hash::sha256(b"a");
        let h2 = Hash::sha256(b"b");
        let root = merkle_root(&[h1, h2]);
        // Muss deterministisch sein
        assert_eq!(root, merkle_root(&[h1, h2]));
        // Muss sich von einzelnen Hashes unterscheiden
        assert_ne!(root, h1);
        assert_ne!(root, h2);
    }

    #[test]
    fn test_merkle_root_odd_count() {
        // Ungerade Anzahl: letzter Hash wird dupliziert
        let hashes: Vec<Hash> = (0..3).map(|i| Hash::sha256(&[i])).collect();
        let root = merkle_root(&hashes);
        assert_ne!(root, ZERO_HASH);
        // Ergebnis muss deterministisch sein
        assert_eq!(root, merkle_root(&hashes));
    }

    #[test]
    fn test_meets_target() {
        let mut target = [0xff; 32];
        target[0] = 0x0f;  // 4 führende Nullbits nötig

        // Hash mit 5 führenden Nullbits → erfüllt target
        let mut low_hash = ZERO_HASH;
        low_hash.0[0] = 0x07;  // 5 führende Nullbits
        assert!(low_hash.meets_target(&target));

        // Hash mit 3 führenden Nullbits → erfüllt target nicht
        let mut high_hash = ZERO_HASH;
        high_hash.0[0] = 0x1f;  // 3 führende Nullbits
        assert!(!high_hash.meets_target(&target));
    }

    #[test]
    fn test_double_sha256_deterministic() {
        let h1 = Hash::double_sha256(b"atlas");
        let h2 = Hash::double_sha256(b"atlas");
        assert_eq!(h1, h2);
        assert_ne!(h1, Hash::sha256(b"atlas"));
    }

    #[test]
    fn test_hex_roundtrip() {
        let h   = Hash::sha256(b"roundtrip");
        let hex = h.as_hex();
        let h2  = Hash::from_hex(&hex).unwrap();
        assert_eq!(h, h2);
    }
}
