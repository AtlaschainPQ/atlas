//! Post-Quantum Kryptographie für ATLAS
//!
//! Implementiert ML-DSA-65 (CRYSTALS-Dilithium3) gemäß NIST FIPS 204.
//! Sicherheitsniveau: 192-Bit klassisch, 128-Bit post-quantum (Level 3).
//!
//! Schlüsselgrößen:
//!   Public Key:  1952 Bytes
//!   Secret Key:  4032 Bytes
//!   Signatur:    3309 Bytes (vs. 64 Bytes bei ECDSA)
//!
//! Adressen: ATLQ:<40 hex> (20 Bytes = SHA256(pk)[..20])
//! Unterscheidbar von klassischen ATL: Adressen durch den Präfix.

use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Signer, Verifier};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Sha256, Digest};
use thiserror::Error;
use zeroize::Zeroize;

use crate::hash::Hash;

// ── Konstanten ────────────────────────────────────────────────────────────────

pub const PQ_PK_LEN:  usize = ml_dsa_65::PK_LEN;   // 1952
pub const PQ_SK_LEN:  usize = ml_dsa_65::SK_LEN;   // 4032
pub const PQ_SIG_LEN: usize = ml_dsa_65::SIG_LEN;  // 3309

// ── Fehler ────────────────────────────────────────────────────────────────────

#[derive(Error, Debug)]
pub enum PqError {
    #[error("Invalid ML-DSA public key")]
    InvalidPublicKey,
    #[error("Invalid ML-DSA secret key")]
    InvalidSecretKey,
    #[error("Invalid ML-DSA signature")]
    InvalidSignature,
    #[error("ML-DSA signature verification failed")]
    VerificationFailed,
    #[error("ML-DSA key generation failed")]
    KeyGenFailed,
    #[error("ML-DSA signing failed")]
    SigningFailed,
}

// ── PqPublicKey ───────────────────────────────────────────────────────────────

/// ML-DSA-65 Public Key (1952 Bytes)
#[derive(Clone, PartialEq, Eq)]
pub struct PqPublicKey(pub Box<[u8; PQ_PK_LEN]>);

impl PqPublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqError> {
        if bytes.len() != PQ_PK_LEN {
            return Err(PqError::InvalidPublicKey);
        }
        let mut arr = [0u8; PQ_PK_LEN];
        arr.copy_from_slice(bytes);
        // Validierung: versuche zu deserialisieren
        ml_dsa_65::PublicKey::try_from_bytes(arr)
            .map_err(|_| PqError::InvalidPublicKey)?;
        Ok(PqPublicKey(Box::new(arr)))
    }

    pub fn as_bytes(&self) -> &[u8] { self.0.as_ref() }

    /// ATLQ: Adresse aus ML-DSA Public Key: SHA256(pk)[..20]
    pub fn to_address(&self) -> PqAddress {
        let hash = Sha256::digest(self.0.as_ref());
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&hash[..20]);
        PqAddress(addr)
    }

    /// Verifiziert eine ML-DSA-65 Signatur über `message`.
    pub fn verify(&self, message: &[u8], sig: &PqSignature) -> Result<(), PqError> {
        let pk = ml_dsa_65::PublicKey::try_from_bytes(*self.0)
            .map_err(|_| PqError::InvalidPublicKey)?;
        // In fips204 0.4.x the Signature type is [u8; SIG_LEN]
        if pk.verify(message, sig.0.as_ref(), &[]) {
            Ok(())
        } else {
            Err(PqError::VerificationFailed)
        }
    }
}

impl Serialize for PqPublicKey {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(self.0.as_ref()))
    }
}

impl<'de> Deserialize<'de> for PqPublicKey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let hex_str = String::deserialize(d)?;
        let bytes   = hex::decode(&hex_str).map_err(serde::de::Error::custom)?;
        PqPublicKey::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

impl std::fmt::Debug for PqPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PqPublicKey({}…)", hex::encode(&self.0[..8]))
    }
}

// ── PqSignature ───────────────────────────────────────────────────────────────

/// ML-DSA-65 Signatur (3309 Bytes)
#[derive(Clone, PartialEq, Eq)]
pub struct PqSignature(pub Box<[u8; PQ_SIG_LEN]>);

impl PqSignature {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqError> {
        if bytes.len() != PQ_SIG_LEN {
            return Err(PqError::InvalidSignature);
        }
        let mut arr = [0u8; PQ_SIG_LEN];
        arr.copy_from_slice(bytes);
        Ok(PqSignature(Box::new(arr)))
    }

    pub fn as_bytes(&self) -> &[u8] { self.0.as_ref() }
}

impl Serialize for PqSignature {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(self.0.as_ref()))
    }
}

impl<'de> Deserialize<'de> for PqSignature {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let hex_str = String::deserialize(d)?;
        let bytes   = hex::decode(&hex_str).map_err(serde::de::Error::custom)?;
        PqSignature::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

impl std::fmt::Debug for PqSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PqSig({}…)", hex::encode(&self.0[..8]))
    }
}

// ── PqAddress ─────────────────────────────────────────────────────────────────

/// Post-Quantum Wallet-Adresse (20 Bytes, Präfix ATLQ:)
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct PqAddress(pub [u8; 20]);

impl PqAddress {
    pub fn as_hex(&self) -> String { hex::encode(self.0) }

    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let s     = s.strip_prefix("ATLQ:").unwrap_or(s);
        let bytes = hex::decode(s)?;
        if bytes.len() != 20 {
            return Err(hex::FromHexError::InvalidStringLength);
        }
        let mut arr = [0u8; 20];
        arr.copy_from_slice(&bytes);
        Ok(PqAddress(arr))
    }
}

impl std::fmt::Display for PqAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ATLQ:{}", hex::encode(self.0))
    }
}

impl std::fmt::Debug for PqAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PqAddress({})", self.as_hex())
    }
}

impl Serialize for PqAddress {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for PqAddress {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        PqAddress::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

// ── PqKeyPair ─────────────────────────────────────────────────────────────────

/// ML-DSA-65 Schlüsselpaar
///
/// Der Secret Key wird mit Zeroize gelöscht wenn er den Scope verlässt.
pub struct PqKeyPair {
    secret:     Box<[u8; PQ_SK_LEN]>,
    pub public:  PqPublicKey,
    pub address: PqAddress,
}

impl std::fmt::Debug for PqKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PqKeyPair")
            .field("address", &self.address)
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl PqKeyPair {
    /// Generiert ein neues ML-DSA-65 Schlüsselpaar (OsRng).
    pub fn generate() -> Result<Self, PqError> {
        let (pk, sk) = ml_dsa_65::try_keygen()
            .map_err(|_| PqError::KeyGenFailed)?;

        let pk_bytes: [u8; PQ_PK_LEN] = pk.into_bytes();
        let sk_bytes: [u8; PQ_SK_LEN] = sk.into_bytes();

        let public  = PqPublicKey(Box::new(pk_bytes));
        let address = public.to_address();

        Ok(PqKeyPair {
            secret:  Box::new(sk_bytes),
            public,
            address,
        })
    }

    /// Erstellt ein PqKeyPair aus serialisierten Secret-Key-Bytes.
    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self, PqError> {
        if bytes.len() != PQ_SK_LEN {
            return Err(PqError::InvalidSecretKey);
        }
        let mut sk_bytes = [0u8; PQ_SK_LEN];
        sk_bytes.copy_from_slice(bytes);

        let sk = ml_dsa_65::PrivateKey::try_from_bytes(sk_bytes)
            .map_err(|_| PqError::InvalidSecretKey)?;

        // Public Key aus Secret Key rekonstruieren
        let pk = sk.get_public_key();
        let pk_bytes: [u8; PQ_PK_LEN] = pk.into_bytes();

        let public  = PqPublicKey(Box::new(pk_bytes));
        let address = public.to_address();

        Ok(PqKeyPair {
            secret:  Box::new(sk_bytes),
            public,
            address,
        })
    }

    /// Signiert eine Nachricht mit ML-DSA-65.
    pub fn sign(&self, message: &[u8]) -> Result<PqSignature, PqError> {
        let sk = ml_dsa_65::PrivateKey::try_from_bytes(*self.secret)
            .map_err(|_| PqError::InvalidSecretKey)?;

        // try_sign returns [u8; SIG_LEN] directly in fips204 0.4.x
        let sig_bytes: [u8; PQ_SIG_LEN] = sk.try_sign(message, &[])
            .map_err(|_| PqError::SigningFailed)?;
        Ok(PqSignature(Box::new(sig_bytes)))
    }

    pub fn secret_bytes(&self) -> &[u8; PQ_SK_LEN] { &self.secret }
}

impl Drop for PqKeyPair {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

// ── Hilfsfunktion: Hash → Bytes (für Signatureingabe) ─────────────────────────

/// Gibt die rohen Bytes eines Hash zurück (für ML-DSA Signatureingabe).
pub fn hash_as_message(hash: &Hash) -> &[u8] {
    hash.as_bytes()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pq_keygen_sign_verify() {
        let kp   = PqKeyPair::generate().expect("keygen should succeed");
        let msg  = b"test quantum transaction";
        let sig  = kp.sign(msg).expect("signing should succeed");

        assert!(
            kp.public.verify(msg, &sig).is_ok(),
            "Signature should verify correctly"
        );
    }

    #[test]
    fn test_pq_wrong_message_fails() {
        let kp  = PqKeyPair::generate().unwrap();
        let sig = kp.sign(b"correct message").unwrap();
        assert!(
            kp.public.verify(b"wrong message", &sig).is_err(),
            "Verification with wrong message must fail"
        );
    }

    #[test]
    fn test_pq_address_format() {
        let kp = PqKeyPair::generate().unwrap();
        let s  = kp.address.to_string();
        assert!(s.starts_with("ATLQ:"), "PQ address must start with ATLQ:");
        assert_eq!(s.len(), 45, "ATLQ: + 40 hex chars = 45");
    }

    #[test]
    fn test_pq_address_roundtrip() {
        let kp   = PqKeyPair::generate().unwrap();
        let addr = kp.address.to_string();
        let back = PqAddress::from_hex(&addr).unwrap();
        assert_eq!(kp.address, back);
    }

    #[test]
    fn test_pq_secret_key_roundtrip() {
        let kp1  = PqKeyPair::generate().unwrap();
        let sk   = kp1.secret_bytes().to_vec();
        let kp2  = PqKeyPair::from_secret_bytes(&sk).unwrap();
        assert_eq!(kp1.address, kp2.address, "Same SK must yield same address");
    }

    #[test]
    fn test_pq_pk_sizes() {
        let kp = PqKeyPair::generate().unwrap();
        assert_eq!(kp.public.as_bytes().len(), PQ_PK_LEN);
        let sig = kp.sign(b"size test").unwrap();
        assert_eq!(sig.as_bytes().len(), PQ_SIG_LEN);
    }
}
