use secp256k1::{Secp256k1, SecretKey, PublicKey as Secp256k1PublicKey, Message};
use secp256k1::ecdsa::Signature as Secp256k1Signature;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Sha256, Digest};
use ripemd::Ripemd160;
use thiserror::Error;
use crate::hash::Hash;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Invalid private key")]
    InvalidPrivateKey,
    #[error("Invalid public key")]
    InvalidPublicKey,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Signature verification failed")]
    VerificationFailed,
    #[error("Secp256k1 error: {0}")]
    Secp256k1(#[from] secp256k1::Error),
    #[error("Hex decode error: {0}")]
    HexDecode(#[from] hex::FromHexError),
}

// ── Serde-Hilfsmakro für feste Byte-Arrays ────────────────────────────────

macro_rules! impl_bytes_serde {
    ($name:ident, $n:literal) => {
        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&hex::encode(&self.0))
            }
        }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let hex_str = String::deserialize(d)?;
                let bytes   = hex::decode(&hex_str).map_err(serde::de::Error::custom)?;
                if bytes.len() != $n {
                    return Err(serde::de::Error::custom(
                        format!("expected {} bytes, got {}", $n, bytes.len())
                    ));
                }
                let mut arr = [0u8; $n];
                arr.copy_from_slice(&bytes);
                Ok($name(arr))
            }
        }
    };
}

// ── PublicKey ─────────────────────────────────────────────────────────────

/// Öffentlicher Schlüssel (33 Bytes, komprimiert)
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PublicKey(pub [u8; 33]);

impl_bytes_serde!(PublicKey, 33);

impl PublicKey {
    /// Null-PublicKey für Coinbase-Inputs
    pub fn zeroed() -> Self { PublicKey([0u8; 33]) }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != 33 {
            return Err(CryptoError::InvalidPublicKey);
        }
        let _check = Secp256k1PublicKey::from_slice(bytes)
            .map_err(|_| CryptoError::InvalidPublicKey)?;
        let mut arr = [0u8; 33];
        arr.copy_from_slice(bytes);
        Ok(PublicKey(arr))
    }

    pub fn as_bytes(&self) -> &[u8; 33] { &self.0 }

    /// ATLAS Adresse: RIPEMD160(SHA256(pubkey)) als hex
    pub fn to_address(&self) -> Address {
        let sha_hash = Sha256::digest(self.0);
        let ripe     = Ripemd160::digest(sha_hash);
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&ripe);
        Address(addr)
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PublicKey({})", hex::encode(self.0[..8].as_ref()))
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

// ── Signature ─────────────────────────────────────────────────────────────

/// ECDSA Signatur (64 Bytes, kompakt)
#[derive(Clone, PartialEq, Eq)]
pub struct Signature(pub [u8; 64]);

impl_bytes_serde!(Signature, 64);

impl Signature {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != 64 {
            return Err(CryptoError::InvalidSignature);
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(bytes);
        Ok(Signature(arr))
    }

    pub fn zeroed() -> Self { Signature([0u8; 64]) }

    pub fn as_bytes(&self) -> &[u8; 64] { &self.0 }

    pub fn verify(&self, message_hash: &Hash, pubkey: &PublicKey) -> Result<(), CryptoError> {
        let secp = Secp256k1::verification_only();
        let msg  = Message::from_digest_slice(&message_hash.0)
            .map_err(|_| CryptoError::InvalidSignature)?;
        let sig  = Secp256k1Signature::from_compact(&self.0)
            .map_err(|_| CryptoError::InvalidSignature)?;
        let pk   = Secp256k1PublicKey::from_slice(&pubkey.0)
            .map_err(|_| CryptoError::InvalidPublicKey)?;
        secp.verify_ecdsa(&msg, &sig, &pk)
            .map_err(|_| CryptoError::VerificationFailed)
    }
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Sig({}...)", hex::encode(&self.0[..8]))
    }
}

// ── Address ───────────────────────────────────────────────────────────────

/// Wallet-Adresse (20 Bytes)
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Address(pub [u8; 20]);

impl Serialize for Address {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.as_hex())
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let hex_str = String::deserialize(d)?;
        Address::from_hex(&hex_str).map_err(serde::de::Error::custom)
    }
}

impl Address {
    pub fn as_hex(&self) -> String { hex::encode(self.0) }

    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let s = s.strip_prefix("ATL:").unwrap_or(s);
        let bytes = hex::decode(s)?;
        if bytes.len() != 20 { return Err(hex::FromHexError::InvalidStringLength); }
        let mut arr = [0u8; 20];
        arr.copy_from_slice(&bytes);
        Ok(Address(arr))
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ATL:{}", hex::encode(self.0))
    }
}

impl std::fmt::Debug for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Address({})", self.as_hex())
    }
}

// ── KeyPair ───────────────────────────────────────────────────────────────

pub struct KeyPair {
    secret:      SecretKey,
    pub public:  PublicKey,
    pub address: Address,
}

impl KeyPair {
    pub fn generate() -> Self {
        let secp   = Secp256k1::new();
        let secret = SecretKey::new(&mut rand::thread_rng());
        let pk     = Secp256k1PublicKey::from_secret_key(&secp, &secret);
        let public = PublicKey(pk.serialize());
        let address = public.to_address();
        KeyPair { secret, public, address }
    }

    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let secp   = Secp256k1::new();
        let secret = SecretKey::from_slice(bytes)
            .map_err(|_| CryptoError::InvalidPrivateKey)?;
        let pk     = Secp256k1PublicKey::from_secret_key(&secp, &secret);
        let public = PublicKey(pk.serialize());
        let address = public.to_address();
        Ok(KeyPair { secret, public, address })
    }

    pub fn sign(&self, message_hash: &Hash) -> Result<Signature, CryptoError> {
        let secp = Secp256k1::signing_only();
        let msg  = Message::from_digest_slice(&message_hash.0)
            .map_err(|_| CryptoError::InvalidSignature)?;
        let sig  = secp.sign_ecdsa(&msg, &self.secret);
        Ok(Signature(sig.serialize_compact()))
    }

    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.secret_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen_sign_verify() {
        let kp   = KeyPair::generate();
        let data = b"test transaction";
        let hash = Hash::double_sha256(data);
        let sig  = kp.sign(&hash).unwrap();
        assert!(sig.verify(&hash, &kp.public).is_ok());
    }

    #[test]
    fn test_address_format() {
        let kp = KeyPair::generate();
        println!("Address: {}", kp.address);
        assert_eq!(kp.address.as_hex().len(), 40);
    }

    #[test]
    fn test_serde_roundtrip() {
        let kp  = KeyPair::generate();
        let pk  = &kp.public;
        let json = serde_json::to_string(pk).unwrap();
        let pk2: PublicKey = serde_json::from_str(&json).unwrap();
        assert_eq!(pk.0, pk2.0);
    }
}
