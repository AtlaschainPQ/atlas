//! Keystore — verschlüsselte Schlüsselverwaltung
//!
//! Privat-Keys werden mit AES-256-GCM verschlüsselt gespeichert.
//! Der AES-Key wird via Argon2id aus dem Wallet-Passwort abgeleitet.
//! Format: JSON mit kdf_salt, nonce, ciphertext (base64-kodiert).
//!
//! Schlüsseltypen:
//!   classic  — ECDSA secp256k1, 32 Byte secret key, Adresse ATL:<40hex>
//!   quantum  — ML-DSA-65,       4032 Byte secret key, Adresse ATLQ:<40hex>

use aes_gcm::{
    aead::{Aead, KeyInit},
    aead::rand_core::RngCore,
    aead::OsRng as AeadOsRng,
    Aes256Gcm, Key, Nonce,
};
use argon2::Argon2;
use atlas_core::crypto::{Address, KeyPair};
use atlas_core::pq_crypto::{PqKeyPair, PQ_SK_LEN};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Error, Debug)]
pub enum KeystoreError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Wallet not found at {0}")]
    NotFound(String),
    #[error("Key '{0}' not found")]
    KeyNotFound(String),
    #[error("Wrong password")]
    WrongPassword,
    #[error("Crypto error: {0}")]
    Crypto(String),
    #[error("Key type mismatch: expected {expected}, got {got}")]
    KeyTypeMismatch { expected: &'static str, got: String },
}

/// Schlüsseltyp: klassisch (ECDSA) oder Post-Quantum (ML-DSA-65)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum KeyType {
    #[default]
    Classic,
    Quantum,
}

impl std::fmt::Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyType::Classic => write!(f, "classic"),
            KeyType::Quantum => write!(f, "quantum"),
        }
    }
}

/// Gespeicherter Schlüssel — privater Schlüssel ist AES-256-GCM-verschlüsselt
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyEntry {
    pub label:    String,
    pub address:  String,
    /// Schlüsseltyp: "classic" (ECDSA) oder "quantum" (ML-DSA-65)
    #[serde(default)]
    pub key_type: KeyType,
    /// base64(salt) für Argon2id-KDF (16 Byte)
    kdf_salt:    String,
    /// base64(nonce) für AES-256-GCM (12 Byte)
    nonce:       String,
    /// base64(ciphertext) — AES-GCM-verschlüsselter private key + 16-Byte tag
    ciphertext:  String,
}

impl KeyEntry {
    pub fn address_parsed(&self) -> Result<Address, KeystoreError> {
        Address::from_hex(&self.address).map_err(|e| KeystoreError::Crypto(e.to_string()))
    }

    /// Entschlüsselt als klassisches ECDSA-KeyPair
    pub fn keypair(&self, password: &[u8]) -> Result<KeyPair, KeystoreError> {
        if self.key_type != KeyType::Classic {
            return Err(KeystoreError::KeyTypeMismatch {
                expected: "classic",
                got: self.key_type.to_string(),
            });
        }
        let plaintext = self.decrypt(password)?;
        KeyPair::from_secret_bytes(&plaintext)
            .map_err(|e| KeystoreError::Crypto(e.to_string()))
    }

    /// Entschlüsselt als ML-DSA-65 PQ-KeyPair
    pub fn pq_keypair(&self, password: &[u8]) -> Result<PqKeyPair, KeystoreError> {
        if self.key_type != KeyType::Quantum {
            return Err(KeystoreError::KeyTypeMismatch {
                expected: "quantum",
                got: self.key_type.to_string(),
            });
        }
        let plaintext = self.decrypt(password)?;
        PqKeyPair::from_secret_bytes(&plaintext)
            .map_err(|e| KeystoreError::Crypto(e.to_string()))
    }

    fn decrypt(&self, password: &[u8]) -> Result<Zeroizing<Vec<u8>>, KeystoreError> {
        let salt_bytes  = b64_decode(&self.kdf_salt)?;
        let nonce_bytes = b64_decode(&self.nonce)?;
        let ciphertext  = b64_decode(&self.ciphertext)?;

        let aes_key = derive_key(password, &salt_bytes)?;
        let cipher  = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(aes_key.as_ref()));
        let nonce   = Nonce::from_slice(&nonce_bytes);

        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())
            .map_err(|_| KeystoreError::WrongPassword)?;

        Ok(Zeroizing::new(plaintext))
    }
}

#[derive(Serialize, Deserialize)]
struct WalletFile {
    version: u32,
    keys:    Vec<KeyEntry>,
}

pub struct Keystore {
    path: PathBuf,
    keys: Vec<KeyEntry>,
}

impl Keystore {
    /// Öffnet oder erstellt eine Wallet-Datei
    pub fn open(path: impl AsRef<Path>) -> Result<Self, KeystoreError> {
        let path = path.as_ref().to_path_buf();
        let keys = if path.exists() {
            let data = std::fs::read_to_string(&path)?;
            let file: WalletFile = serde_json::from_str(&data)?;
            file.keys
        } else {
            vec![]
        };
        Ok(Keystore { path, keys })
    }

    /// Generiert einen neuen klassischen ECDSA-Schlüssel
    pub fn generate_key(&mut self, label: &str, password: &[u8]) -> Result<KeyEntry, KeystoreError> {
        let kp = KeyPair::generate();
        let raw = kp.secret_bytes();
        let priv_bytes: &[u8; 32] = raw.as_slice()
            .try_into()
            .map_err(|_| KeystoreError::Crypto("unexpected key length".into()))?;

        let entry = encrypt_entry(label, &kp.address.as_hex(), KeyType::Classic, priv_bytes, password)?;
        self.keys.push(entry.clone());
        self.save()?;
        Ok(entry)
    }

    /// Generiert einen neuen Post-Quantum ML-DSA-65 Schlüssel (ATLQ: Adresse)
    pub fn generate_pq_key(&mut self, label: &str, password: &[u8]) -> Result<KeyEntry, KeystoreError> {
        let kp = PqKeyPair::generate()
            .map_err(|e| KeystoreError::Crypto(e.to_string()))?;

        let address = kp.address.to_string(); // "ATLQ:<40hex>"
        let sk_bytes = kp.secret_bytes();

        let entry = encrypt_entry(label, &address, KeyType::Quantum, sk_bytes, password)?;
        self.keys.push(entry.clone());
        self.save()?;
        Ok(entry)
    }

    /// Importiert einen klassischen privaten Schlüssel aus Hex
    pub fn import_key(&mut self, label: &str, priv_hex: &str, password: &[u8]) -> Result<KeyEntry, KeystoreError> {
        let raw = Zeroizing::new(
            hex::decode(priv_hex).map_err(|e| KeystoreError::Crypto(e.to_string()))?
        );
        if raw.len() != 32 {
            return Err(KeystoreError::Crypto("Expected 32-byte private key".into()));
        }
        let priv_bytes: &[u8; 32] = raw.as_slice()
            .try_into()
            .map_err(|_| KeystoreError::Crypto("unexpected key length".into()))?;

        let kp = KeyPair::from_secret_bytes(priv_bytes)
            .map_err(|e| KeystoreError::Crypto(e.to_string()))?;

        let entry = encrypt_entry(label, &kp.address.as_hex(), KeyType::Classic, priv_bytes, password)?;
        self.keys.push(entry.clone());
        self.save()?;
        Ok(entry)
    }

    /// Importiert einen ML-DSA-65 privaten Schlüssel aus Hex
    pub fn import_pq_key(&mut self, label: &str, priv_hex: &str, password: &[u8]) -> Result<KeyEntry, KeystoreError> {
        let raw = Zeroizing::new(
            hex::decode(priv_hex).map_err(|e| KeystoreError::Crypto(e.to_string()))?
        );
        if raw.len() != PQ_SK_LEN {
            return Err(KeystoreError::Crypto(
                format!("Expected {}-byte PQ private key, got {}", PQ_SK_LEN, raw.len())
            ));
        }
        let kp = PqKeyPair::from_secret_bytes(&raw)
            .map_err(|e| KeystoreError::Crypto(e.to_string()))?;

        let address = kp.address.to_string();
        let entry = encrypt_entry(label, &address, KeyType::Quantum, kp.secret_bytes(), password)?;
        self.keys.push(entry.clone());
        self.save()?;
        Ok(entry)
    }

    pub fn keys(&self) -> &[KeyEntry] { &self.keys }
    pub fn is_empty(&self) -> bool    { self.keys.is_empty() }

    pub fn get_by_label(&self, label: &str) -> Option<&KeyEntry> {
        self.keys.iter().find(|k| k.label == label)
    }

    pub fn get_by_address(&self, addr: &str) -> Option<&KeyEntry> {
        self.keys.iter().find(|k| k.address == addr)
    }

    fn save(&self) -> Result<(), KeystoreError> {
        let file = WalletFile { version: 3, keys: self.keys.clone() };
        let data = serde_json::to_string_pretty(&file)?;
        std::fs::write(&self.path, data)?;
        Ok(())
    }
}

// ── Hilfsfunktionen ──────────────────────────────────────────────────────────

fn encrypt_entry(
    label:    &str,
    address:  &str,
    key_type: KeyType,
    priv_key: &[u8],
    password: &[u8],
) -> Result<KeyEntry, KeystoreError> {
    let mut salt_bytes  = [0u8; 16];
    let mut nonce_bytes = [0u8; 12];
    AeadOsRng.fill_bytes(&mut salt_bytes);
    AeadOsRng.fill_bytes(&mut nonce_bytes);

    let aes_key = derive_key(password, &salt_bytes)?;
    let cipher  = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(aes_key.as_ref()));
    let nonce   = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, priv_key)
        .map_err(|e| KeystoreError::Crypto(e.to_string()))?;

    Ok(KeyEntry {
        label:      label.to_string(),
        address:    address.to_string(),
        key_type,
        kdf_salt:   b64_encode(&salt_bytes),
        nonce:      b64_encode(&nonce_bytes),
        ciphertext: b64_encode(&ciphertext),
    })
}

/// Leitet einen 32-Byte AES-Schlüssel aus Passwort + Salt via Argon2id ab
fn derive_key(password: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, KeystoreError> {
    let argon2 = Argon2::default();
    let mut key = Zeroizing::new([0u8; 32]);
    argon2.hash_password_into(password, salt, &mut *key)
        .map_err(|e| KeystoreError::Crypto(e.to_string()))?;
    Ok(key)
}

// Minimales base64 ohne externe Abhängigkeit

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = if chunk.len() > 1 { chunk[1] as usize } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as usize } else { 0 };
        out.push(B64[b0 >> 2] as char);
        out.push(B64[((b0 & 3) << 4) | (b1 >> 4)] as char);
        out.push(if chunk.len() > 1 { B64[((b1 & 0xf) << 2) | (b2 >> 6)] as char } else { '=' });
        out.push(if chunk.len() > 2 { B64[b2 & 0x3f] as char } else { '=' });
    }
    out
}

fn b64_decode(s: &str) -> Result<Vec<u8>, KeystoreError> {
    let mut table = [255u8; 128];
    for (i, &c) in B64.iter().enumerate() {
        table[c as usize] = i as u8;
    }

    let vals: Vec<u8> = s.bytes()
        .filter(|&b| b != b'=')
        .map(|b| {
            if b as usize >= 128 || table[b as usize] == 255 {
                Err(KeystoreError::Crypto("invalid base64".into()))
            } else {
                Ok(table[b as usize])
            }
        })
        .collect::<Result<_, _>>()?;

    let mut out = Vec::with_capacity(vals.len() * 3 / 4);
    for chunk in vals.chunks(4) {
        let b0 = chunk[0];
        let b1 = if chunk.len() > 1 { chunk[1] } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] } else { 0 };
        let b3 = if chunk.len() > 3 { chunk[3] } else { 0 };
        out.push((b0 << 2) | (b1 >> 4));
        if chunk.len() > 2 { out.push((b1 << 4) | (b2 >> 2)); }
        if chunk.len() > 3 { out.push((b2 << 6) | b3); }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let password = b"correct horse battery staple";
        let kp = KeyPair::generate();
        let raw = kp.secret_bytes();
        let priv_bytes: &[u8; 32] = raw.as_slice().try_into().unwrap();

        let entry = encrypt_entry("test", &kp.address.as_hex(), KeyType::Classic, priv_bytes, password).unwrap();

        let kp2 = entry.keypair(password).unwrap();
        assert_eq!(kp.address, kp2.address);
    }

    #[test]
    fn test_wrong_password_fails() {
        let password = b"correct password";
        let kp = KeyPair::generate();
        let raw = kp.secret_bytes();
        let priv_bytes: &[u8; 32] = raw.as_slice().try_into().unwrap();

        let entry = encrypt_entry("test", &kp.address.as_hex(), KeyType::Classic, priv_bytes, password).unwrap();

        let result = entry.keypair(b"wrong password");
        assert!(matches!(result, Err(KeystoreError::WrongPassword)));
    }

    #[test]
    fn test_b64_roundtrip() {
        let data = b"Hello, World! This is a test \x00\xff\xfe";
        assert_eq!(b64_decode(&b64_encode(data)).unwrap(), data);
    }

    #[test]
    fn test_pq_key_encrypt_decrypt() {
        let password = b"quantum password";
        let kp = PqKeyPair::generate().expect("PQ keygen");
        let entry = encrypt_entry(
            "pq-test",
            &kp.address.to_string(),
            KeyType::Quantum,
            kp.secret_bytes(),
            password,
        ).unwrap();

        let kp2 = entry.pq_keypair(password).unwrap();
        assert_eq!(kp.address, kp2.address);
    }

    #[test]
    fn test_pq_key_type_mismatch() {
        let password = b"test";
        let kp = KeyPair::generate();
        let raw = kp.secret_bytes();
        let entry = encrypt_entry("test", &kp.address.as_hex(), KeyType::Classic, raw.as_slice().try_into().unwrap(), password).unwrap();

        // Versuche als PQ-Key zu entschlüsseln → Fehler
        let err = entry.pq_keypair(password).unwrap_err();
        assert!(matches!(err, KeystoreError::KeyTypeMismatch { .. }));
    }
}
