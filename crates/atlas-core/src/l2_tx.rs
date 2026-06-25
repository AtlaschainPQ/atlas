//! L2-Transaktion — off-chain signiert, in Batches gebündelt
//!
//! Eine L2-TX ist eine einfache Zahlung (from → to, Betrag, Fee).
//! Der Sender signiert mit Baby-Jubjub EdDSA (circuit-nativ, BN254-Feld).
//! Die kryptographische Signatur-/Adressprüfung passiert im Aggregator
//! (Crate `atlas-zk`), da `atlas-core` keine arkworks-/Poseidon-Abhängigkeit
//! hat. Hier sind nur strukturelle Checks möglich.

use crate::crypto::Address;
use crate::hash::Hash;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

/// EdDSA-Signatur: R (32 Byte, komprimiert) ‖ S (32 Byte) = 64 Byte.
/// Eigener Typ wegen serde (Standard-Arrays nur bis Länge 32).
#[derive(Clone, Copy)]
pub struct EddsaSig(pub [u8; 64]);

impl EddsaSig {
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, L2TxError> {
        if bytes.len() != 64 {
            return Err(L2TxError::MalformedSignature);
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(bytes);
        Ok(EddsaSig(arr))
    }
}

impl Default for EddsaSig {
    fn default() -> Self {
        EddsaSig([0u8; 64])
    }
}

impl std::fmt::Debug for EddsaSig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EddsaSig({}…)", hex::encode(&self.0[..4]))
    }
}

impl Serialize for EddsaSig {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for EddsaSig {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let hex_str = String::deserialize(d)?;
        let bytes = hex::decode(hex_str).map_err(serde::de::Error::custom)?;
        EddsaSig::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

/// EdDSA-Authentifizierung einer L2-TX — Public Key + Signatur als rohe Bytes.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct L2Auth {
    /// Komprimierter Baby-Jubjub Public Key (32 Byte)
    pub pubkey: [u8; 32],
    /// EdDSA-Signatur R‖S (64 Byte)
    pub signature: EddsaSig,
}

/// Signierte L2-Transaktion (EdDSA-nativ)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct L2Transaction {
    /// Absender (lower-160-Bit von Poseidon(pubkey))
    pub from:   Address,
    /// Empfänger
    pub to:     Address,
    /// Betrag in ATOM
    pub amount: u128,
    /// Aggregator-Gebühr in ATOM
    pub fee:    u128,
    /// Replay-Schutz (pro Sender monoton steigend)
    pub nonce:  u64,
    /// Public Key + EdDSA-Signatur
    pub auth:   L2Auth,
}

impl L2Transaction {
    /// Baut eine TX aus bereits berechneten EdDSA-Teilen (Pubkey + Signatur).
    /// Das Signieren selbst lebt in `atlas-zk` (`build_l2_eddsa`), da es
    /// Poseidon/Baby-Jubjub benötigt.
    pub fn from_parts(
        from:      Address,
        to:        Address,
        amount:    u128,
        fee:       u128,
        nonce:     u64,
        pubkey:    [u8; 32],
        signature: [u8; 64],
    ) -> Self {
        L2Transaction {
            from, to, amount, fee, nonce,
            auth: L2Auth { pubkey, signature: EddsaSig(signature) },
        }
    }

    /// Hash der TX (für Batch-Merkle-Root)
    pub fn hash(&self) -> Hash {
        let data = self.signing_bytes();
        Hash::double_sha256(&data)
    }

    /// Bytes die in den TX-Hash einfließen (ohne Signatur/Pubkey).
    /// Hält die DA-Calldata-Invariante: hängt nur von Kernfeldern ab.
    pub fn signing_bytes(&self) -> Vec<u8> {
        bincode::serialize(&(
            self.from.0,
            self.to.0,
            self.amount,
            self.fee,
            self.nonce,
        )).expect("serialization cannot fail")
    }

    /// Strukturelle Validierung (Betrag, Fee, Self-Transfer).
    ///
    /// HINWEIS: Die kryptographische EdDSA-Prüfung (Signatur gültig +
    /// `from == lower160(Poseidon(pubkey))`) kann `atlas-core` nicht
    /// durchführen — sie erfolgt im Aggregator via `atlas-zk`. Eine TX,
    /// die hier `Ok` liefert, ist NICHT zwingend kryptographisch gültig.
    pub fn validate(&self) -> Result<(), L2TxError> {
        if self.amount == 0 {
            return Err(L2TxError::ZeroAmount);
        }
        if self.fee == 0 {
            return Err(L2TxError::ZeroFee);
        }
        if self.from == self.to {
            return Err(L2TxError::SelfTransfer);
        }
        Ok(())
    }
}

#[derive(Error, Debug)]
pub enum L2TxError {
    #[error("Amount cannot be zero")]
    ZeroAmount,
    #[error("Fee cannot be zero")]
    ZeroFee,
    #[error("Cannot transfer to self")]
    SelfTransfer,
    #[error("Signature must be 64 bytes")]
    MalformedSignature,
    #[error("Invalid EdDSA signature or address binding")]
    InvalidSignature,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_tx(from: Address, to: Address) -> L2Transaction {
        L2Transaction {
            from, to, amount: 1000, fee: 10, nonce: 1,
            auth: L2Auth { pubkey: [1u8; 32], signature: EddsaSig([2u8; 64]) },
        }
    }

    #[test]
    fn structural_validation_accepts_well_formed() {
        let tx = dummy_tx(Address([1u8; 20]), Address([9u8; 20]));
        tx.validate().expect("strukturell gültig");
    }

    #[test]
    fn rejects_zero_amount() {
        let mut tx = dummy_tx(Address([1u8; 20]), Address([9u8; 20]));
        tx.amount = 0;
        assert!(matches!(tx.validate(), Err(L2TxError::ZeroAmount)));
    }

    #[test]
    fn rejects_zero_fee() {
        let mut tx = dummy_tx(Address([1u8; 20]), Address([9u8; 20]));
        tx.fee = 0;
        assert!(matches!(tx.validate(), Err(L2TxError::ZeroFee)));
    }

    #[test]
    fn rejects_self_transfer() {
        let tx = dummy_tx(Address([5u8; 20]), Address([5u8; 20]));
        assert!(matches!(tx.validate(), Err(L2TxError::SelfTransfer)));
    }

    #[test]
    fn signature_hex_roundtrip() {
        let sig = EddsaSig([7u8; 64]);
        let json = serde_json::to_string(&sig).unwrap();
        let back: EddsaSig = serde_json::from_str(&json).unwrap();
        assert_eq!(sig.0, back.0);
    }

    #[test]
    fn signing_bytes_independent_of_auth() {
        let from = Address([3u8; 20]);
        let to = Address([7u8; 20]);
        let mut a = dummy_tx(from, to);
        let mut b = dummy_tx(from, to);
        a.auth.pubkey = [0xAAu8; 32];
        b.auth.pubkey = [0xBBu8; 32];
        assert_eq!(a.signing_bytes(), b.signing_bytes());
    }
}
