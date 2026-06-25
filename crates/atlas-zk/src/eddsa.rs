//! Baby-Jubjub EdDSA mit Poseidon-Challenge (native Referenz).
//!
//! ZK-freundliches Signaturschema für die In-Circuit-Verifikation von
//! L2-Transaktionen. Baby-Jubjub ist eine Twisted-Edwards-Kurve, deren Basisfeld
//! exakt das BN254-Scalarfeld (`ark_bn254::Fr`) ist — Punktkoordinaten sind also
//! direkt als Circuit-Feldelemente verwendbar, ohne teure Non-Native-Arithmetik.
//!
//! Schema (EdDSA-Variante mit Poseidon statt SHA-512):
//!   Schlüssel:    privater Skalar `a ∈ Fr_ed`,  Public `A = a·B`
//!   Challenge:    `c = Poseidon(R.x, R.y, A.x, A.y, m)`  (∈ BN254-Fr)
//!   Signatur:     `R = r·B`,  `S = r + c·a  (mod l)`     → (R, S)
//!   Verifikation: `S·B == R + c·A`
//!
//! `m` ist ein einzelnes BN254-Feldelement (der Transaktions-Hash als Fr).
//! Die Challenge-Reduktion `c mod l` ist konsistent mit der Circuit-Seite, da
//! `A` und `B` in der Untergruppe primer Ordnung `l` liegen: `[c_int]·A = [c mod l]·A`.

use ark_bn254::Fr;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ed_on_bn254::{EdwardsAffine, EdwardsProjective, Fr as EdFr};
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::poseidon::hash_many;

/// Konvertiert ein BN254-Feldelement (Challenge) in einen Baby-Jubjub-Skalar.
/// `from_le_bytes_mod_order` reduziert mod `l` — identisch zur Wirkung der
/// Bit-Skalarmultiplikation im Circuit, weil die Punkte Ordnung `l` haben.
fn fr_to_edfr(x: Fr) -> EdFr {
    EdFr::from_le_bytes_mod_order(&x.into_bigint().to_bytes_le())
}

/// Bettet einen Baby-Jubjub-Skalar (`S < l < p`) als BN254-Feldelement ein.
/// Verlustfrei (kein Modulo, da `l < p`) — exakt der Wert, den der Circuit als
/// `FpVar`-Antwort-Skalar gegen die Bit-Zerlegung in `S·B` verwendet.
pub fn edfr_to_fr(s: EdFr) -> Fr {
    Fr::from_le_bytes_mod_order(&s.into_bigint().to_bytes_le())
}

/// Standard-Generator der prime-order-Untergruppe von Baby-Jubjub.
fn generator() -> EdwardsProjective {
    EdwardsAffine::generator().into_group()
}

// ── Schlüssel ──────────────────────────────────────────────────────────────────

/// Baby-Jubjub EdDSA Public Key (ein Kurvenpunkt).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EddsaPublicKey(pub EdwardsAffine);

impl EddsaPublicKey {
    /// Affine Koordinaten (x, y) — beide im BN254-Scalarfeld.
    pub fn xy(&self) -> (Fr, Fr) {
        (self.0.x, self.0.y)
    }

    /// L2-Adresse als volles Feldelement: `Poseidon(A.x, A.y)`.
    pub fn address_field(&self) -> Fr {
        let (x, y) = self.xy();
        hash_many(&[x, y])
    }

    /// L2-Adresse als 20 Byte (untere 160 Bit von `address_field`).
    pub fn address20(&self) -> [u8; 20] {
        let bytes = self.address_field().into_bigint().to_bytes_le();
        let mut out = [0u8; 20];
        out.copy_from_slice(&bytes[..20]);
        out
    }

    /// L2-Adresse als Feldelement aus den unteren 160 Bit (= `address20` als Fr).
    /// Genau dieser Wert wird im Circuit gegen das `from`-Feld gebunden.
    pub fn address_fr(&self) -> Fr {
        Fr::from_le_bytes_mod_order(&self.address20())
    }

    /// Komprimierte 32-Byte-Serialisierung des Kurvenpunkts (für Witness-Transport).
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(32);
        self.0.serialize_compressed(&mut buf).expect("EdwardsAffine serialize");
        let mut out = [0u8; 32];
        out[..buf.len()].copy_from_slice(&buf);
        out
    }

    /// Rekonstruiert den Public Key aus 32 komprimierten Bytes.
    /// `None`, falls die Bytes keinen gültigen Kurvenpunkt kodieren.
    pub fn from_bytes(b: &[u8; 32]) -> Option<Self> {
        EdwardsAffine::deserialize_compressed(&b[..]).ok().map(EddsaPublicKey)
    }
}

/// Baby-Jubjub EdDSA Signatur.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EddsaSignature {
    /// Commitment-Punkt `R = r·B`.
    pub r: EdwardsAffine,
    /// Antwort-Skalar `S = r + c·a (mod l)`.
    pub s: EdFr,
}

impl EddsaSignature {
    /// 64-Byte-Serialisierung: `R` (32, komprimiert) ‖ `S` (32, LE).
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        let mut rbuf = Vec::with_capacity(32);
        self.r.serialize_compressed(&mut rbuf).expect("R serialize");
        out[..rbuf.len()].copy_from_slice(&rbuf);
        let mut sbuf = Vec::with_capacity(32);
        self.s.serialize_compressed(&mut sbuf).expect("S serialize");
        out[32..32 + sbuf.len()].copy_from_slice(&sbuf);
        out
    }

    /// Rekonstruiert die Signatur aus 64 Bytes (`R` ‖ `S`).
    /// `None`, falls `R` kein gültiger Punkt oder `S` kein gültiger Skalar ist.
    pub fn from_bytes(b: &[u8; 64]) -> Option<Self> {
        let r = EdwardsAffine::deserialize_compressed(&b[..32]).ok()?;
        let s = EdFr::deserialize_compressed(&b[32..]).ok()?;
        Some(EddsaSignature { r, s })
    }
}

/// Baby-Jubjub EdDSA Schlüsselpaar.
#[derive(Clone)]
pub struct EddsaKeypair {
    secret:     EdFr,
    pub public: EddsaPublicKey,
}

impl EddsaKeypair {
    /// Erzeugt ein Schlüsselpaar aus einem geheimen Skalar.
    pub fn from_secret(secret: EdFr) -> Self {
        let public = EddsaPublicKey((generator() * secret).into_affine());
        EddsaKeypair { secret, public }
    }

    /// Erzeugt ein Schlüsselpaar aus 32 Secret-Bytes (mod l reduziert).
    pub fn from_secret_bytes(bytes: &[u8]) -> Self {
        Self::from_secret(EdFr::from_le_bytes_mod_order(bytes))
    }

    /// Deterministisches Schlüsselpaar aus einem `u64`-Seed (Test-/Tooling-Pfad,
    /// ohne dass der Aufrufer den Baby-Jubjub-Skalartyp kennen muss).
    pub fn from_seed(seed: u64) -> Self {
        Self::from_secret(EdFr::from(seed))
    }

    /// Zufälliges Schlüsselpaar (Test-/Tooling-Pfad).
    pub fn generate<R: rand::RngCore>(rng: &mut R) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self::from_secret_bytes(&bytes)
    }

    pub fn public(&self) -> EddsaPublicKey {
        self.public
    }

    /// Secret-Skalar als 32 Byte (Little-Endian).
    pub fn secret_bytes(&self) -> [u8; 32] {
        let v = self.secret.into_bigint().to_bytes_le();
        let mut out = [0u8; 32];
        out[..v.len()].copy_from_slice(&v);
        out
    }

    /// Deterministische Nonce-Ableitung: `r = H(secret, m)` (geheim, reproduzierbar).
    fn nonce(&self, m: Fr) -> EdFr {
        let secret_fq = Fr::from_le_bytes_mod_order(&self.secret.into_bigint().to_bytes_le());
        let r_fq = hash_many(&[secret_fq, m]);
        fr_to_edfr(r_fq)
    }

    /// Signiert ein BN254-Feldelement `m`.
    pub fn sign(&self, m: Fr) -> EddsaSignature {
        let r_scalar = self.nonce(m);
        let r_point = (generator() * r_scalar).into_affine();
        let c = challenge(&r_point, &self.public, m);
        let s = r_scalar + c * self.secret;
        EddsaSignature { r: r_point, s }
    }
}

/// Challenge `c = Poseidon(R.x, R.y, A.x, A.y, m)`, als Baby-Jubjub-Skalar.
fn challenge(r: &EdwardsAffine, pk: &EddsaPublicKey, m: Fr) -> EdFr {
    let (ax, ay) = pk.xy();
    let c_fq = hash_many(&[r.x, r.y, ax, ay, m]);
    fr_to_edfr(c_fq)
}

/// Verifiziert eine Baby-Jubjub-EdDSA-Signatur: `S·B == R + c·A`.
pub fn verify(pk: &EddsaPublicKey, m: Fr, sig: &EddsaSignature) -> bool {
    if sig.r.is_zero() {
        return false;
    }
    let c = challenge(&sig.r, pk, m);
    let lhs = generator() * sig.s;
    let rhs = sig.r.into_group() + pk.0.into_group() * c;
    lhs.into_affine() == rhs.into_affine()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;

    #[test]
    fn generator_has_prime_order() {
        // B·l muss die Identität sein → B liegt in der prime-order-Untergruppe.
        let l_minus_1 = -EdFr::from(1u64);
        let almost = generator() * l_minus_1; // (l-1)·B == -B
        let sum = (almost + generator()).into_affine();
        assert!(sum.is_zero(), "B muss prime Ordnung l haben");
    }

    #[test]
    fn sign_verify_roundtrip() {
        let mut rng = test_rng();
        let kp = EddsaKeypair::generate(&mut rng);
        let m = Fr::from(123456789u64);
        let sig = kp.sign(m);
        assert!(verify(&kp.public, m, &sig), "gültige Signatur muss verifizieren");
    }

    #[test]
    fn wrong_message_fails() {
        let mut rng = test_rng();
        let kp = EddsaKeypair::generate(&mut rng);
        let sig = kp.sign(Fr::from(1u64));
        assert!(!verify(&kp.public, Fr::from(2u64), &sig), "falsche Nachricht muss scheitern");
    }

    #[test]
    fn wrong_key_fails() {
        let mut rng = test_rng();
        let kp = EddsaKeypair::generate(&mut rng);
        let other = EddsaKeypair::generate(&mut rng);
        let m = Fr::from(42u64);
        let sig = kp.sign(m);
        assert!(!verify(&other.public, m, &sig), "fremder Schlüssel muss scheitern");
    }

    #[test]
    fn tampered_s_fails() {
        let mut rng = test_rng();
        let kp = EddsaKeypair::generate(&mut rng);
        let m = Fr::from(7u64);
        let mut sig = kp.sign(m);
        sig.s += EdFr::from(1u64);
        assert!(!verify(&kp.public, m, &sig), "manipuliertes S muss scheitern");
    }

    #[test]
    fn deterministic_signature() {
        let mut rng = test_rng();
        let kp = EddsaKeypair::generate(&mut rng);
        let m = Fr::from(999u64);
        assert_eq!(kp.sign(m), kp.sign(m), "Signatur muss deterministisch sein");
    }

    #[test]
    fn pubkey_sig_byte_roundtrip() {
        let mut rng = test_rng();
        let kp = EddsaKeypair::generate(&mut rng);
        let m = Fr::from(2024u64);
        let sig = kp.sign(m);

        let pk2 = EddsaPublicKey::from_bytes(&kp.public.to_bytes()).expect("pk decode");
        assert_eq!(kp.public, pk2, "Pubkey-Byte-Roundtrip");

        let sig2 = EddsaSignature::from_bytes(&sig.to_bytes()).expect("sig decode");
        assert_eq!(sig, sig2, "Signatur-Byte-Roundtrip");
        assert!(verify(&pk2, m, &sig2), "rekonstruierte Sig muss verifizieren");
    }

    #[test]
    fn secret_roundtrip_same_address() {
        let mut rng = test_rng();
        let kp = EddsaKeypair::generate(&mut rng);
        let kp2 = EddsaKeypair::from_secret_bytes(&kp.secret_bytes());
        assert_eq!(kp.public, kp2.public, "gleicher Secret → gleicher Pubkey");
        assert_eq!(kp.public.address20(), kp2.public.address20());
    }
}
