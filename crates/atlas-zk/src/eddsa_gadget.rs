//! In-Circuit-Verifikation der Baby-Jubjub-EdDSA-Signatur.
//!
//! Erzwingt `S·B == R + c·A` mit `c = Poseidon(R.x, R.y, A.x, A.y, m)` — bit-genau
//! konsistent zur nativen Referenz in [`crate::eddsa`]. Die Punktarithmetik läuft
//! nativ im BN254-Scalarfeld (Baby-Jubjub als embedded curve), daher ohne teure
//! Non-Native-Field-Emulation.

use ark_bn254::Fr;
use ark_crypto_primitives::sponge::{
    constraints::CryptographicSpongeVar,
    poseidon::{constraints::PoseidonSpongeVar, PoseidonConfig},
};
use ark_ec::AffineRepr;
use ark_ed_on_bn254::{constraints::EdwardsVar, EdwardsAffine};
use ark_r1cs_std::{fields::fp::FpVar, groups::CurveVar, prelude::*};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

/// Verifiziert eine Baby-Jubjub-EdDSA-Signatur im Circuit (konditional).
///
/// `enforce == false` ⇒ alle Gleichheits-Constraints sind No-Ops (Padding-Slots).
/// `s` ist der Antwort-Skalar als Feldelement (Wert < l), `r`/`pk` sind Kurvenpunkte,
/// `msg` der signierte Transaktions-Hash.
pub fn eddsa_verify_gadget(
    cfg: &PoseidonConfig<Fr>,
    cs: ConstraintSystemRef<Fr>,
    pk: &EdwardsVar,
    msg: &FpVar<Fr>,
    r: &EdwardsVar,
    s: &FpVar<Fr>,
    enforce: &Boolean<Fr>,
) -> Result<(), SynthesisError> {
    // Challenge c = Poseidon(R.x, R.y, A.x, A.y, m).
    let mut sponge = PoseidonSpongeVar::<Fr>::new(cs.clone(), cfg);
    sponge.absorb(&r.x)?;
    sponge.absorb(&r.y)?;
    sponge.absorb(&pk.x)?;
    sponge.absorb(&pk.y)?;
    sponge.absorb(msg)?;
    let c = sponge.squeeze_field_elements(1)?.remove(0);

    // Generator-Konstante B (prime-order-Untergruppe).
    let base = EdwardsVar::new_constant(cs.clone(), EdwardsAffine::generator())?;

    // lhs = S·B, rhs = R + c·A.
    let s_bits = s.to_bits_le()?;
    let c_bits = c.to_bits_le()?;
    let lhs = base.scalar_mul_le(s_bits.iter())?;
    let c_a = pk.scalar_mul_le(c_bits.iter())?;
    let rhs = r + &c_a;

    lhs.conditional_enforce_equal(&rhs, enforce)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eddsa::{verify, EddsaKeypair};
    use crate::poseidon::poseidon_config;
    use ark_ed_on_bn254::Fr as EdFr;
    use ark_ff::{BigInteger, PrimeField};
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::test_rng;

    /// Bettet einen Baby-Jubjub-Skalar als BN254-Feldelement ein (S < l < p).
    fn edfr_to_fr(s: EdFr) -> Fr {
        Fr::from_le_bytes_mod_order(&s.into_bigint().to_bytes_le())
    }

    fn run(pk_pt: EdwardsAffine, m: Fr, r_pt: EdwardsAffine, s: EdFr) -> bool {
        let cfg = poseidon_config();
        let cs = ConstraintSystem::<Fr>::new_ref();
        let pk = EdwardsVar::new_witness(cs.clone(), || Ok(pk_pt)).unwrap();
        let r = EdwardsVar::new_witness(cs.clone(), || Ok(r_pt)).unwrap();
        let s_var = FpVar::new_witness(cs.clone(), || Ok(edfr_to_fr(s))).unwrap();
        let m_var = FpVar::new_witness(cs.clone(), || Ok(m)).unwrap();
        eddsa_verify_gadget(&cfg, cs.clone(), &pk, &m_var, &r, &s_var, &Boolean::TRUE).unwrap();
        cs.is_satisfied().unwrap()
    }

    #[test]
    fn gadget_accepts_valid_signature() {
        let mut rng = test_rng();
        let kp = EddsaKeypair::generate(&mut rng);
        let m = Fr::from(123456789u64);
        let sig = kp.sign(m);
        assert!(verify(&kp.public, m, &sig), "native muss gelten");
        assert!(run(kp.public.0, m, sig.r, sig.s), "Gadget muss gültige Sig akzeptieren");
    }

    #[test]
    fn gadget_rejects_tampered_s() {
        let mut rng = test_rng();
        let kp = EddsaKeypair::generate(&mut rng);
        let m = Fr::from(55u64);
        let sig = kp.sign(m);
        assert!(!run(kp.public.0, m, sig.r, sig.s + EdFr::from(1u64)),
            "manipuliertes S muss im Gadget scheitern");
    }

    #[test]
    fn gadget_rejects_wrong_message() {
        let mut rng = test_rng();
        let kp = EddsaKeypair::generate(&mut rng);
        let sig = kp.sign(Fr::from(1u64));
        assert!(!run(kp.public.0, Fr::from(2u64), sig.r, sig.s),
            "falsche Nachricht muss im Gadget scheitern");
    }

    #[test]
    fn gadget_padding_is_noop() {
        // enforce=false ⇒ selbst eine kaputte Signatur erzeugt keinen Widerspruch.
        let mut rng = test_rng();
        let kp = EddsaKeypair::generate(&mut rng);
        let m = Fr::from(9u64);
        let bad_s = EdFr::from(7u64);
        let cfg = poseidon_config();
        let cs = ConstraintSystem::<Fr>::new_ref();
        let pk = EdwardsVar::new_witness(cs.clone(), || Ok(kp.public.0)).unwrap();
        let r = EdwardsVar::new_witness(cs.clone(), || Ok(kp.sign(m).r)).unwrap();
        let s_var = FpVar::new_witness(cs.clone(), || Ok(edfr_to_fr(bad_s))).unwrap();
        let m_var = FpVar::new_witness(cs.clone(), || Ok(m)).unwrap();
        eddsa_verify_gadget(&cfg, cs.clone(), &pk, &m_var, &r, &s_var, &Boolean::FALSE).unwrap();
        assert!(cs.is_satisfied().unwrap(), "Padding-Slot darf nie scheitern");
    }
}
