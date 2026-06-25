//! Phase-2-Trusted-Setup-MPC (δ-Beitrag) für Groth16 über BN254.
//!
//! ╔══════════════════ ⚠️ SICHERHEITSKRITISCH / UNVOLLSTÄNDIG ══════════════════╗
//! ║ Dieses Modul implementiert die FUNKTIONAL korrekte δ-Re-Randomisierung      ║
//! ║ (mathematisch geprüft: Beweise verifizieren nach jedem Beitrag weiter).     ║
//! ║ Es ist ALLEIN KEINE sichere Ceremony. Zwei Teile fehlen bewusst und sind    ║
//! ║ Cryptographer-+-Audit-Territorium:                                          ║
//! ║                                                                             ║
//! ║  1. PHASE 1 (Powers of Tau): `circuit_specific_setup` erzeugt α/β/τ auf     ║
//! ║     EINER Maschine. δ-Re-Randomisierung ändert daran NICHTS — wer α/β/τ     ║
//! ║     kennt, kann weiterhin Beweise fälschen. Vor echtem Einsatz MÜSSEN α/β/τ ║
//! ║     aus einer Multi-Party-/öffentlichen PoT stammen (Circuit darauf         ║
//! ║     spezialisieren, wie `snarkjs groth16 setup`).                           ║
//! ║                                                                             ║
//! ║  2. BEITRAGS-PROOF-OF-KNOWLEDGE: `Contribution` enthält noch KEINEN PoK,    ║
//! ║     der s in G1↔G2 bindet (Fiat-Shamir). Ohne ihn sind Beiträge nicht      ║
//! ║     öffentlich verifizierbar — ein Teilnehmer könnte δ auf einen bekannten  ║
//! ║     Wert „zurücksetzen". `verify_contribution` prüft daher NUR strukturelle ║
//! ║     Konsistenz, NICHT die Ehrlichkeit des Beitrags.                         ║
//! ║                                                                             ║
//! ║ → NICHT für ein Netz mit echtem Geld verwenden, bis ein Audit beide Punkte  ║
//! ║   abgeschlossen/geprüft hat. Siehe CEREMONY.md.                             ║
//! ╚═════════════════════════════════════════════════════════════════════════════╝

use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, UniformRand};
use ark_groth16::ProvingKey;
use ark_std::rand::RngCore;

fn mul_g1(p: G1Affine, s: Fr) -> G1Affine { (p.into_group() * s).into_affine() }
fn mul_g2(p: G2Affine, s: Fr) -> G2Affine { (p.into_group() * s).into_affine() }

/// Öffentliche Attestation eines δ-Beitrags.
pub struct Contribution {
    /// δ in G1 VOR diesem Beitrag.
    pub delta_before_g1: G1Affine,
    /// δ in G1 NACH diesem Beitrag (= delta_before · s).
    pub delta_after_g1: G1Affine,
    /// [s]₁ — Teil eines künftigen Proof-of-Knowledge (siehe Modul-Header).
    pub s_g1: G1Affine,
    // TODO(SECURITY/AUDIT): vollständiger PoK (Bindung von s in G1↔G2 via
    // Fiat-Shamir-Challenge-Punkt in G2), damit Beiträge öffentlich UND ehrlich
    // verifizierbar sind. Ohne diesen ist die MPC-Garantie NICHT gegeben.
}

/// Wendet einen δ-Beitrag an: δ → δ·s mit zufälligem s. Transformiert den
/// Proving-Key (und den eingebetteten Verifying-Key) KONSISTENT, sodass mit dem
/// neuen `pk` erzeugte Beweise weiterhin unter `pk.vk` verifizieren.
///
/// Ein ehrlicher Teilnehmer ruft dies auf einer Airgap-Maschine auf und
/// vernichtet danach `s` (hier nur lokale Variable) UND die Maschine.
pub fn contribute<R: RngCore>(pk: &mut ProvingKey<Bn254>, rng: &mut R) -> Contribution {
    let s = Fr::rand(rng);
    let s_inv = s.inverse().expect("s != 0 (überwältigend wahrscheinlich)");

    let delta_before_g1 = pk.delta_g1;

    // δ-abhängige Elemente. δ → δ·s ⇒ alles „/δ" wird „·s⁻¹", alles „·δ" wird „·s".
    pk.delta_g1    = mul_g1(pk.delta_g1, s);
    pk.vk.delta_g2 = mul_g2(pk.vk.delta_g2, s);
    for e in pk.l_query.iter_mut() { *e = mul_g1(*e, s_inv); }
    for e in pk.h_query.iter_mut() { *e = mul_g1(*e, s_inv); }

    Contribution {
        delta_before_g1,
        delta_after_g1: pk.delta_g1,
        s_g1: mul_g1(G1Affine::generator(), s),
    }
}

/// Strukturelle (NICHT sicherheitstragende) Konsistenzprüfung eines Beitrags:
/// δ_after == δ_before · s, abgeleitet aus den veröffentlichten Punkten via
/// Pairing — `e(δ_after, G2) == e(δ_before, [s]₂)` würde [s]₂ brauchen; hier
/// prüfen wir nur, dass `s_g1` nicht neutral ist und δ sich verändert hat.
///
/// ⚠️ Ersetzt NICHT den fehlenden Proof-of-Knowledge (siehe Modul-Header).
pub fn verify_contribution_structural(c: &Contribution) -> bool {
    !c.s_g1.is_zero() && c.delta_after_g1 != c.delta_before_g1
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_groth16::Groth16;
    use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar};
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
    use ark_snark::SNARK;
    use ark_std::rand::{rngs::StdRng, SeedableRng};

    /// Triviale Test-Schaltung: beweist Kenntnis von x mit x·x == y (y öffentlich).
    /// Die δ-Re-Randomisierung ist circuit-unabhängig — eine kleine Schaltung
    /// genügt, um ihre Korrektheit zu zeigen.
    #[derive(Clone)]
    struct Square { x: Option<Fr>, y: Fr }
    impl ConstraintSynthesizer<Fr> for Square {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
            let x = FpVar::new_witness(cs.clone(), || self.x.ok_or(SynthesisError::AssignmentMissing))?;
            let y = FpVar::new_input(cs, || Ok(self.y))?;
            (&x * &x).enforce_equal(&y)
        }
    }

    /// KERN-INVARIANTE: nach mehreren δ-Beiträgen erzeugt der transformierte
    /// Proving-Key weiterhin Beweise, die unter dem transformierten Verifying-Key
    /// verifizieren — und ein falscher Public-Input wird abgelehnt.
    #[test]
    fn delta_contributions_preserve_validity() {
        let mut rng = StdRng::seed_from_u64(42);
        let x = Fr::from(3u64);
        let y = Fr::from(9u64);

        let (mut pk, _vk0) = Groth16::<Bn254>::circuit_specific_setup(
            Square { x: None, y }, &mut rng,
        ).unwrap();

        // Drei unabhängige Beiträge.
        for _ in 0..3 {
            let c = contribute(&mut pk, &mut rng);
            assert!(verify_contribution_structural(&c));
        }

        // Beweis mit FINAL-pk, Verifikation unter FINAL-vk (= pk.vk).
        let proof = Groth16::<Bn254>::prove(&pk, Square { x: Some(x), y }, &mut rng).unwrap();
        let pvk = Groth16::<Bn254>::process_vk(&pk.vk).unwrap();

        assert!(Groth16::<Bn254>::verify_with_processed_vk(&pvk, &[y], &proof).unwrap(),
            "Beweis muss nach den δ-Beiträgen weiter verifizieren");
        assert!(!Groth16::<Bn254>::verify_with_processed_vk(&pvk, &[Fr::from(10u64)], &proof).unwrap(),
            "falscher Public-Input muss abgelehnt werden");
    }

    /// δ ändert sich bei jedem Beitrag (keine Identitäts-/Reset-Transformation).
    #[test]
    fn delta_changes_each_contribution() {
        let mut rng = StdRng::seed_from_u64(7);
        let (mut pk, _) = Groth16::<Bn254>::circuit_specific_setup(
            Square { x: None, y: Fr::from(1u64) }, &mut rng,
        ).unwrap();
        let d0 = pk.delta_g1;
        let c1 = contribute(&mut pk, &mut rng);
        let d1 = pk.delta_g1;
        let c2 = contribute(&mut pk, &mut rng);
        assert_ne!(d0, d1);
        assert_ne!(d1, pk.delta_g1);
        assert_eq!(c1.delta_after_g1, c2.delta_before_g1);
    }
}
