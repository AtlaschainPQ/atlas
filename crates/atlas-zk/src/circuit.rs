//! R1CS-Circuit für den ATLAS Batch-Commitment-Beweis.
//!
//! Öffentliche Eingaben: [pre_root, batch_merkle, total_fees, post_commitment]
//! Privater Zeuge:       [nonce]
//!
//! Bedingung: MiMC_sponge([pre_root, batch_merkle, total_fees, nonce]) == post_commitment
//!
//! Das beweist: Der Aggregator kennt einen Nonce, der die öffentlichen Daten
//! deterministisch mit dem post_commitment verknüpft (Commitment-Schema).

use ark_bn254::Fr;
use ark_r1cs_std::{
    fields::fp::FpVar,
    prelude::*,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::constants::mimc_constants;

/// Ein MiMC-7 Schritt im Circuit: y = (x + key + c)^7
fn mimc7_round_gadget(
    x:        &FpVar<Fr>,
    key:      &FpVar<Fr>,
    constant: Fr,
) -> Result<FpVar<Fr>, SynthesisError> {
    let c = FpVar::Constant(constant);
    let t = x + key + &c;   // linear, keine Multiplikation
    // t^7 = t^4 * t^2 * t (4 Multiplikationen)
    let t2 = t.square()?;
    let t4 = t2.square()?;
    let t6 = &t4 * &t2;
    Ok(&t6 * &t)
}

/// MiMC-7 Sponge im Circuit
fn mimc_sponge_gadget(
    inputs:    &[FpVar<Fr>],
    constants: &[Fr],
) -> Result<FpVar<Fr>, SynthesisError> {
    let mut state = FpVar::zero();
    for input in inputs {
        let mut x = state;
        let old_x = x.clone();
        // Verschlüssele: state → durch MIMC-Runden mit key=input
        for &c in constants {
            x = mimc7_round_gadget(&x, input, c)?;
        }
        let encrypted = x + input; // + key am Ende
        // Miyaguchi-Preneel: new_state = encrypted + old_state + input
        state = encrypted + &old_x + input;
    }
    Ok(state)
}

/// Groth16-Circuit für ATLAS Batch-Commitment-Beweis.
/// Einsatz: jeder `ProofRef` in einem Block wird gegen diesen Circuit verifiziert.
#[derive(Clone)]
pub struct BatchProofCircuit {
    // Öffentliche Eingaben (müssen dem Verifier bekannt sein)
    pub pre_root:        Fr,
    pub batch_merkle:    Fr,
    pub total_fees:      Fr,
    pub post_commitment: Fr,
    // Privater Zeuge (nur der Aggregator kennt diesen Wert)
    pub nonce:           Fr,
}

impl BatchProofCircuit {
    /// Dummy-Instanz für das Groth16-Setup (Werte egal)
    pub fn dummy() -> Self {
        BatchProofCircuit {
            pre_root:        Fr::from(0u64),
            batch_merkle:    Fr::from(0u64),
            total_fees:      Fr::from(0u64),
            post_commitment: Fr::from(0u64),
            nonce:           Fr::from(0u64),
        }
    }
}

impl ConstraintSynthesizer<Fr> for BatchProofCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Öffentliche Eingaben (Reihenfolge definiert das public-input-Format!)
        let pre_root        = FpVar::new_input(cs.clone(), || Ok(self.pre_root))?;
        let batch_merkle    = FpVar::new_input(cs.clone(), || Ok(self.batch_merkle))?;
        let total_fees      = FpVar::new_input(cs.clone(), || Ok(self.total_fees))?;
        let post_commitment = FpVar::new_input(cs.clone(), || Ok(self.post_commitment))?;

        // Privater Zeuge
        let nonce = FpVar::new_witness(cs, || Ok(self.nonce))?;

        // Bedingung berechnen und prüfen
        let constants = mimc_constants();
        let inputs = [pre_root, batch_merkle, total_fees, nonce];
        let computed = mimc_sponge_gadget(&inputs, &constants)?;

        // Assert: MiMC(...) == post_commitment
        computed.enforce_equal(&post_commitment)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;
    use crate::native::mimc_sponge;

    #[test]
    fn test_circuit_satisfiable() {
        let pre_root     = Fr::from(111u64);
        let batch_merkle = Fr::from(222u64);
        let total_fees   = Fr::from(333u64);
        let nonce        = Fr::from(999u64);

        let post_commitment = mimc_sponge(&[pre_root, batch_merkle, total_fees, nonce]);

        let circuit = BatchProofCircuit { pre_root, batch_merkle, total_fees, post_commitment, nonce };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap(), "Circuit must be satisfied with valid witness");
    }

    #[test]
    fn test_circuit_unsatisfiable_wrong_commitment() {
        let pre_root     = Fr::from(111u64);
        let batch_merkle = Fr::from(222u64);
        let total_fees   = Fr::from(333u64);
        let nonce        = Fr::from(999u64);

        // Falsches post_commitment (≠ MiMC output)
        let bad_commitment = Fr::from(1u64);

        let circuit = BatchProofCircuit {
            pre_root, batch_merkle, total_fees,
            post_commitment: bad_commitment,
            nonce,
        };

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap(), "Circuit must NOT be satisfied with wrong commitment");
    }
}
