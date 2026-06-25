//! Native (nicht-circuit) MiMC-7 Implementierung für den Prover.

use ark_bn254::Fr;
use ark_ff::Field;

use crate::constants::mimc_constants;

/// MiMC-7 Verschlüsselung: E(x, key) = ((x+key+c0)^7 + key + c1)^7 + ... + key
pub fn mimc7_encrypt(mut x: Fr, key: Fr) -> Fr {
    let constants = mimc_constants();
    for &c in &constants {
        let t = x + key + c;
        x = t.pow([7u64]);
    }
    x + key
}

/// MiMC-7 Sponge (Miyaguchi-Preneel Konstruktion)
/// h_i = E(h_{i-1}, m_i) + h_{i-1} + m_i
pub fn mimc_sponge(inputs: &[Fr]) -> Fr {
    let mut state = Fr::from(0u64);
    for &input in inputs {
        let encrypted = mimc7_encrypt(state, input);
        state = encrypted + state + input;
    }
    state
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Zero;

    #[test]
    fn test_mimc_sponge_deterministic() {
        let a = Fr::from(42u64);
        let b = Fr::from(1337u64);
        let r1 = mimc_sponge(&[a, b]);
        let r2 = mimc_sponge(&[a, b]);
        assert_eq!(r1, r2, "MiMC sponge must be deterministic");
    }

    #[test]
    fn test_mimc_sponge_differs_on_different_input() {
        let r1 = mimc_sponge(&[Fr::from(1u64), Fr::from(2u64)]);
        let r2 = mimc_sponge(&[Fr::from(1u64), Fr::from(3u64)]);
        assert_ne!(r1, r2, "Different inputs must produce different outputs");
    }

    #[test]
    fn test_mimc_zero_input_nonzero_output() {
        let result = mimc_sponge(&[Fr::zero(), Fr::zero()]);
        assert_ne!(result, Fr::zero(), "MiMC of zeros should not be zero (due to round constants)");
    }
}
