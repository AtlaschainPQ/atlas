//! Geteilte Poseidon-Hash-Konfiguration für ATLAS-L2.
//!
//! ENTSCHEIDEND: native Referenz (`PoseidonSponge`) und Circuit-Gadget
//! (`PoseidonSpongeVar`) verwenden EXAKT dieselbe `PoseidonConfig`. Dadurch ist
//! garantiert, dass der im Circuit erzwungene State-Übergang bit-genau dem
//! nativen Executor entspricht — ohne diese Identität wäre der Beweis entweder
//! unerfüllbar oder still abgeschwächt.
//!
//! Parameter: BN254-Scalarfeld (254 Bit), Breite t = 3 (rate = 2, capacity = 1),
//! S-Box x^5 (alpha = 5), 8 volle + 57 partielle Runden — die Standard-
//! Poseidon-128-Parameter für BN254/t=3. Runden­konstanten und MDS-Matrix werden
//! deterministisch via `find_poseidon_ark_and_mds` erzeugt (Grain-LFSR), sodass
//! jede Node ohne eingebettete Tabellen identische Parameter rekonstruiert.

use ark_bn254::Fr;
use ark_crypto_primitives::sponge::{
    poseidon::{find_poseidon_ark_and_mds, PoseidonConfig, PoseidonSponge},
    CryptographicSponge,
};

/// Volle Runden (Standard Poseidon-128, BN254, t=3).
const FULL_ROUNDS: usize = 8;
/// Partielle Runden (Standard Poseidon-128, BN254, t=3).
const PARTIAL_ROUNDS: usize = 57;
/// S-Box-Exponent x^alpha.
const ALPHA: u64 = 5;
/// Rate (absorbierte Feldelemente pro Permutation).
const RATE: usize = 2;
/// Capacity.
const CAPACITY: usize = 1;
/// BN254-Scalarfeld-Bitbreite (für die Konstanten-Generierung).
const PRIME_BITS: u64 = 254;

/// Baut die geteilte Poseidon-Konfiguration.
///
/// Deterministisch: identisch auf jeder Node und in jedem Build. Wird sowohl
/// nativ als auch im Circuit verwendet.
pub fn poseidon_config() -> PoseidonConfig<Fr> {
    // skip_matrices = 0: kein Überspringen — fixiert eine deterministische Wahl.
    let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(
        PRIME_BITS,
        RATE,
        FULL_ROUNDS as u64,
        PARTIAL_ROUNDS as u64,
        0,
    );
    PoseidonConfig::new(FULL_ROUNDS, PARTIAL_ROUNDS, ALPHA, mds, ark, RATE, CAPACITY)
}

/// Native 2-zu-1-Kompression (für innere Merkle-Knoten): H(left, right).
pub fn hash_two(left: Fr, right: Fr) -> Fr {
    let cfg = poseidon_config();
    let mut sponge = PoseidonSponge::<Fr>::new(&cfg);
    sponge.absorb(&left);
    sponge.absorb(&right);
    sponge.squeeze_field_elements(1)[0]
}

/// Native Hash über einen Slice von Feldelementen (für Blatt-/Domänen-Hashes).
pub fn hash_many(inputs: &[Fr]) -> Fr {
    let cfg = poseidon_config();
    let mut sponge = PoseidonSponge::<Fr>::new(&cfg);
    for x in inputs {
        sponge.absorb(x);
    }
    sponge.squeeze_field_elements(1)[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Zero;

    #[test]
    fn config_is_deterministic() {
        let a = poseidon_config();
        let b = poseidon_config();
        assert_eq!(a.full_rounds, b.full_rounds);
        assert_eq!(a.partial_rounds, b.partial_rounds);
        assert_eq!(a.ark, b.ark);
        assert_eq!(a.mds, b.mds);
    }

    #[test]
    fn hash_two_is_deterministic_and_order_sensitive() {
        let a = Fr::from(3u64);
        let b = Fr::from(5u64);
        assert_eq!(hash_two(a, b), hash_two(a, b));
        assert_ne!(hash_two(a, b), hash_two(b, a));
        assert_ne!(hash_two(a, b), Fr::zero());
    }

    #[test]
    fn hash_many_matches_hash_two_semantics() {
        // hash_many über zwei Elemente nutzt dieselbe Sponge wie hash_two.
        let a = Fr::from(7u64);
        let b = Fr::from(11u64);
        assert_eq!(hash_many(&[a, b]), hash_two(a, b));
    }
}
