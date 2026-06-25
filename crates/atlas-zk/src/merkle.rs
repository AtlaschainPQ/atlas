//! Sparse Merkle-Baum fester Tiefe über BN254-`Fr`, mit Poseidon-2-zu-1.
//!
//! Kontoindex-basiert (sequenzielle Allokation, wie zkSync): jedes Konto belegt
//! einen `u64`-Blattindex in einem Baum der Tiefe `DEPTH`. Dadurch bleibt ein
//! Authentifizierungspfad bei `DEPTH` Hashes (statt der vollen Adressbitbreite).
//!
//! Nur belegte Knoten werden materialisiert; alle übrigen Teilbäume sind durch
//! die vorab berechneten „leeren" Hashes (`empty[level]`) bestimmt. Das erlaubt
//! einen Baum der Tiefe 32 (4 Mrd. Blätter) bei O(DEPTH) pro Update/Pfad.

use ark_bn254::Fr;
use ark_ff::Zero;
use std::collections::HashMap;

use crate::poseidon::hash_two;

/// Baumtiefe: 2^32 Konten-Slots. Pfadlänge = 32 Poseidon-Hashes.
pub const DEPTH: usize = 32;

/// Ein Authentifizierungspfad: Geschwisterhashes von Blatt-Ebene nach oben,
/// plus der Blattindex (dessen Bits links/rechts pro Ebene kodieren).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerklePath {
    pub index:    u64,
    pub siblings: Vec<Fr>, // Länge == DEPTH, siblings[0] = Geschwister auf Blattebene
}

/// Sparse Merkle-Baum fester Tiefe.
#[derive(Clone)]
pub struct MerkleTree {
    depth: usize,
    /// `empty[l]` = Wurzel eines vollständig leeren Teilbaums der Höhe `l`.
    empty: Vec<Fr>,
    /// Nur belegte Knoten: Schlüssel `(level, index)`, level 0 = Blattebene.
    nodes: HashMap<(usize, u64), Fr>,
}

impl MerkleTree {
    /// Neuer leerer Baum der Standardtiefe `DEPTH`.
    pub fn new() -> Self {
        Self::with_depth(DEPTH)
    }

    pub fn with_depth(depth: usize) -> Self {
        // empty[0] = 0 (leeres Blatt = „kein Konto"); empty[l] = H(empty[l-1], empty[l-1]).
        let mut empty = Vec::with_capacity(depth + 1);
        empty.push(Fr::zero());
        for l in 1..=depth {
            let prev = empty[l - 1];
            empty.push(hash_two(prev, prev));
        }
        MerkleTree { depth, empty, nodes: HashMap::new() }
    }

    /// Hash eines Knotens — gespeichert oder, falls leer, der `empty[level]`-Default.
    fn node(&self, level: usize, index: u64) -> Fr {
        self.nodes.get(&(level, index)).copied().unwrap_or(self.empty[level])
    }

    /// Aktuelle Wurzel.
    pub fn root(&self) -> Fr {
        self.node(self.depth, 0)
    }

    /// Setzt den Blattwert an `index` und rechnet den Pfad zur Wurzel neu.
    pub fn set_leaf(&mut self, index: u64, leaf: Fr) {
        debug_assert!((index as u128) < (1u128 << self.depth), "Blattindex außerhalb der Baumtiefe");
        self.nodes.insert((0, index), leaf);
        let mut idx = index;
        for level in 0..self.depth {
            let parent = idx >> 1;
            let left = self.node(level, parent << 1);
            let right = self.node(level, (parent << 1) | 1);
            self.nodes.insert((level + 1, parent), hash_two(left, right));
            idx = parent;
        }
    }

    /// Aktueller Blattwert an `index`.
    pub fn leaf(&self, index: u64) -> Fr {
        self.node(0, index)
    }

    /// Authentifizierungspfad für `index` (Geschwister von unten nach oben).
    pub fn path(&self, index: u64) -> MerklePath {
        let mut siblings = Vec::with_capacity(self.depth);
        let mut idx = index;
        for level in 0..self.depth {
            let sibling = idx ^ 1;
            siblings.push(self.node(level, sibling));
            idx >>= 1;
        }
        MerklePath { index, siblings }
    }

    /// `empty[level]`-Defaults (für Circuit-Konstanten / Tests).
    pub fn empty_hashes(&self) -> &[Fr] {
        &self.empty
    }
}

impl Default for MerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

/// Native Nachrechnung der Wurzel aus Blatt + Pfad (Referenz für die Circuit-
/// Inklusions-Constraint). Faltet `leaf` mit den Geschwistern hoch; das jeweils
/// `bit`-te Bit von `index` entscheidet, ob das laufende Element links/rechts steht.
pub fn root_from_path(leaf: Fr, path: &MerklePath) -> Fr {
    let mut cur = leaf;
    let mut idx = path.index;
    for sibling in &path.siblings {
        cur = if idx & 1 == 0 {
            hash_two(cur, *sibling) // laufendes Element ist linkes Kind
        } else {
            hash_two(*sibling, cur) // laufendes Element ist rechtes Kind
        };
        idx >>= 1;
    }
    cur
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_root_stable() {
        let t1 = MerkleTree::new();
        let t2 = MerkleTree::new();
        assert_eq!(t1.root(), t2.root());
    }

    #[test]
    fn set_leaf_changes_root_and_path_verifies() {
        let mut t = MerkleTree::new();
        let r0 = t.root();
        let leaf = Fr::from(42u64);
        t.set_leaf(7, leaf);
        assert_ne!(t.root(), r0, "Wurzel muss sich ändern");

        let path = t.path(7);
        assert_eq!(path.siblings.len(), DEPTH);
        assert_eq!(root_from_path(leaf, &path), t.root(), "Pfad muss die Wurzel rekonstruieren");
    }

    #[test]
    fn two_leaves_independent_paths() {
        let mut t = MerkleTree::new();
        t.set_leaf(3, Fr::from(100u64));
        t.set_leaf(10, Fr::from(200u64));

        let p3 = t.path(3);
        let p10 = t.path(10);
        assert_eq!(root_from_path(Fr::from(100u64), &p3), t.root());
        assert_eq!(root_from_path(Fr::from(200u64), &p10), t.root());
    }

    #[test]
    fn stale_path_fails_after_update() {
        let mut t = MerkleTree::new();
        t.set_leaf(5, Fr::from(1u64));
        let old_path = t.path(5);
        // Ein anderes Blatt ändern, das denselben oberen Teilbaum teilt.
        t.set_leaf(4, Fr::from(9u64));
        assert_ne!(root_from_path(Fr::from(1u64), &old_path), t.root(),
            "veralteter Pfad darf die neue Wurzel nicht rekonstruieren");
    }
}
