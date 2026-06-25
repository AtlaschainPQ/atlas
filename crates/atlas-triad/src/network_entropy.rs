//! Netzwerk-Entropie für TRIAD
//!
//! Peer-Gossip-Inputs werden in den Mining-Prozess eingearbeitet.
//! Minimaler Latenz-Bias, keine zentrale Abhängigkeit.
//! Verhindert vollständige Vorausberechnung durch Isolierung.

use atlas_core::hash::Hash;
use serde::{Deserialize, Serialize};

/// Netzwerk-Entropie: gesammelt aus Peer-Gossip
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkEntropy {
    /// Aggregierter Hash aller eingegangener Peer-Messages in diesem Block-Intervall
    pub entropy_hash: Hash,
    /// Anzahl der beigetragenen Peers
    pub peer_count:   u32,
    /// Zeitstempel der letzten Aktualisierung
    pub updated_at:   u64,
}

impl NetworkEntropy {
    pub fn new() -> Self {
        NetworkEntropy {
            entropy_hash: Hash::sha256(b"ATLAS-genesis-entropy"),
            peer_count:   0,
            updated_at:   0,
        }
    }

    /// Fügt einen Peer-Beitrag hinzu
    pub fn add_peer_input(&mut self, peer_hash: &Hash, timestamp: u64) {
        let input = [
            self.entropy_hash.as_bytes().as_ref(),
            peer_hash.as_bytes().as_ref(),
            &timestamp.to_le_bytes(),
        ].concat();
        self.entropy_hash = Hash::sha256(&input);
        self.peer_count  += 1;
        self.updated_at   = timestamp;
    }

    /// Mischt die Entropie in den Block-Header-Hash
    pub fn mix_with_header(&self, header_hash: &Hash) -> Hash {
        let input = [
            header_hash.as_bytes().as_ref(),
            self.entropy_hash.as_bytes().as_ref(),
            &self.peer_count.to_le_bytes(),
        ].concat();
        Hash::sha256(&input)
    }
}

impl Default for NetworkEntropy {
    fn default() -> Self { Self::new() }
}
