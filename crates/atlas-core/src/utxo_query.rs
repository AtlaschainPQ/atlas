use crate::transaction::{OutPoint, OutputAddress};

/// Minimales Interface zum UTXO-Lookup.
/// Erlaubt dem Mempool UTXO-Prüfung ohne Abhängigkeit auf atlas-state.
pub trait UtxoQuery: Send + Sync {
    fn has_utxo(&self, op: &OutPoint) -> bool;
    /// Gibt die Eigentümer-Adresse des UTXOs zurück, oder None wenn nicht vorhanden.
    /// Liefert klassische *und* Post-Quantum-Adressen.
    fn utxo_address(&self, op: &OutPoint) -> Option<OutputAddress>;
}
