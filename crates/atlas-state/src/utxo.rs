//! UTXO-Set — RAM-basiert, O(1) Lookup
//!
//! Ziel: 40k+ TPS — deterministische Parallelisierung durch
//! partition-basierte Micro-Batch Verarbeitung.

use std::collections::HashMap;
use atlas_core::amount::Amount;
use atlas_core::crypto::Address;
use atlas_core::pq_crypto::PqAddress;
use atlas_core::transaction::{OutPoint, TxId, Transaction, OutputAddress};
use atlas_core::block::BlockHeight;
use atlas_core::utxo_query::UtxoQuery;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use parking_lot::{Mutex, RwLock};

#[derive(Error, Debug)]
pub enum UtxoError {
    #[error("UTXO not found: {0:?}")]
    NotFound(OutPoint),
    #[error("UTXO already spent: {0:?}")]
    AlreadySpent(OutPoint),
    #[error("Insufficient funds: available {available}, required {required}")]
    InsufficientFunds { available: Amount, required: Amount },
    #[error("Output index out of range: {index} for tx with {count} outputs")]
    IndexOutOfRange { index: u32, count: usize },
}

/// Einzelner UTXO-Eintrag
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Utxo {
    pub value:         Amount,
    pub address:       OutputAddress,
    pub block_height:  BlockHeight,
    pub is_coinbase:   bool,
}

/// Delta seit letztem `drain_delta()` — für inkrementelle Disk-Persistenz
pub struct UtxoDelta {
    pub created: Vec<(OutPoint, Utxo)>,
    pub spent:   Vec<OutPoint>,
}

/// RAM-basierter UTXO-Set
pub struct UtxoSet {
    utxos: RwLock<HashMap<OutPoint, Utxo>>,
    /// Akkumulierte Änderungen seit letztem drain_delta() — für Storage-Sync
    delta: Mutex<UtxoDelta>,
}

impl UtxoSet {
    pub fn new() -> Self {
        UtxoSet {
            utxos: RwLock::new(HashMap::new()),
            delta: Mutex::new(UtxoDelta { created: vec![], spent: vec![] }),
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        UtxoSet {
            utxos: RwLock::new(HashMap::with_capacity(capacity)),
            delta: Mutex::new(UtxoDelta { created: vec![], spent: vec![] }),
        }
    }

    /// Fügt neue UTXOs aus einer Transaktion ein
    pub fn apply_outputs(&self, txid: TxId, tx: &Transaction, height: BlockHeight) {
        let mut utxos = self.utxos.write();
        let mut delta = self.delta.lock();
        for (index, output) in tx.outputs.iter().enumerate() {
            // Modell A: wertlose Outputs (Coinbase-L2-Adress-Marker, SettlementBid-
            // bid_output, L2ForcedTx-Marker) erzeugen KEINE UTXOs — sie tragen
            // keinen ausgebbaren L1-Wert. Sonst würde das UTXO-Set über die Zeit mit
            // unausgebbaren Null-Wert-Einträgen anwachsen (Bloat). Die Index-
            // Nummerierung bleibt unverändert (nach Position), nur die Einfügung
            // entfällt. Konsens-neutral: die UTXO-State-Root ist nicht im
            // Block-Header committet/validiert.
            if output.value.as_atom() == 0 {
                continue;
            }
            let outpoint = OutPoint { txid, index: index as u32 };
            let utxo = Utxo {
                value:        output.value,
                address:      output.address.clone(),
                block_height: height,
                is_coinbase:  tx.is_coinbase(),
            };
            delta.created.push((outpoint, utxo.clone()));
            utxos.insert(outpoint, utxo);
        }
    }

    /// Entfernt verbrauchte UTXOs (Inputs)
    pub fn spend_inputs(
        &self,
        tx:     &Transaction,
        height: BlockHeight,
        coinbase_maturity: u64,
    ) -> Result<Vec<(OutPoint, Utxo)>, UtxoError> {
        let mut utxos   = self.utxos.write();
        let mut spent   = Vec::new();

        for input in &tx.inputs {
            if tx.is_coinbase() { continue; }
            let op = OutPoint {
                txid:  input.prev_txid,
                index: input.prev_index,
            };

            let utxo = utxos.get(&op)
                .ok_or(UtxoError::NotFound(op))?;

            // Coinbase-Reife prüfen
            if utxo.is_coinbase && height < utxo.block_height + coinbase_maturity {
                return Err(UtxoError::InsufficientFunds {
                    available: Amount::ZERO,
                    required:  utxo.value,
                });
            }

            spent.push((op, utxo.clone()));
        }

        // Alle erst entfernen wenn alle gefunden
        {
            let mut delta = self.delta.lock();
            for (op, _) in &spent {
                utxos.remove(op);
                delta.spent.push(*op);
            }
        }

        Ok(spent)
    }

    /// Prüft ob alle Inputs einer TX verfügbar und mature sind — ohne zu spenden.
    /// Wird in block_template verwendet um ungültige TXs zu überspringen.
    pub fn inputs_available(
        &self,
        tx:                &Transaction,
        height:            BlockHeight,
        coinbase_maturity: u64,
    ) -> bool {
        if tx.is_coinbase() { return true; }
        // SettlementBid/L2ForcedTx haben Pseudo-Inputs (keine echten UTXOs) → immer "verfügbar"
        if tx.has_pseudo_inputs() {
            return true;
        }
        let utxos = self.utxos.read();
        for input in &tx.inputs {
            let op = OutPoint { txid: input.prev_txid, index: input.prev_index };
            match utxos.get(&op) {
                None => return false,
                Some(utxo) => {
                    if utxo.is_coinbase && height < utxo.block_height + coinbase_maturity {
                        return false;
                    }
                }
            }
        }
        true
    }

    /// Gibt den akkumulierten Delta zurück und setzt ihn zurück.
    /// Wird nach jedem Block aufgerufen um inkrementell auf Disk zu schreiben.
    pub fn drain_delta(&self) -> UtxoDelta {
        let mut delta = self.delta.lock();
        UtxoDelta {
            created: std::mem::take(&mut delta.created),
            spent:   std::mem::take(&mut delta.spent),
        }
    }

    /// UTXO-Lookup
    pub fn get(&self, op: &OutPoint) -> Option<Utxo> {
        self.utxos.read().get(op).cloned()
    }

    pub fn contains(&self, op: &OutPoint) -> bool {
        self.utxos.read().contains_key(op)
    }

    /// Gesamter UTXO-Wert (für Supply-Verifikation)
    pub fn total_value(&self) -> Amount {
        self.utxos.read().values()
            .fold(Amount::ZERO, |acc, u| acc + u.value)
    }

    /// Alle UTXOs einer klassischen Adresse
    pub fn utxos_for_address(&self, address: &Address) -> Vec<(OutPoint, Utxo)> {
        let target = OutputAddress::Classic(*address);
        self.utxos.read().iter()
            .filter(|(_, u)| u.address == target)
            .map(|(op, u)| (*op, u.clone()))
            .collect()
    }

    /// Saldo einer klassischen Adresse
    pub fn balance(&self, address: &Address) -> Amount {
        self.utxos_for_address(address)
            .iter()
            .fold(Amount::ZERO, |acc, (_, u)| acc + u.value)
    }

    /// Alle UTXOs einer Post-Quantum-Adresse (ATLQ:)
    pub fn utxos_for_pq_address(&self, address: &PqAddress) -> Vec<(OutPoint, Utxo)> {
        let target = OutputAddress::Quantum(*address);
        self.utxos.read().iter()
            .filter(|(_, u)| u.address == target)
            .map(|(op, u)| (*op, u.clone()))
            .collect()
    }

    /// Saldo einer Post-Quantum-Adresse (ATLQ:)
    pub fn balance_pq(&self, address: &PqAddress) -> Amount {
        self.utxos_for_pq_address(address)
            .iter()
            .fold(Amount::ZERO, |acc, (_, u)| acc + u.value)
    }

    pub fn len(&self) -> usize {
        self.utxos.read().len()
    }

    pub fn is_empty(&self) -> bool { self.len() == 0 }

    /// Erzeugt einen Snapshot des aktuellen UTXO-Sets
    pub fn snapshot(&self) -> HashMap<OutPoint, Utxo> {
        self.utxos.read().clone()
    }

    /// Stellt einen Snapshot wieder her (für Reorg) — setzt Delta zurück
    pub fn restore(&self, snapshot: HashMap<OutPoint, Utxo>) {
        *self.utxos.write() = snapshot;
        let mut delta = self.delta.lock();
        delta.created.clear();
        delta.spent.clear();
    }

    /// Re-inserts a set of previously spent UTXOs (rollback on failed tx)
    pub fn restore_utxos(&self, utxos: &[(OutPoint, Utxo)]) {
        let mut set = self.utxos.write();
        for (op, utxo) in utxos {
            set.insert(*op, utxo.clone());
        }
    }
}

impl Default for UtxoSet {
    fn default() -> Self { Self::new() }
}

impl UtxoQuery for UtxoSet {
    fn has_utxo(&self, op: &OutPoint) -> bool {
        self.utxos.read().contains_key(op)
    }

    fn utxo_address(&self, op: &OutPoint) -> Option<OutputAddress> {
        self.utxos.read().get(op).map(|u| u.address.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use atlas_core::transaction::Transaction;
    use atlas_core::crypto::Address;

    #[test]
    fn test_utxo_apply_and_lookup() {
        let set   = UtxoSet::new();
        let addr  = Address([1u8; 20]);
        let mut coinbase = Transaction::new_coinbase(
            0,
            Amount::from_atl(44),
            Amount::from_atl(19),
            addr,
            Address([2u8; 20]),
        );
        // Modell A: Die Coinbase ist L1-wertlos (Output 0). Für diesen reinen
        // UTXO-Set-Mechanik-Test injizieren wir einen Wert.
        coinbase.outputs[0].value = Amount::from_atl(44);
        let txid = coinbase.txid();
        set.apply_outputs(txid, &coinbase, 0);

        let op = OutPoint { txid, index: 0 };
        let utxo = set.get(&op).expect("UTXO should exist");
        assert_eq!(utxo.address, OutputAddress::Classic(addr));
        assert_eq!(utxo.value.as_atl_floor(), 44);
        assert_eq!(set.balance(&addr).as_atl_floor(), 44);
    }

    #[test]
    fn test_zero_value_outputs_skipped() {
        // Modell A: wertlose Outputs (z.B. die L1-wertlose Coinbase) erzeugen
        // KEINE UTXOs — verhindert Null-Wert-UTXO-Bloat.
        let set  = UtxoSet::new();
        let addr = Address([7u8; 20]);
        let coinbase = Transaction::new_coinbase(0, Amount::ZERO, Amount::ZERO, addr, Address([8u8; 20]));
        let before = set.len();
        set.apply_outputs(coinbase.txid(), &coinbase, 0);
        assert_eq!(set.len(), before, "wertlose Coinbase-Outputs dürfen keine UTXOs erzeugen");
        assert_eq!(set.balance(&addr).as_atom(), 0);
    }

    #[test]
    fn test_delta_tracking() {
        let set  = UtxoSet::new();
        let addr = Address([1u8; 20]);
        let mut cb = Transaction::new_coinbase(1, Amount::from_atl(50), Amount::ZERO, addr, addr);
        // Modell A: Coinbase L1-wertlos (→ kein UTXO). Für den Delta-Tracking-Test
        // injizieren wir einen Wert in den (einzigen) Output.
        cb.outputs[0].value = Amount::from_atl(50);
        let txid = cb.txid();
        set.apply_outputs(txid, &cb, 1);

        let delta = set.drain_delta();
        assert_eq!(delta.created.len(), 1); // ein wertiger Output
        assert!(delta.spent.is_empty());

        // Nach drain: delta ist leer
        let delta2 = set.drain_delta();
        assert!(delta2.created.is_empty());
    }
}
