//! Mempool — Warteraum für unbestätigte Transaktionen
//!
//! Kernfunktionen:
//! - TX-Stamp Verifikation (Spam-Schutz)
//! - Fee-basierte Sortierung (höchste Fees zuerst)
//! - UTXO-Lookup für Double-Spend Prüfung
//! - Settlement-Bid Priorisierung

use std::collections::HashMap;
use std::sync::Arc;
use atlas_core::transaction::{Transaction, TxId, TxType, OutPoint, DerivedAddress, OutputAddress};
use atlas_core::hash::Hash;
use atlas_core::amount::Amount;
use atlas_core::utxo_query::UtxoQuery;
use atlas_consensus::params::ConsensusParams;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Error, Debug)]
pub enum MempoolError {
    #[error("Transaction already in mempool: {0:?}")]
    AlreadyExists(TxId),
    #[error("TX-Stamp missing")]
    MissingStamp,
    #[error("TX-Stamp invalid")]
    InvalidStamp,
    #[error("Fee too low: {fee} < {min}")]
    FeeTooLow { fee: u128, min: u128 },
    #[error("Fee above cap: {fee} > {max}")]
    FeeAboveCap { fee: u128, max: u128 },
    #[error("Mempool full: {size} / {max}")]
    Full { size: usize, max: usize },
    #[error("Transaction too old")]
    Expired,
    #[error("Double spend: {0:?}")]
    DoubleSpend(OutPoint),
    #[error("Coinbase in mempool")]
    CoinbaseRejected,
    #[error("Input references unknown UTXO: {0:?}")]
    UnknownInput(OutPoint),
    #[error("Input #{index}: public key does not match UTXO owner")]
    PubkeyMismatch { index: usize },
    #[error("Input #{index}: invalid signature")]
    InvalidSignature { index: usize },
    #[error("Duplicate settlement batch: {0:?}")]
    DuplicateBatch(Hash),
    #[error("Timestamp too far in future: {ts_ms} ms > now {now_ms} ms + max drift")]
    TimestampTooFarFuture { ts_ms: u64, now_ms: u64 },
}

/// Maximal erlaubte Zukunfts-Abweichung des TX-Timestamps (2 Stunden, in ms).
/// Großzügiges Fenster gegen Uhren-Drift; weit entfernte Zukunfts-TX werden
/// als Relay-Policy abgelehnt (kein Konsenseingriff). Alte TX bleiben erlaubt.
const MAX_TX_FUTURE_DRIFT_MS: u64 = 2 * 60 * 60 * 1000;

/// Mempool-Eintrag mit Metadaten
#[derive(Clone, Debug)]
pub struct MempoolEntry {
    pub tx:          Transaction,
    pub txid:        TxId,
    pub received_at: u64,
    /// Fee-Rate in ATOM (für Sortierung)
    pub fee_atom:    u128,
    /// Settlement-Bid? Hohe Priorität
    pub is_bid:      bool,
}

impl MempoolEntry {
    fn priority(&self) -> u128 {
        if self.is_bid {
            // Bids immer höchste Priorität
            u128::MAX
        } else if matches!(self.tx.tx_type, TxType::L2ForcedTx { .. }) {
            // Forced-Inclusion-TXs direkt dahinter — Zensurresistenz hängt daran,
            // dass sie zügig on-chain landen.
            u128::MAX - 1
        } else {
            self.fee_atom
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MempoolStats {
    pub tx_count:       usize,
    pub total_fees:     Amount,
    pub avg_fee_atom:   u128,
    pub min_fee_atom:   u128,
    pub max_fee_atom:   u128,
    pub bid_count:      usize,
}

/// Thread-sicherer Mempool
pub struct Mempool {
    params:       ConsensusParams,
    /// TxId → Entry
    entries:      RwLock<HashMap<TxId, MempoolEntry>>,
    /// Verbrauchte OutPoints (Double-Spend Tracking)
    spent_ops:    RwLock<HashMap<OutPoint, TxId>>,
    /// Outputs von Mempool-TXs — erlaubt chained TXs; speichert Eigentümer-Adresse für Sig-Check
    mempool_utxos: RwLock<HashMap<OutPoint, OutputAddress>>,
    /// Settlement-Bids pro batch_id (Dedup: nur EIN Bid je Batch gleichzeitig im Mempool)
    bid_batches:  RwLock<HashMap<Hash, TxId>>,
    /// Maximale Größe
    max_size:     usize,
    /// TX-Ablaufzeit (Sekunden)
    expiry_secs:  u64,
    /// Optionaler UTXO-Lookup zum Validieren dass Inputs existieren
    utxo:         Option<Arc<dyn UtxoQuery>>,
}

impl Mempool {
    pub fn new(params: ConsensusParams) -> Self {
        Mempool {
            params,
            entries:       RwLock::new(HashMap::new()),
            spent_ops:     RwLock::new(HashMap::new()),
            mempool_utxos: RwLock::new(HashMap::new()),
            bid_batches:   RwLock::new(HashMap::new()),
            max_size:      50_000,
            expiry_secs:   3600 * 12,
            utxo:          None,
        }
    }

    /// Verbindet den Mempool mit dem UTXO-Set für Existenzprüfung.
    pub fn with_utxo(mut self, utxo: Arc<dyn UtxoQuery>) -> Self {
        self.utxo = Some(utxo);
        self
    }

    /// Fügt eine Transaktion hinzu
    pub fn submit(&self, tx: Transaction) -> Result<TxId, MempoolError> {
        if tx.is_coinbase() {
            return Err(MempoolError::CoinbaseRejected);
        }

        let txid = tx.txid();

        // Fee-Check and stamp verification are pure computation — no lock needed
        let fee = tx.fee.as_atom();
        if fee < self.params.min_fee_atom {
            return Err(MempoolError::FeeTooLow { fee, min: self.params.min_fee_atom });
        }
        if fee > self.params.max_fee_atom {
            return Err(MempoolError::FeeAboveCap { fee, max: self.params.max_fee_atom });
        }

        match &tx.stamp {
            None => return Err(MempoolError::MissingStamp),
            Some(stamp) => {
                if !stamp.quick_verify(&txid) {
                    return Err(MempoolError::InvalidStamp);
                }
            }
        }

        let now    = now_secs();
        // Timestamp-Sanity: TX aus ferner Zukunft ablehnen (tx.timestamp ist in ms).
        // Reine Relay-Policy — kein Konsenseingriff. Alte TX bleiben erlaubt.
        let now_ms = now.saturating_mul(1000);
        if tx.timestamp > now_ms.saturating_add(MAX_TX_FUTURE_DRIFT_MS) {
            return Err(MempoolError::TimestampTooFarFuture { ts_ms: tx.timestamp, now_ms });
        }

        // Settlement-Bid? batch_id für Dedup extrahieren.
        let bid_batch_id: Option<Hash> = match &tx.tx_type {
            TxType::SettlementBid { batch_id, .. } => Some(*batch_id),
            _ => None,
        };
        let is_bid = bid_batch_id.is_some();

        // L2ForcedTx: Format-Sanity sofort (Konsens lehnt sonst erst den Block ab).
        if let TxType::L2ForcedTx { sig, .. } = &tx.tx_type {
            if sig.len() != 64 {
                return Err(MempoolError::InvalidSignature { index: 0 });
            }
        }

        // ── Phase 1: Signatur-Verifikation OHNE Write-Lock ────────────────────
        // Read-Lock nur kurz halten um Adressen zu kopieren, dann sofort droppen.
        // ECDSA-Verifikation (~0.5ms) läuft danach ohne jeglichen Lock.
        // SettlementBid/L2ForcedTx haben Pseudo-Inputs → UTXO-Check überspringen.
        if self.utxo.is_some() && !tx.has_pseudo_inputs() {
            let input_addrs: Vec<(OutPoint, Option<OutputAddress>)> = {
                let mempool_utxos = self.mempool_utxos.read();
                tx.inputs.iter().map(|input| {
                    let op = OutPoint { txid: input.prev_txid, index: input.prev_index };
                    let addr = self.utxo.as_ref()
                        .and_then(|u| u.utxo_address(&op))
                        .or_else(|| mempool_utxos.get(&op).cloned());
                    (op, addr)
                }).collect()
            }; // read lock wird hier gedroppt

            for (idx, (input, (op, owner_addr))) in
                tx.inputs.iter().zip(input_addrs.iter()).enumerate()
            {
                match owner_addr {
                    None => return Err(MempoolError::UnknownInput(*op)),
                    Some(addr) => {
                        // Address-Abgleich: Witness-Adresse muss mit UTXO-Eigentümer übereinstimmen.
                        // Unterstützt klassische (ECDSA) und Post-Quantum (ML-DSA) Witnesses.
                        let derived = input.witness.derived_address();
                        let addr_ok = match (&derived, addr) {
                            (DerivedAddress::Classic(d), OutputAddress::Classic(u)) => d == u,
                            (DerivedAddress::Quantum(d), OutputAddress::Quantum(u)) => d == u,
                            _ => false, // Adress-Typ-Mismatch (klassisch vs. PQ)
                        };
                        if !addr_ok {
                            return Err(MempoolError::PubkeyMismatch { index: idx });
                        }
                        if input.witness.verify(txid.as_bytes()).is_err() {
                            return Err(MempoolError::InvalidSignature { index: idx });
                        }
                    }
                }
            }
        }

        // ── Phase 2: Zustandsprüfung + Mutation unter Write-Lock ─────────────
        let mut entries       = self.entries.write();
        let mut spent         = self.spent_ops.write();
        let mut mempool_utxos = self.mempool_utxos.write();
        let mut bid_batches   = self.bid_batches.write();

        if entries.contains_key(&txid) {
            return Err(MempoolError::AlreadyExists(txid));
        }
        if entries.len() >= self.max_size {
            return Err(MempoolError::Full { size: entries.len(), max: self.max_size });
        }

        // Bid-Dedup: pro batch_id nur EIN Bid gleichzeitig im Mempool — verhindert
        // konkurrierende Bids mit unterschiedlichem Betrag für denselben Batch.
        if let Some(bid_id) = bid_batch_id {
            if bid_batches.contains_key(&bid_id) {
                return Err(MempoolError::DuplicateBatch(bid_id));
            }
        }

        // SettlementBid/L2ForcedTx: Pseudo-Inputs nicht als Double-Spend tracken
        if !tx.has_pseudo_inputs() {
            for input in &tx.inputs {
                let op = OutPoint { txid: input.prev_txid, index: input.prev_index };
                if spent.contains_key(&op) {
                    return Err(MempoolError::DoubleSpend(op));
                }
            }
        }

        for (i, output) in tx.outputs.iter().enumerate() {
            // Outputs (klassisch + PQ) für chained-TX Prüfung speichern
            mempool_utxos.insert(OutPoint { txid, index: i as u32 }, output.address.clone());
        }
        if !tx.has_pseudo_inputs() {
            for input in &tx.inputs {
                spent.insert(OutPoint { txid: input.prev_txid, index: input.prev_index }, txid);
            }
        }

        if let Some(bid_id) = bid_batch_id {
            bid_batches.insert(bid_id, txid);
        }

        entries.insert(txid, MempoolEntry { fee_atom: fee, txid, received_at: now, is_bid, tx });
        Ok(txid)
    }

    /// Gibt die besten N Transaktionen zurück (nach Fee sortiert)
    pub fn select_for_block(&self, max_count: usize) -> Vec<Transaction> {
        let entries = self.entries.read();
        let mut sorted: Vec<&MempoolEntry> = entries.values().collect();
        sorted.sort_by_key(|e| std::cmp::Reverse(e.priority()));
        sorted.into_iter()
            .take(max_count)
            .map(|e| e.tx.clone())
            .collect()
    }

    /// Entfernt Transaktionen die in einem Block bestätigt wurden
    pub fn remove_confirmed(&self, confirmed_txids: &[TxId]) {
        let mut entries       = self.entries.write();
        let mut spent         = self.spent_ops.write();
        let mut mempool_utxos = self.mempool_utxos.write();
        let mut bid_batches   = self.bid_batches.write();

        for txid in confirmed_txids {
            if let Some(entry) = entries.remove(txid) {
                // Inputs freigeben
                for input in &entry.tx.inputs {
                    spent.remove(&OutPoint { txid: input.prev_txid, index: input.prev_index });
                }
                // Mempool-Outputs dieser TX entfernen (jetzt im bestätigten UTXO-Set)
                for (i, _) in entry.tx.outputs.iter().enumerate() {
                    mempool_utxos.remove(&OutPoint { txid: *txid, index: i as u32 });
                }
                // Bid-Batch freigeben → neuer Bid für denselben Batch wieder möglich
                if let TxType::SettlementBid { batch_id, .. } = &entry.tx.tx_type {
                    bid_batches.remove(batch_id);
                }
            }
        }
    }

    /// Entfernt abgelaufene Transaktionen
    pub fn evict_expired(&self) {
        let now     = now_secs();
        let expired: Vec<TxId> = {
            let entries = self.entries.read();
            entries.values()
                .filter(|e| now > e.received_at + self.expiry_secs)
                .map(|e| e.txid)
                .collect()
        };
        self.remove_confirmed(&expired);
    }

    pub fn len(&self) -> usize { self.entries.read().len() }

    pub fn is_empty(&self) -> bool { self.len() == 0 }

    pub fn params(&self) -> &ConsensusParams { &self.params }

    pub fn contains(&self, txid: &TxId) -> bool {
        self.entries.read().contains_key(txid)
    }

    /// Gibt eine TX aus dem Mempool zurück (für P2P GetData)
    pub fn get_tx(&self, txid: &TxId) -> Option<Transaction> {
        self.entries.read().get(txid).map(|e| e.tx.clone())
    }

    /// Gibt alle TX-Objekte zurück (für Disk-Persistenz)
    pub fn dump_txs(&self) -> Vec<Transaction> {
        self.entries.read().values().map(|e| e.tx.clone()).collect()
    }

    /// Lädt TXs aus einer Liste (z.B. von Disk) — ignoriert Fehler einzelner TXs
    pub fn load_txs(&self, txs: Vec<Transaction>) -> usize {
        let mut count = 0;
        for tx in txs {
            if self.submit(tx).is_ok() {
                count += 1;
            }
        }
        count
    }

    pub fn stats(&self) -> MempoolStats {
        let entries    = self.entries.read();
        let total_fees = entries.values()
            .fold(Amount::ZERO, |acc, e| acc + e.tx.fee);
        let fees: Vec<u128> = entries.values().map(|e| e.fee_atom).collect();
        let avg = if fees.is_empty() { 0 } else { fees.iter().sum::<u128>() / fees.len() as u128 };
        let min = fees.iter().copied().min().unwrap_or(0);
        let max = fees.iter().copied().max().unwrap_or(0);
        let bids = entries.values().filter(|e| e.is_bid).count();

        MempoolStats {
            tx_count:     entries.len(),
            total_fees,
            avg_fee_atom: avg,
            min_fee_atom: min,
            max_fee_atom: max,
            bid_count:    bids,
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use atlas_core::transaction::{TxType, OutputAddress};
    use atlas_core::amount::Amount;
    use atlas_core::crypto::Address;
    use atlas_core::tx_stamp::TxStamp;

    fn make_test_tx(fee_atom: u128) -> Transaction {
        make_test_tx_ts(fee_atom, 0)
    }

    fn make_test_tx_ts(fee_atom: u128, timestamp: u64) -> Transaction {
        let mut tx = Transaction {
            version:   1,
            inputs:    vec![],
            outputs:   vec![atlas_core::transaction::TxOutput {
                value:   Amount::from_atom(1000),
                address: OutputAddress::Classic(Address([1u8; 20])),
            }],
            fee:       Amount::from_atom(fee_atom),
            timestamp,
            stamp:     None,
            tx_type:   TxType::Transfer,
        };
        // TX-Stamp NACH dem Setzen aller signierten Felder berechnen
        let txid  = tx.txid();
        let stamp = TxStamp::mine(&txid, 12).expect("stamp mining");
        tx.stamp  = Some(stamp);
        tx
    }

    fn make_bid_tx(batch_id: Hash, bid_amount: u128, min_fee: u128) -> Transaction {
        let mut tx = Transaction::new_settlement_bid(
            batch_id,
            Address([2u8; 20]),
            Amount::from_atom(bid_amount),
            Hash::zero(),       // pre_root (Test)
            Hash::zero(),       // post_root (Test)
            Hash::zero(),       // batch_commitment (Test)
            0,                  // total_fees
            Vec::new(),         // proof (Test)
            Vec::new(),         // calldata (Test)
            Vec::new(),         // forced_rejections (Test)
        );
        tx.fee       = Amount::from_atom(min_fee);
        tx.timestamp = 0; // alte/neutrale Zeit → Timestamp-Check passiert
        let txid  = tx.txid();
        tx.stamp  = Some(TxStamp::mine(&txid, 12).expect("stamp mining"));
        tx
    }

    /// L2ForcedTx (Pseudo-Inputs): mit Stamp+Fee akzeptiert und hoch
    /// priorisiert; ohne Stamp abgelehnt (Spam-Schutz greift auch hier).
    #[test]
    fn test_forced_tx_accepted_and_prioritized() {
        let params  = ConsensusParams::mainnet();
        let min_fee = params.min_fee_atom;
        let mempool = Mempool::new(params);

        let mk_forced = |with_stamp: bool| {
            let mut tx = Transaction::new_l2_forced_tx(
                [7u8; 20], [8u8; 20], 100, 5, 0, [9u8; 32], vec![1u8; 64], 3,
            );
            tx.fee       = Amount::from_atom(min_fee);
            tx.timestamp = 0;
            if with_stamp {
                let txid = tx.txid();
                tx.stamp = Some(TxStamp::mine(&txid, 12).expect("stamp mining"));
            }
            tx
        };

        // Ohne Stamp → abgelehnt.
        assert!(matches!(mempool.submit(mk_forced(false)), Err(MempoolError::MissingStamp)));

        // Mit Stamp → akzeptiert (trotz Pseudo-Input ohne UTXO).
        mempool.submit(mk_forced(true)).expect("Forced-TX muss akzeptiert werden");

        // Hohe Priorität: bei der Blockauswahl vor normalen TXs gereiht.
        let selected = mempool.select_for_block(10);
        assert!(matches!(selected[0].tx_type, TxType::L2ForcedTx { .. }));
    }

    /// Zwei Bids für denselben batch_id (unterschiedlicher Betrag) → zweiter wird abgelehnt.
    #[test]
    fn test_bid_dedup_same_batch_rejected() {
        let params  = ConsensusParams::mainnet();
        let min_fee = params.min_fee_atom;
        let mempool = Mempool::new(params);

        let batch_id = Hash::sha256(b"batch-A");
        let bid1 = make_bid_tx(batch_id, 1000, min_fee);
        let bid2 = make_bid_tx(batch_id, 2000, min_fee); // selber Batch, anderer Betrag

        mempool.submit(bid1).expect("erster Bid muss akzeptiert werden");
        match mempool.submit(bid2) {
            Err(MempoolError::DuplicateBatch(id)) => assert_eq!(id, batch_id),
            other => panic!("erwartete DuplicateBatch, bekam {:?}", other),
        }

        // Ein Bid für einen ANDEREN Batch bleibt erlaubt.
        let other_batch = Hash::sha256(b"batch-B");
        mempool.submit(make_bid_tx(other_batch, 500, min_fee))
            .expect("anderer Batch muss akzeptiert werden");
    }

    /// Nach Bestätigung des Bids ist derselbe batch_id wieder einreichbar.
    #[test]
    fn test_bid_dedup_released_after_confirm() {
        let params  = ConsensusParams::mainnet();
        let min_fee = params.min_fee_atom;
        let mempool = Mempool::new(params);

        let batch_id = Hash::sha256(b"batch-C");
        let bid1 = make_bid_tx(batch_id, 1000, min_fee);
        let txid1 = bid1.txid();
        mempool.submit(bid1).unwrap();
        mempool.remove_confirmed(&[txid1]);

        // batch_id wieder frei → neuer Bid akzeptiert.
        mempool.submit(make_bid_tx(batch_id, 1500, min_fee))
            .expect("nach Confirm muss derselbe Batch wieder einreichbar sein");
    }

    /// TX mit Timestamp weit in der Zukunft wird als Relay-Policy abgelehnt.
    #[test]
    fn test_timestamp_far_future_rejected() {
        let params  = ConsensusParams::mainnet();
        let mempool = Mempool::new(params);

        let now_ms     = now_secs().saturating_mul(1000);
        let far_future = now_ms + 3 * 60 * 60 * 1000; // +3h, über dem 2h-Limit
        let tx = make_test_tx_ts(50, far_future);

        match mempool.submit(tx) {
            Err(MempoolError::TimestampTooFarFuture { .. }) => {}
            other => panic!("erwartete TimestampTooFarFuture, bekam {:?}", other),
        }

        // Aktueller Timestamp (innerhalb des Fensters) wird akzeptiert.
        let ok_tx = make_test_tx_ts(50, now_ms);
        mempool.submit(ok_tx).expect("aktueller Timestamp muss akzeptiert werden");
    }

    #[test]
    fn test_mempool_submit_and_select() {
        let params  = ConsensusParams::mainnet();
        let mempool = Mempool::new(params);

        let tx1 = make_test_tx(50);
        let tx2 = make_test_tx(100);

        mempool.submit(tx1).unwrap();
        mempool.submit(tx2).unwrap();

        let selected = mempool.select_for_block(10);
        assert_eq!(selected.len(), 2);
        // Höchste Fee zuerst
        assert_eq!(selected[0].fee.as_atom(), 100);

        let stats = mempool.stats();
        println!("Mempool stats: {:?}", stats);
    }

    /// Mock-UTXO-Quelle: liefert genau einen vordefinierten Eintrag.
    struct MockUtxo {
        op:   OutPoint,
        addr: OutputAddress,
    }
    impl UtxoQuery for MockUtxo {
        fn has_utxo(&self, op: &OutPoint) -> bool { *op == self.op }
        fn utxo_address(&self, op: &OutPoint) -> Option<OutputAddress> {
            if *op == self.op { Some(self.addr.clone()) } else { None }
        }
    }

    /// Post-Quantum (ML-DSA-65) signierte TX wird vom Mempool akzeptiert.
    #[test]
    fn test_mempool_accepts_pq_witness() {
        use atlas_core::pq_crypto::PqKeyPair;
        use atlas_core::transaction::{Transaction, TxOutput};

        let params  = ConsensusParams::mainnet();
        let fee     = params.min_fee_atom;

        let sender   = PqKeyPair::generate().unwrap();
        let receiver = PqKeyPair::generate().unwrap();

        let fund_txid = Hash::sha256(b"pq_mempool_funding");
        let op = OutPoint { txid: fund_txid, index: 0 };
        let utxo = Arc::new(MockUtxo {
            op,
            addr: OutputAddress::Quantum(sender.address),
        });
        let mempool = Mempool::new(params).with_utxo(utxo);

        let mut tx = Transaction::new_transfer_quantum(
            vec![(fund_txid, 0)],
            vec![TxOutput {
                value:   Amount::from_atom(1000 - fee),
                address: receiver.address.into(),
            }],
            Amount::from_atom(fee),
            &sender,
        );
        // TX-Stamp nach dem Signieren berechnen (txid schließt Witness aus).
        let txid = tx.txid();
        tx.stamp = Some(TxStamp::mine(&txid, 12).expect("stamp mining"));

        mempool.submit(tx).expect("PQ-Witness muss vom Mempool akzeptiert werden");
    }

    /// PQ-Witness mit falschem Schlüssel (Adress-Mismatch) wird abgelehnt.
    #[test]
    fn test_mempool_rejects_pq_wrong_owner() {
        use atlas_core::pq_crypto::PqKeyPair;
        use atlas_core::transaction::{Transaction, TxOutput};

        let params  = ConsensusParams::mainnet();
        let fee     = params.min_fee_atom;

        let owner    = PqKeyPair::generate().unwrap();
        let attacker = PqKeyPair::generate().unwrap();
        let receiver = PqKeyPair::generate().unwrap();

        let fund_txid = Hash::sha256(b"pq_mempool_attack");
        let op = OutPoint { txid: fund_txid, index: 0 };
        // UTXO gehört owner …
        let utxo = Arc::new(MockUtxo {
            op,
            addr: OutputAddress::Quantum(owner.address),
        });
        let mempool = Mempool::new(params).with_utxo(utxo);

        // … aber attacker signiert.
        let mut tx = Transaction::new_transfer_quantum(
            vec![(fund_txid, 0)],
            vec![TxOutput {
                value:   Amount::from_atom(1000 - fee),
                address: receiver.address.into(),
            }],
            Amount::from_atom(fee),
            &attacker,
        );
        let txid = tx.txid();
        tx.stamp = Some(TxStamp::mine(&txid, 12).expect("stamp mining"));

        match mempool.submit(tx) {
            Err(MempoolError::PubkeyMismatch { .. }) => {}
            other => panic!("erwartete PubkeyMismatch, bekam {:?}", other),
        }
    }
}
