//! Persistente Speicherung mit RocksDB
//!
//! Column Families und Komprimierungs-Strategie:
//!
//!  CF          Komprimierung  Prunable  Inhalt
//!  ─────────────────────────────────────────────────────────────────
//!  "blocks"    Zstd-3         ja        Block ohne ProofRefs (~2x)
//!  "headers"   LZ4            nein      BlockHeader — immer behalten
//!  "proofs"    keine          ja        Vec<ProofRef> — ZK-Proofs sind
//!                                       Pseudo-Zufallsdaten (<1% Ratio)
//!  "height"    LZ4            nein      height(8B BE) → hash(32B)
//!  "txindex"   LZ4            nein      txid(32B) → height+pos
//!  "chain"     LZ4            nein      ChainState
//!  "utxos"     Zstd-3         nein      UTXO-Set
//!  "peers"     LZ4            nein      Peer-Liste
//!  "mempool"   LZ4            nein      Mempool
//!
//! Benchmark-Ergebnisse (synthetische Blocks, 20 Settlement-Batches):
//!   SettlementBid TXs bulk (20x):  Zstd-3 → 2.18x (zeroed witness!)
//!   ProofRefs bulk (20x):          Zstd-3 → 1.05x (ZK = Zufallsdaten)
//!   Full block body (keine Proofs): Zstd-3 → ~2.0x
//!   Voller Block inkl. Proofs:     Zstd-3 → 1.40x
//!
//! Effektiver Speicher nach 10 Jahren (30% Last, Full-Node-Modus):
//!   Ohne Komprimierung/Pruning: 1.42 TB
//!   Mit Komprimierung + Pruning: ~52 GB  (27× Reduktion)

use rocksdb::{DB, ColumnFamilyDescriptor, Options, WriteBatch, DBCompressionType};
use atlas_core::block::{Block, BlockHeader, BlockHeight};
use atlas_core::hash::Hash;
use atlas_core::transaction::{OutPoint, TxId};
use crate::utxo::Utxo;
use crate::state_db::ChainState;
use std::collections::HashMap;
use tracing::{debug, info};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("RocksDB: {0}")]
    Db(#[from] rocksdb::Error),
    #[error("Serialize: {0}")]
    Serde(#[from] bincode::Error),
    #[error("Column family '{0}' not found — database may be corrupt")]
    MissingCf(&'static str),
}

const CF_BLOCKS:  &str = "blocks";    // Block-Body ohne ProofRefs  [Zstd-3]
const CF_HEADERS: &str = "headers";   // BlockHeader separat         [LZ4]
const CF_PROOFS:  &str = "proofs";    // Vec<ProofRef> separat       [unkomprimiert]
const CF_HEIGHT:  &str = "height";    // height(8B BE) → hash(32B)  [LZ4]
const CF_TXINDEX: &str = "txindex";   // txid → (height, pos)       [LZ4]
const CF_CHAIN:   &str = "chain";     // ChainState                  [LZ4]
const CF_UTXOS:   &str = "utxos";     // UTXO-Set                    [Zstd-3]
const CF_PEERS:   &str = "peers";     // Peer-Liste                  [LZ4]
const CF_MEMPOOL: &str = "mempool";   // Mempool                     [LZ4]

// ─── Pruning-Konfiguration ────────────────────────────────────────────────────

/// Speicher-Modus des Nodes
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StorageMode {
    /// Alles für immer behalten — für Block-Explorer / Analytik
    Archive,
    /// Full-Node: Proofs 90 Tage, Block-Bodies 6 Monate behalten (~52 GB/10J @ 30%)
    #[default]
    Full,
    /// Light-Node: nur Headers + UTXO-Set (~21 GB/10J @ 30%)
    Light,
}

/// Pruning-Parameter (in Blöcken ab aktueller Spitze)
#[derive(Clone, Debug)]
pub struct StorageConfig {
    /// Block-Bodies (ohne Proofs) nach N Blöcken löschen. None = behalten.
    pub prune_blocks_after: Option<u64>,
    /// ZK-Proofs nach N Blöcken löschen. None = behalten.
    pub prune_proofs_after: Option<u64>,
}

impl Default for StorageConfig {
    fn default() -> Self { Self::full_node() }
}

impl StorageConfig {
    /// Archive-Node: ~4.4 TB / 10J @ 100% Last
    pub fn archive() -> Self {
        Self { prune_blocks_after: None, prune_proofs_after: None }
    }

    /// Full-Node: Proofs 90d, Bodies 6 Monate → ~52 GB / 10J @ 30% Last
    pub fn full_node() -> Self {
        Self {
            prune_blocks_after: Some(5_259_600),  // ~6 Monate @ 3s
            prune_proofs_after: Some(2_592_000),  // ~90 Tage  @ 3s
        }
    }

    /// Light-Node: nur Headers + UTXO → ~21 GB / 10J unabhängig von Last
    pub fn light_node() -> Self {
        Self {
            prune_blocks_after: Some(100_800),  // ~3.5 Tage (finality window)
            prune_proofs_after: Some(100_800),
        }
    }

    pub fn from_mode(mode: &StorageMode) -> Self {
        match mode {
            StorageMode::Archive => Self::archive(),
            StorageMode::Full    => Self::full_node(),
            StorageMode::Light   => Self::light_node(),
        }
    }
}

// ─── RocksDB CF-Optionen ──────────────────────────────────────────────────────

fn zstd_cf() -> Options {
    // Zstd level 3: gute Ratio, niedrige CPU-Last beim Schreiben
    // Optimal für strukturierte binäre Daten (SettlementBid TXs, UTXOs)
    let mut o = Options::default();
    o.set_compression_type(DBCompressionType::Zstd);
    o
}

fn lz4_cf() -> Options {
    // LZ4: minimale Latenz, ~25% Einsparung auf Indexdaten
    let mut o = Options::default();
    o.set_compression_type(DBCompressionType::Lz4);
    o
}

fn none_cf() -> Options {
    // Keine Komprimierung: für Pseudo-Zufallsdaten (ZK-Proofs)
    let mut o = Options::default();
    o.set_compression_type(DBCompressionType::None);
    o
}

// ─── Storage ──────────────────────────────────────────────────────────────────

pub struct Storage {
    db:     DB,
    config: StorageConfig,
}

impl Storage {
    /// Öffnet Storage mit Standard-Config (Full-Node-Modus)
    pub fn open(path: &str) -> Result<Self, StorageError> {
        Self::open_with_config(path, StorageConfig::default())
    }

    /// Öffnet Storage mit expliziter Pruning-Konfiguration
    pub fn open_with_config(path: &str, config: StorageConfig) -> Result<Self, StorageError> {
        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);
        // 64 MB Write-Buffer: schnelle Schreibpfade ohne ständiges Flushen
        db_opts.set_write_buffer_size(64 * 1024 * 1024);
        // Parallele Kompaktierung für bessere Write-Throughput
        db_opts.increase_parallelism(4);

        let cfs = vec![
            ColumnFamilyDescriptor::new(CF_BLOCKS,  zstd_cf()),  // ~2x auf SettlementBid-Daten
            ColumnFamilyDescriptor::new(CF_HEADERS, lz4_cf()),   // klein, immer behalten
            ColumnFamilyDescriptor::new(CF_PROOFS,  none_cf()),  // ZK-Proofs = unkomprimierbar
            ColumnFamilyDescriptor::new(CF_HEIGHT,  lz4_cf()),
            ColumnFamilyDescriptor::new(CF_TXINDEX, lz4_cf()),
            ColumnFamilyDescriptor::new(CF_CHAIN,   lz4_cf()),
            ColumnFamilyDescriptor::new(CF_UTXOS,   zstd_cf()),  // ~1.5x auf UTXO-Daten
            ColumnFamilyDescriptor::new(CF_PEERS,   lz4_cf()),
            ColumnFamilyDescriptor::new(CF_MEMPOOL, lz4_cf()),
        ];

        let db = DB::open_cf_descriptors(&db_opts, path, cfs)?;

        info!(
            "Storage opened at {} | mode: prune_blocks={:?} prune_proofs={:?}",
            path, config.prune_blocks_after, config.prune_proofs_after
        );

        Ok(Storage { db, config })
    }

    // ── Blocks ───────────────────────────────────────────────────────────────

    /// Speichert Block aufgeteilt auf drei CFs (atomar via WriteBatch):
    ///
    ///  `headers` ← immer behalten, auch nach Pruning
    ///  `blocks`  ← Block ohne ProofRefs (Zstd-3 komprimiert, ~2x)
    ///  `proofs`  ← Vec<ProofRef> separat (unkomprimiert, unabhängig pruneable)
    pub fn save_block(&self, block: &Block) -> Result<(), StorageError> {
        let cf_blocks  = self.db.cf_handle(CF_BLOCKS) .ok_or(StorageError::MissingCf(CF_BLOCKS))?;
        let cf_headers = self.db.cf_handle(CF_HEADERS).ok_or(StorageError::MissingCf(CF_HEADERS))?;
        let cf_proofs  = self.db.cf_handle(CF_PROOFS) .ok_or(StorageError::MissingCf(CF_PROOFS))?;
        let cf_height  = self.db.cf_handle(CF_HEIGHT) .ok_or(StorageError::MissingCf(CF_HEIGHT))?;
        let cf_txindex = self.db.cf_handle(CF_TXINDEX).ok_or(StorageError::MissingCf(CF_TXINDEX))?;

        let hash     = block.hash();
        let height   = block.height();
        let hash_key = hash.as_bytes();

        let mut batch = WriteBatch::default();

        // 1. Header — immer behalten (auch nach Body-Pruning)
        batch.put_cf(cf_headers, hash_key, &bincode::serialize(&block.header)?);

        // 2. Block-Body ohne agg_proof → Zstd-3 im CF komprimiert
        //    SettlementBid-TXs haben zeroed Witnesses (97 Bytes Nullen) →
        //    LZ77-Runs → 2x+ Komprimierungsratio auf dem Body
        let body = Block {
            header:       block.header.clone(),
            transactions: block.transactions.clone(),
            agg_proof:    vec![],   // ← ausgelagert in CF_PROOFS
        };
        batch.put_cf(cf_blocks, hash_key, &bincode::serialize(&body)?);

        // 3. EIN aggregierter ZK-Proof pro Block, separat — Groth16/BN254 =
        //    Pseudo-Zufallsdaten, <1% Komprimierungsgewinn → unkomprimiert lassen,
        //    eigene Retention. ~160 B/Block statt 64× Einzel-Proofs.
        if !block.agg_proof.is_empty() {
            batch.put_cf(cf_proofs, hash_key, &block.agg_proof);
        }

        // 4. Höhen-Index: height(8B BE) → hash(32B)
        batch.put_cf(cf_height, &height.to_be_bytes(), hash_key);

        // 5. TX-Index: txid → height(8B) || tx_pos(4B)
        for (pos, tx) in block.transactions.iter().enumerate() {
            let txid = tx.txid();
            let mut val = [0u8; 12];
            val[..8].copy_from_slice(&height.to_be_bytes());
            val[8..].copy_from_slice(&(pos as u32).to_be_bytes());
            batch.put_cf(cf_txindex, txid.as_bytes(), &val);
        }

        self.db.write(batch)?;
        Ok(())
    }

    /// Lädt Block — rekonstruiert Body + aggregierten Proof aus getrennten CFs.
    /// Gibt None zurück wenn der Block-Body gepruned wurde.
    /// Gibt Block mit leerem agg_proof zurück wenn der Proof gepruned wurde.
    pub fn load_block(&self, hash: &Hash) -> Result<Option<Block>, StorageError> {
        let cf_blocks = self.db.cf_handle(CF_BLOCKS).ok_or(StorageError::MissingCf(CF_BLOCKS))?;
        let cf_proofs = self.db.cf_handle(CF_PROOFS).ok_or(StorageError::MissingCf(CF_PROOFS))?;

        let body_bytes = match self.db.get_cf(cf_blocks, hash.as_bytes())? {
            Some(b) => b,
            None    => return Ok(None),  // Body gepruned
        };
        let mut block: Block = bincode::deserialize(&body_bytes)?;

        // Aggregierten Proof hinzufügen falls noch vorhanden (roh, kein bincode-Wrapper)
        if let Some(proof_bytes) = self.db.get_cf(cf_proofs, hash.as_bytes())? {
            block.agg_proof = proof_bytes;
        }

        Ok(Some(block))
    }

    /// Lädt nur den Header — immer verfügbar, auch für geprunte Blöcke
    pub fn load_header(&self, hash: &Hash) -> Result<Option<BlockHeader>, StorageError> {
        let cf = self.db.cf_handle(CF_HEADERS).ok_or(StorageError::MissingCf(CF_HEADERS))?;
        match self.db.get_cf(cf, hash.as_bytes())? {
            Some(b) => Ok(Some(bincode::deserialize(&b)?)),
            None    => Ok(None),
        }
    }

    /// Lädt Block anhand der Höhe (via Höhen-Index)
    pub fn load_block_by_height(&self, height: BlockHeight) -> Result<Option<Block>, StorageError> {
        match self.hash_at_height(height)? {
            Some(h) => self.load_block(&h),
            None    => Ok(None),
        }
    }

    /// Lädt nur den Header anhand der Höhe
    pub fn load_header_by_height(&self, height: BlockHeight) -> Result<Option<BlockHeader>, StorageError> {
        match self.hash_at_height(height)? {
            Some(h) => self.load_header(&h),
            None    => Ok(None),
        }
    }

    /// Gibt den Hash-des-Blocks bei gegebener Höhe zurück
    pub fn hash_at_height(&self, height: BlockHeight) -> Result<Option<Hash>, StorageError> {
        let cf = self.db.cf_handle(CF_HEIGHT).ok_or(StorageError::MissingCf(CF_HEIGHT))?;
        match self.db.get_cf(cf, &height.to_be_bytes())? {
            Some(b) if b.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                Ok(Some(Hash(arr)))
            }
            _ => Ok(None),
        }
    }

    /// Sucht TX-Position (height + Index im Block) anhand TxId
    pub fn find_tx(&self, txid: &TxId) -> Result<Option<(BlockHeight, u32)>, StorageError> {
        let cf = self.db.cf_handle(CF_TXINDEX).ok_or(StorageError::MissingCf(CF_TXINDEX))?;
        match self.db.get_cf(cf, txid.as_bytes())? {
            Some(b) if b.len() == 12 => {
                let height = u64::from_be_bytes(b[..8].try_into().unwrap());
                let pos    = u32::from_be_bytes(b[8..].try_into().unwrap());
                Ok(Some((height, pos)))
            }
            _ => Ok(None),
        }
    }

    // ── Pruning ───────────────────────────────────────────────────────────────

    /// Pruned ZK-Proofs die älter sind als `prune_proofs_after` Blöcke.
    /// Gibt die Anzahl gelöschter Proof-Bundles zurück.
    /// No-op wenn prune_proofs_after = None (Archive-Modus).
    pub fn prune_old_proofs(&self, current_height: u64) -> Result<u64, StorageError> {
        let keep = match self.config.prune_proofs_after {
            Some(d) => d,
            None    => return Ok(0),
        };
        if current_height <= keep { return Ok(0); }
        let below = current_height - keep;
        let n = self.delete_cf_entries_below_height(CF_PROOFS, below)?;
        if n > 0 { info!("Pruned {} proof bundles (heights < {})", n, below); }
        Ok(n)
    }

    /// Pruned Block-Bodies älter als `prune_blocks_after` Blöcke.
    /// Headers bleiben erhalten (CF_HEADERS ist nie pruneable).
    /// No-op wenn prune_blocks_after = None (Archive-Modus).
    pub fn prune_old_block_bodies(&self, current_height: u64) -> Result<u64, StorageError> {
        let keep = match self.config.prune_blocks_after {
            Some(d) => d,
            None    => return Ok(0),
        };
        if current_height <= keep { return Ok(0); }
        let below = current_height - keep;
        let n = self.delete_cf_entries_below_height(CF_BLOCKS, below)?;
        if n > 0 { info!("Pruned {} block bodies (heights < {})", n, below); }
        Ok(n)
    }

    /// Kombiniertes Pruning: ruft beide Prune-Methoden auf.
    /// Sollte einmal pro Epoch (~2016 Blöcke) aufgerufen werden.
    pub fn run_pruning(&self, current_height: u64) -> Result<(), StorageError> {
        let proofs  = self.prune_old_proofs(current_height)?;
        let bodies  = self.prune_old_block_bodies(current_height)?;
        if proofs > 0 || bodies > 0 {
            info!(
                "Pruning complete: {} proof bundles + {} block bodies deleted",
                proofs, bodies
            );
        }
        Ok(())
    }

    /// Löscht alle Einträge einer CF für Blöcke unterhalb einer bestimmten Höhe.
    /// Verwendet den CF_HEIGHT-Index um Hash-Keys zu ermitteln.
    fn delete_cf_entries_below_height(
        &self,
        target_cf: &'static str,
        below_height: u64,
    ) -> Result<u64, StorageError> {
        let cf_height = self.db.cf_handle(CF_HEIGHT).ok_or(StorageError::MissingCf(CF_HEIGHT))?;
        let cf_target = self.db.cf_handle(target_cf).ok_or(StorageError::MissingCf(target_cf))?;

        let mut batch   = WriteBatch::default();
        let mut deleted = 0u64;
        let start       = 0u64.to_be_bytes();

        let iter = self.db.iterator_cf(
            cf_height,
            rocksdb::IteratorMode::From(&start, rocksdb::Direction::Forward),
        );

        for item in iter {
            let (key_bytes, hash_bytes) = item?;
            if key_bytes.len() < 8 { continue; }
            let height = u64::from_be_bytes(key_bytes[..8].try_into().unwrap());
            if height >= below_height { break; }
            if hash_bytes.len() == 32 {
                batch.delete_cf(cf_target, &hash_bytes);
                deleted += 1;
            }
        }

        if deleted > 0 {
            self.db.write(batch)?;
            debug!("CF '{}': deleted {} entries below height {}", target_cf, deleted, below_height);
        }

        Ok(deleted)
    }

    // ── Chain State ───────────────────────────────────────────────────────────

    pub fn save_chain_state(&self, state: &ChainState) -> Result<(), StorageError> {
        let cf    = self.db.cf_handle(CF_CHAIN).ok_or(StorageError::MissingCf(CF_CHAIN))?;
        let value = bincode::serialize(state)?;
        self.db.put_cf(cf, b"state", &value)?;
        Ok(())
    }

    pub fn load_chain_state(&self) -> Result<Option<ChainState>, StorageError> {
        let cf = self.db.cf_handle(CF_CHAIN).ok_or(StorageError::MissingCf(CF_CHAIN))?;
        match self.db.get_cf(cf, b"state")? {
            Some(b) => Ok(Some(bincode::deserialize(&b)?)),
            None    => Ok(None),
        }
    }

    /// Modell A: Persistiert den node-gehaltenen L2-Baum als `(height, snapshot)`,
    /// damit der Startup-Rebuild nur das Delta seit `height` nachspielen muss
    /// statt die ganze Kette (O(Delta) statt O(Chain)).
    pub fn save_l2_snapshot(&self, height: u64, bytes: &[u8]) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_CHAIN).ok_or(StorageError::MissingCf(CF_CHAIN))?;
        let mut v = Vec::with_capacity(8 + bytes.len());
        v.extend_from_slice(&height.to_le_bytes());
        v.extend_from_slice(bytes);
        self.db.put_cf(cf, b"l2_snapshot", &v)?;
        Ok(())
    }

    /// Lädt den persistierten L2-Snapshot `(height, snapshot_bytes)`, falls vorhanden.
    pub fn load_l2_snapshot(&self) -> Result<Option<(u64, Vec<u8>)>, StorageError> {
        let cf = self.db.cf_handle(CF_CHAIN).ok_or(StorageError::MissingCf(CF_CHAIN))?;
        match self.db.get_cf(cf, b"l2_snapshot")? {
            Some(v) if v.len() >= 8 => {
                let height = u64::from_le_bytes(v[0..8].try_into().unwrap());
                Ok(Some((height, v[8..].to_vec())))
            }
            _ => Ok(None),
        }
    }

    // ── UTXO Set ──────────────────────────────────────────────────────────────

    pub fn save_utxos(&self, utxos: &HashMap<OutPoint, Utxo>) -> Result<(), StorageError> {
        let cf    = self.db.cf_handle(CF_UTXOS).ok_or(StorageError::MissingCf(CF_UTXOS))?;
        let mut batch = WriteBatch::default();
        for (op, utxo) in utxos {
            batch.put_cf(cf, &bincode::serialize(op)?, &bincode::serialize(utxo)?);
        }
        self.db.write(batch)?;
        Ok(())
    }

    pub fn load_utxos(&self) -> Result<HashMap<OutPoint, Utxo>, StorageError> {
        let cf      = self.db.cf_handle(CF_UTXOS).ok_or(StorageError::MissingCf(CF_UTXOS))?;
        let mut map = HashMap::new();
        for item in self.db.iterator_cf(cf, rocksdb::IteratorMode::Start) {
            let (key, val) = item?;
            map.insert(bincode::deserialize(&key)?, bincode::deserialize(&val)?);
        }
        Ok(map)
    }

    /// Inkrementelles UTXO-Update: neue einfügen, verbrauchte löschen (atomar)
    pub fn save_utxo_delta(
        &self,
        created: &[(OutPoint, Utxo)],
        spent:   &[OutPoint],
    ) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_UTXOS).ok_or(StorageError::MissingCf(CF_UTXOS))?;
        let mut batch = WriteBatch::default();
        for (op, utxo) in created {
            batch.put_cf(cf, &bincode::serialize(op)?, &bincode::serialize(utxo)?);
        }
        for op in spent {
            batch.delete_cf(cf, &bincode::serialize(op)?);
        }
        self.db.write(batch)?;
        Ok(())
    }

    /// Ersetzt den gesamten UTXO-Store (für Snapshot-Persist nach Reorg)
    pub fn replace_utxos(&self, utxos: &HashMap<OutPoint, Utxo>) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_UTXOS).ok_or(StorageError::MissingCf(CF_UTXOS))?;
        let old_keys: Vec<Vec<u8>> = self.db
            .iterator_cf(cf, rocksdb::IteratorMode::Start)
            .map(|r| r.map(|(k, _)| k.to_vec()))
            .collect::<Result<_, _>>()?;
        let mut batch = WriteBatch::default();
        for k in old_keys { batch.delete_cf(cf, &k); }
        for (op, utxo) in utxos {
            batch.put_cf(cf, &bincode::serialize(op)?, &bincode::serialize(utxo)?);
        }
        self.db.write(batch)?;
        Ok(())
    }

    // ── Mempool ───────────────────────────────────────────────────────────────

    pub fn save_mempool(&self, txs: &[atlas_core::transaction::Transaction]) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_MEMPOOL).ok_or(StorageError::MissingCf(CF_MEMPOOL))?;
        self.db.put_cf(cf, b"txs", &bincode::serialize(txs)?)?;
        Ok(())
    }

    pub fn load_mempool(&self) -> Result<Vec<atlas_core::transaction::Transaction>, StorageError> {
        let cf = self.db.cf_handle(CF_MEMPOOL).ok_or(StorageError::MissingCf(CF_MEMPOOL))?;
        match self.db.get_cf(cf, b"txs")? {
            Some(b) => Ok(bincode::deserialize(&b)?),
            None    => Ok(vec![]),
        }
    }

    // ── Peer-Adressen ─────────────────────────────────────────────────────────

    pub fn save_peers(&self, addrs: &[std::net::SocketAddr]) -> Result<(), StorageError> {
        let cf = self.db.cf_handle(CF_PEERS).ok_or(StorageError::MissingCf(CF_PEERS))?;
        self.db.put_cf(cf, b"peers", &bincode::serialize(addrs)?)?;
        Ok(())
    }

    pub fn load_peers(&self) -> Result<Vec<std::net::SocketAddr>, StorageError> {
        let cf = self.db.cf_handle(CF_PEERS).ok_or(StorageError::MissingCf(CF_PEERS))?;
        match self.db.get_cf(cf, b"peers")? {
            Some(b) => Ok(bincode::deserialize(&b)?),
            None    => Ok(vec![]),
        }
    }

    // ── Statistiken ───────────────────────────────────────────────────────────

    pub fn config(&self) -> &StorageConfig { &self.config }
}
