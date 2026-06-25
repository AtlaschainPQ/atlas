//! Chain-State: Verbindet UTXO-Set, Block-Index und State-Root

use std::sync::Arc;
use std::collections::{HashMap, VecDeque as VD};
use atlas_core::block::{Block, BlockHeader, BlockHeight, GENESIS_BITS};
use atlas_core::hash::Hash;
use atlas_core::amount::Amount;
use atlas_core::transaction::OutPoint;
use crate::utxo::{Utxo, UtxoSet};
use crate::storage::Storage;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

/// Aktueller Kettenstand
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChainState {
    pub height:          BlockHeight,
    pub best_hash:       Hash,
    pub total_supply:    Amount,
    pub total_fees:      Amount,
    pub total_txs:       u64,
    /// Letzte N Block-Header (für Difficulty-Berechnung und Reorg)
    pub recent_headers:  VD<BlockHeader>,
    pub avg_fees:        Amount,
    pub security_delay:  u32,
    pub current_bits:    u32,
    /// Aktuelle L2-State-Root (Account-Baum-Wurzel) nach dem besten Block.
    /// Fortlaufende Kette: jeder SettlementBid-Batch schiebt sie von `pre_root`
    /// auf `post_root`. Genesis = `EMPTY_L2_ROOT` (leerer Account-Baum).
    #[serde(default = "default_l2_root")]
    pub l2_state_root:   Hash,
    /// Forced-Inclusion-Queue (Zensurresistenz): offene, on-chain eingereichte
    /// L2-TXs, die Aggregatoren innerhalb des Konsens-Fensters aufnehmen oder
    /// nachweislich ablehnen MÜSSEN. Konsens-geführt, Reorg-sicher via Snapshot.
    #[serde(default)]
    pub forced_queue:    Vec<atlas_core::transaction::ForcedQueueEntry>,
}

/// Default für die L2-State-Root beim Laden alter (serialisierter) States.
fn default_l2_root() -> Hash { Hash(atlas_core::block::EMPTY_L2_ROOT) }

impl ChainState {
    pub const MAX_RECENT_HEADERS: usize = 2016;

    pub fn genesis() -> Self {
        let genesis = Block::genesis();
        let mut headers = VD::new();
        headers.push_back(genesis.header.clone());

        ChainState {
            height:         0,
            best_hash:      genesis.hash(),
            total_supply:   Amount::ZERO,
            total_fees:     Amount::ZERO,
            total_txs:      0,
            recent_headers: headers,
            avg_fees:       Amount::ZERO,
            security_delay: 0,
            current_bits:   GENESIS_BITS,
            // Der Genesis-Block verankert den VORAB GEFÖRDERTEN L2-Zustand
            // (GENESIS_L2_ROOT), nicht den leeren Baum — ATLAS hat keine
            // Bridge/Mint, die Genesis-Allokation ist der einzige Förderpfad.
            // MUSS mit Block::genesis().header.l2_state_root und dem Start-Root
            // des Aggregators (L2State::from_genesis) übereinstimmen, sonst wird
            // das ALLERERSTE Settlement verworfen ("pre_root does not chain")
            // und die L2 steht auf einer frischen Chain für immer still.
            l2_state_root:  Hash(atlas_core::block::GENESIS_L2_ROOT),
            forced_queue:   Vec::new(),
        }
    }

    pub fn tip(&self) -> Option<&BlockHeader> {
        self.recent_headers.back()
    }

    pub fn update_fees(&mut self, block_fees: Amount) {
        self.total_fees += block_fees;
        // n = Anzahl bereits vorhandener Headers (vor add_header).
        // Neuer Durchschnitt über n+1 Werte: (old_avg * n + new_fee) / (n + 1)
        let n = self.recent_headers.len() as u128;
        self.avg_fees = (self.avg_fees * n + block_fees) / (n + 1);
    }

    pub fn add_header(&mut self, header: BlockHeader) {
        self.recent_headers.push_back(header);
        if self.recent_headers.len() > Self::MAX_RECENT_HEADERS {
            self.recent_headers.pop_front();
        }
    }

    /// Zeit des letzten Retarget-Intervalls (für Difficulty Adjustment)
    pub fn interval_time(&self) -> Option<u64> {
        if self.recent_headers.len() < 2 {
            return None;
        }
        let newest = self.recent_headers.back()?.timestamp;
        let oldest = self.recent_headers.front()?.timestamp;
        Some(newest.saturating_sub(oldest))
    }

    /// Sucht einen Header anhand seines Hashes (O(n), nur für Reorg-Pfad)
    pub fn find_header_by_hash(&self, hash: &Hash) -> Option<&BlockHeader> {
        self.recent_headers.iter().find(|h| h.hash() == *hash)
    }
}

/// Gesamte State-Datenbank
pub struct StateDb {
    pub utxo_set:    Arc<UtxoSet>,
    pub chain:       RwLock<ChainState>,
    /// In-Memory Block-Store für Reorg-Unterstützung (max. 200 Blöcke)
    block_store:     RwLock<HashMap<Hash, Block>>,
    /// FIFO-Queue für Block-Store-Pruning
    block_queue:     RwLock<VD<Hash>>,
    /// Optionaler Disk-Store — Fallback für Blöcke die aus RAM verdrängt wurden
    storage:         RwLock<Option<Arc<Storage>>>,
}

const MAX_BLOCK_STORE: usize = 200;

impl StateDb {
    pub fn new() -> Self {
        StateDb {
            utxo_set:    Arc::new(UtxoSet::with_capacity(1_000_000)),
            chain:       RwLock::new(ChainState::genesis()),
            block_store: RwLock::new(HashMap::new()),
            block_queue: RwLock::new(VD::new()),
            storage:     RwLock::new(None),
        }
    }

    pub fn with_storage(self, storage: Arc<Storage>) -> Self {
        *self.storage.write() = Some(storage);
        self
    }

    /// Setzt den Storage nachträglich (wenn StateDb bereits in Arc steckt)
    pub fn attach_storage(&self, storage: Arc<Storage>) {
        *self.storage.write() = Some(storage);
    }

    /// Lädt den Chain-State und das UTXO-Set aus einem bestehenden Storage.
    /// Fällt auf Genesis zurück wenn der Storage leer ist.
    pub fn load_or_create(storage: &Storage) -> Self {
        let chain = storage.load_chain_state()
            .unwrap_or_else(|e| {
                tracing::warn!("Could not load chain state: {} — starting from genesis", e);
                None
            })
            .unwrap_or_else(ChainState::genesis);

        let utxo_set = UtxoSet::with_capacity(1_000_000);
        match storage.load_utxos() {
            Ok(utxos) if !utxos.is_empty() => {
                tracing::info!("Loaded {} UTXOs from storage", utxos.len());
                utxo_set.restore(utxos);
            }
            Ok(_) => {}
            Err(e) => tracing::warn!("Could not load UTXOs: {}", e),
        }

        tracing::info!(
            "State loaded: height={} best={}",
            chain.height,
            &chain.best_hash.as_hex()[..16],
        );

        StateDb {
            utxo_set:    Arc::new(utxo_set),
            chain:       RwLock::new(chain),
            block_store: RwLock::new(HashMap::new()),
            block_queue: RwLock::new(VD::new()),
            storage:     RwLock::new(None),
        }
    }

    /// Speichert einen Block im In-Memory Store (mit automatischem Pruning)
    pub fn store_block(&self, block: Block) {
        let hash = block.hash();
        let mut store = self.block_store.write();
        let mut queue = self.block_queue.write();

        if store.contains_key(&hash) { return; }

        store.insert(hash, block);
        queue.push_back(hash);

        if store.len() > MAX_BLOCK_STORE {
            if let Some(old) = queue.pop_front() {
                store.remove(&old);
            }
        }
    }

    pub fn get_block(&self, hash: &Hash) -> Option<Block> {
        // 1. RAM-Store (schnell)
        if let Some(b) = self.block_store.read().get(hash) {
            return Some(b.clone());
        }
        // 2. Disk-Fallback (für ältere Blöcke die aus RAM verdrängt wurden)
        if let Some(storage) = self.storage.read().as_ref() {
            if let Ok(Some(b)) = storage.load_block(hash) {
                return Some(b);
            }
        }
        None
    }

    pub fn is_block_known(&self, hash: &Hash) -> bool {
        if self.chain.read().best_hash == *hash { return true; }
        if self.block_store.read().contains_key(hash) { return true; }
        if let Some(storage) = self.storage.read().as_ref() {
            if let Ok(Some(_)) = storage.load_block(hash) { return true; }
        }
        false
    }

    pub fn height(&self) -> BlockHeight {
        self.chain.read().height
    }

    pub fn best_hash(&self) -> Hash {
        self.chain.read().best_hash
    }

    pub fn total_supply(&self) -> Amount {
        self.chain.read().total_supply
    }

    pub fn avg_fees(&self) -> Amount {
        self.chain.read().avg_fees
    }

    /// Lädt oder initialisiert den State aus dem UTXO-Snapshot
    pub fn restore_utxos(&self, utxos: HashMap<OutPoint, Utxo>) {
        self.utxo_set.restore(utxos);
    }
}

impl Default for StateDb {
    fn default() -> Self { Self::new() }
}
