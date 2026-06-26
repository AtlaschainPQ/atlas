//! Chain Manager — Verbindet Konsens, State und Validierung

use std::sync::Arc;
use atlas_core::block::{Block, BlockHeader, BlockHeight};
use atlas_core::hash::Hash;
use atlas_core::transaction::TxId;
use atlas_consensus::params::ConsensusParams;
use atlas_consensus::validation::{BlockValidator, ValidationError};
use atlas_consensus::difficulty::DifficultyAdjuster;
use atlas_consensus::reward::RewardSchedule;
use atlas_consensus::security_floor::AdaptiveSecurityFloor;
use atlas_consensus::checkpoints;
use atlas_state::state_db::StateDb;
use atlas_state::executor::{BlockExecutor, ExecutionError};
use atlas_state::snapshot::{SnapshotManager, StateSnapshot};
use atlas_state::storage::Storage;
use atlas_mempool::mempool::Mempool;
use atlas_triad::epoch::{EpochSeed, Epoch};
use atlas_triad::network_entropy::NetworkEntropy;
use atlas_triad::verifier::TriadVerifier;
use crate::zk_stub::ZkVerifier;
use atlas_zk::ZkBatchProver;
use parking_lot::RwLock;
use thiserror::Error;
use tracing::{info, warn};
use tokio::sync::broadcast;

#[derive(Error, Debug)]
pub enum ChainError {
    #[error("Validation failed: {0}")]
    Validation(#[from] ValidationError),
    #[error("Execution failed: {0}")]
    Execution(#[from] ExecutionError),
    #[error("Block already known: {0:?}")]
    AlreadyKnown(Hash),
    #[error("Orphan block: parent {0:?} not found")]
    Orphan(Hash),
    #[error("Chain reorganization depth {depth} exceeds max {max}")]
    ReorgTooDeep { depth: u64, max: u64 },
    #[error("Storage error: {0}")]
    Storage(String),
}

const MAX_REORG_DEPTH: u64 = 200;

/// Soundness-tragende Settlement-Daten eines SettlementBid (Block-intern).
#[derive(Clone, Debug)]
struct Settlement {
    batch_id:         [u8; 32],
    bid_amount:       u128,
    pre_root:         [u8; 32],
    post_root:        [u8; 32],
    batch_commitment: [u8; 32],
    total_fees:       u128,
    proof:            Vec<u8>,
    /// On-Chain Data-Availability-Calldata (siehe SettlementBid::calldata).
    calldata:         Vec<u8>,
    /// Ablehnungs-Zeugen für fällige Forced-Inclusion-TXs (nativ verifiziert).
    forced_rejections: Vec<atlas_core::transaction::ForcedRejection>,
}

/// Ereignisse die der ChainManager nach außen veröffentlicht
#[derive(Clone, Debug)]
pub enum ChainEvent {
    /// Neuer Block akzeptiert (hash, height)
    BlockAccepted { hash: Hash, height: u64 },
    /// Reorganisation ausgeführt (neue tip-Höhe)
    Reorg { new_height: u64 },
}

pub struct ChainManager {
    params:       ConsensusParams,
    state:        Arc<StateDb>,
    mempool:      Arc<Mempool>,
    snapshots:    RwLock<SnapshotManager>,
    storage:      Option<Arc<Storage>>,
    events:       broadcast::Sender<ChainEvent>,
    test_mode:    bool,
    /// In-Process ZK-Prover für den aggregierten Block-Proof.
    /// Wird hauptsächlich von Tests genutzt (direkter Groth16-Pfad ohne Subprozess).
    /// None → kein In-Process-Prover.
    prover:       Option<Arc<ZkBatchProver>>,
    /// Produktions-Pfad: Block-Proof in einem isolierten, kurzlebigen Subprozess
    /// erzeugen (`atlas-node prove-worker`). Verhindert den arkworks-RSS-Leak im
    /// langlebigen Node-Prozess und isoliert Prover-Crashes. Hat Vorrang nur wenn
    /// kein In-Process-`prover` gesetzt ist.
    prover_subprocess: bool,
    /// Serialisiert die gesamte Block-Verarbeitung — verhindert Race Conditions bei Reorgs
    process_lock: parking_lot::Mutex<()>,
    /// Modell A: Der Node führt den vollen L2-AccountTree mit (nicht nur die Root).
    /// Er wird in `apply_block` fortgeschrieben — Settlement-Calldata UND die
    /// Coinbase-Emissions-Gutschrift an Miner/Prover-L2-Konten — sodass die
    /// `l2_state_root` pro Block korrekt herauskommt. Für Reorgs wird sein
    /// kompakter Snapshot (`to_snapshot_bytes`) im `StateSnapshot` mitgesichert.
    l2_state: parking_lot::RwLock<atlas_zk::l2_state::L2State>,
}

impl ChainManager {
    pub fn new(
        params:    ConsensusParams,
        state:     Arc<StateDb>,
        mempool:   Arc<Mempool>,
        test_mode: bool,
    ) -> Self {
        let (events, _) = broadcast::channel(64);
        ChainManager {
            params,
            state,
            mempool,
            snapshots:    RwLock::new(SnapshotManager::new(MAX_REORG_DEPTH as usize)),
            storage:      None,
            events,
            test_mode,
            prover:       None,
            prover_subprocess: false,
            process_lock: parking_lot::Mutex::new(()),
            // Genesis-geförderter L2-Zustand — Root == GENESIS_L2_ROOT.
            l2_state: parking_lot::RwLock::new(
                atlas_zk::l2_state::L2State::from_genesis(&atlas_zk::genesis_allocation()),
            ),
        }
    }

    /// Hinterlegt einen In-Process-ZK-Prover (v.a. für Tests / direkter Groth16-Pfad).
    /// Für den Produktions-Mining-Pfad stattdessen `with_prover_subprocess()` nutzen.
    pub fn with_prover(mut self, prover: Arc<ZkBatchProver>) -> Self {
        self.prover = Some(prover);
        self
    }

    /// Aktiviert die Block-Proof-Erzeugung in einem isolierten Subprozess
    /// (`atlas-node prove-worker`) — der Produktions-Pfad für Miner-Nodes.
    /// Hält keinen Proving-Key im langlebigen Prozess und vermeidet so den
    /// arkworks-RSS-Leak.
    pub fn with_prover_subprocess(mut self) -> Self {
        self.prover_subprocess = true;
        self
    }

    /// Extrahiert die soundness-tragenden Settlement-Daten eines Blocks in
    /// Block-Reihenfolge. Jeder SettlementBid trägt seinen eigenen State-
    /// Transition-Beweis und seine L2-State-Roots.
    fn extract_settlements(txs: &[atlas_core::transaction::Transaction]) -> Vec<Settlement> {
        use atlas_core::transaction::TxType;
        txs.iter().filter_map(|tx| match &tx.tx_type {
            TxType::SettlementBid {
                batch_id, bid_amount, pre_root, post_root,
                batch_commitment, total_fees, proof, calldata,
                forced_rejections,
            } => Some(Settlement {
                batch_id:         *batch_id.as_bytes(),
                bid_amount:       bid_amount.as_atom(),
                pre_root:         *pre_root.as_bytes(),
                post_root:        *post_root.as_bytes(),
                batch_commitment: *batch_commitment.as_bytes(),
                total_fees:       *total_fees,
                proof:            proof.clone(),
                calldata:         calldata.clone(),
                forced_rejections: forced_rejections.clone(),
            }),
            _ => None,
        }).collect()
    }

    /// Bindet den Header an die exakte geordnete Settlement-Menge dieses Blocks.
    /// `proof_root` = double-SHA256 über prev_l2_root ++ je Settlement
    /// (batch_id|pre|post|commitment|total_fees|bid_amount). Re-verifizierbar von
    /// Genesis, ohne Vertrauen in den Block-Producer.
    fn compute_settlement_root(prev_l2_root: &Hash, settlements: &[Settlement]) -> Hash {
        let mut buf = Vec::with_capacity(32 + settlements.len() * 144);
        buf.extend_from_slice(prev_l2_root.as_bytes());
        for s in settlements {
            buf.extend_from_slice(&s.batch_id);
            buf.extend_from_slice(&s.pre_root);
            buf.extend_from_slice(&s.post_root);
            buf.extend_from_slice(&s.batch_commitment);
            buf.extend_from_slice(&s.total_fees.to_le_bytes());
            buf.extend_from_slice(&s.bid_amount.to_le_bytes());
        }
        Hash::double_sha256(&buf)
    }

    /// Prüft die Data-Availability-Bindung EINES Settlements: die On-Chain-
    /// Calldata muss exakt zum im Beweis gebundenen `batch_commitment` hashen.
    /// Schlägt fehl bei fehlerhafter Länge, zu vielen TXs oder Commitment-Mismatch.
    fn verify_data_availability(s: &Settlement) -> Result<(), String> {
        let txs = atlas_zk::l2_state::decode_calldata(&s.calldata)
            .map_err(|e| format!("calldata decode failed: {}", e))?;
        if txs.len() > atlas_zk::L2_BATCH_SIZE {
            return Err(format!(
                "calldata enthält {} TXs > Batch-Kapazität {}",
                txs.len(), atlas_zk::L2_BATCH_SIZE
            ));
        }
        let recomputed = atlas_zk::l2_state::batch_commitment_from_inputs(&txs, atlas_zk::L2_BATCH_SIZE);
        if recomputed != s.batch_commitment {
            return Err("calldata hasht nicht zum bewiesenen batch_commitment (DA-Bindung verletzt)".to_string());
        }
        Ok(())
    }

    /// Obergrenze der Forced-Inclusion-Queue (Konsensregel, DoS-Schutz).
    /// Bei voller Queue sind weitere `L2ForcedTx` ungültig (Block-Ablehnung).
    const MAX_FORCED_QUEUE: usize = 10_000;

    /// Wendet die Forced-Inclusion-Konsensregeln EINES Blocks auf die Queue an
    /// (pure Funktion — Grundlage für Block-Validierung UND Template-Bau).
    ///
    /// Regeln:
    /// 1. Inclusion-Discharge: enthält die Calldata eines Settlements eine
    ///    Forced-TX (Feldgleichheit from/to/amount/fee/nonce), ist sie erledigt.
    /// 2. Rejection-Discharge: ein Settlement darf eine Forced-TX per nativ
    ///    verifiziertem Zeugen gegen seinen `pre_root` ablehnen (nur wenn die
    ///    TX dort nachweislich NICHT anwendbar ist).
    /// 3. Enforcement: pro Settlement MÜSSEN die ältesten
    ///    `min(#fällig, L2_BATCH_SIZE)` fälligen Einträge (älter als `window`)
    ///    erledigt werden — sonst ist der Block ungültig.
    /// 4. Neue `L2ForcedTx` des Blocks: native EdDSA-Prüfung, Dedup pro
    ///    (from, nonce), Queue-Kapazität — dann ans Queue-Ende.
    fn apply_forced_rules(
        queue:       &[atlas_core::transaction::ForcedQueueEntry],
        settlements: &[Settlement],
        block_txs:   &[atlas_core::transaction::Transaction],
        height:      u64,
        window:      u64,
    ) -> Result<Vec<atlas_core::transaction::ForcedQueueEntry>, String> {
        use atlas_core::transaction::{ForcedQueueEntry, TxType};

        let mut pending: Vec<ForcedQueueEntry> = queue.to_vec();

        for s in settlements {
            // Calldata ist durch verify_data_availability bereits ans Commitment
            // gebunden — hier nur dekodieren.
            let txs = atlas_zk::l2_state::decode_calldata(&s.calldata)
                .map_err(|e| format!("calldata decode (forced rules): {}", e))?;

            // Fällige Einträge VOR diesem Settlement (Queue ist seen_height-geordnet).
            let due_before: Vec<([u8; 20], u64)> = pending.iter()
                .filter(|e| e.seen_height.saturating_add(window) < height)
                .map(|e| (e.from, e.nonce))
                .collect();

            // (1) Inclusion-Discharge.
            pending.retain(|e| !txs.iter().any(|t|
                t.from == e.from && t.to == e.to && t.amount == e.amount_atom
                && t.fee == e.fee_atom && t.nonce == e.nonce));

            // (2) Rejection-Discharge — jeder Zeuge muss gültig sein und einen
            // offenen Eintrag treffen (sonst Block ungültig).
            for rej in &s.forced_rejections {
                let pos = pending.iter()
                    .position(|e| e.from == rej.from && e.nonce == rej.nonce)
                    .ok_or_else(|| "Forced-Rejection ohne offenen Queue-Eintrag".to_string())?;
                let e = pending[pos].clone();
                atlas_zk::l2_state::verify_forced_rejection(
                    &s.pre_root, e.sender_index,
                    rej.leaf_vacant, &rej.leaf_address, rej.leaf_balance, rej.leaf_nonce,
                    &rej.siblings,
                    &e.from, e.amount_atom, e.fee_atom, e.nonce,
                ).map_err(|err| format!("ungültige Forced-Rejection: {}", err))?;
                pending.remove(pos);
            }

            // (3) Enforcement: MINDESTENS der älteste fällige Eintrag muss von
            // diesem Settlement erledigt worden sein. Genau einer ist immer
            // bedienbar: als erste TX des Batches ist er gegen `pre_root`
            // entweder anwendbar (Inclusion) oder nachweislich nicht
            // (Rejection) — deadlock-frei. Jedes Settlement drainiert die
            // Queue damit um ≥1; mehr ist freiwillig.
            if let Some(key) = due_before.first() {
                if pending.iter().any(|e| (e.from, e.nonce) == *key) {
                    return Err(format!(
                        "älteste fällige Forced-TX (from={}, nonce={}) wurde vom Settlement \
                         weder aufgenommen noch nachweislich abgelehnt",
                        hex::encode(key.0), key.1
                    ));
                }
            }
        }

        // Bereits in DIESEM Block per Settlement erfüllte L2-TXs — eine neue
        // Forced-TX, die ein Settlement desselben Blocks schon enthält, wird
        // gar nicht erst eingereiht (sonst bliebe sie unerfüllbar hängen).
        let included_this_block: Vec<atlas_zk::l2_state::L2Input> = settlements.iter()
            .flat_map(|s| atlas_zk::l2_state::decode_calldata(&s.calldata).unwrap_or_default())
            .collect();

        // (4) Neue Forced-TXs dieses Blocks ans Queue-Ende.
        for tx in block_txs {
            if let TxType::L2ForcedTx {
                from, to, amount_atom, fee_atom, nonce, pubkey, sig, sender_index,
            } = &tx.tx_type {
                let sig64: [u8; 64] = sig.as_slice().try_into()
                    .map_err(|_| "L2ForcedTx: Signatur muss 64 Byte sein".to_string())?;
                if !atlas_zk::l2_state::verify_l2_eddsa(
                    from, to, *amount_atom, *fee_atom, *nonce, pubkey, &sig64,
                ) {
                    return Err("L2ForcedTx: EdDSA-Signatur/Adressbindung ungültig".to_string());
                }
                if pending.iter().any(|e| e.from == *from && e.nonce == *nonce) {
                    return Err("L2ForcedTx: (from, nonce) bereits in der Queue".to_string());
                }
                if pending.len() >= Self::MAX_FORCED_QUEUE {
                    return Err("Forced-Queue voll — L2ForcedTx aktuell nicht zulässig".to_string());
                }
                if included_this_block.iter().any(|t|
                    t.from == *from && t.to == *to && t.amount == *amount_atom
                    && t.fee == *fee_atom && t.nonce == *nonce) {
                    continue; // im selben Block bereits erfüllt
                }
                pending.push(ForcedQueueEntry {
                    from: *from, to: *to,
                    amount_atom: *amount_atom, fee_atom: *fee_atom, nonce: *nonce,
                    pubkey: *pubkey, sig: sig.clone(), sender_index: *sender_index,
                    seen_height: height,
                });
            }
        }
        Ok(pending)
    }

    /// Validiert die L2-State-Root-Kette der Settlements gegen die aktuelle
    /// Chain-L2-Root (strikt — für empfangene Blöcke). Gibt (proof_root,
    /// new_l2_root) zurück. Bei leerer Settlement-Menge bleibt die L2-Root
    /// unverändert und proof_root = Zero.
    fn validate_l2_chain(
        prev_l2_root: &Hash,
        settlements:  &[Settlement],
    ) -> Result<(Hash, Hash), ChainError> {
        if settlements.is_empty() {
            return Ok((Hash::zero(), *prev_l2_root));
        }
        let mut cur = *prev_l2_root;
        for s in settlements {
            if Hash(s.pre_root) != cur {
                return Err(ChainError::Validation(ValidationError::ZkProofInvalid(
                    "settlement pre_root does not chain to current L2 state root".to_string(),
                )));
            }
            cur = Hash(s.post_root);
        }
        let proof_root = Self::compute_settlement_root(prev_l2_root, settlements);
        Ok((proof_root, cur))
    }

    /// Stellt für ein Block-Template die maximale Präfix-Menge von SettlementBids
    /// zusammen, die lückenlos an `prev_l2_root` anschließt; nicht anschließende
    /// Bids werden verworfen (können später erneut aufgenommen werden). Simuliert
    /// dabei die Forced-Inclusion-Regeln, damit der Miner keine Blöcke baut, die
    /// die eigene Validierung ablehnen würde. Gibt die gefilterte TX-Liste,
    /// proof_root, neue L2-Root und batch_count zurück.
    fn assemble_l2_template(
        &self,
        prev_l2_root: Hash,
        txs:          Vec<atlas_core::transaction::Transaction>,
        height:       u64,
    ) -> (Vec<atlas_core::transaction::Transaction>, Hash, Hash, u8) {
        use atlas_core::transaction::TxType;
        let window      = self.params.forced_inclusion_window;
        let mut queue   = self.state.chain.read().forced_queue.clone();
        let mut cur         = prev_l2_root;
        let mut kept        = Vec::with_capacity(txs.len());
        let mut settlements = Vec::new();
        let mut count: u32  = 0;
        for tx in txs {
            match &tx.tx_type {
                TxType::SettlementBid { pre_root, post_root, .. } => {
                    if Hash(*pre_root.as_bytes()) != cur {
                        warn!("Dropping SettlementBid from template: pre_root does not chain");
                        continue;
                    }
                    // Forced-Regeln simulieren: verletzt der Bid die Fälligkeits-
                    // Pflicht (oder trägt ungültige Rejections), fliegt er raus.
                    if !self.test_mode {
                        let s = Self::extract_settlements(std::slice::from_ref(&tx));
                        match Self::apply_forced_rules(&queue, &s, &[], height, window) {
                            Ok(q) => queue = q,
                            Err(e) => {
                                warn!("Dropping SettlementBid from template (forced rules): {}", e);
                                continue;
                            }
                        }
                    }
                    cur = Hash(*post_root.as_bytes());
                    count += 1;
                    settlements.push(tx);
                }
                TxType::L2ForcedTx { .. } if !self.test_mode => {
                    // Signatur/Dedup/Kapazität prüfen — ungültige fliegen raus.
                    match Self::apply_forced_rules(&queue, &[], std::slice::from_ref(&tx), height, window) {
                        Ok(q) => { queue = q; kept.push(tx); }
                        Err(e) => warn!("Dropping L2ForcedTx from template: {}", e),
                    }
                }
                _ => kept.push(tx),
            }
        }
        // Settlements ans Ende anhängen (Reihenfolge der Kette bleibt erhalten)
        let settle_data = Self::extract_settlements(&settlements);
        kept.extend(settlements);
        let proof_root = if settle_data.is_empty() {
            Hash::zero()
        } else {
            Self::compute_settlement_root(&prev_l2_root, &settle_data)
        };
        (kept, proof_root, cur, count.min(u8::MAX as u32) as u8)
    }

    pub fn with_storage(mut self, storage: Storage) -> Self {
        let arc = Arc::new(storage);
        // StateDb bekommt Referenz auf Storage für persistente Block-Lookups
        self.state.attach_storage(arc.clone());

        // Genesis-Block persistieren falls noch nicht vorhanden
        let genesis = Block::genesis();
        let genesis_hash = genesis.hash();
        match arc.load_block(&genesis_hash) {
            Ok(None) => {
                if let Err(e) = arc.save_block(&genesis) {
                    warn!("Could not persist genesis block: {}", e);
                } else {
                    info!("Genesis block persisted to storage");
                }
            }
            Ok(Some(_)) => {} // bereits vorhanden
            Err(e) => warn!("Could not check genesis block in storage: {}", e),
        }

        self.storage = Some(arc);

        // Modell A: Den vollen L2-Baum aus der persistierten Kette rekonstruieren.
        // `ChainManager::new` initialisiert `l2_state` auf Genesis; ohne diesen
        // Schritt divergiert er nach einem Neustart von der (fortgeschrittenen)
        // `chain.l2_state_root` → das nächste Settlement würde als „out of sync"
        // abgelehnt und der Node bliebe hängen.
        self.rebuild_l2_state_from_storage();

        self
    }

    /// Modell A: Rekonstruiert `self.l2_state` aus den persistierten Blöcken
    /// (Settlement-Transfers + gebündelte Coinbase-Emission, exakt wie
    /// `apply_block`), sodass seine Root der geladenen `chain.l2_state_root`
    /// entspricht. Läuft einmalig beim Start mit persistentem Storage.
    fn rebuild_l2_state_from_storage(&self) {
        let storage = match self.storage.as_ref() { Some(s) => s.clone(), None => return };
        let height  = self.state.chain.read().height;
        if height == 0 { return; }
        let chain_root = self.state.chain.read().l2_state_root;

        // Schnellweg: persistierten L2-Snapshot laden + nur das Delta nachspielen
        // (O(Delta) statt O(Chain)). Der Snapshot wird nur auf Settlement-Blöcken
        // geschrieben, daher stoppt der Walk-Back im Delta sauber am Snapshot-Block
        // → keine Doppel-Gutschrift.
        if let Ok(Some((snap_h, bytes))) = storage.load_l2_snapshot() {
            if snap_h <= height {
                if let Some(base) = atlas_zk::l2_state::L2State::from_snapshot_bytes(&bytes) {
                    if let Some(tree) = self.replay_l2_delta(&storage, base, snap_h, height) {
                        if tree.root_bytes() == chain_root.0 {
                            *self.l2_state.write() = tree;
                            info!("Modell A: L2-Baum via Snapshot (Höhe {snap_h}) + Delta rekonstruiert (Tip {height}).");
                            return;
                        }
                    }
                }
                warn!("L2-Snapshot unbrauchbar/inkonsistent — Full-Replay ab Genesis.");
            }
        }

        // Fallback: Full-Replay ab Genesis.
        let genesis = atlas_zk::l2_state::L2State::from_genesis(&atlas_zk::genesis_allocation());
        match self.replay_l2_delta(&storage, genesis, 0, height) {
            Some(tree) if tree.root_bytes() == chain_root.0 => {
                *self.l2_state.write() = tree;
                info!("Modell A: L2-Baum aus Storage (Full-Replay) rekonstruiert (Höhe {height}, Root passt).");
            }
            _ => warn!("L2-Rebuild: rekonstruierte Root != chain.l2_state_root {} — Inkonsistenz!",
                chain_root.as_hex()),
        }
    }

    /// Spielt die L2-Übergänge der Blöcke `(start_h, height]` auf `tree` ab
    /// (Settlement-Transfers + gebündelte Coinbase-Emission, exakt wie apply_block).
    /// `None` bei fehlendem/defektem Block.
    fn replay_l2_delta(
        &self,
        storage: &Arc<Storage>,
        mut tree: atlas_zk::l2_state::L2State,
        start_h: u64,
        height: u64,
    ) -> Option<atlas_zk::l2_state::L2State> {
        for h in (start_h + 1)..=height {
            let block = storage.load_block_by_height(h).ok()??;
            let settlements = Self::extract_settlements(&block.transactions);
            if settlements.is_empty() { continue; } // leerer Block: L2-Root unverändert
            for s in &settlements {
                let inputs = atlas_zk::l2_state::decode_calldata(&s.calldata).ok()?;
                tree.apply_calldata(&inputs).ok()?;
            }
            for (addr, amt) in self.pending_coinbase_credits(h, &block.transactions) {
                if amt > 0 { tree.credit(&addr, amt); }
            }
        }
        Some(tree)
    }

    /// Abonniert Chain-Events (Block akzeptiert, Reorg, …)
    pub fn subscribe(&self) -> broadcast::Receiver<ChainEvent> {
        self.events.subscribe()
    }

    // ── Public API ────────────────────────────────────────────────────────────

    pub fn process_block(&self, block: Block) -> Result<(), ChainError> {
        // Exklusiver Lock: verhindert Race Conditions zwischen Mining-Thread und P2P
        let _guard = self.process_lock.lock();

        let hash   = block.hash();
        let height = block.height();

        if self.state.is_block_known(&hash) {
            return Err(ChainError::AlreadyKnown(hash));
        }

        // Checkpoint-Verifikation: verhindert Long-Range-Angriffe
        if let Err(msg) = checkpoints::verify_checkpoint(self.params.network, height, &hash) {
            return Err(ChainError::Validation(ValidationError::CheckpointMismatch(msg)));
        }

        if height == 0 {
            return self.apply_block(block, hash, height);
        }

        // TRIAD PoW vollständig verifizieren
        let epoch_seed = EpochSeed::for_epoch(block.header.epoch);
        let verifier   = TriadVerifier::new(&epoch_seed, NetworkEntropy::new(), self.test_mode);
        verifier.verify(&block.header, block.header.nonce, &block.header.mix_hash)
            .map_err(|_| ChainError::Validation(ValidationError::PoWFailed))?;

        let prev_hash = block.header.prev_hash;
        let parent    = self.find_parent_header(prev_hash)?;

        let now = now_secs();
        // BlockValidator hält nur eine Referenz — on-the-fly erstellen, kein Box::leak nötig
        BlockValidator::new(&self.params).validate_block(&block, &parent, now)?;

        if prev_hash == self.state.best_hash() {
            self.apply_block(block, hash, height)
        } else {
            self.handle_fork(block, hash, height, parent)
        }
    }

    pub fn height(&self)    -> BlockHeight { self.state.height() }
    pub fn best_hash(&self) -> Hash        { self.state.best_hash() }
    /// Konsens-Parameter (read-only, z. B. für RPC-Antworten).
    pub fn consensus_params(&self) -> &ConsensusParams { &self.params }
    pub fn storage_arc(&self) -> Option<Arc<Storage>> { self.storage.clone() }

    /// Gibt Zugriff auf den StateDb für P2P und RPC
    pub fn state(&self) -> &Arc<StateDb> { &self.state }
    /// Gibt Zugriff auf den Mempool
    pub fn mempool(&self) -> &Arc<Mempool> { &self.mempool }

    pub fn block_template(
        &self,
        miner_addr:  atlas_core::crypto::Address,
        prover_addr: atlas_core::crypto::Address,
    ) -> Block {
        let chain        = self.state.chain.read();
        let height       = chain.height + 1;
        let parent       = chain.tip().cloned();
        let current_bits = chain.current_bits;
        drop(chain);

        let schedule  = RewardSchedule::new(&self.params);
        let candidate = self.mempool.select_for_block(
            self.params.max_txs_per_block.saturating_sub(1)
        );

        // Ungültige TXs (immature Coinbase-Inputs, fehlende UTXOs) filtern und evikten
        let mut invalid_txids = Vec::new();
        let txs: Vec<_> = candidate.into_iter().filter(|tx| {
            let ok = self.state.utxo_set.inputs_available(
                tx, height, self.params.coinbase_maturity,
            );
            if !ok { invalid_txids.push(tx.txid()); }
            ok
        }).collect();
        if !invalid_txids.is_empty() {
            self.mempool.remove_confirmed(&invalid_txids);
            warn!("Evicted {} TX(s) from mempool (immature/missing inputs at height {})",
                invalid_txids.len(), height);
        }

        let reward = schedule.block_reward(height, &txs);

        let mut all_txs = vec![
            atlas_core::transaction::Transaction::new_coinbase(
                height,
                reward.miner_reward,
                reward.prover_reward,
                miner_addr,
                prover_addr,
            )
        ];
        all_txs.extend(txs);

        let prev_hash   = parent.map(|h| h.hash()).unwrap_or_default();
        let epoch = Epoch::from_height(height);

        // L2-State-Transition: SettlementBids tragen ihre eigenen Beweise. Wir
        // nehmen nur die maximale Präfix-Menge auf, die lückenlos an die aktuelle
        // L2-State-Root anschließt, und schreiben die Root fort.
        let prev_l2_root = self.state.chain.read().l2_state_root;
        let (all_txs, proof_root, post_settle_root, batch_count) =
            self.assemble_l2_template(prev_l2_root, all_txs, height);

        // Modell A: finale Header-L2-Root = post-settlement-Root + Coinbase-
        // Emissions-Gutschrift (Subsidy+Fees an Miner/Prover-L2-Konten). Der Node
        // rechnet exakt dasselbe nach (apply_block). Im test_mode keine L2-Gutschrift.
        let l2_state_root = if self.test_mode {
            post_settle_root
        } else {
            let settlements = Self::extract_settlements(&all_txs);
            if settlements.is_empty() {
                // Modell A (gebündelt): leerer Block lässt die L2-Root unverändert.
                prev_l2_root
            } else {
                let mut tree = self.l2_state.read().clone();
                let ok = (|| -> Result<Hash, ()> {
                    for s in &settlements {
                        let inputs = atlas_zk::l2_state::decode_calldata(&s.calldata).map_err(|_| ())?;
                        tree.apply_calldata(&inputs).map_err(|_| ())?;
                    }
                    // Aufgelaufene Coinbase-Emission (dieser Block + vorausgehende
                    // leere Blöcke) nativ gutschreiben — wie der Node in apply_block.
                    for (addr, amt) in self.pending_coinbase_credits(height, &all_txs) {
                        if amt > 0 { tree.credit(&addr, amt); }
                    }
                    Ok(Hash(tree.root_bytes()))
                })();
                // Bei Fehler post_settle_root — der Node lehnt den Block dann ab;
                // der Miner verschwendet höchstens Arbeit, kein Konsens-Schaden.
                ok.unwrap_or(post_settle_root)
            }
        };

        let merkle_root = {
            let hashes: Vec<Hash> = all_txs.iter().map(|tx| tx.txid()).collect();
            atlas_core::hash::merkle_root(&hashes)
        };

        Block {
            header: atlas_core::block::BlockHeader {
                version:      1,
                height,
                prev_hash,
                merkle_root,
                proof_root,
                timestamp:    now_secs(),
                bits:         current_bits,
                nonce:        0,
                mix_hash:     Hash::zero(),
                epoch:        epoch.number,
                network_seed: Hash::zero(),
                batch_count,
                l2_state_root,
            },
            transactions: all_txs,
            agg_proof: Vec::new(),
        }
    }

    // ── Block verarbeitung ────────────────────────────────────────────────────

    /// Validierter Block auf die Kette anwenden (State-Transition + Chain-Update)
    /// Modell A: Emissions-Gutschrift eines Blocks = Subsidy (aus dem Schedule)
    /// + Summe der L2-Settlement-Fees, gesplittet 70/30 Miner/Prover. Die Beträge
    /// werden hier NACHGERECHNET (nicht aus der Coinbase übernommen) → Inflations-
    /// Schutz. Rückgabe: (miner_atom, prover_atom, subsidy_atom).
    fn coinbase_l2_credit(&self, height: u64, settlements: &[Settlement]) -> (u128, u128, u128) {
        let schedule = RewardSchedule::new(&self.params);
        let subsidy  = schedule.subsidy_at(height).as_atom();
        let fees: u128 = settlements.iter().map(|s| s.total_fees).sum();
        let (m, p) = self.params.split_reward(
            atlas_core::amount::Amount::from_atom(subsidy + fees));
        (m.as_atom(), p.as_atom(), subsidy)
    }

    /// Modell A: Die Coinbase-Emissions-Gutschriften eines Blocks als
    /// `(L2-Adresse, Betrag)`-Liste — Adressen aus der Coinbase, Beträge aus dem
    /// Schedule nachgerechnet. Für den Aggregator-Resync/-Follow (DA), damit er
    /// die L2-Root pro Block exakt wie der Node fortschreibt.
    pub(crate) fn coinbase_credits_of_block(&self, block: &Block) -> Vec<([u8; 20], u128)> {
        self.coinbase_credits_from(block.header.height, &block.transactions)
    }

    /// Wie `coinbase_credits_of_block`, aber aus `(height, txs)` — auch für das
    /// noch im Bau befindliche Miner-Template nutzbar.
    fn coinbase_credits_from(
        &self,
        height: u64,
        txs: &[atlas_core::transaction::Transaction],
    ) -> Vec<([u8; 20], u128)> {
        use atlas_core::transaction::OutputAddress;
        let settlements = Self::extract_settlements(txs);
        let (m, p, _) = self.coinbase_l2_credit(height, &settlements);
        let Some(cb) = txs.first() else { return Vec::new(); };
        let addr_of = |o: &atlas_core::transaction::TxOutput| -> Option<[u8; 20]> {
            match &o.address { OutputAddress::Classic(a) => Some(a.0), _ => None }
        };
        match cb.outputs.len() {
            0 => Vec::new(),
            1 => addr_of(&cb.outputs[0]).map(|a| vec![(a, m + p)]).unwrap_or_default(),
            _ => {
                let mut v = Vec::new();
                if let Some(a) = addr_of(&cb.outputs[0]) { v.push((a, m)); }
                if p > 0 { if let Some(a) = addr_of(&cb.outputs[1]) { v.push((a, p)); } }
                v
            }
        }
    }

    /// Modell A (gebündelt): die beim aktuellen Settlement-Block fälligen
    /// Coinbase-Gutschriften = der Block selbst PLUS alle vorausgehenden LEEREN
    /// Blöcke seit dem letzten Settlement (deren Emission lief auf). Der Walk-Back
    /// nutzt den Storage; Credits sind additiv (Reihenfolge egal).
    fn pending_coinbase_credits(
        &self,
        height: u64,
        txs: &[atlas_core::transaction::Transaction],
    ) -> Vec<([u8; 20], u128)> {
        let mut credits = self.coinbase_credits_from(height, txs);
        if let Some(store) = self.storage.as_ref() {
            let mut h = height;
            while h > 1 {
                h -= 1;
                match store.load_block_by_height(h) {
                    Ok(Some(b)) => {
                        if !Self::extract_settlements(&b.transactions).is_empty() {
                            break; // letztes Settlement erreicht — Stop
                        }
                        credits.extend(self.coinbase_credits_of_block(&b));
                    }
                    _ => break,
                }
            }
        }
        credits
    }

    fn apply_block(&self, block: Block, hash: Hash, height: u64) -> Result<(), ChainError> {
        // L2-State-Transition: soundness-tragende Verifikation der SettlementBids.
        // Jeder Bid trägt seinen eigenen Groth16-State-Transition-Beweis; die
        // L2-State-Root-Kette wird strikt gegen den aktuellen Chain-Zustand geprüft.
        let prev_l2_root = self.state.chain.read().l2_state_root;
        let settlements  = Self::extract_settlements(&block.transactions);
        // 1. Settlement-Proof-Kette validieren (proof_root + je-Bid-Beweise + DA)
        //    → Root NACH den Settlements. Im Modell A ist das eine ZWISCHEN-Root;
        //    der Header trägt die Root NACH der zusätzlichen Coinbase-Gutschrift.
        let post_settle_root = if settlements.is_empty() {
            prev_l2_root
        } else {
            let (proof_root, r) = Self::validate_l2_chain(&prev_l2_root, &settlements)?;
            if block.header.proof_root != proof_root {
                return Err(ChainError::Validation(ValidationError::ZkProofInvalid(
                    "proof_root does not match recomputed settlement digest".to_string(),
                )));
            }
            let zk = ZkVerifier::new(self.test_mode);
            for s in &settlements {
                zk.verify_state_bid(
                    &s.proof, &s.pre_root, &s.post_root, s.total_fees, &s.batch_commitment,
                ).map_err(|e| ChainError::Validation(
                    ValidationError::ZkProofInvalid(e.to_string()),
                ))?;
                if !self.test_mode {
                    Self::verify_data_availability(s).map_err(|e| ChainError::Validation(
                        ValidationError::ZkProofInvalid(e),
                    ))?;
                }
            }
            info!("ZK: {} state-transition proof(s) verified for block {} (settle root → {})",
                settlements.len(), height, &r.as_hex()[..16]);
            r
        };

        // 2. Modell A: vollen L2-Baum bauen = Settlements + Coinbase-Emissions-
        //    Gutschrift (Subsidy+Fees, Beträge aus dem Schedule nachgerechnet) und
        //    gegen den Header prüfen. Die L2-Root rückt damit pro Block vor. Im
        //    test_mode (Dummy-Calldata) gilt die alte Semantik: Header ==
        //    Settlement-Root, keine L2-Gutschrift.
        let (new_l2_tree, emission_subsidy) = if self.test_mode {
            if block.header.l2_state_root != post_settle_root {
                return Err(ChainError::Validation(ValidationError::ZkProofInvalid(
                    "header l2_state_root does not match settlement chain".to_string(),
                )));
            }
            (None, RewardSchedule::new(&self.params).subsidy_at(height).as_atom())
        } else {
            let subsidy = RewardSchedule::new(&self.params).subsidy_at(height).as_atom();
            let mut tree = self.l2_state.read().clone();
            if tree.root_bytes() != prev_l2_root.0 {
                return Err(ChainError::Validation(ValidationError::ZkProofInvalid(
                    "node L2 tree out of sync with chain l2_state_root".to_string(),
                )));
            }
            if settlements.is_empty() {
                // Modell A (gebündelt): ein Block OHNE Settlement lässt die L2-Root
                // UNVERÄNDERT. Die Emission läuft auf und wird beim nächsten
                // Settlement-Block nativ nachgetragen — so bleibt die Settlement-
                // `pre_root` zwischen Settlements STABIL (keine Coinbase-Race).
                if block.header.l2_state_root != prev_l2_root {
                    return Err(ChainError::Validation(ValidationError::ZkProofInvalid(
                        "block without settlements must keep L2 state root unchanged (batched coinbase)".to_string(),
                    )));
                }
                (None, subsidy)
            } else {
                // Transfers (bewiesen) anwenden → Settlement-Root.
                for s in &settlements {
                    let inputs = atlas_zk::l2_state::decode_calldata(&s.calldata)
                        .map_err(|e| ChainError::Validation(ValidationError::ZkProofInvalid(
                            format!("L2 calldata decode: {}", e))))?;
                    tree.apply_calldata(&inputs).map_err(|e| ChainError::Validation(
                        ValidationError::ZkProofInvalid(format!("L2 calldata apply: {:?}", e))))?;
                }
                if tree.root_bytes() != post_settle_root.0 {
                    return Err(ChainError::Validation(ValidationError::ZkProofInvalid(
                        "node L2 tree root != settlement chain root".to_string(),
                    )));
                }
                // Aufgelaufene Coinbase-Emission nativ gutschreiben: dieser
                // Settlement-Block + alle vorausgehenden LEEREN Blöcke seit dem
                // letzten Settlement (Credits sind additiv → kommutieren).
                for (addr, amt) in self.pending_coinbase_credits(block.header.height, &block.transactions) {
                    if amt > 0 { tree.credit(&addr, amt); }
                }
                if tree.root_bytes() != block.header.l2_state_root.0 {
                    return Err(ChainError::Validation(ValidationError::ZkProofInvalid(
                        "node L2 tree root != header l2_state_root (Modell A gebündelt)".to_string(),
                    )));
                }
                (Some(tree), subsidy)
            }
        };

        // Forced-Inclusion-Konsensregeln: Queue fortschreiben (Discharge durch
        // Inclusion/Rejection, Fälligkeits-Enforcement, neue L2ForcedTx).
        // Im test_mode deaktiviert (Dummy-Proofs tragen keine echte Calldata).
        let new_forced_queue = if self.test_mode {
            self.state.chain.read().forced_queue.clone()
        } else {
            let prev_queue = self.state.chain.read().forced_queue.clone();
            Self::apply_forced_rules(
                &prev_queue, &settlements, &block.transactions,
                height, self.params.forced_inclusion_window,
            ).map_err(|e| ChainError::Validation(ValidationError::ZkProofInvalid(
                format!("forced inclusion: {}", e),
            )))?
        };

        // Snapshot BEFORE dieser Block angewendet wird (für Reorg-Rollback)
        let pre_snapshot = {
            let chain = self.state.chain.read();
            StateSnapshot {
                height,
                block_hash:    hash,
                utxos:         self.state.utxo_set.snapshot(),
                total_supply:  chain.total_supply,
                total_txs:     chain.total_txs,
                total_fees:    chain.total_fees,
                avg_fees:      chain.avg_fees,
                security_delay: chain.security_delay,
                current_bits:  chain.current_bits,
                l2_state_root: chain.l2_state_root,
                l2_state_bytes: self.l2_state.read().to_snapshot_bytes(),
                forced_queue:  chain.forced_queue.clone(),
            }
        };

        // State-Transition
        let executor = BlockExecutor::new(
            self.params.clone(),
            self.state.utxo_set.clone(),
        );
        let result = executor.execute(&block)?;

        // Chain-State aktualisieren
        {
            let mut chain = self.state.chain.write();
            chain.height    = height;
            chain.best_hash = hash;
            chain.l2_state_root = block.header.l2_state_root;
            chain.forced_queue  = new_forced_queue;

            // Modell A: Die Emission (Subsidy) ist auf L2 gutgeschrieben worden;
            // total_supply zählt die echte Neuemission (Fees = Umverteilung
            // Sender→Miner, keine neue Geldmenge).
            chain.total_supply += atlas_core::amount::Amount::from_atom(emission_subsidy);
            chain.total_txs    += result.tx_count as u64;
            chain.update_fees(result.total_fees);
            chain.add_header(block.header.clone());

            // Difficulty Retarget
            let adjuster = DifficultyAdjuster::new(&self.params);
            if adjuster.is_retarget_block(height) {
                if let Some(interval_time) = chain.interval_time() {
                    let new_bits = adjuster.retarget(block.header.bits, interval_time);
                    chain.current_bits = new_bits;
                    info!("Retarget at height {}: new bits = {:#010x}", height, new_bits);
                }
            }

            // Adaptive Security Floor — bei jedem Halving prüfen
            if height > 0 && height.is_multiple_of(self.params.halving_interval) {
                let floor = AdaptiveSecurityFloor::new(&self.params);
                let sf    = floor.evaluate(height, chain.avg_fees, chain.security_delay);
                chain.security_delay = sf.delay_count;
                if sf.halving_delayed {
                    info!(
                        "Security Floor: Halving delayed at height {} (count={}/3)",
                        height, sf.delay_count
                    );
                }
            }
        }

        // Modell A: den fortgeschriebenen L2-Baum übernehmen (Commit nach
        // erfolgreicher Block-Anwendung). prev_l2_root == self.l2_state vorher
        // wurde oben geprüft; Root-Match gegen new_l2_root ebenfalls.
        let l2_changed = new_l2_tree.is_some();
        if let Some(tree) = new_l2_tree {
            *self.l2_state.write() = tree;
        }

        // Snapshot speichern
        self.snapshots.write().push(pre_snapshot);

        // Block im Store sichern (für Reorg)
        self.state.store_block(block.clone());

        // Optional: auf Disk persistieren
        if let Some(storage) = &self.storage {
            if let Err(e) = storage.save_block(&block) {
                warn!("Failed to persist block {}: {}", height, e);
            }
            let chain = self.state.chain.read();
            if let Err(e) = storage.save_chain_state(&chain) {
                warn!("Failed to persist chain state at height {}: {}", height, e);
            }
            // Modell A: L2-Snapshot nur persistieren, wenn sich der Baum geändert
            // hat (Settlement-Block) → O(Delta)-Startup-Rebuild statt O(Chain).
            if l2_changed {
                let bytes = self.l2_state.read().to_snapshot_bytes();
                if let Err(e) = storage.save_l2_snapshot(height, &bytes) {
                    warn!("Failed to persist L2 snapshot at height {}: {}", height, e);
                }
            }
            // Inkrementelles UTXO-Update: nur veränderte UTXOs schreiben
            let delta = self.state.utxo_set.drain_delta();
            if let Err(e) = storage.save_utxo_delta(&delta.created, &delta.spent) {
                warn!("Failed to persist UTXO delta at height {}: {}", height, e);
            }
            // Pruning einmal pro Epoch (2016 Blöcke ≈ ~1.7 Stunden @ 3s)
            // Löscht ZK-Proofs + Block-Bodies die außerhalb des Retention-Fensters liegen.
            if height % 2016 == 0 && height > 0 {
                if let Err(e) = storage.run_pruning(height) {
                    warn!("Pruning failed at height {}: {}", height, e);
                }
            }
        }

        // Mempool bereinigen
        let confirmed: Vec<TxId> = block.transactions.iter()
            .map(|tx| tx.txid())
            .collect();
        self.mempool.remove_confirmed(&confirmed);

        // Chain-Event veröffentlichen (Fehler ignorieren wenn kein Subscriber da)
        let _ = self.events.send(ChainEvent::BlockAccepted { hash, height });

        info!(
            "Block {} | height={} | txs={} | fees={} ATOM | {} µs",
            &hash.as_hex()[..16],
            height,
            result.tx_count,
            result.total_fees.as_atom(),
            result.execution_us,
        );

        Ok(())
    }

    // ── Reorg ─────────────────────────────────────────────────────────────────

    /// Fork-Handling: neue Kette ist länger → Reorganisation ausführen
    fn handle_fork(
        &self,
        block:          Block,
        _hash:          Hash,
        height:         u64,
        parent_header:  BlockHeader,
    ) -> Result<(), ChainError> {
        let current_height = self.height();

        if height <= current_height {
            // Kürzere oder gleich lange Kette: Block speichern, nicht umschalten
            self.state.store_block(block);
            return Ok(());
        }

        // Echten Fork-Punkt bestimmen: `parent_header` kann selbst ein (nur im
        // Store liegender) Fork-Block sein — bei einem Mehr-Block-Fork zeigt
        // parent.height NICHT auf den gemeinsamen Vorfahren. Vom Parent
        // rückwärts laufen, bis ein Header der AKTIVEN Kette erreicht ist;
        // dessen Höhe ist der Fork-Punkt. (Mit parent.height als Fork-Punkt
        // schlug der Snapshot-Lookup fehl und Fork-Ketten blieben für immer
        // unanwendbar — IBD-Dauerstall bei jedem echten Reorg.)
        let fork_at_height = {
            let mut cur = parent_header.clone();
            loop {
                let on_active = {
                    let chain = self.state.chain.read();
                    chain.recent_headers.iter().any(|h| h.hash() == cur.hash())
                };
                if on_active || cur.height == 0 {
                    break cur.height;
                }
                match self.find_parent_header(cur.prev_hash) {
                    Ok(p)  => cur = p,
                    Err(_) => return Err(ChainError::Orphan(cur.prev_hash)),
                }
            }
        };
        let reorg_depth    = current_height.saturating_sub(fork_at_height);

        if reorg_depth > MAX_REORG_DEPTH {
            return Err(ChainError::ReorgTooDeep { depth: reorg_depth, max: MAX_REORG_DEPTH });
        }

        // Blöcke auf dem neuen Fork sammeln (fork_at_height+1 … new_block-1)
        let mut fork_blocks = self.collect_fork_blocks(&block, fork_at_height)?;

        warn!(
            "Chain reorg: {} blocks rolled back, {} applied (fork at height {})",
            reorg_depth,
            fork_blocks.len() + 1,
            fork_at_height,
        );

        // Pre-Reorg-Zustand sichern — falls der Fork scheitert, können wir zurück
        let pre_reorg_utxos      = self.state.utxo_set.snapshot();
        let pre_reorg_chain      = self.state.chain.read().clone();
        let pre_reorg_snap_count = self.snapshots.read().len();
        let pre_reorg_l2         = self.l2_state.read().to_snapshot_bytes();

        // ── Rollback zum Fork-Punkt ──────────────────────────────────────────
        // Schneller Pfad: In-Memory-Snapshot am Fork-Punkt. Fehlt er (Snapshots
        // sind nicht persistent → nach einem Neustart leer), wird der Zustand
        // durch Neu-Abspielen der aktiven Kette von Genesis rekonstruiert.
        // Ohne diesen Fallback könnte ein neu gestarteter Node NIE reorganisieren.
        let snap = {
            let mgr = self.snapshots.read();
            mgr.get_at_height(fork_at_height + 1).map(|s| {
                (s.utxos.clone(), s.total_supply, s.total_txs,
                 s.total_fees, s.avg_fees, s.security_delay, s.current_bits,
                 s.l2_state_root, s.l2_state_bytes.clone(), s.forced_queue.clone())
            })
        };

        match snap {
            Some((utxo_snap, t_supply, t_txs, t_fees, avg_fees, sec_delay, bits, l2_root, l2_bytes, forced_q)) => {
                self.state.utxo_set.restore(utxo_snap);
                // Modell A: node-gehaltenen L2-Baum aus dem Snapshot wiederherstellen
                // (vor dem Chain-Lock, um nicht zwei Write-Locks zu halten).
                if !l2_bytes.is_empty() {
                    if let Some(st) = atlas_zk::l2_state::L2State::from_snapshot_bytes(&l2_bytes) {
                        *self.l2_state.write() = st;
                    }
                }
                let mut chain = self.state.chain.write();
                chain.height         = fork_at_height;
                chain.total_supply   = t_supply;
                chain.total_txs      = t_txs;
                chain.total_fees     = t_fees;
                chain.avg_fees       = avg_fees;
                chain.security_delay = sec_delay;
                chain.current_bits   = bits;
                chain.l2_state_root  = l2_root;
                chain.forced_queue   = forced_q;
                while chain.recent_headers.len() > 1 {
                    match chain.recent_headers.back() {
                        Some(h) if h.height > fork_at_height => { chain.recent_headers.pop_back(); }
                        _ => break,
                    }
                }
                chain.best_hash = chain.tip().map(|h| h.hash()).unwrap_or_default();
            }
            None => {
                warn!("Reorg-Snapshot bei Höhe {} fehlt (Neustart) — rekonstruiere Zustand von Genesis",
                    fork_at_height + 1);
                if let Err(e) = self.rebuild_state_to(fork_at_height) {
                    // Rekonstruktion fehlgeschlagen → Originalkette wiederherstellen.
                    self.state.utxo_set.restore(pre_reorg_utxos);
                    *self.state.chain.write() = pre_reorg_chain;
                    if let Some(st) = atlas_zk::l2_state::L2State::from_snapshot_bytes(&pre_reorg_l2) {
                        *self.l2_state.write() = st;
                    }
                    self.snapshots.write().truncate(pre_reorg_snap_count);
                    return Err(e);
                }
                // rebuild_state_to lässt self.state exakt auf fork_at_height.
            }
        }

        // Neuen Fork anwenden — bei Fehler: zurück auf ursprüngliche Kette
        fork_blocks.push(block);
        let new_height = fork_blocks.last().map(|b| b.height()).unwrap_or(fork_at_height);
        for (applied, b) in fork_blocks.into_iter().enumerate() {
            let h  = b.hash();
            let bh = b.height();
            if let Err(e) = self.apply_block(b, h, bh) {
                warn!(
                    "Reorg failed after {} blocks (height {}): {} — restoring original chain",
                    applied, bh, e
                );
                self.state.utxo_set.restore(pre_reorg_utxos);
                *self.state.chain.write() = pre_reorg_chain;
                if let Some(st) = atlas_zk::l2_state::L2State::from_snapshot_bytes(&pre_reorg_l2) {
                    *self.l2_state.write() = st;
                }
                // Snapshot-Manager zurücksetzen: fork-Snapshots entfernen
                self.snapshots.write().truncate(pre_reorg_snap_count);
                return Err(e);
            }
        }

        let _ = self.events.send(ChainEvent::Reorg { new_height });
        Ok(())
    }

    /// Sammelt Blöcke auf dem neuen Fork (vom Block-Store), älteste zuerst
    fn collect_fork_blocks(
        &self,
        new_tip:       &Block,
        ancestor_height: u64,
    ) -> Result<Vec<Block>, ChainError> {
        let mut blocks       = Vec::new();
        let mut current_hash = new_tip.header.prev_hash;

        loop {
            // Prüfen ob wir den Common Ancestor erreicht haben
            let is_ancestor = {
                let chain = self.state.chain.read();
                chain.recent_headers.iter()
                    .any(|h| h.hash() == current_hash && h.height <= ancestor_height)
            };
            if is_ancestor || current_hash == Hash::zero() { break; }

            let b = self.state.get_block(&current_hash)
                .ok_or(ChainError::Orphan(current_hash))?;
            current_hash = b.header.prev_hash;
            blocks.push(b);
        }

        blocks.reverse(); // älteste zuerst
        Ok(blocks)
    }

    /// Rekonstruiert den Chain-Zustand exakt auf `target_height`, indem die
    /// AKTIVE Kette von Genesis neu abgespielt wird. Fallback für Reorgs nach
    /// einem Neustart, wenn der In-Memory-Snapshot am Fork-Punkt fehlt
    /// (Snapshots sind nicht persistent). O(Kettenlänge), aber selten — nur bei
    /// Reorg unmittelbar nach Neustart. Lässt `self.state` exakt auf
    /// `target_height` (UTXO, Chain-Felder, recent_headers, Snapshots neu
    /// aufgebaut), indem dieselbe `apply_block`-Logik wie im Normalbetrieb
    /// genutzt wird — keine Logik-Duplikation, garantiert konsistent.
    fn rebuild_state_to(&self, target_height: u64) -> Result<(), ChainError> {
        let storage = self.storage.as_ref()
            .ok_or_else(|| ChainError::Storage(
                "Reorg nach Neustart braucht persistenten Storage zur Rekonstruktion".into()))?;

        // Blöcke der aktiven Kette (Höhe 1..=target) aus dem Storage holen.
        let mut blocks = Vec::with_capacity(target_height as usize);
        for h in 1..=target_height {
            let b = storage.load_block_by_height(h)
                .map_err(|e| ChainError::Storage(format!("load height {}: {}", h, e)))?
                .ok_or_else(|| ChainError::Storage(format!(
                    "Block bei Höhe {} fehlt im Storage — Rekonstruktion unmöglich", h)))?;
            blocks.push(b);
        }

        // Zustand auf Genesis zurücksetzen — exakt wie beim Node-Start:
        // Genesis-Block ist leer (keine L1-UTXOs), L2-Root = EMPTY.
        self.state.utxo_set.restore(std::collections::HashMap::new());
        *self.state.chain.write() = atlas_state::state_db::ChainState::genesis();
        // Modell A: node-L2-Baum ebenfalls auf den Genesis-Zustand zurücksetzen;
        // apply_block baut ihn beim Replay wieder auf.
        *self.l2_state.write() =
            atlas_zk::l2_state::L2State::from_genesis(&atlas_zk::genesis_allocation());
        self.snapshots.write().truncate(0);

        // Aktive Kette via Standard-apply_block neu anwenden → self.state steht
        // danach exakt auf target_height (inkl. neu aufgebauter Snapshots).
        for b in blocks {
            let h  = b.hash();
            let ht = b.height();
            self.apply_block(b, h, ht)?;
        }
        Ok(())
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn find_parent_header(&self, prev_hash: Hash) -> Result<BlockHeader, ChainError> {
        // 1. Aktueller Tip?
        {
            let chain = self.state.chain.read();
            if let Some(tip) = chain.tip() {
                if tip.hash() == prev_hash {
                    return Ok(tip.clone());
                }
            }
            // 2. In recent_headers?
            if let Some(h) = chain.find_header_by_hash(&prev_hash) {
                return Ok(h.clone());
            }
        }
        // 3. Im Block-Store?
        if let Some(b) = self.state.get_block(&prev_hash) {
            return Ok(b.header);
        }
        Err(ChainError::Orphan(prev_hash))
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use atlas_consensus::params::ConsensusParams;
    use atlas_core::block::Block;
    use atlas_core::crypto::KeyPair;
    use atlas_state::state_db::StateDb;
    use atlas_mempool::mempool::Mempool;
    use atlas_triad::dataset::{Dataset, DatasetConfig};
    use atlas_triad::epoch::EpochSeed;
    use atlas_triad::miner::TriadMiner;
    use atlas_triad::network_entropy::NetworkEntropy;
    use std::sync::{Arc, atomic::AtomicBool};

    fn make_chain() -> Arc<ChainManager> {
        let params  = ConsensusParams::mainnet();
        let state   = Arc::new(StateDb::new());
        let mempool = Arc::new(Mempool::new(params.clone()));
        Arc::new(ChainManager::new(params, state, mempool, true))
    }

    /// Inflations-Schutz (Modell A): Die Coinbase-Emissions-Gutschrift entspricht
    /// EXAKT dem Reward-Schedule — der Node rechnet sie selbst nach, ein Miner kann
    /// sich also nicht mehr gutschreiben. Nach dem Halving-Cap ist die Subsidy 0.
    #[test]
    fn test_coinbase_l2_credit_inflation_safe() {
        let chain = make_chain();
        let p     = chain.consensus_params().clone();
        let sched = RewardSchedule::new(&p);

        // Höhe 1, keine Settlements → Gutschrift == Subsidy, Split summiert exakt.
        let (m, pr, subsidy) = chain.coinbase_l2_credit(1, &[]);
        assert_eq!(subsidy, sched.subsidy_at(1).as_atom());
        assert_eq!(m + pr, subsidy, "Gutschrift (ohne Fees) muss == Subsidy sein");
        assert!(m > 0 && m <= subsidy);

        // Nach dem letzten Halving: Subsidy 0 → keine Emission mehr (100M-Cap).
        let past_cap = p.halving_interval * (p.max_halvings as u64) + 1;
        let (m2, pr2, subsidy2) = chain.coinbase_l2_credit(past_cap, &[]);
        assert_eq!(subsidy2, 0, "nach {} Halvings muss die Subsidy 0 sein", p.max_halvings);
        assert_eq!(m2 + pr2, 0, "nach dem Cap darf keine Emission gutgeschrieben werden");
    }

    fn mine_block(chain: &ChainManager) -> Block {
        let kp           = KeyPair::generate();
        let mut template = chain.block_template(kp.address, kp.address);
        template.header.bits = 0x200f_ffff;
        // Anti-Flake: zwei Test-Blöcke im selben Sekunden-Tick verletzen sonst
        // die Konsensregel timestamp > parent.timestamp.
        if let Some(parent) = chain.state().chain.read().tip() {
            if template.header.timestamp <= parent.timestamp {
                template.header.timestamp = parent.timestamp + 1;
            }
        }
        let target = template.header.target();

        let seed    = EpochSeed::for_epoch(template.header.epoch);
        let dataset = Dataset::new_for_verification(&seed, DatasetConfig::test());
        let miner   = TriadMiner::new(dataset, NetworkEntropy::new());
        let stop    = Arc::new(AtomicBool::new(false));

        let result = miner.mine(&template.header, &target, 0, &stop)
            .expect("Should find solution with easy target");

        template.header.nonce    = result.nonce;
        template.header.mix_hash = result.mix_hash;
        template
    }

    #[test]
    fn test_genesis_is_already_known() {
        let chain = make_chain();
        let err   = chain.process_block(Block::genesis()).unwrap_err();
        assert!(matches!(err, ChainError::AlreadyKnown(_)));
    }

    #[test]
    fn test_block_template_starts_at_height_one() {
        let chain    = make_chain();
        let kp       = KeyPair::generate();
        let template = chain.block_template(kp.address, kp.address);
        assert_eq!(template.height(), 1);
        assert!(!template.transactions.is_empty());
        assert!(template.transactions[0].is_coinbase());
    }

    #[test]
    fn test_mine_and_submit_increments_height() {
        let chain = make_chain();
        assert_eq!(chain.height(), 0);
        let block = mine_block(&chain);
        chain.process_block(block).expect("Valid block must be accepted");
        assert_eq!(chain.height(), 1);
    }

    #[test]
    fn test_duplicate_block_rejected() {
        let chain = make_chain();
        let block = mine_block(&chain);
        chain.process_block(block.clone()).unwrap();
        let err = chain.process_block(block).unwrap_err();
        assert!(matches!(err, ChainError::AlreadyKnown(_)));
    }

    #[test]
    fn test_total_supply_tracks_emission() {
        // Modell A: Die Coinbase trägt KEINEN L1-Wert (Output = 0); die Emission
        // (Subsidy) wird auf L2 gutgeschrieben und total_supply zählt genau diese
        // Neuemission — NICHT den (jetzt null) L1-Coinbase-Output.
        let chain = make_chain();
        let block = mine_block(&chain);
        assert_eq!(block.transactions[0].total_output(), atlas_core::amount::Amount::ZERO,
            "Modell A: Coinbase-Output muss wertlos sein");
        let (_, _, subsidy_atom) = chain.coinbase_l2_credit(1, &[]);
        chain.process_block(block).unwrap();
        assert_eq!(chain.state.total_supply().as_atom(), subsidy_atom);
    }

    #[test]
    fn test_orphan_block_rejected() {
        let chain  = make_chain();
        let mut orphan = mine_block(&chain);
        orphan.header.prev_hash = Hash::sha256(b"does not exist");
        let err = chain.process_block(orphan).unwrap_err();
        assert!(matches!(err,
            ChainError::Orphan(_) | ChainError::Validation(_) | ChainError::AlreadyKnown(_)
        ));
    }

    #[test]
    fn test_two_sequential_blocks() {
        let chain = make_chain();
        chain.process_block(mine_block(&chain)).unwrap();
        assert_eq!(chain.height(), 1);
        chain.process_block(mine_block(&chain)).unwrap();
        assert_eq!(chain.height(), 2);
    }

    #[test]
    fn test_short_fork_accepted_but_not_reorged() {
        let chain  = make_chain();
        let block1 = mine_block(&chain);
        chain.process_block(block1.clone()).unwrap();

        // Zweiter Block auf block1 → tip jetzt height=2
        let block2 = mine_block(&chain);
        chain.process_block(block2).unwrap();
        assert_eq!(chain.height(), 2);

        // block1 nochmal einreichen (alt, gleiche height=1 wie jetzt 2) →
        // Kein Reorg (kürzere Kette), kein Fehler
        let err = chain.process_block(block1).unwrap_err();
        // Wird als AlreadyKnown abgewiesen weil block_store es enthält
        assert!(matches!(err, ChainError::AlreadyKnown(_)));
    }

    /// Hilfsfunktion: baut ein Settlement (Block-intern) mit Dummy-Proof.
    fn mk_settlement(pre: [u8; 32], post: [u8; 32], bid: u128, fees: u128) -> Settlement {
        Settlement {
            batch_id:         Hash::sha256(&post).0,
            bid_amount:       bid,
            pre_root:         pre,
            post_root:        post,
            batch_commitment: Hash::sha256(b"commit").0,
            total_fees:       fees,
            proof:            vec![1u8; 8], // Dummy — Logik-Test, keine Krypto
            calldata:         Vec::new(),
            forced_rejections: Vec::new(),
        }
    }

    /// Guard: Die hartkodierte Genesis-L2-Root in atlas-core MUSS exakt der
    /// leeren AccountTree-Wurzel aus atlas-zk entsprechen. Andernfalls würde der
    /// erste SettlementBid nie an die Chain-Genesis anschließen (pre_root-Mismatch)
    /// und die gesamte L2-Kette stünde still.
    #[test]
    fn test_empty_l2_root_matches_zk() {
        assert_eq!(
            atlas_core::block::EMPTY_L2_ROOT,
            atlas_zk::empty_l2_state_root(),
            "EMPTY_L2_ROOT (atlas-core) != empty_l2_state_root() (atlas-zk) — Genesis-Anker driftet"
        );
    }

    /// Guard: Die hartkodierte geförderte Genesis-L2-Root in atlas-core MUSS exakt
    /// der Wurzel der kanonischen Genesis-Allokation aus atlas-zk entsprechen.
    /// Andernfalls verankert der Node-Genesis-Block einen anderen L2-Zustand als
    /// der Aggregator hält → der erste SettlementBid schließt nicht an (pre_root-
    /// Mismatch) und die L2-Kette steht still. Der Genesis-Block selbst verankert
    /// diese geförderte Root (kein leerer Baum, da ATLAS keine Bridge/Mint hat).
    #[test]
    fn test_genesis_l2_root_matches_zk() {
        assert_eq!(
            atlas_core::block::GENESIS_L2_ROOT,
            atlas_zk::genesis_l2_state_root(),
            "GENESIS_L2_ROOT (atlas-core) != genesis_l2_state_root() (atlas-zk) — Genesis-Anker driftet"
        );
        assert_eq!(
            Block::genesis().header.l2_state_root,
            Hash(atlas_zk::genesis_l2_state_root()),
            "Genesis-Block verankert nicht die geförderte L2-Root"
        );
        // KRITISCH: Der LAUFENDE Chain-Zustand eines frischen Nodes MUSS exakt
        // diese geförderte Root tragen — sonst wird das allererste Settlement
        // beim Block-Bau verworfen ("pre_root does not chain") und die L2 ist
        // auf einer frischen Chain tot. (Regressionsschutz: Bug 2026-06-13.)
        assert_eq!(
            atlas_state::state_db::ChainState::genesis().l2_state_root,
            Hash(atlas_zk::genesis_l2_state_root()),
            "ChainState::genesis() L2-Root != geförderte Genesis-Root — erstes Settlement nicht mineable"
        );
    }

    /// L2-State-Root-Kette: validate_l2_chain akzeptiert eine lückenlose Kette,
    /// verwirft Lücken/falschen Anker, und compute_settlement_root ist deterministisch.
    #[test]
    fn test_l2_state_root_chaining() {
        let empty = Hash(atlas_core::block::EMPTY_L2_ROOT);
        let r1 = Hash::sha256(b"root-1").0;
        let r2 = Hash::sha256(b"root-2").0;

        // Lückenlose Kette empty → r1 → r2
        let chain = vec![
            mk_settlement(*empty.as_bytes(), r1, 1_000, 10),
            mk_settlement(r1, r2, 2_000, 20),
        ];
        let (proof_root, new_root) =
            ChainManager::validate_l2_chain(&empty, &chain).expect("Kette muss valide sein");
        assert_eq!(new_root, Hash(r2), "neue L2-Root = post_root des letzten Batches");

        // Determinismus
        let pr2 = ChainManager::compute_settlement_root(&empty, &chain);
        assert_eq!(proof_root, pr2);

        // Falscher Anker (pre_root[0] != aktuelle Root) → Fehler
        let wrong_anchor = Hash::sha256(b"wrong").0;
        let bad = vec![mk_settlement(wrong_anchor, r1, 1, 0)];
        assert!(ChainManager::validate_l2_chain(&empty, &bad).is_err());

        // Lücke in der Mitte → Fehler
        let gapped = vec![
            mk_settlement(*empty.as_bytes(), r1, 1, 0),
            mk_settlement(r2, Hash::sha256(b"root-3").0, 1, 0), // pre=r2 != r1
        ];
        assert!(ChainManager::validate_l2_chain(&empty, &gapped).is_err());
    }

    /// assemble_l2_template nimmt nur die maximale anschließende Präfix-Menge auf
    /// und verwirft nicht-verkettende Bids (statt einen ungültigen Block zu bauen).
    /// Test-ChainManager (test_mode, ohne Storage) für Template-/Regel-Tests.
    fn mk_test_manager() -> ChainManager {
        let params  = ConsensusParams::regtest();
        let state   = Arc::new(StateDb::new());
        let mempool = Arc::new(Mempool::new(params.clone()));
        ChainManager::new(params, state, mempool, true)
    }

    #[test]
    fn test_assemble_l2_template_prefix() {
        use atlas_core::amount::Amount;
        use atlas_core::transaction::Transaction;
        let empty = Hash(atlas_core::block::EMPTY_L2_ROOT);
        let r1 = Hash::sha256(b"a").0;
        let r2 = Hash::sha256(b"b").0;
        let bad = Hash::sha256(b"unrelated").0;

        let mk = |pre: [u8;32], post: [u8;32]| Transaction::new_settlement_bid(
            Hash::sha256(&post), atlas_core::crypto::Address([3u8;20]),
            Amount::from_atom(1), Hash(pre), Hash(post),
            Hash::sha256(b"c"), 0, vec![9u8; 4], Vec::new(), Vec::new(),
        );

        let txs = vec![
            mk(*empty.as_bytes(), r1),  // chains
            mk(bad, r2),                // does NOT chain → dropped
            mk(r1, r2),                 // chains after first
        ];
        let mgr = mk_test_manager();
        let (kept, _proof_root, new_root, count) =
            mgr.assemble_l2_template(empty, txs, 1);
        assert_eq!(count, 2, "nur die 2 verkettenden Bids bleiben");
        assert_eq!(new_root, Hash(r2));
        // Die gedroppte TX darf nicht enthalten sein
        let settle = ChainManager::extract_settlements(&kept);
        assert_eq!(settle.len(), 2);
    }

    // ── Forced Inclusion: Konsensregeln (apply_forced_rules) ─────────────────

    /// Baut eine signierte Forced-TX + zugehörigen L2-State mit einem
    /// geförderten Konto (Balance 1000, Nonce 0).
    fn forced_fixture() -> (
        atlas_zk::l2_state::L2State,   // Zustand (pre_root-Quelle)
        [u8; 20],                      // from
        [u8; 20],                      // to
        u64,                           // sender_index
        atlas_core::transaction::Transaction, // gültige Forced-TX (nonce 0)
    ) {
        use atlas_zk::eddsa::EddsaKeypair;
        use atlas_zk::l2_state::{build_l2_eddsa, GenesisAlloc, L2State};
        let kp   = EddsaKeypair::from_seed(0xF0CE_D001);
        let from = kp.public().address20();
        let to   = [0xCDu8; 20];
        let l2   = L2State::from_genesis(&[GenesisAlloc { address: from, balance: 1_000 }]);
        let idx  = l2.index_of(&from).expect("Konto registriert");
        let (f, pubkey, sig) = build_l2_eddsa(&kp, &to, 100, 5, 0);
        assert_eq!(f, from);
        let ftx = atlas_core::transaction::Transaction::new_l2_forced_tx(
            from, to, 100, 5, 0, pubkey, sig.to_vec(), idx,
        );
        (l2, from, to, idx, ftx)
    }

    /// Settlement mit gegebener Calldata/Rejections an `pre_root` (Identitäts-
    /// Übergang — für Queue-Regeln zählen nur pre_root/calldata/rejections).
    fn mk_settlement_da(
        pre: [u8; 32],
        calldata: Vec<u8>,
        rejections: Vec<atlas_core::transaction::ForcedRejection>,
    ) -> Settlement {
        let mut s = mk_settlement(pre, pre, 1, 0);
        s.calldata = calldata;
        s.forced_rejections = rejections;
        s
    }

    /// Lebenszyklus: Einreihen (Sig-Prüfung, Dedup) → Fälligkeit →
    /// Discharge durch Inclusion.
    #[test]
    fn test_forced_queue_enqueue_and_inclusion() {
        use atlas_core::transaction::TxType;
        use atlas_zk::l2_state::{encode_calldata, L2Input};
        let (l2, from, to, _idx, ftx) = forced_fixture();
        let pre = l2.root_bytes();

        // Einreihen bei Höhe 10 (window = 5)
        let q = ChainManager::apply_forced_rules(&[], &[], &[ftx.clone()], 10, 5)
            .expect("gültige Forced-TX muss eingereiht werden");
        assert_eq!(q.len(), 1);
        assert_eq!(q[0].seen_height, 10);

        // Duplikat (gleiches from+nonce) → Block ungültig
        assert!(ChainManager::apply_forced_rules(&q, &[], &[ftx.clone()], 11, 5).is_err());

        // Manipulierte Signatur → Block ungültig
        let mut bad = ftx.clone();
        if let TxType::L2ForcedTx { sig, .. } = &mut bad.tx_type { sig[0] ^= 0x01; }
        assert!(ChainManager::apply_forced_rules(&[], &[], &[bad], 10, 5).is_err());

        // Settlement, dessen Calldata die Forced-TX enthält → Discharge
        let calldata = encode_calldata(&[L2Input { from, to, amount: 100, fee: 5, nonce: 0 }]);
        let s = mk_settlement_da(pre, calldata, Vec::new());
        let q2 = ChainManager::apply_forced_rules(&q, &[s], &[], 16, 5)
            .expect("Inclusion-Discharge muss gelten");
        assert!(q2.is_empty(), "Eintrag muss erledigt sein");
    }

    /// Enforcement: fälliger Eintrag + Settlement ohne Bedienung → Block ungültig;
    /// vor Fälligkeit → erlaubt; Block ohne Settlements → erlaubt (Queue wächst nur).
    #[test]
    fn test_forced_due_enforcement() {
        let (l2, _from, _to, _idx, ftx) = forced_fixture();
        let pre = l2.root_bytes();
        let q = ChainManager::apply_forced_rules(&[], &[], &[ftx], 10, 5).unwrap();

        // Höhe 16 > 10+5 → fällig. Settlement ohne Inclusion/Rejection → Fehler.
        let s_empty = mk_settlement_da(pre, Vec::new(), Vec::new());
        assert!(ChainManager::apply_forced_rules(&q, &[s_empty.clone()], &[], 16, 5).is_err());

        // Höhe 12 ≤ 10+5 → noch nicht fällig → ok, Eintrag bleibt offen.
        let q2 = ChainManager::apply_forced_rules(&q, &[s_empty], &[], 12, 5).unwrap();
        assert_eq!(q2.len(), 1);

        // Block ganz ohne Settlements: kein Enforcement (Aggregator-Existenz
        // ist nicht erzwingbar) — Queue bleibt.
        let q3 = ChainManager::apply_forced_rules(&q, &[], &[], 99, 5).unwrap();
        assert_eq!(q3.len(), 1);
    }

    /// Rejection: nicht anwendbare Forced-TX (falsche Nonce) wird per nativ
    /// verifiziertem Zeugen abgelehnt; eine GÜLTIGE TX kann NICHT abgelehnt
    /// werden (Zensur-Schutz); manipulierte Zeugen scheitern.
    #[test]
    fn test_forced_rejection_witness() {
        use atlas_core::transaction::ForcedRejection;
        use atlas_zk::eddsa::EddsaKeypair;
        use atlas_zk::l2_state::build_l2_eddsa;
        let (l2, from, to, idx, ftx_valid) = forced_fixture();
        let pre = l2.root_bytes();

        // Forced-TX mit Nonce 1 (Konto steht auf Nonce 0) → nicht anwendbar.
        let kp = EddsaKeypair::from_seed(0xF0CE_D001);
        let (_, pubkey, sig) = build_l2_eddsa(&kp, &to, 100, 5, 1);
        let ftx_stale = atlas_core::transaction::Transaction::new_l2_forced_tx(
            from, to, 100, 5, 1, pubkey, sig.to_vec(), idx,
        );
        let q = ChainManager::apply_forced_rules(&[], &[], &[ftx_stale], 10, 5).unwrap();

        let w = l2.rejection_witness(idx);
        let rej = ForcedRejection {
            from, nonce: 1,
            leaf_address: w.leaf_address, leaf_balance: w.leaf_balance,
            leaf_nonce: w.leaf_nonce, leaf_vacant: w.leaf_vacant,
            siblings: w.siblings.clone(),
        };

        // Gültiger Zeuge → Discharge.
        let s = mk_settlement_da(pre, Vec::new(), vec![rej.clone()]);
        let q2 = ChainManager::apply_forced_rules(&q, &[s], &[], 16, 5)
            .expect("Rejection-Discharge muss gelten");
        assert!(q2.is_empty());

        // Zensur-Versuch: dieselbe Witness-Technik gegen die GÜLTIGE TX (nonce 0)
        // → verify_forced_rejection schlägt fehl → Block ungültig.
        let q_valid = ChainManager::apply_forced_rules(&[], &[], &[ftx_valid], 10, 5).unwrap();
        let rej_censor = ForcedRejection { nonce: 0, ..rej.clone() };
        let s_censor = mk_settlement_da(pre, Vec::new(), vec![rej_censor]);
        assert!(ChainManager::apply_forced_rules(&q_valid, &[s_censor], &[], 16, 5).is_err(),
            "gültige Forced-TX darf NICHT ablehnbar sein");

        // Manipulierter Zeuge (falscher Saldo) → Pfad hasht nicht zum pre_root.
        let mut rej_bad = rej;
        rej_bad.leaf_balance = 0;
        let q3 = ChainManager::apply_forced_rules(
            &[], &[],
            &[{
                let (_, pk2, sg2) = build_l2_eddsa(&kp, &to, 100, 5, 1);
                atlas_core::transaction::Transaction::new_l2_forced_tx(
                    from, to, 100, 5, 1, pk2, sg2.to_vec(), idx)
            }], 10, 5,
        ).unwrap();
        let s_bad = mk_settlement_da(pre, Vec::new(), vec![rej_bad]);
        assert!(ChainManager::apply_forced_rules(&q3, &[s_bad], &[], 16, 5).is_err(),
            "manipulierter Zeuge muss scheitern");
    }

    /// Same-Block-Regel: eine Forced-TX, die ein Settlement DESSELBEN Blocks
    /// bereits enthält, wird gar nicht erst eingereiht.
    #[test]
    fn test_forced_same_block_inclusion() {
        use atlas_zk::l2_state::{encode_calldata, L2Input};
        let (l2, from, to, _idx, ftx) = forced_fixture();
        let pre = l2.root_bytes();
        let calldata = encode_calldata(&[L2Input { from, to, amount: 100, fee: 5, nonce: 0 }]);
        let s = mk_settlement_da(pre, calldata, Vec::new());
        let q = ChainManager::apply_forced_rules(&[], &[s], &[ftx], 10, 5).unwrap();
        assert!(q.is_empty(), "im selben Block erfüllte Forced-TX wird nicht eingereiht");
    }

    /// Vacant-Slot-Rejection: Forced-TX mit `sender_index`, an dem KEIN Konto
    /// liegt (User-Fehler/Garbage) → Zeuge mit leerem Blatt erlaubt Discharge.
    #[test]
    fn test_forced_rejection_vacant_slot() {
        use atlas_core::transaction::ForcedRejection;
        use atlas_zk::eddsa::EddsaKeypair;
        use atlas_zk::l2_state::build_l2_eddsa;
        let (l2, from, to, _idx, _ftx) = forced_fixture();
        let pre = l2.root_bytes();

        // Gültig signierte TX, aber sender_index zeigt auf leeren Slot 99.
        let kp = EddsaKeypair::from_seed(0xF0CE_D001);
        let (_, pubkey, sig) = build_l2_eddsa(&kp, &to, 100, 5, 0);
        let ftx_wrong_idx = atlas_core::transaction::Transaction::new_l2_forced_tx(
            from, to, 100, 5, 0, pubkey, sig.to_vec(), 99,
        );
        let q = ChainManager::apply_forced_rules(&[], &[], &[ftx_wrong_idx], 10, 5).unwrap();

        let w = l2.rejection_witness(99);
        assert!(w.leaf_vacant, "Slot 99 muss leer sein");
        let rej = ForcedRejection {
            from, nonce: 0,
            leaf_address: w.leaf_address, leaf_balance: w.leaf_balance,
            leaf_nonce: w.leaf_nonce, leaf_vacant: w.leaf_vacant,
            siblings: w.siblings,
        };
        let s = mk_settlement_da(pre, Vec::new(), vec![rej]);
        let q2 = ChainManager::apply_forced_rules(&q, &[s], &[], 16, 5)
            .expect("Vacant-Rejection muss gelten");
        assert!(q2.is_empty());
    }

    /// DA-Bindung (adversarial): Calldata, die nicht zum batch_commitment
    /// hasht, MUSS abgelehnt werden; passende Calldata MUSS akzeptiert werden;
    /// überlange Calldata (> Batch-Kapazität) MUSS abgelehnt werden.
    #[test]
    fn test_da_binding_adversarial() {
        use atlas_zk::l2_state::{batch_commitment_from_inputs, encode_calldata, L2Input};
        let tx = L2Input { from: [1u8; 20], to: [2u8; 20], amount: 7, fee: 1, nonce: 0 };
        let calldata = encode_calldata(&[tx]);
        let commitment = batch_commitment_from_inputs(&[tx], atlas_zk::L2_BATCH_SIZE);

        // Korrekt gebunden → Ok.
        let mut s = mk_settlement([0u8; 32], [0u8; 32], 1, 0);
        s.calldata = calldata.clone();
        s.batch_commitment = commitment;
        assert!(ChainManager::verify_data_availability(&s).is_ok());

        // Manipulierte Calldata (1 Byte geflippt) → Commitment-Mismatch.
        let mut s_tampered = s.clone();
        s_tampered.calldata[0] ^= 0x01;
        assert!(ChainManager::verify_data_availability(&s_tampered).is_err(),
            "manipulierte Calldata muss an der DA-Bindung scheitern");

        // Weggelassene Calldata → Mismatch (kein „leeres DA"-Schlupfloch).
        let mut s_empty = s.clone();
        s_empty.calldata = Vec::new();
        assert!(ChainManager::verify_data_availability(&s_empty).is_err(),
            "leere Calldata darf ein nicht-leeres Commitment nicht erfüllen");

        // Überlange Calldata (Kapazität+1 TXs) → abgelehnt.
        let many: Vec<L2Input> = (0..=atlas_zk::L2_BATCH_SIZE as u64)
            .map(|i| L2Input { from: [1u8; 20], to: [2u8; 20], amount: 1, fee: 1, nonce: i })
            .collect();
        let mut s_over = s.clone();
        s_over.calldata = encode_calldata(&many);
        assert!(ChainManager::verify_data_availability(&s_over).is_err(),
            "Calldata über Batch-Kapazität muss scheitern");
    }

    /// End-to-End mit ECHTEM Groth16-State-Transition-Beweis (test_mode = false).
    /// Benötigt `keys/state_pk.bin` (~122 MB) — daher `#[ignore]`; auf dem
    /// Aggregator-Host via `cargo test ... -- --ignored` ausführen.
    /// Beweist: nativer Batch-Executor → prove_state → verify_state_bid akzeptiert,
    /// Manipulation der Public Inputs wird abgelehnt.
    #[test]
    #[ignore]
    fn test_e2e_state_transition_real_groth16() {
        use atlas_zk::account::{Account, AccountTree};
        use atlas_zk::eddsa::EddsaKeypair;
        use atlas_zk::transition::{apply_batch, L2Tx};

        let pk_path = concat!(env!("CARGO_MANIFEST_DIR"), "/../atlas-zk/keys/state_pk.bin");
        let prover = atlas_zk::ZkBatchProver::from_state_file(pk_path)
            .expect("state PK must be present on aggregator host");

        // Konto-Baum mit zwei finanzierten Konten (an echte Pubkeys gebunden).
        let alice_kp = EddsaKeypair::from_seed(1001);
        let bob = EddsaKeypair::from_seed(2002).public().address_fr();
        let mut tree = AccountTree::new();
        tree.register(Account::new(alice_kp.public().address_fr(), 1_000_000, 0));
        tree.register(Account::new(bob, 500_000, 0));
        let pre_root = atlas_zk::fr_to_bytes32(tree.root());

        // Ein Batch mit einer Transfer-TX.
        let txs = vec![L2Tx::signed(bob, 10_000, 100, 0, &alice_kp)];
        let bw  = apply_batch(&mut tree, &txs).expect("native batch must apply");

        // Echter Groth16-Beweis.
        let (proof, post_root, commitment) = prover.prove_state(&bw)
            .expect("state proof generation must succeed");
        let total_fees: u128 = 100;

        // Verifier akzeptiert die korrekten Public Inputs.
        let _ = crate::zk_stub::init_zk_verifier();
        let zk = ZkVerifier::new(false);
        zk.verify_state_bid(&proof, &pre_root, &post_root, total_fees, &commitment)
            .expect("gültiger State-Beweis muss verifizieren");

        // Soundness: manipulierte post_root → Ablehnung.
        let mut bad_post = post_root;
        bad_post[0] ^= 0xff;
        assert!(zk.verify_state_bid(&proof, &pre_root, &bad_post, total_fees, &commitment).is_err());
        // Manipulierte Fees → Ablehnung.
        assert!(zk.verify_state_bid(&proof, &pre_root, &post_root, total_fees + 1, &commitment).is_err());

        // Soundness (Autorisierung): Aus einer gefälschten Signatur lässt sich
        // KEIN gültiger Beweis ableiten. Wir nehmen den gültigen Batch-Witness,
        // verfälschen den EdDSA-Skalar S der ersten TX (Balancen/Wurzeln/Public
        // Inputs bleiben identisch) und erwarten, dass entweder die Beweis-
        // Erzeugung fehlschlägt ODER der entstehende Beweis NICHT verifiziert —
        // der In-Circuit-Check `S·B == R + c·A` ist verletzt. (Groth16 erzeugt
        // bei unerfüllten Constraints einen Beweis, der nur nicht verifiziert.)
        let mut forged = bw.clone();
        forged.txs[0].sig.s += ark_ed_on_bn254::Fr::from(1u64);
        match prover.prove_state(&forged) {
            Err(_) => { /* Fälschung bereits beim Proving abgelehnt */ }
            Ok((bad_proof, bad_root, bad_commit)) => {
                assert!(
                    zk.verify_state_bid(
                        &bad_proof, &pre_root, &bad_root, total_fees, &bad_commit
                    ).is_err(),
                    "Beweis aus gefälschter EdDSA-Signatur darf nicht verifizieren"
                );
            }
        }

        eprintln!("E2E state-transition ok: proof = {} Bytes, soundness-tragend (inkl. Signaturfälschung abgelehnt)", proof.len());
    }
}
