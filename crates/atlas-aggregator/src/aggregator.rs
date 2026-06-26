//! Aggregator-Kern: verwaltet Pending-Pool, koordiniert Batch-Submission
//!
//! Ablauf:
//!   1. L2-TX eintreffen → validate → pending pool
//!   2. Batch voll ODER Timeout → BatchBuilder::take()
//!   3. Proof generieren (ZK)
//!   4. Batch beim Node einreichen (submitbatch RPC)
//!   5. Status verwalten

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use atlas_core::crypto::Address;
use atlas_core::hash::Hash;
use atlas_zk::l2_state::{GenesisAlloc, L2Input, L2State, SignedL2Input};
use atlas_zk::transition::BatchWitness;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
use tracing::{error, info, warn};

use crate::batch::{Batch, BatchBuilder};
use crate::config::AggregatorConfig;
use crate::l2_tx::{L2Transaction, L2TxError};
use crate::node_client::{ForcedEntryInfo, ForcedRejectionInfo, L2BlockData, NodeClient};
use crate::prover::AggregatorProver;

/// Lädt einen persistierten L2-Snapshot `(node_height, L2State)` von Disk.
/// `None` bei fehlender/defekter/versionsfremder Datei → Aufrufer macht Full-Replay.
/// Datei-Layout: `height(u64 LE) ++ L2State::to_snapshot_bytes()`.
fn load_l2_snapshot(path: &str) -> Option<(u64, L2State)> {
    let bytes = std::fs::read(path).ok()?;
    if bytes.len() < 8 {
        return None;
    }
    let height = u64::from_le_bytes(bytes[0..8].try_into().ok()?);
    let state = L2State::from_snapshot_bytes(&bytes[8..])?;
    Some((height, state))
}

/// Modell A (gebündelt): einen Block auf den L2-Zustand anwenden — exakt wie der
/// Node in `apply_block`. Ein **leerer** Block (keine Calldata) lässt die Root
/// UNVERÄNDERT und staut nur seine Coinbase-Credits in `pending` auf. Ein
/// **Settlement**-Block wendet erst die Transfers an, dann die aufgelaufenen
/// `pending`-Credits PLUS die eigenen (Credits sind additiv → Reihenfolge egal).
fn apply_l2_block(
    state: &mut L2State,
    b: &L2BlockData,
    pending: &mut Vec<([u8; 20], u128)>,
) -> Result<(), String> {
    if !b.has_settlement {
        // Leerer Block: Root unverändert, Credits aufstauen.
        pending.extend(b.credits.iter().copied());
        return Ok(());
    }
    // Settlement-Block: Transfers (Calldata kann leer sein → Heartbeat), dann die
    // aufgelaufenen `pending`-Credits PLUS die eigenen (Credits sind additiv).
    if !b.calldata.is_empty() {
        let inputs = atlas_zk::l2_state::decode_calldata(&b.calldata)
            .map_err(|e| format!("calldata decode (Block {}): {e}", b.height))?;
        state.apply_calldata(&inputs)
            .map_err(|e| format!("calldata apply (Block {}): {e:?}", b.height))?;
    }
    for (addr, amt) in pending.drain(..) {
        if amt > 0 { state.credit(&addr, amt); }
    }
    for (addr, amt) in &b.credits {
        if *amt > 0 { state.credit(addr, *amt); }
    }
    Ok(())
}

/// Maximale Anzahl gleichzeitiger State-Proofs/submitbatch-Calls.
///
/// State-Transition-Beweise sind verkettet (jeder Batch baut auf der `post_root`
/// des vorigen auf). Strikt serielle Einreichung (=1) vermeidet Lücken in der
/// L2-State-Root-Kette, falls ein Beweis/Submit fehlschlägt.
const MAX_CONCURRENT_SUBMISSIONS: usize = 1;

/// Kryptographische EdDSA-Prüfung einer L2-TX (Signatur + Adressbindung).
///
/// `atlas-core` kann das nicht — Poseidon/Baby-Jubjub leben in `atlas-zk`.
/// Diese Funktion ist der EINZIGE Ort, an dem der Aggregator die
/// Sender-Autorisierung nativ prüft, bevor eine TX in einen Batch gelangt.
fn verify_tx_crypto(tx: &L2Transaction) -> bool {
    atlas_zk::l2_state::verify_l2_eddsa(
        &tx.from.0,
        &tx.to.0,
        tx.amount,
        tx.fee,
        tx.nonce,
        &tx.auth.pubkey,
        tx.auth.signature.as_bytes(),
    )
}

/// Klassifiziert die Forced-Inclusion-Queue gegen den aktuellen L2-State:
/// in Sequenz anwendbare Einträge werden (in Queue-Reihenfolge, älteste zuerst)
/// als Batch-TXs übernommen; gegen `pre_root` nachweislich nicht anwendbare
/// erhalten einen Rejection-Zeugen. Einträge, die nur wegen vorhergehender
/// Forced-TXs desselben Batches (noch) nicht passen, werden auf den nächsten
/// Batch verschoben (weder Inclusion noch Rejection).
fn classify_forced(
    l2:       &L2State,
    entries:  &[ForcedEntryInfo],
    max_take: usize,
) -> (Vec<L2Transaction>, Vec<ForcedRejectionInfo>) {
    let mut txs:  Vec<L2Transaction>      = Vec::new();
    let mut rejs: Vec<ForcedRejectionInfo> = Vec::new();
    // Sequenz-Simulation: Salden/Nonces inkl. Wirkung bereits übernommener TXs.
    let mut bal: HashMap<[u8; 20], u128> = HashMap::new();
    let mut non: HashMap<[u8; 20], u64>  = HashMap::new();

    for e in entries {
        if txs.len() >= max_take {
            break; // Kapazität erschöpft — Rest im nächsten Batch
        }
        let b = *bal.entry(e.from).or_insert_with(|| l2.balance(&e.from));
        let n = *non.entry(e.from).or_insert_with(|| l2.nonce(&e.from));
        let debit = e.amount_atom.saturating_add(e.fee_atom);

        if n == e.nonce && b >= debit {
            txs.push(L2Transaction::from_parts(
                Address(e.from), Address(e.to),
                e.amount_atom, e.fee_atom, e.nonce, e.pubkey, e.sig,
            ));
            bal.insert(e.from, b - debit);
            non.insert(e.from, n + 1);
            let rb = bal.entry(e.to).or_insert_with(|| l2.balance(&e.to));
            *rb = rb.saturating_add(e.amount_atom);
        } else {
            // Nur ablehnen, wenn die TX auch gegen den ECHTEN pre_root ungültig
            // ist (der Node verifiziert den Zeugen genau dagegen).
            let invalid_vs_pre = match l2.index_of(&e.from) {
                None                                => true, // Konto existiert nicht
                Some(i) if i != e.sender_index      => true, // falscher Index angegeben
                Some(_) => l2.nonce(&e.from) != e.nonce
                        || l2.balance(&e.from) < debit,
            };
            if invalid_vs_pre {
                let w = l2.rejection_witness(e.sender_index);
                rejs.push(ForcedRejectionInfo {
                    from:         e.from,
                    nonce:        e.nonce,
                    leaf_address: w.leaf_address,
                    leaf_balance: w.leaf_balance,
                    leaf_nonce:   w.leaf_nonce,
                    leaf_vacant:  w.leaf_vacant,
                    siblings:     w.siblings,
                });
            }
            // sonst: gegen pre_root gültig, in Sequenz (noch) nicht → später.
        }
    }
    (txs, rejs)
}

/// Wandelt eine validierte L2-TX in den Witness-Input für `L2State::apply` um.
fn to_signed_input(tx: &L2Transaction) -> SignedL2Input {
    SignedL2Input {
        input: L2Input {
            from:   tx.from.0,
            to:     tx.to.0,
            amount: tx.amount,
            fee:    tx.fee,
            nonce:  tx.nonce,
        },
        pubkey: tx.auth.pubkey,
        sig:    *tx.auth.signature.as_bytes(),
    }
}

// ── Batch-Status ─────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum BatchStatus {
    /// Batch eingesammelt, ZK-Proof wird generiert
    Proving,
    /// Beim Node eingereicht
    Submitted { txid: String },
    /// Fehlgeschlagen
    Failed { reason: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchRecord {
    pub batch_id:   String,
    pub tx_count:   u32,
    pub total_fees: u128,
    pub status:     BatchStatus,
    pub submitted_at: u64,
}

// ── Aggregator-State (thread-safe) ────────────────────────────────────────────

struct AggregatorState {
    builder:   BatchBuilder,
    batches:   HashMap<String, BatchRecord>,
    last_flush: Instant,
    stats:     AggregatorStats,
    /// Modell A: der BESTÄTIGTE L2-Zustand des Nodes (Settlements + Coinbase-
    /// Gutschriften). Wird AUSSCHLIESSLICH vom Follower fortgeschrieben (nicht
    /// mehr optimistisch beim Flush) — `root_bytes()` ist die `pre_root` für den
    /// nächsten Batch und entspricht exakt der Node-Tip-Root.
    l2:        L2State,
    /// Höhe, bis zu der `l2` den Node nachvollzogen hat (Follower-Anker).
    applied_height: u64,
    /// `pre_root` des zuletzt geflushten Batches — Gate gegen das Bauen mehrerer
    /// Batches gegen dieselbe (noch unbestätigte) Root.
    last_flush_root: Option<[u8; 32]>,
}

/// Mindest-Wartezeit für einen erneuten Flush gegen UNVERÄNDERTE Root (Retry,
/// falls ein Batch verworfen wurde und die Root nicht vorrückt).
const FLUSH_RETRY_SECS: u64 = 30;

/// Modell A: Ab wie vielen aufgelaufenen Blöcken (Emission seit dem letzten
/// Settlement) der Heartbeat ein leeres Settlement zum Ausschütten einreicht.
const HEARTBEAT_BLOCKS: u64 = 3;

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct AggregatorStats {
    pub txs_received:      u64,
    pub txs_rejected:      u64,
    pub batches_submitted: u64,
    pub batches_failed:    u64,
}

pub struct Aggregator {
    config:    AggregatorConfig,
    state:     Arc<Mutex<AggregatorState>>,
    node:      Arc<NodeClient>,
    prover:    Arc<AggregatorProver>,
    agg_addr:  Address,
    /// Begrenzt parallele submitbatch-Calls an den Node
    submit_sem: Arc<Semaphore>,
}

impl Aggregator {
    pub fn new(config: AggregatorConfig, prover: AggregatorProver) -> anyhow::Result<Self> {
        let agg_addr = Address::from_hex(&config.aggregator_address)
            .map_err(|e| anyhow::anyhow!("Invalid aggregator_address: {}", e))?;

        let node = Arc::new(NodeClient::new(
            config.node_rpc_addr.clone(),
            config.node_api_key.clone(),
        ));

        // Circuit ist auf L2_BATCH_SIZE fixiert — größere Batches kann der Beweis
        // nicht abdecken. Hart deckeln.
        let max_batch = config.max_batch_size.min(atlas_zk::L2_BATCH_SIZE);
        if config.max_batch_size > atlas_zk::L2_BATCH_SIZE {
            warn!(
                "max_batch_size {} > Circuit-Kapazität {} — gedeckelt auf {}",
                config.max_batch_size, atlas_zk::L2_BATCH_SIZE, max_batch
            );
        }

        // L2-Genesis-Förderung — MUSS mit der Node-Genesis übereinstimmen.
        // Ohne explizite Config-Allokation: kanonische Dev-/Testnet-Allokation
        // (atlas_zk::genesis_allocation) → Root == atlas-core GENESIS_L2_ROOT.
        let allocs = if config.genesis_alloc.is_empty() {
            atlas_zk::genesis_allocation()
        } else {
            parse_genesis_allocs(&config)?
        };
        let l2 = L2State::from_genesis(&allocs);
        info!(
            "L2-Genesis: {} vorab-geförderte Konten, Genesis-Root={}",
            allocs.len(), hex::encode(l2.root_bytes())
        );

        let state = Arc::new(Mutex::new(AggregatorState {
            builder:    BatchBuilder::new(max_batch),
            batches:    HashMap::new(),
            last_flush: Instant::now(),
            stats:      AggregatorStats::default(),
            l2,
            applied_height:  0,
            last_flush_root: None,
        }));

        Ok(Aggregator {
            config,
            state,
            node,
            prover: Arc::new(prover),
            agg_addr,
            submit_sem: Arc::new(Semaphore::new(MAX_CONCURRENT_SUBMISSIONS)),
        })
    }

    /// Rekonstruiert den L2-Zustand beim Start — macht den Aggregator REBOOT-FEST.
    /// Ohne diesen Schritt startet er stets auf Genesis, während der Node weit
    /// voraus ist; dann prallt jeder Bid am `pre_root`-Check ab → Split-Brain.
    ///
    /// Zwei Wege: (1) persistierten L2-Snapshot laden und nur das kleine Delta
    /// seit der Snapshot-Höhe aus der Calldata nachspielen (SEKUNDEN); (2) als
    /// Fallback ein Full-Replay ab Genesis (langsam, O(TX-Historie)). In beiden
    /// Fällen MUSS die rekonstruierte Root exakt der Node-Root entsprechen.
    pub async fn resync_l2(&self) -> anyhow::Result<()> {
        // Reiner Genesis-Zustand (in `new()` gebaut, noch nichts angewandt).
        let genesis_state = self.state.lock().l2.clone();
        let path = self.config.l2_snapshot_path.clone();

        // (1) Schnellweg: Snapshot + Delta.
        if !path.is_empty() {
            if let Some((snap_height, snap_state)) = load_l2_snapshot(&path) {
                match self.resync_onto(snap_state, snap_height).await {
                    Ok(tip) => {
                        info!("L2-Resync via Snapshot OK: Höhe {snap_height} → {tip} (nur Delta).");
                        let _ = self.persist_l2_snapshot().await;
                        return Ok(());
                    }
                    Err(e) => warn!("Snapshot-Resync verworfen ({e}) — Full-Replay aus Calldata."),
                }
            }
        }

        // (2) Fallback: Full-Replay ab Genesis.
        let tip = self.resync_onto(genesis_state, 0).await?;
        info!("L2-Resync via Full-Replay OK bis Höhe {tip}.");
        let _ = self.persist_l2_snapshot().await;
        Ok(())
    }

    /// Spielt die Delta-Calldata ab `base_height` auf `base_state` und übernimmt
    /// den Zustand NUR, wenn die resultierende Root == Node-Tip-Root ist.
    /// Gibt die Tip-Höhe zurück. Modifiziert `self.state.l2` erst bei Erfolg.
    async fn resync_onto(&self, mut base_state: L2State, base_height: u64) -> anyhow::Result<u64> {
        let (height, target_root, blocks) = self.node.get_l2_snapshot(base_height).await?;
        let mut pending: Vec<([u8; 20], u128)> = Vec::new();
        let mut new_applied = base_height;
        for b in &blocks {
            apply_l2_block(&mut base_state, b, &mut pending)
                .map_err(|e| anyhow::anyhow!("Replay Block {} (ab {base_height}): {e}", b.height))?;
            if b.has_settlement { new_applied = b.height; }
        }
        let local = base_state.root_bytes();
        if local != target_root {
            anyhow::bail!(
                "Root {} != Node-Root {} (Höhe {}, {} Blöcke)",
                hex::encode(local), hex::encode(target_root), height, blocks.len()
            );
        }
        {
            let mut s = self.state.lock();
            s.l2 = base_state;
            // applied_height = letzter Settlement-Block (leere Blöcke danach
            // werden nächste Runde re-akkumuliert → restart-sicher).
            s.applied_height = new_applied;
        }
        Ok(height)
    }

    /// Modell A — Live-Follower: verfolgt die Chain blockweise und schreibt den
    /// bestätigten L2-Zustand fort (Settlements + Coinbase-Gutschriften), sodass
    /// die Aggregator-Root stets der Node-Tip-Root entspricht. EINZIGER Mutator
    /// von `state.l2` im Betrieb. Läuft als Hintergrund-Task.
    pub async fn follow_chain(&self) {
        // Zähler für ANHALTENDE Divergenz (Block nicht anwendbar / Root-Mismatch).
        // Tritt v.a. bei einem Reorg unterhalb von `applied_height` auf (Multi-Node):
        // dann ist der Aggregator-Zustand auf einem verworfenen Fork. Heilung: nach
        // wenigen Fehlversuchen ein voller Resync (Snapshot scheitert → Full-Replay
        // ab Genesis auf dem neuen Fork).
        let mut diverged: u32 = 0;
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
            let from = self.state.lock().applied_height;
            let (tip, tip_root, blocks) = match self.node.get_l2_snapshot(from).await {
                Ok(v) => v,
                Err(e) => { warn!("Follower: getl2snapshot fehlgeschlagen: {e}"); continue; } // Netz, kein Divergenz-Signal
            };
            if blocks.is_empty() { diverged = 0; continue; }
            // Auf einer Kopie anwenden (all-or-nothing), dann übernehmen.
            let mut trial = self.state.lock().l2.clone();
            let mut pending: Vec<([u8; 20], u128)> = Vec::new();
            let mut new_applied = from;
            let mut ok = true;
            for b in &blocks {
                if let Err(e) = apply_l2_block(&mut trial, b, &mut pending) {
                    warn!("Follower: Block {} nicht anwendbar: {e}", b.height);
                    ok = false;
                    break;
                }
                if b.has_settlement { new_applied = b.height; }
            }
            // `trial` steht nach dem letzten Settlement (nachfolgende leere Blöcke
            // stauen nur `pending` auf) — das muss exakt die Node-Tip-Root sein.
            if !ok || trial.root_bytes() != tip_root {
                diverged += 1;
                warn!("Follower: Divergenz (#{diverged}) bei Höhe {tip} — Reorg? retry/Resync.");
                if diverged >= 3 {
                    warn!("Follower: anhaltende Divergenz → voller L2-Resync (Reorg-Selbstheilung).");
                    if let Err(e) = self.resync_l2().await {
                        warn!("Follower: Resync fehlgeschlagen: {e}");
                    } else {
                        diverged = 0;
                    }
                }
                continue;
            }
            diverged = 0;
            {
                let mut s = self.state.lock();
                s.l2 = trial;
                s.applied_height = new_applied;
            }
        }
    }

    /// Schreibt den L2-Zustand + zugehörige Node-Höhe atomar auf Disk — aber nur,
    /// wenn die eigene Root == Node-Root ist (sonst ist die Höhen-Verankerung
    /// nicht gültig, z.B. weil noch ungesettelte Batches ausstehen). Datei:
    /// `height(u64 LE) ++ L2State-Snapshot`.
    pub async fn persist_l2_snapshot(&self) -> anyhow::Result<()> {
        let path = self.config.l2_snapshot_path.clone();
        if path.is_empty() {
            return Ok(());
        }
        // Modell A: `state.l2` IST der bestätigte Node-Zustand bei `applied_height`
        // (der Follower hält ihn synchron). Also direkt mit dieser Höhe persistieren
        // — kein Puffer-Matching mehr nötig.
        let (height, bytes) = {
            let state = self.state.lock();
            (state.applied_height, state.l2.to_snapshot_bytes())
        };
        let mut buf = Vec::with_capacity(8 + bytes.len());
        buf.extend_from_slice(&height.to_le_bytes());
        buf.extend_from_slice(&bytes);
        let tmp = format!("{path}.tmp");
        std::fs::write(&tmp, &buf)?;
        std::fs::rename(&tmp, &path)?; // atomar
        Ok(())
    }

    /// L2-TX einreichen — gibt TX-Hash zurück oder Fehler
    pub async fn submit_tx(&self, tx: L2Transaction) -> Result<Hash, L2TxError> {
        // Strukturelle + kryptographische Validierung (EdDSA)
        tx.validate()?;
        if !verify_tx_crypto(&tx) {
            return Err(L2TxError::InvalidSignature);
        }

        let tx_hash = tx.hash();
        let should_flush = {
            let mut state = self.state.lock();
            state.stats.txs_received += 1;
            state.builder.push(tx)
        };

        if should_flush {
            self.flush_batch().await;
        }

        Ok(tx_hash)
    }

    /// Mehrere L2-TXs auf einmal einreichen (high-throughput path)
    ///
    /// Signatur-Verifikation läuft OHNE Lock (parallelisierbar).
    /// Nur die Insertion in den BatchBuilder hält kurz den Mutex.
    /// Gibt (accepted, rejected) zurück.
    pub async fn submit_batch_txs(&self, txs: Vec<L2Transaction>) -> (usize, usize) {
        // Phase 1: Validierung (ECDSA-Verify) komplett lock-frei
        // tokio::task::spawn_blocking damit der Event-Loop nicht blockiert
        let validated: Vec<(L2Transaction, bool)> =
            tokio::task::spawn_blocking(move || {
                txs.into_iter()
                    .map(|tx| {
                        let ok = tx.validate().is_ok() && verify_tx_crypto(&tx);
                        (tx, ok)
                    })
                    .collect()
            })
            .await
            .unwrap_or_default();

        // Phase 2: Nur valide TXs in den BatchBuilder — kurzer Lock
        let mut accepted = 0usize;
        let mut rejected = 0usize;
        let mut flush_needed = false;

        {
            let mut state = self.state.lock();
            for (tx, ok) in validated {
                if !ok {
                    rejected += 1;
                    state.stats.txs_rejected += 1;
                    continue;
                }
                state.stats.txs_received += 1;
                accepted += 1;
                if state.builder.push(tx) {
                    flush_needed = true;
                }
            }
        }

        if flush_needed {
            self.flush_batch().await;
        }

        (accepted, rejected)
    }

    /// Batch zwangsweise einreichen (bei Timeout oder Batch-Voll).
    ///
    /// Konsens-Pflicht: offene Forced-Inclusion-TXs (on-chain Queue) werden
    /// VOR den User-TXs aufgenommen; nicht anwendbare werden per Rejection-
    /// Zeuge nachweislich abgelehnt. Sonst würde der Node Settlements mit
    /// fälligen, unbedienten Einträgen ablehnen.
    pub async fn flush_batch(&self) {
        self.flush_inner(false).await
    }

    /// Modell A — Heartbeat: reicht ein LEERES Settlement (0 Transfers) ein, um
    /// die aufgelaufene Coinbase-Emission auszuschütten. Nötig für den Fair Launch
    /// (kein Premine): ohne ein Settlement käme die Emission nie in ein ausgebbares
    /// Konto. Nur wenn Emission ansteht (Node-Tip > applied_height) und der Builder
    /// leer ist (sonst erledigt es ein normaler Flush).
    pub async fn maybe_heartbeat(&self) {
        // Steht Emission an? (Node hat seit dem letzten Settlement Blöcke gemined.)
        let applied = self.state.lock().applied_height;
        let tip = match self.node.get_l2_snapshot(u64::MAX).await {
            Ok((h, _, _)) => h,
            Err(_) => return,
        };
        let has_user_txs = self.state.lock().builder.len() > 0;
        if tip > applied + HEARTBEAT_BLOCKS && !has_user_txs {
            info!("Heartbeat: {} Blöcke aufgelaufene Emission seit Settlement {} — leeres Settlement zum Ausschütten.",
                tip - applied, applied);
            self.flush_inner(true).await;
        }
    }

    async fn flush_inner(&self, allow_empty: bool) {
        // Modell A Gate: keinen neuen Batch gegen dieselbe (noch unbestätigte)
        // Root bauen. Der Follower rückt `state.l2` vor, sobald der vorige Batch
        // gemined ist; erst dann — oder nach `FLUSH_RETRY_SECS` (Retry bei Verwurf)
        // — wird wieder geflusht. Verhindert Stapel rejecteter Batches, weil die
        // L2-Root unter Modell A pro Block (Coinbase) vorrückt.
        {
            let state = self.state.lock();
            let cur = state.l2.root_bytes();
            if state.last_flush_root == Some(cur)
                && state.last_flush.elapsed().as_secs() < FLUSH_RETRY_SECS
            {
                return;
            }
        }

        let forced_entries = match self.node.get_forced_queue().await {
            Ok(v) => v,
            Err(e) => {
                warn!("getforcedqueue fehlgeschlagen ({}) — flushe ohne Forced-Daten", e);
                Vec::new()
            }
        };

        let max_bs = self.config.max_batch_size;
        let work = {
            let mut state = self.state.lock();
            state.last_flush = Instant::now();

            // Forced-Einträge gegen den aktuellen L2-State klassifizieren.
            let (forced_txs, rejections) = classify_forced(&state.l2, &forced_entries, max_bs);
            if !forced_txs.is_empty() || !rejections.is_empty() {
                info!("Forced Inclusion: {} TX(s) aufgenommen, {} Rejection(s)",
                    forced_txs.len(), rejections.len());
            }

            // Kombinieren: Forced zuerst (Slot 0 garantiert bedienbar), dann
            // User-TXs bis zur Kapazität; Überhang zurück in den Builder.
            let user_txs: Vec<L2Transaction> = state.builder.take()
                .map(|b| b.transactions).unwrap_or_default();
            let mut combined = forced_txs;
            let mut leftover = Vec::new();
            for tx in user_txs {
                let dup = combined.iter().any(|f| f.from == tx.from && f.nonce == tx.nonce);
                if dup {
                    continue; // bereits als Forced-TX enthalten
                }
                if combined.len() < max_bs {
                    combined.push(tx);
                } else {
                    leftover.push(tx);
                }
            }
            for tx in leftover {
                state.builder.push(tx);
            }

            if combined.is_empty() && rejections.is_empty() && !allow_empty {
                None
            } else {
                let total_fees: u128 = combined.iter().map(|t| t.fee).sum();
                let batch = Batch {
                    batch_merkle: crate::batch::compute_batch_merkle(&combined),
                    transactions: combined,
                    total_fees,
                };
                Some((batch, rejections))
            }
        };

        let Some((batch, rejections)) = work else { return };

        info!(
            "Flushing batch: {} TXs, {} ATOM fees",
            batch.transactions.len(),
            batch.total_fees
        );

        let batch_id_hex = batch.batch_merkle.as_hex();

        // ── State-Übergang SYNCHRON anwenden (nativ, schnell) ────────────────
        // Unter dem Lock: pre_root lesen, Batch auf den L2-Baum anwenden, post_root
        // lesen. Damit ist die L2-State-Root-Kette deterministisch fortgeschrieben,
        // BEVOR der (langsame) Beweis erzeugt wird. Schlägt die native Anwendung
        // fehl (z.B. zu wenig Guthaben), wird der Batch verworfen.
        let signed_inputs: Vec<SignedL2Input> =
            batch.transactions.iter().map(to_signed_input).collect();
        let inputs: Vec<L2Input> =
            signed_inputs.iter().map(|s| s.input).collect();

        // On-Chain Data-Availability-Calldata für diesen Batch.
        let calldata = atlas_zk::l2_state::encode_calldata(&inputs);

        let (witness, pre_root, post_root) = {
            let mut state = self.state.lock();
            let pre_root = state.l2.root_bytes();
            // Modell A: auf einer KOPIE anwenden (nur für Witness + post_root). Der
            // bestätigte Zustand wird hier NICHT committet — der Follower übernimmt
            // den Block, sobald er gemined ist (inkl. Coinbase-Gutschrift). So
            // bleibt `state.l2` exakt die Node-Tip-Root.
            let mut trial = state.l2.clone();
            match trial.apply(&signed_inputs) {
                Ok(w) => {
                    let post_root = trial.root_bytes();
                    state.last_flush_root = Some(pre_root); // Gate gegen Doppel-Flush
                    state.batches.insert(batch_id_hex.clone(), BatchRecord {
                        batch_id:     batch_id_hex.clone(),
                        tx_count:     batch.transactions.len() as u32,
                        total_fees:   batch.total_fees,
                        status:       BatchStatus::Proving,
                        submitted_at: crate::now_secs(),
                    });
                    (w, pre_root, post_root)
                }
                Err(e) => {
                    state.stats.batches_failed += 1;
                    error!("L2-State-Übergang fehlgeschlagen, Batch verworfen: {}", e);
                    return;
                }
            }
        };

        // ZK-Proof + Node-Submission im Hintergrund (Semaphore serialisiert).
        let node    = self.node.clone();
        let prover  = self.prover.clone();
        let addr    = self.agg_addr;
        let state   = self.state.clone();
        let bid_amt = self.config.bid_amount_atom;
        let sem     = self.submit_sem.clone();

        tokio::spawn(async move {
            let _permit = sem.acquire_owned().await
                .expect("Semaphore should not be closed");
            Self::prove_and_submit(node, prover, addr, batch, witness, pre_root, post_root, calldata, rejections, state, bid_amt).await;
        });
    }

    #[allow(clippy::too_many_arguments)]
    async fn prove_and_submit(
        node:       Arc<NodeClient>,
        prover:     Arc<AggregatorProver>,
        agg_addr:   Address,
        batch:      Batch,
        witness:    BatchWitness,
        pre_root:   [u8; 32],
        post_root:  [u8; 32],
        calldata:   Vec<u8>,
        rejections: Vec<crate::node_client::ForcedRejectionInfo>,
        state:      Arc<Mutex<AggregatorState>>,
        bid_amt:    u128,
    ) {
        let batch_id_hex = batch.batch_merkle.as_hex();
        let tx_count     = batch.transactions.len() as u32;

        // State-Transition-Beweis generieren (langsam: echter Groth16 ~Sekunden).
        // CPU-gebunden → auf den Blocking-Pool, damit der Event-Loop frei bleibt.
        let proof_result = tokio::task::spawn_blocking({
            let prover       = prover.clone();
            let batch_merkle = batch.batch_merkle;
            move || prover.prove_state(&witness, post_root, &batch_merkle)
        }).await;

        let (proof_bytes, proof_post_root, batch_commitment) = match proof_result {
            Ok(Ok(r))   => r,
            Ok(Err(e))  => {
                error!("ZK state proof failed: {}", e);
                Self::set_failed(&state, &batch_id_hex, format!("ZK state proof failed: {}", e));
                return;
            }
            Err(e) => {
                error!("ZK prove task panicked: {}", e);
                Self::set_failed(&state, &batch_id_hex, "prove task panicked".into());
                return;
            }
        };
        debug_assert_eq!(proof_post_root, post_root);

        info!(
            "ZK state proof ready for batch {} ({} bytes), submitting...",
            &batch_id_hex[..16], proof_bytes.len()
        );

        // Beim Node einreichen. Der Bid-Betrag (bid_amt) ist ein separater
        // L1-Anreiz; die ZK-Public-Inputs sind pre/post-Root, total_fees und
        // batch_commitment (Poseidon, aus dem Beweis).
        let _ = bid_amt;
        match node.submit_batch(
            &batch.batch_merkle,
            &agg_addr,
            tx_count,
            &proof_bytes,
            &pre_root,
            &post_root,
            &batch_commitment,
            batch.total_fees,
            &calldata,
            &rejections,
        ).await {
            Ok(txid) => {
                info!("Batch {} submitted → txid {}", &batch_id_hex[..16], &txid[..txid.len().min(16)]);
                let mut s = state.lock();
                s.stats.batches_submitted += 1;
                if let Some(rec) = s.batches.get_mut(&batch_id_hex) {
                    rec.status = BatchStatus::Submitted { txid };
                }
            }
            Err(e) => {
                warn!("Batch submission failed: {}", e);
                Self::set_failed(&state, &batch_id_hex, format!("submission failed: {}", e));
            }
        }
    }

    fn set_failed(state: &Mutex<AggregatorState>, batch_id: &str, reason: String) {
        let mut s = state.lock();
        s.stats.batches_failed += 1;
        if let Some(rec) = s.batches.get_mut(batch_id) {
            rec.status = BatchStatus::Failed { reason };
        }
    }

    /// Status eines Batches abfragen
    pub fn batch_status(&self, batch_id: &str) -> Option<BatchRecord> {
        self.state.lock().batches.get(batch_id).cloned()
    }

    /// Aggregator-Statistiken
    pub fn stats(&self) -> AggregatorStats {
        self.state.lock().stats.clone()
    }

    /// Anzahl der ausstehenden TXs
    pub fn pending_count(&self) -> usize {
        self.state.lock().builder.len()
    }

    /// Aktuelle L2-State-Root (Hex) — für Diagnose/RPC.
    #[allow(dead_code)] // öffentliche Diagnose-API
    pub fn l2_root_hex(&self) -> String {
        hex::encode(self.state.lock().l2.root_bytes())
    }

    /// L2-Guthaben einer Adresse — für Diagnose/RPC.
    #[allow(dead_code)] // öffentliche Diagnose-API
    pub fn l2_balance(&self, addr: &Address) -> u128 {
        self.state.lock().l2.balance(&addr.0)
    }

    /// L2-Konto (Guthaben + nächste Nonce) einer 20-Byte-Adresse — für die Wallet.
    pub fn l2_account(&self, addr: &[u8; 20]) -> (u128, u64) {
        let st = self.state.lock();
        (st.l2.balance(addr), st.l2.nonce(addr))
    }

    /// Prüft ob Timeout abgelaufen und flusht ggf. Flusht auch bei LEEREM
    /// Builder: `flush_batch` bedient dann offene Forced-Inclusion-Einträge
    /// (Konsens-Pflicht) und kehrt andernfalls ohne Wirkung zurück.
    pub async fn maybe_flush_on_timeout(&self) {
        let should_flush = {
            let state = self.state.lock();
            let timeout = Duration::from_secs(self.config.batch_timeout_secs);
            state.last_flush.elapsed() >= timeout
        };
        if should_flush {
            self.flush_batch().await;
        }
    }
}

/// Parst die Genesis-Allokation aus der Config in `atlas_zk`-Typen.
fn parse_genesis_allocs(config: &AggregatorConfig) -> anyhow::Result<Vec<GenesisAlloc>> {
    config.genesis_alloc.iter().map(|g| {
        let raw = hex::decode(g.address.trim_start_matches("0x"))
            .map_err(|e| anyhow::anyhow!("Ungültige Genesis-Adresse '{}': {}", g.address, e))?;
        let address: [u8; 20] = raw.as_slice().try_into()
            .map_err(|_| anyhow::anyhow!("Genesis-Adresse '{}' ist nicht 20 Byte", g.address))?;
        Ok(GenesisAlloc { address, balance: g.balance })
    }).collect()
}


#[cfg(test)]
mod tests {
    use super::*;
    use atlas_zk::eddsa::EddsaKeypair;
    use atlas_zk::l2_state::{GenesisAlloc, L2State, build_l2_eddsa};
    use crate::node_client::ForcedEntryInfo;

    /// Baut einen ForcedEntryInfo für ein gefördertes Genesis-Konto.
    fn forced_entry(seed: u64, idx: u64, amount: u128, fee: u128, nonce: u64) -> ([u8;20], ForcedEntryInfo) {
        let kp = EddsaKeypair::from_seed(seed);
        let to = [0xABu8; 20];
        let (from, pubkey, sig) = build_l2_eddsa(&kp, &to, amount, fee, nonce);
        (from, ForcedEntryInfo {
            from, to, amount_atom: amount, fee_atom: fee, nonce, pubkey, sig,
            sender_index: idx, seen_height: 0, due: true,
        })
    }

    /// Ein gültiges Forced-TX aus einem geförderten Konto MUSS aufgenommen werden
    /// (Zensurresistenz) — und zwar UNABHÄNGIG vom angegebenen sender_index, weil
    /// die Inklusionsprüfung (nonce/balance) vor der Index-Prüfung greift.
    #[test]
    fn test_classify_forced_includes_valid_tx() {
        let kp = EddsaKeypair::from_seed(0xA71A_5009);
        let from = kp.public().address20();
        let l2 = L2State::from_genesis(&[GenesisAlloc { address: from, balance: 1_000_000 }]);
        let real_idx = l2.index_of(&from).expect("Konto gefördert");

        // Korrekter Index → Inklusion.
        let (_f, e) = forced_entry(0xA71A_5009, real_idx, 100, 5, 0);
        let (txs, rejs) = classify_forced(&l2, &[e], 16);
        assert_eq!(txs.len(), 1, "gültige Forced-TX muss aufgenommen werden");
        assert!(rejs.is_empty(), "keine Rejection für gültige TX");

        // FALSCHER Index → trotzdem Inklusion (nonce/balance gültig, Index egal).
        let (_f2, e2) = forced_entry(0xA71A_5009, real_idx.wrapping_add(7), 100, 5, 0);
        let (txs2, rejs2) = classify_forced(&l2, &[e2], 16);
        assert_eq!(txs2.len(), 1, "gültige TX wird auch bei falschem Index aufgenommen");
        assert!(rejs2.is_empty(), "kein Zensur-Schlupfloch über falschen Index");
    }

    /// Eine Forced-TX mit veralteter Nonce (Konto schon weiter) ist gegen den
    /// pre_root ungültig → korrekte Rejection (kein Inkludieren ungültiger TX).
    #[test]
    fn test_classify_forced_rejects_stale_nonce() {
        let kp = EddsaKeypair::from_seed(0xA71A_5009);
        let from = kp.public().address20();
        let l2 = L2State::from_genesis(&[GenesisAlloc { address: from, balance: 1_000_000 }]);
        let real_idx = l2.index_of(&from).expect("gefördert");
        // Konto steht auf Nonce 0 → TX mit Nonce 5 ist nicht anwendbar.
        let (_f, e) = forced_entry(0xA71A_5009, real_idx, 100, 5, 5);
        let (txs, rejs) = classify_forced(&l2, &[e], 16);
        assert!(txs.is_empty(), "stale-Nonce-TX darf nicht aufgenommen werden");
        assert_eq!(rejs.len(), 1, "stale-Nonce-TX muss per Zeuge abgelehnt werden");
    }

    /// Das von der WASM-Wallet erzeugte /submit-JSON MUSS exakt als
    /// `L2Transaction` parsen UND eine gültige EdDSA-Signatur tragen (sonst
    /// lehnt der Aggregator/Circuit ab). Spiegelt `web-wallet/src/lib.rs::build_submit_tx`.
    #[test]
    fn test_wallet_submit_json_is_valid_l2tx() {
        use atlas_zk::eddsa::EddsaKeypair;
        use atlas_zk::l2_state::{build_l2_eddsa, verify_l2_eddsa};
        use crate::l2_tx::L2Transaction;

        let kp = EddsaKeypair::from_seed(0xA71A_5000);
        let to = [0xABu8; 20];
        let (from, pubkey, sig) = build_l2_eddsa(&kp, &to, 100, 5, 0);

        // IDENTISCHE json!-Struktur wie die WASM-Wallet:
        let json = serde_json::json!({
            "from":   hex::encode(from),
            "to":     hex::encode(to),
            "amount": 100u128,
            "fee":    5u128,
            "nonce":  0u64,
            "auth": { "pubkey": pubkey.to_vec(), "signature": hex::encode(sig) }
        }).to_string();

        let tx: L2Transaction = serde_json::from_str(&json)
            .expect("Wallet-JSON muss als L2Transaction deserialisieren");
        assert_eq!(tx.from.0, from);
        assert_eq!(tx.to.0, to);
        assert_eq!(tx.amount, 100);
        assert_eq!(tx.nonce, 0);
        assert!(verify_l2_eddsa(&tx.from.0, &tx.to.0, tx.amount, tx.fee, tx.nonce,
            &tx.auth.pubkey, tx.auth.signature.as_bytes()),
            "Wallet-Signatur muss gültig sein (sonst Circuit-Reject)");
    }

    /// Unzureichendes Guthaben → Rejection.
    #[test]
    fn test_classify_forced_rejects_insufficient_balance() {
        let kp = EddsaKeypair::from_seed(0xA71A_5009);
        let from = kp.public().address20();
        let l2 = L2State::from_genesis(&[GenesisAlloc { address: from, balance: 10 }]);
        let real_idx = l2.index_of(&from).expect("gefördert");
        let (_f, e) = forced_entry(0xA71A_5009, real_idx, 100, 5, 0); // braucht 105 > 10
        let (txs, rejs) = classify_forced(&l2, &[e], 16);
        assert!(txs.is_empty(), "unterdeckte TX nicht aufnehmen");
        assert_eq!(rejs.len(), 1, "unterdeckte TX per Zeuge ablehnen");
    }
}
