//! ATLAS Node — Hauptkomponente
//!
//! Orchestriert: Chain, Mempool, Mining, P2P-Netzwerk, JSON-RPC

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use atlas_consensus::params::ConsensusParams;
use atlas_core::utxo_query::UtxoQuery;
use crate::zk_stub::init_zk_verifier;
use atlas_zk::ZkBatchProver;
use atlas_state::state_db::StateDb;
use atlas_state::storage::{Storage, StorageConfig};
use atlas_mempool::mempool::Mempool;
use atlas_triad::epoch::EpochSeed;
use atlas_triad::dataset::DatasetConfig;
use atlas_triad::miner::TriadMiner;
use atlas_triad::network_entropy::NetworkEntropy;
use atlas_core::crypto::{Address, KeyPair};
use crate::chain::ChainManager;
use crate::config::NodeConfig;
use crate::ibd::IbdManager;
use crate::p2p::P2pNetwork;
use crate::rpc::RpcServer;
use parking_lot::Mutex;
use tokio::sync::Notify;
use tracing::{info, warn};

#[cfg(target_os = "linux")]
extern "C" {
    /// glibc: gibt freien Heap-Speicher oberhalb von `pad` Bytes ans OS zurück.
    fn malloc_trim(pad: usize) -> i32;
}

/// Gibt freigewordenen Heap-Speicher aktiv ans Betriebssystem zurück.
///
/// Mit dem produktiven glibc-Arena-Tuning (`MALLOC_ARENA_MAX=2`,
/// `MALLOC_TRIM_THRESHOLD_=0`) gibt glibc große, gerade freigegebene Blöcke nicht
/// immer sofort zurück — insbesondere nach dem Drop des ~4 GB TRIAD-Datasets beim
/// Epoch-Wechsel. `malloc_trim(0)` erzwingt das. Auf Nicht-Linux (Entwicklung auf
/// macOS) ist es ein No-op.
fn release_memory_to_os() {
    #[cfg(target_os = "linux")]
    unsafe {
        let _ = malloc_trim(0);
    }
}

pub struct AtlasNode {
    config:   NodeConfig,
    chain:    Arc<ChainManager>,
    state:    Arc<StateDb>,
    mempool:  Arc<Mempool>,
    storage:  Option<Arc<Storage>>,
    stop:     Arc<AtomicBool>,
    /// Signalisiert run() dass stop() aufgerufen wurde
    shutdown: Arc<Notify>,
    /// P2P-Referenz wird in run() gesetzt und in stop() für Peer-Persistenz genutzt
    p2p:      Mutex<Option<Arc<P2pNetwork>>>,
    /// IBD-Manager (in run() gesetzt) — das Mining liest `is_syncing()`, um
    /// während des Aufholens einer längeren Fremdkette zu pausieren.
    ibd:      Mutex<Option<Arc<IbdManager>>>,
}

impl AtlasNode {
    pub fn new(config: NodeConfig) -> Self {
        let params = match config.network.as_str() {
            "testnet" => ConsensusParams::testnet(),
            "regtest" => ConsensusParams::regtest(),
            _         => ConsensusParams::mainnet(),
        };

        let db_path = format!("{}/chain", config.data_dir);

        // ZK-Prover nur für Miner-Nodes (Non-Test): erzeugt den EINEN aggregierten
        // Block-Proof. Im test_mode wird die Proof-Verifikation ohnehin übersprungen.
        //
        // Der eigentliche Proof läuft NICHT im langlebigen Node-Prozess, sondern pro
        // Block in einem isolierten Subprozess (`atlas-node prove-worker`) — so gibt
        // das OS den arkworks-Speicher nach jedem Proof vollständig zurück
        // (struktureller Fix gegen den RSS-Leak). Hier wird der gebündelte PK nur
        // einmalig als Start-Sanity-Check geladen und sofort wieder verworfen.
        let prover_subprocess: bool = if config.mining && !config.test_mode {
            match ZkBatchProver::from_bundled() {
                Ok(_)  => { info!("ZK prover available (bundled PK) — block proofs run in isolated subprocess"); true }
                Err(e) => { warn!("Could not load bundled ZK prover: {} — blocks carry digest only", e); false }
            }
        } else {
            false
        };

        // Storage öffnen; Fehler → ohne Persistenz starten
        let storage_cfg = StorageConfig::from_mode(&config.storage_mode);
        info!(
            "Storage mode: {:?} | prune_blocks={:?} prune_proofs={:?}",
            config.storage_mode, storage_cfg.prune_blocks_after, storage_cfg.prune_proofs_after
        );
        let (chain, storage): (Arc<ChainManager>, Option<Arc<Storage>>) =
            match Storage::open_with_config(&db_path, storage_cfg) {
                Ok(storage) => {
                    info!("Persistent storage opened at {} (Zstd-3 blocks, LZ4 indexes)", db_path);
                    let state   = Arc::new(StateDb::load_or_create(&storage));
                    let utxo_ref: Arc<dyn UtxoQuery> = state.utxo_set.clone();
                    let mempool = Arc::new(
                        Mempool::new(params.clone())
                            .with_utxo(utxo_ref)
                    );
                    let mut cm = ChainManager::new(params.clone(), state, mempool, config.test_mode)
                        .with_storage(storage);
                    if prover_subprocess { cm = cm.with_prover_subprocess(); }
                    let chain = Arc::new(cm);
                    let storage_arc = chain.storage_arc();
                    (chain, storage_arc)
                }
                Err(e) => {
                    warn!("Storage unavailable ({}), running without persistence", e);
                    let state   = Arc::new(StateDb::new());
                    let utxo_ref: Arc<dyn UtxoQuery> = state.utxo_set.clone();
                    let mempool = Arc::new(
                        Mempool::new(params.clone())
                            .with_utxo(utxo_ref)
                    );
                    let mut cm = ChainManager::new(params.clone(), state, mempool, config.test_mode);
                    if prover_subprocess { cm = cm.with_prover_subprocess(); }
                    (Arc::new(cm), None)
                }
            };

        let state   = chain.state().clone();
        let mempool = chain.mempool().clone();

        // Mempool von Disk laden wenn vorhanden
        if config.persist_mempool {
            if let Some(ref storage) = storage {
                match storage.load_mempool() {
                    Ok(txs) if !txs.is_empty() => {
                        let count = mempool.load_txs(txs);
                        info!("Loaded {} transactions from mempool storage", count);
                    }
                    Ok(_) => {}
                    Err(e) => warn!("Could not load mempool from disk: {}", e),
                }
            }
        }

        AtlasNode {
            config,
            chain,
            state,
            mempool,
            storage,
            stop:     Arc::new(AtomicBool::new(false)),
            shutdown: Arc::new(Notify::new()),
            p2p:      Mutex::new(None),
            ibd:      Mutex::new(None),
        }
    }

    /// Startet den Node (P2P, RPC, Mining)
    pub async fn run(&self) -> anyhow::Result<()> {
        info!("ATLAS Node starting — network: {}", self.config.network);
        info!("Chain height: {}", self.chain.height());

        // ZK-Verifier initialisieren (Groth16/BN254, hardcodierter VK)
        if let Err(e) = init_zk_verifier() {
            warn!("ZK verifier init failed: {} — settlement proofs will not be verified", e);
        }

        // P2P starten
        let p2p = P2pNetwork::new(
            self.chain.clone(),
            self.mempool.clone(),
            self.config.max_peers,
            &self.config.data_dir,
        );
        // Bekannte Peer-Adressen aus Disk laden
        if let Some(ref storage) = self.storage {
            if let Ok(addrs) = storage.load_peers() {
                if !addrs.is_empty() {
                    p2p.seed_known_addrs(addrs);
                }
            }
        }
        let bind_p2p = format!("0.0.0.0:{}", self.config.p2p_port);
        p2p.start(&bind_p2p).await?;

        // Seed-Nodes verbinden — mit periodischem Retry, solange der Node
        // unterverbunden ist. Ein einmaliger Versuch beim Start reicht nicht:
        // Seeds können temporär down sein, später starten (Race beim
        // gleichzeitigen Hochfahren) oder Verbindungen können abreißen.
        // Ohne Retry bliebe der Node dauerhaft isoliert (kein IBD, kein Relay).
        if !self.config.seed_nodes.is_empty() {
            let seeds = self.config.seed_nodes.clone();
            // Seeds sind Operator-Vertrauen: nie bannen (sonst Selbst-Isolation).
            let seed_socks: Vec<std::net::SocketAddr> =
                seeds.iter().filter_map(|s| s.parse().ok()).collect();
            p2p.whitelist_ips(&seed_socks);
            let p2p2  = p2p.clone();
            tokio::spawn(async move {
                let mut delay = tokio::time::Duration::from_secs(2);
                loop {
                    if p2p2.peer_count() == 0 {
                        for addr in &seeds {
                            match p2p2.connect(addr).await {
                                Ok(())  => info!("Seed node {} connected", addr),
                                Err(e)  => warn!("Seed node {} unreachable: {} (retry in {:?})",
                                    addr, e, delay),
                            }
                        }
                        // Backoff bis max. 60 s, Reset bei Erfolg.
                        delay = if p2p2.peer_count() > 0 {
                            tokio::time::Duration::from_secs(2)
                        } else {
                            (delay * 2).min(tokio::time::Duration::from_secs(60))
                        };
                    } else {
                        delay = tokio::time::Duration::from_secs(2);
                    }
                    // Verbundene Nodes prüfen nur noch gelegentlich (Reconnect-Wächter).
                    let sleep_for = if p2p2.peer_count() > 0 {
                        tokio::time::Duration::from_secs(30)
                    } else {
                        delay
                    };
                    tokio::time::sleep(sleep_for).await;
                }
            });
        }

        // P2P-Referenz im Struct speichern (für stop())
        *self.p2p.lock() = Some(p2p.clone());

        // IBD starten
        let ibd = IbdManager::new(self.chain.clone(), p2p.clone());
        ibd.start();
        *self.ibd.lock() = Some(ibd.clone());

        // JSON-RPC starten
        let rpc = RpcServer::new(
            self.chain.clone(),
            self.state.clone(),
            self.mempool.clone(),
            Some(p2p.clone()),
            self.config.rpc_api_key.clone(),
            self.config.test_mode,
        );
        let bind_rpc = format!("127.0.0.1:{}", self.config.rpc_port);
        rpc.start(&bind_rpc).await?;

        // Metrics-Server starten wenn aktiviert
        if self.config.metrics_port > 0 {
            let chain   = self.chain.clone();
            let mempool = self.mempool.clone();
            let state   = self.state.clone();
            let port    = self.config.metrics_port;
            tokio::spawn(async move {
                if let Err(e) = run_metrics_server(port, chain, mempool, state).await {
                    warn!("Metrics server error: {}", e);
                }
            });
            info!("Metrics server listening on 0.0.0.0:{}", self.config.metrics_port);
        }

        // Mempool-Expiry: abgelaufene TXs alle 5 Minuten entfernen
        let mempool_gc = self.mempool.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(
                tokio::time::Duration::from_secs(300)
            );
            loop {
                interval.tick().await;
                let before = mempool_gc.len();
                mempool_gc.evict_expired();
                let evicted = before.saturating_sub(mempool_gc.len());
                if evicted > 0 {
                    tracing::info!("Mempool GC: evicted {} expired transactions", evicted);
                }
            }
        });

        // Mining starten wenn konfiguriert
        if self.config.mining {
            self.start_mining().await?;
        }

        info!("Node ready. Press Ctrl+C to stop.");

        // Blockiert bis stop() aufgerufen wird
        self.shutdown.notified().await;
        Ok(())
    }

    pub async fn start_mining(&self) -> anyhow::Result<()> {
        let miner_addr = match &self.config.miner_address {
            Some(hex) => Address::from_hex(hex)?,
            None => {
                let kp = KeyPair::generate();
                info!("No miner address configured, using: {}", kp.address);
                kp.address
            }
        };
        let prover_addr = match &self.config.prover_address {
            Some(hex) => Address::from_hex(hex)?,
            None      => miner_addr,
        };

        // Mining-Threads: 0 = alle CPU-Kerne
        let threads = if self.config.mining_threads == 0 {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
        } else {
            self.config.mining_threads
        };

        let chain = self.chain.clone();
        let stop  = self.stop.clone();
        let test  = self.config.test_mode;
        let ibd   = self.ibd.lock().clone();
        // TRIAD-Dataset pro Epoche auf Disk cachen → Neustart lädt statt neu zu rechnen.
        let cache_dir = std::path::PathBuf::from(format!("{}/triad-cache", self.config.data_dir));

        info!("Mining started — miner: {} — threads: {}", miner_addr, threads);

        tokio::spawn(async move {
            Self::mine_loop(chain, miner_addr, prover_addr, stop, test, threads, cache_dir, ibd).await;
        });

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn mine_loop(
        chain:       Arc<ChainManager>,
        miner_addr:  Address,
        prover_addr: Address,
        stop:        Arc<AtomicBool>,
        test_mode:   bool,
        threads:     usize,
        cache_dir:   std::path::PathBuf,
        ibd:         Option<Arc<IbdManager>>,
    ) {
        // Dataset pro Epoch cachen — wird nur neu aufgebaut wenn sich die Epoch ändert
        let mut cached_epoch: Option<u32>        = None;
        let mut cached_miner: Option<TriadMiner> = None;

        while !stop.load(Ordering::Relaxed) {
            // Mining pausieren, solange wir eine bekannte längere Fremdkette
            // aufholen. Sonst verlängern wir unsere eigene (kürzere) Kette bis
            // zum Gleichstand und der Reorg auf die längere Kette löst nie aus.
            if let Some(ibd) = &ibd {
                if ibd.is_syncing() {
                    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                    continue;
                }
            }

            let template = chain.block_template(miner_addr, prover_addr);
            let height   = template.height();
            let target   = template.header.target();
            let epoch    = template.header.epoch;

            // Dataset nur neu bauen wenn Epoch gewechselt hat
            if cached_epoch != Some(epoch) {
                // Altes Dataset (~4 GB) VOR dem Aufbau des neuen explizit freigeben.
                // Sonst existieren während der bis zu ~8-minütigen Generierung beide
                // Datasets gleichzeitig (~8 GB Peak) und glibc behält diesen
                // Hochwasserstand. Erst droppen, dann ans OS zurückgeben.
                if cached_miner.is_some() {
                    info!("Releasing previous epoch dataset before rebuild ...");
                    drop(cached_miner.take()); // altes ~4-GB-Dataset sofort fallenlassen
                    release_memory_to_os();
                }

                let epoch_seed  = EpochSeed::for_epoch(epoch);
                let dataset_cfg = if test_mode { DatasetConfig::test() } else { DatasetConfig::production() };
                info!("Loading TRIAD dataset for epoch {} (cache dir: {}) ...", epoch, cache_dir.display());
                let t0 = std::time::Instant::now();
                // WICHTIG: spawn_blocking — die Generierung rechnet Minuten auf
                // allen Kernen. Direkt im async-Task würde sie die Runtime
                // blockieren: keine Pings, kein RPC, hängende TLS-Handshakes
                // (Node wirkt für Peers tot und wird getrennt).
                let (dataset, from_disk) = tokio::task::spawn_blocking({
                    let cache_dir = cache_dir.clone();
                    move || atlas_triad::dataset::Dataset::new_for_mining_cached(
                        &epoch_seed, dataset_cfg, &cache_dir,
                    )
                }).await.expect("dataset generation task panicked");
                let entropy     = NetworkEntropy::new();
                cached_miner = Some(TriadMiner::new(dataset, entropy));
                cached_epoch = Some(epoch);
                let src = if from_disk { "loaded from disk cache" } else { "generated + cached" };
                info!("TRIAD dataset ready (epoch {}, {}, {:.1}s)", epoch, src, t0.elapsed().as_secs_f64());

                // Zwischenpuffer der Generierung (cache-Vektor etc.) ans OS zurückgeben.
                release_memory_to_os();
            }

            info!("Mining block {} with {} thread(s) ...", height, threads);

            // WICHTIG: spawn_blocking — eine Mining-Runde blockiert bis zum
            // gefundenen Block (Sekunden bis Minuten). Auf der Runtime würde
            // sie P2P/RPC aushungern (siehe Dataset-Kommentar oben). Der Miner
            // (~4-GB-Dataset) wandert per move hinein und wieder heraus.
            let stop_mining = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let miner  = cached_miner.take().expect("miner is cached at this point");
            let header = template.header.clone();
            let (miner, result) = tokio::task::spawn_blocking(move || {
                let r = if threads <= 1 {
                    miner.mine(&header, &target, 0, &stop_mining)
                } else {
                    miner.mine_parallel(&header, &target, threads, stop_mining)
                };
                (miner, r)
            }).await.expect("mining task panicked");
            cached_miner = Some(miner);

            if let Some(result) = result {
                let mut block          = template;
                block.header.nonce    = result.nonce;
                block.header.mix_hash = result.mix_hash;

                let chain2 = chain.clone();
                match tokio::task::spawn_blocking(move || chain2.process_block(block)).await {
                    Ok(Ok(()))  => info!("Block {} mined! nonce={}", height, result.nonce),
                    Ok(Err(e))  => warn!("Block rejected: {}", e),
                    Err(_)      => warn!("Block processing task panicked"),
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
        self.shutdown.notify_one();
        info!("Node wird gestoppt...");

        // Bekannte Peer-Adressen auf Disk schreiben
        if let Some(ref storage) = self.storage {
            if let Some(p2p) = self.p2p.lock().as_ref() {
                let addrs = p2p.known_addrs();
                if !addrs.is_empty() {
                    match storage.save_peers(&addrs) {
                        Ok(())  => info!("Peer-Adressen gespeichert: {} Einträge", addrs.len()),
                        Err(e)  => warn!("Peer-Persistenz fehlgeschlagen: {}", e),
                    }
                }
            }
        }

        // Mempool auf Disk schreiben
        if self.config.persist_mempool {
            if let Some(ref storage) = self.storage {
                let txs   = self.mempool.dump_txs();
                let count = txs.len();
                match storage.save_mempool(&txs) {
                    Ok(())  => info!("Mempool gespeichert: {} Transaktionen", count),
                    Err(e)  => warn!("Mempool-Persistenz fehlgeschlagen: {}", e),
                }
            }
        }

        info!("ATLAS Node gestoppt.");
    }

    pub fn status(&self) -> NodeStatus {
        let chain = self.state.chain.read();
        NodeStatus {
            height:        chain.height,
            best_hash:     chain.best_hash.as_hex(),
            total_supply:  chain.total_supply.as_atl_decimal(),
            total_txs:     chain.total_txs,
            mempool_size:  self.mempool.len(),
            utxo_count:    self.state.utxo_set.len(),
            avg_fees_atom: chain.avg_fees.as_atom(),
        }
    }
}

// ── Prometheus-Metrics Server ─────────────────────────────────────────────────

async fn run_metrics_server(
    port:    u16,
    chain:   Arc<ChainManager>,
    mempool: Arc<Mempool>,
    state:   Arc<StateDb>,
) -> anyhow::Result<()> {
    use tokio::net::TcpListener;
    use tokio::io::AsyncWriteExt;

    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    loop {
        let Ok((mut stream, _)) = listener.accept().await else { continue };
        let chain   = chain.clone();
        let mempool = mempool.clone();
        let state   = state.clone();
        tokio::spawn(async move {
            // Guards VOR dem await droppen (parking_lot guards sind nicht Send)
            let body = {
                let chain_state   = state.chain.read();
                let mempool_stats = mempool.stats();
                format!(
                    "# HELP atlas_height Current chain height\n\
                     # TYPE atlas_height gauge\n\
                     atlas_height {}\n\
                     # HELP atlas_total_supply Total supply in ATOM\n\
                     # TYPE atlas_total_supply gauge\n\
                     atlas_total_supply {}\n\
                     # HELP atlas_mempool_size Pending transactions\n\
                     # TYPE atlas_mempool_size gauge\n\
                     atlas_mempool_size {}\n\
                     # HELP atlas_utxo_count UTXO set size\n\
                     # TYPE atlas_utxo_count gauge\n\
                     atlas_utxo_count {}\n\
                     # HELP atlas_avg_fee_atom Average fee in ATOM\n\
                     # TYPE atlas_avg_fee_atom gauge\n\
                     atlas_avg_fee_atom {}\n",
                    chain_state.height,
                    chain_state.total_supply.as_atom(),
                    mempool_stats.tx_count,
                    state.utxo_set.len(),
                    mempool_stats.avg_fee_atom,
                )
            }; // chain_state guard dropped here
            let _ = chain;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\n\r\n{}",
                body.len(), body
            );
            let _ = stream.write_all(response.as_bytes()).await;
        });
    }
}

#[derive(Debug, serde::Serialize)]
pub struct NodeStatus {
    pub height:        u64,
    pub best_hash:     String,
    pub total_supply:  String,
    pub total_txs:     u64,
    pub mempool_size:  usize,
    pub utxo_count:    usize,
    pub avg_fees_atom: u128,
}
