//! ATLAS L2 Aggregator
//!
//! Sammelt L2-Transaktionen, erstellt Groth16-Beweise (MiMC-7/BN254)
//! und reicht Settlement-Batches beim Full-Node ein.
//!
//! Verwendung:
//!   atlas-aggregator [--config <path>]
//!
//! Konfiguration: JSON-Datei (AggregatorConfig), Standard: aggregator.json

mod aggregator;
mod batch;
mod config;
mod l2_tx;
mod node_client;
mod prover;
mod server;

use std::sync::Arc;
use std::env;
use tracing::{info, warn, error};

use crate::aggregator::Aggregator;
use crate::config::AggregatorConfig;
use crate::prover::AggregatorProver;
use crate::server::AggregatorServer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Logging initialisieren.
    //
    // WICHTIG: Die arkworks-r1cs-Gadgets sind mit `#[tracing::instrument(target =
    // "r1cs")]` annotiert (Default-Level INFO). Bei aktivem Subscriber und globalem
    // `info` werden diese Spans aufgezeichnet und die Funktionsargumente — inkl. der
    // `ConstraintSystemRef` (eine mit jeder Operation wachsende BTreeMap) — per Debug
    // in Strings formatiert. Bei ~190k Constraints ist das O(n²) und frisst
    // zweistellige GB RAM → OOM beim Proving. Das Target "r1cs" MUSS hart auf `off`
    // stehen, sonst stirbt der Aggregator beim ersten echten Groth16-Beweis.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("atlas_aggregator=info".parse()?)
                .add_directive("atlas_zk=info".parse()?)
                .add_directive("r1cs=off".parse()?)
        )
        .init();

    // Konfiguration laden
    let config_path = parse_config_arg();
    let config = if std::path::Path::new(&config_path).exists() {
        info!("Loading config from {}", config_path);
        AggregatorConfig::from_file(&config_path)?
    } else {
        warn!("Config file '{}' not found, using defaults", config_path);
        AggregatorConfig::default()
    };

    info!("=== ATLAS L2 Aggregator ===");
    info!("Node RPC:          {}", config.node_rpc_addr);
    info!("Listen port:       {}", config.listen_port);
    info!("Max batch size:    {}", config.max_batch_size);
    info!("Batch timeout:     {}s", config.batch_timeout_secs);
    info!("Aggregator addr:   {}", config.aggregator_address);
    info!("State-PK path:     {}", config.state_pk_path);
    info!("Genesis-Allokationen: {}", config.genesis_alloc.len());

    // State-Proving-Key laden (bzw. Test-Modus mit Dummy-Proofs).
    let prover = if config.test_mode {
        info!("Test-Modus: Aggregator generiert Dummy-Proofs (Groth16 übersprungen)");
        AggregatorProver::test_mode()
    } else {
        match AggregatorProver::from_state_file(&config.state_pk_path) {
            Ok(p)  => p,
            Err(e) => {
                error!("Failed to load state proving key from '{}': {}", config.state_pk_path, e);
                error!("Generate keys first: cargo run -p atlas-zk --bin zk_setup_state");
                return Err(e);
            }
        }
    };

    // Aggregator erstellen
    let agg = match Aggregator::new(config.clone(), prover) {
        Ok(a)  => Arc::new(a),
        Err(e) => {
            error!("Failed to create aggregator: {}", e);
            return Err(e);
        }
    };

    // L2-Zustand aus der On-Chain-Calldata rekonstruieren (REBOOT-FESTIGKEIT).
    // MUSS vor dem Annehmen von TXs laufen — sonst baut der Aggregator auf
    // Genesis statt auf dem aktuellen Node-Zustand → Split-Brain, jeder Bid
    // prallt am pre_root-Check ab. Mit Retry, falls der Node beim Start noch
    // nicht antwortet. Schlägt der Resync endgültig fehl, wird NICHT serviert
    // (lieber kein Service als stiller Split-Brain).
    {
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            match agg.resync_l2().await {
                Ok(()) => break,
                Err(e) if attempt < 10 => {
                    warn!("L2-Resync Versuch {attempt} fehlgeschlagen: {e} — neuer Versuch in 3s");
                    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
                }
                Err(e) => {
                    error!("L2-Resync endgültig fehlgeschlagen — Aggregator startet NICHT: {e}");
                    return Err(e);
                }
            }
        }
    }

    // HTTP-Server starten
    let server = AggregatorServer::new(agg.clone());
    let bind   = format!("0.0.0.0:{}", config.listen_port);
    server.start(&bind).await?;

    // Timeout-Loop: flusht ausstehende Batches wenn Timeout abläuft
    let agg2    = agg.clone();
    let timeout = config.batch_timeout_secs;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(
            tokio::time::Duration::from_secs(timeout / 2 + 1)
        );
        loop {
            interval.tick().await;
            agg2.maybe_flush_on_timeout().await;
        }
    });

    // Periodische L2-Snapshot-Persistenz (REBOOT-FESTIGKEIT): schreibt den
    // L2-Zustand + Node-Höhe regelmäßig auf Disk, sodass ein Neustart in
    // Sekunden lädt + nur das Delta nachspielt statt die ganze TX-Historie.
    if !config.l2_snapshot_path.is_empty() {
        let agg3 = agg.clone();
        let iv   = config.snapshot_interval_secs.max(5);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(iv));
            interval.tick().await; // erster Tick feuert sofort → überspringen
            loop {
                interval.tick().await;
                if let Err(e) = agg3.persist_l2_snapshot().await {
                    warn!("L2-Snapshot-Persistenz fehlgeschlagen: {e}");
                }
            }
        });
    }

    info!("Aggregator ready. POST L2 TXs to http://localhost:{}/submit", config.listen_port);
    info!("Press Ctrl+C to stop.");

    // Graceful shutdown bei SIGINT
    tokio::signal::ctrl_c().await?;
    info!("Flushing remaining batch before shutdown...");
    agg.flush_batch().await;
    info!("Aggregator stopped.");

    Ok(())
}

fn parse_config_arg() -> String {
    let args: Vec<String> = env::args().collect();
    for i in 0..args.len() {
        if (args[i] == "--config" || args[i] == "-c") && i + 1 < args.len() {
            return args[i + 1].clone();
        }
    }
    "aggregator.json".to_string()
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
