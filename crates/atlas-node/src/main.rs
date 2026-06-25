//! ATLAS Node — Einstiegspunkt
//!
//! Verwendung:
//!   atlas-node [OPTIONEN]
//!
//! Optionen:
//!   --config FILE          Konfigurationsdatei (Standard: atlas.json)
//!   --network NET          mainnet | testnet | regtest (Standard: mainnet)
//!   --data-dir DIR         Datenbankverzeichnis (Standard: ./data)
//!   --p2p-port PORT        P2P-Port (Standard: 8333)
//!   --rpc-port PORT        RPC-Port (Standard: 8334)
//!   --api-key KEY          RPC API-Key (Standard: kein Auth)
//!   --max-peers N          Maximale Peers (Standard: 125)
//!   --mining               Mining aktivieren
//!   --no-mining            Mining deaktivieren
//!   --miner-address ADDR   Miner-Belohnungsadresse (ATL:...)
//!   --prover-address ADDR  Prover-Belohnungsadresse (ATL:...)
//!   --threads N            Mining-Threads (0 = alle Kerne)
//!   --metrics-port PORT    Prometheus-Port (0 = aus)
//!   --log-level LEVEL      trace|debug|info|warn|error
//!   --help                 Diese Hilfe
//!   --version              Versionsnummer

use atlas_node::{AtlasNode, NodeConfig};
use tracing::error;

#[tokio::main]
async fn main() {
    // Verdeckter Prover-Worker-Modus: `atlas-node prove-worker` liest einen
    // Proof-Job von stdin, erzeugt EINEN aggregierten Block-Proof und beendet sich.
    // Der Mining-Node startet diesen kurzlebigen Subprozess pro Block-Proof, damit
    // das OS den (arkworks-)Proof-Speicher danach vollständig zurückgibt
    // (struktureller Fix gegen den RSS-Leak). Muss VOR jeglichem Node-/Logging-Setup
    // abgefangen werden — der Worker spricht ein binäres Protokoll über stdout.
    if std::env::args().nth(1).as_deref() == Some("prove-worker") {
        atlas_node::prove_worker::run_stdio(); // beendet den Prozess selbst
    }

    // rustls 0.23 benötigt einen explizit registrierten Crypto-Provider wenn
    // mehrere Features (ring + aws-lc-rs) im Dependency-Baum aktiv sind.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("rustls CryptoProvider konnte nicht registriert werden");

    let args: Vec<String> = std::env::args().collect();

    // Frühe Flags — kein Logging nötig
    if has_flag(&args, "--help") || has_flag(&args, "-h") {
        print_help();
        return;
    }
    if has_flag(&args, "--version") || has_flag(&args, "-V") {
        println!("atlas-node {}", env!("CARGO_PKG_VERSION"));
        return;
    }

    // Log-Level: CLI > Umgebungsvariable > "info"
    let log_level = get_flag(&args, "--log-level")
        .or_else(|| std::env::var("ATLAS_LOG").ok())
        .unwrap_or_else(|| "info".to_string());

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_new(&log_level)
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .with_thread_ids(false)
        .compact()
        .init();

    // Konfiguration laden (CLI hat Vorrang vor Datei)
    let config_path = get_flag(&args, "--config")
        .unwrap_or_else(|| "atlas.json".to_string());

    let mut config = load_or_create_config(&config_path, &args);
    apply_cli_overrides(&mut config, &args);

    // Sicherheits-Validierung VOR dem Start (fail-fast statt stiller Fehlkonfiguration).
    if let Err(e) = config.validate() {
        error!("Konfiguration abgelehnt: {}", e);
        std::process::exit(1);
    }

    // RPC ohne API-Key: auf produktiven Netzen warnen (lokal gebunden, aber Footgun).
    if config.rpc_api_key.is_none() && config.network != "regtest" {
        tracing::warn!(
            "RPC läuft OHNE API-Key — alle RPC-Methoden sind unauthentifiziert. \
             Für '{}' dringend --api-key setzen (RPC bindet auf 127.0.0.1).",
            config.network
        );
    }

    // Konfiguration zurückschreiben (damit Änderungen persistent sind)
    if let Err(e) = config.save_to_file(&config_path) {
        tracing::warn!("Konfiguration konnte nicht gespeichert werden: {}", e);
    }

    tracing::info!("ATLAS Node v{} — Netzwerk: {}", env!("CARGO_PKG_VERSION"), config.network);
    tracing::info!("Datenverzeichnis: {}", config.data_dir);
    tracing::info!("P2P: 0.0.0.0:{} | RPC: 127.0.0.1:{}", config.p2p_port, config.rpc_port);
    if config.mining {
        tracing::info!("Mining: aktiv ({} Threads)", config.mining_threads);
    }

    let node = AtlasNode::new(config);

    tokio::select! {
        result = node.run() => {
            if let Err(e) = result {
                error!("Node-Fehler: {}", e);
                std::process::exit(1);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Ctrl+C empfangen — Node wird gestoppt...");
            node.stop();
            tracing::info!("ATLAS Node gestoppt.");
        }
    }
}

// ── Konfiguration ──────────────────────────────────────────────────────────────

fn load_or_create_config(path: &str, args: &[String]) -> NodeConfig {
    if std::path::Path::new(path).exists() {
        match NodeConfig::load_from_file(path) {
            Ok(cfg) => {
                tracing::info!("Konfiguration geladen: {}", path);
                return cfg;
            }
            Err(e) => tracing::warn!("Konfigurationsdatei fehlerhaft ({}): {} — verwende Standard", path, e),
        }
    }

    // Neue Standardkonfiguration basierend auf --network (Standard: mainnet)
    let network = get_flag(args, "--network").unwrap_or_else(|| "mainnet".to_string());
    let cfg = match network.as_str() {
        "testnet" => NodeConfig::testnet(),
        "regtest" => NodeConfig::regtest(),
        _         => NodeConfig::default(),
    };
    tracing::info!("Neue Konfigurationsdatei erstellt: {}", path);
    cfg
}

fn apply_cli_overrides(config: &mut NodeConfig, args: &[String]) {
    if let Some(v) = get_flag(args, "--network")      { config.network   = v; }
    if let Some(v) = get_flag(args, "--data-dir")     { config.data_dir  = v; }
    if let Some(v) = get_flag(args, "--p2p-port")     { if let Ok(p) = v.parse() { config.p2p_port  = p; } }
    if let Some(v) = get_flag(args, "--rpc-port")     { if let Ok(p) = v.parse() { config.rpc_port  = p; } }
    if let Some(v) = get_flag(args, "--api-key")      { config.rpc_api_key = Some(v); }
    if let Some(v) = get_flag(args, "--max-peers")    { if let Ok(n) = v.parse() { config.max_peers = n; } }
    if let Some(v) = get_flag(args, "--threads")      { if let Ok(n) = v.parse() { config.mining_threads = n; } }
    if let Some(v) = get_flag(args, "--metrics-port") { if let Ok(p) = v.parse() { config.metrics_port = p; } }
    if let Some(v) = get_flag(args, "--miner-address")  { config.miner_address  = Some(v); }
    if let Some(v) = get_flag(args, "--prover-address") { config.prover_address = Some(v); }

    if has_flag(args, "--mining")    { config.mining = true; }
    if has_flag(args, "--no-mining") { config.mining = false; }

    // test_mode aus Netzwerk ableiten.
    // Nur regtest läuft im schnellen Test-Modus (16-MB-Dataset, ZK übersprungen).
    // testnet ist die Generalprobe für Mainnet: echtes 4-GB-TRIAD-Dataset, echte
    // Groth16-Proofs und vollständige PoW-/ZK-Verifikation (test_mode = false).
    config.test_mode = matches!(config.network.as_str(), "regtest");
}

// ── CLI-Hilfsfunktionen ────────────────────────────────────────────────────────

fn get_flag(args: &[String], flag: &str) -> Option<String> {
    // Format: --flag=value
    for arg in args {
        if let Some(val) = arg.strip_prefix(&format!("{}=", flag)) {
            return Some(val.to_string());
        }
    }
    // Format: --flag value
    args.windows(2)
        .find(|w| w[0] == flag)
        .map(|w| w[1].clone())
}

fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|a| a == flag)
}

fn print_help() {
    println!(
        "ATLAS Node v{ver}\n\
         \n\
         VERWENDUNG:\n\
         \n\
         atlas-node [OPTIONEN]\n\
         \n\
         NODE-OPTIONEN:\n\
           --config FILE          Konfigurationsdatei       (Standard: atlas.json)\n\
           --network NET          mainnet|testnet|regtest   (Standard: mainnet)\n\
           --data-dir DIR         Datenbankverzeichnis      (Standard: ./data)\n\
           --p2p-port PORT        P2P-Port                  (Standard: 8333)\n\
           --rpc-port PORT        RPC-Port                  (Standard: 8334)\n\
           --api-key KEY          RPC API-Key               (Standard: kein Auth)\n\
           --max-peers N          Maximale Peers            (Standard: 125)\n\
           --metrics-port PORT    Prometheus-Port           (Standard: 0 = aus)\n\
         \n\
         MINING-OPTIONEN:\n\
           --mining               Mining aktivieren\n\
           --no-mining            Mining deaktivieren\n\
           --miner-address ADDR   Miner-Belohnungsadresse (ATL:...)\n\
           --prover-address ADDR  Prover-Belohnungsadresse (ATL:...)\n\
           --threads N            Mining-Threads (0 = alle CPU-Kerne)\n\
         \n\
         LOGGING:\n\
           --log-level LEVEL      trace|debug|info|warn|error (Standard: info)\n\
         \n\
         ALLGEMEIN:\n\
           --help                 Diese Hilfe anzeigen\n\
           --version              Versionsnummer anzeigen\n\
         \n\
         UMGEBUNGSVARIABLEN:\n\
           ATLAS_LOG              Log-Level (wird von --log-level überschrieben)\n\
         \n\
         BEISPIELE:\n\
           # Mainnet-Node (Standardkonfiguration)\n\
           atlas-node\n\
         \n\
           # Mainnet mit API-Key und benutzerdefiniertem Verzeichnis\n\
           atlas-node --data-dir /var/lib/atlas --api-key meingeheimkey\n\
         \n\
           # Mining-Node\n\
           atlas-node --mining --miner-address ATL:abc... --threads 8\n\
         \n\
           # Lokales Testnetz (kein echter PoW)\n\
           atlas-node --network regtest --mining\n",
        ver = env!("CARGO_PKG_VERSION"),
    );
}
