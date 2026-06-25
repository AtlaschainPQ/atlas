//! Aggregator-Konfiguration

use serde::{Deserialize, Serialize};

/// Eine Genesis-Förderung: ein L2-Konto mit Startguthaben.
/// Node und Aggregator MÜSSEN dieselbe Liste verwenden, damit ihre
/// Genesis-L2-Wurzeln übereinstimmen.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenesisAllocCfg {
    /// L2-Adresse als Hex (20 Byte / 40 Hex-Zeichen).
    pub address: String,
    /// Startguthaben in der kleinsten L2-Einheit.
    pub balance: u128,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregatorConfig {
    /// HTTP-Port für L2-TX-Einreichungen
    pub listen_port: u16,
    /// atlas-node JSON-RPC Adresse (z.B. "127.0.0.1:18336")
    pub node_rpc_addr: String,
    /// API-Key für den atlas-node (optional)
    pub node_api_key: Option<String>,
    /// Aggregator-Adresse (Hex, empfängt Bid-Belohnungen)
    pub aggregator_address: String,
    /// Maximale Batch-Größe (TXs pro Batch)
    pub max_batch_size: usize,
    /// Maximale Wartezeit bis Batch eingereicht wird (Sekunden)
    pub batch_timeout_secs: u64,
    /// Pfad zur (alten) Batch-Commitment-Proving-Key-Datei (pk.bin) — deprecated.
    #[serde(default)]
    pub pk_path: String,
    /// Pfad zur State-Transition-Proving-Key-Datei (state_pk.bin, ~122 MB).
    #[serde(default = "default_state_pk_path")]
    pub state_pk_path: String,
    /// Genesis-Förderung der L2-Konten (muss mit der Node-Genesis übereinstimmen).
    #[serde(default)]
    pub genesis_alloc: Vec<GenesisAllocCfg>,
    /// Bid-Betrag pro Batch (ATOM) — Anreiz für den Miner
    pub bid_amount_atom: u128,
    /// Test-Modus: Dummy-Proof statt echtem Groth16 (passend zu node test_mode=true)
    #[serde(default)]
    pub test_mode: bool,
    /// Pfad für den persistierten L2-Snapshot (Reboot-Festigkeit). Leer ⇒
    /// Persistenz aus, Start fällt immer auf Full-Replay aus der Calldata zurück.
    #[serde(default = "default_l2_snapshot_path")]
    pub l2_snapshot_path: String,
    /// Intervall (Sekunden), in dem der L2-Snapshot auf Disk geschrieben wird.
    #[serde(default = "default_snapshot_interval")]
    pub snapshot_interval_secs: u64,
}

fn default_state_pk_path() -> String {
    "keys/state_pk.bin".to_string()
}

fn default_l2_snapshot_path() -> String {
    "aggregator_l2.snapshot".to_string()
}

fn default_snapshot_interval() -> u64 {
    30
}

impl Default for AggregatorConfig {
    fn default() -> Self {
        AggregatorConfig {
            listen_port:        8080,
            node_rpc_addr:      "127.0.0.1:18336".to_string(),
            node_api_key:       None,
            aggregator_address: String::new(),
            max_batch_size:     16,
            batch_timeout_secs: 30,
            pk_path:            "keys/pk.bin".to_string(),
            state_pk_path:      default_state_pk_path(),
            genesis_alloc:      Vec::new(),
            bid_amount_atom:    50,
            test_mode:          false,
            l2_snapshot_path:       default_l2_snapshot_path(),
            snapshot_interval_secs: default_snapshot_interval(),
        }
    }
}

impl AggregatorConfig {
    pub fn from_file(path: &str) -> anyhow::Result<Self> {
        let data = std::fs::read_to_string(path)?;
        let cfg: AggregatorConfig = serde_json::from_str(&data)?;
        Ok(cfg)
    }
}
