use serde::{Deserialize, Serialize};
use atlas_state::storage::StorageMode;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Netzwerk: "mainnet" | "testnet" | "regtest"
    pub network:          String,
    /// Daten-Verzeichnis
    pub data_dir:         String,
    /// P2P Port
    pub p2p_port:         u16,
    /// RPC Port
    pub rpc_port:         u16,
    /// Mining aktiviert?
    pub mining:           bool,
    /// Miner-Adresse (hex)
    pub miner_address:    Option<String>,
    /// Prover-Adresse (hex)
    pub prover_address:   Option<String>,
    /// Maximale Peer-Anzahl
    pub max_peers:        usize,
    /// Maximale Mempool-Größe
    pub mempool_max_size: usize,
    /// Test-Modus (kleines TRIAD-Dataset)
    pub test_mode:        bool,
    /// Log-Level
    pub log_level:        String,
    /// Optionaler API-Key für den JSON-RPC Server (Bearer Token)
    pub rpc_api_key:      Option<String>,
    /// Bootstrap-Peers (host:port) — werden beim Start verbunden
    pub seed_nodes:       Vec<String>,
    /// Mining-Threads (0 = auto: alle CPU-Kerne)
    pub mining_threads:   usize,
    /// Prometheus-Metrics Port (0 = deaktiviert)
    pub metrics_port:     u16,
    /// Mempool auf Disk persistieren?
    pub persist_mempool:  bool,
    /// Speicher-Modus: "archive" | "full" | "light"
    #[serde(default)]
    pub storage_mode:     StorageMode,
}

impl Default for NodeConfig {
    fn default() -> Self {
        NodeConfig {
            network:          "mainnet".to_string(),
            data_dir:         "./data".to_string(),
            p2p_port:         8333,
            rpc_port:         8334,
            mining:           false,
            miner_address:    None,
            prover_address:   None,
            max_peers:        125,
            mempool_max_size: 50_000,
            test_mode:        false,
            log_level:        "info".to_string(),
            rpc_api_key:      None,
            seed_nodes:       vec![
                "seed1.atlas-network.io:8333".to_string(),
                "seed2.atlas-network.io:8333".to_string(),
                "seed3.atlas-network.io:8333".to_string(),
            ],
            mining_threads:   0,
            metrics_port:     9090,
            persist_mempool:  true,
            storage_mode:     StorageMode::Full,
        }
    }
}

impl NodeConfig {
    pub fn testnet() -> Self {
        NodeConfig {
            network:   "testnet".to_string(),
            p2p_port:  18333,
            rpc_port:  18334,
            // Generalprobe für Mainnet: volle PoW-/ZK-Verifikation, kein Test-Modus.
            test_mode: false,
            seed_nodes: vec![
                "testnet1.atlas-network.io:18333".to_string(),
                "testnet2.atlas-network.io:18333".to_string(),
            ],
            ..Default::default()
        }
    }

    pub fn regtest() -> Self {
        NodeConfig {
            network:   "regtest".to_string(),
            p2p_port:  18444,
            rpc_port:  18445,
            mining:    true,
            test_mode: true,
            ..Default::default()
        }
    }

    /// Prüft die Konfiguration auf gefährliche Inkonsistenzen, BEVOR der Node startet.
    ///
    /// Wichtigster Schutz (Defense-in-Depth): `test_mode` deaktiviert die ZK- und
    /// PoW-Verifikation. Das ist NUR für `regtest` zulässig. Eine handgeschriebene
    /// `atlas.json` mit `test_mode=true` auf mainnet/testnet würde eine Kette ohne
    /// echte Proof-Prüfung produzieren — das wird hier hart abgelehnt statt still
    /// ignoriert.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.test_mode && self.network != "regtest" {
            anyhow::bail!(
                "Unsichere Konfiguration: test_mode=true ist nur für 'regtest' erlaubt, \
                 nicht für Netzwerk '{}'. test_mode überspringt ZK-/PoW-Verifikation. \
                 Setze test_mode=false oder network=regtest.",
                self.network
            );
        }
        if !matches!(self.network.as_str(), "mainnet" | "testnet" | "regtest") {
            anyhow::bail!(
                "Unbekanntes Netzwerk '{}': erlaubt sind mainnet | testnet | regtest.",
                self.network
            );
        }
        Ok(())
    }

    pub fn load_from_file(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&content)?)
    }

    pub fn save_to_file(&self, path: &str) -> anyhow::Result<()> {
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }
}
