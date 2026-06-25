//! ATLAS Wallet CLI
//!
//! Transaktionen laufen standardmäßig über L2 (Aggregator).
//! Steuerung via:
//!   1. ~/.atlas/wallet.conf  → { "default_via_l2": true, "aggregator_url": "...", ... }
//!   2. Umgebungsvariable     → ATLAS_VIA_L2=1
//!   3. CLI-Flag              → --via-l2 (oder --l1 um L1 zu erzwingen)
//!
//! Befehle:
//!   new-key      [--label NAME] [--wallet FILE]    Neuen ECDSA-Schlüssel generieren
//!   new-key-pq   [--label NAME] [--wallet FILE]    Neuen PQ-Schlüssel generieren
//!   import-key   --privkey HEX [--label NAME]      Schlüssel importieren
//!   list-keys    [--wallet FILE]                   Alle Schlüssel anzeigen
//!   balance      <ADDRESS> [--rpc URL]             Kontostand abfragen
//!   send         --from <ADDR> --to <ADDR>         Transfer (default: L2)
//!                --amount <ATOM> [--fee <ATOM>]    [--via-l2 | --l1] [--nonce N]
//!   send-pq      --from <ATLQ:ADDR> --to <ADDR>   PQ-Transfer (immer L1)
//!                --amount <ATOM> [--fee <ATOM>]
//!   height       [--rpc URL]                       Aktuelle Chain-Höhe
//!   l2-send      --from --to --amount --fee        L2-TX explizit senden
//!   l2-status    <BATCH_ID>                        Batch-Status abfragen
//!   l2-address   --from <ATL-Adresse>             Abgeleitete L2-Adresse anzeigen
//!   config       show | set <KEY> <VALUE>          Wallet-Config verwalten

use atlas_wallet::{Keystore, KeyType, RpcClient, build_transfer, build_transfer_quantum, UtxoInfo};
use atlas_core::amount::Amount;
use atlas_core::crypto::Address;
use atlas_core::l2_tx::L2Transaction;
use atlas_zk::eddsa::EddsaKeypair;
use atlas_zk::l2_state::build_l2_eddsa;
use atlas_core::pq_crypto::PqAddress;
use atlas_core::transaction::OutputAddress;
use std::collections::HashMap;
use zeroize::Zeroizing;

// ── Wallet-Konfiguration ──────────────────────────────────────────────────────

/// Standard-Konfiguration – wird durch ~/.atlas/wallet.conf oder
/// eine wallet.conf im selben Verzeichnis wie die Wallet-Datei überschrieben.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct WalletConfig {
    /// Transaktionen standardmäßig über L2 senden
    #[serde(default = "default_true")]
    pub default_via_l2: bool,
    /// Aggregator-URL
    #[serde(default = "default_agg_url")]
    pub aggregator_url: String,
    /// Node RPC URL
    #[serde(default = "default_rpc_url")]
    pub node_rpc_url: String,
    /// Node API-Key (optional)
    #[serde(default)]
    pub node_api_key: Option<String>,
    /// Standard-Fee für L2-Transaktionen (ATOM)
    #[serde(default = "default_l2_fee")]
    pub l2_fee_atom: u64,
}

fn default_true()    -> bool   { true }
fn default_agg_url() -> String { "http://127.0.0.1:8080".to_string() }
fn default_rpc_url() -> String { "http://127.0.0.1:18334".to_string() }
fn default_l2_fee()  -> u64   { 5 }

impl Default for WalletConfig {
    fn default() -> Self {
        WalletConfig {
            default_via_l2: true,
            aggregator_url: default_agg_url(),
            node_rpc_url:   default_rpc_url(),
            node_api_key:   None,
            l2_fee_atom:    default_l2_fee(),
        }
    }
}

/// Liest die Wallet-Konfiguration (Priorität: ~/.atlas/wallet.conf > Defaults)
fn load_wallet_config() -> WalletConfig {
    let paths: Vec<std::path::PathBuf> = vec![
        // 1. Lokale wallet.conf im CWD
        std::path::PathBuf::from("wallet.conf"),
        // 2. ~/.atlas/wallet.conf
        dirs_config_path(),
    ];
    for path in &paths {
        if let Ok(s) = std::fs::read_to_string(path) {
            if let Ok(cfg) = serde_json::from_str::<WalletConfig>(&s) {
                return cfg;
            }
        }
    }
    WalletConfig::default()
}

fn dirs_config_path() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    std::path::PathBuf::from(home).join(".atlas").join("wallet.conf")
}

fn nonces_path() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    std::path::PathBuf::from(home).join(".atlas").join("nonces.json")
}

/// Liest den nächsten Nonce für eine Adresse (auto-increment)
fn next_nonce(address: &str) -> u64 {
    let map: HashMap<String, u64> = std::fs::read_to_string(nonces_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    map.get(address).copied().unwrap_or(0) + 1
}

/// Speichert den verwendeten Nonce
fn persist_nonce(address: &str, nonce: u64) {
    let path = nonces_path();
    let mut map: HashMap<String, u64> = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    map.insert(address.to_string(), nonce);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&path, serde_json::to_string_pretty(&map).unwrap_or_default());
}

// ── Hauptprogramm ─────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("help");

    // Konfiguration laden
    let mut cfg = load_wallet_config();

    // CLI-Flags überschreiben Config
    if let Some(rpc) = get_flag(&args, "--rpc") {
        cfg.node_rpc_url = rpc;
    }
    if let Some(key) = get_flag(&args, "--api-key") {
        cfg.node_api_key = Some(key);
    }
    if let Some(agg) = get_flag(&args, "--aggregator") {
        cfg.aggregator_url = agg;
    }

    let wallet_path  = get_flag(&args, "--wallet").unwrap_or("wallet.json".to_string());
    let cli_password = get_flag(&args, "--password");

    // L2-Modus bestimmen:
    // 1. --l1 Flag → erzwingt L1
    // 2. --via-l2 Flag → erzwingt L2
    // 3. ATLAS_VIA_L2=0 → erzwingt L1
    // 4. ATLAS_VIA_L2=1 → erzwingt L2
    // 5. Config default_via_l2
    let force_l1   = args.contains(&"--l1".to_string());
    let force_l2   = args.contains(&"--via-l2".to_string());
    let env_via_l2 = std::env::var("ATLAS_VIA_L2").ok();
    let via_l2 = if force_l1 { false }
                 else if force_l2 { true }
                 else if env_via_l2.as_deref() == Some("0") { false }
                 else if env_via_l2.as_deref() == Some("1") { true }
                 else { cfg.default_via_l2 };

    match cmd {
        // ── Schlüsselverwaltung ───────────────────────────────────────────────
        "new-key" => {
            let label    = get_flag(&args, "--label").unwrap_or("default".to_string());
            let password = prompt_password_confirm_or_cli(&cli_password)?;
            let mut ks   = Keystore::open(&wallet_path)?;
            let entry    = ks.generate_key(&label, password.as_bytes())?;
            println!("Neuer Schlüssel '{}' erstellt:", label);
            println!("  Adresse:  {}", entry.address);
            println!("  Typ:      ECDSA (ATL:)");
            println!("  Wallet:   {}", wallet_path);
        }

        "new-key-pq" => {
            let label    = get_flag(&args, "--label").unwrap_or("pq-default".to_string());
            let password = prompt_password_confirm_or_cli(&cli_password)?;
            let mut ks   = Keystore::open(&wallet_path)?;
            println!("Generiere ML-DSA-65 Schlüssel…");
            let entry    = ks.generate_pq_key(&label, password.as_bytes())?;
            println!("Neuer Post-Quantum-Schlüssel '{}' erstellt:", label);
            println!("  Adresse:  {}", entry.address);
            println!("  Typ:      ML-DSA-65 (ATLQ:)");
            println!("  Wallet:   {}", wallet_path);
        }

        "import-key" => {
            let label    = get_flag(&args, "--label").unwrap_or("imported".to_string());
            let priv_hex = get_flag(&args, "--privkey")
                .ok_or_else(|| anyhow::anyhow!("--privkey required"))?;
            let password = prompt_password_confirm_or_cli(&cli_password)?;
            let mut ks   = Keystore::open(&wallet_path)?;
            let entry    = ks.import_key(&label, &priv_hex, password.as_bytes())?;
            println!("Schlüssel '{}' importiert:", label);
            println!("  Adresse: {}", entry.address);
        }

        "list-keys" => {
            let ks = Keystore::open(&wallet_path)?;
            if ks.is_empty() {
                println!("Keine Schlüssel in Wallet. Verwende 'new-key' oder 'new-key-pq'.");
            } else {
                println!("{:<20} {:<12} Adresse", "Label", "Typ");
                println!("{}", "-".repeat(80));
                for key in ks.keys() {
                    let typ = match key.key_type {
                        KeyType::Classic => "ECDSA",
                        KeyType::Quantum => "ML-DSA-65",
                    };
                    println!("{:<20} {:<12} {}", key.label, typ, key.address);
                }
            }
        }

        // ── Abfragen ─────────────────────────────────────────────────────────
        "balance" => {
            let address = args.get(2).ok_or_else(|| anyhow::anyhow!("Usage: balance <address>"))?;
            let client  = RpcClient::new(&cfg.node_rpc_url, cfg.node_api_key.clone());
            let info    = client.get_balance(address).await?;
            println!("Adresse: {}", address);
            println!("Saldo:   {} ATL", info["balance_atl"].as_str().unwrap_or("?"));
            println!("         {} ATOM", info["balance_atom"].as_str().unwrap_or("?"));
        }

        "height" => {
            let client = RpcClient::new(&cfg.node_rpc_url, cfg.node_api_key.clone());
            let h      = client.get_block_count().await?;
            println!("Chain-Höhe: {}", h);
        }

        // ── Transfer (Standard: L2) ───────────────────────────────────────────
        "send" => {
            let from_addr = get_flag(&args, "--from")
                .ok_or_else(|| anyhow::anyhow!("--from <address> required"))?;
            let to_addr = get_flag(&args, "--to")
                .ok_or_else(|| anyhow::anyhow!("--to <address> required"))?;
            let amount_str = get_flag(&args, "--amount")
                .ok_or_else(|| anyhow::anyhow!("--amount <ATOM> required"))?;

            let password = prompt_password_or_cli(&cli_password)?;
            let ks  = Keystore::open(&wallet_path)?;
            let key = ks.get_by_address(&from_addr)
                .ok_or_else(|| anyhow::anyhow!("Adresse '{}' nicht in Wallet", from_addr))?;

            if via_l2 {
                // ── L2-Pfad (Standard) ───────────────────────────────────────
                let fee_str = get_flag(&args, "--fee")
                    .unwrap_or(cfg.l2_fee_atom.to_string());
                let fee    = fee_str.parse::<u128>()?;
                let amount = amount_str.parse::<u128>()?;
                let to     = Address::from_hex(&to_addr)?;
                let nonce  = get_flag(&args, "--nonce")
                    .and_then(|n| n.parse().ok())
                    .unwrap_or_else(|| next_nonce(&from_addr));

                let kp = key.keypair(password.as_bytes())?;
                // L2-Identität: Baby-Jubjub EdDSA-Key, deterministisch aus dem
                // Wallet-Secret abgeleitet. L2-from = EdDSA-Adresse.
                let l2_kp = EddsaKeypair::from_secret_bytes(&kp.secret_bytes());
                let (from, pubkey, sig) =
                    build_l2_eddsa(&l2_kp, &to.0, amount, fee, nonce);
                let tx = L2Transaction::from_parts(
                    Address(from), to, amount, fee, nonce, pubkey, sig);
                let tx_hash = tx.hash();

                let tx_json = serde_json::to_string(&tx)?;
                let result  = l2_http_post(&cfg.aggregator_url, "/submit", &tx_json).await
                    .map_err(|e| anyhow::anyhow!("Aggregator nicht erreichbar: {}\n\
                        Tipp: Aggregator starten oder --l1 für direkte L1-Übertragung", e))?;
                let resp: serde_json::Value = serde_json::from_str(&result)?;

                if let Some(err) = resp.get("error") {
                    anyhow::bail!("Aggregator abgelehnt: {}", err);
                }

                persist_nonce(&from_addr, nonce);

                println!("✓ L2-Transfer gesendet:");
                println!("  Von:    ATL:{}", from_addr);
                println!("  An:     ATL:{}", to_addr);
                println!("  Betrag: {} ATOM  ({:.6} ATL)", amount, amount as f64 / 1e12);
                println!("  Fee:    {} ATOM", fee);
                println!("  Nonce:  {}", nonce);
                println!("  Hash:   {}", tx_hash.as_hex());
                println!("  Status: {}", resp["status"].as_str().unwrap_or("accepted"));

            } else {
                // ── L1-Pfad (explizit via --l1) ──────────────────────────────
                let fee_str = get_flag(&args, "--fee").unwrap_or("100".to_string());
                let amount  = Amount::from_atom(amount_str.parse::<u128>()?);
                let fee     = Amount::from_atom(fee_str.parse::<u128>()?);
                let to      = Address::from_hex(&to_addr)?;

                let kp     = key.keypair(password.as_bytes())?;
                let change = kp.address;
                let client = RpcClient::new(&cfg.node_rpc_url, cfg.node_api_key.clone());
                let utxos  = client.get_utxos(&from_addr).await?;

                if utxos.is_empty() {
                    anyhow::bail!("Keine UTXOs für Adresse {}", from_addr);
                }
                let balance: u128 = utxos.iter().map(|u| u.value).sum();
                if balance < amount.as_atom() + fee.as_atom() {
                    anyhow::bail!(
                        "Zu wenig Guthaben: {} ATOM verfügbar, {} ATOM benötigt",
                        balance, amount.as_atom() + fee.as_atom()
                    );
                }

                let selected = select_utxos(&utxos, amount.as_atom() + fee.as_atom());
                let tx       = build_transfer(&selected, to, amount, fee, change, &kp)?;
                let tx_bytes = bincode::serialize(&tx)?;
                let txid     = client.send_raw_tx(&hex::encode(tx_bytes)).await?;

                println!("✓ L1-Transfer gesendet:");
                println!("  TXID: {}", txid);
            }
        }

        "send-pq" => {
            // Post-Quantum immer L1
            let from_addr = get_flag(&args, "--from")
                .ok_or_else(|| anyhow::anyhow!("--from <ATLQ:address> required"))?;
            let to_addr = get_flag(&args, "--to")
                .ok_or_else(|| anyhow::anyhow!("--to <address> required"))?;
            let amount_str = get_flag(&args, "--amount")
                .ok_or_else(|| anyhow::anyhow!("--amount <ATOM> required"))?;
            let fee_str = get_flag(&args, "--fee").unwrap_or("100".to_string());

            let password = prompt_password_or_cli(&cli_password)?;
            let ks  = Keystore::open(&wallet_path)?;
            let key = ks.get_by_address(&from_addr)
                .ok_or_else(|| anyhow::anyhow!("Adresse '{}' nicht in Wallet", from_addr))?;
            let kp        = key.pq_keypair(password.as_bytes())?;
            let amount    = Amount::from_atom(amount_str.parse::<u128>()?);
            let fee       = Amount::from_atom(fee_str.parse::<u128>()?);
            let change_to = OutputAddress::Quantum(kp.address);

            let recipient: OutputAddress = if to_addr.starts_with("ATLQ:") {
                OutputAddress::Quantum(PqAddress::from_hex(&to_addr)
                    .map_err(|e| anyhow::anyhow!("Ungültige ATLQ-Adresse: {}", e))?)
            } else {
                OutputAddress::Classic(Address::from_hex(&to_addr)?)
            };

            let client = RpcClient::new(&cfg.node_rpc_url, cfg.node_api_key.clone());
            let utxos  = client.get_utxos(&from_addr).await?;

            if utxos.is_empty() { anyhow::bail!("Keine UTXOs für Adresse {}", from_addr); }
            let balance: u128 = utxos.iter().map(|u| u.value).sum();
            if balance < amount.as_atom() + fee.as_atom() {
                anyhow::bail!("Zu wenig Guthaben: {} ATOM", balance);
            }

            let selected = select_utxos(&utxos, amount.as_atom() + fee.as_atom());
            let tx       = build_transfer_quantum(&selected, recipient, amount, fee, change_to, &kp)?;
            let tx_bytes = bincode::serialize(&tx)?;
            let txid     = client.send_raw_tx(&hex::encode(tx_bytes)).await?;

            println!("✓ PQ-Transfer gesendet!");
            println!("  TXID: {}", txid);
        }

        // ── L2-Befehle (explizit) ─────────────────────────────────────────────

        "l2-send" => {
            let from_str = get_flag(&args, "--from")
                .ok_or_else(|| anyhow::anyhow!("--from <address> required"))?;
            let to_str = get_flag(&args, "--to")
                .ok_or_else(|| anyhow::anyhow!("--to <address> required"))?;
            let amount_str = get_flag(&args, "--amount")
                .ok_or_else(|| anyhow::anyhow!("--amount <ATOM> required"))?;
            let fee_str = get_flag(&args, "--fee")
                .unwrap_or(cfg.l2_fee_atom.to_string());
            let nonce: u64 = get_flag(&args, "--nonce")
                .and_then(|n| n.parse().ok())
                .unwrap_or_else(|| next_nonce(&from_str));
            let agg_url = cfg.aggregator_url.clone();

            let amount = amount_str.parse::<u128>()?;
            let fee    = fee_str.parse::<u128>()?;
            let to     = Address::from_hex(&to_str)?;

            let password = prompt_password_or_cli(&cli_password)?;
            let ks  = Keystore::open(&wallet_path)?;
            let key = ks.get_by_address(&from_str)
                .ok_or_else(|| anyhow::anyhow!("Adresse '{}' nicht in Wallet", from_str))?;
            let kp = key.keypair(password.as_bytes())?;
            let l2_kp = EddsaKeypair::from_secret_bytes(&kp.secret_bytes());
            let (from, pubkey, sig) =
                build_l2_eddsa(&l2_kp, &to.0, amount, fee, nonce);
            let tx      = L2Transaction::from_parts(
                Address(from), to, amount, fee, nonce, pubkey, sig);
            let tx_hash = tx.hash();

            let tx_json = serde_json::to_string(&tx)?;
            let result  = l2_http_post(&agg_url, "/submit", &tx_json).await?;
            let resp: serde_json::Value = serde_json::from_str(&result)?;

            if let Some(err) = resp.get("error") {
                anyhow::bail!("Aggregator rejected TX: {}", err);
            }
            persist_nonce(&from_str, nonce);

            println!("L2-TX erstellt:");
            println!("  Von:    ATL:{}", from_str);
            println!("  An:     ATL:{}", to_str);
            println!("  Betrag: {} ATOM", amount);
            println!("  Fee:    {} ATOM", fee);
            println!("  Nonce:  {}", nonce);
            println!("  Hash:   {}", tx_hash.as_hex());
            println!("\n✓ L2-TX akzeptiert:");
            println!("  TX-Hash:  {}", resp["tx_hash"].as_str().unwrap_or(&tx_hash.as_hex()));
            println!("  Status:   {}", resp["status"].as_str().unwrap_or("accepted"));
        }

        "l2-address" => {
            let from_str = get_flag(&args, "--from")
                .ok_or_else(|| anyhow::anyhow!("--from <address> required"))?;
            let password = prompt_password_or_cli(&cli_password)?;
            let ks  = Keystore::open(&wallet_path)?;
            let key = ks.get_by_address(&from_str)
                .ok_or_else(|| anyhow::anyhow!("Adresse '{}' nicht in Wallet", from_str))?;
            let kp = key.keypair(password.as_bytes())?;
            let l2_kp = EddsaKeypair::from_secret_bytes(&kp.secret_bytes());
            let l2_addr = l2_kp.public().address20();

            println!("L2-Adresse (Baby-Jubjub EdDSA):");
            println!("  L1-Schlüssel: ATL:{}", from_str);
            println!("  L2-Adresse:   {}", hex::encode(l2_addr));
        }

        "l2-status" => {
            let batch_id = args.get(2)
                .ok_or_else(|| anyhow::anyhow!("Usage: l2-status <BATCH_ID>"))?;
            let agg_url  = cfg.aggregator_url.clone();

            let path   = format!("/batch/{}", batch_id);
            let result = l2_http_get(&agg_url, &path).await?;
            let resp: serde_json::Value = serde_json::from_str(&result)?;

            if let Some(err) = resp.get("error") {
                anyhow::bail!("Aggregator error: {}", err);
            }

            println!("Batch-Status:");
            println!("  ID:   {}", resp["batch_id"].as_str().unwrap_or(batch_id));
            println!("  TXs:  {}", resp["tx_count"].as_u64().unwrap_or(0));
            println!("  Fees: {} ATOM", resp["total_fees"].as_u64().unwrap_or(0));
            if let Some(status) = resp.get("status") {
                if status.is_object() {
                    if let Some(txid) = status.get("Submitted").and_then(|s| s.get("txid")) {
                        println!("  Status: ✓ On-chain (txid: {})", txid.as_str().unwrap_or("?"));
                    } else if let Some(reason) = status.get("Failed").and_then(|s| s.get("reason")) {
                        println!("  Status: ✗ Failed: {}", reason.as_str().unwrap_or("?"));
                    } else {
                        println!("  Status: {} (Proving)", status);
                    }
                } else {
                    println!("  Status: {}", status.as_str().unwrap_or("?"));
                }
            }
        }

        // ── Config-Verwaltung ────────────────────────────────────────────────
        "config" => {
            let sub = args.get(2).map(|s| s.as_str()).unwrap_or("show");
            let conf_path = dirs_config_path();

            match sub {
                "show" => {
                    println!("Konfigurationsdatei: {}", conf_path.display());
                    println!("{}", serde_json::to_string_pretty(&cfg)?);
                    println!("\nL2-Modus aktiv: {}", via_l2);
                    println!("Nonces-Datei:    {}", nonces_path().display());
                    if let Ok(nonces) = std::fs::read_to_string(nonces_path()) {
                        println!("Gespeicherte Nonces:\n{}", nonces);
                    }
                }
                "set" => {
                    let key = args.get(3).ok_or_else(|| anyhow::anyhow!("Usage: config set <KEY> <VALUE>"))?;
                    let val = args.get(4).ok_or_else(|| anyhow::anyhow!("Usage: config set <KEY> <VALUE>"))?;

                    // Bestehende Config laden oder Default
                    let mut existing: serde_json::Value = std::fs::read_to_string(&conf_path)
                        .ok()
                        .and_then(|s| serde_json::from_str(&s).ok())
                        .unwrap_or_else(|| serde_json::to_value(&WalletConfig::default()).unwrap());

                    // Wert setzen
                    let typed_val: serde_json::Value = match val.as_str() {
                        "true"  => serde_json::Value::Bool(true),
                        "false" => serde_json::Value::Bool(false),
                        other   => if let Ok(n) = other.parse::<u64>() {
                            serde_json::Value::Number(n.into())
                        } else {
                            serde_json::Value::String(other.to_string())
                        },
                    };
                    existing[key.as_str()] = typed_val;

                    if let Some(parent) = conf_path.parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    std::fs::write(&conf_path, serde_json::to_string_pretty(&existing)?)?;
                    println!("✓ Config gesetzt: {} = {}", key, val);
                    println!("  Gespeichert in: {}", conf_path.display());
                }
                "init" => {
                    // Erstellt eine Default-Config für diesen Server
                    if let Some(parent) = conf_path.parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    let default = WalletConfig::default();
                    std::fs::write(&conf_path, serde_json::to_string_pretty(&default)?)?;
                    println!("✓ Standard-Config erstellt: {}", conf_path.display());
                    println!("{}", serde_json::to_string_pretty(&default)?);
                }
                _ => println!("Usage: config [show|set <KEY> <VALUE>|init]"),
            }
        }

        _ => print_help(),
    }

    Ok(())
}

// ── L2 HTTP-Hilfsfunktionen ───────────────────────────────────────────────────

async fn l2_http_post(base_url: &str, path: &str, body: &str) -> anyhow::Result<String> {
    let addr = parse_host_port(base_url)?;
    let mut stream = tokio::net::TcpStream::connect(&addr).await
        .map_err(|e| anyhow::anyhow!("Verbindung zu {} fehlgeschlagen: {}", addr, e))?;

    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        path, addr, body.len(), body
    );
    tokio::io::AsyncWriteExt::write_all(&mut stream, request.as_bytes()).await?;
    let mut response = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut response).await?;
    extract_http_body(&String::from_utf8_lossy(&response))
}

async fn l2_http_get(base_url: &str, path: &str) -> anyhow::Result<String> {
    let addr = parse_host_port(base_url)?;
    let mut stream = tokio::net::TcpStream::connect(&addr).await
        .map_err(|e| anyhow::anyhow!("Verbindung zu {} fehlgeschlagen: {}", addr, e))?;

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        path, addr
    );
    tokio::io::AsyncWriteExt::write_all(&mut stream, request.as_bytes()).await?;
    let mut response = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut response).await?;
    extract_http_body(&String::from_utf8_lossy(&response))
}

fn extract_http_body(response: &str) -> anyhow::Result<String> {
    let idx = response.find("\r\n\r\n")
        .ok_or_else(|| anyhow::anyhow!("Ungültige HTTP-Antwort"))?;
    Ok(response[idx + 4..].to_string())
}

fn parse_host_port(url: &str) -> anyhow::Result<String> {
    let url = url.trim_start_matches("http://").trim_start_matches("https://");
    Ok(url.split('/').next().unwrap_or(url).to_string())
}

// ── Hilfsfunktionen ───────────────────────────────────────────────────────────

fn select_utxos(utxos: &[UtxoInfo], needed: u128) -> Vec<UtxoInfo> {
    let mut sorted = utxos.to_vec();
    sorted.sort_by_key(|u| std::cmp::Reverse(u.value));
    let mut selected = Vec::new();
    let mut total = 0u128;
    for u in sorted {
        if total >= needed { break; }
        total += u.value;
        selected.push(u);
    }
    selected
}

fn get_flag(args: &[String], flag: &str) -> Option<String> {
    args.windows(2)
        .find(|w| w[0] == flag)
        .map(|w| w[1].clone())
}

#[allow(dead_code)]
fn prompt_password() -> anyhow::Result<Zeroizing<String>> {
    let pw = rpassword::prompt_password("Wallet-Passwort: ")?;
    Ok(Zeroizing::new(pw))
}

fn prompt_password_or_cli(cli: &Option<String>) -> anyhow::Result<Zeroizing<String>> {
    if let Some(pw) = cli { return Ok(Zeroizing::new(pw.clone())); }
    Ok(Zeroizing::new(rpassword::prompt_password("Wallet-Passwort: ")?))
}

fn prompt_password_confirm_or_cli(cli: &Option<String>) -> anyhow::Result<Zeroizing<String>> {
    if let Some(pw) = cli { return Ok(Zeroizing::new(pw.clone())); }
    let pw1 = rpassword::prompt_password("Neues Wallet-Passwort: ")?;
    let pw2 = rpassword::prompt_password("Passwort bestätigen:   ")?;
    if pw1 != pw2 { anyhow::bail!("Passwörter stimmen nicht überein"); }
    Ok(Zeroizing::new(pw1))
}

fn print_help() {
    println!("\n=== ATLAS Wallet v{} ===", env!("CARGO_PKG_VERSION"));
    println!("\n[Standard: Transaktionen laufen über L2 — schnell, gebührengünstig, kein UTXO nötig]");
    println!("\nBefehle:");
    println!("  new-key     [--label NAME] [--wallet FILE]     Neuen ECDSA-Schlüssel erstellen");
    println!("  new-key-pq  [--label NAME] [--wallet FILE]     Neuen PQ-Schlüssel erstellen");
    println!("  import-key  --privkey HEX [--label NAME]       Schlüssel importieren");
    println!("  list-keys   [--wallet FILE]                    Alle Schlüssel anzeigen");
    println!("  balance     <ADDRESS> [--rpc URL]              Kontostand abfragen");
    println!("  send        --from <ADDR> --to <ADDR>          Transfer senden [default: L2]");
    println!("              --amount <ATOM>                    [--via-l2 | --l1] [--nonce N]");
    println!("              [--fee <ATOM>]                     [--aggregator URL]");
    println!("  send-pq     --from <ATLQ:ADDR> --to <ADDR>    PQ-Transfer (L1)");
    println!("              --amount <ATOM> [--fee <ATOM>]");
    println!("  height      [--rpc URL]                        Chain-Höhe");
    println!("  l2-send     --from --to --amount [--fee]       L2-TX explizit");
    println!("              [--nonce N] [--aggregator URL]");
    println!("  l2-status   <BATCH_ID>                         Batch-Status");
    println!("  l2-address  --from <ATL-Adresse>               Abgeleitete L2-Adresse");
    println!("  config      show | set <KEY> <VALUE> | init    Konfiguration");
    println!("\nL2-Steuerung:");
    println!("  --via-l2           L2 erzwingen (auch wenn L1 default)");
    println!("  --l1               L1 erzwingen (direkt an Node)");
    println!("  ATLAS_VIA_L2=0/1   Env-Variable (überschreibt Config)");
    println!("  config set default_via_l2 true   Permanent L2 als Default");
    println!("\nOptionen:");
    println!("  --wallet     FILE   Wallet-Datei  (default: wallet.json)");
    println!("  --rpc        URL    Node RPC       (default: http://127.0.0.1:18334)");
    println!("  --aggregator URL    L2 Aggregator  (default: http://127.0.0.1:8080)");
    println!("  --api-key    KEY    RPC API-Key");
    println!("  --password   PW     Passwort (Scripting — nicht für Produktion)");
    println!();
}
