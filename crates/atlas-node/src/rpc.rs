//! JSON-RPC 2.0 Server (HTTP/TCP)
//!
//! Methoden:
//!  Kette:
//!    getblockcount          → Kettenhöhe (u64)
//!    getbestblockhash       → Tip-Hash (hex-string)
//!    getchaininfo           → Übersicht über die Kette
//!    getblock <hash|height> → Vollständiger Block als JSON
//!    getblockheader <hash>  → Nur Block-Header als JSON
//!    gettransaction <txid>  → Transaktion aus Block oder Mempool
//!  Wallet:
//!    getbalance <address>   → Saldo (ATL/ATOM)
//!    getutxos <address>     → Alle UTXOs einer Adresse (ATL: und ATLQ:)
//!  Mempool:
//!    getmempoolinfo         → Mempool-Statistiken
//!    getrawmempool          → Alle TXIDs im Mempool
//!    sendrawtransaction <hex> → TX einreichen
//!  Netzwerk:
//!    getpeers               → verbundene Peers + Höhen
//!    getnetworkinfo         → Netzwerk-Übersicht
//!  L2 Settlement:
//!    submitbatch            → ZK-Proof für Settlement-Batch einreichen
//!    getbatchinfo           → L2 Settlement Status

use crate::chain::ChainManager;
use crate::p2p::P2pNetwork;
use crate::zk_stub::ZkVerifier;
use atlas_core::crypto::Address;
use atlas_core::pq_crypto::PqAddress;
use atlas_core::hash::Hash;
use atlas_mempool::mempool::Mempool;
use atlas_state::state_db::StateDb;
use dashmap::DashMap;
use serde_json::{json, Value};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{debug, info, warn};

/// Token-Bucket-Eintrag pro IP
struct RateBucket {
    tokens:      f64,
    last_refill: Instant,
}

impl RateBucket {
    fn new(capacity: f64) -> Self {
        RateBucket { tokens: capacity, last_refill: Instant::now() }
    }

    fn try_consume(&mut self, rate_per_sec: f64, capacity: f64) -> bool {
        let now     = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * rate_per_sec).min(capacity);
        self.last_refill = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

pub struct RpcServer {
    chain:        Arc<ChainManager>,
    state:        Arc<StateDb>,
    mempool:      Arc<Mempool>,
    p2p:          Option<Arc<P2pNetwork>>,
    api_key:      Option<String>,
    rate_buckets: Arc<DashMap<IpAddr, RateBucket>>,
    /// Im Testnet/Regtest wird ZK-Verifikation übersprungen (Proof-Format gilt als vertrauenswürdig)
    test_mode:    bool,
}

/// Normales Rate-Limit für externe Clients (public RPC)
const RATE_CAPACITY:      f64 = 60.0;
const RATE_PER_SEC:       f64 = 1.0;
/// Erhöhtes Limit für localhost — Aggregator sendet viele submitbatch-Calls
const RATE_CAPACITY_LOCAL: f64 = 10_000.0;
const RATE_PER_SEC_LOCAL:  f64 = 1_000.0;

impl RpcServer {
    pub fn new(
        chain:     Arc<ChainManager>,
        state:     Arc<StateDb>,
        mempool:   Arc<Mempool>,
        p2p:       Option<Arc<P2pNetwork>>,
        api_key:   Option<String>,
        test_mode: bool,
    ) -> Arc<Self> {
        Arc::new(RpcServer {
            chain, state, mempool, p2p, api_key,
            rate_buckets: Arc::new(DashMap::new()),
            test_mode,
        })
    }

    pub async fn start(self: Arc<Self>, bind_addr: &str) -> anyhow::Result<()> {
        let listener = TcpListener::bind(bind_addr).await?;
        info!("JSON-RPC listening on http://{}", bind_addr);

        let buckets = self.rate_buckets.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(300));
            loop {
                interval.tick().await;
                buckets.retain(|_, b| b.tokens < RATE_CAPACITY - 0.1);
            }
        });

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        let ip  = addr.ip();
                        let srv = self.clone();

                        // Localhost (Aggregator) bekommt deutlich höheres Rate-Limit
                        let is_local = ip.is_loopback();
                        let (capacity, rate) = if is_local {
                            (RATE_CAPACITY_LOCAL, RATE_PER_SEC_LOCAL)
                        } else {
                            (RATE_CAPACITY, RATE_PER_SEC)
                        };

                        let allowed = {
                            let mut bucket = srv.rate_buckets
                                .entry(ip)
                                .or_insert_with(|| RateBucket::new(capacity));
                            bucket.try_consume(rate, capacity)
                        };

                        if !allowed {
                            warn!("RPC rate limit exceeded for {}", ip);
                            drop(stream);
                            continue;
                        }

                        debug!("RPC connection from {}", addr);
                        tokio::spawn(async move {
                            if let Err(e) = srv.handle_client(stream).await {
                                debug!("RPC client error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        warn!("RPC accept error: {}", e);
                        break;
                    }
                }
            }
        });
        Ok(())
    }

    async fn handle_client(&self, stream: tokio::net::TcpStream) -> anyhow::Result<()> {
        let (reader, mut writer) = stream.into_split();
        let mut buf_reader = tokio::io::BufReader::new(reader);

        let mut content_length  = 0usize;
        let mut auth_ok         = self.api_key.is_none();
        let mut header_bytes    = 0usize;
        let mut line            = String::new();
        let mut http_method     = String::new();
        let mut first_line      = true;

        const MAX_HEADER_BYTES: usize = 8 * 1024;

        loop {
            line.clear();
            buf_reader.read_line(&mut line).await?;
            header_bytes += line.len();
            if header_bytes > MAX_HEADER_BYTES {
                send_http_error(&mut writer, 431, "Request Header Fields Too Large").await?;
                return Ok(());
            }
            let trimmed = line.trim();
            if first_line {
                http_method = trimmed.split_whitespace().next().unwrap_or("").to_ascii_uppercase();
                first_line = false;
            }
            if trimmed.is_empty() { break; }
            let lower = trimmed.to_ascii_lowercase();
            if lower.starts_with("content-length:") {
                content_length = trimmed
                    .split(':')
                    .nth(1)
                    .and_then(|s| s.trim().parse().ok())
                    .unwrap_or(0);
            } else if lower.starts_with("authorization:") {
                if let Some(ref key) = self.api_key {
                    if let Some(rest) = lower.strip_prefix("authorization:") {
                        if let Some(token_lower) = rest.trim().strip_prefix("bearer ") {
                            let original_rest = &trimmed[trimmed.to_ascii_lowercase()
                                .find("bearer ")
                                .map(|i| i + 7)
                                .unwrap_or(trimmed.len())..];
                            if constant_time_eq(original_rest.trim(), key) {
                                let _ = token_lower;
                                auth_ok = true;
                            }
                        }
                    }
                }
            }
        }

        // CORS-Preflight (Browser-Wallet/Tooling): ohne Auth/Body beantworten.
        if http_method == "OPTIONS" {
            let resp = "HTTP/1.1 204 No Content\r\n\
                Access-Control-Allow-Origin: *\r\n\
                Access-Control-Allow-Methods: POST, GET, OPTIONS\r\n\
                Access-Control-Allow-Headers: Content-Type, Authorization\r\n\
                Access-Control-Max-Age: 86400\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            writer.write_all(resp.as_bytes()).await?;
            return Ok(());
        }

        if !auth_ok {
            send_http_error(&mut writer, 401, "Unauthorized").await?;
            return Ok(());
        }
        if content_length == 0 || content_length > 1_000_000 {
            send_http_error(&mut writer, 400, "Bad Request").await?;
            return Ok(());
        }

        let mut body = vec![0u8; content_length];
        tokio::io::AsyncReadExt::read_exact(&mut buf_reader, &mut body).await?;

        let request: Value = match serde_json::from_slice(&body) {
            Ok(v)  => v,
            Err(_) => {
                send_json_error(&mut writer, Value::Null, -32700, "Parse error").await?;
                return Ok(());
            }
        };

        let response = self.dispatch(&request).await;
        let resp_str = serde_json::to_string(&response)?;

        let http = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{}",
            resp_str.len(), resp_str,
        );
        writer.write_all(http.as_bytes()).await?;
        Ok(())
    }

    async fn dispatch(&self, req: &Value) -> Value {
        let id     = req.get("id").cloned().unwrap_or(Value::Null);
        let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("");
        let params = req.get("params").cloned().unwrap_or(json!([]));

        match self.call(method, &params).await {
            Ok(result) => json!({ "jsonrpc": "2.0", "result": result, "id": id }),
            Err((code, msg)) => json!({
                "jsonrpc": "2.0",
                "error":   { "code": code, "message": msg },
                "id":      id,
            }),
        }
    }

    async fn call(&self, method: &str, params: &Value) -> Result<Value, (i64, String)> {
        match method {

            // ── Kette ────────────────────────────────────────────────────────

            "getblockcount" => Ok(json!(self.chain.height())),

            "getbestblockhash" => Ok(json!(self.chain.best_hash().as_hex())),

            "getchaininfo" => {
                let chain = self.state.chain.read();
                Ok(json!({
                    "height":         chain.height,
                    "best_hash":      chain.best_hash.as_hex(),
                    "total_supply":   chain.total_supply.as_atl_decimal(),
                    "total_txs":      chain.total_txs,
                    "current_bits":   format!("{:#010x}", chain.current_bits),
                    "security_delay": chain.security_delay,
                    "avg_fee_atom":   chain.avg_fees.as_atom().to_string(),
                }))
            }

            // getblock <hash_hex | height>  (Alias: getblockbyheight)
            "getblock" | "getblockbyheight" => {
                let param = params.get(0)
                    .ok_or((-32602, "Missing hash or height param".to_string()))?;

                let block = if let Some(s) = param.as_str() {
                    // Hash als Hex-String
                    let hash = atlas_core::hash::Hash::from_hex(s)
                        .map_err(|e| (-32602, format!("Invalid hash: {}", e)))?;
                    self.state.get_block(&hash)
                        .or_else(|| self.chain.storage_arc().as_ref()
                            .and_then(|s| s.load_block(&hash).ok().flatten()))
                        .ok_or((-32603, format!("Block not found: {}", s)))?
                } else if let Some(height) = param.as_u64() {
                    // Nach Höhe
                    let block = self.chain.storage_arc().as_ref()
                        .and_then(|s| s.load_block_by_height(height).ok().flatten());
                    match block {
                        Some(b) => b,
                        None => {
                            // Fallback: aus recent_headers
                            let hash = {
                                let chain = self.state.chain.read();
                                chain.recent_headers.iter()
                                    .find(|h| h.height == height)
                                    .map(|h| h.hash())
                            };
                            hash.and_then(|h| self.state.get_block(&h))
                                .ok_or((-32603, format!("Block at height {} not found", height)))?
                        }
                    }
                } else {
                    return Err((-32602, "Param must be hash string or height number".to_string()));
                };

                Ok(block_to_json(&block))
            }

            "getblockheader" => {
                let hash_str = params.get(0)
                    .and_then(|v| v.as_str())
                    .ok_or((-32602, "Missing hash param".to_string()))?;
                let hash = atlas_core::hash::Hash::from_hex(hash_str)
                    .map_err(|e| (-32602, format!("Invalid hash: {}", e)))?;

                let header = {
                    let chain = self.state.chain.read();
                    chain.recent_headers.iter().find(|h| h.hash() == hash).cloned()
                };
                let header = header.ok_or((-32603, "Header not found in recent window".to_string()))?;
                Ok(header_to_json(&header))
            }

            // gettransaction <txid_hex>
            "gettransaction" => {
                let txid_str = params.get(0)
                    .and_then(|v| v.as_str())
                    .ok_or((-32602, "Missing txid param".to_string()))?;
                let txid = atlas_core::hash::Hash::from_hex(txid_str)
                    .map_err(|e| (-32602, format!("Invalid txid: {}", e)))?;

                // 1. Im Mempool suchen
                if let Some(tx) = self.mempool.get_tx(&txid) {
                    return Ok(json!({
                        "txid":        txid_str,
                        "confirmations": 0,
                        "in_mempool":  true,
                        "tx":          tx_to_json(&tx),
                    }));
                }

                // 2. Im TX-Index suchen (Storage)
                if let Some(storage) = self.chain.storage_arc() {
                    if let Ok(Some((height, pos))) = storage.find_tx(&txid) {
                        if let Ok(Some(block)) = storage.load_block_by_height(height) {
                            if let Some(tx) = block.transactions.get(pos as usize) {
                                let tip = self.chain.height();
                                return Ok(json!({
                                    "txid":          txid_str,
                                    "confirmations": tip.saturating_sub(height) + 1,
                                    "in_mempool":    false,
                                    "block_hash":    block.hash().as_hex(),
                                    "block_height":  height,
                                    "block_index":   pos,
                                    "tx":            tx_to_json(tx),
                                }));
                            }
                        }
                    }
                }

                Err((-32603, format!("Transaction not found: {}", txid_str)))
            }

            // ── Wallet ───────────────────────────────────────────────────────

            // getbalance <address>  — ATL: oder ATLQ: Adressen
            "getbalance" => {
                let addr_str = params.get(0)
                    .and_then(|v| v.as_str())
                    .ok_or((-32602, "Missing address param".to_string()))?;

                let balance = if addr_str.starts_with("ATLQ:") {
                    let addr = PqAddress::from_hex(addr_str)
                        .map_err(|e| (-32602, format!("Invalid ATLQ address: {}", e)))?;
                    self.state.utxo_set.balance_pq(&addr)
                } else {
                    let addr = Address::from_hex(addr_str)
                        .map_err(|e| (-32602, format!("Invalid address: {}", e)))?;
                    self.state.utxo_set.balance(&addr)
                };

                Ok(json!({
                    "address":      addr_str,
                    "balance_atom": balance.as_atom().to_string(),
                    "balance_atl":  balance.as_atl_decimal(),
                }))
            }

            // getutxos <address>  — ATL: oder ATLQ: Adressen
            "getutxos" => {
                let addr_str = params.get(0)
                    .and_then(|v| v.as_str())
                    .ok_or((-32602, "Missing address param".to_string()))?;

                let utxos = if addr_str.starts_with("ATLQ:") {
                    let addr = PqAddress::from_hex(addr_str)
                        .map_err(|e| (-32602, format!("Invalid ATLQ address: {}", e)))?;
                    self.state.utxo_set.utxos_for_pq_address(&addr)
                } else {
                    let addr = Address::from_hex(addr_str)
                        .map_err(|e| (-32602, format!("Invalid address: {}", e)))?;
                    self.state.utxo_set.utxos_for_address(&addr)
                };

                let result: Vec<Value> = utxos.into_iter().map(|(op, utxo)| json!({
                    "txid":         op.txid.as_hex(),
                    "index":        op.index,
                    "value_atom":   utxo.value.as_atom().to_string(),
                    "value_atl":    utxo.value.as_atl_decimal(),
                    "block_height": utxo.block_height,
                    "is_coinbase":  utxo.is_coinbase,
                })).collect();
                Ok(json!(result))
            }

            // ── Mempool ──────────────────────────────────────────────────────

            "getmempoolinfo" => {
                let stats = self.mempool.stats();
                Ok(json!({
                    "tx_count":     stats.tx_count,
                    "total_fees":   stats.total_fees.as_atom().to_string(),
                    "avg_fee_atom": stats.avg_fee_atom.to_string(),
                    "min_fee_atom": stats.min_fee_atom.to_string(),
                    "max_fee_atom": stats.max_fee_atom.to_string(),
                    "bid_count":    stats.bid_count,
                }))
            }

            "getrawmempool" => {
                let txs = self.mempool.dump_txs();
                let txids: Vec<String> = txs.iter().map(|tx| tx.txid().as_hex()).collect();
                Ok(json!(txids))
            }

            "sendrawtransaction" => {
                let hex = params.get(0)
                    .and_then(|v| v.as_str())
                    .ok_or((-32602, "Missing tx hex param".to_string()))?;
                let bytes = hex::decode(hex)
                    .map_err(|e| (-32602, format!("Invalid hex: {}", e)))?;
                let tx: atlas_core::transaction::Transaction = bincode::deserialize(&bytes)
                    .map_err(|e| (-32602, format!("Invalid transaction: {}", e)))?;
                let txid = self.mempool.submit(tx)
                    .map_err(|e| (-32001, format!("TX rejected: {}", e)))?;
                Ok(json!(txid.as_hex()))
            }

            // ── Netzwerk ─────────────────────────────────────────────────────

            "getpeers" => {
                let peers = match &self.p2p {
                    Some(p2p) => p2p.peer_heights().into_iter()
                        .map(|(addr, h)| json!({ "addr": addr.to_string(), "height": h }))
                        .collect::<Vec<_>>(),
                    None => vec![],
                };
                Ok(json!({ "count": peers.len(), "peers": peers }))
            }

            // Bitcoin-kompatibles Pendant zu getpeers — erweiterte Felder
            "getpeerinfo" => {
                let (peers, known_count) = match &self.p2p {
                    Some(p2p) => {
                        let connected = p2p.peer_heights().into_iter()
                            .enumerate()
                            .map(|(i, (addr, height))| json!({
                                "id":              i,
                                "addr":            addr.to_string(),
                                "height":          height,
                                "synced_headers":  height,
                                "synced_blocks":   height,
                                "subver":          format!("atlas/{}", env!("CARGO_PKG_VERSION")),
                                "version":         1,
                                "connection_type": "outbound",
                                "network":         "ipv4",
                            }))
                            .collect::<Vec<_>>();
                        let known = p2p.known_addrs().len();
                        (connected, known)
                    }
                    None => (vec![], 0),
                };
                Ok(json!({
                    "connected": peers.len(),
                    "known_addrs": known_count,
                    "peers": peers,
                }))
            }

            "getnetworkinfo" => {
                let (peer_count, known_count) = match &self.p2p {
                    Some(p2p) => (p2p.peer_count(), p2p.known_addrs().len()),
                    None      => (0, 0),
                };
                Ok(json!({
                    "peer_count":   peer_count,
                    "known_addrs":  known_count,
                    "version":      env!("CARGO_PKG_VERSION"),
                    "protocol":     1,
                    "subver":       format!("atlas/{}", env!("CARGO_PKG_VERSION")),
                    "network":      "testnet",
                }))
            }

            // ── L2 Settlement ─────────────────────────────────────────────────

            // submitbatch — Aggregator reicht ZK-Beweis für einen Settlement-Batch ein.
            //
            // Params: [{
            //   "batch_id":         "<hex>",          // 32-Byte Batch-ID (Merkle-Root der Batch-TXs)
            //   "aggregator":       "<hex-address>",  // Aggregator ATL-Adresse
            //   "tx_count":         <u32>,            // Anzahl TXs im Batch
            //   "proof_bytes":      "<hex>",          // Groth16-Proof (serialisiert)
            //   "pre_state_root":   "<hex>",          // State-Root vor Batch-Ausführung
            //   "post_state_root":  "<hex>",          // State-Root nach Batch-Ausführung
            //   "total_fees_atom":  <u128>,           // Gesamtgebühren im Batch (ATOM)
            //   "batch_merkle":     "<hex>"           // Merkle-Root der Batch-TXs (= batch_id)
            // }]
            //
            // Returns: { "batch_id": "<hex>", "status": "accepted" }
            "submitbatch" => {
                let p = params.get(0)
                    .ok_or((-32602, "Missing batch params".to_string()))?;

                // Parameter parsen
                let batch_id_hex = p["batch_id"].as_str()
                    .ok_or((-32602, "Missing batch_id".to_string()))?;
                let aggregator_hex = p["aggregator"].as_str()
                    .ok_or((-32602, "Missing aggregator".to_string()))?;
                let tx_count = p["tx_count"].as_u64()
                    .ok_or((-32602, "Missing tx_count".to_string()))? as u32;
                let proof_hex = p["proof_bytes"].as_str()
                    .ok_or((-32602, "Missing proof_bytes".to_string()))?;
                let pre_root_hex = p["pre_state_root"].as_str()
                    .ok_or((-32602, "Missing pre_state_root".to_string()))?;
                let post_root_hex = p["post_state_root"].as_str()
                    .ok_or((-32602, "Missing post_state_root".to_string()))?;
                let total_fees = p["total_fees_atom"].as_u64()
                    .ok_or((-32602, "Missing total_fees_atom".to_string()))? as u128;
                let batch_merkle_hex = p["batch_merkle"].as_str()
                    .unwrap_or(batch_id_hex);

                // Typen konvertieren
                let batch_id   = Hash::from_hex(batch_id_hex)
                    .map_err(|e| (-32602, format!("Invalid batch_id: {}", e)))?;
                let aggregator = Address::from_hex(aggregator_hex)
                    .map_err(|e| (-32602, format!("Invalid aggregator: {}", e)))?;
                let proof_bytes = hex::decode(proof_hex)
                    .map_err(|e| (-32602, format!("Invalid proof_bytes: {}", e)))?;
                let pre_state_root = Hash::from_hex(pre_root_hex)
                    .map_err(|e| (-32602, format!("Invalid pre_state_root: {}", e)))?;
                let post_state_root = Hash::from_hex(post_root_hex)
                    .map_err(|e| (-32602, format!("Invalid post_state_root: {}", e)))?;
                let batch_merkle = Hash::from_hex(batch_merkle_hex)
                    .map_err(|e| (-32602, format!("Invalid batch_merkle: {}", e)))?;
                // Data-Availability-Calldata (optional; im test_mode i.d.R. leer).
                let calldata = match p["calldata"].as_str() {
                    Some(h) if !h.is_empty() => hex::decode(h)
                        .map_err(|e| (-32602, format!("Invalid calldata: {}", e)))?,
                    _ => Vec::new(),
                };
                // Forced-Rejection-Zeugen (optional): Aggregator lehnt nicht
                // anwendbare Forced-TXs nachweislich ab.
                let forced_rejections = parse_forced_rejections(p)
                    .map_err(|e| (-32602, e))?;
                let total_fees_amount = atlas_core::amount::Amount::from_atom(total_fees);

                // Soundness-tragenden State-Transition-Beweis verifizieren.
                // batch_merkle dient als batch_commitment (Data-Availability-Bindung).
                let _ = tx_count; // nur informativ in der RPC-Antwort
                let zk = ZkVerifier::new(self.test_mode);
                zk.verify_state_bid(
                    &proof_bytes,
                    pre_state_root.as_bytes(),
                    post_state_root.as_bytes(),
                    total_fees,
                    batch_merkle.as_bytes(),
                ).map_err(|e| (-32003, format!("ZK state proof rejected: {}", e)))?;

                // Data Availability: schon beim Mempool-Eintritt prüfen, dass die
                // Calldata zum batch_commitment passt (frühe Ablehnung; außer test_mode).
                if !self.test_mode {
                    let txs = atlas_zk::l2_state::decode_calldata(&calldata)
                        .map_err(|e| (-32004, format!("Invalid DA calldata: {}", e)))?;
                    if txs.len() > atlas_zk::L2_BATCH_SIZE {
                        return Err((-32004, format!(
                            "calldata enthält {} TXs > Kapazität {}",
                            txs.len(), atlas_zk::L2_BATCH_SIZE
                        )));
                    }
                    let recomputed = atlas_zk::l2_state::batch_commitment_from_inputs(
                        &txs, atlas_zk::L2_BATCH_SIZE,
                    );
                    if recomputed != *batch_merkle.as_bytes() {
                        return Err((-32004,
                            "DA-Bindung verletzt: calldata hasht nicht zum batch_commitment".to_string()));
                    }
                }

                // Als SettlementBid-TX in den Mempool einreichen — der Bid trägt den
                // Beweis und die L2-State-Roots selbst (von Genesis re-verifizierbar).
                // Settlement-Bids benötigen eine minimale Fee und einen TxStamp (Mini-PoW).
                let min_fee = atlas_core::amount::Amount::from_atom(
                    atlas_core::transaction::Transaction::MIN_FEE_ATOM
                );
                let mut bid_tx = atlas_core::transaction::Transaction::new_settlement_bid(
                    batch_id,
                    aggregator,
                    total_fees_amount,
                    pre_state_root,
                    post_state_root,
                    batch_merkle,
                    total_fees,
                    proof_bytes.clone(),
                    calldata,
                    forced_rejections,
                );
                bid_tx.fee = min_fee; // Mindestgebühr setzen (geht an Miner)

                // TxStamp (Mini-PoW) minen — ca. 20-50ms auf Consumer-Hardware
                let stamp_txid = bid_tx.txid();
                let stamp = atlas_core::tx_stamp::TxStamp::mine(
                    &stamp_txid,
                    atlas_core::tx_stamp::TX_STAMP_DIFFICULTY_BITS,
                ).map_err(|e| (-32001, format!("Stamp mining failed: {}", e)))?;
                bid_tx.stamp = Some(stamp);

                let txid = self.mempool.submit(bid_tx)
                    .map_err(|e| (-32001, format!("Bid rejected: {}", e)))?;

                tracing::info!(
                    "Settlement batch accepted: id={} aggregator={} txs={} fees={} ATOM txid={}",
                    &batch_id_hex[..16], aggregator_hex, tx_count,
                    total_fees, txid.as_hex()
                );

                Ok(json!({
                    "batch_id": batch_id_hex,
                    "txid":     txid.as_hex(),
                    "status":   "accepted",
                    "tx_count": tx_count,
                }))
            }

            "getbatchinfo" => {
                let stats = self.mempool.stats();
                let chain = self.state.chain.read();
                Ok(json!({
                    "pending_bids":      stats.bid_count,
                    "max_batches_block": 8,
                    "chain_height":      chain.height,
                    "l2_active":         true,
                }))
            }

            // getl2snapshot — Data-Availability-Snapshot für Aggregator-Resync.
            // Liefert die L2-Root am aktuellen Tip + die konkatenierte Settlement-
            // Calldata ALLER Blöcke (Genesis→Tip), in Block- und TX-Reihenfolge.
            // Der Aggregator spielt sie ab Genesis ab und muss exakt diese Root
            // erreichen → reboot-fester L2-Zustand ohne eigenen Persistenz-Layer.
            "getl2snapshot" => {
                // Optional: nur die Settlement-Calldata der Blöcke > from_height
                // (Delta für den Aggregator-Resync ab einem persistierten Snapshot).
                // from_height >= Tip ⇒ leere Calldata, nur Root/Höhe (billiger Head-Check).
                let from_height = params.get(0).and_then(|v| v.as_u64()).unwrap_or(0);
                // Höhe + Root konsistent unter EINEM Lock lesen.
                let (height, l2_root) = {
                    let chain = self.state.chain.read();
                    (chain.height, chain.l2_state_root)
                };
                // Modell A: pro Block GEORDNET {Settlement-Calldata, Coinbase-
                // Credits}. Der Aggregator spielt je Block erst die Calldata
                // (Transfers) und dann die Coinbase-Gutschriften (Emission) ab und
                // schreibt so seine L2-Root exakt wie der Node fort.
                let mut blocks: Vec<Value> = Vec::new();
                let mut settlements: u64 = 0;
                if let Some(store) = self.chain.storage_arc().as_ref() {
                    for h in from_height.saturating_add(1)..=height {
                        if let Ok(Some(block)) = store.load_block_by_height(h) {
                            let mut cd_all: Vec<u8> = Vec::new();
                            let mut block_has_settle = false;
                            for tx in &block.transactions {
                                if let atlas_core::transaction::TxType::SettlementBid { calldata: cd, .. } = &tx.tx_type {
                                    cd_all.extend_from_slice(cd);
                                    block_has_settle = true;
                                    settlements += 1;
                                }
                            }
                            let credits: Vec<Value> = self.chain
                                .coinbase_credits_of_block(&block)
                                .into_iter()
                                .map(|(a, amt)| json!({ "addr": hex::encode(a), "amount": amt.to_string() }))
                                .collect();
                            blocks.push(json!({
                                "height":         h,
                                // Modell A: ob der Block ein Settlement enthält — maßgeblich
                                // dafür, ob die aufgelaufene Emission hier ausgeschüttet wird.
                                // Ein Heartbeat-Settlement hat LEERE Calldata, ist aber ein
                                // Settlement → darf NICHT als leerer Block gelten.
                                "has_settlement": block_has_settle,
                                "calldata":       hex::encode(&cd_all),
                                "credits":        credits,
                            }));
                        }
                    }
                }
                Ok(json!({
                    "height":        height,
                    "from_height":   from_height,
                    "l2_state_root": l2_root.as_hex(),
                    "settlements":   settlements,
                    "blocks":        blocks,
                }))
            }

            // forcel2tx — Forced Inclusion: signierte L2-TX direkt auf L1 einreichen
            // (Zensurresistenz-Pfad; jeder Helfer kann sie für den User einreichen).
            //
            // Params: [{ "from": "<hex20>", "to": "<hex20>", "amount_atom": <u64>,
            //            "fee_atom": <u64>, "nonce": <u64>, "pubkey": "<hex32>",
            //            "sig": "<hex64>", "sender_index": <u64> }]
            "forcel2tx" => {
                let p = params.get(0)
                    .ok_or((-32602, "Missing forced tx params".to_string()))?;
                let from: [u8; 20] = parse_hex_array(p, "from")?;
                let to:   [u8; 20] = parse_hex_array(p, "to")?;
                let pubkey: [u8; 32] = parse_hex_array(p, "pubkey")?;
                let sig_vec = hex::decode(p["sig"].as_str()
                    .ok_or((-32602, "Missing sig".to_string()))?)
                    .map_err(|e| (-32602, format!("Invalid sig: {}", e)))?;
                let sig: [u8; 64] = sig_vec.as_slice().try_into()
                    .map_err(|_| (-32602, "sig muss 64 Byte sein".to_string()))?;
                let amount_atom = p["amount_atom"].as_u64()
                    .ok_or((-32602, "Missing amount_atom".to_string()))? as u128;
                let fee_atom = p["fee_atom"].as_u64()
                    .ok_or((-32602, "Missing fee_atom".to_string()))? as u128;
                let nonce = p["nonce"].as_u64()
                    .ok_or((-32602, "Missing nonce".to_string()))?;
                let sender_index = p["sender_index"].as_u64()
                    .ok_or((-32602, "Missing sender_index".to_string()))?;

                // Native EdDSA-Prüfung inkl. Adressbindung — Müll sofort abweisen.
                if !atlas_zk::l2_state::verify_l2_eddsa(
                    &from, &to, amount_atom, fee_atom, nonce, &pubkey, &sig,
                ) {
                    return Err((-32005,
                        "EdDSA-Signatur/Adressbindung ungültig".to_string()));
                }
                // Dedup gegen die offene Konsens-Queue.
                {
                    let chain = self.state.chain.read();
                    if chain.forced_queue.iter().any(|e| e.from == from && e.nonce == nonce) {
                        return Err((-32005,
                            "(from, nonce) bereits in der Forced-Queue".to_string()));
                    }
                }

                let min_fee = atlas_core::amount::Amount::from_atom(
                    atlas_core::transaction::Transaction::MIN_FEE_ATOM
                );
                let mut ftx = atlas_core::transaction::Transaction::new_l2_forced_tx(
                    from, to, amount_atom, fee_atom, nonce, pubkey, sig.to_vec(), sender_index,
                );
                ftx.fee = min_fee;
                let stamp_txid = ftx.txid();
                let stamp = atlas_core::tx_stamp::TxStamp::mine(
                    &stamp_txid,
                    atlas_core::tx_stamp::TX_STAMP_DIFFICULTY_BITS,
                ).map_err(|e| (-32001, format!("Stamp mining failed: {}", e)))?;
                ftx.stamp = Some(stamp);

                let txid = self.mempool.submit(ftx)
                    .map_err(|e| (-32001, format!("Forced tx rejected: {}", e)))?;
                tracing::info!(
                    "Forced-Inclusion-TX accepted: from={} nonce={} txid={}",
                    hex::encode(from), nonce, txid.as_hex()
                );
                Ok(json!({ "txid": txid.as_hex(), "status": "accepted" }))
            }

            // getforcedqueue — offene Forced-Inclusion-Einträge (für Aggregatoren).
            "getforcedqueue" => {
                let window = self.chain.consensus_params().forced_inclusion_window;
                let chain  = self.state.chain.read();
                let height = chain.height;
                let entries: Vec<Value> = chain.forced_queue.iter().map(|e| json!({
                    "from":         hex::encode(e.from),
                    "to":           hex::encode(e.to),
                    "amount_atom":  e.amount_atom as u64,
                    "fee_atom":     e.fee_atom as u64,
                    "nonce":        e.nonce,
                    "pubkey":       hex::encode(e.pubkey),
                    "sig":          hex::encode(&e.sig),
                    "sender_index": e.sender_index,
                    "seen_height":  e.seen_height,
                    "due":          e.seen_height.saturating_add(window) < height.saturating_add(1),
                })).collect();
                Ok(json!({
                    "chain_height": height,
                    "window":       window,
                    "entries":      entries,
                }))
            }

            _ => Err((-32601, format!("Method not found: {}", method))),
        }
    }
}

// ── JSON-Hilfsfunktionen ──────────────────────────────────────────────────────

/// Liest ein Hex-Feld fester Länge aus einem JSON-Objekt.
fn parse_hex_array<const N: usize>(p: &Value, key: &str) -> Result<[u8; N], (i64, String)> {
    let s = p[key].as_str()
        .ok_or((-32602, format!("Missing {}", key)))?;
    let v = hex::decode(s)
        .map_err(|e| (-32602, format!("Invalid {}: {}", key, e)))?;
    v.as_slice().try_into()
        .map_err(|_| (-32602, format!("{} muss {} Byte sein", key, N)))
}

/// Parst das optionale `forced_rejections`-Array eines submitbatch-Calls.
fn parse_forced_rejections(
    p: &Value,
) -> Result<Vec<atlas_core::transaction::ForcedRejection>, String> {
    let Some(arr) = p["forced_rejections"].as_array() else {
        return Ok(Vec::new());
    };
    let mut out = Vec::with_capacity(arr.len());
    for r in arr {
        let from: [u8; 20] = parse_hex_array(r, "from").map_err(|(_, e)| e)?;
        let leaf_address: [u8; 20] = if r["leaf_vacant"].as_bool().unwrap_or(false) {
            [0u8; 20]
        } else {
            parse_hex_array(r, "leaf_address").map_err(|(_, e)| e)?
        };
        let siblings_arr = r["siblings"].as_array()
            .ok_or_else(|| "forced_rejection ohne siblings".to_string())?;
        let mut siblings = Vec::with_capacity(siblings_arr.len());
        for s in siblings_arr {
            let h = s.as_str().ok_or_else(|| "sibling muss Hex-String sein".to_string())?;
            let v = hex::decode(h).map_err(|e| format!("Invalid sibling: {}", e))?;
            let b: [u8; 32] = v.as_slice().try_into()
                .map_err(|_| "sibling muss 32 Byte sein".to_string())?;
            siblings.push(b);
        }
        out.push(atlas_core::transaction::ForcedRejection {
            from,
            nonce:        r["nonce"].as_u64().ok_or_else(|| "rejection ohne nonce".to_string())?,
            leaf_address,
            leaf_balance: r["leaf_balance"].as_u64().unwrap_or(0) as u128,
            leaf_nonce:   r["leaf_nonce"].as_u64().unwrap_or(0),
            leaf_vacant:  r["leaf_vacant"].as_bool().unwrap_or(false),
            siblings,
        });
    }
    Ok(out)
}

fn block_to_json(block: &atlas_core::block::Block) -> Value {
    json!({
        "hash":        block.hash().as_hex(),
        "height":      block.height(),
        "version":     block.header.version,
        "prev_hash":   block.header.prev_hash.as_hex(),
        "merkle_root": block.header.merkle_root.as_hex(),
        "timestamp":   block.header.timestamp,
        "bits":        format!("{:#010x}", block.header.bits),
        "nonce":       block.header.nonce,
        "tx_count":    block.transactions.len(),
        "txids":       block.transactions.iter().map(|tx| tx.txid().as_hex()).collect::<Vec<_>>(),
    })
}

fn header_to_json(h: &atlas_core::block::BlockHeader) -> Value {
    json!({
        "hash":        h.hash().as_hex(),
        "height":      h.height,
        "version":     h.version,
        "prev_hash":   h.prev_hash.as_hex(),
        "merkle_root": h.merkle_root.as_hex(),
        "timestamp":   h.timestamp,
        "bits":        format!("{:#010x}", h.bits),
        "nonce":       h.nonce,
    })
}

fn tx_to_json(tx: &atlas_core::transaction::Transaction) -> Value {
    use atlas_core::transaction::OutputAddress;
    json!({
        "txid":      tx.txid().as_hex(),
        "version":   tx.version,
        "fee_atom":  tx.fee.as_atom().to_string(),
        "timestamp": tx.timestamp,
        "type":      format!("{:?}", tx.tx_type),
        "inputs":    tx.inputs.iter().map(|i| json!({
            "prev_txid":  i.prev_txid.as_hex(),
            "prev_index": i.prev_index,
            "sequence":   i.sequence,
            "witness_type": match &i.witness {
                atlas_core::transaction::Witness::Classic { .. } => "ecdsa",
                atlas_core::transaction::Witness::Quantum { .. } => "ml-dsa-65",
            },
        })).collect::<Vec<_>>(),
        "outputs":   tx.outputs.iter().enumerate().map(|(idx, o)| json!({
            "index":      idx,
            "value_atom": o.value.as_atom().to_string(),
            "value_atl":  o.value.as_atl_decimal(),
            "address":    match &o.address {
                OutputAddress::Classic(a) => a.as_hex(),
                OutputAddress::Quantum(a) => a.to_string(),
            },
            "address_type": match &o.address {
                OutputAddress::Classic(_) => "classic",
                OutputAddress::Quantum(_) => "quantum",
            },
        })).collect::<Vec<_>>(),
    })
}

// ── HTTP Helpers ──────────────────────────────────────────────────────────────

async fn send_http_error(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    code:   u16,
    msg:    &str,
) -> anyhow::Result<()> {
    let body = format!("{} {}", code, msg);
    let resp = format!(
        "HTTP/1.1 {} {}\r\nContent-Length: {}\r\n\r\n{}",
        code, msg, body.len(), body
    );
    writer.write_all(resp.as_bytes()).await?;
    Ok(())
}

async fn send_json_error(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    id:     Value,
    code:   i64,
    msg:    &str,
) -> anyhow::Result<()> {
    let body = serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "error": { "code": code, "message": msg },
        "id": id,
    }))?;
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\n\r\n{}",
        body.len(), body
    );
    writer.write_all(resp.as_bytes()).await?;
    Ok(())
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() { return false; }
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
