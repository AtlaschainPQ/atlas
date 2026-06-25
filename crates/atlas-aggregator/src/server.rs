//! HTTP-Server für den Aggregator
//!
//! API:
//!   POST /submit        → L2-TX einreichen
//!   GET  /status        → Aggregator-Status
//!   GET  /batch/<id>    → Batch-Status abfragen
//!
//! Format: JSON über HTTP/1.1

use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tracing::{info, warn};

use crate::aggregator::Aggregator;
use crate::l2_tx::L2Transaction;

pub struct AggregatorServer {
    aggregator: Arc<Aggregator>,
}

impl AggregatorServer {
    pub fn new(aggregator: Arc<Aggregator>) -> Self {
        AggregatorServer { aggregator }
    }

    pub async fn start(&self, bind_addr: &str) -> anyhow::Result<()> {
        let listener = TcpListener::bind(bind_addr).await?;
        info!("Aggregator HTTP server listening on {}", bind_addr);

        let agg = self.aggregator.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, peer)) => {
                        let agg2 = agg.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(stream, agg2).await {
                                warn!("Connection from {} error: {}", peer, e);
                            }
                        });
                    }
                    Err(e) => warn!("Accept error: {}", e),
                }
            }
        });

        Ok(())
    }
}

async fn handle_connection(
    stream: tokio::net::TcpStream,
    agg:    Arc<Aggregator>,
) -> anyhow::Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    // Request-Line lesen
    let mut request_line = String::new();
    reader.read_line(&mut request_line).await?;
    let request_line = request_line.trim().to_string();

    // Header lesen (bis Leerzeile)
    let mut content_length: usize = 0;
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).await?;
        let header = header.trim();
        if header.is_empty() { break; }
        if header.to_lowercase().starts_with("content-length:") {
            if let Some(v) = header.split(':').nth(1) {
                content_length = v.trim().parse().unwrap_or(0);
            }
        }
    }

    // Body lesen
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        tokio::io::AsyncReadExt::read_exact(&mut reader, &mut body).await?;
    }

    // Routing
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Ok(());
    }
    let method = parts[0];
    let path   = parts[1];

    let (status, response_body) = route(method, path, &body, &agg).await;

    let response = format!(
        "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\n\r\n{}",
        status,
        response_body.len(),
        response_body
    );
    writer.write_all(response.as_bytes()).await?;
    Ok(())
}

async fn route(
    method: &str,
    path:   &str,
    body:   &[u8],
    agg:    &Arc<Aggregator>,
) -> (&'static str, String) {
    match (method, path) {

        // POST /submit — einzelne L2-TX einreichen
        ("POST", "/submit") => {
            let tx: L2Transaction = match serde_json::from_slice(body) {
                Ok(tx)  => tx,
                Err(e)  => return ("400 Bad Request", json_err(&format!("Invalid JSON: {}", e))),
            };
            match agg.submit_tx(tx).await {
                Ok(hash) => (
                    "200 OK",
                    serde_json::json!({
                        "status":  "accepted",
                        "tx_hash": hash.as_hex(),
                    }).to_string()
                ),
                Err(e) => ("400 Bad Request", json_err(&format!("{}", e))),
            }
        }

        // POST /submit_batch — viele L2-TXs auf einmal (high-throughput path)
        ("POST", "/submit_batch") => {
            let txs: Vec<L2Transaction> = match serde_json::from_slice(body) {
                Ok(v)  => v,
                Err(e) => return ("400 Bad Request", json_err(&format!("Invalid JSON: {}", e))),
            };
            let count = txs.len();
            let (accepted, rejected) = agg.submit_batch_txs(txs).await;
            (
                "200 OK",
                serde_json::json!({
                    "status":   "accepted",
                    "total":    count,
                    "accepted": accepted,
                    "rejected": rejected,
                }).to_string()
            )
        }

        // GET /account/<hex20> — L2-Guthaben + nächste Nonce (für die Wallet)
        ("GET", p) if p.starts_with("/account/") => {
            let addr_hex = p.trim_start_matches("/account/").trim_start_matches("ATL:");
            let addr: [u8; 20] = match hex::decode(addr_hex).ok()
                .and_then(|v| v.as_slice().try_into().ok())
            {
                Some(a) => a,
                None    => return ("400 Bad Request", json_err("Adresse muss 20 Byte Hex sein")),
            };
            let (balance, nonce) = agg.l2_account(&addr);
            (
                "200 OK",
                serde_json::json!({
                    "address": addr_hex,
                    "balance": balance,   // ATOM (u128)
                    "nonce":   nonce,     // nächste zu verwendende Nonce
                }).to_string()
            )
        }

        // GET /status — Aggregator-Status
        ("GET", "/status") => {
            let stats   = agg.stats();
            let pending = agg.pending_count();
            let body = serde_json::json!({
                "status":             "ok",
                "pending_txs":        pending,
                "txs_received":       stats.txs_received,
                "txs_rejected":       stats.txs_rejected,
                "batches_submitted":  stats.batches_submitted,
                "batches_failed":     stats.batches_failed,
            }).to_string();
            ("200 OK", body)
        }

        // GET /batch/<id> — Batch-Status
        ("GET", p) if p.starts_with("/batch/") => {
            let batch_id = &p["/batch/".len()..];
            match agg.batch_status(batch_id) {
                Some(rec) => ("200 OK", serde_json::to_string(&rec).unwrap_or_default()),
                None      => ("404 Not Found", json_err("Batch not found")),
            }
        }

        // OPTIONS (CORS preflight)
        ("OPTIONS", _) => ("200 OK", "{}".to_string()),

        _ => ("404 Not Found", json_err("Unknown endpoint")),
    }
}

fn json_err(msg: &str) -> String {
    serde_json::json!({ "error": msg }).to_string()
}
