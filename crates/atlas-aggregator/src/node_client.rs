//! JSON-RPC Client für atlas-node
//!
//! Kommuniziert mit dem Full-Node über das JSON-RPC-Protokoll (HTTP/1.1).
//! Verwendet raw tokio TCP — kein externes HTTP-Framework nötig.

use atlas_core::hash::Hash;
use atlas_core::crypto::Address;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, warn};

pub struct NodeClient {
    addr:    String,
    api_key: Option<String>,
}

/// Eintrag der Forced-Inclusion-Queue (von `getforcedqueue`).
#[derive(Clone, Debug)]
#[allow(dead_code)] // seen_height/due sind informative API-Felder
pub struct ForcedEntryInfo {
    pub from:         [u8; 20],
    pub to:           [u8; 20],
    pub amount_atom:  u128,
    pub fee_atom:     u128,
    pub nonce:        u64,
    pub pubkey:       [u8; 32],
    pub sig:          [u8; 64],
    pub sender_index: u64,
    pub seen_height:  u64,
    pub due:          bool,
}

/// Rejection-Zeuge (Aggregator → Node, Teil von `submitbatch`).
#[derive(Clone, Debug)]
pub struct ForcedRejectionInfo {
    pub from:         [u8; 20],
    pub nonce:        u64,
    pub leaf_address: [u8; 20],
    pub leaf_balance: u128,
    pub leaf_nonce:   u64,
    pub leaf_vacant:  bool,
    pub siblings:     Vec<[u8; 32]>,
}

impl NodeClient {
    pub fn new(addr: String, api_key: Option<String>) -> Self {
        NodeClient { addr, api_key }
    }

    /// Sendet einen JSON-RPC-Aufruf und gibt result zurück
    async fn call(&self, method: &str, params: Value) -> anyhow::Result<Value> {
        let body = serde_json::to_string(&json!({
            "jsonrpc": "2.0",
            "id":      1,
            "method":  method,
            "params":  params,
        }))?;

        let mut stream = TcpStream::connect(&self.addr).await
            .map_err(|e| anyhow::anyhow!("Cannot connect to node at {}: {}", self.addr, e))?;

        // HTTP-Request bauen
        let mut request = format!(
            "POST / HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
            self.addr,
            body.len()
        );
        if let Some(key) = &self.api_key {
            request.push_str(&format!("Authorization: Bearer {}\r\n", key));
        }
        request.push_str("\r\n");
        request.push_str(&body);

        stream.write_all(request.as_bytes()).await?;
        stream.flush().await?;

        // Antwort lesen
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await?;
        let response_str = String::from_utf8_lossy(&response);

        debug!("RPC {} response: {}", method, &response_str[..response_str.len().min(200)]);

        // HTTP-Header überspringen
        let body_start = response_str.find("\r\n\r\n")
            .ok_or_else(|| anyhow::anyhow!("Invalid HTTP response (no header end)"))?;
        let body_str = &response_str[body_start + 4..];

        let value: Value = serde_json::from_str(body_str)
            .map_err(|e| anyhow::anyhow!("Invalid JSON response: {} — body: {}", e, &body_str[..body_str.len().min(200)]))?;

        if let Some(err) = value.get("error") {
            return Err(anyhow::anyhow!("Node RPC error for '{}': {}", method, err));
        }

        Ok(value["result"].clone())
    }

    /// Liefert den Hash des aktuellen Best-Blocks (als State-Root für den Proof)
    #[allow(dead_code)] // Node-RPC-Client-API (Diagnose/zukünftige Nutzung)
    pub async fn get_best_block_hash(&self) -> anyhow::Result<Hash> {
        let result = self.call("getbestblockhash", json!([])).await?;
        let hex = result.as_str()
            .ok_or_else(|| anyhow::anyhow!("Expected string from getbestblockhash"))?;
        Hash::from_hex(hex)
            .map_err(|e| anyhow::anyhow!("Invalid hash from node: {}", e))
    }

    /// Reicht einen Settlement-Batch (State-Transition-Beweis) beim Node ein.
    /// Gibt die txid der SettlementBid-TX zurück.
    ///
    /// WICHTIG: `batch_commitment` ist die Poseidon-Commitment-Wurzel aus
    /// `prove_state` (Public Input des Beweises) — der Node verwendet das
    /// `batch_merkle`-Feld genau als dieses Commitment bei der Verifikation.
    /// `batch_id` dient nur der Identifikation (Merkle-Root der TX-Hashes).
    #[allow(clippy::too_many_arguments)]
    pub async fn submit_batch(
        &self,
        batch_id:          &Hash,
        aggregator:        &Address,
        tx_count:          u32,
        proof_bytes:       &[u8],
        pre_state_root:    &[u8; 32],
        post_state_root:   &[u8; 32],
        batch_commitment:  &[u8; 32],
        total_fees_atom:   u128,
        calldata:          &[u8],
        forced_rejections: &[ForcedRejectionInfo],
    ) -> anyhow::Result<String> {
        let rejections: Vec<Value> = forced_rejections.iter().map(|r| json!({
            "from":         hex::encode(r.from),
            "nonce":        r.nonce,
            "leaf_address": hex::encode(r.leaf_address),
            "leaf_balance": r.leaf_balance as u64,
            "leaf_nonce":   r.leaf_nonce,
            "leaf_vacant":  r.leaf_vacant,
            "siblings":     r.siblings.iter().map(hex::encode).collect::<Vec<_>>(),
        })).collect();
        let result = self.call("submitbatch", json!([{
            "batch_id":        batch_id.as_hex(),
            "aggregator":      aggregator.as_hex(),
            "tx_count":        tx_count,
            "proof_bytes":     hex::encode(proof_bytes),
            "pre_state_root":  hex::encode(pre_state_root),
            "post_state_root": hex::encode(post_state_root),
            "total_fees_atom": total_fees_atom,
            "batch_merkle":    hex::encode(batch_commitment),
            "calldata":        hex::encode(calldata),
            "forced_rejections": rejections,
        }])).await?;

        let txid = result["txid"].as_str()
            .unwrap_or("")
            .to_string();
        Ok(txid)
    }

    /// Holt die offene Forced-Inclusion-Queue vom Node (Konsens-Pflicht des
    /// Aggregators: fällige Einträge aufnehmen oder nachweislich ablehnen).
    pub async fn get_forced_queue(&self) -> anyhow::Result<Vec<ForcedEntryInfo>> {
        let result = self.call("getforcedqueue", json!([])).await?;
        let mut out = Vec::new();
        for e in result["entries"].as_array().cloned().unwrap_or_default() {
            let parse20 = |k: &str| -> Option<[u8; 20]> {
                hex::decode(e[k].as_str()?).ok()?.as_slice().try_into().ok()
            };
            let parse32 = |k: &str| -> Option<[u8; 32]> {
                hex::decode(e[k].as_str()?).ok()?.as_slice().try_into().ok()
            };
            let parse64 = |k: &str| -> Option<[u8; 64]> {
                hex::decode(e[k].as_str()?).ok()?.as_slice().try_into().ok()
            };
            let (Some(from), Some(to), Some(pubkey), Some(sig)) =
                (parse20("from"), parse20("to"), parse32("pubkey"), parse64("sig"))
            else {
                warn!("getforcedqueue: Eintrag mit defekten Feldern übersprungen");
                continue;
            };
            out.push(ForcedEntryInfo {
                from, to, pubkey, sig,
                amount_atom:  e["amount_atom"].as_u64().unwrap_or(0) as u128,
                fee_atom:     e["fee_atom"].as_u64().unwrap_or(0) as u128,
                nonce:        e["nonce"].as_u64().unwrap_or(0),
                sender_index: e["sender_index"].as_u64().unwrap_or(0),
                seen_height:  e["seen_height"].as_u64().unwrap_or(0),
                due:          e["due"].as_bool().unwrap_or(false),
            });
        }
        Ok(out)
    }

    /// Gibt Batch-Infos vom Node zurück (pending bids, chain height, …)
    #[allow(dead_code)] // Node-RPC-Client-API (Diagnose/zukünftige Nutzung)
    pub async fn get_batch_info(&self) -> anyhow::Result<Value> {
        self.call("getbatchinfo", json!([])).await
    }

    /// Holt einen Data-Availability-Snapshot für den Aggregator-Resync:
    /// `(height, l2_state_root, calldata)` — die L2-Root am Tip und die
    /// konkatenierte Settlement-Calldata der Blöcke `> from_height`.
    /// `from_height = 0` ⇒ Genesis→Tip (Full-Replay); `from_height >= Tip`
    /// ⇒ leere Calldata (billiger Head-Check für Root+Höhe).
    pub async fn get_l2_snapshot(&self, from_height: u64) -> anyhow::Result<(u64, [u8; 32], Vec<u8>)> {
        let result = self.call("getl2snapshot", json!([from_height])).await?;
        let height = result["height"].as_u64()
            .ok_or_else(|| anyhow::anyhow!("getl2snapshot: height fehlt"))?;
        let root: [u8; 32] = hex::decode(
                result["l2_state_root"].as_str()
                    .ok_or_else(|| anyhow::anyhow!("getl2snapshot: l2_state_root fehlt"))?)?
            .as_slice().try_into()
            .map_err(|_| anyhow::anyhow!("getl2snapshot: l2_state_root keine 32 Byte"))?;
        let calldata = hex::decode(result["calldata"].as_str().unwrap_or(""))?;
        Ok((height, root, calldata))
    }

    /// Prüft ob der Node erreichbar ist
    #[allow(dead_code)] // Node-RPC-Client-API (Diagnose/zukünftige Nutzung)
    pub async fn ping(&self) -> bool {
        match self.call("getbestblockhash", json!([])).await {
            Ok(_)  => true,
            Err(e) => {
                warn!("Node ping failed: {}", e);
                false
            }
        }
    }
}
