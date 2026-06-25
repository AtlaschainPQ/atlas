//! Einfacher JSON-RPC Client für Node-Kommunikation

use anyhow::Result;
use serde_json::{json, Value};

pub struct RpcClient {
    endpoint: String,
    api_key:  Option<String>,
}

impl RpcClient {
    pub fn new(endpoint: &str, api_key: Option<String>) -> Self {
        RpcClient { endpoint: endpoint.to_string(), api_key }
    }

    pub async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });
        let body_str = serde_json::to_string(&body)?;

        // Einfacher HTTP POST über tokio TCP
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        let addr = self.endpoint
            .trim_start_matches("http://")
            .trim_start_matches("https://");

        let mut stream = TcpStream::connect(addr).await?;

        let auth_header = self.api_key.as_ref()
            .map(|k| format!("Authorization: Bearer {}\r\n", k))
            .unwrap_or_default();

        let request = format!(
            "POST / HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{}\r\n{}",
            addr, body_str.len(), auth_header, body_str
        );

        stream.write_all(request.as_bytes()).await?;

        // HTTP-Response lesen: erst Header, dann exakt Content-Length Bytes Body
        let mut header_buf = Vec::new();
        let mut buf = [0u8; 1];
        // Header Byte-für-Byte bis \r\n\r\n lesen (max 8 KB)
        loop {
            let n = stream.read(&mut buf).await?;
            if n == 0 { break; }
            header_buf.push(buf[0]);
            if header_buf.ends_with(b"\r\n\r\n") { break; }
            if header_buf.len() > 8192 {
                anyhow::bail!("HTTP response headers too large");
            }
        }
        let header_str = String::from_utf8_lossy(&header_buf);

        // Content-Length aus Header extrahieren
        let content_length: usize = header_str.lines()
            .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
            .and_then(|l| l.split(':').nth(1))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0);

        if content_length == 0 || content_length > 10_000_000 {
            anyhow::bail!("Invalid or missing Content-Length: {}", content_length);
        }

        // Body exakt in der angegebenen Länge lesen
        let mut body = vec![0u8; content_length];
        stream.read_exact(&mut body).await?;

        let resp: Value = serde_json::from_slice(&body)?;

        if let Some(err) = resp.get("error") {
            anyhow::bail!("RPC error: {}", err);
        }

        Ok(resp["result"].clone())
    }

    pub async fn get_balance(&self, address: &str) -> Result<Value> {
        self.call("getbalance", json!([address])).await
    }

    /// Gibt alle UTXOs einer Adresse zurück (für echte TX-Erstellung)
    pub async fn get_utxos(&self, address: &str) -> Result<Vec<crate::UtxoInfo>> {
        let result = self.call("getutxos", json!([address])).await?;
        let arr = result.as_array()
            .ok_or_else(|| anyhow::anyhow!("Expected array from getutxos"))?;

        arr.iter().map(|v| {
            Ok(crate::UtxoInfo {
                txid:    v["txid"].as_str().unwrap_or("").to_string(),
                index:   v["index"].as_u64().unwrap_or(0) as u32,
                value:   v["value_atom"].as_str()
                    .and_then(|s| s.parse::<u128>().ok())
                    .unwrap_or(0),
                address: address.to_string(),
            })
        }).collect()
    }

    pub async fn send_raw_tx(&self, tx_hex: &str) -> Result<String> {
        let result = self.call("sendrawtransaction", json!([tx_hex])).await?;
        Ok(result.as_str().unwrap_or("").to_string())
    }

    pub async fn get_block_count(&self) -> Result<u64> {
        let result = self.call("getblockcount", json!([])).await?;
        Ok(result.as_u64().unwrap_or(0))
    }
}
