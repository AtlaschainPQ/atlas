//! Einzelne Peer-Verbindung — Reader/Writer Tasks

use super::message::{P2pMessage, PROTOCOL_VERSION};
use atlas_core::hash::Hash;
use bytes::BytesMut;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{debug, warn};

/// Maximale Nachrichtengröße: 32 MB (verhindert Memory-Exhaustion)
const MAX_MSG_SIZE: u32 = 32 * 1024 * 1024;
/// Token-Bucket: maximale Nachrichten pro Sekunde (Burst + Dauerrate)
const RATE_LIMIT_PER_SEC: f64 = 200.0;
/// Idle-Timeout: Peer der 60s keine Daten sendet wird getrennt
// 180 s statt 60 s: Keepalive-Pings kommen alle 30 s, aber unter Volllast
// (Mining/Proving) darf ein Peer auch mal mehrere Intervalle still sein,
// ohne dass gesunde Verbindungen gekappt werden.
const IDLE_TIMEOUT: tokio::time::Duration = tokio::time::Duration::from_secs(180);

pub struct Peer {
    pub addr:      SocketAddr,
    pub height:    Arc<AtomicU64>,
    pub connected: Arc<AtomicBool>,
    sender:        mpsc::UnboundedSender<P2pMessage>,
}

impl Peer {
    /// Gibt einen Sender zurück mit dem Nachrichten an diesen Peer geschickt werden
    pub fn send(&self, msg: P2pMessage) {
        let _ = self.sender.send(msg);
    }

    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    pub fn peer_height(&self) -> u64 {
        self.height.load(Ordering::Relaxed)
    }
}

/// Startet Reader- und Writer-Tasks für eine (ggf. TLS-gewrappte) Verbindung.
/// Gibt den Peer und einen Receiver für eingehende Nachrichten zurück.
pub fn spawn_peer<S>(
    stream:     S,
    addr:       SocketAddr,
    our_height: u64,
    our_best:   Hash,
) -> (Arc<Peer>, mpsc::UnboundedReceiver<P2pMessage>)
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (out_tx, out_rx) = mpsc::unbounded_channel::<P2pMessage>(); // ausgehend
    let (in_tx,  in_rx)  = mpsc::unbounded_channel::<P2pMessage>(); // eingehend

    let height    = Arc::new(AtomicU64::new(0));
    let connected = Arc::new(AtomicBool::new(true));

    let peer = Arc::new(Peer {
        addr,
        height:    height.clone(),
        connected: connected.clone(),
        sender:    out_tx.clone(),
    });

    // Direkt Version schicken
    let _ = out_tx.send(P2pMessage::Version {
        version:    PROTOCOL_VERSION,
        height:     our_height,
        best_hash:  our_best,
        user_agent: format!("atlas/{}", env!("CARGO_PKG_VERSION")),
    });

    let (reader, writer) = tokio::io::split(stream);

    // Writer-Task
    let conn_w = connected.clone();
    tokio::spawn(async move {
        run_writer(writer, out_rx, conn_w).await;
    });

    // Reader-Task
    let conn_r = connected.clone();
    tokio::spawn(async move {
        run_reader(reader, in_tx, height, conn_r, addr).await;
    });

    (peer, in_rx)
}

// ── Framing: 4-byte LE length + bincode payload ───────────────────────────────

async fn run_writer<W>(
    mut writer: W,
    mut rx:     mpsc::UnboundedReceiver<P2pMessage>,
    connected:  Arc<AtomicBool>,
)
where
    W: AsyncWriteExt + Unpin,
{
    while let Some(msg) = rx.recv().await {
        match encode_message(&msg) {
            Ok(bytes) => {
                if writer.write_all(&bytes).await.is_err() {
                    break;
                }
            }
            Err(e) => warn!("Message encode error: {}", e),
        }
    }
    connected.store(false, Ordering::Relaxed);
}

async fn run_reader<R>(
    mut reader: R,
    in_tx:      mpsc::UnboundedSender<P2pMessage>,
    height:     Arc<AtomicU64>,
    connected:  Arc<AtomicBool>,
    addr:       SocketAddr,
)
where
    R: AsyncReadExt + Unpin,
{
    let mut len_buf     = [0u8; 4];
    let mut tokens      = RATE_LIMIT_PER_SEC;
    let mut last_refill = tokio::time::Instant::now();

    loop {
        // Tokens seit letztem Check nachfüllen
        let now     = tokio::time::Instant::now();
        let elapsed = now.duration_since(last_refill).as_secs_f64();
        tokens      = (tokens + elapsed * RATE_LIMIT_PER_SEC).min(RATE_LIMIT_PER_SEC);
        last_refill = now;

        // 1 Token pro Nachricht. Bei leerem Bucket DROSSELN statt trennen: ein
        // legitimer Burst (v.a. IBD-Block-Download bei langer Kette) darf die
        // Verbindung nicht killen. Der Durchsatz bleibt auf RATE_LIMIT_PER_SEC
        // gedeckelt (Backpressure via TCP-Flow-Control) — ein Spammer wird so
        // gedrosselt statt belohnt; tote/lahme Verbindungen fängt IDLE_TIMEOUT ab.
        if tokens < 1.0 {
            let wait = ((1.0 - tokens) / RATE_LIMIT_PER_SEC).min(1.0);
            tokio::time::sleep(std::time::Duration::from_secs_f64(wait)).await;
            continue; // Loop-Anfang füllt Tokens anhand der verstrichenen Zeit nach
        }
        tokens -= 1.0;

        // Länge lesen — mit Idle-Timeout
        match tokio::time::timeout(IDLE_TIMEOUT, reader.read_exact(&mut len_buf)).await {
            Ok(Ok(_)) => {}
            Ok(Err(_)) => break,
            Err(_) => {
                warn!("Peer {}: idle timeout ({}s), disconnecting", addr, IDLE_TIMEOUT.as_secs());
                break;
            }
        }
        let len = u32::from_le_bytes(len_buf);

        if len == 0 || len > MAX_MSG_SIZE {
            warn!("Peer {}: invalid message length {}", addr, len);
            break;
        }

        // Payload lesen — gleicher Timeout wie beim Length-Read (Slowloris-Schutz)
        let mut buf = BytesMut::zeroed(len as usize);
        match tokio::time::timeout(IDLE_TIMEOUT, reader.read_exact(&mut buf)).await {
            Ok(Ok(_)) => {}
            Ok(Err(_)) => break,
            Err(_) => {
                warn!("Peer {}: payload read timeout after {}s, disconnecting", addr, IDLE_TIMEOUT.as_secs());
                break;
            }
        }

        match decode_message(&buf) {
            Ok(msg) => {
                // Peer-Höhe frisch halten — nicht nur beim Version-Handshake.
                // Eine nur-einmal gesetzte Höhe veraltet über lange Verbindungen;
                // IBD rechnet den Gap dann gegen einen stalen Wert und hält sich
                // fälschlich für synced (Freeze-Baustein im Incident 2026-07-03).
                match &msg {
                    P2pMessage::Version { height: h, .. } => {
                        height.store(*h, Ordering::Relaxed);
                    }
                    P2pMessage::Block(b) => {
                        height.fetch_max(b.header.height, Ordering::Relaxed);
                    }
                    P2pMessage::Headers(hs) => {
                        if let Some(max) = hs.iter().map(|h| h.height).max() {
                            height.fetch_max(max, Ordering::Relaxed);
                        }
                    }
                    _ => {}
                }
                debug!("← {} from {}", msg.name(), addr);
                if in_tx.send(msg).is_err() { break; }
            }
            Err(e) => {
                warn!("Peer {}: decode error: {}", addr, e);
                break;
            }
        }
    }
    connected.store(false, Ordering::Relaxed);
    debug!("Peer {} disconnected", addr);
}

fn encode_message(msg: &P2pMessage) -> Result<Vec<u8>, bincode::Error> {
    let payload = bincode::serialize(msg)?;
    let len = payload.len() as u32;
    let mut out = BytesMut::with_capacity(4 + payload.len());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&payload);
    Ok(out.to_vec())
}

fn decode_message(buf: &[u8]) -> Result<P2pMessage, bincode::Error> {
    bincode::deserialize(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::message::InvItem;
    use atlas_core::block::Block;

    #[test]
    fn test_message_encode_decode_roundtrip() {
        let block   = Block::genesis();
        let msg     = P2pMessage::Block(Box::new(block));
        let encoded = encode_message(&msg).unwrap();
        // Skip the 4-byte length header
        let decoded = decode_message(&encoded[4..]).unwrap();
        assert_eq!(decoded.name(), "block");
    }

    #[test]
    fn test_inv_roundtrip() {
        let hash = atlas_core::hash::Hash::sha256(b"test");
        let msg  = P2pMessage::Inv(vec![InvItem::Block(hash)]);
        let enc  = encode_message(&msg).unwrap();
        let dec  = decode_message(&enc[4..]).unwrap();
        match dec {
            P2pMessage::Inv(items) => assert_eq!(items[0], InvItem::Block(hash)),
            _ => panic!("wrong variant"),
        }
    }
}
