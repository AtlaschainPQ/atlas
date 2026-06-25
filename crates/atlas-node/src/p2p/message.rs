//! P2P Protokoll-Nachrichten

use atlas_core::block::{Block, BlockHeader};
use atlas_core::hash::Hash;
use atlas_core::transaction::Transaction;
use serde::{Deserialize, Serialize};

/// Protokoll-Version dieses Nodes
pub const PROTOCOL_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum P2pMessage {
    // ── Handshake ─────────────────────────────────────────────────────────────
    Version {
        version:    u32,
        height:     u64,
        best_hash:  Hash,
        user_agent: String,
    },
    VerAck,

    // ── Keepalive ─────────────────────────────────────────────────────────────
    Ping(u64),
    Pong(u64),

    // ── Inventory (Ankündigung) ───────────────────────────────────────────────
    /// Wir haben diese Objekte (Block oder TX)
    Inv(Vec<InvItem>),
    /// Wir wollen diese Objekte haben
    GetData(Vec<Hash>),

    // ── Daten ────────────────────────────────────────────────────────────────
    Block(Box<Block>),
    Tx(Box<Transaction>),

    // ── Header-Sync ──────────────────────────────────────────────────────────
    /// Locator: Liste von bekannten Hashes (neueste zuerst)
    GetHeaders { locator: Vec<Hash> },
    Headers(Vec<BlockHeader>),

    // ── Peer Discovery ───────────────────────────────────────────────────────
    /// Anfrage nach bekannten Peer-Adressen
    GetAddr,
    /// Liste bekannter Peer-Adressen (max 1000)
    Addr(Vec<std::net::SocketAddr>),

    // ── Ablehnung ────────────────────────────────────────────────────────────
    Reject { reason: String },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum InvItem {
    Block(Hash),
    Tx(Hash),
}

impl P2pMessage {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Version { .. } => "version",
            Self::VerAck          => "verack",
            Self::Ping(_)         => "ping",
            Self::Pong(_)         => "pong",
            Self::Inv(_)          => "inv",
            Self::GetData(_)      => "getdata",
            Self::Block(_)        => "block",
            Self::Tx(_)           => "tx",
            Self::GetHeaders { .. } => "getheaders",
            Self::Headers(_)      => "headers",
            Self::GetAddr         => "getaddr",
            Self::Addr(_)         => "addr",
            Self::Reject { .. }   => "reject",
        }
    }
}
