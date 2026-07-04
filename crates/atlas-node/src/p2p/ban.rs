//! Peer-Scoring und automatisches Banning
//!
//! Scores: +1 für validen Block, -10 für invaliden Block, -5 für ungültige Nachricht.
//! Unter -100 → Ban für BAN_DURATION.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use tracing::warn;

const BAN_DURATION:   Duration = Duration::from_secs(60 * 60 * 24); // 24 Stunden
const BAN_THRESHOLD:  i32      = -100;

pub const SCORE_VALID_BLOCK:    i32 = 1;
pub const SCORE_INVALID_BLOCK:  i32 = -10;
pub const SCORE_INVALID_MSG:    i32 = -5;
pub const SCORE_VALID_TX:       i32 = 1;
pub const SCORE_DUPLICATE:      i32 = -2;

#[derive(Debug)]
struct PeerRecord {
    score:      i32,
    banned_until: Option<Instant>,
}

impl PeerRecord {
    fn new() -> Self {
        PeerRecord { score: 0, banned_until: None }
    }

    fn is_banned(&self) -> bool {
        self.banned_until.map(|t| Instant::now() < t).unwrap_or(false)
    }
}

pub struct PeerBanManager {
    records: RwLock<HashMap<IpAddr, PeerRecord>>,
    /// Operator-konfigurierte Seeds: NIE bannen. Live-Incident 2026-07-03:
    /// node2 bannte seinen einzigen Seed (Duplicate-Strafen im IBD, Score -101
    /// in 21 s) und war danach 24 h isoliert — ohne Seed kein Sync, kein Relay.
    whitelist: RwLock<std::collections::HashSet<IpAddr>>,
}

impl PeerBanManager {
    pub fn new() -> Self {
        PeerBanManager {
            records:   RwLock::new(HashMap::new()),
            whitelist: RwLock::new(std::collections::HashSet::new()),
        }
    }

    /// Nimmt eine IP dauerhaft vom Banning aus (konfigurierte Seed-Nodes).
    pub fn whitelist(&self, ip: IpAddr) {
        self.whitelist.write().insert(ip);
    }

    /// Gibt true zurück wenn die IP gerade gebannt ist
    pub fn is_banned(&self, ip: IpAddr) -> bool {
        if self.whitelist.read().contains(&ip) { return false; }
        self.records.read()
            .get(&ip)
            .map(|r| r.is_banned())
            .unwrap_or(false)
    }

    /// Passt den Score an; bannt automatisch bei Unterschreitung des Schwellwerts
    pub fn adjust_score(&self, ip: IpAddr, delta: i32) {
        if self.whitelist.read().contains(&ip) { return; }
        let mut records = self.records.write();
        let record = records.entry(ip).or_insert_with(PeerRecord::new);

        if record.is_banned() { return; }

        record.score += delta;

        if record.score < BAN_THRESHOLD {
            record.banned_until = Some(Instant::now() + BAN_DURATION);
            warn!("Peer {} banned for {} hours (score={})", ip, BAN_DURATION.as_secs() / 3600, record.score);
        }
    }

    /// Manuelles Bannen (z.B. bei Protokoll-Verletzung)
    pub fn ban(&self, ip: IpAddr, reason: &str) {
        let mut records = self.records.write();
        let record = records.entry(ip).or_insert_with(PeerRecord::new);
        record.score        = BAN_THRESHOLD - 1;
        record.banned_until = Some(Instant::now() + BAN_DURATION);
        warn!("Peer {} manually banned: {}", ip, reason);
    }

    /// Entfernt abgelaufene Bans (periodisch aufrufen)
    pub fn prune_expired(&self) {
        let now = Instant::now();
        let mut records = self.records.write();
        records.retain(|_, r| {
            if let Some(until) = r.banned_until {
                if now >= until {
                    r.banned_until = None;
                    r.score        = 0; // Reset nach Ban-Ablauf
                }
            }
            true
        });
    }

    pub fn score(&self, ip: IpAddr) -> i32 {
        self.records.read().get(&ip).map(|r| r.score).unwrap_or(0)
    }
}

impl Default for PeerBanManager {
    fn default() -> Self { Self::new() }
}
