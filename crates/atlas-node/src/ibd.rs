//! Initial Block Download (IBD) State-Machine
//!
//! Koordiniert den Sync eines neuen Nodes:
//!  1. IDLE:    Warte bis Peer mit höherem Tip verbunden ist
//!  2. SYNCING: Header-First → paralleler Block-Download via mehrerer Peers
//!  3. SYNCED:  Lokaler Tip ≥ bester bekannter Peer-Tip
//!
//! Verbesserungen gegenüber der Vorgängerversion:
//!  - GetHeaders wird gezielt an den Peer mit dem höchsten Tip gesendet (nicht broadcast)
//!  - Stall-Detection: wenn N aufeinanderfolgende Ticks keine Fortschritte bringen,
//!    wird ein anderer Peer ausgewählt und der Sync neu angestoßen
//!  - Fortschrittsanzeige (lokale Höhe / Ziel / Prozent)

use crate::chain::ChainManager;
use crate::p2p::P2pNetwork;
use atlas_core::hash::Hash;
use parking_lot::Mutex;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tracing::{info, warn, debug};

/// Abstand zum Best-Peer-Tip ab dem IBD aktiv wird.
/// MUSS 1 sein: jede Lücke wird aktiv synchronisiert. Mit höherer Schwelle
/// bliebe ein Node, der < N Blöcke zurückliegt, dauerhaft zurück, wenn er
/// Live-Announcements verpasst (z. B. nach Reconnect) — auf jungen Ketten
/// hieß das: gar kein Sync.
const IBD_THRESHOLD: u64 = 1; // Vergleich ist `gap >= N`: JEDE Lücke wird gesynct
/// Anzahl Ticks ohne Fortschritt bevor wir den Peer wechseln (1 Tick = 5 s)
const STALL_TICKS_LIMIT: u64 = 6; // 30 s

#[derive(Debug, Clone, PartialEq)]
pub enum IbdState {
    Idle,
    Syncing { target_height: u64 },
    Synced,
}

pub struct IbdManager {
    chain:               Arc<ChainManager>,
    p2p:                 Arc<P2pNetwork>,
    state:               Mutex<IbdState>,
    stop:                Arc<AtomicBool>,
    /// Letzte Höhe bei der Fortschritt gemessen wurde
    last_progress_height: AtomicU64,
    /// Aufeinanderfolgende Ticks ohne Höhenänderung
    stall_ticks:         AtomicU64,
    /// Letzter aktiv genutzter Sync-Peer (für Rotation bei Stall)
    last_sync_peer:      Mutex<Option<SocketAddr>>,
}

impl IbdManager {
    pub fn new(chain: Arc<ChainManager>, p2p: Arc<P2pNetwork>) -> Arc<Self> {
        Arc::new(IbdManager {
            chain,
            p2p,
            state:               Mutex::new(IbdState::Idle),
            stop:                Arc::new(AtomicBool::new(false)),
            last_progress_height: AtomicU64::new(0),
            stall_ticks:         AtomicU64::new(0),
            last_sync_peer:      Mutex::new(None),
        })
    }

    /// Startet die IBD-Überwachung als Background-Task
    pub fn start(self: &Arc<Self>) {
        let mgr = self.clone();
        tokio::spawn(async move {
            mgr.run().await;
        });
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    pub fn is_synced(&self) -> bool {
        *self.state.lock() == IbdState::Synced
    }

    /// True, solange der Node WEISS, dass ein Peer eine längere Kette hat, und
    /// noch nicht aufgeschlossen ist. Während dieser Phase MUSS das Mining
    /// pausieren — sonst kann der Node seine eigene (kürzere) Kette bis zum
    /// Gleichstand verlängern, wodurch der Reorg auf die fremde Kette nie
    /// auslöst (Gleichstand wechselt nicht) → Chain-Split.
    pub fn is_syncing(&self) -> bool {
        matches!(*self.state.lock(), IbdState::Syncing { .. })
    }

    async fn run(self: Arc<Self>) {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
        loop {
            interval.tick().await;
            if self.stop.load(Ordering::Relaxed) { break; }
            self.tick().await;
        }
    }

    async fn tick(self: &Arc<Self>) {
        let local_height  = self.chain.height();
        let best_peer_tip = self.best_peer_height();

        if best_peer_tip == 0 { return; } // noch kein Peer verbunden

        let gap           = best_peer_tip.saturating_sub(local_height);
        let current_state = { self.state.lock().clone() };

        // Fortschritt messen
        let last = self.last_progress_height.load(Ordering::Relaxed);
        if local_height > last {
            self.last_progress_height.store(local_height, Ordering::Relaxed);
            self.stall_ticks.store(0, Ordering::Relaxed);
        }

        match current_state {
            IbdState::Idle => {
                if gap >= IBD_THRESHOLD {
                    info!(
                        "IBD start: local={} peer_best={} gap={}",
                        local_height, best_peer_tip, gap
                    );
                    *self.state.lock() = IbdState::Syncing { target_height: best_peer_tip };
                    self.last_progress_height.store(local_height, Ordering::Relaxed);
                    self.stall_ticks.store(0, Ordering::Relaxed);
                    self.request_headers(None).await;
                } else if gap == 0 {
                    *self.state.lock() = IbdState::Synced;
                    info!("Chain fully synced at height {}", local_height);
                }
            }

            IbdState::Syncing { target_height } => {
                if local_height >= target_height {
                    let new_best = self.best_peer_height();
                    if local_height >= new_best {
                        *self.state.lock() = IbdState::Synced;
                        info!("IBD complete: height={}", local_height);
                    } else {
                        *self.state.lock() = IbdState::Syncing { target_height: new_best };
                        self.request_headers(None).await;
                    }
                } else {
                    // Fortschritt anzeigen
                    let pct = local_height * 100 / target_height.max(1);
                    debug!("IBD sync: {}/{} ({}%)", local_height, target_height, pct);

                    // Stall-Detection
                    let stalls = self.stall_ticks.fetch_add(1, Ordering::Relaxed) + 1;
                    if stalls >= STALL_TICKS_LIMIT {
                        warn!(
                            "IBD stalled at height {} ({}s), rotating sync peer",
                            local_height,
                            stalls * 5,
                        );
                        self.stall_ticks.store(0, Ordering::Relaxed);
                        // Anderen Peer wählen
                        let avoid = { self.last_sync_peer.lock().take() };
                        self.request_headers(avoid).await;
                    } else {
                        // Regelmäßig neue Header anfordern (pipelining)
                        self.request_headers(None).await;
                    }
                }
            }

            IbdState::Synced => {
                if gap >= IBD_THRESHOLD {
                    warn!("IBD: new longer chain detected (gap={}), re-syncing", gap);
                    *self.state.lock() = IbdState::Syncing { target_height: best_peer_tip };
                    self.stall_ticks.store(0, Ordering::Relaxed);
                    self.request_headers(None).await;
                }
            }
        }
    }

    /// Fordert die nächsten Header vom besten Peer an.
    ///
    /// `avoid`: diese Peer-Adresse überspringen (Stall-Rotation).
    async fn request_headers(self: &Arc<Self>, avoid: Option<SocketAddr>) {
        let locator = self.build_locator();

        // Peer mit höchstem Tip wählen, `avoid` ausschließen
        let peer_heights = self.p2p.peer_heights();
        if peer_heights.is_empty() {
            debug!("IBD: no peers connected, waiting...");
            return;
        }

        let best_peer = peer_heights.iter()
            .filter(|(addr, _)| Some(*addr) != avoid)
            .max_by_key(|(_, h)| h)
            .map(|(addr, _)| *addr)
            // Fallback wenn alle gemieden werden: nehme einfach irgendeinen
            .or_else(|| peer_heights.first().map(|(a, _)| *a));

        if let Some(addr) = best_peer {
            debug!("IBD: GetHeaders → {}", addr);
            *self.last_sync_peer.lock() = Some(addr);
            if !self.p2p.send_to_peer(addr, crate::p2p::P2pMessage::GetHeaders { locator }) {
                // Peer nicht mehr verbunden — fallback auf broadcast
                self.p2p.broadcast_get_headers(self.build_locator());
            }
        }
    }

    fn build_locator(&self) -> Vec<Hash> {
        let chain   = self.chain.state().chain.read();
        let headers: Vec<_> = chain.recent_headers.iter().rev().collect();
        let mut locator = Vec::new();
        let mut step    = 1usize;
        let mut i       = 0usize;
        while i < headers.len() {
            locator.push(headers[i].hash());
            i += step;
            if locator.len() > 10 { step *= 2; }
        }
        locator
    }

    fn best_peer_height(&self) -> u64 {
        self.p2p.peer_heights()
            .into_iter()
            .map(|(_, h)| h)
            .max()
            .unwrap_or(0)
    }
}
