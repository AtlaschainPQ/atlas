//! P2P Netzwerk-Manager

use super::ban::{PeerBanManager, SCORE_VALID_BLOCK, SCORE_INVALID_BLOCK, SCORE_VALID_TX, SCORE_DUPLICATE, SCORE_INVALID_MSG};
use super::message::{InvItem, P2pMessage, PROTOCOL_VERSION};
use super::peer::{spawn_peer, Peer};
use super::tls::TlsConfig;
use crate::chain::{ChainEvent, ChainManager};
use atlas_core::block::Block;
use atlas_core::hash::Hash;
use atlas_mempool::mempool::Mempool;
use parking_lot::RwLock;
use rustls::pki_types::ServerName;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, warn, debug};

/// Maximale Peer-Adressen pro Addr-Nachricht
const MAX_ADDR_ITEMS: usize = 1_000;

/// Maximale Anzahl Objekte pro GetData-Request (verhindert DoS)
const MAX_GETDATA_ITEMS: usize = 500;

/// Obergrenze des Orphan-Puffers (out-of-order IBD-Blöcke) — DoS-Schutz: ein
/// Peer könnte sonst beliebig viele nicht-anschließende Blöcke einspeisen.
const MAX_ORPHANS: usize = 20_000;

pub struct P2pNetwork {
    chain:       Arc<ChainManager>,
    mempool:     Arc<Mempool>,
    peers:       Arc<RwLock<HashMap<SocketAddr, Arc<Peer>>>>,
    connecting:  Arc<RwLock<HashSet<SocketAddr>>>,
    known_addrs: Arc<RwLock<HashSet<SocketAddr>>>,
    bans:        Arc<PeerBanManager>,
    tls:         Arc<TlsConfig>,
    stop:        Arc<AtomicBool>,
    max_peers:   usize,
    /// Out-of-order IBD-Blöcke: Block, dessen Parent noch NICHT bekannt ist,
    /// zwischengespeichert keyed by Parent-Hash. Beim Eintreffen des Parents wird
    /// der wartende Block in Reihenfolge angewandt (verhindert, dass beim IBD
    /// nebenläufig gelieferte Blöcke als Orphan durchfallen → 1-Block-pro-Zyklus).
    orphans:     Arc<RwLock<HashMap<Hash, Box<Block>>>>,
}

impl P2pNetwork {
    pub fn new(
        chain:     Arc<ChainManager>,
        mempool:   Arc<Mempool>,
        max_peers: usize,
        data_dir:  &str,
    ) -> Arc<Self> {
        let tls = TlsConfig::load_or_generate(data_dir)
            .expect("TLS certificate generation failed");
        Arc::new(P2pNetwork {
            chain,
            mempool,
            peers:       Arc::new(RwLock::new(HashMap::new())),
            connecting:  Arc::new(RwLock::new(HashSet::new())),
            known_addrs: Arc::new(RwLock::new(HashSet::new())),
            bans:        Arc::new(PeerBanManager::new()),
            tls:         Arc::new(tls),
            stop:        Arc::new(AtomicBool::new(false)),
            max_peers,
            orphans:     Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub fn seed_known_addrs(&self, addrs: Vec<SocketAddr>) {
        let mut known = self.known_addrs.write();
        for addr in addrs {
            known.insert(addr);
        }
    }

    pub async fn start(self: &Arc<Self>, bind_addr: &str) -> anyhow::Result<()> {
        let listener = TcpListener::bind(bind_addr).await?;
        info!("P2P listening on {} (TLS)", bind_addr);

        let net = self.clone();
        tokio::spawn(async move { net.accept_loop(listener).await; });

        let net = self.clone();
        let mut events = self.chain.subscribe();
        tokio::spawn(async move {
            while let Ok(event) = events.recv().await {
                net.on_chain_event(event);
            }
        });

        // Periodische Bereinigung + Ping-Keepalive (verhindert Idle-Timeout während IBD)
        let net = self.clone();
        tokio::spawn(async move {
            let mut interval   = tokio::time::interval(tokio::time::Duration::from_secs(30));
            let mut ping_nonce = 0u64;
            loop {
                interval.tick().await;
                if net.stop.load(Ordering::Relaxed) { break; }
                net.prune_disconnected();
                net.bans.prune_expired();
                // Keepalive-Ping an alle verbundenen Peers
                ping_nonce = ping_nonce.wrapping_add(1);
                net.broadcast(P2pMessage::Ping(ping_nonce));
            }
        });

        Ok(())
    }

    pub fn stop(&self) { self.stop.store(true, Ordering::Relaxed); }

    pub async fn connect(self: &Arc<Self>, addr: &str) -> anyhow::Result<()> {
        let sock_addr: SocketAddr = addr.parse()?;

        if self.bans.is_banned(sock_addr.ip()) {
            return Ok(());
        }

        {
            let peers     = self.peers.read();
            let mut conns = self.connecting.write();
            if peers.contains_key(&sock_addr) || conns.contains(&sock_addr) {
                return Ok(());
            }
            conns.insert(sock_addr);
        }

        let result = TcpStream::connect(sock_addr).await;
        self.connecting.write().remove(&sock_addr);

        let tcp = result?;
        info!("Connected to peer {} (TLS handshake...)", sock_addr);

        // TLS-Client-Handshake mit TOFU-Verifikation
        let connector  = self.tls.outbound_connector(sock_addr);
        let server_name = ServerName::IpAddress(sock_addr.ip().into());
        let tls_stream  = connector.connect(server_name, tcp).await?;
        info!("TLS established with {}", sock_addr);

        self.clone().handle_connection(tls_stream, sock_addr).await;
        Ok(())
    }

    pub fn peer_count(&self) -> usize { self.peers.read().len() }

    pub fn peer_heights(&self) -> Vec<(SocketAddr, u64)> {
        self.peers.read().iter()
            .map(|(addr, p)| (*addr, p.peer_height()))
            .collect()
    }

    /// Schickt eine Nachricht gezielt an einen bestimmten Peer.
    /// Gibt `true` zurück wenn der Peer verbunden war, sonst `false`.
    pub fn send_to_peer(&self, addr: SocketAddr, msg: P2pMessage) -> bool {
        if let Some(peer) = self.peers.read().get(&addr) {
            if peer.is_connected() {
                peer.send(msg);
                return true;
            }
        }
        false
    }

    // ── Internals ─────────────────────────────────────────────────────────────

    async fn accept_loop(self: Arc<Self>, listener: TcpListener) {
        loop {
            if self.stop.load(Ordering::Relaxed) { break; }
            match listener.accept().await {
                Ok((tcp, addr)) => {
                    if self.bans.is_banned(addr.ip()) {
                        warn!("Rejected banned peer {}", addr.ip());
                        continue;
                    }
                    if self.peers.read().len() >= self.max_peers {
                        warn!("Max peers ({}) reached, rejecting {}", self.max_peers, addr);
                        continue;
                    }
                    info!("Inbound peer: {} (TLS handshake...)", addr);
                    let net = self.clone();
                    tokio::spawn(async move {
                        match net.tls.acceptor.accept(tcp).await {
                            Ok(tls_stream) => {
                                info!("TLS established with {}", addr);
                                net.handle_connection(tls_stream, addr).await;
                            }
                            Err(e) => warn!("TLS handshake failed with {}: {}", addr, e),
                        }
                    });
                }
                Err(e) => {
                    if !self.stop.load(Ordering::Relaxed) { warn!("Accept error: {}", e); }
                    break;
                }
            }
        }
    }

    async fn handle_connection<S>(self: Arc<Self>, stream: S, addr: SocketAddr)
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        let height    = self.chain.height();
        let best_hash = self.chain.best_hash();

        let (peer, mut in_rx) = spawn_peer(stream, addr, height, best_hash);
        self.peers.write().insert(addr, peer.clone());
        self.known_addrs.write().insert(addr);
        peer.send(P2pMessage::GetAddr);

        while let Some(msg) = in_rx.recv().await {
            if !peer.is_connected() { break; }
            if self.bans.is_banned(addr.ip()) {
                warn!("Disconnecting newly-banned peer {}", addr);
                break;
            }
            self.clone().handle_message(msg, peer.clone());
        }

        self.peers.write().remove(&addr);
        debug!("Peer {} removed from active set", addr);
    }

    fn handle_message(self: Arc<Self>, msg: P2pMessage, peer: Arc<Peer>) {
        let ip = peer.addr.ip();
        match msg {
            P2pMessage::Version { version, height, best_hash, .. } => {
                if version != PROTOCOL_VERSION {
                    self.bans.adjust_score(ip, SCORE_INVALID_MSG);
                    peer.send(P2pMessage::Reject {
                        reason: format!(
                            "protocol version mismatch: ours={}, yours={}",
                            PROTOCOL_VERSION, version
                        ),
                    });
                    return;
                }
                peer.send(P2pMessage::VerAck);
                if height > self.chain.height() {
                    let locator = self.build_locator();
                    peer.send(P2pMessage::GetHeaders { locator });
                }
                let _ = best_hash;
            }

            P2pMessage::VerAck => {}

            P2pMessage::Ping(nonce) => {
                peer.send(P2pMessage::Pong(nonce));
            }

            P2pMessage::Pong(_) => {}

            P2pMessage::Inv(items) => {
                let want: Vec<Hash> = items.into_iter()
                    .filter_map(|item| match item {
                        InvItem::Block(h) => {
                            if !self.chain.state().is_block_known(&h) { Some(h) } else { None }
                        }
                        InvItem::Tx(h) => {
                            if !self.mempool.contains(&h) { Some(h) } else { None }
                        }
                    })
                    .collect();
                if !want.is_empty() {
                    peer.send(P2pMessage::GetData(want));
                }
            }

            P2pMessage::GetData(hashes) => {
                let hashes = hashes.into_iter().take(MAX_GETDATA_ITEMS);
                for hash in hashes {
                    if let Some(block) = self.chain.state().get_block(&hash) {
                        peer.send(P2pMessage::Block(Box::new(block)));
                    } else if let Some(tx) = self.mempool.get_tx(&hash) {
                        peer.send(P2pMessage::Tx(Box::new(tx)));
                    }
                }
            }

            P2pMessage::Block(block) => {
                // Out-of-order-fester Eingang: parent bekannt → anwenden + wartende
                // Kinder in Reihenfolge nachziehen; parent unbekannt → puffern.
                let net  = self.clone();
                let addr = peer.addr;
                tokio::spawn(async move { net.ingest_block(block, addr).await; });
            }

            P2pMessage::Tx(tx) => {
                match self.mempool.submit(*tx) {
                    Ok(txid) => {
                        self.bans.adjust_score(ip, SCORE_VALID_TX);
                        self.gossip_to_others(
                            P2pMessage::Inv(vec![InvItem::Tx(txid)]),
                            Some(peer.addr),
                        );
                    }
                    Err(e) => debug!("TX from {}: {}", peer.addr, e),
                }
            }

            P2pMessage::GetHeaders { locator } => {
                let headers = self.headers_since(&locator);
                if !headers.is_empty() {
                    peer.send(P2pMessage::Headers(headers));
                }
            }

            P2pMessage::Headers(headers) => {
                let want: Vec<Hash> = headers.iter()
                    .filter(|h| !self.chain.state().is_block_known(&h.hash()))
                    .map(|h| h.hash())
                    .collect();
                if !want.is_empty() {
                    // Paralleler Block-Download: Hashes auf alle verbundenen Peers verteilen.
                    // Jeder Peer bekommt max. CHUNK_SIZE Blöcke — verhindert Single-Peer-Bottleneck.
                    const CHUNK_SIZE: usize = 64;
                    let peer_list: Vec<Arc<super::peer::Peer>> = {
                        let peers = self.peers.read();
                        peers.values().filter(|p| p.is_connected()).cloned().collect()
                    };
                    if peer_list.is_empty() {
                        // Fallback: nur den Absender fragen
                        peer.send(P2pMessage::GetData(want));
                    } else {
                        let n = peer_list.len();
                        for (idx, chunk) in want.chunks(CHUNK_SIZE).enumerate() {
                            peer_list[idx % n].send(P2pMessage::GetData(chunk.to_vec()));
                        }
                    }
                }
            }

            P2pMessage::GetAddr => {
                let addrs: Vec<SocketAddr> = {
                    let peers = self.peers.read();
                    peers.keys()
                        .filter(|&&a| a != peer.addr)
                        .take(MAX_ADDR_ITEMS)
                        .copied()
                        .collect()
                };
                if !addrs.is_empty() {
                    peer.send(P2pMessage::Addr(addrs));
                }
            }

            P2pMessage::Addr(addrs) => {
                let new_addrs: Vec<SocketAddr> = {
                    let mut known = self.known_addrs.write();
                    addrs.into_iter()
                        .take(MAX_ADDR_ITEMS)
                        .filter(|a| !self.bans.is_banned(a.ip()))
                        .filter(|a| known.insert(*a))
                        .collect()
                };
                if !new_addrs.is_empty() {
                    self.gossip_to_others(
                        P2pMessage::Addr(new_addrs.iter().take(10).copied().collect()),
                        Some(peer.addr),
                    );
                    let net = self.clone();
                    let addrs_to_connect = new_addrs;
                    tokio::spawn(async move {
                        for addr in addrs_to_connect {
                            if net.peers.read().len() >= net.max_peers { break; }
                            let _ = net.connect(&addr.to_string()).await;
                        }
                    });
                }
            }

            P2pMessage::Reject { reason } => {
                warn!("Peer {} rejected: {}", peer.addr, reason);
            }
        }
    }

    fn on_chain_event(&self, event: ChainEvent) {
        match event {
            ChainEvent::BlockAccepted { hash, .. } => {
                self.gossip_to_others(P2pMessage::Inv(vec![InvItem::Block(hash)]), None);
            }
            ChainEvent::Reorg { .. } => {
                let height    = self.chain.height();
                let best_hash = self.chain.best_hash();
                self.broadcast(P2pMessage::Version {
                    version:    super::message::PROTOCOL_VERSION,
                    height,
                    best_hash,
                    user_agent: format!("atlas/{}", env!("CARGO_PKG_VERSION")),
                });
            }
        }
    }

    fn gossip_to_others(&self, msg: P2pMessage, except: Option<SocketAddr>) {
        let peers = self.peers.read();
        for (addr, peer) in peers.iter() {
            if Some(*addr) != except && peer.is_connected() {
                peer.send(msg.clone());
            }
        }
    }

    fn broadcast(&self, msg: P2pMessage) { self.gossip_to_others(msg, None); }

    fn prune_disconnected(&self) {
        self.peers.write().retain(|_, p| p.is_connected());
    }

    pub fn known_addrs(&self) -> Vec<SocketAddr> {
        self.known_addrs.read().iter().copied().collect()
    }

    pub fn broadcast_get_headers(&self, locator: Vec<Hash>) {
        self.broadcast(P2pMessage::GetHeaders { locator });
    }

    fn build_locator(&self) -> Vec<Hash> {
        let chain = self.chain.state().chain.read();
        let headers: Vec<_> = chain.recent_headers.iter().rev().collect();
        let mut locator = Vec::new();
        let mut step = 1usize;
        let mut i    = 0usize;
        while i < headers.len() {
            locator.push(headers[i].hash());
            i += step;
            if locator.len() > 10 { step *= 2; }
        }
        locator
    }

    /// Verarbeitet einen eingehenden Block out-of-order-fest. Ist der Parent noch
    /// nicht bekannt, wird der Block (keyed by Parent-Hash) gepuffert und beim
    /// Eintreffen des Parents in Reihenfolge angewandt. So fallen beim IBD
    /// nebenläufig gelieferte Blöcke nicht mehr als Orphan durch (Durchsatz statt
    /// ~1 Block pro Re-Request-Zyklus). `process_block` ist intern serialisiert
    /// (process_lock) → keine Doppel-Anwendung bei nebenläufigen Tasks.
    async fn ingest_block(self: Arc<Self>, block: Box<Block>, from: SocketAddr) {
        let parent = block.header.prev_hash;
        if !self.chain.state().is_block_known(&parent) {
            {
                let mut orph = self.orphans.write();
                if orph.len() >= MAX_ORPHANS {
                    debug!("Orphan-Puffer voll — Block von {} verworfen", from);
                    return;
                }
                orph.insert(parent, block);
            }
            // Race: der Parent landete genau zwischen Check und Insert? Dann den
            // eben gepufferten Block sofort nachziehen (sonst bliebe er liegen).
            if self.chain.state().is_block_known(&parent) {
                let pending = self.orphans.write().remove(&parent); // Guard hier fallen lassen
                if let Some(b) = pending {
                    Box::pin(self.clone().ingest_block(b, from)).await;
                }
            }
            return;
        }

        // Parent bekannt → diesen Block und dann seine wartende Nachfolgekette
        // (`orphans[hash]`) in Reihenfolge anwenden.
        let mut next = Some(block);
        while let Some(b) = next.take() {
            let hash  = b.hash();
            let chain = self.chain.clone();
            match tokio::task::spawn_blocking(move || chain.process_block(*b)).await {
                Ok(Ok(())) => {
                    self.bans.adjust_score(from.ip(), SCORE_VALID_BLOCK);
                    self.gossip_to_others(P2pMessage::Inv(vec![InvItem::Block(hash)]), Some(from));
                    next = self.orphans.write().remove(&hash);
                }
                Ok(Err(e)) => {
                    use crate::chain::ChainError;
                    match &e {
                        ChainError::AlreadyKnown(_) => {
                            self.bans.adjust_score(from.ip(), SCORE_DUPLICATE);
                            // Block ist vorhanden → ein wartendes Kind trotzdem nachziehen.
                            next = self.orphans.write().remove(&hash);
                        }
                        ChainError::Validation(_) | ChainError::Execution(_) => {
                            self.bans.adjust_score(from.ip(), SCORE_INVALID_BLOCK);
                            warn!("Invalid block from {} (score={}): {}", from, self.bans.score(from.ip()), e);
                        }
                        _ => debug!("Block from {} not applied: {}", from, e),
                    }
                }
                Err(_) => warn!("Block processing task panicked for peer {}", from),
            }
        }
    }

    fn headers_since(&self, locator: &[Hash]) -> Vec<atlas_core::block::BlockHeader> {
        // Gemeinsamen Vorfahren bestimmen: der höchste Locator-Hash, den WIR
        // kennen (Locator ist tip→genesis geordnet). Erst im RAM-Fenster, dann im
        // STORAGE suchen — sonst kann ein frischer Node nie syncen: liegt der
        // Genesis außerhalb des `recent_headers`-Fensters (Kette > MAX_RECENT_
        // HEADERS=2016), wird der Vorfahre nicht gefunden und es kämen Header aus
        // der Mitte der Kette, die nicht an den Genesis des Joiners anschließen.
        let storage = self.chain.storage_arc();
        let mut start_height: u64 = 0;
        'find: for h in locator {
            {
                let chain = self.chain.state().chain.read();
                if let Some(hdr) = chain.recent_headers.iter().find(|x| x.hash() == *h) {
                    start_height = hdr.height;
                    break 'find;
                }
            }
            if let Some(store) = storage.as_ref() {
                if let Ok(Some(hdr)) = store.load_header(h) {
                    start_height = hdr.height;
                    break 'find;
                }
            }
        }

        let tip = self.chain.height();
        // Header ab `start_height + 1` (max 2000) — bevorzugt aus dem Storage
        // (vollständige Kette ab Genesis), damit auch ein Node bei Höhe 0 syncen kann.
        if let Some(store) = storage.as_ref() {
            let mut out = Vec::new();
            let mut height = start_height + 1;
            while height <= tip && out.len() < 2000 {
                match store.load_header_by_height(height) {
                    Ok(Some(hdr)) => out.push(hdr),
                    _ => break,
                }
                height += 1;
            }
            out
        } else {
            // Kein Storage (z.B. Test-/RAM-Only-Node): Fallback auf das Fenster.
            let chain = self.chain.state().chain.read();
            let known: HashSet<Hash> = locator.iter().copied().collect();
            let start_pos = chain.recent_headers.iter()
                .position(|h| known.contains(&h.hash()))
                .unwrap_or(0);
            chain.recent_headers.iter().skip(start_pos + 1).take(2000).cloned().collect()
        }
    }
}
