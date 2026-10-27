use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};

use crate::p2p::addr_class::AddrClass;
use crate::p2p::classify_peer_addr::classify_peer_addr;
use crate::p2p::node::P2PNode;

impl P2PNode {
    /// The single ingestion point for a peer address learned from any
    /// discovery source (Identify, mDNS, peer cache, bootstrap, DHT).
    ///
    /// - `Malformed` addrs are always dropped: they can never reach the peer
    ///   and would otherwise be re-dialed forever.
    /// - `Local` addrs (loopback/unspecified) are dropped for untrusted
    ///   `trusted = false` sources; trusted input (bootstrap config, explicit
    ///   user commands, relay registration) keeps them for same-host and
    ///   LAN-only setups. They still never persist: `PeerCache::sanitize`
    ///   strips them on load.
    /// - `Lan` addrs go only to the local dial book and peer cache — never
    ///   into Kademlia, where they would be served to WAN peers that cannot
    ///   use them (poisoning the shared routing table).
    /// - `PublicDirect`/`Circuit` go to Kademlia, the local dial book, and
    ///   the persistent cache.
    /// - Addrs targeting our own listen sockets or our own peer id are
    ///   always dropped (self-dial protection).
    pub(crate) fn register_peer_addr(
        &mut self,
        peer: PeerId,
        addr: Multiaddr,
        source: &'static str,
        trusted: bool,
    ) {
        if peer == self.peer_id {
            log::debug!("Dropping {} addr for self peer: {}", source, addr);
            return;
        }
        // Self-check on the addr attributed to *this* peer: a bare transport
        // addr gets the /p2p/ suffix so the foreign terminal id exempts it
        // (same-NAT siblings share our public ip:port — dropping them at
        // ingestion starved the dial book). A genuine leak of our own addr
        // under a foreign id self-corrects via WrongPeerId eviction.
        let tagged = match addr.iter().last() {
            Some(Protocol::P2p(_)) => addr.clone(),
            _ => addr.clone().with(Protocol::P2p(peer)),
        };
        if self.is_own_listen_addr(&tagged) {
            log::debug!("Dropping {} addr for {} — self: {}", source, peer, addr);
            return;
        }
        // An addr that keeps failing (undialable transport, wrong peer at the
        // socket) is dead-marked — without this gate identify would re-learn
        // it on every connection and the poisoned-addr loop would never end.
        if self.is_dead_addr(&addr) {
            log::debug!("Dropping {} addr for {} — dead-marked: {}", source, peer, addr);
            return;
        }
        match classify_peer_addr(&addr, &peer) {
            AddrClass::Malformed => {
                log::debug!("Dropping {} addr for {} — malformed: {}", source, peer, addr);
                return;
            }
            AddrClass::Local if !trusted => {
                log::debug!("Dropping {} addr for {} — local: {}", source, peer, addr);
                return;
            }
            AddrClass::Local | AddrClass::Lan => {
                self.swarm.add_peer_address(peer, addr.clone());
            }
            AddrClass::PublicDirect | AddrClass::Circuit => {
                self.swarm
                    .behaviour_mut()
                    .kademlia
                    .add_address(&peer, addr.clone());
                self.swarm.add_peer_address(peer, addr.clone());
            }
        }
        self.peer_cache.upsert(peer, vec![addr], false);
        self.peer_cache_dirty = true;
    }
}
