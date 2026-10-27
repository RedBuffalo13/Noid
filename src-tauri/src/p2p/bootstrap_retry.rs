//! Periodic re-dial of pinned bootstrap seeds.
//!
//! `P2PNode::bootstrap` dials each seed exactly once. A pinned seed behind a
//! shared port (SO_REUSEPORT with another node answering on the same socket)
//! randomly lands on the wrong peer and fails with `WrongPeerId` — and dial
//! backoff then suppresses redials for up to 5 minutes, while three unlucky
//! landings evict the seed from `known_relays` entirely. The node would sit
//! disconnected until restart.
//!
//! Every tick we re-dial each bootstrap seed that has no live connection:
//! the dial backoff is cleared for seed peers (they are infrastructure, not
//! flaky contacts), the seed is restored into `known_relays` when eviction
//! dropped it, and the dial itself is deduplicated by the swarm when one is
//! already in flight.
//!
//! Each tick dials ONE transport per seed, rotating quic → tcp → ws via
//! `bootstrap_dial_cursor` — spraying all transports in parallel opens a
//! burst of carrier-NAT flows that starve each other on mobile networks.

use libp2p::PeerId;

use crate::p2p::node::P2PNode;

impl P2PNode {
    /// Re-dial every pinned bootstrap seed that currently has no connection.
    /// Cheap no-op while connected — intended to run on a short interval.
    pub fn retry_bootstrap_dials(&mut self) {
        let seeds: Vec<(PeerId, libp2p::Multiaddr)> = self.bootstrap_peers.clone();
        let mut by_peer: std::collections::HashMap<PeerId, Vec<libp2p::Multiaddr>> =
            std::collections::HashMap::new();
        for (peer, addr) in seeds {
            by_peer.entry(peer).or_default().push(addr);
        }
        let now = std::time::Instant::now();
        for (peer, mut addrs) in by_peer {
            if self.connected_peers.contains(&peer) {
                self.bootstrap_retry_state.remove(&peer.to_string());
                continue;
            }
            // Infrastructure retries stay bounded even after a long outage.
            // Contact dial backoff is separate and remains unchanged.
            let key = peer.to_string();
            if let Some(&(_, next)) = self.bootstrap_retry_state.get(&key) {
                if now < next {
                    continue;
                }
            }
            // Restore the seed's relay book entry — repeated WrongPeerId
            // landings on a shared port trigger the 3-strikes eviction, but
            // the seed addr is correct and must stay dialable.
            addrs.sort_by_key(crate::p2p::transport_rank::transport_rank);
            if !self.known_relays.iter().any(|(p, _)| *p == peer) {
                self.known_relays.push((peer, addrs[0].clone()));
            }
            self.clear_dial_backoff(&peer);
            // D8: skip dead-marked transports — rotate to the next one.
            let len = addrs.len();
            let start = *self.bootstrap_dial_cursor.get(&peer).unwrap_or(&0);
            let mut addr = None;
            let mut picked = 0usize;
            for i in 0..len {
                let idx = (start + i) % len;
                if !self.is_dead_addr(&addrs[idx]) {
                    addr = Some(addrs[idx].clone());
                    picked = idx + 1;
                    break;
                }
            }
            self.bootstrap_dial_cursor.insert(peer, picked);
            let Some(addr) = addr else {
                continue;
            };
            let tries = self.bootstrap_retry_state.get(&key).map(|s| s.0).unwrap_or(0) + 1;
            let delay = std::time::Duration::from_secs(30)
                .saturating_mul(1u32 << tries.min(9))
                .min(std::time::Duration::from_secs(60));
            self.bootstrap_retry_state.insert(key, (tries, now + delay));
            // Failure eviction removes address books as well as routing.
            // Re-seed before the bounded retry so request_response and
            // Kademlia can recover too, not just the explicit swarm dial.
            for candidate in &addrs {
                self.register_peer_addr(peer, candidate.clone(), "bootstrap-retry", true);
            }
            log::debug!("Bootstrap retry: redialing seed {} (try {})", addr, tries);
            let _ = self
                .swarm
                .dial(crate::p2p::dial_opts::dial_opts(Some(peer), addr));
        }
        // D9: blind seeds (no pinned peer id) get one-shot dials that are
        // never retried. Re-dial them under the same backoff policy —
        // ConnectionEstablished removes the addr once the peer id is
        // learned, so re-dial only while the addr is still unresolved.
        for addr in self.blind_bootstrap_addrs.clone() {
            let key = addr.to_string();
            if self.is_dead_addr(&addr) {
                continue;
            }
            if let Some(&(_, next)) = self.bootstrap_retry_state.get(&key) {
                if now < next {
                    continue;
                }
            }
            let tries = self.bootstrap_retry_state.get(&key).map(|s| s.0).unwrap_or(0) + 1;
            let delay = std::time::Duration::from_secs(30)
                .saturating_mul(1u32 << tries.min(9))
                .min(std::time::Duration::from_secs(60));
            self.bootstrap_retry_state.insert(key, (tries, now + delay));
            log::debug!("Bootstrap retry: blind redial {} (try {})", addr, tries);
            let _ = self.swarm.dial(crate::p2p::dial_opts::dial_opts(None, addr));
        }
    }
}
