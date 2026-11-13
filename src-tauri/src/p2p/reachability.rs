//! Reachability level — how a contact can be reached right now, ranked by
//! certainty/cost. Replaces the binary `connected_peers` presence model:
//! in on-demand mode a peer without a live conn is not "offline", it is
//! reachable through a dialable path (direct / relay circuit / onion3)
//! or through its mailbox node.

use libp2p::PeerId;
use serde::{Deserialize, Serialize};

use crate::p2p::addr_class::AddrClass;
use crate::p2p::classify_peer_addr::classify_peer_addr;
use crate::p2p::node::P2PNode;

/// Ranked reachability — first match wins (best/cheapest path).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReachLevel {
    /// Live connection right now — instant delivery.
    Connected,
    /// Fresh public/LAN direct addr in the peer cache — on-demand dial
    /// probably succeeds.
    Direct,
    /// A `/p2p-circuit` addr terminating at the peer — dial through its
    /// relay reservation.
    Relayed,
    /// An `/onion3/` endpoint — dialable while OUR Tor generation runs.
    Onion,
    /// Only the mailbox pointer resolves — store-and-forward, the peer
    /// picks envelopes up when it comes online.
    Mailbox,
    /// Nothing dialable and no mailbox — outbox only.
    Offline,
}

/// Per-peer reachability snapshot for the UI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reachability {
    pub level: ReachLevel,
    /// Every dialable path class found ("direct"/"relay"/"onion") —
    /// the UI shows all variants when several exist.
    pub paths: Vec<String>,
    /// Whether the peer itself advertises relay capability.
    pub is_relay: bool,
}

impl P2PNode {
    /// Pure function over local state — no probes. First found level wins.
    pub fn reachability(&self, peer_id: &PeerId) -> Reachability {
        if self.connected_peers.contains(peer_id) {
            return self.reach_snapshot(ReachLevel::Connected, peer_id);
        }
        let mut has_direct = false;
        let mut has_circuit = false;
        let mut has_onion = false;
        for addr in self.peer_cache.addrs_of(peer_id) {
            match classify_peer_addr(&addr, peer_id) {
                AddrClass::PublicDirect | AddrClass::Lan => has_direct = true,
                AddrClass::Circuit => has_circuit = true,
                AddrClass::Onion3 => has_onion = true,
                _ => {}
            }
        }
        let level = if has_direct {
            ReachLevel::Direct
        } else if has_circuit {
            ReachLevel::Relayed
        } else if has_onion {
            ReachLevel::Onion
        } else if self
            .mailbox_cache
            .contains_key(&peer_id.to_string())
        {
            ReachLevel::Mailbox
        } else {
            ReachLevel::Offline
        };
        let mut snap = self.reach_snapshot(level, peer_id);
        // Multi-path: collect every dialable class, not just the winning one.
        if has_direct {
            snap.paths.push("direct".into());
        }
        if has_circuit {
            snap.paths.push("relay".into());
        }
        if has_onion {
            snap.paths.push("onion".into());
        }
        snap
    }

    fn reach_snapshot(&self, level: ReachLevel, peer_id: &PeerId) -> Reachability {
        Reachability {
            level,
            paths: Vec::new(),
            is_relay: self.known_relays.iter().any(|(p, _)| p == peer_id),
        }
    }
}
