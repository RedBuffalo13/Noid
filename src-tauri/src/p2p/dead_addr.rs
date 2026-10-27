use libp2p::multiaddr::Protocol;
use libp2p::Multiaddr;

use crate::p2p::node::P2PNode;

/// Consecutive transport-level dial failures before an addr is dead-marked.
const DEAD_AFTER_FAILURES: u8 = 3;
/// How long a transport-failed addr stays dead (it may be a transient NAT
/// flap — the mark expires so the addr can be re-learned later).
const TRANSPORT_DEAD_TTL: std::time::Duration = std::time::Duration::from_secs(30 * 60);
/// A `WrongPeerId` answer is a hard fact: this ip:port is bound to a
/// different peer for the whole session — re-learning it only produces an
/// endless dial→WrongPeerId→evict→identify→re-learn loop.
const WRONG_PEER_DEAD_TTL: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);

impl P2PNode {
    /// Canonical transport form of a dialed addr for failure bookkeeping.
    /// A dialed addr carries the `/p2p/<id>` dial tag while Kademlia and the
    /// peer cache store the bare form — removal and dead-marking must
    /// normalize or they silently miss. A circuit addr keeps its terminal
    /// `/p2p`: it is the destination, not a dial tag.
    pub(crate) fn canonical_dial_addr(addr: &Multiaddr) -> Multiaddr {
        let has_circuit = addr.iter().any(|p| matches!(p, Protocol::P2pCircuit));
        match (addr.iter().last(), has_circuit) {
            (Some(Protocol::P2p(_)), false) => {
                let mut a = addr.clone();
                a.pop();
                a
            }
            _ => addr.clone(),
        }
    }

    /// Record a dial failure for `addr`. After enough consecutive failures
    /// (or immediately on `wrong_peer`) the addr is dead-marked: learned
    /// addrs are checked against the dead set at ingestion, so identify
    /// cannot resurrect an undialable addr on every connection.
    /// Circuit addrs are never dead-marked — their liveness is owned by the
    /// relay reservation, not by our dial history.
    pub(crate) fn note_dial_failure(&mut self, addr: &Multiaddr, wrong_peer: bool) {
        if addr.iter().any(|p| matches!(p, Protocol::P2pCircuit)) {
            return;
        }
        let key = Self::canonical_dial_addr(addr).to_string();
        if wrong_peer {
            self.addr_failures.remove(&key);
            self.dead_addrs
                .insert(key.clone(), std::time::Instant::now() + WRONG_PEER_DEAD_TTL);
            log::info!("Dead-marked addr (wrong peer id): {}", key);
            return;
        }
        // Configured seeds are recovery infrastructure, not discovered
        // hints. Their retry loop bounds dial rate; a transient outage
        // must not additionally quarantine every transport for 30 minutes.
        let seed = self.bootstrap_peers.iter().any(|(_, a)| {
            Self::canonical_dial_addr(a).to_string() == key
        }) || self.blind_bootstrap_addrs.iter().any(|a| {
            Self::canonical_dial_addr(a).to_string() == key
        });
        if seed {
            self.addr_failures.remove(&key);
            return;
        }
        let failures = self.addr_failures.entry(key.clone()).or_insert(0);
        *failures = failures.saturating_add(1);
        if *failures >= DEAD_AFTER_FAILURES {
            self.addr_failures.remove(&key);
            self.dead_addrs
                .insert(key.clone(), std::time::Instant::now() + TRANSPORT_DEAD_TTL);
            log::info!("Dead-marked addr after {} dial failures: {}", DEAD_AFTER_FAILURES, key);
        }
    }

    /// A successful dial proves the addr — reset its failure bookkeeping so
    /// a previously dead-marked addr can live again.
    pub(crate) fn note_dial_success(&mut self, addr: &Multiaddr) {
        let key = Self::canonical_dial_addr(addr).to_string();
        self.addr_failures.remove(&key);
        self.dead_addrs.remove(&key);
    }

    /// True while `addr` is dead-marked — `register_peer_addr` and
    /// `seed_peer_addrs` must skip it. Expired marks are dropped lazily.
    pub(crate) fn is_dead_addr(&mut self, addr: &Multiaddr) -> bool {
        let key = Self::canonical_dial_addr(addr).to_string();
        match self.dead_addrs.get(&key) {
            Some(until) if *until > std::time::Instant::now() => true,
            Some(_) => {
                self.dead_addrs.remove(&key);
                false
            }
            None => false,
        }
    }
}
