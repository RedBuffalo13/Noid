//! P2PNode external-addr validation + seed-addr methods — extracted from node.rs (Q05/A5b). Bodies moved verbatim.

use libp2p::{multiaddr::Protocol, Multiaddr, PeerId};

use crate::p2p::node::P2PNode;

impl P2PNode {
    /// Ephemeral node for tests — fresh random keys, nothing written to disk.
    /// Production code never uses this: real nodes are created via
    /// `new_with_keys` after the key store is unlocked by a successful login.
    pub fn register_external_addr(&mut self, addr: Multiaddr) {
        self.swarm.add_external_address(addr.clone());
        if !self.external_addrs.contains(&addr) {
            self.external_addrs.push(addr);
        }
    }

    /// Whether `addr` plausibly identifies `peer` as a dialable address:
    /// - at most one `/p2p-circuit` — nested circuits are malformed;
    /// - if a circuit is present, the address must terminate at `peer`
    ///   (`…/p2p/<relay>/p2p-circuit/p2p/<peer>`). A relayed address ending
    ///   in a *different* peer id is that other peer's address, and one
    ///   ending in bare `/p2p-circuit` is a reservation-listen form, not a
    ///   peer address.
    pub fn is_valid_addr_for_peer(addr: &Multiaddr, peer: &PeerId) -> bool {
        let mut circuits = 0u8;
        let mut last_p2p: Option<PeerId> = None;
        for p in addr.iter() {
            match p {
                Protocol::P2pCircuit => circuits += 1,
                Protocol::P2p(id) => last_p2p = Some(id),
                _ => {}
            }
        }
        if circuits > 1 {
            return false;
        }
        circuits == 0 || last_p2p == Some(*peer)
    }

    /// True when `addr` targets one of our own listen sockets. Same-host
    /// instances and stale peer-cache entries leak our own addrs into the
    /// address book under foreign peer ids — dialing them can only reach
    /// ourselves (or fail outright: on Windows the shared listen port makes
    /// the outbound connect error with WSAEADDRINUSE/10048). Circuit addrs
    /// legitimately reuse a relay's ip:port — never self-matched.
    pub(crate) fn is_own_listen_addr(&self, addr: &Multiaddr) -> bool {
        // A circuit addr terminating at OUR peer id is ours too — without
        // this check a self-minted `/p2p-circuit/p2p/<self>` leaked into the
        // dial book and produced `tried to dial local peer id`.
        if crate::p2p::terminal_peer_id::terminal_peer_id(addr) == Some(self.peer_id) {
            return true;
        }
        if addr.iter().any(|p| matches!(p, Protocol::P2pCircuit)) {
            return false;
        }
        // An addr terminating at a *different* peer id cannot be our own
        // listen address: two devices behind the same NAT legitimately
        // advertise the same public ip:port shape, and ip-only matching
        // would drop a real sibling's addr as "self". A genuinely stale
        // leak of our own addr under a foreign id self-corrects — dialing
        // it reaches our listener and fails with UnexpectedPeerId, which
        // evicts the addr.
        if let Some(Protocol::P2p(id)) = addr.iter().last() {
            if id != self.peer_id {
                return false;
            }
        }
        let mut ip = None;
        let mut port = None;
        for p in addr.iter() {
            match p {
                Protocol::Ip4(v) => ip = Some(std::net::IpAddr::V4(v)),
                Protocol::Ip6(v) => ip = Some(std::net::IpAddr::V6(v)),
                Protocol::Tcp(v) => port = Some(v),
                _ => {}
            }
        }
        let (Some(ip), Some(port)) = (ip, port) else {
            return false;
        };
        // Loopback/unspecified remote ip can only ever reach this host — any
        // listener on the same port is ours.
        if ip.is_loopback() || ip.is_unspecified() {
            return self.swarm.listeners().any(|l| {
                l.iter().any(|p| matches!(p, Protocol::Tcp(v) if v == port))
            });
        }
        // Concrete remote ip: self only when it matches a *bound* listener ip
        // or one of our confirmed/provisioned external addresses. A wildcard
        // listener (0.0.0.0) does NOT make every same-port remote addr ours —
        // other hosts legitimately listen on the same port.
        self.swarm.listeners().any(|l| {
            let mut lip = None;
            let mut lport = None;
            for p in l.iter() {
                match p {
                    Protocol::Ip4(v) => lip = Some(std::net::IpAddr::V4(v)),
                    Protocol::Ip6(v) => lip = Some(std::net::IpAddr::V6(v)),
                    Protocol::Tcp(v) => lport = Some(v),
                    _ => {}
                }
            }
            lport == Some(port)
                && match lip {
                    Some(lip) if !lip.is_unspecified() => lip == ip,
                    _ => self.is_own_ip(ip),
                }
        })
    }

    /// True when `ip` belongs to this node: a confirmed external address or a
    /// provisioned `external_addr` from relay_config.
    fn is_own_ip(&self, ip: std::net::IpAddr) -> bool {
        self.external_addrs.iter().any(|a| {
            a.iter().any(|p| match p {
                Protocol::Ip4(v) => std::net::IpAddr::V4(v) == ip,
                Protocol::Ip6(v) => std::net::IpAddr::V6(v) == ip,
                _ => false,
            })
        })
    }

    /// Feed every valid cached addr for `peer` into the swarm's address
    /// sources so a queued request-response dial has something to try.
    /// Skipped while already connected (no dial will be issued anyway).
    pub(crate) fn seed_peer_addrs(&mut self, peer_id: &PeerId) {
        if self.connected_peers.contains(peer_id) {
            return;
        }
        // A reservation-eligible relay must be reached directly — feeding a
        // cached circuit addr for it could produce a relayed conn that a
        // later RESERVE deduplicates onto (nested-circuit listen addr).
        let is_relay = self.known_relays.iter().any(|(p, _)| p == peer_id);
        let mut addrs = self.peer_cache.addrs_of(peer_id);
        // Address order is the dial order. Same-NAT peers share our observed
        // public IP — the WAN hairpin path back through the router almost
        // never works, so their LAN addrs (learned via mDNS/Identify) must
        // be tried first. For WAN-only peers a stale LAN addr fails fast
        // (RST/ARP timeout), so ordering Lan-first unconditionally is safe.
        let shares_ext_ip = addrs.iter().any(|a| {
            a.iter().any(|p| match p {
                Protocol::Ip4(v) => self.is_own_ip(std::net::IpAddr::V4(v)),
                Protocol::Ip6(v) => self.is_own_ip(std::net::IpAddr::V6(v)),
                _ => false,
            })
        });
        if shares_ext_ip {
            addrs.sort_by_key(|a| {
                match crate::p2p::classify_peer_addr::classify_peer_addr(a, peer_id) {
                    crate::p2p::addr_class::AddrClass::Lan => 0,
                    _ => 1,
                }
            });
        }
        // QUIC first always: on carrier NAT (Tele2 evicts TCP flow mappings
        // mid-stream) a QUIC conn survives rebind via connection ID, while
        // every TCP flow is a ~30s ticking bomb. Feeding QUIC addrs first
        // means the parallel dial lands the resilient transport earliest.
        addrs.sort_by_key(|a| {
            crate::p2p::transport_rank::transport_rank(a)
        });
        // Cap how many addrs a single seed round feeds the swarm — a peer
        // with many stale addrs must not fan out into a dial burst per
        // retry cycle (small routers drown their conntrack on this).
        const MAX_SEED_ADDRS: usize = 6;
        let mut fed = 0usize;
        for addr in addrs {
            // Dead-marked addrs proved undialable — feeding them again just
            // re-arms the dial→fail→evict→re-learn loop.
            if self.is_dead_addr(&addr) {
                continue;
            }
            if is_relay
                && addr
                    .iter()
                    .any(|p| matches!(p, Protocol::P2pCircuit))
            {
                continue;
            }
            // Same-NAT siblings legitimately advertise our observed public
            // ip:port — the self-check must run on the addr *attributed to
            // this peer*, so a bare transport addr gets the /p2p/ suffix
            // first (foreign terminal id → not "ours"). These addrs are
            // dialed with an expected peer id anyway: a real self-leak fails
            // with WrongPeerId and is evicted.
            let tagged = match addr.iter().last() {
                Some(Protocol::P2p(_)) => addr.clone(),
                _ => addr.clone().with(Protocol::P2p(*peer_id)),
            };
            if self.is_own_listen_addr(&tagged) {
                continue;
            }
            match crate::p2p::classify_peer_addr::classify_peer_addr(&addr, peer_id) {
                crate::p2p::addr_class::AddrClass::Local
                | crate::p2p::addr_class::AddrClass::Malformed => continue,
                _ => {}
            }
            // F4: request-response/mailbox dial whatever is seeded here — the
            // explicit `dial()` privacy filter is bypassed. Enforce the same
            // policy so RelayedOnly never fans out direct WAN dials.
            if !self.dial_allowed(&tagged) {
                continue;
            }
            self.swarm.add_peer_address(*peer_id, addr);
            fed += 1;
            if fed >= MAX_SEED_ADDRS {
                break;
            }
        }
    }

}
