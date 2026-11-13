//! P2PNode connection-class/bootstrap/dial methods — extracted from node.rs (Q05/A5b). Bodies moved verbatim.

use anyhow::Result;
use libp2p::{multiaddr::Protocol, Multiaddr, PeerId};

use crate::p2p::node::P2PNode;
use crate::p2p::relay_config::PrivacyMode;

impl P2PNode {
    /// Ephemeral node for tests — fresh random keys, nothing written to disk.
    /// Production code never uses this: real nodes are created via
    /// `new_with_keys` after the key store is unlocked by a successful login.
    pub(crate) fn conn_class(
        &self,
        peer_id: &PeerId,
    ) -> crate::p2p::connectivity_config::ConnClass {
        use crate::p2p::connectivity_config::ConnClass;
        if self.reserved_relays.contains(peer_id)
            || self.known_relays.iter().any(|(p, _)| p == peer_id)
            || self
                .mailbox_cache
                .values()
                .any(|(mp, _, _)| mp == &peer_id.to_string())
        {
            ConnClass::Infra
        } else {
            ConnClass::Contact
        }
    }

    pub fn bootstrap(&mut self, nodes: Vec<Multiaddr>) -> Result<()> {
        log::debug!("Starting bootstrap with {} nodes", nodes.len());
        for addr in &nodes {
            log::debug!("Bootstrap node: {}", addr);
        }
        // Group pinned seed addrs by peer — dialing every transport at once
        // opens parallel flows that starve carrier-NAT mappings on mobile
        // (Tele2 evicts old mappings as new conns form). One conn per seed
        // suffices; retries rotate transports via bootstrap_dial_cursor.
        let mut pinned: std::collections::HashMap<PeerId, Vec<Multiaddr>> =
            std::collections::HashMap::new();
        let mut blind: Vec<Multiaddr> = Vec::new();
        for addr in nodes {
            if let Some(peer_id) = addr.iter().find_map(|p| match p {
                Protocol::P2p(id) => Some(id),
                _ => None,
            }) {
                if peer_id != self.peer_id {
                    pinned.entry(peer_id).or_default().push(addr);
                }
            } else {
                blind.push(addr);
            }
        }
        for (peer_id, mut addrs) in pinned {
            addrs.sort_by_key(crate::p2p::transport_rank::transport_rank);
            for addr in &addrs {
                self.register_peer_addr(peer_id, addr.clone(), "bootstrap", true);
                // Only transport-level relay addresses are usable for
                // reservations — a relayed address here would compose into
                // a nested circuit, which we refuse to dial.
                if !addr.iter().any(|p| matches!(p, Protocol::P2pCircuit)) {
                    self.known_relays.push((peer_id, addr.clone()));
                    self.bootstrap_peers.push((peer_id, addr.clone()));
                }
            }
            // Dial the bootstrap node to establish connection.
            // NOTE: no relay reservation here — the reservation request
            // must be issued AFTER the connection exists, otherwise the
            // behaviour's internal dial races with this manual dial and
            // the RESERVE command is silently dropped (dial dedup).
            // The ConnectionEstablished handler issues the reservation.
            let preferred = addrs[0].clone();
            log::info!("Bootstrap: dialing {}", preferred);
            if let Some(opts) =
                crate::p2p::dial_opts::dial_opts(Some(peer_id), preferred)
            {
                let _ = self.swarm.dial(opts);
            }
            self.bootstrap_dial_cursor.insert(peer_id, 1);
        }
        for addr in blind {
            // Blind seed: no pinned peer id — survives relay identity
            // rotation. Dial the bare transport; ConnectionEstablished
            // registers the learned peer id into Kademlia + relay book.
            log::info!("Bootstrap: blind-dialing {} (no pinned peer id)", addr);
            self.blind_bootstrap_addrs.push(addr.clone());
            if let Some(opts) = crate::p2p::dial_opts::dial_opts(None, addr) {
                let _ = self.swarm.dial(opts);
            }
        }
        match self.swarm.behaviour_mut().kademlia.bootstrap() {
            Ok(query_id) => log::debug!("Bootstrap query started: {:?}", query_id),
            Err(e) => {
                // No known peers — expected on a fresh install. The network is
                // joined via mDNS (LAN) or a contact's address hint (WAN).
                log::debug!("Kademlia bootstrap deferred until first peer: {}", e);
            }
        }
        Ok(())
    }

    /// Whether dialing `addr` is allowed under the current privacy mode.
    /// In `RelayedOnly` mode we may still dial known relays directly (the relay
    /// inherently sees our IP) and LAN/private addresses — but never other
    /// WAN peers directly.
    pub(crate) fn dial_allowed(&self, addr: &Multiaddr) -> bool {
        if self.relay_config.privacy != PrivacyMode::RelayedOnly {
            return true;
        }
        if addr
            .iter()
            .any(|p| matches!(p, Protocol::P2pCircuit | Protocol::Onion3(_)))
        {
            return true;
        }
        // Explicit user-provided address (invite/contact hint) — consent given.
        if self.allowed_dial_addrs.contains(addr) {
            return true;
        }
        if let Some(target) = addr.iter().find_map(|p| match p {
            Protocol::P2p(id) => Some(id),
            _ => None,
        }) {
            if self.known_relays.iter().any(|(p, _)| *p == target) {
                return true;
            }
        }
        // LAN/private addresses are fine — the local network sees our IP anyway.
        let mut only_local = true;
        for proto in addr.iter() {
            match proto {
                Protocol::Ip4(ip) => {
                    if !(ip.is_private() || ip.is_loopback() || ip.is_link_local()) {
                        only_local = false;
                    }
                }
                Protocol::Ip6(ip) => {
                    if !(ip.is_loopback() || ip.is_unicast_link_local()) {
                        only_local = false;
                    }
                }
                Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_) | Protocol::Dnsaddr(_) => {
                    only_local = false;
                }
                _ => {}
            }
        }
        only_local
    }

    /// Register an external (public) address: advertised to AutoNAT observers,
    /// included in invites and relay RESERVE responses.
    pub async fn dial(&mut self, addr: Multiaddr) -> Result<()> {
        if addr
            .iter()
            .filter(|p| matches!(p, Protocol::P2pCircuit))
            .count()
            > 1
        {
            log::debug!("Refusing to dial nested-circuit address: {}", addr);
            return Ok(());
        }
        // A circuit addr terminating at a known relay would create a *relayed*
        // conn to that relay — reservations issued on it later can be
        // deduplicated onto the circuit and produce undialable nested listen
        // addrs. A relay must be reached directly: substitute its transport
        // address.
        let has_circuit = addr
            .iter()
            .any(|p| matches!(p, Protocol::P2pCircuit));
        if has_circuit {
            let target = addr
                .iter()
                .filter_map(|p| match p {
                    Protocol::P2p(id) => Some(id),
                    _ => None,
                })
                .last();
            if let Some(target) = target {
                if self.known_relays.iter().any(|(p, _)| *p == target)
                    && !self.allowed_dial_addrs.contains(&addr)
                {
                    let direct = self.direct_addrs_of(&target);
                    if !direct.is_empty() {
                        log::debug!(
                            "Dial to relay {} via circuit refused — dialing {} direct transport(s)",
                            target,
                            direct.len()
                        );
                        if let Err(e) = self.swarm.dial(
                            crate::p2p::dial_opts::dial_opts_multi(target, direct),
                        ) {
                            log::debug!("Direct dial to relay {} failed: {}", target, e);
                        }
                    }
                    return Ok(());
                }
            }
        }
        if self.is_own_listen_addr(&addr) {
            log::debug!("Refusing to dial our own listen socket: {}", addr);
            return Ok(());
        }
        if !self.dial_allowed(&addr) {
            log::debug!(
                "RelayedOnly mode: blocked direct WAN dial to {} \
                 (not a known relay and not user-provided)",
                addr
            );
            return Ok(());
        }
        // Per-peer backoff: a recently unreachable peer is not redialed —
        // outgoing messages route through the mailbox path instead.
        let dial_peer = addr
            .iter()
            .filter_map(|p| match p {
                Protocol::P2p(id) => Some(id),
                _ => None,
            })
            .last();
        if let Some(target) = dial_peer {
            if target == self.peer_id {
                log::debug!("Refusing to dial our own peer id: {}", addr);
                return Ok(());
            }
            if self.dial_is_backed_off(&target) {
                log::debug!("Dial to {} skipped — peer in backoff window", target);
                return Ok(());
            }
            // Last line of defense for internal dial paths (kad/rr resolution)
            // that bypass the ingestion-time filter: never dial addrs that can
            // structurally never reach the peer. User-authorized addrs
            // (`allowed_dial_addrs`) are exempt — loopback dials are a legit
            // same-host/dev scenario.
            if !self.allowed_dial_addrs.contains(&addr)
                && matches!(
                    crate::p2p::classify_peer_addr::classify_peer_addr(&addr, &target),
                    crate::p2p::addr_class::AddrClass::Malformed
                        | crate::p2p::addr_class::AddrClass::Local
                )
            {
                log::debug!("Refusing to dial undialable addr for {}: {}", target, addr);
                return Ok(());
            }
        }
        let dial_peer = addr
            .iter()
            .filter_map(|p| match p {
                Protocol::P2p(id) => Some(id),
                _ => None,
            })
            .last();
        if let Some(opts) = crate::p2p::dial_opts::dial_opts(dial_peer, addr.clone()) {
            if let Err(e) = self.swarm.dial(opts) {
                log::debug!("Dial {} failed to initiate: {}", addr, e);
            }
        }
        Ok(())
    }
}
