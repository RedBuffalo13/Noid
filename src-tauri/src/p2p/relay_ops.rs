//! Relay discovery, advertisement and reservation management.
//!
//! Public relays announce themselves via a well-known Kademlia **provider
//! record** (`noid:relay-providers`). Clients query providers to find live
//! relay nodes, then request circuit reservations on them. This keeps relay
//! discovery fully decentralized — no hardcoded addresses.

use libp2p::kad;
use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};

use crate::p2p::node::P2PNode;
use crate::p2p::relay_config::NodeRole;
use crate::p2p::relay_status::{NatStatus, RelayStatus};

impl P2PNode {
    /// Well-known Kademlia key under which relay nodes publish provider records.
    pub fn relay_provider_key() -> kad::RecordKey {
        kad::RecordKey::new(&b"noid:relay-providers")
    }

    /// Whether this node should currently accept relay reservations.
    /// - `Relay` → always try.
    /// - `Client` → never (protocol-level limits are also zeroed).
    /// - `Auto` → only when AutoNAT confirmed we are publicly reachable.
    pub fn should_relay(&self) -> bool {
        match self.relay_config.role {
            NodeRole::Relay => true,
            NodeRole::Client => false,
            NodeRole::Auto => self.nat_status == NatStatus::Public,
        }
    }

    /// Announce ourselves as a relay provider in the DHT.
    /// Safe to call repeatedly — Kademlia republishes provider records.
    pub fn advertise_as_relay(&mut self) {
        if self.relay_provider_announced {
            return;
        }
        let key = Self::relay_provider_key();
        match self.swarm.behaviour_mut().kademlia.start_providing(key) {
            Ok(query_id) => {
                self.relay_provider_announced = true;
                log::debug!(
                    "Advertising as relay provider in DHT (query {:?})",
                    query_id
                );
            }
            Err(e) => log::warn!("Failed to advertise as relay provider: {}", e),
        }
    }

    /// Stop announcing ourselves as a relay provider.
    pub fn stop_advertising_as_relay(&mut self) {
        if self.relay_provider_announced {
            self.swarm
                .behaviour_mut()
                .kademlia
                .stop_providing(&Self::relay_provider_key());
            self.relay_provider_announced = false;
            log::debug!("Stopped advertising as relay provider");
        }
    }

    /// Ask the DHT for relay provider records.
    pub fn discover_relays(&mut self) {
        let key = Self::relay_provider_key();
        let query_id = self.swarm.behaviour_mut().kademlia.get_providers(key);
        self.pending_relay_provider_queries.insert(query_id);
        log::debug!("Started relay provider discovery (query {:?})", query_id);
    }

    /// Register a relay discovered via DHT provider records.
    /// Stores the relay and its addresses for later reservation requests.
    /// Dedup is per (peer, addr): a relay's listen set evolves over time —
    /// a peer-level early return used to drop every transport learned
    /// after the first, pinning the relay book to one stale addr.
    pub fn add_known_relay(&mut self, peer_id: PeerId, addrs: Vec<Multiaddr>) {
        if peer_id == self.peer_id {
            return;
        }
        for addr in &addrs {
            // Drop only undialable addrs — register_peer_addr itself sorts
            // loopback/LAN into the local dial book (trusted source) and
            // keeps them out of Kademlia/persistence. Filtering them here
            // starved the relay book on LAN-only networks and same-host
            // test setups, where a loopback relay is the only option.
            if matches!(
                crate::p2p::classify_peer_addr::classify_peer_addr(addr, &peer_id),
                crate::p2p::addr_class::AddrClass::Malformed
            ) {
                continue;
            }
            self.register_peer_addr(peer_id, addr.clone(), "relay", true);
            // Reservation requests need a base transport address: stripping a
            // relayed (p2p-circuit) addr yields the *intermediate* relay's
            // transport, producing a reservation aimed at the wrong peer.
            if !addr.iter().any(|p| matches!(p, Protocol::P2pCircuit))
                && !self
                    .known_relays
                    .iter()
                    .any(|(p, a)| *p == peer_id && a == addr)
            {
                // F17: bound the relay book — every 600s refresh used to
                // dial every HOP peer ever seen.
                const MAX_KNOWN_RELAYS: usize = 32;
                while self.known_relays.len() >= MAX_KNOWN_RELAYS {
                    self.known_relays.remove(0);
                }
                self.known_relays.push((peer_id, addr.clone()));
            }
        }
        self.peer_cache.upsert(peer_id, addrs.clone(), true);
        self.peer_cache_dirty = true;
        self.maybe_flush_peer_cache();
        // A relayed conn to this peer may predate its identification as a
        // relay (e.g. dialed via its own circuit addr before Identify ran).
        // Any RESERVE to it could dedup onto that conn → nested circuit.
        // But the circuit may also be the ONLY data path to the peer —
        // killing it unconditionally (TR-01) stranded relayed peers ~100ms
        // after every connect. Close it only once a direct conn exists,
        // after the standard grace window; the fire-time check in the
        // status tick cancels the close if the direct conn died meanwhile.
        // The ids stay in `relayed_conn_ids` until ConnectionClosed so
        // request_reservation keeps deferring while the hazard exists.
        if self.direct_conns.get(&peer_id).copied().unwrap_or(0) > 0 {
            if let Some(ids) = self.relayed_conn_ids.get(&peer_id) {
                let deadline = tokio::time::Instant::now()
                    + tokio::time::Duration::from_secs(20);
                for id in ids.iter().copied().collect::<Vec<_>>() {
                    log::debug!(
                        "Scheduling close of relayed conn {:?} to relay {} — direct conn available",
                        id, peer_id
                    );
                    self.pending_conn_close.push((deadline, peer_id, id));
                }
            }
        }
        log::info!("Known relay: {} ({} addrs)", peer_id, addrs.len());
    }

    /// All known direct (non-circuit), non-dead addrs for `peer`, cheapest
    /// transport first (QUIC → TCP → WS). Used for direct upgrades and
    /// relay dials — a dead preferred transport must fall through to the
    /// next instead of failing the whole dial (TR-04).
    pub(crate) fn direct_addrs_of(&mut self, peer_id: &PeerId) -> Vec<Multiaddr> {
        let candidates: Vec<Multiaddr> = self
            .known_relays
            .iter()
            .filter(|(p, _)| p == peer_id)
            .map(|(_, a)| a.clone())
            .filter(|a| !a.iter().any(|p| matches!(p, Protocol::P2pCircuit)))
            .collect();
        let mut addrs: Vec<Multiaddr> = candidates
            .into_iter()
            .filter(|a| !self.is_dead_addr(a))
            .map(|a| Self::relay_base_addr(&a).with(Protocol::P2p(*peer_id)))
            .collect();
        addrs.sort_by_key(crate::p2p::transport_rank::transport_rank);
        addrs.dedup();
        addrs
    }

    /// Strip trailing `/p2p/*` and `/p2p-circuit` protocols, yielding the
    /// relay's base transport address (safe for both bare and peer-suffixed
    /// addrs — bootstrap entries and DHT records carry `/p2p/{peer}`).
    pub fn relay_base_addr(addr: &Multiaddr) -> Multiaddr {
        let mut base = addr.clone();
        while matches!(
            base.iter().last(),
            Some(Protocol::P2p(_) | Protocol::P2pCircuit)
        ) {
            base.pop();
        }
        base
    }

    /// Relay peer id of a single-hop circuit addr
    /// (`…/p2p/<relay>/p2p-circuit/p2p/<dest>`), i.e. the id directly before
    /// the `/p2p-circuit` marker.
    pub(crate) fn circuit_relay_id(addr: &Multiaddr) -> Option<PeerId> {
        let mut prev_p2p: Option<PeerId> = None;
        for p in addr.iter() {
            match p {
                Protocol::P2p(id) => prev_p2p = Some(id),
                Protocol::P2pCircuit => return prev_p2p,
                _ => {}
            }
        }
        None
    }

    /// True once the relay has accepted our reservation — including the gap
    /// between ReservationReqAccepted and the NewListenAddr that mints the
    /// circuit addr. Requiring the addr here let a second RESERVE slip
    /// through in that gap (one per transport → duplicate reservations and
    /// duplicate `relayed_addrs` in the UI). Stale entries are cleared by
    /// the ListenerClosed cleanup, so re-reservation still works when the
    /// last listener dies.
    fn holds_reservation_on(&self, relay_peer: &PeerId) -> bool {
        self.reserved_relays.contains(relay_peer)
    }

    /// Request a circuit reservation on a relay peer.
    /// `relay_addr` may be bare or `/p2p/`-suffixed — it is normalized first.
    /// Skipped while the relay sits inside a denial window (2min after a
    /// failed/denied RESERVE — resource-limited relays must not be hammered,
    /// but a 10min blackout strands mobile clients on churning networks),
    /// while we ourselves act as a relay (public nodes don't need circuits —
    /// prevents relay→relay reservation chains), and while the only path to
    /// the relay is another relay's circuit (would produce an undialable
    /// nested `/p2p-circuit/…/p2p-circuit` listen address).
    pub fn request_reservation(&mut self, relay_peer: PeerId, relay_addr: &Multiaddr) {
        // Only a DEDICATED relay process skips reservations (it is the relay —
        // reserving on clients would be circular). Auto nodes reserve even
        // when publicly reachable: the circuit is what makes them dialable
        // from day one (fresh install = connected mode by default), and
        // relay→relay chains are already prevented by the direct-conn
        // requirements below.
        if self.relay_config.role == NodeRole::Relay {
            log::debug!("Reservation to {} skipped — we are a dedicated relay", relay_peer);
            return;
        }
        // A confirmed-public relay IS the reachable node — reserving on
        // other relays would hand out borrowed circuit addrs instead of our
        // own direct addrs and burn relay slots for nothing.
        if self.nat_status == NatStatus::Public && self.should_relay() {
            log::debug!(
                "Reservation to {} skipped — we are a public relay",
                relay_peer
            );
            return;
        }
        // A reservation on a LAN relay (RFC1918 + CGNAT 100.64/10 base
        // transport) cannot mint a WAN-usable circuit addr — but it is the
        // only option on LAN-only networks and in loopback/LAN e2e tests, and
        // it does serve same-LAN peers. Skip it only once a public circuit
        // already covers WAN reachability; until then a LAN circuit beats no
        // circuit. Invite building prefers public addrs either way.
        // Carrier-internal ranges 25/8 and 26/8 (used by mobile CGNATs like
        // Tele2) are unreachable from the WAN — a reservation through them
        // can never produce a dialable circuit, only a wasted RESERVE.
        let lan_only = Self::relay_base_addr(relay_addr).iter().any(|p| {
            matches!(p, Protocol::Ip4(ip)
                if ip.is_private()
                    || (ip.octets()[0] == 100 && ip.octets()[1] & 0xC0 == 64)
                    || ip.octets()[0] == 25
                    || ip.octets()[0] == 26)
        });
        let have_public_circuit = self
            .relayed_addrs
            .iter()
            .any(crate::p2p::invite::is_public_addr);
        // A publicly reachable node gains nothing from a LAN/CGNAT relay —
        // its circuit addr would be undialable from the WAN anyway. This
        // also stops VPS nodes from RESERVE-ing on every mobile client that
        // advertises HOP ("friends relay for friends" must not produce
        // reservation attempts on phones).
        let we_are_public = self.nat_status == NatStatus::Public
            || self.relay_config.external_addr.is_some();
        if lan_only && (have_public_circuit || we_are_public) {
            log::debug!(
                "Reservation to {} skipped — LAN relay; public circuit already held",
                relay_peer
            );
            return;
        }
        if self
            .reservation_denied
            .get(&relay_peer)
            .map(|t| t.elapsed() < std::time::Duration::from_secs(120))
            .unwrap_or(false)
        {
            log::debug!("Reservation to {} skipped — relay in denial window", relay_peer);
            return;
        }
        if !self.connected_peers.contains(&relay_peer) {
            // F17: honour dial backoff — the deferred path used to bypass it
            // and storm a dead relay every refresh tick.
            if self.dial_is_backed_off(&relay_peer) {
                log::debug!("Reservation to {} deferred — relay in dial backoff", relay_peer);
                return;
            }
            // No conn at all — do NOT listen_on: the relay-client behaviour's
            // own dial resolves the relay through every address source
            // (Kademlia, request-response books) and may pick the relay's own
            // *relayed* addr, producing a relayed conn that the RESERVE then
            // deduplicates onto → undialable nested-circuit listen addr.
            // Dial the direct transport instead; the ConnectionEstablished
            // handler issues the reservation once a direct conn exists.
            log::debug!(
                "Reservation to {} deferred — not connected; dialing directly",
                relay_peer
            );
            let mut direct = self.direct_addrs_of(&relay_peer);
            if direct.is_empty() {
                direct.push(
                    Self::relay_base_addr(relay_addr).with(Protocol::P2p(relay_peer)),
                );
            }
            let _ = self
                .swarm
                .dial(crate::p2p::dial_opts::dial_opts_multi(relay_peer, direct));
            return;
        }
        // Relayed conn(s) to this relay may still be mid-close — a RESERVE
        // issued now could dedup onto one. Defer; the refresh tick retries.
        if self
            .relayed_conn_ids
            .get(&relay_peer)
            .map(|s| !s.is_empty())
            .unwrap_or(false)
        {
            log::debug!(
                "Reservation to {} deferred — relayed conn still closing",
                relay_peer
            );
            return;
        }
        if self.direct_conns.get(&relay_peer).copied().unwrap_or(0) == 0 {
            // F17: honour dial backoff on this deferred dial too.
            if self.dial_is_backed_off(&relay_peer) {
                log::debug!("Reservation to {} deferred — relay in dial backoff", relay_peer);
                return;
            }
            // Reachable only via another relay's circuit — a RESERVE issued now
            // would produce an undialable nested-circuit listen addr. Try the
            // direct transport path instead; ConnectionEstablished requests
            // the reservation once a direct conn exists.
            log::debug!(
                "Reservation to {} deferred — only relayed conn; dialing directly",
                relay_peer
            );
            // TR-02: a live relayed conn to this peer makes the default
            // PeerCondition::DisconnectedAndNotDialing reject the dial —
            // dial_opts_multi uses NotDialing so the direct upgrade runs
            // while the circuit is still up.
            let mut direct = self.direct_addrs_of(&relay_peer);
            if direct.is_empty() {
                direct.push(
                    Self::relay_base_addr(relay_addr).with(Protocol::P2p(relay_peer)),
                );
            }
            let _ = self
                .swarm
                .dial(crate::p2p::dial_opts::dial_opts_multi(relay_peer, direct));
            return;
        }
        // Dedup in-flight RESERVE attempts: ConnectionEstablished, the
        // identify handler and the refresh tick can all request a reservation
        // for the same relay — parallel listen_on calls create duplicate
        // circuit listeners for the same addr.
        if self
            .pending_reservations
            .values()
            .any(|p| *p == relay_peer)
        {
            log::debug!("Reservation to {} skipped — request already in flight", relay_peer);
            return;
        }
        // Sequential dedup: the relay advertises several listen addrs
        // (loopback, LAN, public) and each of our conns to it triggers a
        // request via that conn's addr. One accepted reservation is enough —
        // more only mint duplicate circuit listeners (UI shows 4 reservations
        // where 1 is needed) and waste the relay's per-peer slots.
        if self.holds_reservation_on(&relay_peer) {
            log::debug!(
                "Reservation to {} skipped — live reservation already held",
                relay_peer
            );
            return;
        }
        let listen = Self::relay_base_addr(relay_addr)
            .with(Protocol::P2p(relay_peer))
            .with(Protocol::P2pCircuit);
        match self.swarm.listen_on(listen.clone()) {
            Ok(id) => {
                self.pending_reservations.insert(id, relay_peer);
                log::info!(
                    "Relay reservation requested on {} via {}",
                    relay_peer,
                    listen
                );
            }
            Err(e) => {
                log::warn!("Reservation request to {} failed: {}", relay_peer, e);
                self.reservation_denied
                    .insert(relay_peer, std::time::Instant::now());
            }
        }
    }

    /// Re-request reservations on relays we actually use. Reservations
    /// expire (default 1h) — this is called periodically to renew them.
    /// F17: only reserved/in-flight relays are renewed — walking the whole
    /// relay book every 600s dials every HOP peer ever seen.
    pub fn refresh_reservations(&mut self) {
        const MAX_ACTIVE_RESERVATIONS: usize = 4;
        // Dedup by peer — known_relays holds several addrs per relay and a
        // RESERVE per (peer, addr) pair would fire duplicate requests that
        // the dedup in request_reservation then rejects one by one.
        let mut peers: Vec<PeerId> = Vec::new();
        for (p, _) in &self.known_relays {
            if self.reserved_relays.contains(p) && !peers.contains(p) {
                peers.push(*p);
            }
        }
        // Top up to the cap with the freshest known relays when we hold
        // fewer than we need — a private node keeps trying until reachable.
        if peers.len() < MAX_ACTIVE_RESERVATIONS {
            for (p, _) in self.known_relays.iter().rev() {
                if !peers.contains(p) {
                    peers.push(*p);
                    if peers.len() >= MAX_ACTIVE_RESERVATIONS {
                        break;
                    }
                }
            }
        }
        for peer in peers {
            // Reserve via the best live transport — a dead TCP addr must
            // not block a reservation the QUIC addr could serve.
            if let Some(addr) = self.direct_addrs_of(&peer).into_iter().next() {
                self.request_reservation(peer, &addr);
            }
        }
    }

    /// Build the current [`RelayStatus`] snapshot for the UI.
    pub fn relay_status(&self) -> RelayStatus {
        // AutoNAT only reports while it can run probes — with no usable
        // probe peers it sits in Unknown forever and the UI shows
        // "Определяется…" indefinitely. A confirmed relayed addr is hard
        // proof the node is reachable only through a relay — report
        // Private until AutoNAT says otherwise.
        let nat_status = match self.nat_status {
            NatStatus::Unknown if !self.relayed_addrs.is_empty() => NatStatus::Private,
            s => s,
        };
        RelayStatus {
            nat_status,
            is_relaying: self.should_relay(),
            external_addrs: self.external_addrs.iter().map(|a| a.to_string()).collect(),
            relayed_addrs: self.relayed_addrs.iter().map(|a| a.to_string()).collect(),
            active_reservations: self.relayed_addrs.len(),
            inbound_reservations: self.inbound_reservations,
            active_circuits: self.active_circuits,
            // D5: distinct relay peers, not (peer, addr) pairs.
            known_relays: self
                .known_relays
                .iter()
                .map(|(p, _)| *p)
                .collect::<std::collections::HashSet<_>>()
                .len(),
            peers_connected: self.swarm.connected_peers().count(),
        }
    }
}
