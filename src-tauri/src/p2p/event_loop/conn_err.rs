//! Connection/listener error + listener-closed arms — extracted from the
//! event_loop megaloop (Q04/A5). Behaviour-preserving move only.

use super::*;

impl P2PNode {
    pub(crate) async fn on_conn_err_event(
        &mut self,
        event: SwarmEvent<NoidBehaviourEvent>,
        ctx: &LoopCtx<'_>,
    ) -> LoopCtl {
        match event {
                    SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                        // Dial failed — back the peer off so subsequent sends
                        // route to mailbox instead of storming more dials.
                        // The error dump lists every attempted address, so
                        // only the first line is logged at debug level.
                        //
                        // NoAddresses is NOT a connectivity failure — the dial
                        // was queued without a single usable addr (cold start,
                        // empty Kademlia). Arming backoff for it would make a
                        // peer unreachable even after real addrs arrive.
                        if let Some(peer) = peer_id {
                            // Evict addresses that just proved undialable —
                            // stale entries (rotated listen ports, dead LAN
                            // peers) are otherwise retried forever by
                            // Kademlia's internal redials and re-served at
                            // every warm start. They re-enter automatically
                            // via identify/mDNS if the peer is really back.
                            let mut failed: Vec<Multiaddr> = Vec::new();
                            let mut wrong_peer = false;
                            match &error {
                                libp2p::swarm::DialError::Transport(list) => {
                                    failed.extend(list.iter().map(|(a, _)| a.clone()));
                                }
                                libp2p::swarm::DialError::WrongPeerId { address, obtained } => {
                                    let remote = address.clone();
                                    // SEC-1111-02: a pinned seed answering
                                    // with a DIFFERENT PeerId is a
                                    // substitution event (MITM/eclipse or a
                                    // genuinely rotated host key) — adopting
                                    // the observed id automatically used to
                                    // hand the attacker's node our Kademlia
                                    // bootstrap and relay book. Fail closed:
                                    // audit + UI warning, quarantine the
                                    // addr; the operator must re-pin the seed
                                    // explicitly.
                                    let base = Self::relay_base_addr(&remote);
                                    let is_seed = self
                                        .bootstrap_peers
                                        .iter()
                                        .any(|(_, a)| Self::relay_base_addr(a) == base)
                                        || self
                                            .blind_bootstrap_addrs
                                            .iter()
                                            .any(|a| Self::relay_base_addr(a) == base);
                                    if is_seed {
                                        log::error!(
                                            "Pinned bootstrap seed at {} answered with unexpected PeerId {} — refusing to adopt",
                                            base,
                                            obtained
                                        );
                                        let _ = emit_ev(ctx.event_tx, P2PEvent::SecurityAlert {
                                            code: "bootstrap-peerid-mismatch".to_string(),
                                            detail: format!(
                                                "Seed {} answered as {}",
                                                base, obtained
                                            ),
                                        }).await;
                                    }
                                    failed.push(remote);
                                    wrong_peer = true;
                                }
                                _ => {}
                            }
                            for addr in &failed {
                                // A /p2p-circuit addr that failed is NOT
                                // stale by default — it is relay-minted, and
                                // the usual failure cause is the destination's
                                // reservation being between renewal cycles
                                // (NAT kill → re-reserve takes 10–30s). The
                                // addr will work on the next retry, and the
                                // DHT re-resolve below refreshes it anyway.
                                // WrongPeerId still evicts — that is a real
                                // misattribution, not a transient window.
                                let is_circuit = addr.iter().any(|p| {
                                    matches!(
                                        p,
                                        libp2p::multiaddr::Protocol::P2pCircuit
                                            | libp2p::multiaddr::Protocol::Onion3(_)
                                    )
                                });
                                if is_circuit && !wrong_peer {
                                    continue;
                                }
                                // Failure bookkeeping must see the failed
                                // addr even when it is not in any book yet —
                                // identify re-learns it on the next conn, so
                                // eviction alone cannot break the poison loop.
                                self.note_dial_failure(addr, wrong_peer);
                                // Kad stores bare transport addrs — a dialed
                                // addr carries the /p2p/<id> suffix and would
                                // never match. Strip it before removal.
                                let bare = Self::canonical_dial_addr(addr);
                                let bh = self.swarm.behaviour_mut();
                                bh.kademlia.remove_address(&peer, &bare);
                                // Both request_response behaviours keep their
                                // own PeerAddresses book (fed via
                                // NewExternalAddrOfPeer) — without these
                                // removals a dead addr keeps being picked for
                                // dial despite every other eviction.
                                // `remove_address` is deprecated in libp2p 0.54
                                // but has no replacement API — the address book
                                // must still be kept consistent.
                                #[allow(deprecated)]
                                {
                                    bh.request_response.remove_address(&peer, addr);
                                    bh.request_response.remove_address(&peer, &bare);
                                    bh.mailbox.remove_address(&peer, addr);
                                    bh.mailbox.remove_address(&peer, &bare);
                                }
                                if self.peer_cache.remove_addr(&peer, addr)
                                    || self.peer_cache.remove_addr(&peer, &bare)
                                {
                                    self.peer_cache_dirty = true;
                                }
                            }
                            if !failed.is_empty() {
                                log::debug!("Evicted {} failed addr(s) for {}", failed.len(), peer);
                            }
                            // A failed circuit addr usually means the relay
                            // has no reservation for the destination — the
                            // peer moved to another relay. Re-resolve its
                            // addrs via the DHT (passive refresh: fills the
                            // address books, does NOT dial or clear backoff —
                            // the next post-backoff send picks up the fresh
                            // circuit). One in-flight query per peer.
                            if failed.iter().any(|a| {
                                a.iter().any(|p| {
                                    matches!(p, libp2p::multiaddr::Protocol::P2pCircuit)
                                })
                            }) && !self.pending_addr_refresh.values().any(|p| *p == peer)
                            {
                                let q = self
                                    .swarm
                                    .behaviour_mut()
                                    .kademlia
                                    .get_closest_peers(peer);
                                self.pending_addr_refresh.insert(q, peer);
                                log::debug!(
                                    "Circuit addr failed for {} — refreshing addrs via DHT",
                                    peer
                                );
                            }
                            if !matches!(
                                error,
                                libp2p::swarm::DialError::NoAddresses
                            ) {
                                let failures = self.record_dial_failure(&peer);
                                // Kademlia's internal redials bypass our dial
                                // gate — after repeated failures, purge the
                                // peer from the routing table so there is no
                                // address left for them to try. Identify and
                                // fresh discovery re-populate it if the peer
                                // is actually back.
                                //
                                // NEVER purge a peer we are still connected
                                // to: dial failures are per-*address*, not
                                // per-peer. On CGNAT the TCP/WS paths to a
                                // peer flap while a QUIC conn stays alive —
                                // evicting the peer anyway empties the
                                // routing table and every PutRecord/FindNode
                                // fails with QuorumFailed behind a live conn.
                                if failures >= 3 && !self.swarm.is_connected(&peer) {
                                    log::debug!(
                                        "Removing {} from Kademlia after {} consecutive dial failures",
                                        peer, failures
                                    );
                                    self.swarm.behaviour_mut().kademlia.remove_peer(&peer);
                                    // A relay that cannot be dialed is dead
                                    // weight — drop it from the relay book and
                                    // clear reservation bookkeeping, otherwise
                                    // refresh_reservations re-dials it forever.
                                    // DHT provider discovery re-adds it when it
                                    // comes back.
                                    if self.known_relays.iter().any(|(p, _)| *p == peer) {
                                        self.known_relays.retain(|(p, _)| *p != peer);
                                        self.reserved_relays.remove(&peer);
                                        let dead: Vec<Multiaddr> = self
                                            .relayed_addrs
                                            .iter()
                                            .filter(|a| {
                                                Self::circuit_relay_id(a).as_ref() == Some(&peer)
                                            })
                                            .cloned()
                                            .collect();
                                        for a in dead {
                                            self.relayed_listener_refs.remove(&a);
                                            self.relayed_addrs.retain(|x| *x != a);
                                        }
                                        log::info!("Evicted dead relay {} from known relays", peer);
                                    }
                                }
                            }
                        } else if let libp2p::swarm::DialError::Transport(list) = &error {
                            // Bare-address dials carry no peer id, so the
                            // peer-scoped eviction above never ran — without
                            // this branch a dead bare addr stays in the peer
                            // cache and is re-dialed on every startup.
                            let mut evicted = 0usize;
                            for (addr, _) in list {
                                if addr.iter().any(|p| {
                                    matches!(
                                        p,
                                        libp2p::multiaddr::Protocol::P2pCircuit
                                            | libp2p::multiaddr::Protocol::Onion3(_)
                                    )
                                }) {
                                    continue;
                                }
                                self.note_dial_failure(addr, false);
                                let ids: Vec<PeerId> = self
                                    .peer_cache
                                    .peers
                                    .iter()
                                    .filter_map(|p| p.peer_id.parse::<PeerId>().ok())
                                    .collect();
                                for pid in ids {
                                    let bh = self.swarm.behaviour_mut();
                                    bh.kademlia.remove_address(&pid, addr);
                                    #[allow(deprecated)] // no replacement API in libp2p 0.54
                                    {
                                        bh.request_response.remove_address(&pid, addr);
                                        bh.mailbox.remove_address(&pid, addr);
                                    }
                                    if self.peer_cache.remove_addr(&pid, addr) {
                                        self.peer_cache_dirty = true;
                                        evicted += 1;
                                    }
                                }
                            }
                            if evicted > 0 {
                                log::debug!("Evicted {} unbound dead addr(s) from peer cache", evicted);
                            }
                        }
                        log::warn!("Dial failed to {:?}: {}", peer_id, error);
                    }
                    SwarmEvent::IncomingConnectionError { error, .. } => {
                        let summary = error.to_string();
                        let summary = summary.lines().next().unwrap_or("inbound error");
                        log::debug!("Incoming connection error: {}", summary);
                    }
                    SwarmEvent::ListenerError { listener_id, error } => {
                        // A failed relay-circuit listener is a denied/failed
                        // RESERVE (resource limits, timeout). Only mark the
                        // relay denied when this was its LAST pending attempt —
                        // parallel reservations on other addrs may still win,
                        // and one failed transport must not poison the relay.
                        if let Some(relay_peer) = self.pending_reservations.remove(&listener_id) {
                            log::warn!(
                                "Relay reservation attempt failed on {}: {}",
                                relay_peer, error
                            );
                            if !self.pending_reservations.values().any(|p| *p == relay_peer) {
                                self.reserved_relays.remove(&relay_peer);
                                // A listener can die because the conn carrying
                                // the in-flight RESERVE died — that is churn,
                                // not a refusal. Only a still-connected relay
                                // actually denied us; arm the window then.
                                if self.connected_peers.contains(&relay_peer) {
                                    self.reservation_denied
                                        .insert(relay_peer, std::time::Instant::now());
                                }
                            }
                        } else {
                            log::debug!("Listener error: {}", error);
                        }
                    }
                    SwarmEvent::ListenerClosed { listener_id, addresses, reason } => {
                        // Any relayed listen addrs this listener served are
                        // dead now — decrement the refcount and drop them from
                        // the advertised set so invites stop carrying
                        // undialable circuit addresses.
                        let mut dead_relay: Option<PeerId> = None;
                        for addr in &addresses {
                            // Only single-hop circuit addrs were registered —
                            // nested-circuit addrs (`relayA/p2p-circuit/relayB/
                            // p2p-circuit/me`) are never tracked. Skipping them
                            // here also stops a nested addr from being mistaken
                            // for the DEAD relay (its first p2p id is the outer
                            // relay, not the one that served the reservation).
                            let circuits = addr
                                .iter()
                                .filter(|p| matches!(p, libp2p::multiaddr::Protocol::P2pCircuit))
                                .count();
                            if circuits != 1 {
                                continue;
                            }
                            if dead_relay.is_none() {
                                dead_relay = Self::circuit_relay_id(addr);
                            }
                            let last = match self.relayed_listener_refs.get_mut(addr) {
                                Some(n) => {
                                    *n = n.saturating_sub(1);
                                    *n == 0
                                }
                                None => true,
                            };
                            if last {
                                self.relayed_listener_refs.remove(addr);
                                self.relayed_addrs.retain(|a| a != addr);
                            }
                        }
                        if let Some(relay_peer) = self.pending_reservations.remove(&listener_id) {
                            match reason {
                                Err(e) => {
                                    // libp2p-relay surfaces a refused RESERVE
                                    // as a listener closed with error — same
                                    // denial semantics as ListenerError. Only
                                    // mark denied when this was the relay's
                                    // last pending attempt.
                                    log::warn!(
                                        "Relay reservation on {} closed with error: {}",
                                        relay_peer, e
                                    );
                                    if !self.pending_reservations.values().any(|p| *p == relay_peer) {
                                        self.reserved_relays.remove(&relay_peer);
                                        // Same churn-vs-denial split as
                                        // ListenerError: a dead conn is not a
                                        // refusal — no window for it.
                                        if self.connected_peers.contains(&relay_peer) {
                                            self.reservation_denied
                                                .insert(relay_peer, std::time::Instant::now());
                                        }
                                    }
                                }
                                Ok(()) => {
                                    // Benign: reservation listeners close on
                                    // dedup (a sibling addr already reserved),
                                    // renewal rotation or transport
                                    // replacement — NOT a denial signal.
                                    log::debug!("Reservation listener for {} closed", relay_peer);
                                }
                            }
                        } else if let Some(relay_peer) = dead_relay {
                            // An ESTABLISHED reservation listener closed — on
                            // Err the renewal failed or the relay dropped us;
                            // on Ok it was dedup/rotation. Either way, when it
                            // was the LAST listener serving this relay the
                            // reservation is gone: reserved_relays must reflect
                            // reality, otherwise holds_reservation_on
                            // suppresses re-reservation forever and we keep
                            // advertising a dead circuit.
                            let still_held = self.relayed_addrs.iter().any(|a| {
                                Self::circuit_relay_id(a).as_ref() == Some(&relay_peer)
                            });
                            let in_flight = self
                                .pending_reservations
                                .values()
                                .any(|p| *p == relay_peer);
                            if !still_held && !in_flight && self.reserved_relays.remove(&relay_peer)
                            {
                                log::warn!(
                                    "Relay reservation on {} gone (listener closed) — requesting a fresh one",
                                    relay_peer
                                );
                                // Prefer the transport a live conn to this
                                // relay is on — the book's top-ranked entry
                                // may be a carrier-blocked QUIC addr.
                                let addr = self
                                    .conn_remote
                                    .values()
                                    .find(|a| {
                                        a.iter().any(|p| matches!(
                                            p,
                                            libp2p::multiaddr::Protocol::P2p(id)
                                                if id == relay_peer
                                        )) && !a.iter().any(|p| matches!(
                                            p,
                                            libp2p::multiaddr::Protocol::P2pCircuit
                                        ))
                                    })
                                    .cloned()
                                    .or_else(|| {
                                        self.direct_addrs_of(&relay_peer)
                                            .into_iter()
                                            .next()
                                    });
                                if let Some(addr) = addr {
                                    self.request_reservation(relay_peer, &addr);
                                }
                            }
                        }
                    }
            _ => {}
        }
        LoopCtl::Keep
    }
}
