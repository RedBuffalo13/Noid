//! Kademlia GetClosestPeers/RoutingUpdated/GetProviders arms — extracted from the event_loop megaloop (Q04/A5).
//! Behaviour-preserving move only.

use super::*;

impl P2PNode {
    pub(crate) async fn on_kad_tail(
        &mut self,
        event: SwarmEvent<NoidBehaviourEvent>,
        _ctx: &LoopCtx<'_>,
    ) -> LoopCtl {
        match event {
                    SwarmEvent::Behaviour(NoidBehaviourEvent::Kademlia(kad::Event::OutboundQueryProgressed {
                        id,
                        result: kad::QueryResult::GetClosestPeers(Ok(kad::GetClosestPeersOk { peers, .. })),
                        ..
                    })) => {
                        if let Some(relay_peer) = self.pending_relay_addr_lookups.remove(&id) {
                            // We resolved a DHT-advertised relay provider's addresses.
                            if let Some(info) = peers.iter().find(|p| p.peer_id == relay_peer) {
                                let addrs = info.addrs.clone();
                                self.add_known_relay(relay_peer, addrs);
                                // Request a reservation on the newly found relay.
                                for (peer, addr) in self.known_relays.clone() {
                                    if peer == relay_peer {
                                        self.request_reservation(peer, &addr);
                                    }
                                }
                            }
                        } else if let Some(target_peer) = self.pending_addr_refresh.remove(&id) {
                            // Passive refresh result: re-register fresh addrs
                            // into the address books only — no dial (backoff
                            // still applies), no eviction of existing addrs.
                            if let Some(peer_info) = peers.iter().find(|p| p.peer_id == target_peer) {
                                for addr in &peer_info.addrs {
                                    let full_addr = match addr.iter().last() {
                                        Some(libp2p::multiaddr::Protocol::P2p(pid))
                                            if pid == target_peer =>
                                        {
                                            addr.clone()
                                        }
                                        Some(libp2p::multiaddr::Protocol::P2p(_)) => continue,
                                        _ => addr.clone().with(
                                            libp2p::multiaddr::Protocol::P2p(target_peer),
                                        ),
                                    };
                                    self.register_peer_addr(
                                        target_peer,
                                        full_addr,
                                        "dht-refresh",
                                        true,
                                    );
                                }
                            }
                        } else if let Some(target_peer) = self.pending_dials.remove(&id) {
                            let found = peers.iter().find(|p| p.peer_id == target_peer);
                            // pending_dials is populated only by explicit
                            // ConnectToPeer commands (send / retry / add-contact)
                            // — fresh DHT addrs from that lookup are dialed even
                            // inside a stale backoff window. Automatic retry
                            // loops use different query maps.
                            self.clear_dial_backoff(&target_peer);
                            // D18: `found` with an empty addr list used to
                            // fall into the dial loop over zero addresses —
                            // no dials, no relay fallback, silent dead end.
                            if let Some(peer_info) = found.filter(|p| !p.addrs.is_empty()) {
                                for addr in &peer_info.addrs {
                                    // A stored addr may already terminate at the
                                    // target (relayed `…/p2p-circuit/p2p/<peer>`),
                                    // end in bare `/p2p-circuit` (reservation form),
                                    // or name a different peer — normalize instead
                                    // of blindly appending `/p2p/<target>`.
                                    let full_addr = match addr.iter().last() {
                                        Some(libp2p::multiaddr::Protocol::P2p(id))
                                            if id == target_peer =>
                                        {
                                            addr.clone()
                                        }
                                        Some(libp2p::multiaddr::Protocol::P2p(_)) => continue,
                                        _ => addr.clone().with(
                                            libp2p::multiaddr::Protocol::P2p(target_peer),
                                        ),
                                    };
                                    if !Self::is_valid_addr_for_peer(&full_addr, &target_peer) {
                                        continue;
                                    }
                                    log::debug!("Kademlia found peer {} at {} — dialing", target_peer, full_addr);
                                    let _ = self.dial(full_addr).await;
                                }
                            } else {
                                log::debug!("Kademlia find_peer: peer {} not found in closest peers ({} found), trying known relays", target_peer, peers.len());
                                if self.known_relays.is_empty() {
                                    log::debug!("No known relays — cannot reach peer {}", target_peer);
                                }
                                for (relay_peer_id, relay_addr) in &self.known_relays.clone() {
                                    let circuit_addr = Self::relay_base_addr(relay_addr)
                                        .with(libp2p::multiaddr::Protocol::P2p(*relay_peer_id))
                                        .with(libp2p::multiaddr::Protocol::P2pCircuit)
                                        .with(libp2p::multiaddr::Protocol::P2p(target_peer));
                                    log::debug!("Dialing peer {} via relay {} : {}", target_peer, relay_peer_id, circuit_addr);
                                    let _ = self.dial(circuit_addr).await;
                                }
                            }
                        }
                    }
                    SwarmEvent::Behaviour(NoidBehaviourEvent::Kademlia(kad::Event::OutboundQueryProgressed {
                        id,
                        result: kad::QueryResult::GetClosestPeers(Err(e)),
                        ..
                    })) => {
                        // F16: a failed query must release every tracking map —
                        // a leftover pending_addr_refresh entry permanently
                        // disables address re-resolve for that peer.
                        if let Some(provider) = self.pending_relay_addr_lookups.remove(&id) {
                            log::debug!("Relay addr lookup for {} failed: {:?}", provider, e);
                        }
                        if let Some(target) = self.pending_addr_refresh.remove(&id) {
                            log::debug!("Addr refresh for {} failed: {:?}", target, e);
                        }
                        if let Some(target_peer) = self.pending_dials.remove(&id) {
                            log::debug!("Kademlia find_peer failed for {}: {:?} — trying known relays", target_peer, e);
                            if self.known_relays.is_empty() {
                                log::debug!("No known relays — cannot reach peer {}", target_peer);
                            }
                            for (relay_peer_id, relay_addr) in &self.known_relays.clone() {
                                let circuit_addr = Self::relay_base_addr(relay_addr)
                                    .with(libp2p::multiaddr::Protocol::P2p(*relay_peer_id))
                                    .with(libp2p::multiaddr::Protocol::P2pCircuit)
                                    .with(libp2p::multiaddr::Protocol::P2p(target_peer));
                                log::debug!("Dialing peer {} via relay {} : {}", target_peer, relay_peer_id, circuit_addr);
                                let _ = self.dial(circuit_addr).await;
                            }
                        }
                    }
                    SwarmEvent::Behaviour(NoidBehaviourEvent::Kademlia(kad::Event::RoutingUpdated { peer, addresses, .. })) => {
                        // Phase 5.5: Don't emit PeerDiscovered on RoutingUpdated —
                        // a routing table entry doesn't mean the peer is online or connected.
                        // Online status is signaled by ConnectionEstablished → PeerConnected.
                        log::debug!("Kademlia routing updated: peer {} with {} addresses", peer, addresses.len());
                    }
                    // --- Relay discovery via DHT provider records ---
                    SwarmEvent::Behaviour(NoidBehaviourEvent::Kademlia(kad::Event::OutboundQueryProgressed {
                        id,
                        result: kad::QueryResult::GetProviders(Ok(kad::GetProvidersOk::FoundProviders { providers, .. })),
                        ..
                    })) => {
                        if self.pending_relay_provider_queries.remove(&id) {
                            log::debug!("Found {} relay providers in DHT", providers.len());
                            for provider in providers {
                                if provider != self.peer_id
                                    && !self.known_relays.iter().any(|(p, _)| *p == provider)
                                {
                                    // Resolve the provider's addresses via Kademlia.
                                    let qid = self
                                        .swarm
                                        .behaviour_mut()
                                        .kademlia
                                        .get_closest_peers(provider);
                                    self.pending_relay_addr_lookups.insert(qid, provider);
                                }
                            }
                        }
                    }
                    // D4: a providers query that finishes with zero results
                    // lands here — without the remove the query id leaks and
                    // the guard never re-arms.
                    SwarmEvent::Behaviour(NoidBehaviourEvent::Kademlia(kad::Event::OutboundQueryProgressed {
                        id,
                        result: kad::QueryResult::GetProviders(Ok(kad::GetProvidersOk::FinishedWithNoAdditionalRecord { .. })),
                        ..
                    })) => {
                        self.pending_relay_provider_queries.remove(&id);
                    }
                    SwarmEvent::Behaviour(NoidBehaviourEvent::Kademlia(kad::Event::OutboundQueryProgressed {
                        id,
                        result: kad::QueryResult::GetProviders(Err(_)),
                        ..
                    })) => {
                        self.pending_relay_provider_queries.remove(&id);
                    }
            _ => {}
        }
        LoopCtl::Keep
    }
}
