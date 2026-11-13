//! AutoNAT/UPnP/DCUtR/relay-client/relay-server/ping arms — extracted from the event_loop megaloop (Q04/A5).
//! Behaviour-preserving move only.

use super::*;

impl P2PNode {
    pub(crate) async fn on_net_aux_event(
        &mut self,
        event: SwarmEvent<NoidBehaviourEvent>,
        ctx: &LoopCtx<'_>,
    ) -> LoopCtl {
        match event {
                    SwarmEvent::Behaviour(NoidBehaviourEvent::Autonat(autonat::Event::StatusChanged { new, .. })) => {
                        match new {
                            autonat::NatStatus::Public(addr) => {
                                log::info!("AutoNAT: we are publicly reachable at {}", addr);
                                self.nat_status = NatStatus::Public;
                                // A Public verdict means dial-back probes
                                // proved this exact addr — strongest
                                // third-party evidence we get.
                                self.addr_evidence.mark(
                                    &Self::canonical_dial_addr(&addr).to_string(),
                                    crate::p2p::addr_evidence::EvidenceState::Verified,
                                    crate::p2p::addr_evidence::EvidenceSource::AutonatProbe,
                                );
                                if self.relay_config.privacy == crate::p2p::relay_config::PrivacyMode::Direct {
                                    self.swarm.add_external_address(addr.clone());
                                    if !self.external_addrs.contains(&addr) {
                                        self.external_addrs.push(addr);
                                    }
                                }
                                // Public + role allows → start relaying for others.
                                if self.should_relay() {
                                    self.advertise_as_relay();
                                }
                                // RelayedOnly still needs circuit addrs — its
                                // invites carry ONLY /p2p-circuit multiaddrs,
                                // so without reservations the invite is a bare
                                // peer id and the node is unreachable by design.
                                if self.relay_config.privacy == crate::p2p::relay_config::PrivacyMode::RelayedOnly {
                                    self.discover_relays();
                                }
                            }
                            autonat::NatStatus::Private => {
                                log::info!("AutoNAT: we are behind NAT (private)");
                                self.nat_status = NatStatus::Private;
                                self.stop_advertising_as_relay();
                                // We need relays to be reachable — find some.
                                self.discover_relays();
                            }
                            autonat::NatStatus::Unknown => {
                                self.nat_status = NatStatus::Unknown;
                            }
                        }
                        let _ = emit_ev(ctx.event_tx, P2PEvent::RelayStatusChanged {
                            status: self.relay_status(),
                        }).await;
                    }
                    // --- AutoNAT dial-back probes (RV-01 evidence) ---
                    SwarmEvent::Behaviour(NoidBehaviourEvent::Autonat(autonat::Event::OutboundProbe(ev))) => {
                        match ev {
                            autonat::OutboundProbeEvent::Response { peer, address, .. } => {
                                log::info!(
                                    "AutoNAT probe: {} dialed us back at {} — verified",
                                    peer, address
                                );
                                self.addr_evidence.mark(
                                    &Self::canonical_dial_addr(&address).to_string(),
                                    crate::p2p::addr_evidence::EvidenceState::Verified,
                                    crate::p2p::addr_evidence::EvidenceSource::AutonatProbe,
                                );
                            }
                            autonat::OutboundProbeEvent::Error { peer, error, .. } => {
                                log::info!("AutoNAT probe via {:?} failed: {:?}", peer, error);
                                // `Response(..)` = the server received our
                                // tested addrs and could dial NONE — mark
                                // each unverified external candidate failed.
                                if matches!(error, autonat::OutboundProbeError::Response(_)) {
                                    for a in self.external_addrs.clone() {
                                        self.addr_evidence.mark_failed_if_unverified(
                                            &Self::canonical_dial_addr(&a).to_string(),
                                            crate::p2p::addr_evidence::EvidenceSource::AutonatProbe,
                                        );
                                    }
                                }
                            }
                            autonat::OutboundProbeEvent::Request { peer, .. } => {
                                // Probing has started — open the honesty
                                // window (RV-03) if it was never opened.
                                log::debug!("AutoNAT probe request via {}", peer);
                                if self.nat_probe_opened_at.is_none() {
                                    self.nat_probe_opened_at = Some(std::time::Instant::now());
                                }
                            }
                        }
                    }
                    SwarmEvent::Behaviour(NoidBehaviourEvent::Autonat(autonat::Event::InboundProbe(ev))) => {
                        // We are the probe SERVER — the remote's addrs are
                        // being tested by us; not our evidence, log only.
                        log::debug!("AutoNAT inbound probe event: {:?}", ev);
                    }
                    // --- UPnP port-mapping results ---
                    SwarmEvent::Behaviour(NoidBehaviourEvent::Upnp(upnp::Event::NewExternalAddr { external_addr: addr, .. })) => {
                        log::info!("UPnP: external address mapped {}", addr);
                        // The gateway confirmed the lease — this addr is
                        // verified public until the lease expires.
                        self.addr_evidence.mark(
                            &Self::canonical_dial_addr(&addr).to_string(),
                            crate::p2p::addr_evidence::EvidenceState::Verified,
                            crate::p2p::addr_evidence::EvidenceSource::UpnpLease,
                        );
                        if self.relay_config.privacy == crate::p2p::relay_config::PrivacyMode::Direct {
                            self.swarm.add_external_address(addr.clone());
                        }
                        if !self.external_addrs.contains(&addr) {
                            self.external_addrs.push(addr);
                        }
                        // A UPnP mapping is a confirmed public address.
                        self.nat_status = NatStatus::Public;
                        if self.should_relay() {
                            self.advertise_as_relay();
                        }
                        let _ = emit_ev(ctx.event_tx, P2PEvent::RelayStatusChanged {
                            status: self.relay_status(),
                        }).await;
                    }
                    SwarmEvent::Behaviour(NoidBehaviourEvent::Upnp(upnp::Event::ExpiredExternalAddr { external_addr: addr, .. })) => {
                        log::debug!("UPnP: external address expired {}", addr);
                        self.external_addrs.retain(|a| *a != addr);
                    }
                    SwarmEvent::Behaviour(NoidBehaviourEvent::Upnp(upnp::Event::GatewayNotFound)) => {
                        log::debug!("UPnP: no IGD gateway found on this network");
                    }
                    SwarmEvent::Behaviour(NoidBehaviourEvent::Upnp(upnp::Event::NonRoutableGateway)) => {
                        log::debug!("UPnP: gateway found but is not publicly routable");
                    }
                    // --- DCUtR direct-connection upgrade (hole punch) ---
                    SwarmEvent::Behaviour(NoidBehaviourEvent::Dcutr(ev)) => {
                        // Two NAT'd peers connected via a circuit exchange
                        // observed addrs and attempt a synchronized direct
                        // dial. Success means the relayed conn upgrades to a
                        // direct one — log at info so topology diagnostics
                        // can see whether hole-punching actually engages.
                        match ev.result {
                            Ok(conn_id) => log::info!(
                                "DCUtR: hole-punch to {} succeeded — direct conn {:?}",
                                ev.remote_peer_id, conn_id
                            ),
                            Err(e) => log::debug!(
                                "DCUtR: hole-punch to {} failed: {}",
                                ev.remote_peer_id, e
                            ),
                        }
                    }
                    // --- Relay client: our reservations on remote relays ---
                    SwarmEvent::Behaviour(NoidBehaviourEvent::RelayClient(
                        relay::client::Event::ReservationReqAccepted { relay_peer_id, renewal, .. },
                    )) => {
                        log::info!(
                            "Relay reservation {} on {}",
                            if renewal { "renewed" } else { "accepted" },
                            relay_peer_id
                        );
                        self.reserved_relays.insert(relay_peer_id);
                        self.reservation_denied.remove(&relay_peer_id);
                        self.pending_reservations
                            .retain(|_, p| *p != relay_peer_id);
                        // Announce this relay as our mailbox node in the DHT —
                        // without this record `find_mailbox_node` can never
                        // resolve where our offline envelopes are stored.
                        // Republished on every accept AND renewal: a failed
                        // put (e.g. no DHT peers yet) is retried on the next
                        // renewal, and the record's 24h TTL stays fresh for
                        // long-running nodes instead of expiring silently.
                        {
                            // F17: pin the mailbox record to the first relay
                            // that accepted — renewals on other relays must
                            // not flap the published record.
                            if self
                                .mailbox_record_peer
                                .map(|p| !self.reserved_relays.contains(&p) || p == relay_peer_id)
                                .unwrap_or(true)
                            {
                                self.mailbox_record_peer = Some(relay_peer_id);
                            }
                            if self.mailbox_record_peer != Some(relay_peer_id) {
                                // Another relay holds the pin and still has a
                                // reservation — keep its record stable.
                                let _ = emit_ev(ctx.event_tx, P2PEvent::RelayStatusChanged {
                                    status: self.relay_status(),
                                }).await;
                                return LoopCtl::Keep;
                            }
                            let relay_addr = self
                                .known_relays
                                .iter()
                                .filter(|(p, _)| *p == relay_peer_id)
                                .map(|(_, a)| a.clone())
                                .find(crate::p2p::invite::is_public_addr)
                                .or_else(|| {
                                    self.known_relays
                                        .iter()
                                        .find(|(p, _)| *p == relay_peer_id)
                                        .map(|(_, a)| a.clone())
                                });
                            if let Some(addr) = relay_addr {
                                if let Err(e) = self.register_as_mailbox(
                                    &self.peer_id.to_string(),
                                    &relay_peer_id.to_string(),
                                    &addr.to_string(),
                                ) {
                                    log::warn!("Failed to publish mailbox record: {}", e);
                                }
                            }
                        }
                        let _ = emit_ev(ctx.event_tx, P2PEvent::RelayStatusChanged {
                            status: self.relay_status(),
                        }).await;
                    }
                    SwarmEvent::Behaviour(NoidBehaviourEvent::RelayClient(
                        relay::client::Event::OutboundCircuitEstablished { relay_peer_id, .. },
                    )) => {
                        log::debug!("Outbound circuit established via relay {}", relay_peer_id);
                    }
                    SwarmEvent::Behaviour(NoidBehaviourEvent::RelayClient(
                        relay::client::Event::InboundCircuitEstablished { src_peer_id, .. },
                    )) => {
                        log::debug!("Inbound circuit from {} via our relay reservation", src_peer_id);
                    }
                    // --- Relay server: peers using us as relay (counters only, no payload) ---
                    SwarmEvent::Behaviour(NoidBehaviourEvent::Relay(relay::Event::ReservationReqAccepted {
                        src_peer_id, renewed,
                    })) => {
                        if !renewed {
                            self.inbound_reservations += 1;
                        }
                        log::debug!("Relay: reservation {} by {}", if renewed { "renewed" } else { "accepted" }, src_peer_id);
                        let _ = emit_ev(ctx.event_tx, P2PEvent::RelayStatusChanged {
                            status: self.relay_status(),
                        }).await;
                    }
                    SwarmEvent::Behaviour(NoidBehaviourEvent::Relay(relay::Event::ReservationTimedOut { src_peer_id })) => {
                        self.inbound_reservations = self.inbound_reservations.saturating_sub(1);
                        log::debug!("Relay: reservation timed out for {}", src_peer_id);
                    }
                    SwarmEvent::Behaviour(NoidBehaviourEvent::Relay(relay::Event::CircuitReqAccepted {
                        src_peer_id, dst_peer_id,
                    })) => {
                        self.active_circuits += 1;
                        log::debug!("Relay: circuit {} -> {}", src_peer_id, dst_peer_id);
                    }
                    SwarmEvent::Behaviour(NoidBehaviourEvent::Relay(relay::Event::CircuitClosed {
                        src_peer_id, dst_peer_id, ..
                    })) => {
                        self.active_circuits = self.active_circuits.saturating_sub(1);
                        log::debug!("Relay: circuit closed {} -> {}", src_peer_id, dst_peer_id);
                    }
                    SwarmEvent::Behaviour(NoidBehaviourEvent::Relay(relay::Event::ReservationReqDenied { src_peer_id, .. })) => {
                        log::debug!("Relay: reservation denied for {} (limits)", src_peer_id);
                    }
                    SwarmEvent::Behaviour(NoidBehaviourEvent::Relay(relay::Event::CircuitReqDenied {
                        src_peer_id, dst_peer_id, ..
                    })) => {
                        log::debug!("Relay: circuit denied {} -> {} (limits)", src_peer_id, dst_peer_id);
                    }
                    SwarmEvent::Behaviour(NoidBehaviourEvent::Ping(ping::Event { peer, connection, result: Ok(_), .. })) => {
                        // Protocol-level keepalive only — online status is
                        // driven by ConnectionEstablished/Closed, not pings.
                        self.ping_failures.remove(&connection);
                        log::debug!("Ping success from peer {}", peer);
                    }
                    SwarmEvent::Behaviour(NoidBehaviourEvent::Ping(ping::Event {
                        peer, connection, result: Err(e),
                    })) => {
                        // Zombie-conn reaper: a peer that stops answering
                        // pings (expired CGNAT mapping, suspended mobile
                        // radio) has a conn that stays ESTABLISHED while
                        // writes vanish into a black hole. Close it so the
                        // dial retry path builds a fresh one — otherwise
                        // requests ride the dead conn and time out.
                        // F18: three consecutive failures required (any
                        // live inbound traffic resets the streak) — a
                        // congested-but-alive conn must not be reaped.
                        // On-demand contact conns are exempt: the idle-TTL
                        // teardown owns their lifecycle (≤120s anyway), so
                        // ping never drives a close→redial churn on a
                        // laggy-but-alive contact.
                        if self.connectivity_config.on_demand
                            && self.conn_class(&peer)
                                == crate::p2p::connectivity_config::ConnClass::Contact
                        {
                            log::debug!(
                                "Ping failed to contact {} — tolerated (TTL teardown owns it): {}",
                                peer, e
                            );
                            return LoopCtl::Keep;
                        }
                        let fails = self.ping_failures.entry(connection).or_insert(0);
                        *fails += 1;
                        if *fails >= 3 {
                            log::info!(
                                "Ping failed to {} (x{}) — closing dead connection: {}",
                                peer, fails, e
                            );
                            self.swarm.close_connection(connection);
                        } else {
                            log::info!("Ping failed to {} — tolerating failure x{}: {}", peer, fails, e);
                        }
                    }
            _ => {}
        }
        LoopCtl::Keep
    }
}
