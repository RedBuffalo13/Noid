//! Infra-protocol arms: mDNS, identify, gossipsub, AutoNAT, UPnP, DCUtR,
//! relay client/server, ping — extracted from the event_loop megaloop (Q04/A5).

use super::*;

impl P2PNode {
    pub(crate) async fn on_misc_event(
        &mut self,
        event: SwarmEvent<NoidBehaviourEvent>,
        ctx: &LoopCtx<'_>,
    ) -> LoopCtl {
        match event {
                    SwarmEvent::Behaviour(NoidBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                        for (peer_id, addr) in list {
                            if peer_id == self.peer_id {
                                continue;
                            }
                            // Same-host instances advertise each other's relayed
                            // addrs via mDNS — nested circuits, foreign
                            // terminal peer ids and loopback transports (the
                            // relay's 127.0.0.1 listeners leak here) must not
                            // reach Kademlia or the peer cache.
                            if matches!(
                                crate::p2p::classify_peer_addr::classify_peer_addr(&addr, &peer_id),
                                crate::p2p::addr_class::AddrClass::Malformed
                                    | crate::p2p::addr_class::AddrClass::Local
                            ) {
                                log::debug!("Dropping malformed/local mDNS addr from {}: {}", peer_id, addr);
                                continue;
                            }
                            // An addr pointing at our own listen socket is a
                            // same-host leak — dialing it hits our listener or
                            // fails with WSAEADDRINUSE. Never book it.
                            if self.is_own_listen_addr(&addr) {
                                log::debug!("Dropping mDNS addr matching our listener: {}", addr);
                                continue;
                            }
                            log::info!("mDNS discovered peer {} at {}", peer_id, addr);
                            self.swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                            self.register_peer_addr(peer_id, addr.clone(), "mdns", false);
                            if !emit_ev(ctx.event_tx, P2PEvent::PeerDiscovered(peer_id.to_string(), addr.to_string())).await { return LoopCtl::Exit; }
                        }
                    }
                    SwarmEvent::Behaviour(NoidBehaviourEvent::Identify(event)) => {
                        if let identify::Event::Received { peer_id, connection_id, info, .. } = *event {
                        log::debug!("Identify received from peer {}: protocol={}, observed_addr={}", peer_id, info.protocol_version, info.observed_addr);
                        // Classify listen addrs before they reach Kademlia /
                        // peer_cache: nested circuits and foreign-terminal
                        // addrs are undialable, loopback/LAN addrs poison the
                        // shared DHT routing table (Local/Malformed dropped,
                        // Lan kept only in the local dial book).
                        let listen_addrs: Vec<Multiaddr> = info
                            .listen_addrs
                            .iter()
                            .filter(|addr| {
                                let ok = !matches!(
                                    crate::p2p::classify_peer_addr::classify_peer_addr(addr, &peer_id),
                                    crate::p2p::addr_class::AddrClass::Malformed
                                        | crate::p2p::addr_class::AddrClass::Local
                                ) && !self.is_own_listen_addr(addr);
                                if !ok {
                                    log::debug!(
                                        "Dropping malformed/self listen addr from {}: {}",
                                        peer_id,
                                        addr
                                    );
                                }
                                ok
                            })
                            .cloned()
                            .collect();
                        for addr in &listen_addrs {
                            self.register_peer_addr(peer_id, addr.clone(), "identify", false);
                        }
                        // NOTE: info.observed_addr is NOT added to Kademlia —
                        // it is the remote peer's view of our outbound socket
                        // (often an ephemeral source port, not a listen addr),
                        // so it is never a dialable address for us.
                        self.maybe_flush_peer_cache();

                        // Friends relay for friends: if the peer speaks the
                        // circuit-relay HOP protocol AND has at least one
                        // reachable direct transport, adopt it as a known
                        // relay (TR-01). Every noid node bundles
                        // relay::Behaviour and advertises HOP — the protocol
                        // bit alone is NOT relay proof. PublicDirect or Lan
                        // addrs can serve a circuit (LAN relays deliver
                        // locally); Local/Malformed-only peers cannot —
                        // without this filter every Identify turned contacts
                        // into "relays". The dangerous half of TR-01 — the
                        // immediate close of the just-established circuit —
                        // is fixed inside `add_known_relay` itself (grace
                        // close only when a direct conn exists; never the
                        // last conn unless it is a relay we hold a
                        // reservation on).
                        if info.protocols.contains(&relay::HOP_PROTOCOL_NAME) {
                            let has_reachable_direct = listen_addrs.iter().any(|a| {
                                matches!(
                                    crate::p2p::classify_peer_addr::classify_peer_addr(
                                        a, &peer_id,
                                    ),
                                    crate::p2p::addr_class::AddrClass::PublicDirect
                                        | crate::p2p::addr_class::AddrClass::Lan
                                )
                            });
                            if has_reachable_direct {
                                let was_known =
                                    self.known_relays.iter().any(|(p, _)| *p == peer_id);
                                self.add_known_relay(peer_id, listen_addrs.clone());
                                let want_more = self.reserved_relays.len() < 4;
                                if !was_known
                                    && want_more
                                    && !self.reserved_relays.contains(&peer_id)
                                {
                                    // Identify arrived over a live conn —
                                    // reserve over that proven transport
                                    // (the rank-ordered book may prefer a
                                    // carrier-blocked QUIC addr, observed:
                                    // Android reservations=0).
                                    let addr = self
                                        .conn_remote
                                        .get(&connection_id)
                                        .filter(|a| {
                                            !a.iter().any(|p| matches!(
                                                p,
                                                libp2p::multiaddr::Protocol::P2pCircuit
                                            ))
                                        })
                                        .cloned()
                                        .or_else(|| {
                                            self.direct_addrs_of(&peer_id)
                                                .into_iter()
                                                .next()
                                        });
                                    if let Some(addr) = addr {
                                        self.request_reservation(peer_id, &addr);
                                    }
                                }
                            }
                        }
                        }
                    }
            ev => return self.on_room_event(ev, ctx).await,
        }
        LoopCtl::Keep
    }
}
