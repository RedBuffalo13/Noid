//! Connection + listener lifecycle arms — extracted from the event_loop
//! megaloop (Q04/A5). Behaviour-preserving move only.

use super::*;

impl P2PNode {
    pub(crate) async fn on_conn_event(
        &mut self,
        event: SwarmEvent<NoidBehaviourEvent>,
        ctx: &LoopCtx<'_>,
    ) -> LoopCtl {
        match event {
                    SwarmEvent::NewListenAddr { listener_id, address, .. } => {
                        // A pending reservation that produced a listen addr
                        // succeeded — clear it (ReservationReqAccepted does
                        // the rest of the bookkeeping).
                        self.pending_reservations.remove(&listener_id);
                        // Track our relayed (p2p-circuit) listen addresses —
                        // these are how other peers reach us through a relay.
                        // Exactly one hop: a nested circuit listen addr means a
                        // reservation was issued over a relayed connection and
                        // is undialable — don't advertise it.
                        let circuits = address
                            .iter()
                            .filter(|p| matches!(p, libp2p::multiaddr::Protocol::P2pCircuit))
                            .count();
                        if circuits == 1 {
                            *self.relayed_listener_refs
                                .entry(address.clone())
                                .or_insert(0) += 1;
                            if !self.relayed_addrs.contains(&address) {
                                log::info!("Relayed listen addr: {}", address);
                                self.relayed_addrs.push(address.clone());
                            }
                        } else if circuits > 1 {
                            // Nested-circuit addr (`…/p2p/Y/p2p-circuit/p2p/X/
                            // p2p-circuit/p2p/me`) — the relay advertises its
                            // own relayed addrs, so ONE addr of this listener's
                            // set nests relay→relay→me. It is benign: a real
                            // reservation-over-circuit cannot happen because
                            // request_reservation only issues RESERVE on
                            // direct conns. Killing the whole listener here
                            // (previous behaviour) destroyed the reservation
                            // — ListenerClosed reported every sibling addr as
                            // dead → "reservation gone" → re-RESERVE → the
                            // listener minted the same nested addr again → an
                            // infinite reserve/remove churn loop. Just skip
                            // the addr: it never enters relayed_addrs.
                            log::debug!("Ignoring nested-circuit listen addr: {}", address);
                        } else {
                            // DHT-01: only a publicly routable (or loopback,
                            // for same-host tests) bound address is an
                            // external-addr candidate. The old
                            // `!is_unspecified` check fed LAN/CGNAT listen
                            // addrs (192.168.x.x, 100.64.x.x) into
                            // add_external_address — AutoNAT "confirmed"
                            // them and every NATted phone promoted itself
                            // to Kademlia Server mode, quietly becoming a
                            // DHT record holder that prekey/mailbox writes
                            // then landed on while it slept.
                            let scope = address.iter().find_map(|p| match p {
                                libp2p::multiaddr::Protocol::Ip4(ip)
                                    if !ip.is_unspecified() =>
                                {
                                    Some(crate::p2p::classify_peer_addr::ip_scope(
                                        std::net::IpAddr::V4(ip),
                                    ))
                                }
                                libp2p::multiaddr::Protocol::Ip6(ip)
                                    if !ip.is_unspecified() =>
                                {
                                    Some(crate::p2p::classify_peer_addr::ip_scope(
                                        std::net::IpAddr::V6(ip),
                                    ))
                                }
                                _ => None,
                            });
                            match scope {
                                Some(crate::p2p::addr_class::AddrClass::PublicDirect)
                                    if self.relay_config.privacy
                                        == crate::p2p::relay_config::PrivacyMode::Direct =>
                                {
                                    // A globally routable interface — this
                                    // node IS a public relay candidate. The
                                    // old code only fed add_external_address
                                    // and never touched nat_status, so a
                                    // public VPS stayed "Behind the NAT"
                                    // with empty external_addrs and its
                                    // invites carried no direct addrs.
                                    self.swarm.add_external_address(address.clone());
                                    if !self.external_addrs.contains(&address) {
                                        self.external_addrs.push(address.clone());
                                    }
                                    if self.nat_status != NatStatus::Public {
                                        self.nat_status = NatStatus::Public;
                                        self.swarm
                                            .behaviour_mut()
                                            .kademlia
                                            .set_mode(Some(kad::Mode::Server));
                                        log::info!(
                                            "Public interface bound {} — node is public",
                                            address
                                        );
                                    }
                                    // Loopback external addrs fed earlier
                                    // are same-host placeholders — a WAN
                                    // relay must never hand out 127.0.0.1
                                    // circuit addrs to remote clients.
                                    let stale_locals: Vec<Multiaddr> = self
                                        .external_addrs
                                        .iter()
                                        .filter(|a| {
                                            a.iter().any(|p| match p {
                                                libp2p::multiaddr::Protocol::Ip4(ip) => {
                                                    ip.is_loopback()
                                                }
                                                libp2p::multiaddr::Protocol::Ip6(ip) => {
                                                    ip.is_loopback()
                                                }
                                                _ => false,
                                            })
                                        })
                                        .cloned()
                                        .collect();
                                    for a in stale_locals {
                                        self.external_addrs.retain(|x| *x != a);
                                        self.swarm.remove_external_address(&a);
                                    }
                                    if self.should_relay() {
                                        self.advertise_as_relay();
                                    }
                                }
                                Some(crate::p2p::addr_class::AddrClass::Local)
                                    if self.relay_config.privacy
                                        == crate::p2p::relay_config::PrivacyMode::Direct =>
                                {
                                    // Loopback feeds the swarm's external
                                    // set only while no public addr is known
                                    // — same-host tests need it for RESERVE
                                    // responses; self.external_addrs (the
                                    // invite source) stays clean.
                                    let have_public = self.external_addrs.iter().any(|a| {
                                        matches!(
                                            crate::p2p::classify_peer_addr::classify_peer_addr(
                                                a,
                                                &self.peer_id,
                                            ),
                                            crate::p2p::addr_class::AddrClass::PublicDirect
                                        )
                                    });
                                    if !have_public && self.external_addrs.is_empty() {
                                        self.swarm.add_external_address(address.clone());
                                    }
                                }
                                _ => {}
                            }
                        }
                        if !emit_ev(ctx.event_tx, P2PEvent::NewListenAddr(address.to_string())).await { return LoopCtl::Exit; }
                    }
                    SwarmEvent::ExpiredListenAddr { address, .. } => {
                        // One listener expired — the addr stays advertised
                        // while another live listener still serves it
                        // (parallel reservations dedup onto the same addr).
                        let last = match self.relayed_listener_refs.get_mut(&address) {
                            Some(n) => {
                                *n = n.saturating_sub(1);
                                *n == 0
                            }
                            None => true,
                        };
                        if last {
                            self.relayed_listener_refs.remove(&address);
                            self.relayed_addrs.retain(|a| *a != address);
                        }
                    }
                    SwarmEvent::ExternalAddrConfirmed { address } => {
                        // RV-02: any ExternalAddrConfirmed — relay circuit
                        // reservation or direct — carries a peer's proof the
                        // addr routes back to us. Mark it verified.
                        self.addr_evidence.mark(
                            &Self::canonical_dial_addr(&address).to_string(),
                            crate::p2p::addr_evidence::EvidenceState::Verified,
                            crate::p2p::addr_evidence::EvidenceSource::AutonatProbe,
                        );
                        if self.nat_probe_opened_at.is_none() {
                            self.nat_probe_opened_at = Some(std::time::Instant::now());
                        }
                        // The relay client reports our confirmed reservation
                        // address here (not via NewListenAddr) when the relay
                        // returns no usable addrs. Single-hop only, same as
                        // the NewListenAddr path.
                        let circuits = address
                            .iter()
                            .filter(|p| matches!(p, libp2p::multiaddr::Protocol::P2pCircuit))
                            .count();
                        if circuits == 1 && !self.relayed_addrs.contains(&address) {
                            self.relayed_addrs.push(address.clone());
                        } else if circuits > 1 {
                            // Undialable nested circuit — drop it so Identify
                            // stops advertising it to every connected peer.
                            log::warn!("Removing nested-circuit external addr: {}", address);
                            self.swarm.remove_external_address(&address);
                        } else if circuits == 0
                            && matches!(
                                crate::p2p::classify_peer_addr::classify_peer_addr(
                                    &address,
                                    &self.peer_id,
                                ),
                                crate::p2p::addr_class::AddrClass::PublicDirect
                            )
                        {
                            // A direct PUBLIC addr was confirmed (configured
                            // external_addr or a bound public interface) —
                            // sync reachability the same way NewListenAddr
                            // does so Auto-role VPS nodes advertise as
                            // relays and invites include the direct addrs.
                            if !self.external_addrs.contains(&address) {
                                self.external_addrs.push(address.clone());
                            }
                            if self.nat_status != NatStatus::Public {
                                self.nat_status = NatStatus::Public;
                                self.swarm
                                    .behaviour_mut()
                                    .kademlia
                                    .set_mode(Some(kad::Mode::Server));
                                log::info!(
                                    "Public external addr confirmed {} — node is public",
                                    address
                                );
                            }
                            if self.should_relay() {
                                self.advertise_as_relay();
                            }
                        }
                        log::debug!("External address confirmed: {}", address);
                    }
                    SwarmEvent::ExternalAddrExpired { address } => {
                        // Listener-backed relayed addrs are owned by the
                        // New/ExpiredListenAddr refcount — an external-addr
                        // expiry must not remove an addr a live listener
                        // still serves.
                        if !self.relayed_listener_refs.contains_key(&address) {
                            self.relayed_addrs.retain(|a| *a != address);
                        }
                    }
            ev => return self.on_conn_peer_event(ev, ctx).await,
        }
        LoopCtl::Keep
    }
}
