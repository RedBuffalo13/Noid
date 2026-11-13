//! Peer connection established/closed arms — extracted from the event_loop
//! megaloop (Q04/A5). Behaviour-preserving move only.

use super::*;

impl P2PNode {
    /// Build + send the signed endpoint advertisement (onion3 listen addr
    /// plus confirmed external addrs) to a connected contact. Called on
    /// ConnectionEstablished and when a peer becomes a contact while
    /// already connected — the receiver verifies the signature and caches
    /// the endpoints as hints.
    /// SEC-1111-05: transport planes stay separated — onion3 is never
    /// advertised while Tor is off, direct IPs never under RelayedOnly.
    pub(crate) fn send_endpoint_advertise(&mut self, peer_id: &PeerId) {
        // RV-05: advertise the onion endpoint only once the self-connect
        // probe proved the descriptor is published — an unpublished
        // `/onion3/` in a signed record poisons the receiver's dial book
        // exactly like the ungated invite did.
        let tor_on = self
            .tor
            .as_ref()
            .map(|t| {
                t.status().publish_state
                    == crate::p2p::tor::status::PublishState::Published
            })
            .unwrap_or(false);
        let mut endpoints: Vec<String> = Vec::new();
        if tor_on {
            let own_onion = self
                .own_onion_addr
                .clone()
                .or_else(|| self.tor.as_ref().and_then(|t| t.listen_multiaddr()));
            if let Some(o) = own_onion {
                endpoints.push(o.to_string());
            }
        }
        if self.relay_config.privacy == crate::p2p::relay_config::PrivacyMode::Direct {
            endpoints.extend(self.external_addrs.iter().map(|a| a.to_string()));
        }
        if endpoints.is_empty() {
            return;
        }
        match crate::p2p::endpoint_record::sign_record(&self.identity_keypair, endpoints) {
            Ok(mut rec) => {
                // RV-07: attest the addr WE used to reach this peer — a
                // signed "your path X works from me" so their invite can
                // rank it verified. Dialer conns only: on inbound we don't
                // know which advertised hint the remote picked.
                let dialed = self
                    .conn_quic
                    .get(peer_id)
                    .into_iter()
                    .flat_map(|m| m.keys().copied())
                    .find(|id| self.conn_dialer.get(id).copied().unwrap_or(false))
                    .and_then(|id| self.conn_remote.get(&id).cloned());
                if let Some(via) = dialed {
                    let via = Self::canonical_dial_addr(&via).to_string();
                    match crate::p2p::endpoint_record::sign_attestation(
                        &self.identity_keypair,
                        &peer_id.to_string(),
                        &via,
                    ) {
                        Ok(att) => rec.attest = Some(att),
                        Err(e) => log::debug!("attestation sign failed: {}", e),
                    }
                }
                if let Ok(json) = serde_json::to_string(&rec) {
                    let adv = crate::p2p::types::NoidMessage {
                        sender: self.peer_id.to_string(),
                        content: json,
                        msg_type: crate::p2p::types::MessageType::EndpointAdvertise,
                        timestamp: Some(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
                        id: uuid::Uuid::new_v4().to_string(),
                    };
                    let _ = self.swarm.behaviour_mut().request_response.send_request(peer_id, adv);
                }
            }
            Err(e) => log::warn!("endpoint record sign failed: {}", e),
        }
    }

    pub(crate) async fn on_conn_peer_event(
        &mut self,
        event: SwarmEvent<NoidBehaviourEvent>,
        ctx: &LoopCtx<'_>,
    ) -> LoopCtl {
        match event {
                    SwarmEvent::ConnectionEstablished { peer_id, connection_id, endpoint, .. } => {
                        log::info!(
                            "Peer connected: {} ({}) via {}",
                            peer_id,
                            if endpoint.is_relayed() { "relayed" } else { "direct" },
                            endpoint.get_remote_address()
                        );
                        // Blind-bootstrap seed connected — the pinned peer id
                        // rotated (or was never known). Register the learned
                        // id into Kademlia + the relay book so the node joins
                        // the WAN even when the bundled seed's identity
                        // changed. The pinned path stays preferred: this only
                        // fires for seeds dialed without /p2p/.
                        if !endpoint.is_relayed() {
                            let remote_base = Self::relay_base_addr(endpoint.get_remote_address());
                            if self.blind_bootstrap_addrs.contains(&remote_base) {
                                log::info!(
                                    "Blind bootstrap seed answered as {} — registering learned peer",
                                    peer_id
                                );
                                let learned = remote_base
                                    .clone()
                                    .with(libp2p::multiaddr::Protocol::P2p(peer_id));
                                self.register_peer_addr(peer_id, learned.clone(), "bootstrap-learned", true);
                                self.add_known_relay(peer_id, vec![learned]);
                                self.blind_bootstrap_addrs.retain(|a| *a != remote_base);
                                // Populate the routing table now that we have
                                // a real peer — the initial bootstrap() may
                                // have deferred with an empty table.
                                let _ = self.swarm.behaviour_mut().kademlia.bootstrap();
                            }
                        }
                        // First live connection to this peer — peers may hold
                        // several (TCP + relayed), so PeerConnected fires once.
                        let first = self.connected_peers.insert(peer_id);
                        // RV-03: a live conn is what AutoNAT's use_connected
                        // probes need — open the honesty window from here.
                        if self.nat_probe_opened_at.is_none() {
                            self.nat_probe_opened_at = Some(std::time::Instant::now());
                        }
                        // On-demand bookkeeping: a fresh conn starts the
                        // peer's idle window (torn down past the TTL).
                        self.contact_idle_since
                            .insert(peer_id, tokio::time::Instant::now());
                        self.conn_transport_branch(peer_id, connection_id, &endpoint);
                        // Transport bookkeeping for QUIC pinning. F9: a
                        // relayed endpoint whose relay hop happens to ride
                        // QUIC must NOT count — pinning on it would kill
                        // healthy direct conns and strand traffic on a
                        // byte-capped circuit.
                        let is_quic = !endpoint.is_relayed()
                            && endpoint.get_remote_address().iter().any(|p| {
                                matches!(p, libp2p::multiaddr::Protocol::QuicV1)
                            });
                        self.conn_quic
                            .entry(peer_id)
                            .or_default()
                            .insert(connection_id, is_quic);
                        self.conn_dialer
                            .insert(connection_id, endpoint.is_dialer());
                        // EL-08: conns closed inside this handler must not
                        // report PeerConnected for a socket already dying.
                        let conn_closing = self.conn_pin_quic(peer_id, connection_id, is_quic, &endpoint);
                        self.clear_dial_backoff(&peer_id);
                        // A dialer endpoint just proved the remote addr
                        // works — (re)register it in the routing table and the
                        // peer cache. This is what heals the table after the
                        // 3-strike eviction or after Kademlia dropped the
                        // peer while one transport still lived.
                        // RV-02: an inbound conn is a real peer's proof our
                        // advertised path works — mark it in the ledger.
                        if endpoint.is_listener() {
                            if let libp2p::core::ConnectedPoint::Listener { local_addr, .. } = &endpoint {
                                self.note_inbound_path(local_addr);
                            }
                        }
                        if endpoint.is_dialer() {
                            let remote = endpoint.get_remote_address().clone();
                            self.note_dial_success(&remote);
                            self.conn_remote.insert(connection_id, remote.clone());
                            // Route through the classifier — raw
                            // kademlia.add_address/peer_cache.upsert skipped
                            // own-addr, malformed and circuit-terminal checks,
                            // which is how self-dial and bare-relay entries
                            // poisoned the routing table.
                            self.register_peer_addr(peer_id, remote, "dial-ok", false);
                        }
                        if first
                            && !conn_closing
                            && !emit_ev(ctx.event_tx, P2PEvent::PeerConnected(peer_id.to_string())).await { return LoopCtl::Exit; }

                        // SEC-1111-05: announce our username only to
                        // confirmed contacts — every-DHT-peer fan-out used to
                        // leak the @name ↔ PeerId binding to strangers.
                        if self.contact_peers.contains(&peer_id) {
                            if let Some((username, record)) = &self.my_username {
                            let record_json = serde_json::to_string(record).unwrap_or_default();
                            let announce_msg = crate::p2p::types::NoidMessage {
                                sender: self.peer_id.to_string(),
                                content: record_json,
                                msg_type: crate::p2p::types::MessageType::UsernameAnnounce {
                                    username: username.clone(),
                                },
                                timestamp: Some(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
                                id: uuid::Uuid::new_v4().to_string(),
                            };
                            let _ = self.swarm.behaviour_mut().request_response.send_request(&peer_id, announce_msg);
                            log::debug!("Sent username announce to peer {}", peer_id);
                            }
                        }

                        // P4: signed endpoint advertisement — our onion3
                        // listen addr plus confirmed external addrs. The
                        // receiver verifies the signature and caches the
                        // endpoints as hints (an onion addr alone proves
                        // nothing about reachability).
                        // SEC-1111-05: contacts only, and transport planes
                        // stay separated — onion3 is never advertised while
                        // Tor is off, direct IPs never under RelayedOnly.
                        if self.contact_peers.contains(&peer_id) {
                            self.send_endpoint_advertise(&peer_id);
                        }

                        // Once directly connected to a known relay, request a
                        // circuit reservation. Doing it here (not at dial time)
                        // avoids a race where the relay-client behaviour's own
                        // dial is deduplicated against our manual dial and the
                        // RESERVE request is silently dropped.
                        if !endpoint.is_relayed() && !self.reserved_relays.contains(&peer_id) {
                            // Reserve over the transport THIS conn just
                            // proved — direct_addrs_of is rank-ordered and
                            // can pick a dead transport (e.g. QUIC blocked
                            // by the carrier) while the live conn sits on
                            // TCP/WS (observed: Android reservations=0).
                            let live = endpoint.get_remote_address().clone();
                            let addr = if endpoint.is_dialer()
                                && !live.iter().any(|p| matches!(
                                    p,
                                    libp2p::multiaddr::Protocol::P2pCircuit
                                )) {
                                Some(live)
                            } else {
                                self.direct_addrs_of(&peer_id).into_iter().next()
                            };
                            if let Some(addr) = addr {
                                self.request_reservation(peer_id, &addr);
                            }
                        }
                        let _ = emit_ev(ctx.event_tx, P2PEvent::RelayStatusChanged {
                            status: self.relay_status(),
                        }).await;
                    }
                    SwarmEvent::ConnectionClosed { peer_id, connection_id, endpoint, num_established, cause, .. } => {
                        log::info!(
                            "Conn closed: peer={} conn={:?} relayed={} remote={} remaining={} cause={:?}",
                            peer_id, connection_id, endpoint.is_relayed(),
                            endpoint.get_remote_address(), num_established, cause
                        );
                        self.ping_failures.remove(&connection_id);
                        self.conn_dialer.remove(&connection_id);
                        self.conn_remote.remove(&connection_id);
                        if let Some(m) = self.conn_quic.get_mut(&peer_id) {
                            m.remove(&connection_id);
                            if m.is_empty() {
                                self.conn_quic.remove(&peer_id);
                            }
                        }
                        if endpoint.is_relayed() {
                            if let Some(ids) = self.relayed_conn_ids.get_mut(&peer_id) {
                                ids.remove(&connection_id);
                                if ids.is_empty() {
                                    self.relayed_conn_ids.remove(&peer_id);
                                }
                            }
                            // A deferred reservation (skipped while this relayed
                            // conn was closing) can go out now that dedup can
                            // only land on a direct conn. request_reservation
                            // picks the right arm itself: no conns → direct
                            // dial, direct conn → RESERVE, still-closing
                            // circuits → defer.
                            let no_relayed_left = self
                                .relayed_conn_ids
                                .get(&peer_id)
                                .map(|s| s.is_empty())
                                .unwrap_or(true);
                            if no_relayed_left
                                && !self.reserved_relays.contains(&peer_id)
                                && self.known_relays.iter().any(|(p, _)| *p == peer_id)
                            {
                                if let Some(addr) =
                                    self.direct_addrs_of(&peer_id).into_iter().next()
                                {
                                    self.request_reservation(peer_id, &addr);
                                }
                            }
                        } else if let Some(n) = self.direct_conns.get_mut(&peer_id) {
                            *n = n.saturating_sub(1);
                            // EL-06: the last direct conn to a relay died
                            // while relayed conns to it survive — reservation
                            // renewals would dedup onto the circuit (nested).
                            // Retire the leftovers; the relayed-closed arm
                            // above (or the disconnected arm below) rebuilds
                            // the direct path and the reservation.
                            if *n == 0
                                && self.known_relays.iter().any(|(p, _)| *p == peer_id)
                            {
                                if let Some(ids) = self.relayed_conn_ids.get(&peer_id) {
                                    let deadline = tokio::time::Instant::now()
                                        + tokio::time::Duration::from_secs(20);
                                    for id in ids.iter().copied().collect::<Vec<_>>() {
                                        log::debug!(
                                            "Scheduling close of leftover relayed conn {:?} to relay {} — last direct conn died",
                                            id, peer_id
                                        );
                                        self.pending_conn_close.push((deadline, peer_id, id));
                                    }
                                }
                            }
                        }
                        // num_established counts connections still open —
                        // only the last close means the peer went offline.
                        if num_established == 0 {
                            log::info!("Peer disconnected: {}", peer_id);
                            self.connected_peers.remove(&peer_id);
                            self.direct_conns.remove(&peer_id);
                            let had_reservation = self.reserved_relays.remove(&peer_id);
                            if !emit_ev(ctx.event_tx, P2PEvent::PeerDisconnected(peer_id.to_string())).await { return LoopCtl::Exit; }
                            // A reservation dies with its conn — while we
                            // are unreserved nobody can reach us through this
                            // relay. Redial immediately instead of waiting
                            // for the periodic refresh; ConnectionEstablished
                            // re-issues RESERVE. Backoff still applies so a
                            // truly dead relay is not stormed.
                            if had_reservation && !self.dial_is_backed_off(&peer_id) {
                                let direct = self.direct_addrs_of(&peer_id);
                                if !direct.is_empty() {
                                    log::info!(
                                        "Reservation lost with conn — redialing relay {}",
                                        peer_id
                                    );
                                    let _ = self.swarm.dial(
                                        crate::p2p::dial_opts::dial_opts_multi(
                                            peer_id, direct,
                                        ),
                                    );
                                }
                            } else if !had_reservation
                                && !self.connectivity_config.on_demand
                                && !self.dial_is_backed_off(&peer_id)
                                && !self
                                    .pending_conn_close
                                    .iter()
                                    .any(|(_, p, _)| *p == peer_id)
                            {
                                // Mobile CGNAT mappings expire mid-session
                                // (Tele2 kills idle TCP state in ~90-120s):
                                // the conn dies while the peer stays online.
                                // Re-punch + fast redial over its known
                                // direct addrs — the relay path above only
                                // covers lost reservations.
                                let direct: Vec<Multiaddr> = self
                                    .direct_addrs_of(&peer_id)
                                    .into_iter()
                                    .filter(|a| self.dial_allowed(a))
                                    .collect();
                                if !direct.is_empty() && self.direct_net_allowed() {
                                    for a in &direct {
                                        if let Some(sa) =
                                            crate::p2p::punch_assist::extract_wan_socket_addr(a)
                                        {
                                            crate::p2p::punch_assist::spawn_udp_punch_burst(
                                                sa, false,
                                            );
                                        }
                                    }
                                    log::info!(
                                        "Peer {} lost — fast redial over {} direct addr(s)",
                                        peer_id,
                                        direct.len()
                                    );
                                    let _ = self.swarm.dial(
                                        crate::p2p::dial_opts::dial_opts_multi(
                                            peer_id, direct,
                                        ),
                                    );
                                }
                            }
                        }
                        let _ = emit_ev(ctx.event_tx, P2PEvent::RelayStatusChanged {
                            status: self.relay_status(),
                        }).await;
                    }
            ev => return self.on_conn_err_event(ev, ctx).await,
        }
        LoopCtl::Keep
    }
}
