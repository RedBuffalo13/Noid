//! Request-response protocol arms: chat messages, mailbox, 2-hop —
//! extracted from the event_loop megaloop (Q04/A5). Behaviour-preserving move only.

use super::*;

impl P2PNode {
    pub(crate) async fn on_proto_event(
        &mut self,
        event: SwarmEvent<NoidBehaviourEvent>,
        ctx: &LoopCtx<'_>,
    ) -> LoopCtl {
        match event {
                    SwarmEvent::Behaviour(NoidBehaviourEvent::RequestResponse(request_response::Event::Message {
                        peer,
                        connection_id: _,
                        message: request_response::Message::Request { request_id: _req_id, request, channel },
                    })) => {
                        // F18: any live inbound traffic proves the peer's
                        // conns are not zombies — reset their streaks (the
                        // request_response 0.27 event carries no conn id).
                        if let Some(ids) = self.conn_quic.get(&peer) {
                            let ids: Vec<_> = ids.keys().copied().collect();
                            for id in ids { self.ping_failures.remove(&id); }
                        }
                        // S22: dedup keyed by (peer, id) — a sender-chosen id
                        // must not be able to pre-fill the replay cache and
                        // suppress another peer's message carrying the same id.
                        let seen_key = format!("{}:{}", peer, request.id);
                        if self.seen_message_ids.contains(&seen_key) {
                            log::warn!("Replay detected: duplicate direct message ID {}", request.id);
                            // Phase J.3: Log replay detection
                            if let Some(ref log) = self.audit_log {
                                let _ = log.log_replay_detected(&request.id);
                            }
                            if let Err(e) = self.swarm.behaviour_mut().request_response.send_response(channel, crate::p2p::types::NoidResponse {
                                status: "DUPLICATE".into(),
                                data: None,
                            }) {
                                log::warn!("Failed to send response to {}: {:?}", peer, e);
                            }
                            return LoopCtl::Keep;
                        }

                        // X3DH-07: a direct prekey request is answered from
                        // our own signed bundle in the local DHT fallback —
                        // the DHT may be unreachable while this very peer is
                        // already connected and asking.
                        if matches!(request.msg_type, crate::p2p::types::MessageType::PrekeyBundleRequest) {
                            let own_key =
                                Self::prekey_dht_key(&self.peer_id.to_string());
                            let data = self.local_dht_get(&own_key.to_vec());
                            let status = if data.is_some() { "OK" } else { "NO_BUNDLE" };
                            if let Err(e) = self.swarm.behaviour_mut().request_response.send_response(channel, crate::p2p::types::NoidResponse {
                                status: status.into(),
                                data,
                            }) {
                                log::warn!("Failed to answer prekey request from {}: {:?}", peer, e);
                            } else {
                                self.mark_seen(&seen_key);
                            }
                            return LoopCtl::Keep;
                        }

                        // UsernameAnnounce / EndpointAdvertise are answered
                        // inline — handled synchronously below and never
                        // reaching the app layer.
                        if !matches!(request.msg_type,
                            crate::p2p::types::MessageType::UsernameAnnounce { .. }
                            | crate::p2p::types::MessageType::EndpointAdvertise)
                        {
                            // Exchanged X25519 key — derives this contact's
                            // persistent daily rendezvous slot (rv v2).
                            if let crate::p2p::types::MessageType::PublicKeyExchange {
                                public_key,
                            } = &request.msg_type
                            {
                                self.peer_pubkeys.insert(peer, *public_key);
                            }
                            // TI-1: park the response channel. The transport
                            // "OK" doubles as the application-level ack and is
                            // sent only after the app layer reports durable
                            // processing via P2PCommand::AckReceived — acking
                            // here used to confirm delivery before the message
                            // was persisted (a real loss window on crash).
                            self.park_app_ack(peer.to_string(), request.id.clone(), channel);
                            // Inbound activity keeps the contact's idle
                            // window open in on-demand mode.
                            self.contact_idle_since
                                .insert(peer, tokio::time::Instant::now());
                            if !emit_ev(ctx.event_tx, P2PEvent::RequestReceived {
                                from: peer.to_string(),
                                data: request,
                            }).await { return LoopCtl::Exit; }
                            return LoopCtl::Keep;
                        }

                        if let Err(e) = self.swarm.behaviour_mut().request_response.send_response(channel, crate::p2p::types::NoidResponse {
                            status: "OK".into(),
                            data: None,
                        }) {
                            log::warn!("Failed to send response to {}: {:?}", peer, e);
                        } else {
                            // Same rule as the parked-ack path: an id is
                            // seen only once its answer actually left.
                            self.mark_seen(&seen_key);
                        }

                        // Handle UsernameAnnounce — store in local DHT records.
                        // The announced record must belong to the connected peer
                        // AND carry a valid identity signature — otherwise a peer
                        // could claim someone else's username by gossip.
                        if let crate::p2p::types::MessageType::UsernameAnnounce { ref username } = request.msg_type {
                            if let Ok(record) = serde_json::from_str::<crate::p2p::types::DHTUserRecord>(&request.content) {
                                let sig_ok = record.signature.as_ref().map(|sig| {
                                    crate::security::identity_sig::verify_payload(
                                        &record.peer_id,
                                        &crate::p2p::types::user_record_signing_payload(&record),
                                        sig,
                                    )
                                }).unwrap_or(false);
                                // The announced name must match the signed
                                // username — otherwise the record could be
                                // replayed under a different DHT key.
                                if record.peer_id != peer.to_string() || !sig_ok || record.username != *username {
                                    log::warn!(
                                        "Rejected username announce from {}: owner={} sig_valid={} name_match={}",
                                        peer, record.peer_id, sig_ok, record.username == *username
                                    );
                                } else {
                                    let key = crate::p2p::dht_username_ops::DHTUsernameKey::compute(username);
                                    // SEC-1111-01: same ownership-continuity
                                    // policy as the DHT store — gossip must
                                    // not bypass it. Also refuse far-future
                                    // timestamps here since the announce path
                                    // skips ValidatingStore entirely.
                                    if !crate::p2p::validate_record_timestamp::record_timestamp_acceptable(
                                        Some(&record.updated_at),
                                    ) {
                                        log::warn!("Rejected username announce for '{}': future-dated record", username);
                                        return LoopCtl::Keep;
                                    }
                                    let replace = self
                                        .local_dht_get(&key)
                                        .map(|stored| {
                                            serde_json::from_slice::<crate::p2p::types::DHTUserRecord>(&stored)
                                                .map(|stored_rec| {
                                                    crate::p2p::can_replace_user_record::can_replace_user_record(&stored_rec, &record)
                                                })
                                                .unwrap_or(true)
                                        })
                                        .unwrap_or(true);
                                    if replace {
                                        self.local_dht_put(key, request.content.into_bytes());
                                        log::debug!("Received username announce from peer {}: username='{}'", peer, username);
                                    } else {
                                        log::debug!("Ignored stale/foreign username announce for '{}'", username);
                                    }
                                }
                            }
                            return LoopCtl::Keep;
                        }

                        // P4: EndpointAdvertise — verify + canonicalize the
                        // signed record, then cache its endpoints as hints.
                        if matches!(request.msg_type, crate::p2p::types::MessageType::EndpointAdvertise) {
                            match serde_json::from_str::<crate::p2p::endpoint_record::EndpointRecord>(&request.content) {
                                Ok(rec) => {
                                    // The record must name the connected
                                    // peer — otherwise anyone could pin
                                    // foreign endpoints on a session.
                                    if rec.peer_id != peer.to_string() {
                                        log::warn!("Endpoint record from {} names {} — dropped", peer, rec.peer_id);
                                    } else {
                                        match crate::p2p::endpoint_record::verify_and_canonicalize(&rec, &self.peer_id) {
                                            Ok(ve) => {
                                                for a in &ve.addrs {
                                                    self.swarm.add_peer_address(peer, a.clone());
                                                }
                                                self.peer_cache.upsert(peer, ve.addrs, false);
                                                self.peer_cache_dirty = true;
                                                // RV-07: the peer signed
                                                // "I reached you via X" —
                                                // positive evidence for the
                                                // matching advertised addr.
                                                if let Some(via) = ve.attested_addr {
                                                    let key = Self::canonical_dial_addr(&via).to_string();
                                                    let ours = self.external_addrs.iter()
                                                        .chain(self.relayed_addrs.iter())
                                                        .chain(self.own_onion_addr.iter())
                                                        .any(|a| Self::canonical_dial_addr(a).to_string() == key);
                                                    if ours {
                                                        self.addr_evidence.mark(
                                                            &key,
                                                            crate::p2p::addr_evidence::EvidenceState::Verified,
                                                            crate::p2p::addr_evidence::EvidenceSource::PeerAttest,
                                                        );
                                                        log::info!("Peer {} attested reaching us via {}", peer, key);
                                                    }
                                                }
                                            }
                                            Err(e) => log::warn!("Rejected endpoint record from {}: {}", peer, e),
                                        }
                                    }
                                }
                                Err(e) => log::warn!("Malformed endpoint record from {}: {}", peer, e),
                            }
                            return LoopCtl::Keep;
                        }

                        if !emit_ev(ctx.event_tx, P2PEvent::RequestReceived {
                            from: peer.to_string(),
                            data: request,
                        }).await { return LoopCtl::Exit; }
                    }
                    SwarmEvent::Behaviour(NoidBehaviourEvent::RequestResponse(request_response::Event::Message {
                        peer,
                        connection_id: _,
                        message: request_response::Message::Response { request_id, response },
                    })) => {
                        log::debug!("Received response from {} for request {}", peer, request_id);
                        // META-05: a forwarded /noid answer — wrap into
                        // HopResponse for the parked upstream requester.
                        if let Some(channel) = self.hop_pending_noid.remove(&request_id.to_string()) {
                            match serde_json::to_vec(&response) {
                                Ok(payload) => {
                                    let _ = self.swarm.behaviour_mut().hop.send_response(
                                        channel,
                                        crate::p2p::hop::HopResponse { payload },
                                    );
                                }
                                Err(e) => log::warn!("Hop response serialize failed: {}", e),
                            }
                            return LoopCtl::Keep;
                        }
                        // X3DH-07: a direct prekey answer resolves the fetch
                        // independently of the DHT path — owner + signature
                        // are verified exactly like a DHT-served bundle.
                        if let Some(peer_id) = self.pending_prekey_requests.remove(&request_id.to_string()) {
                            let bundle = response.data.as_ref()
                                .and_then(|v| serde_json::from_slice::<crate::security::PrekeyBundle>(v).ok())
                                .filter(|b| {
                                    b.owner_peer_id.as_deref() == Some(peer_id.as_str())
                                        && crate::security::x3dh::verify_prekey_bundle(b)
                                });
                            match bundle {
                                Some(b) => {
                                    if self.prekey_recently_resolved(&peer_id) { return LoopCtl::Keep; }
                                    self.mark_prekey_resolved(&peer_id);
                                    // Cache the verified copy for the local
                                    // DHT fallback path (DHT-04).
                                    if let Some(bytes) = response.data.as_ref() {
                                        self.local_dht_put(
                                            Self::prekey_dht_key(&peer_id).to_vec(),
                                            bytes.clone(),
                                        );
                                    }
                                    let _ = emit_ev(ctx.event_tx, P2PEvent::PrekeyBundleRetrieved {
                                        peer_id,
                                        bundle: Some(b),
                                    }).await;
                                }
                                None => {
                                    log::debug!("Direct prekey answer from {} carried no valid bundle", peer);
                                    // The DHT query may still resolve it —
                                    // emit the failure only when nothing is
                                    // left in flight for this peer.
                                    if !self.prekey_dht_pending(&peer_id)
                                        && !self.prekey_recently_resolved(&peer_id)
                                    {
                                        let _ = emit_ev(ctx.event_tx, P2PEvent::PrekeyBundleRetrieved {
                                            peer_id,
                                            bundle: None,
                                        }).await;
                                    }
                                }
                            }
                            return LoopCtl::Keep;
                        }
                        // Phase 1.3: Emit MessageDelivered so the forwarder can delete the pending record
                        if let Some(msg) = self.pending_messages.remove(&request_id.to_string()) {
                            let _ = emit_ev(ctx.event_tx, P2PEvent::MessageDelivered {
                                peer_id: peer.to_string(),
                                message_id: msg.id.clone(),
                            }).await;
                        }
                    }
                    SwarmEvent::Behaviour(NoidBehaviourEvent::RequestResponse(request_response::Event::OutboundFailure {
                        peer,
                        connection_id: _,
                        request_id,
                        error,
                    })) => {
                        // META-05: if this leg was a hop forward, drop the
                        // parked channel — the upstream requester times out.
                        if self.hop_pending_noid.remove(&request_id.to_string()).is_some() {
                            log::debug!("Hop-forward leg to {} failed: {}", peer, error);
                            return LoopCtl::Keep;
                        }
                        // F7: a request that timed out proves the conn it rode
                        // is a zombie — but request_response 0.27 does not say
                        // WHICH conn. disconnect_peer_id would also kill the
                        // conn carrying our circuit reservation → reservation-
                        // loss cycle. Instead: bump every conn's suspicion so
                        // ping reaps the dead ones, and arm dial backoff so
                        // the next send prefers a fresh path / mailbox.
                        if matches!(error, request_response::OutboundFailure::Timeout) {
                            log::debug!("Send timeout to {} — flagging non-QUIC conns for ping-reap", peer);
                            // Only DIRECT non-QUIC conns are flagged: QUIC
                            // survives NAT rebinding, and a relayed conn is
                            // a shared circuit whose failures belong to the
                            // relay hop, not the peer path — reaping it for
                            // an unrelated timeout strands CGNAT peers on
                            // their only route (EL-07).
                            let relayed_ids = self
                                .relayed_conn_ids
                                .get(&peer)
                                .cloned()
                                .unwrap_or_default();
                            if let Some(ids) = self.conn_quic.get(&peer) {
                                let ids: Vec<_> = ids
                                    .iter()
                                    .filter(|(id, quic)| !**quic && !relayed_ids.contains(*id))
                                    .map(|(id, _)| *id)
                                    .collect();
                                for id in ids {
                                    *self.ping_failures.entry(id).or_insert(0) += 1;
                                }
                            }
                        }
                        // X3DH-07: a failed direct prekey request resolves
                        // the fetch only when the DHT path is done too —
                        // and must NOT emit MessageFailed (it is not a chat
                        // message; the generic arm would re-pend junk).
                        if let Some(peer_id) =
                            self.pending_prekey_requests.remove(&request_id.to_string())
                        {
                            log::debug!(
                                "Direct prekey request to {} failed: {:?} — DHT path may still resolve",
                                peer, error
                            );
                            if !self.prekey_dht_pending(&peer_id)
                                && !self.prekey_recently_resolved(&peer_id)
                            {
                                let _ = emit_ev(ctx.event_tx, P2PEvent::PrekeyBundleRetrieved {
                                    peer_id,
                                    bundle: None,
                                }).await;
                            }
                            return LoopCtl::Keep;
                        }
                        let pending_msg = self.pending_messages.remove(&request_id.to_string());
                        let content = pending_msg.as_ref().map(|msg| msg.content.clone()).unwrap_or_default();
                        let message_id = pending_msg.as_ref().map(|msg| msg.id.clone()).unwrap_or_default();
                        let msg_type = pending_msg.as_ref().map(|msg| msg.msg_type.clone())
                            .unwrap_or(crate::p2p::MessageType::Chat(content.clone()));

                        if !emit_ev(ctx.event_tx, P2PEvent::MessageFailed {
                            to: peer.to_string(),
                            request_id: request_id.to_string(),
                            error: error.to_string(),
                            content,
                            message_id,
                            msg_type,
                        }).await { return LoopCtl::Exit; }
                    }
            ev => return self.on_mailbox_event(ev, ctx).await,
        }
        LoopCtl::Keep
    }
}
