//! Mailbox request-response arms — extracted from the event_loop megaloop (Q04/A5).
//! Behaviour-preserving move only.

use super::*;

impl P2PNode {
    pub(crate) async fn on_mailbox_event(
        &mut self,
        event: SwarmEvent<NoidBehaviourEvent>,
        ctx: &LoopCtx<'_>,
    ) -> LoopCtl {
        match event {
                    // Phase B.2: Mailbox protocol — handle incoming mailbox requests
                    SwarmEvent::Behaviour(NoidBehaviourEvent::Mailbox(request_response::Event::Message {
                        peer,
                        connection_id: _,
                        message: request_response::Message::Request { request_id: _req_id, request, channel },
                    })) => {
                        // F18: live mailbox traffic also proves the conns.
                        if let Some(ids) = self.conn_quic.get(&peer) {
                            let ids: Vec<_> = ids.keys().copied().collect();
                            for id in ids { self.ping_failures.remove(&id); }
                        }
                        log::debug!("Received mailbox request from {}", peer);
                        // Clone db ref before async — P2PNode is not Sync
                        let db_ref = self.db.clone();
                        let response = match db_ref {
                            Some(db) => {
                                let db_guard = db.lock().await;
                                match db_guard.as_ref() {
                                    Some(db) => {
                                        match request {
                                            crate::p2p::types::MailboxRequest::Store { recipient_peer_id, sender_peer_id, encrypted_content, signature, client_msg_id } => {
                                                // AUTH: the Noise-authenticated swarm peer must be the
                                                // claimed sender, and the envelope must carry that
                                                // sender's identity signature. A present client_msg_id
                                                // shifts the signature to the v2 payload that binds it.
                                                let peer_str = peer.to_string();
                                                let authed = sender_peer_id == peer_str
                                                    && crate::security::identity_sig::verify_payload(
                                                        &sender_peer_id,
                                                        &match &client_msg_id {
                                                            Some(id) => crate::p2p::types::envelope_signing_payload_v2(
                                                                &recipient_peer_id,
                                                                &sender_peer_id,
                                                                id,
                                                                &encrypted_content,
                                                            ),
                                                            None => crate::p2p::types::envelope_signing_payload(
                                                                &recipient_peer_id,
                                                                &sender_peer_id,
                                                                &encrypted_content,
                                                            ),
                                                        },
                                                        &signature,
                                                    );
                                                if !authed {
                                                    log::warn!("Mailbox: rejected Store from {} (claimed sender {})", peer, sender_peer_id);
                                                    crate::p2p::types::MailboxResponse::Ack { success: false }
                                                } else if !crate::p2p::mailbox_guard::MailboxGuard::envelope_size_ok(&encrypted_content) {
                                                    log::warn!("Mailbox: oversized envelope from {}", peer);
                                                    crate::p2p::types::MailboxResponse::Ack { success: false }
                                                } else if !self.mailbox_guard.allow_store(&peer_str) {
                                                    log::warn!("Mailbox: rate-limited Store from {}", peer);
                                                    crate::p2p::types::MailboxResponse::Ack { success: false }
                                                } else {
                                                    // Quotas: 50 per sender→recipient, 200 per recipient.
                                                    let pair = db.get_mailbox_count_for_pair(&recipient_peer_id, &sender_peer_id).await.unwrap_or(0);
                                                    let total = db.get_mailbox_message_count(&recipient_peer_id).await.unwrap_or(0);
                                                    if pair >= crate::p2p::mailbox_guard::MAX_PER_SENDER_PER_RECIPIENT
                                                        || total >= crate::p2p::mailbox_guard::MAX_PER_RECIPIENT
                                                    {
                                                        log::warn!("Mailbox: quota exceeded for {} (pair={}, total={})", recipient_peer_id, pair, total);
                                                        crate::p2p::types::MailboxResponse::Ack { success: false }
                                                    } else {
                                                        // F2: keep the sender's stable message id — a
                                                        // direct+mailbox duplicate then dedups at the
                                                        // recipient; INSERT OR REPLACE on the same id
                                                        // is idempotent for mailbox retries.
                                                        let msg_id = client_msg_id
                                                            .as_deref()
                                                            .filter(|id| !id.is_empty() && id.len() <= 64)
                                                            .map(|id| id.to_string())
                                                            .unwrap_or_else(crate::p2p::node::P2PNode::generate_mailbox_message_id);
                                                        let expires_at = chrono::Utc::now() + chrono::Duration::days(7);
                                                        let expires_str = expires_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
                                                        match db.store_mailbox_message(&msg_id, &recipient_peer_id, &sender_peer_id, &encrypted_content, &expires_str, &signature).await {
                                                            Ok(_) => {
                                                                log::debug!("Mailbox: stored message {} for {}", msg_id, recipient_peer_id);
                                                                crate::p2p::types::MailboxResponse::Ack { success: true }
                                                            }
                                                            Err(e) => {
                                                                log::error!("Mailbox: failed to store message: {}", e);
                                                                crate::p2p::types::MailboxResponse::Ack { success: false }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            crate::p2p::types::MailboxRequest::Retrieve { recipient_peer_id } => {
                                                // AUTH: only the envelope's recipient may retrieve their mail —
                                                // the swarm peer id is Noise-authenticated, so a mismatched
                                                // request is a theft attempt.
                                                if recipient_peer_id != peer.to_string() {
                                                    log::warn!("Mailbox: rejected Retrieve for {} from {}", recipient_peer_id, peer);
                                                    crate::p2p::types::MailboxResponse::Messages { messages: vec![] }
                                                } else if !self.mailbox_guard.allow_retrieve(&recipient_peer_id) {
                                                    log::warn!("Mailbox: rate-limited Retrieve from {}", peer);
                                                    crate::p2p::types::MailboxResponse::Messages { messages: vec![] }
                                                } else {
                                                    match db.get_mailbox_messages(&recipient_peer_id).await {
                                                        Ok(messages) => {
                                                            log::debug!("Mailbox: retrieved {} messages for {}", messages.len(), recipient_peer_id);
                                                            crate::p2p::types::MailboxResponse::Messages { messages }
                                                        }
                                                        Err(e) => {
                                                            log::error!("Mailbox: failed to retrieve messages: {}", e);
                                                            crate::p2p::types::MailboxResponse::Messages { messages: vec![] }
                                                        }
                                                    }
                                                }
                                            }
                                            crate::p2p::types::MailboxRequest::Delete { message_id } => {
                                                // AUTH: only the envelope's recipient or sender may delete it.
                                                let parties = db.get_mailbox_message_parties(&message_id).await.unwrap_or(None);
                                                let peer_str = peer.to_string();
                                                let allowed = parties
                                                    .map(|(r, s)| r == peer_str || s == peer_str)
                                                    .unwrap_or(false);
                                                if !allowed {
                                                    log::warn!("Mailbox: rejected Delete of {} from {}", message_id, peer);
                                                    crate::p2p::types::MailboxResponse::Ack { success: false }
                                                } else if !self.mailbox_guard.allow_delete(&peer_str) {
                                                    log::warn!("Mailbox: rate-limited Delete from {}", peer);
                                                    crate::p2p::types::MailboxResponse::Ack { success: false }
                                                } else {
                                                    match db.delete_mailbox_message(&message_id).await {
                                                        Ok(_) => {
                                                            log::debug!("Mailbox: deleted message {}", message_id);
                                                            crate::p2p::types::MailboxResponse::Ack { success: true }
                                                        }
                                                        Err(e) => {
                                                            log::error!("Mailbox: failed to delete message: {}", e);
                                                            crate::p2p::types::MailboxResponse::Ack { success: false }
                                                        }
                                                    }
                                                }
                                            }
                                            // META-02: sealed-sender blind box —
                                            // no sender identity exists at all;
                                            // PoW stands in for the signature and
                                            // the box id stands in for the
                                            // recipient.
                                            crate::p2p::types::MailboxRequest::StoreBlind { box_id, sealed, pow_nonce } => {
                                                let peer_str = peer.to_string();
                                                if sealed.len() != crate::security::sealed_sender::SEALED_ENVELOPE_BYTES {
                                                    log::warn!("Mailbox: blind envelope wrong size {} from {}", sealed.len(), peer);
                                                    crate::p2p::types::MailboxResponse::Ack { success: false }
                                                } else if !crate::p2p::blind_box::verify_pow(&box_id, &sealed, pow_nonce) {
                                                    log::warn!("Mailbox: bad PoW on blind Store from {}", peer);
                                                    crate::p2p::types::MailboxResponse::Ack { success: false }
                                                } else if !self.mailbox_guard.allow_store(&peer_str) {
                                                    log::warn!("Mailbox: rate-limited blind Store from {}", peer);
                                                    crate::p2p::types::MailboxResponse::Ack { success: false }
                                                } else {
                                                    let total = db.get_mailbox_message_count(&box_id).await.unwrap_or(0);
                                                    if total >= crate::p2p::mailbox_guard::MAX_PER_RECIPIENT {
                                                        log::warn!("Mailbox: blind box quota exceeded");
                                                        crate::p2p::types::MailboxResponse::Ack { success: false }
                                                    } else {
                                                        let msg_id = crate::p2p::node::P2PNode::generate_mailbox_message_id();
                                                        let expires_at = chrono::Utc::now() + chrono::Duration::days(7);
                                                        let expires_str = expires_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
                                                        match db.store_mailbox_message(&msg_id, &box_id, "sealed", &sealed, &expires_str, &[]).await {
                                                            Ok(_) => crate::p2p::types::MailboxResponse::Ack { success: true },
                                                            Err(e) => {
                                                                log::error!("Mailbox: blind store failed: {}", e);
                                                                crate::p2p::types::MailboxResponse::Ack { success: false }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            crate::p2p::types::MailboxRequest::RetrieveBlind { box_id, pub_key, day, signature } => {
                                                let payload = crate::p2p::blind_box::retrieve_signing_payload(&box_id, day);
                                                if !crate::p2p::blind_box::verify_ownership(&box_id, &pub_key, day, &payload, &signature) {
                                                    log::warn!("Mailbox: rejected RetrieveBlind from {}", peer);
                                                    crate::p2p::types::MailboxResponse::Messages { messages: vec![] }
                                                } else if !self.mailbox_guard.allow_retrieve(&box_id) {
                                                    log::warn!("Mailbox: rate-limited RetrieveBlind from {}", peer);
                                                    crate::p2p::types::MailboxResponse::Messages { messages: vec![] }
                                                } else {
                                                    match db.get_mailbox_messages(&box_id).await {
                                                        Ok(messages) => crate::p2p::types::MailboxResponse::Messages { messages },
                                                        Err(e) => {
                                                            log::error!("Mailbox: blind retrieve failed: {}", e);
                                                            crate::p2p::types::MailboxResponse::Messages { messages: vec![] }
                                                        }
                                                    }
                                                }
                                            }
                                            crate::p2p::types::MailboxRequest::DeleteBlind { box_id, message_id, pub_key, day, signature } => {
                                                let payload = crate::p2p::blind_box::delete_signing_payload(&box_id, &message_id, day);
                                                let peer_str = peer.to_string();
                                                let parties = db.get_mailbox_message_parties(&message_id).await.unwrap_or(None);
                                                let item_ok = parties.map(|(r, s)| r == box_id && s == "sealed").unwrap_or(false);
                                                if !item_ok
                                                    || !crate::p2p::blind_box::verify_ownership(&box_id, &pub_key, day, &payload, &signature)
                                                {
                                                    log::warn!("Mailbox: rejected DeleteBlind of {} from {}", message_id, peer);
                                                    crate::p2p::types::MailboxResponse::Ack { success: false }
                                                } else if !self.mailbox_guard.allow_delete(&peer_str) {
                                                    crate::p2p::types::MailboxResponse::Ack { success: false }
                                                } else {
                                                    match db.delete_mailbox_message(&message_id).await {
                                                        Ok(_) => crate::p2p::types::MailboxResponse::Ack { success: true },
                                                        Err(e) => {
                                                            log::error!("Mailbox: blind delete failed: {}", e);
                                                            crate::p2p::types::MailboxResponse::Ack { success: false }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    None => {
                                        log::error!("Mailbox: database not initialized");
                                        crate::p2p::types::MailboxResponse::Ack { success: false }
                                    }
                                }
                            }
                            None => {
                                log::error!("Mailbox: no database available");
                                crate::p2p::types::MailboxResponse::Ack { success: false }
                            }
                        };
                        let _ = self.swarm.behaviour_mut().mailbox.send_response(channel, response);
                    }
                    // Phase B.2: Mailbox protocol — handle incoming mailbox responses
                    SwarmEvent::Behaviour(NoidBehaviourEvent::Mailbox(request_response::Event::Message {
                        peer,
                        connection_id: _,
                        message: request_response::Message::Response { request_id, response },
                    })) => {
                        match response {
                            crate::p2p::types::MailboxResponse::Ack { success } => {
                                log::debug!("Mailbox store ack: success={}", success);
                                // Correlate back to the pending row — it is
                                // deleted by the forwarder only now, on a
                                // real store confirmation.
                                let (message_id, recipient_peer_id) = self
                                    .pending_mailbox_sends
                                    .remove(&request_id.to_string())
                                    .unwrap_or((None, String::new()));
                                let _ = emit_ev(ctx.event_tx, P2PEvent::MailboxStoreAck {
                                    success,
                                    message_id,
                                    recipient_peer_id,
                                }).await;
                            }
                            crate::p2p::types::MailboxResponse::Messages { messages } => {
                                log::debug!("Retrieved {} messages from mailbox", messages.len());
                                let _ = emit_ev(ctx.event_tx, P2PEvent::MailboxMessagesRetrieved {
                                    mailbox_peer_id: peer.to_string(),
                                    messages,
                                }).await;
                            }
                        }
                    }
                    // Phase B.2: Mailbox protocol — handle outbound failures
                    SwarmEvent::Behaviour(NoidBehaviourEvent::Mailbox(request_response::Event::OutboundFailure {
                        peer,
                        connection_id: _,
                        request_id,
                        error,
                    })) => {
                        log::debug!("Mailbox outbound failure to {}: {}", peer, error);
                        // F7: timeout flags conns for ping-reap instead of
                        // disconnect_peer_id — the reservation conn survives.
                        // Same rule as the chat path: only non-QUIC conns —
                        // a zombie TCP/WS flow is the timeout suspect, QUIC
                        // survives NAT rebinding.
                        if matches!(error, request_response::OutboundFailure::Timeout) {
                            // Same relayed-conn exemption as the chat path
                            // (EL-07) — a circuit must not be reaped for a
                            // mailbox-store timeout that rode the relay hop.
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
                        // Report the failed store so the pending row stays
                        // and the periodic retry can attempt delivery again.
                        let (message_id, recipient_peer_id) = self
                            .pending_mailbox_sends
                            .remove(&request_id.to_string())
                            .unwrap_or((None, String::new()));
                        let _ = emit_ev(ctx.event_tx, P2PEvent::MailboxStoreAck {
                            success: false,
                            message_id,
                            recipient_peer_id,
                        }).await;
                        let _ = emit_ev(ctx.event_tx, P2PEvent::MailboxError {
                            error: format!("Mailbox error: {}", error),
                        }).await;
                    }
                    // META-05: /noid-hop/1.0.0 — onion-style forwarding.
            ev => return self.on_hop_event(ev, ctx).await,
        }
        LoopCtl::Keep
    }
}
