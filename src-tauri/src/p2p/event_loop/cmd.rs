//! P2PCommand dispatch — extracted from the event_loop megaloop (Q04/A5).
//! Behaviour-preserving move only.

use super::*;

impl P2PNode {
    pub(crate) async fn on_command(
        &mut self,
        command: P2PCommand,
        ctx: &LoopCtx<'_>,
    ) -> LoopCtl {
        match command {
                            P2PCommand::Shutdown => {
                                // RC9: app exit — persist discovered peers
                                // unconditionally (the 30s dirty-flush tick
                                // won't fire again), close every connection
                                // (libp2p 0.54 has no swarm.close()), and drop
                                // the swarm cleanly instead of aborting mid-poll.
                                self.peer_cache.save(
                                    &self.data_dir.clone(),
                                    self.field_cipher.as_deref(),
                                );
                                self.peer_cache_dirty = false;
                                for peer in self.swarm.connected_peers().cloned().collect::<Vec<_>>() {
                                    let _ = self.swarm.disconnect_peer_id(peer);
                                }
                                log::info!("P2P node shutting down (Shutdown command)");
                                return LoopCtl::Exit;
                            }
                            P2PCommand::NetworkChanged => {
                                // B5: ConnectivityManager can flap several
                                // times a minute — each run drops every
                                // external addr and non-QUIC conn, so bursts
                                // are coalesced: within the window just mark
                                // a pending run and let the debounce tick
                                // fire the real handler once.
                                const NETCHANGE_DEBOUNCE: std::time::Duration =
                                    std::time::Duration::from_secs(5);
                                if self
                                    .last_network_change
                                    .is_some_and(|t| t.elapsed() < NETCHANGE_DEBOUNCE)
                                {
                                    self.pending_network_change = true;
                                } else {
                                    self.last_network_change =
                                        Some(std::time::Instant::now());
                                    self.on_network_changed();
                                }
                            }
                            P2PCommand::SendMessage { peer_id, msg } => {
                                if let Ok(peer) = peer_id.parse::<libp2p::PeerId>() {
                                    if peer != *self.swarm.local_peer_id() {
                                        log::info!(
                                            "SendMessage → {} (type={:?}, connected={})",
                                            peer,
                                            std::mem::discriminant(&msg.msg_type),
                                            self.connected_peers.contains(&peer)
                                        );
                                        // Outbound activity keeps the
                                        // contact's idle window open.
                                        self.contact_idle_since
                                            .insert(peer, tokio::time::Instant::now());
                                        self.send_request(peer, msg, ctx.event_tx).await;
                                    }
                                }
                            }
                            P2PCommand::SetConnectivityConfig { config } => {
                                log::info!(
                                    "Connectivity policy updated: on_demand={}, idle_ttl={}s, poll={}s",
                                    config.on_demand,
                                    config.idle_conn_ttl_secs,
                                    config.mailbox_poll_secs
                                );
                                self.connectivity_config = config;
                            }
                            P2PCommand::SetHopRelays { relays } => {
                                log::info!("Hop relay chain updated: {} relays", relays.len());
                                self.relay_config.hop_relays = relays;
                            }
                            P2PCommand::ConnectToPeer { peer_id, addr_hint } => {
                                if let Ok(peer) = peer_id.parse::<libp2p::PeerId>() {
                                    if self.connected_peers.contains(&peer) {
                                        return LoopCtl::Keep;
                                    }
                                    // Explicit intent (send, add-contact,
                                    // manual reconnect) — a peer that just
                                    // came online must be reachable even
                                    // inside an old backoff window. Automatic
                                    // retry paths don't issue this command.
                                    self.clear_dial_backoff(&peer);
                                    if let Some(addr_str) = addr_hint {
                                        if let Ok(addr) = addr_str.parse::<libp2p::Multiaddr>() {
                                            log::debug!("Dialing peer {} with addr hint: {}", peer, addr);
                                            self.allowed_dial_addrs.insert(addr.clone());
                                            // Feed the hint into the address
                                            // books too — a SendMessage queued
                                            // right behind this command must
                                            // be able to dial the peer itself
                                            // if our manual dial hasn't
                                            // completed yet.
                                            self.register_peer_addr(peer, addr.clone(), "command", true);
                                            self.assist_cgnat_dial(&addr, ctx.rv_tx);
                                            let _ = self.dial(addr).await;
                                        }
                                    } else {
                                        self.seed_peer_addrs(&peer);
                                        for cached in self.peer_cache.addrs_of(&peer) {
                                            let full_addr = match cached.iter().last() {
                                                Some(libp2p::multiaddr::Protocol::P2p(id)) if id == peer => cached,
                                                Some(libp2p::multiaddr::Protocol::P2p(_)) => continue,
                                                _ => cached.with(libp2p::multiaddr::Protocol::P2p(peer)),
                                            };
                                            let _ = self.dial(full_addr).await;
                                        }
                                        // No addr hint — use Kademlia to find peer's address
                                        log::debug!("Looking up peer {} via Kademlia DHT", peer);
                                        // DB31: bound in-flight dials — a
                                        // command flood must not pile up
                                        // unbounded query bookkeeping.
                                        if self.pending_dials.len() >= 256 {
                                            log::warn!("pending_dials full — dropping lookup for {}", peer);
                                            return LoopCtl::Keep;
                                        }
                                        let query_id = self.swarm.behaviour_mut().kademlia.get_closest_peers(peer);
                                        self.pending_dials.insert(query_id, peer);
                                    }
                                }
                            }
                            P2PCommand::DialAddress { addr, rv } => {
                                if let Ok(addr) = addr.parse::<libp2p::Multiaddr>() {
                                    // The TARGET is the terminal /p2p/ id —
                                    // for `…/p2p/<relay>/p2p-circuit/p2p/<target>`
                                    // the first id is the relay; registering
                                    // the addr under it is dropped as Malformed
                                    // and the target never gets a dialable
                                    // address (invite flow was dead on
                                    // circuit-only invites).
                                    if let Some(peer) = crate::p2p::terminal_peer_id::terminal_peer_id(&addr) {
                                        if let Some(secret) = &rv {
                                            self.pending_rv.insert(peer, secret.clone());
                                        }
                                        self.register_peer_addr(peer, addr.clone(), "command", true);
                                        // Manual dial = user intent — an old
                                        // backoff window must not suppress it.
                                        self.clear_dial_backoff(&peer);
                                    }
                                    // User explicitly provided this address —
                                    // allowed even under RelayedOnly.
                                    self.allowed_dial_addrs.insert(addr.clone());
                                    self.assist_cgnat_dial(&addr, ctx.rv_tx);
                                    let _ = self.dial(addr).await;
                                } else {
                                    log::warn!("DialAddress: invalid multiaddr {}", addr);
                                }
                            }
                            P2PCommand::SendPublicKey { peer_id } => {
                                if let Ok(peer) = peer_id.parse::<libp2p::PeerId>() {
                                    let _ = self.send_public_key(peer, ctx.event_tx).await;
                                }
                            }
                            P2PCommand::AckReceived { peer_id, message_id, status } => {
                                // TI-1: the app layer finished durable
                                // processing — answer the parked channel and
                                // record the id so transport retries dedup.
                                if let Some((channel, _)) = self
                                    .pending_app_acks
                                    .remove(&(peer_id.clone(), message_id.clone()))
                                {
                                    // EL-05: mark the id seen ONLY once the
                                    // ack actually left — a failed
                                    // send_response (conn died between park
                                    // and ack) used to still mark the id, so
                                    // the sender's transport retry deduped
                                    // as "already processed" and the message
                                    // vanished without ever being acked.
                                    if let Err(e) = self
                                        .swarm
                                        .behaviour_mut()
                                        .request_response
                                        .send_response(
                                            channel,
                                            crate::p2p::types::NoidResponse {
                                                status,
                                                data: None,
                                            },
                                        )
                                    {
                                        log::warn!("Failed to send app-ack to {}: {:?}", peer_id, e);
                                    } else {
                                        self.mark_seen(&format!("{}:{}", peer_id, message_id));
                                    }
                                } else {
                                    log::debug!(
                                        "App-ack for {} from {} — no parked channel (timed out?)",
                                        message_id, peer_id
                                    );
                                }
                            }
                            P2PCommand::SetRendezvousSecret { secret } => {
                                // Ring of recently-issued secrets: an invite
                                // copied a minute ago must keep working while
                                // the UI already displays the next one.
                                const MAX_RV_SECRETS: usize = 8;
                                const RV_TTL: std::time::Duration =
                                    std::time::Duration::from_secs(1800);
                                self.rv_secrets
                                    .retain(|(_, ts)| ts.elapsed() < RV_TTL);
                                if let Some(entry) = self
                                    .rv_secrets
                                    .iter_mut()
                                    .find(|(s, _)| *s == secret)
                                {
                                    entry.1 = std::time::Instant::now();
                                } else {
                                    self.rv_secrets.push_front((
                                        secret,
                                        std::time::Instant::now(),
                                    ));
                                    while self.rv_secrets.len() > MAX_RV_SECRETS {
                                        self.rv_secrets.pop_back();
                                    }
                                }
                            }
                            P2PCommand::SetContacts { peer_ids } => {
                                let peers: std::collections::HashSet<PeerId> = peer_ids
                                    .iter()
                                    .filter_map(|s| s.parse().ok())
                                    .collect();
                                // A peer that became a contact while already
                                // connected must receive our signed endpoint
                                // advertisement NOW — otherwise it never
                                // learns our onion/external addrs (the
                                // advertise arm only fires on connect).
                                let added: Vec<PeerId> = peers
                                    .difference(&self.contact_peers)
                                    .copied()
                                    .collect();
                                self.set_contact_peers(peers.clone());
                                for p in added {
                                    if self.connected_peers.contains(&p) {
                                        self.send_endpoint_advertise(&p);
                                    }
                                }
                                // rv v2: restore contact pubkeys from the DB
                                // (the in-memory map dies with the node, but
                                // the exchanged keys persist) so the daily
                                // rendezvous slots are computable right after
                                // a restart, before any re-exchange.
                                if let Some(db) = &self.db {
                                    let db = db.clone();
                                    let mut peers_iter = peers.into_iter();
                                    for peer in std::iter::from_fn(|| peers_iter.next()) {
                                        let db = db.clone();
                                        let key_bytes = {
                                            let g = db.lock().await;
                                            match g.as_ref() {
                                                Some(d) => d
                                                    .get_contact_public_key(
                                                        &peer.to_string(),
                                                    )
                                                    .await
                                                    .ok()
                                                    .flatten(),
                                                None => None,
                                            }
                                        };
                                        if let Some(kb) = key_bytes {
                                            if let Ok(arr) = <[u8; 32]>::try_from(kb.as_slice()) {
                                                self.peer_pubkeys.insert(peer, arr);
                                            }
                                        }
                                    }
                                }
                            }
                            P2PCommand::JoinRoom { room_id, room_key } => {
                                match self.join_room(&room_id, room_key) {
                                    Ok(_) => log::debug!("Joined room: {}", room_id),
                                    Err(e) => log::error!("Failed to join room {}: {}", room_id, e),
                                }
                            }
                            P2PCommand::SendRoomMessage { room_id, content } => {
                                match self.send_room_message(&room_id, &content) {
                                    Ok(_) => log::debug!("Sent room message to: {}", room_id),
                                    Err(e) => log::error!("Failed to send room message to {}: {}", room_id, e),
                                }
                            }
                            P2PCommand::SendRoomPayload { room_id, payload } => {
                                match self.send_room_payload(&room_id, &payload) {
                                    Ok(_) => log::debug!("Sent room control to: {}", room_id),
                                    Err(e) => log::error!("Failed to send room control to {}: {}", room_id, e),
                                }
                            }
                            P2PCommand::SendRoomChat { room_id, content, respond_to } => {
                                let _ = respond_to.send(
                                    self.send_room_chat_envelope(&room_id, &content)
                                        .map_err(|e| e.to_string()),
                                );
                            }
                            P2PCommand::UpdateRoomKey { room_id, room_key } => {
                                self.update_room_key(&room_id, room_key);
                                log::debug!("Room key rotated for {}", room_id);
                            }
                            P2PCommand::LeaveRoom { room_id } => {
                                self.leave_room(&room_id);
                                log::debug!("Left room {}", room_id);
                            }
                            P2PCommand::PublishUsername { username, record } => {
                                match self.publish_username(&username, &record) {
                                    // D14: Ok means the get-before-put gate
                                    // query was issued — the verdict event
                                    // is emitted on query resolution.
                                    Ok(_) => {
                                        log::info!("Username '{}' publish gated on availability query", username);
                                    }
                                    Err(e) => {
                                        log::error!("Failed to publish username '{}': {}", username, e);
                                        let _ = emit_ev(ctx.event_tx, P2PEvent::UsernameAvailabilityChecked {
                                            username: username.clone(),
                                            available: false,
                                            uncertain: false,
                                        }).await;
                                    }
                                }
                            }
                            P2PCommand::CheckUsernameAvailability { username } => {
                                self.check_username_availability(&username);
                            }
                            P2PCommand::LookupUser { username } => {
                                self.lookup_user(&username);
                            }
                            P2PCommand::UnpublishUsername { username } => {
                                match self.unpublish_username(&username) {
                                    Ok(_) => log::debug!("Username '{}' unpublished", username),
                                    Err(e) => log::error!("Failed to unpublish username '{}': {}", username, e),
                                }
                            }
                            P2PCommand::PublishPrekeyBundle { peer_id, bundle } => {
                                match self.publish_prekey_bundle(&peer_id, &bundle) {
                                    Ok(_) => log::info!("Prekey bundle publish issued to DHT for {}", peer_id),
                                    Err(e) => log::error!("Failed to publish prekey bundle: {}", e),
                                }
                            }
                            P2PCommand::FetchPrekeyBundle { peer_id } => {
                                self.fetch_prekey_bundle(&peer_id);
                            }
                            P2PCommand::SeedPeerAddr { peer_id, addr } => {
                                match (peer_id.parse::<libp2p::PeerId>(), addr.parse::<libp2p::Multiaddr>()) {
                                    (Ok(peer), Ok(addr)) => {
                                        self.register_peer_addr(peer, addr, "mailbox-record", true);
                                    }
                                    _ => log::warn!("SeedPeerAddr: bad peer/addr for {}", peer_id),
                                }
                            }
                            P2PCommand::SendToMailbox { mailbox_peer_id, recipient_peer_id, sender_peer_id, encrypted_content, client_msg_id } => {
                                // F12: an oversized envelope can NEVER be
                                // stored — tell the app to drop the pending
                                // row instead of retrying it forever.
                                if !crate::p2p::mailbox_guard::MailboxGuard::envelope_size_ok(&encrypted_content) {
                                    let _ = emit_ev(ctx.event_tx, P2PEvent::PendingUndeliverable {
                                        peer_id: recipient_peer_id,
                                        message_id: client_msg_id,
                                        reason: "envelope exceeds mailbox size limit".into(),
                                    }).await;
                                    return LoopCtl::Keep;
                                }
                                match self.send_to_mailbox(&mailbox_peer_id, &recipient_peer_id, &sender_peer_id, encrypted_content, client_msg_id) {
                                    Ok(_) => log::debug!("Message sent to mailbox {}", mailbox_peer_id),
                                    Err(e) => log::error!("Failed to send to mailbox: {}", e),
                                }
                            }
                            P2PCommand::RetrieveFromMailbox { mailbox_peer_id, recipient_peer_id } => {
                                match self.retrieve_from_mailbox(&mailbox_peer_id, &recipient_peer_id) {
                                    Ok(_) => log::debug!("Retrieving from mailbox {}", mailbox_peer_id),
                                    Err(e) => log::error!("Failed to retrieve from mailbox: {}", e),
                                }
                            }
                            P2PCommand::AckMailboxMessage { mailbox_peer_id, message_id } => {
                                match self.ack_mailbox_message(&mailbox_peer_id, &message_id) {
                                    Ok(_) => log::debug!("Acking message {} at mailbox {}", message_id, mailbox_peer_id),
                                    Err(e) => log::error!("Failed to ack mailbox message: {}", e),
                                }
                            }
            c => return self.on_command_tail(c, ctx).await,
        }
        LoopCtl::Keep
    }
}
