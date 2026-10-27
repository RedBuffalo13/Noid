use libp2p::futures::StreamExt;
use libp2p::swarm::SwarmEvent;
use libp2p::{autonat, gossipsub, identify, kad, mdns, ping, relay, request_response, upnp, Multiaddr, PeerId};
use sha2::Digest;
use tokio::sync::mpsc;

use crate::p2p::behaviour::NoidBehaviourEvent;
use crate::p2p::node::P2PNode;
use crate::p2p::relay_status::NatStatus;
use crate::p2p::types::{DHTUserRecord, P2PCommand, P2PEvent};

/// Bounded event send (F5/RC3): `send().await?` on the bounded forwarder
/// channel used to kill the whole event loop when the channel filled or the
/// forwarder died — and a permanently blocked send deadlocked the
/// cmd-channel drain (circular wait). A full channel now waits up to 5s
/// then drops the event (delivery-critical events self-heal via
/// pending/mailbox retry); a closed channel stops the node gracefully.
pub(crate) async fn emit_ev(event_tx: &mpsc::Sender<P2PEvent>, ev: P2PEvent) -> bool {
    match tokio::time::timeout(std::time::Duration::from_secs(5), event_tx.send(ev)).await {
        Ok(Ok(())) => true,
        Ok(Err(_)) => {
            log::error!("P2P event channel closed — stopping node");
            false
        }
        Err(_) => {
            log::warn!("P2P event channel blocked >5s — dropping event");
            true
        }
    }
}

impl P2PNode {
    pub async fn run(
        mut self,
        event_tx: mpsc::Sender<P2PEvent>,
        mut cmd_rx: mpsc::Receiver<P2PCommand>,
    ) -> anyhow::Result<()> {
        // Phase J.1: Periodic cleanup of expired mailbox messages (every hour)
        let mut mailbox_cleanup_interval = tokio::time::interval(tokio::time::Duration::from_secs(3600));
        // Relay maintenance: renew reservations (~30min), re-discover relays.
        let mut relay_maintain_interval = tokio::time::interval(tokio::time::Duration::from_secs(600));
        // Peer cache flush must not wait for the 10-min maintenance tick —
        // a short session (connect, chat a minute, quit) would otherwise
        // never persist discovered peers and the next start is cold again.
        let mut peer_cache_flush = tokio::time::interval(tokio::time::Duration::from_secs(30));
        // UI status heartbeat: events-only reporting left the panel frozen on
        // the default snapshot whenever a listener missed the early emits.
        let mut status_tick = tokio::time::interval(tokio::time::Duration::from_secs(10));
        // Pinned seed dials behind a shared port randomly land on the wrong
        // peer — bootstrap() never retries, so do it here until connected.
        let mut bootstrap_retry_interval =
            tokio::time::interval(tokio::time::Duration::from_secs(30));

        loop {
            tokio::select! {
                _ = relay_maintain_interval.tick() => {
                    // Renew circuit reservations before they expire (~1h TTL)
                    self.refresh_reservations();
                    // DHT work is pointless with zero connections — every
                    // query only churns the routing table into internal dials
                    // that all fail. Wait for the first connection (bootstrap,
                    // cached relay, or mDNS peer).
                    if self.connected_peers.is_empty() {
                        continue;
                    }
                    // Keep looking for relays until we have a few options.
                    // D5: known_relays holds (peer, addr) pairs — count
                    // distinct peers, not addresses (bundled seeds carry
                    // 5 addrs for 2 peers).
                    {
                        let distinct: std::collections::HashSet<_> =
                            self.known_relays.iter().map(|(p, _)| *p).collect();
                        if distinct.len() < 3 {
                            self.discover_relays();
                        }
                    }
                    // (Re-)announce ourselves as relay provider when reachable
                    if self.should_relay() && !self.relay_provider_announced {
                        self.advertise_as_relay();
                    }
                    // Random Kademlia walk: refreshes the routing table and
                    // pulls in peers from any "circles" that bridged into ours.
                    let _ = self
                        .swarm
                        .behaviour_mut()
                        .kademlia
                        .get_closest_peers(libp2p::PeerId::random());
                }
                _ = status_tick.tick() => {
                    // F8: close conns whose grace period expired — but
                    // revalidate first (EL-04): during the 20s window the
                    // surviving sibling conn may have died, making the
                    // scheduled conn the LAST path to its peer. Closing it
                    // anyway strands the peer until redial.
                    let now = tokio::time::Instant::now();
                    let (due, pending): (Vec<_>, Vec<_>) = std::mem::take(&mut self.pending_conn_close)
                        .into_iter()
                        .partition(|(deadline, _, _)| *deadline <= now);
                    self.pending_conn_close = pending;
                    for (_, peer, id) in due {
                        let live = self
                            .conn_quic
                            .get(&peer)
                            .map(|m| m.len())
                            .unwrap_or(0);
                        // Known relays are exempt from the last-conn
                        // protection: a leftover RELAYED conn to a relay
                        // actively harms it (reservation renewals dedup
                        // onto the circuit → nested). Killing it forces
                        // the clean direct redial the relay needs.
                        // The exemption is scoped to relays WE RESERVE ON —
                        // a contact mis-registered as a relay candidate
                        // (HOP protocol + private addr) must keep the
                        // last-conn protection so a scheduled close can
                        // never strand it (TR-01).
                        let is_reserved_relay = self.reserved_relays.contains(&peer);
                        if live <= 1 && !is_reserved_relay {
                            log::debug!(
                                "Canceling scheduled close of {:?} to {} — last live conn",
                                id, peer
                            );
                            continue;
                        }
                        let _ = self.swarm.close_connection(id);
                    }
                    // EL-09: pending_app_acks was swept only on insert —
                    // a quiet session let stale channels pile up past the
                    // sender's timeout forever. Sweep on the status tick too.
                    {
                        let cutoff = std::time::Instant::now()
                            - std::time::Duration::from_secs(30);
                        self.pending_app_acks
                            .retain(|_, (_, parked_at)| *parked_at > cutoff);
                    }
                    // DHT-02: flush records whose put_record was refused
                    // synchronously at cold start (empty routing table).
                    self.drain_deferred_dht_puts();
                    let _ = emit_ev(&event_tx, P2PEvent::RelayStatusChanged {
                        status: self.relay_status(),
                    }).await;
                }
                _ = bootstrap_retry_interval.tick() => {
                    self.retry_bootstrap_dials();
                }
                _ = peer_cache_flush.tick() => {
                    if self.peer_cache_dirty {
                        self.peer_cache
                            .save(&self.data_dir.clone(), self.field_cipher.as_deref());
                        self.peer_cache_dirty = false;
                    }
                }
                _ = mailbox_cleanup_interval.tick() => {
                    // Phase J.1: Clean up expired mailbox messages from local storage
                    if let Some(ref db) = self.db {
                        let db_guard = db.lock().await;
                        if let Some(ref db) = *db_guard {
                            match db.cleanup_expired_mailbox().await {
                                Ok(n) => {
                                    if n > 0 {
                                        log::debug!("Cleaned up {} expired mailbox messages", n);
                                    }
                                }
                                Err(e) => log::error!("Mailbox cleanup failed: {}", e),
                            }
                        }
                    }
                }
                cmd = cmd_rx.recv() => {
                    if let Some(command) = cmd {
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
                                return Ok(());
                            }
                            P2PCommand::NetworkChanged => {
                                // EL-01: the interface that owned every
                                // addr and socket just died (Wi-Fi ↔ LTE,
                                // Doze wake, VPN switch). On Android the old
                                // TCP/WS sockets stay ESTABLISHED-but-dead
                                // for ~60s — outbound requests routed onto
                                // them burn full timeouts while the swarm
                                // still reports the peer "connected".
                                //
                                // 1) All external addrs are stale — direct
                                //    ones were bound to the dead interface,
                                //    relayed ones rode reservations on conns
                                //    that are dying too.
                                let stale: Vec<Multiaddr> = self.external_addrs.to_vec();
                                for addr in &stale {
                                    self.swarm.remove_external_address(addr);
                                }
                                self.external_addrs.clear();
                                // 2) Reservation bookkeeping belonged to the
                                //    dead interface — clearing it lets
                                //    refresh_reservations re-issue RESERVE
                                //    instead of skipping a phantom
                                //    "still held" reservation (the listener
                                //    on the dead conn never revives).
                                self.reserved_relays.clear();
                                self.pending_reservations.clear();
                                self.reservation_denied.clear();
                                self.relayed_addrs.clear();
                                self.relayed_listener_refs.clear();
                                self.mailbox_record_peer = None;
                                // 3) Backoffs / dead-addr marks observed on
                                //    the dead network would suppress redials
                                //    on the new one — clear them all.
                                self.dial_backoffs.clear();
                                self.addr_failures.clear();
                                self.dead_addrs.clear();
                                self.ping_failures.clear();
                                self.bootstrap_retry_state.clear();
                                // 4) Close connections that cannot migrate:
                                //    TCP/WS sockets bound to the dead
                                //    interface are zombies. QUIC keeps its
                                //    conn-ID migration path — if migration
                                //    fails, ping failure handling reaps it
                                //    within ~30s anyway.
                                let zombie: Vec<libp2p::swarm::ConnectionId> = self
                                    .conn_quic
                                    .values()
                                    .flat_map(|m| m.iter())
                                    .filter(|(_, quic)| !**quic)
                                    .map(|(id, _)| *id)
                                    .collect();
                                for id in &zombie {
                                    let _ = self.swarm.close_connection(*id);
                                }
                                log::info!(
                                    "Network changed — dropped {} stale external addr(s), closing {} non-QUIC conn(s)",
                                    stale.len(),
                                    zombie.len()
                                );
                                // 5) Re-dial bootstrap seeds immediately so
                                //    the relay book refills on the new
                                //    interface; then re-reserve and
                                //    re-discover (each accepted reservation
                                //    republishes the mailbox record, A7).
                                self.retry_bootstrap_dials();
                                self.refresh_reservations();
                                self.discover_relays();
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
                                        self.send_request(peer, msg, &event_tx).await;
                                    }
                                }
                            }
                            P2PCommand::ConnectToPeer { peer_id, addr_hint } => {
                                if let Ok(peer) = peer_id.parse::<libp2p::PeerId>() {
                                    if self.connected_peers.contains(&peer) {
                                        continue;
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
                                            let _ = self.dial(addr).await;
                                        }
                                    } else {
                                        // No addr hint — use Kademlia to find peer's address
                                        log::debug!("Looking up peer {} via Kademlia DHT", peer);
                                        // DB31: bound in-flight dials — a
                                        // command flood must not pile up
                                        // unbounded query bookkeeping.
                                        if self.pending_dials.len() >= 256 {
                                            log::warn!("pending_dials full — dropping lookup for {}", peer);
                                            continue;
                                        }
                                        let query_id = self.swarm.behaviour_mut().kademlia.get_closest_peers(peer);
                                        self.pending_dials.insert(query_id, peer);
                                    }
                                }
                            }
                            P2PCommand::DialAddress { addr } => {
                                if let Ok(addr) = addr.parse::<libp2p::Multiaddr>() {
                                    // The TARGET is the terminal /p2p/ id —
                                    // for `…/p2p/<relay>/p2p-circuit/p2p/<target>`
                                    // the first id is the relay; registering
                                    // the addr under it is dropped as Malformed
                                    // and the target never gets a dialable
                                    // address (invite flow was dead on
                                    // circuit-only invites).
                                    if let Some(peer) = crate::p2p::terminal_peer_id::terminal_peer_id(&addr) {
                                        self.register_peer_addr(peer, addr.clone(), "command", true);
                                        // Manual dial = user intent — an old
                                        // backoff window must not suppress it.
                                        self.clear_dial_backoff(&peer);
                                    }
                                    // User explicitly provided this address —
                                    // allowed even under RelayedOnly.
                                    self.allowed_dial_addrs.insert(addr.clone());
                                    let _ = self.dial(addr).await;
                                } else {
                                    log::warn!("DialAddress: invalid multiaddr {}", addr);
                                }
                            }
                            P2PCommand::SendPublicKey { peer_id } => {
                                if let Ok(peer) = peer_id.parse::<libp2p::PeerId>() {
                                    let _ = self.send_public_key(peer, &event_tx).await;
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
                                        let _ = emit_ev(&event_tx, P2PEvent::UsernameAvailabilityChecked {
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
                                    let _ = emit_ev(&event_tx, P2PEvent::PendingUndeliverable {
                                        peer_id: recipient_peer_id,
                                        message_id: client_msg_id,
                                        reason: "envelope exceeds mailbox size limit".into(),
                                    }).await;
                                    continue;
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
                            P2PCommand::RegisterAsMailbox { peer_id, mailbox_peer_id, relay_addr } => {
                                match self.register_as_mailbox(&peer_id, &mailbox_peer_id, &relay_addr) {
                                    Ok(_) => log::debug!("Registered mailbox node"),
                                    Err(e) => log::error!("Failed to register mailbox: {}", e),
                                }
                            }
                            P2PCommand::FindMailboxNode { peer_id } => {
                                // D19: serve fresh resolutions from cache —
                                // the 15s retry tick used to fire a full
                                // DHT query per offline peer every cycle.
                                let cached = self
                                    .mailbox_cache
                                    .get(&peer_id)
                                    .filter(|(_, _, ts)| ts.elapsed() < std::time::Duration::from_secs(600))
                                    .map(|(mp, ra, _)| (mp.clone(), ra.clone()));
                                if let Some((mailbox_peer_id, relay_addr)) = cached {
                                    let _ = emit_ev(&event_tx, P2PEvent::MailboxNodeFound {
                                        peer_id: peer_id.clone(),
                                        mailbox_peer_id,
                                        relay_addr,
                                    }).await;
                                    continue;
                                }
                                // D11: when resolving our OWN mailbox, drain
                                // the history too — envelopes parked on a
                                // superseded node are invisible to the
                                // current record but still within their TTL.
                                if peer_id == self.peer_id.to_string() {
                                    let history = self.mailbox_history.clone();
                                    for (mailbox_peer_id, relay_addr, _) in history {
                                        let _ = emit_ev(&event_tx, P2PEvent::MailboxNodeFound {
                                            peer_id: peer_id.clone(),
                                            mailbox_peer_id,
                                            relay_addr,
                                        }).await;
                                    }
                                }
                                // Single-flight: a pending lookup for this
                                // peer makes a second query redundant.
                                if self.pending_mailbox_lookups.values().any(|p| *p == peer_id) {
                                    continue;
                                }
                                // DB31: bound in-flight mailbox lookups.
                                if self.pending_mailbox_lookups.len() >= 256 {
                                    log::warn!("pending_mailbox_lookups full — dropping lookup for {}", peer_id);
                                    continue;
                                }
                                let query_id = self.find_mailbox_node(&peer_id);
                                self.pending_mailbox_lookups.insert(query_id, peer_id);
                            }
                            P2PCommand::DiscoverRelays => {
                                self.discover_relays();
                            }
                            P2PCommand::RequestReservation { relay_peer_id, relay_addr } => {
                                match (relay_peer_id.parse::<libp2p::PeerId>(), relay_addr.parse::<libp2p::Multiaddr>()) {
                                    (Ok(peer), Ok(addr)) => self.request_reservation(peer, &addr),
                                    _ => log::warn!("RequestReservation: invalid peer_id or addr"),
                                }
                            }
                            P2PCommand::RefreshReservations => {
                                self.refresh_reservations();
                            }
                            P2PCommand::ReportRelayStatus { respond_to } => {
                                let status = self.relay_status();
                                let _ = respond_to.send(status.clone());
                                let _ = emit_ev(&event_tx, P2PEvent::RelayStatusChanged {
                                    status,
                                }).await;
                            }
                        }
                    } else {
                        // Phase 1.9: cmd channel closed — terminate event loop cleanly
                        // instead of busy-looping forever.
                        log::debug!("P2P command channel closed, shutting down event loop");
                        break Ok(());
                    }
                }

                event = self.swarm.select_next_some() => match event {
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
                        if !emit_ev(&event_tx, P2PEvent::NewListenAddr(address.to_string())).await { return Ok(()); }
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
                        if endpoint.is_relayed() {
                            // Track first, decide second: close_connection is
                            // async — until ConnectionClosed the conn still sits
                            // in the pool and RESERVE dedup can land on it.
                            // request_reservation defers while this set is
                            // non-empty.
                            self.relayed_conn_ids
                                .entry(peer_id)
                                .or_default()
                                .insert(connection_id);
                            // A relayed conn to a reservation-eligible relay is
                            // only safe to close when a DIRECT conn to that
                            // peer already exists — every noid node advertises
                            // HOP, so "known relay" here is any connected peer,
                            // and for a CGNAT-locked peer the circuit is the
                            // ONLY data path. Killing it unconditionally
                            // stranded relayed peers entirely: conns flapped on
                            // establish and pending traffic dead-ended until a
                            // direct conn happened to form. With no direct
                            // path we keep the circuit and dial a direct
                            // upgrade in parallel; the direct-connection arm
                            // above closes the circuit once one lands. The
                            // nested-circuit hazard (RESERVE deduping onto a
                            // relayed conn) stays covered — request_reservation
                            // defers while `relayed_conn_ids` is non-empty.
                            let is_known_relay =
                                self.known_relays.iter().any(|(p, _)| *p == peer_id);
                            if is_known_relay {
                                if self.direct_conns.get(&peer_id).copied().unwrap_or(0) > 0 {
                                    // Grace close, not immediate (TR-08):
                                    // the RESERVE-dedup hazard stays
                                    // covered because the id remains in
                                    // relayed_conn_ids until
                                    // ConnectionClosed, and the fire-time
                                    // revalidation saves the circuit if the
                                    // direct conn dies inside the window.
                                    log::info!(
                                        "Scheduling close of relayed conn to known relay {} — direct conn available",
                                        peer_id
                                    );
                                    self.pending_conn_close.push((
                                        tokio::time::Instant::now()
                                            + tokio::time::Duration::from_secs(20),
                                        peer_id,
                                        connection_id,
                                    ));
                                } else if !self.dial_is_backed_off(&peer_id) {
                                    log::info!(
                                        "Relayed conn to {} is the only path — keeping; dialing direct upgrade",
                                        peer_id
                                    );
                                    // TR-02: dial_opts_multi lifts the
                                    // DisconnectedAndNotDialing condition so
                                    // the upgrade runs over the live circuit.
                                    let direct = self.direct_addrs_of(&peer_id);
                                    if !direct.is_empty() {
                                        let _ = self.swarm.dial(
                                            crate::p2p::dial_opts::dial_opts_multi(
                                                peer_id, direct,
                                            ),
                                        );
                                    }
                                }
                            }
                        } else {
                            *self.direct_conns.entry(peer_id).or_insert(0) += 1;
                            // A direct conn to a reservation-eligible relay
                            // makes any relayed conns to it redundant AND
                            // dangerous: a RESERVE issued now deduplicates
                            // onto an arbitrary existing conn — a relayed one
                            // would yield a nested-circuit listen addr.
                            // Grace close (TR-08): the ids stay in
                            // relayed_conn_ids so request_reservation keeps
                            // deferring until ConnectionClosed confirms them
                            // gone.
                            if self.known_relays.iter().any(|(p, _)| *p == peer_id) {
                                if let Some(ids) = self.relayed_conn_ids.get(&peer_id) {
                                    let deadline = tokio::time::Instant::now()
                                        + tokio::time::Duration::from_secs(20);
                                    for id in ids.iter().copied().collect::<Vec<_>>() {
                                        log::debug!(
                                            "Scheduling close of redundant relayed conn {:?} to relay {}",
                                            id, peer_id
                                        );
                                        self.pending_conn_close.push((deadline, peer_id, id));
                                    }
                                }
                            }
                        }
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
                        let mut conn_closing = false;
                        // A circuit reservation is bound to the conn it was
                        // negotiated over — QUIC-pinning a relay's ws/tcp
                        // conn mid-RESERVE kills the pending reservation
                        // (observed: reservation listener dies with the
                        // conn). Relay peers are exempt from pinning, and so
                        // is every conn on a node that relays for others:
                        // the peer's reservation may ride any conn here.
                        let is_known_relay_conn =
                            self.known_relays.iter().any(|(p, _)| *p == peer_id);
                        if is_known_relay_conn || self.should_relay() {
                            // keep every conn — reservations ride them
                        } else if is_quic {
                            // A QUIC conn to this peer exists — close its
                            // non-QUIC conns. request-response picks an
                            // arbitrary conn, and on CGNAT a TCP flow can be
                            // dead-but-ESTABLISHED for ~60s until ping catches
                            // it; sends riding that zombie always time out.
                            // QUIC survives NAT rebinds via connection IDs.
                            let dead: Vec<libp2p::swarm::ConnectionId> = self
                                .conn_quic
                                .get(&peer_id)
                                .map(|m| {
                                    m.iter()
                                        .filter(|(_, q)| !**q)
                                        .map(|(id, _)| *id)
                                        .collect()
                                })
                                .unwrap_or_default();
                            // F8: grace before close — an in-flight request
                            // on the superseded conn gets 20s to finish.
                            // Relayed conns join the retire set too — the
                            // circuit is byte-capped and loses to a proven
                            // direct conn; the fire-time revalidation saves
                            // it if QUIC dies inside the window (EL-02).
                            let deadline = tokio::time::Instant::now()
                                + tokio::time::Duration::from_secs(20);
                            for id in dead {
                                log::debug!(
                                    "Scheduling close of non-QUIC conn {:?} to {} — QUIC pinned (grace 20s)",
                                    id, peer_id
                                );
                                self.pending_conn_close.push((deadline, peer_id, id));
                            }
                        } else {
                            let has_quic = self
                                .conn_quic
                                .get(&peer_id)
                                .map(|m| m.values().any(|q| *q))
                                .unwrap_or(false);
                            if has_quic {
                                // QUIC already lives — this new non-QUIC conn
                                // is another zombie candidate request-response
                                // might pick over the resilient path. A
                                // relayed conn may still carry in-flight
                                // traffic — grace close; a fresh direct conn
                                // has none — close now.
                                if endpoint.is_relayed() {
                                    log::debug!(
                                        "Scheduling close of new relayed conn {:?} to {} — QUIC pinned",
                                        connection_id, peer_id
                                    );
                                    self.pending_conn_close.push((
                                        tokio::time::Instant::now()
                                            + tokio::time::Duration::from_secs(20),
                                        peer_id,
                                        connection_id,
                                    ));
                                } else {
                                    log::debug!(
                                        "Closing new non-QUIC conn {:?} to {} — QUIC pinned",
                                        connection_id, peer_id
                                    );
                                    let _ = self.swarm.close_connection(connection_id);
                                }
                                conn_closing = true;
                            } else {
                                // EL-03: deterministic symmetric survivor.
                                // The conn dialed by the SMALLER peer id is
                                // preferred on BOTH ends — for the smaller
                                // peer it is its own outgoing (dialer) conn,
                                // for the larger it is the inbound one — so
                                // both nodes retire the same socket instead
                                // of each killing a different one (the old
                                // "keep freshest" rule disagreed under
                                // simultaneous dials and killed BOTH).
                                // Relayed conns never count as preferred —
                                // a circuit is a byte-capped fallback kept
                                // only while it is the sole path.
                                let prefer_dialer = self.peer_id < peer_id;
                                let relayed_ids = self
                                    .relayed_conn_ids
                                    .get(&peer_id)
                                    .cloned()
                                    .unwrap_or_default();
                                let is_relayed_conn =
                                    |id: &libp2p::swarm::ConnectionId| {
                                        relayed_ids.contains(id)
                                    };
                                let prefers = |id: &libp2p::swarm::ConnectionId| {
                                    !is_relayed_conn(id)
                                        && self
                                            .conn_dialer
                                            .get(id)
                                            .copied()
                                            .unwrap_or(false)
                                            == prefer_dialer
                                };
                                let others: Vec<libp2p::swarm::ConnectionId> = self
                                    .conn_quic
                                    .get(&peer_id)
                                    .map(|m| {
                                        m.keys()
                                            .filter(|id| **id != connection_id)
                                            .copied()
                                            .collect()
                                    })
                                    .unwrap_or_default();
                                if endpoint.is_relayed() {
                                    if others.iter().any(|id| !is_relayed_conn(id)) {
                                        // A direct conn exists — the fresh
                                        // circuit is redundant; retire it
                                        // after grace.
                                        log::debug!(
                                            "Scheduling close of redundant relayed conn {:?} to {} — direct conn exists",
                                            connection_id, peer_id
                                        );
                                        self.pending_conn_close.push((
                                            tokio::time::Instant::now()
                                                + tokio::time::Duration::from_secs(20),
                                            peer_id,
                                            connection_id,
                                        ));
                                        conn_closing = true;
                                    } else {
                                        // Only circuits — keep the freshest,
                                        // retire the siblings.
                                        for id in others {
                                            log::debug!(
                                                "Scheduling close of superseded relayed conn {:?} to {}",
                                                id, peer_id
                                            );
                                            self.pending_conn_close.push((
                                                tokio::time::Instant::now()
                                                    + tokio::time::Duration::from_secs(20),
                                                peer_id,
                                                id,
                                            ));
                                        }
                                    }
                                } else {
                                    let new_preferred = prefers(&connection_id);
                                    let others_preferred =
                                        others.iter().any(prefers);
                                    if new_preferred || !others_preferred {
                                        // This conn survives — retire every
                                        // sibling after grace. With no
                                        // preferred conn at all the freshest
                                        // fallback wins; both ends agree.
                                        let deadline = tokio::time::Instant::now()
                                            + tokio::time::Duration::from_secs(20);
                                        for id in others {
                                            log::debug!(
                                                "Scheduling close of superseded conn {:?} to {} (grace 20s)",
                                                id, peer_id
                                            );
                                            self.pending_conn_close.push((
                                                deadline, peer_id, id,
                                            ));
                                        }
                                    } else {
                                        // A preferred survivor already
                                        // exists — this fresh conn is the
                                        // redundant one; nothing in flight.
                                        log::debug!(
                                            "Closing new non-preferred conn {:?} to {} — symmetric survivor exists",
                                            connection_id, peer_id
                                        );
                                        let _ =
                                            self.swarm.close_connection(connection_id);
                                        conn_closing = true;
                                    }
                                }
                            }
                        }
                        self.clear_dial_backoff(&peer_id);
                        // A dialer endpoint just proved the remote addr
                        // works — (re)register it in the routing table and the
                        // peer cache. This is what heals the table after the
                        // 3-strike eviction or after Kademlia dropped the
                        // peer while one transport still lived.
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
                            && !emit_ev(&event_tx, P2PEvent::PeerConnected(peer_id.to_string())).await { return Ok(()); }

                        // Announce our username to the newly connected peer
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
                        let _ = emit_ev(&event_tx, P2PEvent::RelayStatusChanged {
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
                            if !emit_ev(&event_tx, P2PEvent::PeerDisconnected(peer_id.to_string())).await { return Ok(()); }
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
                            }
                        }
                        let _ = emit_ev(&event_tx, P2PEvent::RelayStatusChanged {
                            status: self.relay_status(),
                        }).await;
                    }
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
                            if !emit_ev(&event_tx, P2PEvent::PeerDiscovered(peer_id.to_string(), addr.to_string())).await { return Ok(()); }
                        }
                    }
                    SwarmEvent::Behaviour(NoidBehaviourEvent::Identify(identify::Event::Received { peer_id, connection_id, info, .. })) => {
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
                    SwarmEvent::Behaviour(NoidBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                        propagation_source: _peer_id,
                        message_id: _id,
                        message,
                    })) => {
                        // Rooms only ever carry sealed RoomEnvelope payloads —
                        // plaintext NoidMessage on gossipsub is rejected.
                        let room_id = message
                            .topic
                            .as_str()
                            .strip_prefix("noid-room-")
                            .map(|s| s.to_string());
                        let Some(room_id) = room_id else {
                            log::warn!("Gossipsub message on unknown topic — dropped");
                            continue;
                        };
                        let Some(key) = self.room_keys.get(&room_id).copied() else {
                            // Subscribed topic but no key — can't happen after
                            // key-gated join, but fail closed anyway.
                            continue;
                        };
                        match serde_json::from_slice::<crate::security::room_crypto::RoomEnvelope>(&message.data) {
                            Ok(env) => {
                                // Replay protection per room message id.
                                let replay_key = format!("{}:{}", room_id, env.msg_id);
                                if !self.seen_room_msgs.insert(replay_key.clone()) {
                                    continue;
                                }
                                self.seen_room_order.push_back(replay_key);
                                // Bound the cache FIFO — evict the OLDEST ids
                                // (HashSet::iter().skip() would drop an
                                // arbitrary half, re-opening the replay window
                                // for fresh messages).
                                while self.seen_room_msgs.len() > 10_000 {
                                    if let Some(oldest) = self.seen_room_order.pop_front() {
                                        self.seen_room_msgs.remove(&oldest);
                                    } else {
                                        break;
                                    }
                                }
                                match crate::security::room_crypto::open(&key, &room_id, &env) {
                                    Ok(pt) => {
                                        // Typed room payload — Chat goes to history,
                                        // control variants to the room dispatcher.
                                        match serde_json::from_slice::<crate::p2p::RoomPayload>(&pt) {
                                            Ok(crate::p2p::RoomPayload::Chat { content }) => {
                                                let _ = emit_ev(&event_tx, P2PEvent::RoomMessage {
                                                    room_id,
                                                    sender: env.sender_peer_id,
                                                    content,
                                                    msg_id: env.msg_id,
                                                    ts: env.ts,
                                                }).await;
                                            }
                                            Ok(payload) => {
                                                match serde_json::to_string(&payload) {
                                                    Ok(payload) => {
                                                        let _ = emit_ev(&event_tx, P2PEvent::RoomControl {
                                                            room_id,
                                                            sender: env.sender_peer_id,
                                                            payload,
                                                        }).await;
                                                    }
                                                    Err(_) => continue,
                                                }
                                            }
                                            // Legacy envelope: raw text, not a typed payload.
                                            Err(_) => {
                                                let content = String::from_utf8_lossy(&pt).to_string();
                                                let _ = emit_ev(&event_tx, P2PEvent::RoomMessage {
                                                    room_id,
                                                    sender: env.sender_peer_id,
                                                    content,
                                                    msg_id: env.msg_id,
                                                    ts: env.ts,
                                                }).await;
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        // Distinguish stale key (signature valid,
                                        // AES open fails — room rekeyed and we missed
                                        // the KeyUpdate) from a forged envelope.
                                        let sig_ok = crate::security::identity_sig::verify_payload(
                                            &env.sender_peer_id,
                                            &crate::security::room_crypto::envelope_payload(
                                                &room_id, &env.msg_id, &env.ts, &env.ciphertext,
                                            ),
                                            &env.signature,
                                        );
                                        if sig_ok {
                                            log::debug!("Stale room key in {} — requesting resync", room_id);
                                            let _ = emit_ev(&event_tx, P2PEvent::RoomKeyStale {
                                                room_id,
                                            }).await;
                                        } else {
                                            log::warn!("Rejected room envelope in {}: {}", room_id, e);
                                            if let Some(ref al) = self.audit_log {
                                                let _ = al.log_replay_detected(&format!("room-tamper:{}", env.msg_id));
                                            }
                                        }
                                    }
                                }
                            }
                            Err(_) => {
                                log::warn!("Non-envelope gossipsub payload in {} — dropped", room_id);
                            }
                        }
                    }
                    SwarmEvent::Behaviour(NoidBehaviourEvent::RequestResponse(request_response::Event::Message {
                        peer,
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
                            continue;
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
                            continue;
                        }

                        // UsernameAnnounce is answered inline — it is handled
                        // synchronously below and never reaches the app layer.
                        if !matches!(request.msg_type, crate::p2p::types::MessageType::UsernameAnnounce { .. }) {
                            // TI-1: park the response channel. The transport
                            // "OK" doubles as the application-level ack and is
                            // sent only after the app layer reports durable
                            // processing via P2PCommand::AckReceived — acking
                            // here used to confirm delivery before the message
                            // was persisted (a real loss window on crash).
                            self.park_app_ack(peer.to_string(), request.id.clone(), channel);
                            if !emit_ev(&event_tx, P2PEvent::RequestReceived {
                                from: peer.to_string(),
                                data: request,
                            }).await { return Ok(()); }
                            continue;
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
                                    // updated_at is signed — a replayed older
                                    // record must not overwrite a newer one.
                                    let fresher = self
                                        .local_dht_get(&key)
                                        .map(|stored| {
                                            crate::p2p::types::user_record_is_fresher(&stored, &record)
                                        })
                                        .unwrap_or(true);
                                    if fresher {
                                        self.local_dht_put(key, request.content.into_bytes());
                                        log::debug!("Received username announce from peer {}: username='{}'", peer, username);
                                    } else {
                                        log::debug!("Ignored stale username announce for '{}'", username);
                                    }
                                }
                            }
                            continue;
                        }

                        if !emit_ev(&event_tx, P2PEvent::RequestReceived {
                            from: peer.to_string(),
                            data: request,
                        }).await { return Ok(()); }
                    }
                    SwarmEvent::Behaviour(NoidBehaviourEvent::RequestResponse(request_response::Event::Message {
                        peer,
                        message: request_response::Message::Response { request_id, response },
                    })) => {
                        log::debug!("Received response from {} for request {}", peer, request_id);
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
                                    if self.prekey_recently_resolved(&peer_id) { continue; }
                                    self.mark_prekey_resolved(&peer_id);
                                    // Cache the verified copy for the local
                                    // DHT fallback path (DHT-04).
                                    if let Some(bytes) = response.data.as_ref() {
                                        self.local_dht_put(
                                            Self::prekey_dht_key(&peer_id).to_vec(),
                                            bytes.clone(),
                                        );
                                    }
                                    let _ = emit_ev(&event_tx, P2PEvent::PrekeyBundleRetrieved {
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
                                        let _ = emit_ev(&event_tx, P2PEvent::PrekeyBundleRetrieved {
                                            peer_id,
                                            bundle: None,
                                        }).await;
                                    }
                                }
                            }
                            continue;
                        }
                        // Phase 1.3: Emit MessageDelivered so the forwarder can delete the pending record
                        if let Some(msg) = self.pending_messages.remove(&request_id.to_string()) {
                            let _ = emit_ev(&event_tx, P2PEvent::MessageDelivered {
                                peer_id: peer.to_string(),
                                message_id: msg.id.clone(),
                            }).await;
                        }
                    }
                    SwarmEvent::Behaviour(NoidBehaviourEvent::RequestResponse(request_response::Event::OutboundFailure {
                        peer,
                        request_id,
                        error,
                    })) => {
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
                                let _ = emit_ev(&event_tx, P2PEvent::PrekeyBundleRetrieved {
                                    peer_id,
                                    bundle: None,
                                }).await;
                            }
                            continue;
                        }
                        let pending_msg = self.pending_messages.remove(&request_id.to_string());
                        let content = pending_msg.as_ref().map(|msg| msg.content.clone()).unwrap_or_default();
                        let message_id = pending_msg.as_ref().map(|msg| msg.id.clone()).unwrap_or_default();
                        let msg_type = pending_msg.as_ref().map(|msg| msg.msg_type.clone())
                            .unwrap_or(crate::p2p::MessageType::Chat(content.clone()));

                        if !emit_ev(&event_tx, P2PEvent::MessageFailed {
                            to: peer.to_string(),
                            request_id: request_id.to_string(),
                            error: error.to_string(),
                            content,
                            message_id,
                            msg_type,
                        }).await { return Ok(()); }
                    }
                    // Phase B.2: Mailbox protocol — handle incoming mailbox requests
                    SwarmEvent::Behaviour(NoidBehaviourEvent::Mailbox(request_response::Event::Message {
                        peer,
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
                                let _ = emit_ev(&event_tx, P2PEvent::MailboxStoreAck {
                                    success,
                                    message_id,
                                    recipient_peer_id,
                                }).await;
                            }
                            crate::p2p::types::MailboxResponse::Messages { messages } => {
                                log::debug!("Retrieved {} messages from mailbox", messages.len());
                                let _ = emit_ev(&event_tx, P2PEvent::MailboxMessagesRetrieved {
                                    mailbox_peer_id: peer.to_string(),
                                    messages,
                                }).await;
                            }
                        }
                    }
                    // Phase B.2: Mailbox protocol — handle outbound failures
                    SwarmEvent::Behaviour(NoidBehaviourEvent::Mailbox(request_response::Event::OutboundFailure {
                        peer,
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
                        let _ = emit_ev(&event_tx, P2PEvent::MailboxStoreAck {
                            success: false,
                            message_id,
                            recipient_peer_id,
                        }).await;
                        let _ = emit_ev(&event_tx, P2PEvent::MailboxError {
                            error: format!("Mailbox error: {}", error),
                        }).await;
                    }
                    SwarmEvent::Behaviour(NoidBehaviourEvent::Kademlia(kad::Event::OutboundQueryProgressed {
                        id,
                        result: kad::QueryResult::GetRecord(Ok(kad::GetRecordOk::FoundRecord(peer_record))),
                        ..
                    })) => {
                        // Dispatch by PENDING-MAP OWNERSHIP first, payload
                        // shape second: a record stored under a queried key
                        // with an unexpected shape must still resolve its
                        // pending query — the UI waits on the result event
                        // and spins forever without one.
                        if let Some(peer_id) = self.pending_prekey_queries.remove(&id) {
                            // Phase A.3: Prekey bundle retrieved from DHT.
                            // Must be signed by the queried peer's identity key —
                            // a forged bundle is a MITM attempt and is rejected.
                            // X3DH-07: the direct path may have resolved this
                            // peer already — a second emit would re-initiate
                            // the session just created.
                            if self.prekey_recently_resolved(&peer_id) {
                                continue;
                            }
                            match serde_json::from_slice::<crate::security::PrekeyBundle>(&peer_record.record.value) {
                                Ok(bundle) => {
                                    let valid = bundle.owner_peer_id.as_deref() == Some(peer_id.as_str())
                                        && crate::security::x3dh::verify_prekey_bundle(&bundle);
                                    if valid {
                                        log::debug!("Verified prekey bundle from DHT for peer {}", peer_id);
                                        self.mark_prekey_resolved(&peer_id);
                                        let _ = emit_ev(&event_tx, P2PEvent::PrekeyBundleRetrieved {
                                            peer_id,
                                            bundle: Some(bundle),
                                        }).await;
                                    } else {
                                        log::warn!("Rejected unverified prekey bundle for {}", peer_id);
                                        if let Some(ref log) = self.audit_log {
                                            let _ = log.log_replay_detected(&format!("prekey-forgery:{}", peer_id));
                                        }
                                        let _ = emit_ev(&event_tx, P2PEvent::PrekeyBundleRetrieved {
                                            peer_id,
                                            bundle: None,
                                        }).await;
                                    }
                                }
                                Err(e) => {
                                    log::warn!("Failed to parse prekey bundle for {}: {}", peer_id, e);
                                    let _ = emit_ev(&event_tx, P2PEvent::PrekeyBundleRetrieved {
                                        peer_id,
                                        bundle: None,
                                    }).await;
                                }
                            }
                        } else if let Some(peer_id) = self.pending_mailbox_lookups.remove(&id) {
                            // Phase H.1: Mailbox node record retrieved from DHT.
                            // Value is a SignedMailboxRecord — verify the owner's
                            // signature so a DHT peer cannot redirect envelopes.
                            match serde_json::from_slice::<crate::p2p::types::SignedMailboxRecord>(&peer_record.record.value) {
                                Ok(rec) => {
                                    let valid = rec.owner_peer_id == peer_id
                                        && crate::security::identity_sig::verify_payload(
                                            &rec.owner_peer_id,
                                            &crate::p2p::types::mailbox_record_signing_payload(&rec),
                                            &rec.signature,
                                        );
                                    if valid {
                                        log::debug!("Mailbox node found for {}: mailbox_peer={}", peer_id, rec.mailbox_peer_id);
                                        // D19: cache the verified pointer for
                                        // the retry tick (10min TTL).
                                        self.mailbox_cache.insert(
                                            peer_id.clone(),
                                            (
                                                rec.mailbox_peer_id.clone(),
                                                rec.relay_addr.clone(),
                                                std::time::Instant::now(),
                                            ),
                                        );
                                        let _ = emit_ev(&event_tx, P2PEvent::MailboxNodeFound {
                                            peer_id,
                                            mailbox_peer_id: rec.mailbox_peer_id,
                                            relay_addr: rec.relay_addr,
                                        }).await;
                                    } else {
                                        log::warn!("Rejected unsigned/forged mailbox record for {}", peer_id);
                                        let _ = emit_ev(&event_tx, P2PEvent::MailboxError {
                                            error: format!("Mailbox record for {} failed verification", peer_id),
                                        }).await;
                                    }
                                }
                                Err(e) => {
                                    log::warn!("Invalid mailbox record for {}: {}", peer_id, e);
                                    let _ = emit_ev(&event_tx, P2PEvent::MailboxError {
                                        error: format!("Mailbox record for {} is unreadable", peer_id),
                                    }).await;
                                }
                            }
                        } else if let Some((pub_username, value, signed)) = self.pending_username_publishes.remove(&id) {
                            // D14: get-before-put gate — commit only when no
                            // fresher valid record owned by another peer.
                            if self.username_publish_allowed(&pub_username, &value, Some(&peer_record)) {
                                match self.commit_username_publish(&pub_username, value, signed) {
                                    Ok(_) => {
                                        let _ = emit_ev(&event_tx, P2PEvent::UsernameAvailabilityChecked {
                                            username: pub_username,
                                            available: true,
                                            uncertain: false,
                                        }).await;
                                    }
                                    Err(e) => {
                                        log::error!("Username publish failed: {}", e);
                                        let _ = emit_ev(&event_tx, P2PEvent::UsernameAvailabilityChecked {
                                            username: pub_username,
                                            available: false,
                                            uncertain: false,
                                        }).await;
                                    }
                                }
                            } else {
                                log::warn!("Username '{}' is held by another peer — refusing to publish", pub_username);
                                let _ = emit_ev(&event_tx, P2PEvent::UsernameAvailabilityChecked {
                                    username: pub_username,
                                    available: false,
                                    uncertain: false,
                                }).await;
                            }
                        } else if let Some(avail_username) = self.pending_availability_queries.remove(&id) {
                            // D21: availability queries resolve as the
                            // availability event only — a search result must
                            // not pop into it, and vice versa.
                            match serde_json::from_slice::<DHTUserRecord>(&peer_record.record.value) {
                                Ok(user_record) => {
                                    // D13: a revoked record is a tombstone —
                                    // the owner released the name.
                                    let sig_ok = user_record.signature.as_ref().map(|sig| {
                                        crate::security::identity_sig::verify_payload(
                                            &user_record.peer_id,
                                            &crate::p2p::types::user_record_signing_payload(&user_record),
                                            sig,
                                        )
                                    }).unwrap_or(false)
                                        && user_record.username == avail_username
                                        && !user_record.revoked;
                                    let _ = emit_ev(&event_tx, P2PEvent::UsernameAvailabilityChecked {
                                        username: avail_username,
                                        available: !sig_ok,
                                        uncertain: false,
                                    }).await;
                                }
                                Err(e) => {
                                    log::warn!("Malformed user record for '{}': {}", avail_username, e);
                                    let _ = emit_ev(&event_tx, P2PEvent::UsernameAvailabilityChecked {
                                        username: avail_username,
                                        available: true,
                                        uncertain: false,
                                    }).await;
                                }
                            }
                        } else if let Some(lookup_username) = self.pending_lookups.remove(&id) {
                            // Username records must be signed by the claimed
                            // owner — unsigned/forged/malformed records resolve
                            // the lookup as "not found", never silently.
                            match serde_json::from_slice::<DHTUserRecord>(&peer_record.record.value) {
                                Ok(user_record) => {
                                    let sig_ok = user_record.signature.as_ref().map(|sig| {
                                        crate::security::identity_sig::verify_payload(
                                            &user_record.peer_id,
                                            &crate::p2p::types::user_record_signing_payload(&user_record),
                                            sig,
                                        )
                                    }).unwrap_or(false);
                                    // The username is inside the signed
                                    // payload — a record signed for another
                                    // name cannot be replayed under this key.
                                    // D13: a revoked record is a tombstone —
                                    // the owner released the name.
                                    let sig_ok = sig_ok && user_record.username == lookup_username
                                        && !user_record.revoked;
                                    if sig_ok {
                                        log::debug!("Received signed user record from DHT for username lookup '{}'", lookup_username);
                                        let _ = emit_ev(&event_tx, P2PEvent::UserLookupResult {
                                            username: lookup_username,
                                            record: Some(user_record),
                                        }).await;
                                    } else {
                                        log::warn!("Rejected unsigned/forged user record for '{}'", lookup_username);
                                        let _ = emit_ev(&event_tx, P2PEvent::UserLookupResult {
                                            username: lookup_username,
                                            record: None,
                                        }).await;
                                    }
                                }
                                Err(e) => {
                                    log::warn!("Malformed user record for '{}': {}", lookup_username, e);
                                    let _ = emit_ev(&event_tx, P2PEvent::UserLookupResult {
                                        username: lookup_username,
                                        record: None,
                                    }).await;
                                }
                            }
                        } else {
                            log::debug!("Received non-DHT record from Kademlia, ignoring");
                        }
                    }
                    SwarmEvent::Behaviour(NoidBehaviourEvent::Kademlia(kad::Event::OutboundQueryProgressed {
                        id,
                        result: kad::QueryResult::GetRecord(Ok(kad::GetRecordOk::FinishedWithNoAdditionalRecord { .. })),
                        ..
                    })) => {
                        // Successful completion follows FoundRecord; it is
                        // not a NotFound result. Resolve only leftover state.
                        if self.resolve_get_record_miss(&id, &event_tx).await {
                            continue;
                        }
                    }
                    SwarmEvent::Behaviour(NoidBehaviourEvent::Kademlia(kad::Event::OutboundQueryProgressed {
                        id,
                        result: kad::QueryResult::GetRecord(Err(e)),
                        ..
                    })) => {
                        // All failure variants end here — NotFound (queried,
                        // absent), Timeout, Failed, QuorumFailed. A query
                        // that ends in ANY error must still resolve its
                        // pending map: the UI spinner waits for the result
                        // event and hangs forever without one.
                        log::debug!("DHT GetRecord failed: {:?}", e);
                        // Phase A.3: Check if this was a prekey query
                        if let Some(peer_id) = self.pending_prekey_queries.remove(&id) {
                            // X3DH-07: a direct request may still answer —
                            // emitting None here would fail the handshake
                            // while the peer is about to reply.
                            if self.prekey_direct_pending(&peer_id)
                                || self.prekey_recently_resolved(&peer_id)
                            {
                                continue;
                            }
                            // DHT-04: the local fallback copy answers a
                            // failed network query — a self-published bundle
                            // or a cached peer bundle must not read as
                            // "absent" just because the DHT errored.
                            let local = self
                                .local_dht_get(&Self::prekey_dht_key(&peer_id).to_vec())
                                .and_then(|v| {
                                    serde_json::from_slice::<crate::security::PrekeyBundle>(&v)
                                        .ok()
                                        .filter(|b| {
                                            b.owner_peer_id.as_deref() == Some(peer_id.as_str())
                                                && crate::security::x3dh::verify_prekey_bundle(b)
                                        })
                                });
                            if local.is_some() {
                                log::debug!("Prekey bundle for {} served from local DHT store", peer_id);
                                self.mark_prekey_resolved(&peer_id);
                            } else {
                                log::warn!("Prekey bundle not found in DHT for peer {} ({:?})", peer_id, e);
                            }
                            let _ = emit_ev(&event_tx, P2PEvent::PrekeyBundleRetrieved {
                                peer_id,
                                bundle: local,
                            }).await;
                            continue;
                        }
                        // Phase H.1: Check if this was a mailbox lookup
                        // D18: surface the failure — pending rows wait for
                        // the retry tick, and the caller must know the
                        // resolver produced nothing instead of an answer.
                        if let Some(peer_id) = self.pending_mailbox_lookups.remove(&id) {
                            // DHT-04: same local fallback — a verified
                            // SignedMailboxRecord in our store beats a
                            // network miss.
                            let local = self
                                .local_dht_get(&Self::mailbox_dht_key(&peer_id).to_vec())
                                .and_then(|v| {
                                    serde_json::from_slice::<crate::p2p::types::SignedMailboxRecord>(
                                        &v,
                                    )
                                    .ok()
                                    .filter(|rec| {
                                        rec.owner_peer_id == peer_id
                                            && crate::security::identity_sig::verify_payload(
                                                &rec.owner_peer_id,
                                                &crate::p2p::types::mailbox_record_signing_payload(
                                                    rec,
                                                ),
                                                &rec.signature,
                                            )
                                    })
                                });
                            if let Some(rec) = local {
                                log::debug!(
                                    "Mailbox record for {} served from local DHT store",
                                    peer_id
                                );
                                self.mailbox_cache.insert(
                                    peer_id.clone(),
                                    (
                                        rec.mailbox_peer_id.clone(),
                                        rec.relay_addr.clone(),
                                        std::time::Instant::now(),
                                    ),
                                );
                                let _ = emit_ev(&event_tx, P2PEvent::MailboxNodeFound {
                                    peer_id,
                                    mailbox_peer_id: rec.mailbox_peer_id,
                                    relay_addr: rec.relay_addr,
                                }).await;
                            } else {
                                log::debug!("Mailbox node not found in DHT for peer {} ({:?})", peer_id, e);
                                let _ = emit_ev(&event_tx, P2PEvent::MailboxNodeNotFound {
                                    peer_id,
                                }).await;
                            }
                            continue;
                        }
                        // D14: a publish gate query that resolved — NotFound
                        // means the name is free; any other failure is
                        // inconclusive and the publish is refused.
                        if let Some((pub_username, value, signed)) = self.pending_username_publishes.remove(&id) {
                            let not_found = matches!(e, kad::GetRecordError::NotFound { .. });
                            if not_found {
                                match self.commit_username_publish(&pub_username, value, signed) {
                                    Ok(_) => {
                                        let _ = emit_ev(&event_tx, P2PEvent::UsernameAvailabilityChecked {
                                            username: pub_username,
                                            available: true,
                                            uncertain: false,
                                        }).await;
                                    }
                                    Err(err) => {
                                        log::error!("Username publish failed: {}", err);
                                    }
                                }
                            } else {
                                log::warn!("Username availability query for '{}' inconclusive ({:?}) — refusing publish", pub_username, e);
                                let _ = emit_ev(&event_tx, P2PEvent::UsernameAvailabilityChecked {
                                    username: pub_username,
                                    available: false,
                                    uncertain: true,
                                }).await;
                            }
                            continue;
                        }
                        // D21: availability and lookup queries resolve into
                        // their own events — never both.
                        enum UsernameQueryKind { Availability, Lookup }
                        let (lookup_username, kind) =
                            if let Some(u) = self.pending_availability_queries.remove(&id) {
                                (u, UsernameQueryKind::Availability)
                            } else if let Some(u) = self.pending_lookups.remove(&id) {
                                (u, UsernameQueryKind::Lookup)
                            } else {
                                // other GetRecord queries (random walks) end here silently
                                continue;
                            };
                        // Check local DHT store as fallback — real data beats
                        // a failed query regardless of the failure kind.
                        let prefix = format!("noid:username:{}", lookup_username);
                        let mut hasher = sha2::Sha256::new();
                        sha2::Digest::update(&mut hasher, prefix.as_bytes());
                        let key_hash = sha2::Digest::finalize(hasher);
                        if let Some(value) = self.local_dht_get(&key_hash) {
                            if let Ok(user_record) = serde_json::from_slice::<DHTUserRecord>(&value) {
                                log::debug!("Found user '{}' in local DHT store (fallback)", lookup_username);
                                match kind {
                                    UsernameQueryKind::Lookup => {
                                        let _ = emit_ev(&event_tx, P2PEvent::UserLookupResult {
                                            username: lookup_username.clone(),
                                            record: Some(user_record.clone()),
                                        }).await;
                                    }
                                    UsernameQueryKind::Availability => {
                                        let _ = emit_ev(&event_tx, P2PEvent::UsernameAvailabilityChecked {
                                            username: lookup_username.clone(),
                                            available: false,
                                            uncertain: false,
                                        }).await;
                                    }
                                }
                                continue;
                            }
                        }
                        // D6: NotFound = peers were queried and nobody holds
                        // the record → genuinely available. Timeout /
                        // QuorumFailed / an empty routing table = we never
                        // got an answer → "unknown", not "available".
                        let not_found = matches!(e, kad::GetRecordError::NotFound { .. });
                        if not_found {
                            log::debug!("DHT record not found for username '{}' - available", lookup_username);
                        } else {
                            log::warn!("DHT lookup for '{}' inconclusive ({:?}) - reporting unknown", lookup_username, e);
                        }
                        match kind {
                            UsernameQueryKind::Availability => {
                                let _ = emit_ev(&event_tx, P2PEvent::UsernameAvailabilityChecked {
                                    username: lookup_username,
                                    available: not_found,
                                    uncertain: !not_found,
                                }).await;
                            }
                            UsernameQueryKind::Lookup => {
                                let _ = emit_ev(&event_tx, P2PEvent::UserLookupResult {
                                    username: lookup_username,
                                    record: None,
                                }).await;
                            }
                        }
                    }
                    SwarmEvent::Behaviour(NoidBehaviourEvent::Kademlia(kad::Event::OutboundQueryProgressed {
                        id,
                        result: kad::QueryResult::PutRecord(Ok(_)),
                        ..
                    })) => {
                        self.pending_prekey_puts.remove(&id);
                        log::info!("DHT PutRecord succeeded — username/prekey/message published to the DHT");
                    }
                    SwarmEvent::Behaviour(NoidBehaviourEvent::Kademlia(kad::Event::OutboundQueryProgressed {
                        id,
                        result: kad::QueryResult::PutRecord(Err(e)),
                        ..
                    })) => {
                        log::warn!("DHT PutRecord failed — record is only stored locally, other nodes cannot see it: {:?}", e);
                        // A failed prekey publish is retried — without a
                        // published bundle no peer can initiate X3DH with us.
                        if let Some((record, attempts)) = self.pending_prekey_puts.remove(&id) {
                            if attempts < 4 {
                                match self.swarm.behaviour_mut().kademlia.put_record(record.clone(), kad::Quorum::One) {
                                    Ok(qid) => {
                                        self.pending_prekey_puts.insert(qid, (record, attempts + 1));
                                        log::info!("Retrying prekey bundle publish (attempt {})", attempts + 1);
                                    }
                                    Err(e2) => {
                                        log::warn!("Prekey publish retry could not be queued: {}", e2);
                                    }
                                }
                            } else {
                                log::warn!("Prekey bundle publish gave up after {} attempts — next republish cycle retries", attempts + 1);
                            }
                        }
                    }
                    SwarmEvent::Behaviour(NoidBehaviourEvent::Kademlia(kad::Event::OutboundQueryProgressed {
                        result: kad::QueryResult::Bootstrap(Ok(_)),
                        ..
                    })) => {
                        log::debug!("DHT bootstrap query succeeded");
                    }
                    SwarmEvent::Behaviour(NoidBehaviourEvent::Kademlia(kad::Event::OutboundQueryProgressed {
                        result: kad::QueryResult::Bootstrap(Err(e)),
                        ..
                    })) => {
                        log::debug!("DHT bootstrap query failed: {:?}", e);
                    }
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
                    // --- AutoNAT: public reachability measurement ---
                    SwarmEvent::Behaviour(NoidBehaviourEvent::Autonat(autonat::Event::StatusChanged { new, .. })) => {
                        match new {
                            autonat::NatStatus::Public(addr) => {
                                log::debug!("AutoNAT: we are publicly reachable at {}", addr);
                                self.nat_status = NatStatus::Public;
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
                            }
                            autonat::NatStatus::Private => {
                                log::debug!("AutoNAT: we are behind NAT (private)");
                                self.nat_status = NatStatus::Private;
                                self.stop_advertising_as_relay();
                                // We need relays to be reachable — find some.
                                self.discover_relays();
                            }
                            autonat::NatStatus::Unknown => {
                                self.nat_status = NatStatus::Unknown;
                            }
                        }
                        let _ = emit_ev(&event_tx, P2PEvent::RelayStatusChanged {
                            status: self.relay_status(),
                        }).await;
                    }
                    // --- UPnP port-mapping results ---
                    SwarmEvent::Behaviour(NoidBehaviourEvent::Upnp(upnp::Event::NewExternalAddr(addr))) => {
                        log::debug!("UPnP: external address mapped {}", addr);
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
                        let _ = emit_ev(&event_tx, P2PEvent::RelayStatusChanged {
                            status: self.relay_status(),
                        }).await;
                    }
                    SwarmEvent::Behaviour(NoidBehaviourEvent::Upnp(upnp::Event::ExpiredExternalAddr(addr))) => {
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
                                let _ = emit_ev(&event_tx, P2PEvent::RelayStatusChanged {
                                    status: self.relay_status(),
                                }).await;
                                continue;
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
                        let _ = emit_ev(&event_tx, P2PEvent::RelayStatusChanged {
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
                        let _ = emit_ev(&event_tx, P2PEvent::RelayStatusChanged {
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
                    SwarmEvent::Behaviour(NoidBehaviourEvent::Relay(relay::Event::ReservationReqDenied { src_peer_id })) => {
                        log::debug!("Relay: reservation denied for {} (limits)", src_peer_id);
                    }
                    SwarmEvent::Behaviour(NoidBehaviourEvent::Relay(relay::Event::CircuitReqDenied {
                        src_peer_id, dst_peer_id,
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
                                libp2p::swarm::DialError::WrongPeerId { endpoint, obtained } => {
                                    let remote = endpoint.get_remote_address().clone();
                                    // A pinned bootstrap seed whose identity
                                    // rotated answers WrongPeerId — adopt the
                                    // observed id instead of dead-marking the
                                    // seed's ip:port for 24h (the mark is
                                    // peer-agnostic and would block the fresh
                                    // identity too).
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
                                        let learned = base
                                            .clone()
                                            .with(libp2p::multiaddr::Protocol::P2p(*obtained));
                                        self.bootstrap_peers.retain(|(p, a)| {
                                            !(Self::relay_base_addr(a) == base && *p != *obtained)
                                        });
                                        self.known_relays.retain(|(p, a)| {
                                            !(Self::relay_base_addr(a) == base && *p != *obtained)
                                        });
                                        self.bootstrap_peers.push((*obtained, remote));
                                        self.register_peer_addr(
                                            *obtained,
                                            learned.clone(),
                                            "bootstrap-rotated",
                                            true,
                                        );
                                        self.add_known_relay(*obtained, vec![learned]);
                                        log::info!(
                                            "Bootstrap seed at {} rotated — adopted {}",
                                            base,
                                            obtained
                                        );
                                    } else {
                                        failed.push(remote);
                                        wrong_peer = true;
                                    }
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
                                    matches!(p, libp2p::multiaddr::Protocol::P2pCircuit)
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
                    other => {
                        log::debug!("Unhandled swarm event: {:?}", other);
                    }
                }
            }
        }
    }

    /// Phase B.2: Set the database reference for mailbox storage.
    pub fn set_db(&mut self, db: std::sync::Arc<tokio::sync::Mutex<Option<crate::db::Database>>>) {
        self.db = Some(db);
    }

    /// Phase J.2: Set the audit log reference for DHT/replay/screenshot logging.
    pub fn set_audit_log(&mut self, log: std::sync::Arc<crate::security::audit_log::AuditLog>) {
        self.audit_log = Some(log);
    }
}
