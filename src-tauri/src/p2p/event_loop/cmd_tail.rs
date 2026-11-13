//! Mailbox/relay/reachability command arms — extracted from the event_loop megaloop (Q04/A5).
//! Behaviour-preserving move only.

use super::*;

impl P2PNode {
    pub(crate) async fn on_command_tail(
        &mut self,
        command: P2PCommand,
        ctx: &LoopCtx<'_>,
    ) -> LoopCtl {
        match command {
                            P2PCommand::SendToMailboxBlind { mailbox_peer_id, box_id, sealed, pow_nonce, client_msg_id, recipient_peer_id } => {
                                match self.send_to_mailbox_blind(&mailbox_peer_id, &box_id, sealed, pow_nonce, client_msg_id, &recipient_peer_id) {
                                    Ok(_) => log::debug!("Sealed envelope sent to mailbox {}", mailbox_peer_id),
                                    Err(e) => log::error!("Failed to send blind to mailbox: {}", e),
                                }
                            }
                            P2PCommand::RetrieveFromMailboxBlind { mailbox_peer_id, days } => {
                                match self.retrieve_from_mailbox_blind(&mailbox_peer_id, &days, ctx.event_tx) {
                                    Ok(_) => log::debug!("Retrieving blind box from {} (ephemeral)", mailbox_peer_id),
                                    Err(e) => log::error!("Failed to retrieve blind box: {}", e),
                                }
                            }
                            P2PCommand::AckMailboxBlind { mailbox_peer_id, message_id } => {
                                match self.ack_mailbox_blind(&mailbox_peer_id, &message_id) {
                                    Ok(_) => log::debug!("Acking blind item {} at {}", message_id, mailbox_peer_id),
                                    Err(e) => log::error!("Failed to ack blind item: {}", e),
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
                                    let _ = emit_ev(ctx.event_tx, P2PEvent::MailboxNodeFound {
                                        peer_id: peer_id.clone(),
                                        mailbox_peer_id,
                                        relay_addr,
                                        backup_mailbox_peer_id: None,
                                        backup_relay_addr: None,
                                    }).await;
                                    return LoopCtl::Keep;
                                }
                                // D11: when resolving our OWN mailbox, drain
                                // the history too — envelopes parked on a
                                // superseded node are invisible to the
                                // current record but still within their TTL.
                                if peer_id == self.peer_id.to_string() {
                                    let history = self.mailbox_history.clone();
                                    for (mailbox_peer_id, relay_addr, _) in history {
                                        let _ = emit_ev(ctx.event_tx, P2PEvent::MailboxNodeFound {
                                            peer_id: peer_id.clone(),
                                            mailbox_peer_id,
                                            relay_addr,
                                            backup_mailbox_peer_id: None,
                                            backup_relay_addr: None,
                                        }).await;
                                    }
                                }
                                // Single-flight: a pending lookup for this
                                // peer makes a second query redundant.
                                if self.pending_mailbox_lookups.values().any(|p| *p == peer_id) {
                                    return LoopCtl::Keep;
                                }
                                // DB31: bound in-flight mailbox lookups.
                                if self.pending_mailbox_lookups.len() >= 256 {
                                    log::warn!("pending_mailbox_lookups full — dropping lookup for {}", peer_id);
                                    return LoopCtl::Keep;
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
                            P2PCommand::ReachabilityQuery { peer_id, respond_to } => {
                                if let Ok(peer) = peer_id.parse::<libp2p::PeerId>() {
                                    let r = self.reachability(&peer);
                                    let _ = respond_to.send(serde_json::to_value(&r).unwrap_or_default());
                                } else {
                                    let _ = respond_to.send(serde_json::json!({"level": "offline", "paths": [], "is_relay": false}));
                                }
                            }
                            P2PCommand::ReportRelayStatus { respond_to } => {
                                let status = self.relay_status();
                                let _ = respond_to.send(status.clone());
                                let _ = emit_ev(ctx.event_tx, P2PEvent::RelayStatusChanged {
                                    status,
                                }).await;
                            }
            _ => {}
        }
        LoopCtl::Keep
    }
}
