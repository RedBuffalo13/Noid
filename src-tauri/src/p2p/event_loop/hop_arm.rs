//! Hop-forwarding request-response arms — extracted from the event_loop megaloop (Q04/A5).
//! Behaviour-preserving move only.

use super::*;

impl P2PNode {
    pub(crate) async fn on_hop_event(
        &mut self,
        event: SwarmEvent<NoidBehaviourEvent>,
        ctx: &LoopCtx<'_>,
    ) -> LoopCtl {
        match event {
                    // Only a node serving relay duty forwards; a Client
                    // must not become an open proxy.
                    SwarmEvent::Behaviour(NoidBehaviourEvent::Hop(request_response::Event::Message {
                        peer,
                        connection_id: _,
                        message: request_response::Message::Request { request_id: _req_id, request, channel },
                    })) => {
                        if self.relay_config.role != crate::p2p::relay_config::NodeRole::Relay {
                            log::debug!("Hop request from {} refused — not a relay", peer);
                            return LoopCtl::Keep; // channel drops → requester times out
                        }
                        if self.hop_pending_noid.len() + self.hop_pending_hop.len()
                            >= crate::p2p::hop::MAX_HOP_PENDING
                        {
                            log::warn!("Hop pending map full — refusing forward from {}", peer);
                            return LoopCtl::Keep;
                        }
                        let Ok((next, proto, payload)) = crate::p2p::hop::unwrap(&request) else {
                            log::warn!("Malformed hop frame from {}", peer);
                            return LoopCtl::Keep;
                        };
                        let Ok(next_peer) = next.parse::<libp2p::PeerId>() else {
                            log::warn!("Hop frame from {} names invalid next {}", peer, next);
                            return LoopCtl::Keep;
                        };
                        if proto == crate::p2p::hop::PROTO_HOP {
                            match serde_json::from_slice::<crate::p2p::hop::HopRequest>(&payload) {
                                Ok(inner) => {
                                    let id = self.swarm.behaviour_mut().hop.send_request(&next_peer, inner);
                                    self.hop_pending_hop.insert(id.to_string(), channel);
                                }
                                Err(_) => log::warn!("Nested hop frame from {} unparseable", peer),
                            }
                        } else {
                            match serde_json::from_slice::<crate::p2p::types::NoidMessage>(&payload) {
                                Ok(msg) => {
                                    let id = self.swarm.behaviour_mut().request_response.send_request(&next_peer, msg);
                                    self.hop_pending_noid.insert(id.to_string(), channel);
                                }
                                Err(_) => log::warn!("Noid payload in hop frame from {} unparseable", peer),
                            }
                        }
                    }
                    // A forwarded hop answer — return it to the requester.
                    SwarmEvent::Behaviour(NoidBehaviourEvent::Hop(request_response::Event::Message {
                        peer: _,
                        connection_id: _,
                        message: request_response::Message::Response { request_id, response },
                    })) => {
                        if let Some(channel) = self.hop_pending_hop.remove(&request_id.to_string()) {
                            let _ = self.swarm.behaviour_mut().hop.send_response(channel, response);
                        } else {
                            // Our own outbound 2-hop send — the transport
                            // ack doubles as the delivered signal, same as
                            // the direct path.
                            let dest = self
                                .hop_outbound_dest
                                .remove(&request_id.to_string())
                                .unwrap_or_default();
                            if let Some(msg) = self.pending_messages.remove(&request_id.to_string()) {
                                let _ = emit_ev(ctx.event_tx, P2PEvent::MessageDelivered {
                                    peer_id: dest,
                                    message_id: msg.id.clone(),
                                }).await;
                            }
                        }
                    }
                    SwarmEvent::Behaviour(NoidBehaviourEvent::Hop(request_response::Event::OutboundFailure {
                        peer: _,
                        connection_id: _,
                        request_id,
                        error,
                    })) => {
                        // Forward leg failed → the parked channel drops and
                        // the original requester times out naturally.
                        self.hop_pending_hop.remove(&request_id.to_string());
                        let dest = self
                            .hop_outbound_dest
                            .remove(&request_id.to_string())
                            .unwrap_or_default();
                        if let Some(msg) = self.pending_messages.remove(&request_id.to_string()) {
                            let _ = emit_ev(ctx.event_tx, P2PEvent::MessageFailed {
                                to: dest,
                                request_id: request_id.to_string(),
                                error: format!("hop: {}", error),
                                content: msg.content,
                                message_id: msg.id,
                                msg_type: msg.msg_type,
                            }).await;
                        }
                    }
                    SwarmEvent::Behaviour(NoidBehaviourEvent::Hop(request_response::Event::InboundFailure {
                        peer,
                        connection_id: _,
                        request_id: _,
                        error,
                    })) => {
                        log::debug!("Hop inbound failure from {}: {}", peer, error);
                    }
            _ => {}
        }
        LoopCtl::Keep
    }
}
