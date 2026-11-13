//! Gossipsub room-message arm — extracted from the event_loop megaloop (Q04/A5).
//! Behaviour-preserving move only.

use super::*;

impl P2PNode {
    pub(crate) async fn on_room_event(
        &mut self,
        event: SwarmEvent<NoidBehaviourEvent>,
        ctx: &LoopCtx<'_>,
    ) -> LoopCtl {
        match event {
                    SwarmEvent::Behaviour(NoidBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                        propagation_source: _peer_id,
                        message_id: _id,
                        message,
                    })) => {
                        // Rooms only ever carry sealed RoomEnvelope payloads —
                        // plaintext NoidMessage on gossipsub is rejected.
                        // META-04: rotating topics (`noid-rt-*`) resolve through
                        // room_topics; V2 payloads are opaque blobs, not JSON.
                        let room_id = message
                            .topic
                            .as_str()
                            .strip_prefix("noid-room-")
                            .map(|s| s.to_string())
                            .or_else(|| self.room_topics.get(message.topic.as_str()).cloned());
                        let Some(room_id) = room_id else {
                            log::warn!("Gossipsub message on unknown topic — dropped");
                            return LoopCtl::Keep;
                        };
                        let Some(key) = self.room_keys.get(&room_id).copied() else {
                            // Subscribed topic but no key — can't happen after
                            // key-gated join, but fail closed anyway.
                            return LoopCtl::Keep;
                        };
                        // META-04: V2 blob — unwrap the outer seal, then run
                        // the identical V1 pipeline on the inner envelope.
                        // Magic present but unwrap failed → drop (not a member
                        // or tampered); no magic → legacy V1 JSON.
                        let message_data: std::borrow::Cow<'_, [u8]> =
                            if message.data.starts_with(b"NRV2") {
                                match crate::security::room_crypto::unwrap_v2(&key, &message.data) {
                                    Some(inner) => std::borrow::Cow::Owned(inner),
                                    None => return LoopCtl::Keep,
                                }
                            } else {
                                std::borrow::Cow::Borrowed(&message.data[..])
                            };
                        match serde_json::from_slice::<crate::security::room_crypto::RoomEnvelope>(&message_data) {
                            Ok(env) => {
                                // Replay protection per room message id.
                                let replay_key = format!("{}:{}", room_id, env.msg_id);
                                if !self.seen_room_msgs.insert(replay_key.clone()) {
                                    return LoopCtl::Keep;
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
                                                let _ = emit_ev(ctx.event_tx, P2PEvent::RoomMessage {
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
                                                        let _ = emit_ev(ctx.event_tx, P2PEvent::RoomControl {
                                                            room_id,
                                                            sender: env.sender_peer_id,
                                                            payload,
                                                            control_id: env.msg_id,
                                                        }).await;
                                                    }
                                                    Err(_) => return LoopCtl::Keep,
                                                }
                                            }
                                            // Legacy envelope: raw text, not a typed payload.
                                            Err(_) => {
                                                let content = String::from_utf8_lossy(&pt).to_string();
                                                let _ = emit_ev(ctx.event_tx, P2PEvent::RoomMessage {
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
                                            let _ = emit_ev(ctx.event_tx, P2PEvent::RoomKeyStale {
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
            ev => return self.on_net_aux_event(ev, ctx).await,
        }
        LoopCtl::Keep
    }
}
