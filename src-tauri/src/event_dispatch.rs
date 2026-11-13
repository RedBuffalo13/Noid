//! P2PEvent dispatch head — listen/discovery/chat/request arms — extracted from the lib.rs event consumer (Q05/A5b).
//! Bodies moved verbatim.

use std::sync::Arc;
use tauri::Manager;

use crate::p2p::P2PEvent;
use crate::{safe_emit, send_p2p_cmd, AppState};

pub(crate) async fn dispatch_p2p_event(
    event: P2PEvent,
    handle: &tauri::AppHandle,
    last_relay_status: &mut Option<crate::p2p::relay_status::RelayStatus>,
) {
    let handle = handle.clone();
    match event {
                            P2PEvent::NewListenAddr(addr) => {
                                safe_emit(&handle, "p2p-event", format!("Listening on {}", addr));
                            }
                            P2PEvent::PeerDiscovered(peer, addr) => {
                                safe_emit(&handle, "p2p-event", format!("Discovered {} at {}", peer, addr));
                                // No pending flush here: discovery (mDNS) fires before a
                                // connection exists, and this path used to send raw
                                // plaintext Chat messages. The PeerConnected handler
                                // flushes pending with ratchet encryption instead.
                            }
                            P2PEvent::MessageReceived { from, data } => {
                                safe_emit(&handle, "chat-msg", serde_json::json!({"from": from, "data": data}));
                            }
                            P2PEvent::RequestReceived { from, data } => {
                                // RC10: spawn per request — decrypt + DB must
                                // not serialize the event forwarder (an inbound
                                // storm would backpressure the swarm's emit_ev).
                                // TI-1: application-level ack — the response
                                // channel parked in the node is answered only
                                // after the payload reached durable state.
                                // None = leave unanswered so the sender
                                // request times out and the message re-pends.
                                // CR-03: same-peer requests run FIFO under a
                                // per-peer lock — an X3DHInit task stalled on
                                // SQLite was overtaken by the RatchetChat
                                // right behind it and lost the session race.
                                let h = handle.clone();
                                let task = tokio::spawn(async move {
                                    let peer_lock = {
                                        let app_state = h.state::<AppState>();
                                        let mut locks = app_state.inbound_peer_locks.lock().await;
                                        locks
                                            .entry(from.clone())
                                            .or_insert_with(|| {
                                                Arc::new(tokio::sync::Mutex::new(()))
                                            })
                                            .clone()
                                    };
                                    let _peer_guard = peer_lock.lock().await;
                                    let ack_status = crate::request_dispatch::handle_request_received(
                                        &h, &from, &data,
                                    )
                                    .await;
                                    if let Some(status) = ack_status {
                                        let app_state = h.state::<AppState>();
                                        if let Some(tx) = app_state.p2p() {
                                            let _ = send_p2p_cmd(&tx, crate::p2p::P2PCommand::AckReceived {
                                                    peer_id: from,
                                                    message_id: data.id.clone(),
                                                    status: status.to_string(),
                                                })
                                                .await;
                                        }
                                    }
                                });
                                // SEC-A01: tracked — KillPin joins this writer.
                                crate::track_task(&handle, task).await;
                            }
            ev => return crate::ev_room::on_room_event(ev, &handle, last_relay_status).await,
    }
}
