//! Room message/control arms — extracted from the lib.rs event consumer (Q05/A5b).
//! Bodies moved verbatim.

use tauri::Manager;

use crate::p2p::P2PEvent;
use crate::{safe_emit, AppState};

pub(crate) async fn on_room_event(
    event: P2PEvent,
    handle: &tauri::AppHandle,
    last_relay_status: &mut Option<crate::p2p::relay_status::RelayStatus>,
) {
    let handle = handle.clone();
    match event {
                            P2PEvent::RoomMessage { room_id, sender, content, msg_id, ts } => {
                                // RC10: DB write off the forwarder path.
                                // Verified + decrypted room envelope — persist and notify UI.
                                // The PK dedup doubles as the emit gate: a copy that
                                // already arrived out-of-band (RoomChat direct/mailbox)
                                // must not emit a second room-msg — the in-memory
                                // seen_room_msgs cache is empty after a restart.
                                let h = handle.clone();
                                let task = tokio::spawn(async move {
                                    let app_state = h.state::<AppState>();
                                    let db_state = app_state.db.lock().await;
                                    let inserted = if let Some(db) = db_state.as_ref() {
                                        db
                                            .add_room_message(&msg_id, &room_id, &sender, content.as_bytes(), &ts)
                                            .await
                                            .unwrap_or(false)
                                    } else {
                                        false
                                    };
                                    drop(db_state);
                                    if inserted {
                                        safe_emit(&h, "room-msg", serde_json::json!({
                                            "room_id": room_id,
                                            "sender": sender,
                                            "content": content,
                                            "msg_id": msg_id,
                                            "ts": ts,
                                        }));
                                    }
                                });
                                // SEC-A01: tracked — KillPin joins this writer.
                                crate::track_task(&handle, task).await;
                            }
                            P2PEvent::RoomControl { room_id, sender, payload, control_id } => {
                                // RC10: spawn — the dispatcher authorizes and may
                                // hit the DB/network; do not stall the forwarder.
                                let h = handle.clone();
                                let task = tokio::spawn(async move {
                                    if let Ok(p) = serde_json::from_str::<crate::p2p::RoomPayload>(&payload) {
                                        crate::room_rekey::dispatch_room_topic_payload(
                                            &h, &room_id, &sender, &control_id, p,
                                        ).await;
                                    }
                                });
                                crate::track_task(&handle, task).await;
                            }
                            P2PEvent::RoomKeyStale { room_id } => {
                                // Signed envelope failed to open — our stored
                                // key is stale; ask the owner for the current one.
                                let h = handle.clone();
                                crate::track_task(&handle, tokio::spawn(async move {
                                    crate::room_control::request_key_sync(&h, &room_id).await;
                                })).await;
                            }
            ev => return crate::ev_peer::on_peer_event(ev, &handle, last_relay_status).await,
    }
}
