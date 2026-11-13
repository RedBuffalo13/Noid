//! Post-login retry of buffered inbound ratchet messages. Extracted from
//! lib.rs (Q05/A5b); body moved verbatim.

use tauri::Manager;

use crate::{safe_emit, AppState, BufferedInbound};

/// available (called after login and after any successful ratchet decrypt).
/// Without this, offline redelivery that arrives before login is lost —
/// the sender deletes its pending copy after the send succeeds.
pub async fn retry_undecrypted_messages(handle: &tauri::AppHandle) {
    let app_state = handle.state::<AppState>();

    let buffered: Vec<(String, Vec<BufferedInbound>)> = {
        let mut buf = app_state.undecrypted_inbound.lock().await;
        if buf.is_empty() {
            return;
        }
        std::mem::take(&mut *buf).into_iter().collect()
    };

    // RC2: snapshot the Database — the global db guard must not be held
    // across `security`/`my_id`/`undecrypted_inbound` locks below.
    let db = match app_state.db.lock().await.clone() {
        Some(db) => db,
        None => {
            // DB still unavailable — put the messages back for a later retry.
            let mut buf = app_state.undecrypted_inbound.lock().await;
            for (peer, msgs) in buffered {
                buf.entry(peer).or_default().extend(msgs);
            }
            return;
        }
    };

    for (from, msgs) in buffered {
        if !app_state.ratchet_sessions.has_session(&from).await {
            let _ = app_state.ratchet_sessions.load_session(&db, &from).await;
        }
        for m in msgs {
            match app_state.ratchet_sessions.decrypt(&from, &m.msg).await {
                Ok(plaintext) => {
                    if db.message_exists(&m.id).await.unwrap_or(false) {
                        continue;
                    }
                    let text = String::from_utf8_lossy(&plaintext).to_string();
                    let my_id = app_state.my_id.lock().await.clone();
                    let ts = m.timestamp.clone().unwrap_or_else(|| {
                        chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
                    });
                    // DB28/F20: emit only after a durable insert — a failed
                    // persist used to show a phantom message that vanished on
                    // restart.
                    let persisted = {
                        let security_guard = app_state.security.lock().await;
                        match security_guard.encrypt(&plaintext) {
                            Ok(enc) => db
                                .add_message_with_timestamp(&m.id, &from, &my_id, &enc, &ts)
                                .await
                                .map(|_| true)
                                .unwrap_or(false),
                            Err(e) => {
                                log::error!("Cannot encrypt buffered message {} for storage: {}", m.id, e);
                                false
                            }
                        }
                    };
                    let _ = app_state.ratchet_sessions.save_session(&db, &from).await;
                    if persisted {
                        log::debug!("Delivered buffered ratchet message {} from {}", m.id, from);
                        safe_emit(handle, "chat-msg", serde_json::json!({
                            "from": &from,
                            "data": {
                                "content": &text,
                                "id": &m.id,
                                "sender": &from,
                                "timestamp": &ts,
                            },
                        }));
                    } else {
                        log::warn!("Buffered message {} not persisted — not emitted", m.id);
                    }
                }
                Err(e) => {
                    log::warn!("Buffered message {} from {} still undecryptable: {}", m.id, from, e);
                    // The session may still arrive later via X3DH — re-buffer.
                    // RC24: honor the same 500-entry cap as the inbound
                    // buffer — a permanently undecryptable flood must not
                    // grow memory without bound.
                    let mut buf = app_state.undecrypted_inbound.lock().await;
                    let total: usize = buf.values().map(|v| v.len()).sum();
                    if total < 500 {
                        buf.entry(from.clone()).or_default().push(m);
                    }
                }
            }
        }
    }
}
