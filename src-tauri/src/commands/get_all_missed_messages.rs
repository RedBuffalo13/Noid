use crate::AppState;
use std::collections::HashMap;
use tauri::State;

/// (id, sender, content, timestamp) rows grouped by peer.
type MissedByPeer = HashMap<String, Vec<(String, String, String, String)>>;

#[tauri::command]
pub async fn get_all_missed_messages(
    state: State<'_, AppState>,
) -> Result<MissedByPeer, String> {
    // Lock-order rule: db snapshot first — the security and my_id locks are
    // taken only after the global db guard is released (RC2).
    let db = state.require_db().await?;

    // Get the last sync time for this user (RC18: SQL moved to db layer)
    let last_sync_time = db.get_last_sync_time().await.map_err(|e| e.to_string())?;

    // Get all contacts to fetch messages from
    let contacts = db.get_contacts().await.map_err(|e| e.to_string())?;

    let mut all_missed_messages = HashMap::new();
    let my_id = state.my_id.lock().await.clone();

    // Decrypt each message
    let security = state.security.lock().await;

    // DB3: the cursor only advances to the max timestamp we actually
    // returned — never to `now`. A message inserted between the SELECT and
    // a `now`-write was skipped forever; a far-future wire timestamp would
    // poison the cursor permanently.
    let mut max_seen_ts: Option<String> = None;

    for (peer_id, _, _) in contacts {
        // Get raw encrypted messages from database that are newer than the last sync time
        let encrypted_messages = db
            .get_messages_for_contact_since(&peer_id, &last_sync_time)
            .await
            .map_err(|e| e.to_string())?;

        let mut decrypted_messages = Vec::new();

        for (id, sender_id, content_bytes, timestamp) in encrypted_messages {
            // Only include messages sent TO this user (not from)
            if sender_id != my_id {
                if max_seen_ts.as_deref() < Some(timestamp.as_str()) {
                    max_seen_ts = Some(timestamp.clone());
                }
                // Phase 3.3: Return marker instead of raw ciphertext on decryption failure
                let decrypted_content = match security.decrypt(&content_bytes) {
                    Ok(decrypted_bytes) => String::from_utf8(decrypted_bytes)
                        .unwrap_or_else(|_| "[undecryptable: invalid UTF-8]".to_string()),
                    Err(_) => "[undecryptable]".to_string(),
                };

                decrypted_messages.push((id, sender_id, decrypted_content, timestamp));
            }
        }

        if !decrypted_messages.is_empty() {
            all_missed_messages.insert(peer_id, decrypted_messages);
        }
    }
    drop(security);

    // Advance the cursor to the highest delivered timestamp, clamped to
    // local now (a poisoned far-future wire ts must not wedge it). With an
    // empty result set the cursor stays put — no rows were missed.
    if let Some(ts) = max_seen_ts {
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let cursor = if ts > now { now } else { ts };
        if cursor > last_sync_time {
            db.set_last_sync_time(&cursor)
                .await
                .map_err(|e| e.to_string())?;
        }
    }

    Ok(all_missed_messages)
}
