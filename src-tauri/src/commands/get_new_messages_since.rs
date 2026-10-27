use crate::AppState;
use tauri::State;

#[tauri::command]
pub async fn get_new_messages_since(
    peer_id: String,
    since_time: String,  // ISO 8601 timestamp
    state: State<'_, AppState>,
) -> Result<Vec<(String, String, String, String)>, String> {
    // Lock-order rule: db snapshot first, security lock after (never hold the
    // db guard across `security.lock()` — see get_chat_messages / RC2).
    let db = {
        let db_state = state.db.lock().await;
        match db_state.clone() {
            Some(d) => d,
            None => return Err("Database not initialized".into()),
        }
    };

    // Get raw encrypted messages from database that are newer than the specified time
    let encrypted_messages = db
        .get_messages_for_contact_since(&peer_id, &since_time)
        .await
        .map_err(|e| e.to_string())?;

    // Decrypt each message
    let security = state.security.lock().await;
    let mut decrypted_messages = Vec::new();

    for (id, sender_id, content_bytes, timestamp) in encrypted_messages {
        // Phase 3.3: marker on decrypt failure — raw ciphertext never
        // leaks to the UI (see get_chat_messages).
        let decrypted_content = match security.decrypt(&content_bytes) {
            Ok(decrypted_bytes) => String::from_utf8(decrypted_bytes)
                .unwrap_or_else(|_| "[undecryptable: invalid UTF-8]".to_string()),
            Err(_) => "[undecryptable]".to_string(),
        };

        decrypted_messages.push((id, sender_id, decrypted_content, timestamp));
    }

    Ok(decrypted_messages)
}
