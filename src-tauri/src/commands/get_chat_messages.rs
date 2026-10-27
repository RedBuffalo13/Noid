use crate::AppState;
use tauri::State;

#[tauri::command]
pub async fn get_chat_messages(
    peer_id: String,
    state: State<'_, AppState>,
) -> Result<Vec<(String, String, String, String)>, String> {
    log::debug!("get_chat_messages: history requested for {}", peer_id);
    // Lock-order rule: snapshot the Database (shared pool) and release the
    // global db mutex BEFORE taking `security` — commands must never hold the
    // db guard across another lock (kill_switch holds security → db; holding
    // db → security here deadlocks a KillPin wipe, see RC2).
    let db = {
        let db_state = state.db.lock().await;
        match db_state.clone() {
            Some(d) => d,
            None => return Err("Database not initialized".into()),
        }
    };

    // Get raw encrypted messages from database
    let encrypted_messages = db
        .get_messages_for_contact(&peer_id)
        .await
        .map_err(|e| e.to_string())?;
    log::debug!("get_chat_messages: loaded {} rows for {}", encrypted_messages.len(), peer_id);

    // Decrypt each message
    let security = state.security.lock().await;
    let mut decrypted_messages = Vec::new();

    for (id, sender_id, content_bytes, timestamp) in encrypted_messages {
        // Phase 3.3: On decryption failure, return a marker instead of raw ciphertext bytes.
        // Showing raw ciphertext would expose encrypted data and confuse the user.
        let decrypted_content = match security.decrypt(&content_bytes) {
            Ok(decrypted_bytes) => String::from_utf8(decrypted_bytes)
                .unwrap_or_else(|_| "[undecryptable: invalid UTF-8]".to_string()),
            Err(_) => "[undecryptable]".to_string(),
        };

        decrypted_messages.push((id, sender_id, decrypted_content, timestamp));
    }

    Ok(decrypted_messages)
}
