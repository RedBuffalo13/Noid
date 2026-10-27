use crate::p2p::{DHTUserRecord, P2PCommand};
use crate::AppState;
use tauri::State;

#[tauri::command]
pub async fn update_profile(
    app: tauri::AppHandle,
    nickname: String,
    avatar: Option<String>,
    state: State<'_, AppState>,
) -> Result<(), String> {
    crate::validation::bounded_str("nickname", &nickname, 128)?;
    // Avatars are data-URI/base64 payloads — bound them, but generously.
    if let Some(ref a) = avatar {
        crate::validation::bounded_str("avatar", a, 400_000)?;
    }
    let db_state = state.db.lock().await;
    if let Some(db) = db_state.as_ref() {
        db.update_profile(&nickname, avatar.as_deref())
            .await
            .map_err(|e| e.to_string())?;
        // If a public username is already published, re-announce it with the
        // new display name — otherwise peers keep seeing the stale nickname
        // until the next periodic republish (up to 30 min).
        let username = db.get_username().await.map_err(|e| e.to_string())?;
        let effective_avatar = if username.is_some() {
            db.get_profile().await.ok().and_then(|(_, a)| a)
        } else {
            None
        };
        drop(db_state);
        log::info!("Profile updated: nickname saved (len={})", nickname.len());
        // Refresh our member profile in every room — sealed MemberProfile
        // announces are bound to the envelope signer.
        crate::room_presence::announce_all_rooms(&app).await;
        if let Some(username) = username {
            let my_id = state.my_id.lock().await.clone();
            if !my_id.is_empty() {
                let short_id: String = my_id[my_id.len() - 4..].to_string();
                let record = DHTUserRecord {
                    peer_id: my_id,
                    username: username.clone(),
                    nickname: nickname.clone(),
                    avatar: effective_avatar,
                    short_id,
                    updated_at: chrono::Utc::now()
                        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                    signature: None,
            revoked: false,
                };
                if let Some(tx) = state.p2p() {
                    let _ = crate::send_p2p_cmd(&tx, P2PCommand::PublishUsername { username, record })
                        .await;
                }
            }
        }
        Ok(())
    } else {
        Err("Database not initialized".into())
    }
}
