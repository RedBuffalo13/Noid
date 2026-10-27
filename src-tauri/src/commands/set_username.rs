use crate::p2p::{P2PCommand, DHTUserRecord};
use crate::AppState;
use tauri::State;

fn validate_username(username: &str) -> Result<(), String> {
    if username.len() < 3 || username.len() > 32 {
        return Err("Username must be 3-32 characters".into());
    }
    if !username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err("Username can only contain letters, numbers, _ and -".into());
    }
    if username.starts_with('-') || username.starts_with('_') {
        return Err("Username cannot start with - or _".into());
    }
    Ok(())
}

#[tauri::command]
pub async fn set_username(
    username: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    validate_username(&username)?;

    log::debug!("set_username: setting username to '{}'", username);

    let old_username = {
        let db_state = state.db.lock().await;
        if let Some(db) = db_state.as_ref() {
            db.get_username().await.map_err(|e| e.to_string())?
        } else {
            return Err("Database not initialized".into());
        }
    };

    if let Some(ref old) = old_username {
        if old != &username {
            if let Some(tx) = state.p2p() {
                let _ = crate::send_p2p_cmd(&tx, P2PCommand::UnpublishUsername {
                    username: old.clone(),
                }).await;
            }
        }
    }

    {
        let db_state = state.db.lock().await;
        if let Some(db) = db_state.as_ref() {
            db.set_username(&username).await.map_err(|e| e.to_string())?;
            db.set_username_published(false).await.map_err(|e| e.to_string())?;
        }
    }

    // Publish username to DHT
    {
        let my_id = state.my_id.lock().await.clone();
        let (nickname, avatar) = {
            let db_state = state.db.lock().await;
            if let Some(db) = db_state.as_ref() {
                match db.get_profile().await {
                    Ok((nick, av)) => (nick, av),
                    Err(_) => (username.clone(), None),
                }
            } else {
                (username.clone(), None)
            }
        };

        let short_id = my_id[my_id.len() - 4..].to_string();
        let record = DHTUserRecord {
            peer_id: my_id,
            // The publisher also binds the username into the signed payload.
            username: username.clone(),
            nickname,
            avatar,
            short_id,
            updated_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            signature: None,
            revoked: false,
        };

        if let Some(tx) = state.p2p() {
            let _ = crate::send_p2p_cmd(&tx, P2PCommand::PublishUsername {
                username: username.clone(),
                record,
            }).await;
            log::debug!("Username '{}' publish command sent to P2P", username);
        }
    }

    Ok(())
}
