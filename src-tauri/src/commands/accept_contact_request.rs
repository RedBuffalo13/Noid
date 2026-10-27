use crate::p2p::{MessageType, P2PCommand, NoidMessage};
use crate::AppState;
use tauri::State;
use uuid::Uuid;

#[tauri::command]
pub async fn accept_contact_request(
    peer_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    crate::validation::parse_peer_id(&peer_id)?;
    let (nickname, avatar) = {
        let db_state = state.db.lock().await;
        if let Some(db) = db_state.as_ref() {
            if let Ok(profile) = db.get_profile().await {
                (profile.0, profile.1)
            } else {
                log::warn!("Failed to get profile, using default");
                ("User".to_string(), None)
            }
        } else {
            log::warn!("Database not initialized when getting profile");
            ("User".to_string(), None)
        }
    };

    let my_id = state.my_id.lock().await.clone();
    let msg = NoidMessage {
        sender: my_id,
        content: "CONTACT_ACCEPTED".into(),
        msg_type: MessageType::ContactAccept { nickname, avatar },
        timestamp: Some(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
        id: Uuid::new_v4().to_string(),
    };

    {
        let db_state = state.db.lock().await;
        if let Some(db) = db_state.as_ref() {
            let mut contact_nick = "User".to_string();
            let mut contact_avatar = None;

            if let Ok(requests) = db.get_contact_requests().await {
                if let Some(req) = requests.iter().find(|r| r.0 == peer_id) {
                    contact_nick = req.2.clone();
                    contact_avatar = req.3.clone();
                }
            }

            if let Err(e) = db
                .add_contact(&peer_id, &contact_nick, contact_avatar.as_deref())
                .await
            {
                log::error!("Failed to add contact to database: {}", e);
                return Err(format!("Failed to add contact: {}", e));
            }
            if let Err(e) = db.delete_contact_request(&peer_id).await {
                log::error!("Failed to delete contact request: {}", e);
            }
        } else {
            log::error!("Database not initialized when accepting contact");
            return Err("Database not initialized".into());
        }
    }

    {
        if let Some(tx) = state.p2p() {
            let _ = crate::send_p2p_cmd(&tx, P2PCommand::SendPublicKey { peer_id: peer_id.clone() }).await;
        }
    }

    crate::pend_typed_message(&state, &peer_id, &msg).await;
    crate::send_message_to_peer(&state, &peer_id, msg).await?;
    Ok(())
}
