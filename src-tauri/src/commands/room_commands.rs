use crate::p2p::P2PCommand;
use crate::AppState;
use tauri::State;

/// Create a new encrypted room: generates a stable random room id and an
/// AES-256 room key, stores both (field-encrypted) with ourselves as
/// owner, and subscribes the node to the room's gossipsub topic.
/// The id is decoupled from the key so topic + history survive rekeying.
#[tauri::command]
pub async fn create_room(
    name: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let name = name.trim().to_string();
    if name.is_empty() || name.len() > 128 {
        return Err("Invalid room name".to_string());
    }
    let key = crate::security::room_crypto::RoomKey::generate();
    let mut id_bytes = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut id_bytes);
    let room_id = hex::encode(id_bytes);
    let my_id = state.my_id.lock().await.clone();
    // The creator is recorded as the room owner — refuse to persist a
    // placeholder identity ("Loading..." pre-P2P), which would strip the
    // creator of owner controls on every node.
    if crate::validation::parse_peer_id(&my_id).is_err() {
        return Err("P2P identity not ready — try again".to_string());
    }

    {
        let db_state = state.db.lock().await;
        if let Some(db) = db_state.as_ref() {
            db.create_room_full(&room_id, &name, &key.0, Some(&my_id), None, 0)
                .await
                .map_err(|e| e.to_string())?;
            // The owner is a member too — a member row carries our profile
            // so peers can render our name/avatar in the member list.
            let _ = db.add_room_member(&room_id, &my_id, true).await;
            if let Ok((n, a)) = db.get_profile().await {
                let _ = db
                    .set_member_profile(&room_id, &my_id, Some(&n), a.as_deref())
                    .await;
            }
        } else {
            return Err("Database not initialized".to_string());
        }
    }

    if let Some(tx) = state.p2p() {
        crate::send_p2p_cmd(&tx, P2PCommand::JoinRoom {
            room_id: room_id.clone(),
            room_key: Some(key.0),
        })
        .await
        .map_err(|e| e.to_string())?;
    } else {
        return Err("P2P not initialized".to_string());
    }

    Ok(room_id)
}

/// Join a room — only possible when we already hold its key (i.e. a
/// ratchet-encrypted invite was received and stored). Arbitrary room ids
/// cannot be joined: without the key the node could neither read nor produce
/// valid envelopes anyway.
#[tauri::command]
pub async fn join_room(
    room_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let key = {
        let db_state = state.db.lock().await;
        match db_state.as_ref() {
            Some(db) => db.get_room_key(&room_id).await.map_err(|e| e.to_string())?,
            None => return Err("Database not initialized".to_string()),
        }
    };

    let Some(key) = key else {
        return Err("No room key — join is only possible via an invite".to_string());
    };

    if let Some(tx) = state.p2p() {
        crate::send_p2p_cmd(&tx, P2PCommand::JoinRoom {
            room_id,
            room_key: Some(key),
        })
        .await
        .map_err(|e| e.to_string())?;
    } else {
        return Err("P2P not initialized".to_string());
    }
    Ok(())
}

/// Publish a sealed, signed envelope to the room topic — then fan the
/// same envelope out to every approved member as a direct typed
/// `RoomChat` message. Gossipsub is best-effort only; the direct copies
/// ride the pending/mailbox machinery so offline members receive the
/// message on their next connect. Receivers dedup by `msg_id`.
#[tauri::command]
pub async fn send_room_message(
    room_id: String,
    content: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    if content.len() > crate::p2p::MAX_DHT_MESSAGE_SIZE {
        return Err("Message too large".to_string());
    }

    let tx = state.p2p().ok_or("P2P not initialized")?;
    let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
    crate::send_p2p_cmd(&tx, P2PCommand::SendRoomChat {
        room_id: room_id.clone(),
        content: content.clone(),
        respond_to: resp_tx,
    })
    .await
    .map_err(|e| e.to_string())?;
    let envelope = resp_rx
        .await
        .map_err(|_| "P2P node dropped".to_string())??;

    // The envelope msg_id doubles as the dedup key everywhere — use it
    // for the direct copies and the local echo alike.
    let env_msg_id = serde_json::from_slice::<crate::security::room_crypto::RoomEnvelope>(&envelope)
        .map(|e| e.msg_id.clone())
        .unwrap_or_else(|_| uuid::Uuid::new_v4().to_string());

    let my_id = state.my_id.lock().await.clone();
    let members = {
        let db_state = state.db.lock().await;
        match db_state.as_ref() {
            Some(db) => db.get_room_members(&room_id).await.unwrap_or_default(),
            None => Vec::new(),
        }
    };
    for m in members
        .into_iter()
        .filter(|m| m.approved && m.peer_id != my_id)
    {
        let msg = crate::p2p::NoidMessage {
            id: env_msg_id.clone(),
            sender: my_id.clone(),
            content: String::new(),
            msg_type: crate::p2p::MessageType::RoomChat {
                room_id: room_id.clone(),
                envelope: envelope.clone(),
            },
            timestamp: Some(
                chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            ),
        };
        // F13: pending-first — direct RoomChat copies ride the pending
        // machinery; the row must exist before the send is queued.
        crate::pend_typed_message(&state, &m.peer_id, &msg).await;
        let _ = crate::send_p2p_cmd(&tx, P2PCommand::SendMessage {
                peer_id: m.peer_id,
                msg,
            })
            .await;
    }

    // Local echo — under the envelope msg_id so any bounced copy dedups.
    let db_state = state.db.lock().await;
    if let Some(db) = db_state.as_ref() {
        let _ = db
            .add_room_message(
                &env_msg_id,
                &room_id,
                &my_id,
                content.as_bytes(),
                &chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            )
            .await;
    }
    Ok(())
}

/// List rooms we hold keys for: (room_id, name).
#[tauri::command]
pub async fn list_rooms(
    state: State<'_, AppState>,
) -> Result<Vec<(String, String)>, String> {
    let db_state = state.db.lock().await;
    match db_state.as_ref() {
        Some(db) => db.list_rooms().await.map_err(|e| e.to_string()),
        None => Err("Database not initialized".to_string()),
    }
}

/// Room history: (msg_id, sender_peer_id, content, timestamp) — decrypted.
#[tauri::command]
pub async fn get_room_messages(
    room_id: String,
    state: State<'_, AppState>,
) -> Result<Vec<(String, String, String, String)>, String> {
    let db_state = state.db.lock().await;
    match db_state.as_ref() {
        Some(db) => db.get_room_messages(&room_id).await.map_err(|e| e.to_string()),
        None => Err("Database not initialized".to_string()),
    }
}
