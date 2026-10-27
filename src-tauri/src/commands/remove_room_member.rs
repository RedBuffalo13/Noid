use crate::p2p::{P2PCommand, RoomControlPayload, RoomPayload};
use crate::room_control::send_room_control;
use crate::AppState;
use tauri::State;

/// Owner-only kick: removes the member row, notifies the kicked peer
/// (ratchet-encrypted `Removed`), then rekeys so the removed key no
/// longer decrypts future room traffic.
#[tauri::command]
pub async fn remove_room_member(
    app: tauri::AppHandle,
    room_id: String,
    peer_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    crate::validation::bounded_str("room_id", &room_id, 64)?;
    crate::validation::parse_peer_id(&peer_id)?;
    {
        let my_id = state.my_id.lock().await.clone();
        let db_state = state.db.lock().await;
        let Some(db) = db_state.as_ref() else {
            return Err("Database not initialized".to_string());
        };
        let info = db
            .get_room_info(&room_id)
            .await
            .map_err(|e| e.to_string())?
            .ok_or("Unknown room")?;
        if info.owner.as_deref() != Some(my_id.as_str()) {
            return Err("Only the room owner can remove members".to_string());
        }
        if peer_id == my_id {
            return Err("The owner cannot kick themselves — delete the room".to_string());
        }
        db.remove_room_member(&room_id, &peer_id)
            .await
            .map_err(|e| e.to_string())?;
    }

    // Tell the kicked peer first (best effort — they also stop being able
    // to read the room after the rekey below).
    let my_id = state.my_id.lock().await.clone();
    let _ = send_room_control(
        &app,
        &room_id,
        &peer_id,
        &RoomControlPayload::Removed { by: my_id },
    )
    .await;

    // Rekey BEFORE the in-topic announcement — MemberRemoved is sealed
    // under the new key, invisible to the kicked peer.
    crate::room_rekey::rekey_room(&app, &room_id, std::slice::from_ref(&peer_id)).await;

    if let Some(tx) = state.p2p() {
        let _ = crate::send_p2p_cmd(&tx, P2PCommand::SendRoomPayload {
                room_id,
                payload: RoomPayload::MemberRemoved { peer_id },
            })
            .await;
    }
    Ok(())
}
