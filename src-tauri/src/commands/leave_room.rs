use crate::p2p::{P2PCommand, RoomControlPayload, RoomPayload};
use crate::room_control::send_room_control;
use crate::AppState;
use tauri::State;

/// Voluntary leave: announces the leave in-topic (still under the current
/// key — members see it immediately), notifies the owner directly (triggers
/// their rekey), then unsubscribes and wipes the room locally.
/// The owner cannot leave — they must delete the room instead.
#[tauri::command]
pub async fn leave_room(
    app: tauri::AppHandle,
    room_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let (my_id, owner) = {
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
        if info.owner.as_deref() == Some(my_id.as_str()) {
            return Err("The owner cannot leave — delete the room".to_string());
        }
        (my_id, info.owner)
    };

    if let Some(tx) = state.p2p() {
        let _ = crate::send_p2p_cmd(&tx, P2PCommand::SendRoomPayload {
                room_id: room_id.clone(),
                payload: RoomPayload::MemberLeft {
                    peer_id: my_id.clone(),
                },
            })
            .await;
    }
    if let Some(owner) = owner {
        let _ = send_room_control(
            &app,
            &room_id,
            &owner,
            &RoomControlPayload::MemberLeft { peer_id: my_id },
        )
        .await;
    }

    {
        let db_state = state.db.lock().await;
        if let Some(db) = db_state.as_ref() {
            db.delete_room(&room_id).await.map_err(|e| e.to_string())?;
        }
    }
    if let Some(tx) = state.p2p() {
        let _ = crate::send_p2p_cmd(&tx, P2PCommand::LeaveRoom { room_id }).await;
    }
    Ok(())
}
