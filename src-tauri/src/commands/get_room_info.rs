use crate::db::room_store::{RoomInfo, RoomMember};
use crate::AppState;
use tauri::State;

/// Room details for the settings UI: decrypted record + member list.
#[derive(serde::Serialize)]
pub struct RoomDetails {
    pub id: String,
    pub name: String,
    pub avatar: Option<String>,
    pub owner: Option<String>,
    pub key_epoch: u32,
    /// Members with approval state and announced profiles (name/avatar).
    pub members: Vec<RoomMember>,
}

impl From<RoomInfo> for RoomDetails {
    fn from(r: RoomInfo) -> Self {
        Self {
            id: r.id,
            name: r.name,
            avatar: r.avatar,
            owner: r.owner,
            key_epoch: r.key_epoch,
            members: Vec::new(),
        }
    }
}

/// Decrypted room record + member list. Fails when the room is unknown.
#[tauri::command]
pub async fn get_room_info(
    room_id: String,
    state: State<'_, AppState>,
) -> Result<RoomDetails, String> {
    let db_state = state.db.lock().await;
    let Some(db) = db_state.as_ref() else {
        return Err("Database not initialized".to_string());
    };
    let mut info = db
        .get_room_info(&room_id)
        .await
        .map_err(|e| e.to_string())?
        .ok_or("Unknown room")?;
    // Normalize a non-PeerId owner (pre-P2P "Loading..." placeholder) to
    // None — ownerless rooms show "owner unknown" and expose no admin
    // controls until the owner backfill / Meta{owner} convergence sets one.
    if info
        .owner
        .as_deref()
        .map(|o| crate::validation::parse_peer_id(o).is_err())
        .unwrap_or(false)
    {
        info.owner = None;
    }
    let mut details = RoomDetails::from(info);
    details.members = db
        .get_room_members(&room_id)
        .await
        .map_err(|e| e.to_string())?;
    Ok(details)
}
