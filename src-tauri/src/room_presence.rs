//! Room presence — self-announce of the local profile inside room topics.
//!
//! Members learn each other's display name/avatar from `MemberProfile`
//! announces (sealed envelopes, bound to the envelope signer). Announces
//! happen on join, on profile change, and on startup rejoin so member
//! lists converge without a dedicated sync round.

use crate::p2p::{P2PCommand, RoomPayload};
use crate::AppState;
use tauri::Manager;

/// Publish our current display name/avatar to a room topic. Receivers
/// bind the announce to the envelope signer — a peer can only ever
/// rewrite its own member-profile row.
pub(crate) async fn announce_room_profile(handle: &tauri::AppHandle, room_id: &str) {
    let app_state = handle.state::<AppState>();
    let my_id = app_state.my_id.lock().await.clone();
    if my_id.is_empty() {
        return;
    }
    let (name, avatar) = {
        let db_state = app_state.db.lock().await;
        match db_state.as_ref() {
            Some(db) => db
                .get_profile()
                .await
                .map(|(n, a)| (Some(n), a))
                .unwrap_or((None, None)),
            None => (None, None),
        }
    };
    if let Some(tx) = app_state.p2p() {
        let _ = crate::send_p2p_cmd(&tx, P2PCommand::SendRoomPayload {
                room_id: room_id.to_string(),
                payload: RoomPayload::MemberProfile {
                    peer_id: my_id,
                    name,
                    avatar,
                },
            })
            .await;
    }
}

/// Announce our profile to every room we hold a key for — used after
/// profile changes and on startup rejoin.
pub(crate) async fn announce_all_rooms(handle: &tauri::AppHandle) {
    let rooms = {
        let app_state = handle.state::<AppState>();
        let db_state = app_state.db.lock().await;
        match db_state.as_ref() {
            Some(db) => db.list_rooms().await.unwrap_or_default(),
            None => Vec::new(),
        }
    };
    for (room_id, _) in rooms {
        announce_room_profile(handle, &room_id).await;
    }
}
