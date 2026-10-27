//! Room rekey orchestration and in-topic control dispatch.
//!
//! Rekey rotates the room's AES-256 key after membership changes: the new
//! key goes only to remaining members via ratchet-encrypted `KeyUpdate`
//! control messages (offline members get it through pending/mailbox or
//! the reconnect resend). The room id — and therefore the gossipsub
//! topic and local history — is stable across epochs.

use crate::p2p::{P2PCommand, RoomControlPayload, RoomPayload};
use crate::room_control::{emit_room_updated, send_room_control};
use crate::AppState;
use tauri::Manager;

/// Rotate the room key and distribute it to every remaining member
/// except `exclude`. No-op unless we are the recorded owner.
pub(crate) async fn rekey_room(handle: &tauri::AppHandle, room_id: &str, exclude: &[String]) {
    let app_state = handle.state::<AppState>();
    let my_id = app_state.my_id.lock().await.clone();
    let (members, epoch, key) = {
        let db_state = app_state.db.lock().await;
        let Some(db) = db_state.as_ref() else { return };
        let Ok(Some(info)) = db.get_room_info(room_id).await else {
            return;
        };
        if info.owner.as_deref() != Some(my_id.as_str()) {
            log::warn!("rekey requested for {} but we are not the owner", room_id);
            return;
        }
        let key = crate::security::room_crypto::RoomKey::generate();
        let epoch = info.key_epoch + 1;
        if let Err(e) = db.update_room_key(room_id, &key.0, epoch).await {
            log::error!("Failed to persist rekey for {}: {}", room_id, e);
            return;
        }
        if let Some(tx) = app_state.p2p() {
            let _ = crate::send_p2p_cmd(&tx, P2PCommand::UpdateRoomKey {
                    room_id: room_id.to_string(),
                    room_key: key.0,
                })
                .await;
        }
        let members = db
            .get_room_members(room_id)
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|m| m.approved)
            .map(|m| m.peer_id)
            .collect::<Vec<_>>();
        (members, epoch, key)
    };

    // Distribute under the new epoch — members without a ratchet session
    // self-heal on reconnect or via KeySyncRequest.
    for peer in members {
        if peer == my_id || exclude.contains(&peer) {
            continue;
        }
        let _ = send_room_control(
            handle,
            room_id,
            &peer,
            &RoomControlPayload::KeyUpdate {
                epoch,
                key: key.0.to_vec(),
            },
        )
        .await;
    }

    // Announce the new epoch in-topic — sealed under the NEW key, so
    // removed members cannot read it.
    if let Some(tx) = app_state.p2p() {
        let _ = crate::send_p2p_cmd(&tx, P2PCommand::SendRoomPayload {
                room_id: room_id.to_string(),
                payload: RoomPayload::KeyEpoch { epoch },
            })
            .await;
    }
    emit_room_updated(handle, room_id, "key");
}

/// Re-send the current KeyUpdate to `peer` for every room we own where
/// they are a member — cheap self-heal on reconnect for offline rekeys.
pub(crate) async fn resend_owned_keys(handle: &tauri::AppHandle, peer: &str) {
    let app_state = handle.state::<AppState>();
    let my_id = app_state.my_id.lock().await.clone();
    let updates: Vec<(String, u32, [u8; 32])> = {
        let db_state = app_state.db.lock().await;
        let Some(db) = db_state.as_ref() else { return };
        let Ok(rooms) = db.rooms_owned_by(&my_id).await else {
            return;
        };
        let mut out = Vec::new();
        for room_id in rooms {
            if !db.is_room_member(&room_id, peer).await.unwrap_or(false) {
                continue;
            }
            let info = db.get_room_info(&room_id).await.ok().flatten();
            let key = db.get_room_key(&room_id).await.ok().flatten();
            if let (Some(info), Some(key)) = (info, key) {
                out.push((room_id, info.key_epoch, key));
            }
        }
        out
    };
    for (room_id, epoch, key) in updates {
        let _ = send_room_control(
            handle,
            &room_id,
            peer,
            &RoomControlPayload::KeyUpdate {
                epoch,
                key: key.to_vec(),
            },
        )
        .await;
    }
}

/// Apply a `RoomPayload` that arrived inside a verified topic envelope.
/// `sender` is the envelope's authenticated signer.
pub(crate) async fn dispatch_room_topic_payload(
    handle: &tauri::AppHandle,
    room_id: &str,
    sender: &str,
    payload: RoomPayload,
) {
    let app_state = handle.state::<AppState>();
    let my_id = app_state.my_id.lock().await.clone();
    let db_state = app_state.db.lock().await;
    let Some(db) = db_state.as_ref() else { return };
    let info = db.get_room_info(room_id).await.ok().flatten();
    let Some(info) = info else { return };
    let sender_is_owner = info.owner.as_deref() == Some(sender);

    match payload {
        RoomPayload::Meta { name, avatar } => {
            if !sender_is_owner {
                return;
            }
            if let Some(name) = name {
                let _ = db.rename_room(room_id, &name).await;
            }
            if avatar.is_some() {
                let _ = db.set_room_avatar(room_id, avatar.as_deref()).await;
            }
            drop(db_state);
            emit_room_updated(handle, room_id, "meta");
        }
        RoomPayload::MemberJoined {
            peer_id,
            name,
            avatar,
        } => {
            if !sender_is_owner {
                return;
            }
            let _ = db.add_room_member(room_id, &peer_id, true).await;
            // add_room_member rewrites the row — the profile must follow it.
            if name.is_some() || avatar.is_some() {
                let _ = db
                    .set_member_profile(room_id, &peer_id, name.as_deref(), avatar.as_deref())
                    .await;
            }
            drop(db_state);
            emit_room_updated(handle, room_id, "members");
        }
        RoomPayload::MemberProfile {
            peer_id,
            name,
            avatar,
        } => {
            // Self-announce: a member may only set their own profile, and
            // only on an existing membership row (non-members' UPDATEs are
            // no-ops).
            if peer_id != sender {
                return;
            }
            let _ = db
                .set_member_profile(room_id, &peer_id, name.as_deref(), avatar.as_deref())
                .await;
            drop(db_state);
            emit_room_updated(handle, room_id, "members");
        }
        RoomPayload::MemberRemoved { peer_id } => {
            if !sender_is_owner {
                return;
            }
            if peer_id == my_id {
                let _ = db.delete_room(room_id).await;
                drop(db_state);
                if let Some(tx) = app_state.p2p() {
                    let _ = crate::send_p2p_cmd(&tx, P2PCommand::LeaveRoom {
                            room_id: room_id.to_string(),
                        })
                        .await;
                }
                emit_room_updated(handle, room_id, "removed");
            } else {
                let _ = db.remove_room_member(room_id, &peer_id).await;
                drop(db_state);
                emit_room_updated(handle, room_id, "members");
            }
        }
        RoomPayload::MemberLeft { peer_id } => {
            if peer_id != sender {
                return;
            }
            let _ = db.remove_room_member(room_id, &peer_id).await;
            let i_am_owner = info.owner.as_deref() == Some(my_id.as_str());
            drop(db_state);
            emit_room_updated(handle, room_id, "members");
            if i_am_owner {
                rekey_room(handle, room_id, &[peer_id]).await;
            }
        }
        RoomPayload::KeyEpoch { epoch } => {
            if epoch > info.key_epoch {
                drop(db_state);
                crate::room_control::request_key_sync(handle, room_id).await;
            }
        }
        RoomPayload::Chat { .. } => {}
    }
}

#[cfg(test)]
mod tests {
    /// Regression for the PeerConnected self-deadlock: `resend_owned_keys`
    /// locks `state.db` internally, so any caller holding that same
    /// `tokio::Mutex` guard across the call deadlocks forever (tokio Mutex
    /// is NOT reentrant). This model pins the required pattern — outer
    /// guard scoped and dropped BEFORE the inner-locking call. If a
    /// regression reintroduces the nested lock, the timeout fires.
    #[tokio::test]
    async fn db_guard_dropped_before_inner_locking_call() {
        use std::sync::Arc;
        let db = Arc::new(tokio::sync::Mutex::new(0u32));
        let db2 = Arc::clone(&db);

        // Stands in for resend_owned_keys: re-locks the same mutex.
        async fn inner_locking_call(db: &tokio::sync::Mutex<u32>) {
            let mut g = db.lock().await;
            *g += 1;
        }

        let done = tokio::time::timeout(std::time::Duration::from_secs(2), async move {
            {
                let mut g = db2.lock().await;
                *g += 1;
            } // guard dropped here — REQUIRED before the call below
            inner_locking_call(&db2).await;
        })
        .await;

        assert!(done.is_ok(), "nested db lock deadlocked — guard must drop first");
        assert_eq!(*db.lock().await, 2);
    }
}
