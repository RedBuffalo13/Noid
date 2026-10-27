//! Room control plane — ratchet-encrypted direct messages between two
//! peers carrying `RoomControlPayload`. Because the payload is wrapped at
//! send time, a failed direct send can be re-pended and routed through
//! the recipient's mailbox exactly like chat messages (the mailbox only
//! ever sees the wrapped bytes).

use crate::p2p::{MessageType, NoidMessage, P2PCommand, RoomControlPayload};
use crate::{safe_emit, AppState};
use tauri::Manager;

/// Ratchet-wrap `payload` and send it as a `RoomControl` request to
/// `peer_id`. Requires an established Double Ratchet session — callers
/// skip (and log) members without one; they self-heal via KeySyncRequest
/// or the reconnect resend.
pub(crate) async fn send_room_control(
    handle: &tauri::AppHandle,
    room_id: &str,
    peer_id: &str,
    payload: &RoomControlPayload,
) -> Result<(), String> {
    let app_state = handle.state::<AppState>();
    let body = serde_json::to_vec(payload).map_err(|e| e.to_string())?;

    // DHT-06: an in-memory miss is not fatal — the session may live on
    // disk (restart/eviction); restore it before giving up. A real miss
    // triggers the FetchPrekeyBundle recovery the same way chat does.
    if !app_state.ratchet_sessions.has_session(peer_id).await {
        if let Some(db) = app_state.db.lock().await.as_ref() {
            let _ = app_state.ratchet_sessions.load_session(db, peer_id).await;
        }
        if !app_state.ratchet_sessions.has_session(peer_id).await {
            if let Some(tx) = app_state.p2p() {
                let _ = crate::send_p2p_cmd(&tx, P2PCommand::FetchPrekeyBundle {
                    peer_id: peer_id.to_string(),
                })
                .await;
            }
            return Err("No E2EE session with this peer".to_string());
        }
    }

    let wrapped = match app_state.ratchet_sessions.encrypt(peer_id, &body).await {
        Ok(Some(m)) => serde_json::to_vec(&m).map_err(|e| e.to_string())?,
        _ => return Err("No E2EE session with this peer".to_string()),
    };

    {
        let db_state = app_state.db.lock().await;
        if let Some(db) = db_state.as_ref() {
            let _ = app_state.ratchet_sessions.save_session(db, peer_id).await;
        }
    }

    let my_id = app_state.my_id.lock().await.clone();
    let msg = NoidMessage {
        sender: my_id,
        content: String::new(),
        msg_type: MessageType::RoomControl {
            room_id: room_id.to_string(),
            wrapped_payload: wrapped,
        },
        timestamp: Some(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
        id: uuid::Uuid::new_v4().to_string(),
    };

    // F13: pending-first — a crash between queue and failure must not
    // lose the control payload.
    crate::pend_typed_message_h(handle, peer_id, &msg).await;
    let tx = app_state.p2p().ok_or("P2P not initialized")?;
    crate::send_p2p_cmd(&tx, P2PCommand::SendMessage {
        peer_id: peer_id.to_string(),
        msg,
    })
    .await
    .map_err(|e| e.to_string())
}

/// Apply an unwrapped `RoomControlPayload` received from `from`.
/// Every mutating action verifies the sender's role against the stored
/// room record — control messages are authenticated (ratchet unwrap)
/// but authorization still lives in the local membership model.
pub(crate) async fn dispatch_room_control(
    handle: &tauri::AppHandle,
    room_id: &str,
    from: &str,
    payload: RoomControlPayload,
) {
    let app_state = handle.state::<AppState>();
    let my_id = app_state.my_id.lock().await.clone();
    let db_state = app_state.db.lock().await;
    let Some(db) = db_state.as_ref() else { return };
    let info = db.get_room_info(room_id).await.ok().flatten();
    let Some(info) = info else {
        // A KeyUpdate for a room we never joined is meaningless — drop it.
        log::debug!("RoomControl for unknown room {} — ignored", room_id);
        return;
    };
    let is_owner = info.owner.as_deref() == Some(from);
    let i_am_owner = info.owner.as_deref() == Some(my_id.as_str());

    match payload {
        RoomControlPayload::KeyUpdate { epoch, key } => {
            // Only the recorded owner may rotate the key — a member-issued
            // KeyUpdate would fork the room's key space.
            if !is_owner {
                log::warn!("KeyUpdate for {} from non-owner {} — ignored", room_id, from);
                return;
            }
            // Idempotent: applies only when strictly newer — replayed or
            // reordered KeyUpdates are no-ops.
            if epoch <= info.key_epoch {
                return;
            }
            let Ok(key) = <[u8; 32]>::try_from(key.as_slice()) else {
                log::warn!("KeyUpdate for {} has malformed key — ignored", room_id);
                return;
            };
            let _ = db.update_room_key(room_id, &key, epoch).await;
            drop(db_state);
            if let Some(tx) = app_state.p2p() {
                let _ = crate::send_p2p_cmd(&tx, P2PCommand::UpdateRoomKey {
                        room_id: room_id.to_string(),
                        room_key: key,
                    })
                    .await;
            }
            emit_room_updated(handle, room_id, "key");
        }
        RoomControlPayload::Removed { .. } | RoomControlPayload::Deleted => {
            // Only the recorded owner may kick members or delete the room.
            if !is_owner {
                log::warn!("Non-owner {} tried to end room {} — ignored", from, room_id);
                return;
            }
            let _ = db.delete_room(room_id).await;
            drop(db_state);
            if let Some(tx) = app_state.p2p() {
                let _ = crate::send_p2p_cmd(&tx, P2PCommand::LeaveRoom {
                        room_id: room_id.to_string(),
                    })
                    .await;
            }
            emit_room_updated(handle, room_id, "removed");
        }
        RoomControlPayload::MemberLeft { peer_id } => {
            // A leave notice is only valid when sent BY the leaver.
            if peer_id != from {
                return;
            }
            let _ = db.remove_room_member(room_id, &peer_id).await;
            drop(db_state);
            emit_room_updated(handle, room_id, "members");
            if i_am_owner {
                crate::room_rekey::rekey_room(handle, room_id, &[peer_id]).await;
            }
        }
        RoomControlPayload::Meta { name, avatar, owner } => {
            // Owner convergence for legacy ownerless rooms: a self-
            // declared owner is adopted ONLY while our local record has
            // no valid owner and only when the claim matches the
            // ratchet-authenticated sender. A present valid owner
            // ignores it entirely — no takeover surface.
            let mut owner_now = info.owner.clone();
            let owner_valid = info
                .owner
                .as_deref()
                .map(|o| crate::validation::parse_peer_id(o).is_ok())
                .unwrap_or(false);
            // The backfill only self-assigns when the creator is NOT in
            // the member list — mirror that check receiver-side: a peer
            // who IS a member here can never declare ownership.
            let sender_is_member = db.is_room_member(room_id, from).await.unwrap_or(true);
            if !owner_valid
                && !sender_is_member
                && owner.as_deref() == Some(from)
                && db
                    .set_room_owner_if_unset(room_id, info.owner.as_deref(), from)
                    .await
                    .unwrap_or(false)
            {
                log::info!("Room {}: owner {} set via Meta convergence", room_id, from);
                owner_now = Some(from.to_string());
            }
            if owner_now.as_deref() != Some(from) {
                log::warn!("Non-owner {} sent room meta for {} — ignored", from, room_id);
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
        RoomControlPayload::KeySyncRequest { epoch } => {
            // Only the owner serves keys, and only to current members.
            if !i_am_owner || epoch >= info.key_epoch {
                return;
            }
            if !db.is_room_member(room_id, from).await.unwrap_or(false) {
                return;
            }
            let Ok(Some(key)) = db.get_room_key(room_id).await else {
                return;
            };
            drop(db_state);
            let _ = send_room_control(
                handle,
                room_id,
                from,
                &RoomControlPayload::KeyUpdate {
                    epoch: info.key_epoch,
                    key: key.to_vec(),
                },
            )
            .await;
        }
    }
}

/// Unwrap a `RoomControl` payload and dispatch it. Returns true when the
/// payload unwrapped and was dispatched — used by the mailbox path to
/// decide whether the envelope is safe to ack/delete.
pub(crate) async fn apply_room_control(
    handle: &tauri::AppHandle,
    room_id: &str,
    from: &str,
    wrapped_payload: &[u8],
) -> bool {
    let app_state = handle.state::<AppState>();
    let Ok(rm) = serde_json::from_slice::<crate::security::RatchetMessage>(wrapped_payload)
    else {
        return false;
    };
    {
        let db_state = app_state.db.lock().await;
        if let Some(db) = db_state.as_ref() {
            if !app_state.ratchet_sessions.has_session(from).await {
                let _ = app_state.ratchet_sessions.load_session(db, from).await;
            }
        }
    }
    let Ok(pt) = app_state.ratchet_sessions.decrypt(from, &rm).await else {
        log::warn!("RoomControl from {} failed to unwrap", from);
        return false;
    };
    {
        let db_state = app_state.db.lock().await;
        if let Some(db) = db_state.as_ref() {
            let _ = app_state.ratchet_sessions.save_session(db, from).await;
        }
    }
    let Ok(payload) = serde_json::from_slice::<RoomControlPayload>(&pt) else {
        log::warn!("RoomControl from {} has malformed payload", from);
        return false;
    };
    dispatch_room_control(handle, room_id, from, payload).await;
    true
}

/// Unwrap a `RoomInvite` and materialize the room locally. Handles both
/// the current format (serialized `RoomInvitePayload`) and legacy raw
/// 32-byte keys. Returns true when the room was created.
pub(crate) async fn apply_room_invite(
    handle: &tauri::AppHandle,
    room_id: &str,
    from: &str,
    wrapped_key: &[u8],
) -> bool {
    let app_state = handle.state::<AppState>();
    let ratchet_msg: Option<crate::security::RatchetMessage> =
        serde_json::from_slice(wrapped_key).ok();
    let key_bytes = match ratchet_msg {
        Some(rm) => {
            {
                let db_state = app_state.db.lock().await;
                if let Some(db) = db_state.as_ref() {
                    if !app_state.ratchet_sessions.has_session(from).await {
                        let _ = app_state.ratchet_sessions.load_session(db, from).await;
                    }
                }
            }
            app_state.ratchet_sessions.decrypt(from, &rm).await.ok()
        }
        None => None,
    };
    let invite: Option<crate::p2p::RoomInvitePayload> = key_bytes
        .as_deref()
        .and_then(|b| serde_json::from_slice(b).ok());
    let key: Option<[u8; 32]> = match &invite {
        Some(p) => <[u8; 32]>::try_from(p.key.as_slice()).ok(),
        None => key_bytes.as_deref().and_then(|b| b.try_into().ok()),
    };
    let Some(key) = key else {
        log::warn!("Room invite from {} could not be decrypted — ignored", from);
        return false;
    };
    let (name, avatar, owner, epoch) = match &invite {
        Some(p) => (
            p.name
                .clone()
                .unwrap_or_else(|| format!("Room {}", room_id.chars().take(8).collect::<String>())),
            p.avatar.clone(),
            p.owner.clone().or(Some(from.to_string())),
            p.epoch,
        ),
        None => (
            format!("Room {}", room_id.chars().take(8).collect::<String>()),
            None,
            Some(from.to_string()),
            0,
        ),
    };
    let my_id = app_state.my_id.lock().await.clone();
    {
        let db_state = app_state.db.lock().await;
        if let Some(db) = db_state.as_ref() {
            // INSERT OR IGNORE — a re-delivered key must not wipe local
            // state (renames, member profiles) for a room we already have.
            let _ = db
                .create_room_full(
                    room_id,
                    &name,
                    &key,
                    owner.as_deref(),
                    avatar.as_deref(),
                    epoch,
                )
                .await;
            // The inviter is always a member — added BEFORE the roster loop
            // because add_room_member is delete-then-insert: a later re-add
            // would wipe the profile the roster just wrote.
            let _ = db.add_room_member(room_id, from, true).await;
            // Roster: everyone the inviter knows about (owner + approved
            // members), then ourselves — matching the owner's member list.
            if let Some(p) = &invite {
                for m in &p.members {
                    if m.peer_id == my_id {
                        continue;
                    }
                    let _ = db.add_room_member(room_id, &m.peer_id, true).await;
                    let _ = db
                        .set_member_profile(
                            room_id,
                            &m.peer_id,
                            m.name.as_deref(),
                            m.avatar.as_deref(),
                        )
                        .await;
                }
            }
            let _ = db.add_room_member(room_id, &my_id, true).await;
            // Our own profile is the freshest source for our member row.
            if let Ok((n, a)) = db.get_profile().await {
                let _ = db
                    .set_member_profile(room_id, &my_id, Some(&n), a.as_deref())
                    .await;
            }
            // The key materialized the room — the pending invite has
            // served its purpose (kept until now so a failed delivery
            // left the invite retryable).
            let _ = db.delete_pending_room_invite(room_id).await;
            let _ = app_state.ratchet_sessions.save_session(db, from).await;
        }
    }
    if let Some(tx) = app_state.p2p() {
        let _ = crate::send_p2p_cmd(&tx, P2PCommand::JoinRoom {
                room_id: room_id.to_string(),
                room_key: Some(key),
            })
            .await;
    }
    safe_emit(
        handle,
        "room-joined",
        serde_json::json!({ "room_id": room_id, "from": from, "name": name }),
    );
    // Announce our profile so existing members learn our name/avatar
    // without waiting for a MemberJoined rebroadcast.
    crate::room_presence::announce_room_profile(handle, room_id).await;
    true
}

/// Unwrap a `RoomInviteOffer` and park it as a pending invite — the room
/// is NOT created and no key exists yet. The user accepts/declines via
/// `accept_room_invite`/`decline_room_invite`; only acceptance makes the
/// inviter deliver the wrapped key in a follow-up `RoomInvite`.
pub(crate) async fn apply_room_offer(
    handle: &tauri::AppHandle,
    room_id: &str,
    from: &str,
    wrapped_meta: &[u8],
) -> bool {
    let app_state = handle.state::<AppState>();
    let ratchet_msg: Option<crate::security::RatchetMessage> =
        serde_json::from_slice(wrapped_meta).ok();
    let meta_bytes = match ratchet_msg {
        Some(rm) => {
            {
                let db_state = app_state.db.lock().await;
                if let Some(db) = db_state.as_ref() {
                    if !app_state.ratchet_sessions.has_session(from).await {
                        let _ = app_state.ratchet_sessions.load_session(db, from).await;
                    }
                }
            }
            app_state.ratchet_sessions.decrypt(from, &rm).await.ok()
        }
        None => None,
    };
    let offer: Option<crate::p2p::RoomInviteOfferPayload> = meta_bytes
        .as_deref()
        .and_then(|b| serde_json::from_slice(b).ok());
    // S15: an offer that did not unwrap is ratchet garbage — persisting it
    // let any peer flood pending invites and UI toasts. Bail before write.
    let Some(offer) = offer else {
        log::warn!("Room invite offer from {} could not be decrypted — dropped", from);
        return false;
    };
    let (name, avatar) = (offer.name.clone(), offer.avatar.clone());
    {
        let db_state = app_state.db.lock().await;
        if let Some(db) = db_state.as_ref() {
            let _ = db
                .add_pending_room_invite(room_id, from, name.as_deref(), avatar.as_deref())
                .await;
            let _ = app_state.ratchet_sessions.save_session(db, from).await;
        }
    }
    safe_emit(
        handle,
        "room-invite",
        serde_json::json!({ "room_id": room_id, "from": from, "name": name, "avatar": avatar }),
    );
    true
}

/// Invitee accepted our offer: approve the pending member row and deliver
/// the ratchet-wrapped room key (`RoomInvite`). Without this step the
/// peer holds no key material at all.
pub(crate) async fn handle_room_invite_accept(
    handle: &tauri::AppHandle,
    room_id: &str,
    from: &str,
) {
    let app_state = handle.state::<AppState>();
    // Only deliver the key to a peer we actually invited — the member row
    // with is_approved=0 was written by invite_to_room.
    let invited = {
        let db_state = app_state.db.lock().await;
        match db_state.as_ref() {
            Some(db) => db
                .get_room_members(room_id)
                .await
                .map(|ms| ms.iter().any(|m| m.peer_id == from && !m.approved))
                .unwrap_or(false),
            None => false,
        }
    };
    if !invited {
        log::warn!(
            "RoomInviteAccept from {} for room {} — no pending invite, ignored",
            from, room_id
        );
        return;
    }
    {
        let db_state = app_state.db.lock().await;
        if let Some(db) = db_state.as_ref() {
            let _ = db.approve_member(room_id, from).await;
        }
    }
    if let Err(e) = deliver_room_key(handle, room_id, from).await {
        log::warn!("Failed to deliver room key to {}: {}", from, e);
    }
    // Tell existing members about the join — name/avatar are our best
    // local knowledge (contact profile if we have one). Write it to our
    // own member row too — the broadcast alone doesn't update our DB.
    let (name, avatar) = {
        let db_state = app_state.db.lock().await;
        match db_state.as_ref() {
            Some(db) => {
                let profile = db
                    .get_contacts()
                    .await
                    .unwrap_or_default()
                    .into_iter()
                    .find(|(id, _, _)| id == from)
                    .map(|(_, n, a)| (n, a))
                    .unwrap_or((None, None));
                if profile.0.is_some() || profile.1.is_some() {
                    let _ = db
                        .set_member_profile(
                            room_id,
                            from,
                            profile.0.as_deref(),
                            profile.1.as_deref(),
                        )
                        .await;
                }
                profile
            }
            None => (None, None),
        }
    };
    if let Some(tx) = app_state.p2p() {
        let _ = crate::send_p2p_cmd(&tx, P2PCommand::SendRoomPayload {
                room_id: room_id.to_string(),
                payload: crate::p2p::RoomPayload::MemberJoined {
                    peer_id: from.to_string(),
                    name,
                    avatar,
                },
            })
            .await;
    }
    emit_room_updated(handle, room_id, "members");
}

/// Invitee declined our offer: drop the pending member row so they never
/// receive a key.
pub(crate) async fn handle_room_invite_decline(
    handle: &tauri::AppHandle,
    room_id: &str,
    from: &str,
) {
    let app_state = handle.state::<AppState>();
    {
        let db_state = app_state.db.lock().await;
        if let Some(db) = db_state.as_ref() {
            let _ = db.remove_room_member(room_id, from).await;
        }
    }
    safe_emit(
        handle,
        "room-invite-declined",
        serde_json::json!({ "room_id": room_id, "from": from }),
    );
    emit_room_updated(handle, room_id, "members");
}

/// Ratchet-wrap the room key + metadata (`RoomInvitePayload`) and send it
/// to `to` as a `RoomInvite` — the second phase of the invite handshake.
async fn deliver_room_key(
    handle: &tauri::AppHandle,
    room_id: &str,
    to: &str,
) -> Result<(), String> {
    let app_state = handle.state::<AppState>();
    let my_id = app_state.my_id.lock().await.clone();
    let invite = {
        let db_state = app_state.db.lock().await;
        let db = db_state.as_ref().ok_or("Database not initialized")?;
        let mut key = db
            .get_room_key(room_id)
            .await
            .map_err(|e| e.to_string())?
            .ok_or("Unknown room or missing key")?;
        let info = db
            .get_room_info(room_id)
            .await
            .map_err(|e| e.to_string())?
            .ok_or("Unknown room")?;
        let members = room_roster(db, room_id, info.owner.as_deref(), &my_id).await;
        let invite = crate::p2p::RoomInvitePayload {
            key: key.to_vec(),
            name: Some(info.name),
            avatar: info.avatar,
            owner: info.owner,
            epoch: info.key_epoch,
            members,
        };
        use zeroize::Zeroize;
        key.zeroize();
        invite
    };
    let body = serde_json::to_vec(&invite).map_err(|e| e.to_string())?;
    let ratchet_msg = match app_state.ratchet_sessions.encrypt(to, &body).await {
        Ok(Some(m)) => m,
        _ => return Err("No E2EE session with this peer".to_string()),
    };
    {
        let db_state = app_state.db.lock().await;
        if let Some(db) = db_state.as_ref() {
            let _ = app_state.ratchet_sessions.save_session(db, to).await;
        }
    }
    let wrapped = serde_json::to_vec(&ratchet_msg).map_err(|e| e.to_string())?;
    let msg = NoidMessage {
        sender: my_id,
        content: String::new(),
        msg_type: MessageType::RoomInvite {
            room_id: room_id.to_string(),
            wrapped_key: wrapped,
        },
        timestamp: Some(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
        id: uuid::Uuid::new_v4().to_string(),
    };
    // F13: pending-first — a lost RoomInvite wedges membership permanently
    // (inviter thinks the member is approved, invitee never got the key).
    crate::pend_typed_message_h(handle, to, &msg).await;
    let tx = app_state.p2p().ok_or("P2P not initialized")?;
    crate::send_p2p_cmd(&tx, P2PCommand::SendMessage {
        peer_id: to.to_string(),
        msg,
    })
    .await
    .map_err(|e| e.to_string())
}

/// Ask the room owner to resend the current key — triggered when a
/// signed envelope fails to open (we missed a rekey while offline).
pub(crate) async fn request_key_sync(handle: &tauri::AppHandle, room_id: &str) {
    let app_state = handle.state::<AppState>();
    let db_state = app_state.db.lock().await;
    let Some(db) = db_state.as_ref() else { return };
    let Ok(Some(info)) = db.get_room_info(room_id).await else {
        return;
    };
    let Some(owner) = info.owner else { return };
    let epoch = info.key_epoch;
    drop(db_state);
    let _ = send_room_control(
        handle,
        room_id,
        &owner,
        &RoomControlPayload::KeySyncRequest { epoch },
    )
    .await;
}

/// Apply a sealed `RoomEnvelope` that arrived out-of-band — a direct
/// `MessageType::RoomChat` copy delivered live, via pending resend, or
/// from the recipient's mailbox. The envelope is self-authenticating
/// (AES-256-GCM under the room key + Ed25519 sender signature), so the
/// transport `from` is advisory only; authorization comes from holding
/// the room key.
pub(crate) async fn apply_room_chat(
    handle: &tauri::AppHandle,
    room_id: &str,
    env_bytes: &[u8],
) {
    let Ok(env) =
        serde_json::from_slice::<crate::security::room_crypto::RoomEnvelope>(env_bytes)
    else {
        log::warn!("RoomChat for {}: malformed envelope — dropped", room_id);
        return;
    };

    let app_state = handle.state::<AppState>();
    let db_state = app_state.db.lock().await;
    let Some(db) = db_state.as_ref() else { return };
    let Ok(Some(key)) = db.get_room_key(room_id).await else {
        // Not a member (or the room was wiped) — drop silently.
        log::debug!("RoomChat for {}: no room key — dropped", room_id);
        return;
    };

    let pt = match crate::security::room_crypto::open(&key, room_id, &env) {
        Ok(pt) => pt,
        Err(e) => {
            // A signature-valid envelope that fails to open means our key
            // is stale — ask the owner for a resync, same as the topic path.
            let sig_ok = crate::security::identity_sig::verify_payload(
                &env.sender_peer_id,
                &crate::security::room_crypto::envelope_payload(
                    room_id, &env.msg_id, &env.ts, &env.ciphertext,
                ),
                &env.signature,
            );
            if sig_ok {
                log::debug!("RoomChat in {}: stale key — requesting resync", room_id);
                drop(db_state);
                request_key_sync(handle, room_id).await;
            } else {
                log::warn!("RoomChat in {}: rejected envelope ({})", room_id, e);
            }
            return;
        }
    };

    match serde_json::from_slice::<crate::p2p::RoomPayload>(&pt) {
        Ok(crate::p2p::RoomPayload::Chat { content }) => {
            let inserted = db
                .add_room_message(
                    &env.msg_id,
                    room_id,
                    &env.sender_peer_id,
                    content.as_bytes(),
                    &env.ts,
                )
                .await
                .unwrap_or(false);
            drop(db_state);
            if inserted {
                safe_emit(handle, "room-msg", serde_json::json!({
                    "room_id": room_id,
                    "sender": env.sender_peer_id,
                    "content": content,
                    "msg_id": env.msg_id,
                    "ts": env.ts,
                }));
            }
        }
        Ok(payload) => {
            // Non-chat payloads (MemberJoined/Profile/...) go through the
            // same dispatcher as topic envelopes — sender is the signed
            // envelope field, not the transport peer.
            let sender = env.sender_peer_id.clone();
            drop(db_state);
            crate::room_rekey::dispatch_room_topic_payload(handle, room_id, &sender, payload).await;
        }
        Err(_) => {
            // Legacy raw-text envelope — treat as chat.
            let content = String::from_utf8_lossy(&pt).to_string();
            let inserted = db
                .add_room_message(
                    &env.msg_id,
                    room_id,
                    &env.sender_peer_id,
                    content.as_bytes(),
                    &env.ts,
                )
                .await
                .unwrap_or(false);
            drop(db_state);
            if inserted {
                safe_emit(handle, "room-msg", serde_json::json!({
                    "room_id": room_id,
                    "sender": env.sender_peer_id,
                    "content": content,
                    "msg_id": env.msg_id,
                    "ts": env.ts,
                }));
            }
        }
    }
}

/// The inviter's view of the room roster — owner plus every approved
/// member with the best-known profile (announced member profile first,
/// contacts fallback, our own profile when we are the owner).
pub(crate) async fn room_roster(
    db: &crate::db::Database,
    room_id: &str,
    owner: Option<&str>,
    my_id: &str,
) -> Vec<crate::p2p::RoomMemberProfile> {
    let contacts: std::collections::HashMap<String, (Option<String>, Option<String>)> = db
        .get_contacts()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|(id, n, a)| (id, (n, a)))
        .collect();
    let mut roster = Vec::new();
    if let Some(owner) = owner {
        let (name, avatar) = if owner == my_id {
            db.get_profile()
                .await
                .map(|(n, a)| (Some(n), a))
                .unwrap_or((None, None))
        } else {
            contacts.get(owner).cloned().unwrap_or((None, None))
        };
        roster.push(crate::p2p::RoomMemberProfile {
            peer_id: owner.to_string(),
            name,
            avatar,
        });
    }
    if let Ok(members) = db.get_room_members(room_id).await {
        for m in members.into_iter().filter(|m| m.approved) {
            if roster.iter().any(|r| r.peer_id == m.peer_id) {
                continue;
            }
            let (cn, ca) = contacts.get(&m.peer_id).cloned().unwrap_or((None, None));
            roster.push(crate::p2p::RoomMemberProfile {
                peer_id: m.peer_id,
                name: m.name.or(cn),
                avatar: m.avatar.or(ca),
            });
        }
    }
    roster
}

/// Notify the UI that a room record changed (meta/membership/key/lifecycle).
pub(crate) fn emit_room_updated(handle: &tauri::AppHandle, room_id: &str, kind: &str) {
    safe_emit(
        handle,
        "room-updated",
        serde_json::json!({ "room_id": room_id, "kind": kind }),
    );
}
