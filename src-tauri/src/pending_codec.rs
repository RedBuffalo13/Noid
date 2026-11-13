//! Pending-message content codec — AES-GCM envelopes for the
//! `pending_messages` table. Extracted from lib.rs (Q05/A5b); bodies moved
//! verbatim.

use base64::Engine as _;
use tauri::Manager;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::security::SecurityManager;
use crate::AppState;


/// Decrypt a `pending_messages.content` cell: "enc2:" (or legacy "enc1:")
/// + base64(AES-GCM blob). Rows without the prefix are legacy plaintext and
///   are returned as-is (they are migrated on write, not on read).
pub async fn decode_pending_content(
    security: &Arc<Mutex<SecurityManager>>,
    raw: &str,
) -> Option<String> {
    if let Some(b64) = raw
        .strip_prefix("enc2:")
        .or_else(|| raw.strip_prefix("enc1:"))
    {
        let bytes = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
        let plaintext = security.lock().await.decrypt(&bytes).ok()?;
        Some(String::from_utf8_lossy(&plaintext).to_string())
    } else {
        // DB30: fail-open for legacy pre-encryption rows — flagged so the
        // surviving plaintext is visible in the log; writes are always
        // encrypted so this branch only shrinks over time.
        log::warn!("pending row carries legacy plaintext (pre-enc2 era) — passing through");
        Some(raw.to_string())
    }
}

/// Encrypt a pending body for storage — returns None when the master key is
/// not available; callers must then keep the message out of pending rather
/// than persist plaintext.
/// F13: pending-first for typed messages — the encrypted NOIDMSG1 row is
/// written BEFORE the send is queued, so a crash between enqueue and
/// OutboundFailure cannot lose a ContactRequest/RoomInvite/etc.
/// No-op when a row for this (peer, message_id) already exists.
pub async fn pend_typed_message(
    state: &tauri::State<'_, AppState>,
    peer_id: &str,
    msg: &crate::p2p::NoidMessage,
) {
    let db = state.db.lock().await.clone();
    let Some(db) = db else { return };
    if db
        .pending_exists_by_message_id(peer_id, &msg.id)
        .await
        .unwrap_or(false)
    {
        return;
    }
    let json = match serde_json::to_string(msg) {
        Ok(j) => j,
        Err(_) => return,
    };
    if let Some(enc) = encode_pending_content(&state.security, &format!("NOIDMSG1:{}", json)).await {
        let _ = db
            .add_pending_message_with_content(peer_id, &enc, &msg.id)
            .await;
    }
}

/// AppHandle variant for non-command call sites (room_control, dispatchers).
pub async fn pend_typed_message_h(
    handle: &tauri::AppHandle,
    peer_id: &str,
    msg: &crate::p2p::NoidMessage,
) {
    let app_state = handle.state::<AppState>();
    let db = app_state.db.lock().await.clone();
    let Some(db) = db else { return };
    if db
        .pending_exists_by_message_id(peer_id, &msg.id)
        .await
        .unwrap_or(false)
    {
        return;
    }
    let json = match serde_json::to_string(msg) {
        Ok(j) => j,
        Err(_) => return,
    };
    if let Some(enc) = encode_pending_content(&app_state.security, &format!("NOIDMSG1:{}", json)).await {
        let _ = db
            .add_pending_message_with_content(peer_id, &enc, &msg.id)
            .await;
    }
}

pub async fn encode_pending_content(
    security: &Arc<Mutex<SecurityManager>>,
    plaintext: &str,
) -> Option<String> {
    let enc = security.lock().await.encrypt(plaintext.as_bytes()).ok()?;
    Some(format!(
        "enc2:{}",
        base64::engine::general_purpose::STANDARD.encode(&enc)
    ))
}
