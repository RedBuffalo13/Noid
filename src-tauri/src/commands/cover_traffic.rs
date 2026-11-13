//! META-01: adaptive cover traffic. While enabled the node emits a
//! padded `NOIDMETA1 {"kind":"chaff"}` frame to a random contact with a
//! live ratchet session every 45–150 s. Chaff frames are wire-identical
//! to chat frames (same ratchet, same bucket padding), so a passive
//! observer cannot read activity level from traffic volume.

use crate::AppState;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tauri::{AppHandle, Manager};
use uuid::Uuid;

static COVER_ENABLED: AtomicBool = AtomicBool::new(false);

/// Toggle cover traffic. Enabling spawns a tracked session task (KillPin
/// drains it); disabling flips the flag the loop checks each cycle.
#[tauri::command]
pub async fn set_cover_traffic(
    enabled: bool,
    app: AppHandle,
) -> Result<(), String> {
    let was = COVER_ENABLED.swap(enabled, Ordering::SeqCst);
    if enabled && !was {
        let handle = tokio::spawn(cover_loop(app.clone()));
        crate::track_task(&app, handle).await;
    }
    Ok(())
}

async fn cover_loop(app: AppHandle) {
    loop {
        let wait_ms = 45_000 + (rand::random::<u32>() % 105_001) as u64;
        tokio::time::sleep(Duration::from_millis(wait_ms)).await;
        if !COVER_ENABLED.load(Ordering::SeqCst) {
            break;
        }
        let state = app.state::<AppState>();
        if let Some(peer) = pick_cover_peer(&state).await {
            send_chaff(&state, &peer).await;
        }
    }
}

async fn pick_cover_peer(state: &AppState) -> Option<String> {
    let contacts = {
        let db_guard = state.db.lock().await;
        db_guard.as_ref()?.get_contacts().await.ok()?
    };
    let mut candidates = Vec::new();
    for (id, _, _) in contacts {
        if state.ratchet_sessions.can_send(&id).await {
            candidates.push(id);
        }
    }
    if candidates.is_empty() {
        return None;
    }
    Some(candidates.swap_remove((rand::random::<u32>() as usize) % candidates.len()))
}

async fn send_chaff(state: &AppState, peer_id: &str) {
    let filler = rand::random::<u32>();
    let payload = format!(
        "NOIDMETA1:{}",
        serde_json::json!({"kind": "chaff", "pad": filler})
    );
    let Ok(msg) = crate::commands::file_transfer::wrap_ratchet_payload(
        state,
        peer_id,
        &payload,
        &Uuid::new_v4().to_string(),
    )
    .await
    else {
        return;
    };
    if let Some(tx) = state.p2p() {
        let _ = crate::send_p2p_cmd(&tx, crate::p2p::P2PCommand::SendMessage {
            peer_id: peer_id.to_string(),
            msg,
        })
        .await;
    }
}
