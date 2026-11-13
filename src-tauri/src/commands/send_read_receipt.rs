use crate::p2p::P2PCommand;
use crate::AppState;
use tauri::State;
use uuid::Uuid;

/// META-01: receipts ride inside the ratchet-encrypted payload
/// (`NOIDMETA1:` marker) — a plaintext ReadReceipt used to leak the
/// conversation shape (who acks whom, and when) to every hop.
/// Send is jittered 200–1200 ms so arrival timing cannot be read as
/// "user just read the message".
#[tauri::command]
pub async fn send_read_receipt(
    peer_id: String,
    message_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    crate::validation::parse_peer_id(&peer_id)?;
    crate::validation::bounded_str("message_id", &message_id, 64)?;

    let delay_ms = 200 + (rand::random::<u16>() % 1001) as u64;
    tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;

    let payload = format!(
        "NOIDMETA1:{}",
        serde_json::json!({"kind": "read", "message_id": message_id})
    );
    let msg = crate::commands::file_transfer::wrap_ratchet_payload(
        &state,
        &peer_id,
        &payload,
        &Uuid::new_v4().to_string(),
    )
    .await?;

    let tx = state.require_p2p()?;
    crate::send_p2p_cmd(&tx, P2PCommand::SendMessage { peer_id, msg })
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}
