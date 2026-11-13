use crate::p2p::P2PCommand;
use crate::AppState;
use tauri::State;
use uuid::Uuid;

/// META-01: typing indicators ride inside the ratchet-encrypted payload
/// — a plaintext TypingIndicator leaked "user is composing right now"
/// timing to every hop on the path.
#[tauri::command]
pub async fn send_typing_indicator(
    peer_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    crate::validation::parse_peer_id(&peer_id)?;

    let payload = format!(
        "NOIDMETA1:{}",
        serde_json::json!({"kind": "typing"})
    );
    // No session → drop silently: a typing hint is not worth kicking an
    // X3DH cycle (and would stall the send path on it).
    let Ok(msg) = crate::commands::file_transfer::wrap_ratchet_payload(
        &state,
        &peer_id,
        &payload,
        &Uuid::new_v4().to_string(),
    )
    .await
    else {
        return Ok(());
    };

    let tx = state.require_p2p()?;
    crate::send_p2p_cmd(&tx, P2PCommand::SendMessage { peer_id, msg })
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}
