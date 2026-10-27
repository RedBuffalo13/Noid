use crate::p2p::{MessageType, P2PCommand, NoidMessage};
use crate::AppState;
use tauri::State;
use uuid::Uuid;

#[tauri::command]
pub async fn send_read_receipt(
    peer_id: String,
    message_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    crate::validation::parse_peer_id(&peer_id)?;
    crate::validation::bounded_str("message_id", &message_id, 64)?;
    let my_id = state.my_id.lock().await.clone();
    let msg = NoidMessage {
        sender: my_id,
        content: message_id.clone(),
        msg_type: MessageType::ReadReceipt { message_id },
        timestamp: Some(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
        id: Uuid::new_v4().to_string(),
    };

    let tx = state.require_p2p()?;
    crate::send_p2p_cmd(&tx, P2PCommand::SendMessage { peer_id, msg })
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}
