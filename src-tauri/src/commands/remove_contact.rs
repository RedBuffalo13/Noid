use crate::AppState;
use tauri::State;

#[tauri::command]
pub async fn remove_contact(peer_id: String, state: State<'_, AppState>) -> Result<(), String> {
    crate::validation::parse_peer_id(&peer_id)?;
    let db = state.require_db().await?;
    db.delete_contact(&peer_id).await.map_err(|e| e.to_string())?;
    Ok(())
}
