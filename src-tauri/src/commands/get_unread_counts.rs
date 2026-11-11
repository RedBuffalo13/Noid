use crate::AppState;
use tauri::State;

/// FE-A08: every peer_hmac with a nonzero unread count — the frontend
/// matches them to the peers it already knows (peer ids are encrypted,
/// so the backend returns tokens, not plaintext ids).
#[tauri::command]
pub async fn get_unread_counts(
    state: State<'_, AppState>,
) -> Result<Vec<(String, i64)>, String> {
    let db = state.require_db().await?;
    db.get_unread_counts().await.map_err(|e| e.to_string())
}
