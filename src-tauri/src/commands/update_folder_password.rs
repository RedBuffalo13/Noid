use argon2::password_hash::PasswordHasher;
use crate::AppState;
use tauri::State;
use zeroize::Zeroizing;

#[tauri::command]
pub async fn update_folder_password(
    id: String,
    password: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let password = Zeroizing::new(password);
    crate::validation::bounded_str("folder id", &id, 256)?;
    if password.is_empty() {
        let db = state.require_db().await?;
        db.clear_folder_password(&id)
            .await
            .map_err(|e| e.to_string())?;
        return Ok(());
    }
    crate::validation::bounded_str("folder password", password.as_str(), 1024)?;
    // Reject pre-login requests before allocating an expensive Argon2 task.
    // Recheck the current DB after the task instead of retaining a stale snapshot.
    drop(state.require_db().await?);

    // RC15: Argon2 is blocking CPU work — keep it off the tokio worker.
    let password_hash = tokio::task::spawn_blocking(move || {
        argon2::Argon2::default()
            .hash_password(password.as_bytes())
            .map_err(|e| e.to_string())
            .map(|h| h.to_string())
    })
    .await
    .map_err(|e| format!("hash task failed: {}", e))??;

    let db = state.require_db().await?;
    db.update_folder_password(&id, &password_hash)
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}
