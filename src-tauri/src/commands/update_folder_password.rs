use argon2::password_hash::PasswordHasher;
use crate::AppState;
use tauri::State;

#[tauri::command]
pub async fn update_folder_password(
    id: String,
    password: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    if password.is_empty() {
        let db = state.require_db().await?;
        db.clear_folder_password(&id)
            .await
            .map_err(|e| e.to_string())?;
        return Ok(());
    }

    // RC15: Argon2 is blocking CPU work — keep it off the tokio worker.
    let password_hash = tokio::task::spawn_blocking(move || {
        let salt =
            argon2::password_hash::SaltString::generate(&mut rand::thread_rng());
        argon2::Argon2::default()
            .hash_password(password.as_bytes(), &salt)
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
