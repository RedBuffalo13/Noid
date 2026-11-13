//! SEC-1111-06: explicit user consent for file offers. A parked offer is
//! promoted into the ingest map only here — chunks arriving before this
//! call are dropped by the dispatcher.

use crate::AppState;
use tauri::State;

#[tauri::command]
pub async fn accept_file_offer(
    from: String,
    offer_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    crate::validation::parse_peer_id(&from)?;
    let key = format!("{}:{}", from, offer_id);
    let Some((sender, name, size)) = state.pending_file_offers.lock().await.remove(&key)
    else {
        return Err("No pending file offer".to_string());
    };
    let db = state.require_db().await?;
    let _ = sqlx::query("DELETE FROM pending_file_offers WHERE key = ?")
        .bind(&key)
        .execute(&db.pool)
        .await;
    drop(db);
    let mut inbox = state.file_inbox.lock().await;
    if crate::file_inbox::register_offer(&mut inbox, &key, &name, size) {
        log::info!("File offer {} from {} accepted by user", offer_id, sender);
        Ok(())
    } else {
        Err("Offer cannot be accepted (oversize or inbox budget)".to_string())
    }
}

#[tauri::command]
pub async fn decline_file_offer(
    from: String,
    offer_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let key = format!("{}:{}", from, offer_id);
    state.pending_file_offers.lock().await.remove(&key);
    if let Ok(db) = state.require_db().await {
        let _ = sqlx::query("DELETE FROM pending_file_offers WHERE key = ?")
            .bind(&key)
            .execute(&db.pool)
            .await;
    }
    Ok(())
}
