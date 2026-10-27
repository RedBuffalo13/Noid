use anyhow::{anyhow, Result};
use tokio::sync::Mutex;

use crate::db::Database;
use crate::security::RatchetSessionManager;

/// Persist an initiated session without holding the global database mutex
/// across I/O. The returned snapshot is also used to pend X3DHInit.
pub(crate) async fn persist_initiated_session(
    db_state: &Mutex<Option<Database>>,
    sessions: &RatchetSessionManager,
    peer_id: &str,
    identity_public: &[u8],
) -> Result<Database> {
    let db = db_state
        .lock()
        .await
        .clone()
        .ok_or_else(|| anyhow!("Database not initialized"))?;
    db.save_contact_public_key(peer_id, identity_public).await?;
    sessions.save_session(&db, peer_id).await?;
    Ok(db)
}
