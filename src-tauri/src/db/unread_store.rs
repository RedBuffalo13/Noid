//! Unread-count persistence (FE-A08).
//!
//! Unread badges used to live only in the in-memory `unreadCount` map —
//! a restart silently zeroed them while messages stayed unread. peer_id
//! is stored field-encrypted with the deterministic `unread.peer` HMAC
//! for lookup, matching the field-cipher convention; counts are written
//! on every change and read once at session load.
use anyhow::Result;
use crate::db::database::Database;

impl Database {
    /// Upsert a peer's unread count; 0 removes the row so the table stays
    /// the live set, not an audit trail.
    pub async fn set_unread_count(&self, peer_id: &str, count: i64) -> Result<()> {
        if count <= 0 {
            sqlx::query("DELETE FROM unread_counts WHERE peer_hmac = ?")
                .bind(self.hmac("unread.peer", peer_id))
                .execute(&self.pool)
                .await?;
            return Ok(());
        }
        sqlx::query(
            "INSERT INTO unread_counts (peer_id, peer_hmac, count) VALUES (?, ?, ?) \
             ON CONFLICT(peer_hmac) DO UPDATE SET count = excluded.count",
        )
        .bind(self.enc_text(peer_id)?)
        .bind(self.hmac("unread.peer", peer_id))
        .bind(count)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Every peer with a nonzero unread count — `(peer_id, count)` decrypted.
    pub async fn get_unread_counts(&self) -> Result<Vec<(String, i64)>> {
        let rows = sqlx::query_as::<_, (String, i64)>(
            "SELECT peer_id, count FROM unread_counts WHERE count > 0",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(Self::collect_tolerant(
            rows.into_iter().map(|(id, count)| Ok((self.dec_text(&id)?, count))),
            "unread_counts",
        ))
    }
}
