use anyhow::Result;
use crate::db::database::Database;

impl Database {
    /// `peer_id` is field-encrypted at rest; lookups go through `peer_hmac`.
    /// DB19: test-only — stores the bare msg_id as `content` (legacy format)
    /// and bypasses the 200-row cap. Production inserts go through
    /// `add_pending_message_with_content`.
    #[cfg(test)]
    pub async fn add_pending_message(&self, peer_id: &str, message_id: &str) -> Result<()> {
        sqlx::query("INSERT INTO pending_messages (peer_id, content, message_id, peer_hmac) VALUES (?, ?, ?, ?)")
            .bind(self.enc_text(peer_id)?)
            .bind(message_id)
            .bind(message_id)
            .bind(self.hmac("pending.peer", peer_id))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn add_pending_message_with_content(&self, peer_id: &str, content: &str, message_id: &str) -> Result<()> {
        // DB8: insert + cap-trim atomically — a crash between them used to
        // leave the peer above the 200-row bound until the next write.
        let mut tx = self.pool.begin().await?;
        sqlx::query("INSERT INTO pending_messages (peer_id, content, message_id, peer_hmac) VALUES (?, ?, ?, ?)")
            .bind(self.enc_text(peer_id)?)
            .bind(content)
            .bind(message_id)
            .bind(self.hmac("pending.peer", peer_id))
            .execute(&mut *tx)
            .await?;
        // DoS bound: keep at most 200 pending rows per peer (oldest evicted).
        sqlx::query(
            "DELETE FROM pending_messages WHERE peer_hmac = ? AND id NOT IN \
             (SELECT id FROM pending_messages WHERE peer_hmac = ? ORDER BY id DESC LIMIT 200)",
        )
        .bind(self.hmac("pending.peer", peer_id))
        .bind(self.hmac("pending.peer", peer_id))
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Whether a pending row with this message_id already exists — prevents
    /// duplicate pending entries when a send failure re-queues a message that
    /// was already persisted by the send command.
    /// Pending-row existence is scoped to (peer, message_id): the same
    /// message_id can be fanned out to several room members, and a global
    /// id check would confuse one member's row with another's.
    pub async fn pending_exists_by_message_id(&self, peer_id: &str, message_id: &str) -> Result<bool> {
        let row: Option<(i64,)> = sqlx::query_as(
            "SELECT 1 FROM pending_messages WHERE peer_hmac = ? AND message_id = ? LIMIT 1",
        )
        .bind(self.hmac("pending.peer", peer_id))
        .bind(message_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.is_some())
    }

    pub async fn get_pending_messages(&self, peer_id: &str) -> Result<Vec<(i64, String, String)>> {
        let rows = sqlx::query_as::<_, (i64, String, String)>(
            // MD-07: oldest-first — a flush that skips the head row must not
            // starve it behind newer entries every retry round.
            "SELECT id, content, message_id FROM pending_messages WHERE peer_hmac = ? ORDER BY id ASC",
        )
        .bind(self.hmac("pending.peer", peer_id))
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// TI-4: ids only — the chat view marks these as still-queued instead
    /// of the blanket `delivered` that history reloads used to fabricate.
    pub async fn get_pending_message_ids(&self, peer_id: &str) -> Result<Vec<String>> {
        let rows = sqlx::query_as::<_, (String,)>(
            "SELECT message_id FROM pending_messages WHERE peer_hmac = ? AND message_id IS NOT NULL",
        )
        .bind(self.hmac("pending.peer", peer_id))
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|r| r.0).collect())
    }

    pub async fn delete_pending_message(&self, id: i64) -> Result<()> {
        sqlx::query("DELETE FROM pending_messages WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Scoped delete — a delivery ack for (peer, message_id) must never
    /// remove another peer's pending row for the same fanned-out message.
    pub async fn delete_pending_message_by_id(&self, peer_id: &str, message_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM pending_messages WHERE peer_hmac = ? AND message_id = ?")
            .bind(self.hmac("pending.peer", peer_id))
            .bind(message_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// F14: drop pending rows older than `max_age_secs` — a mailbox would
    /// expire the envelope after 7 days anyway, so an older pending row can
    /// never be delivered and would otherwise churn the retry loop forever.
    /// Returns (peer_id, message_id) of the deleted rows for UI signalling.
    pub async fn cleanup_stale_pending(&self, max_age_secs: i64) -> Result<Vec<(String, String)>> {
        let cutoff = (chrono::Utc::now() - chrono::Duration::seconds(max_age_secs))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        // DB8: select + delete in one tx — a row written between them used
        // to be deleted without being reported to the caller.
        let mut tx = self.pool.begin().await?;
        let rows = sqlx::query_as::<_, (String, String)>(
            "SELECT peer_id, message_id FROM pending_messages WHERE timestamp < ?",
        )
        .bind(&cutoff)
        .fetch_all(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM pending_messages WHERE timestamp < ?")
            .bind(&cutoff)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(Self::collect_tolerant(
            rows.into_iter()
                .map(|(peer, mid)| Ok((self.dec_text(&peer)?, mid))),
            "pending",
        ))
    }

    /// Phase H.1: Get all pending messages across all peers (for mailbox retry).
    /// Returns (id, content, message_id, peer_id) — peer_id decrypted.
    /// DB20: ORDER BY id so the retry flush sends oldest-first.
    /// DB22: NULL columns filtered — migration 001 made them nullable and a
    /// NULL row used to fail the decode of the whole result set.
    pub async fn get_pending_messages_all(&self) -> Result<Vec<(i64, String, String, String)>> {
        let rows = sqlx::query_as::<_, (i64, String, String, String)>(
            "SELECT id, content, message_id, peer_id FROM pending_messages \
             WHERE content IS NOT NULL AND message_id IS NOT NULL AND peer_id IS NOT NULL \
             ORDER BY id",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(Self::collect_tolerant(
            rows.into_iter().map(|(id, content, msg_id, peer)| {
                Ok((id, content, msg_id, self.dec_text(&peer)?))
            }),
            "pending",
        ))
    }
}
