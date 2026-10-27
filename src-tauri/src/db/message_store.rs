use anyhow::Result;
use crate::db::database::Database;

/// (id, sender, content, timestamp) raw row as read from `messages`.
type RawMessageRow = (String, String, Vec<u8>, String);

impl Database {
    /// Store a message. `sender_id`/`receiver_id` are field-encrypted; the
    /// `sender_hmac`/`receiver_hmac` columns carry deterministic lookup tokens.
    pub async fn add_message(
        &self,
        msg_id: &str,
        sender_id: &str,
        receiver_id: &str,
        encrypted_content: &[u8],
    ) -> Result<()> {
        let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        sqlx::query(
            "INSERT INTO messages (id, sender_id, receiver_id, content, timestamp, sender_hmac, receiver_hmac) VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(msg_id)
        .bind(self.enc_text(sender_id)?)
        .bind(self.enc_text(receiver_id)?)
        .bind(encrypted_content)
        .bind(Self::sanitize_ts(&timestamp))
        .bind(self.hmac("msg.sender", sender_id))
        .bind(self.hmac("msg.receiver", receiver_id))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn add_message_with_timestamp(
        &self,
        msg_id: &str,
        sender_id: &str,
        receiver_id: &str,
        encrypted_content: &[u8],
        timestamp: &str,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO messages (id, sender_id, receiver_id, content, timestamp, sender_hmac, receiver_hmac) VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(msg_id)
        .bind(self.enc_text(sender_id)?)
        .bind(self.enc_text(receiver_id)?)
        .bind(encrypted_content)
        .bind(Self::sanitize_ts(timestamp))
        .bind(self.hmac("msg.sender", sender_id))
        .bind(self.hmac("msg.receiver", receiver_id))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Inserts a message only when `msg_id` is not already stored.
    /// Returns `true` when the row was actually inserted.
    pub async fn add_message_if_absent(
        &self,
        msg_id: &str,
        sender_id: &str,
        receiver_id: &str,
        encrypted_content: &[u8],
        timestamp: &str,
    ) -> Result<bool> {
        let res = sqlx::query(
            "INSERT OR IGNORE INTO messages (id, sender_id, receiver_id, content, timestamp, sender_hmac, receiver_hmac) VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(msg_id)
        .bind(self.enc_text(sender_id)?)
        .bind(self.enc_text(receiver_id)?)
        .bind(encrypted_content)
        .bind(Self::sanitize_ts(timestamp))
        .bind(self.hmac("msg.sender", sender_id))
        .bind(self.hmac("msg.receiver", receiver_id))
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    fn dec_row(
        &self,
        rows: Vec<RawMessageRow>,
    ) -> Result<Vec<RawMessageRow>> {
        // DB4: a single corrupt row must not hide the whole chat history.
        Ok(Self::collect_tolerant(
            rows.into_iter()
                .map(|(id, sender, content, ts)| {
                    Ok((id, self.dec_text(&sender)?, content, ts))
                }),
            "message",
        ))
    }

    /// DB12: unbounded history reads pulled the entire table into memory and
    /// ran N decrypts under the security mutex. History is bounded — newest
    /// `HISTORY_LIMIT` rows, returned ascending.
    const HISTORY_LIMIT: i64 = 500;

    pub async fn get_messages_for_contact(
        &self,
        peer_id: &str,
    ) -> Result<Vec<RawMessageRow>> {
        let mut rows = sqlx::query_as::<_, RawMessageRow>(
            "SELECT id, sender_id, content, timestamp FROM messages WHERE sender_hmac = ? OR receiver_hmac = ? ORDER BY timestamp DESC LIMIT ?"
        )
        .bind(self.hmac("msg.sender", peer_id))
        .bind(self.hmac("msg.receiver", peer_id))
        .bind(Self::HISTORY_LIMIT)
        .fetch_all(&self.pool)
        .await?;
        rows.reverse();
        self.dec_row(rows)
    }

    pub async fn get_messages_for_contact_since(
        &self,
        peer_id: &str,
        since_time: &str,
    ) -> Result<Vec<RawMessageRow>> {
        let mut rows = sqlx::query_as::<_, RawMessageRow>(
            "SELECT id, sender_id, content, timestamp FROM messages WHERE (sender_hmac = ? OR receiver_hmac = ?) AND timestamp > ? ORDER BY timestamp DESC LIMIT ?"
        )
        .bind(self.hmac("msg.sender", peer_id))
        .bind(self.hmac("msg.receiver", peer_id))
        .bind(since_time)
        .bind(Self::HISTORY_LIMIT)
        .fetch_all(&self.pool)
        .await?;
        rows.reverse();
        self.dec_row(rows)
    }

    pub async fn message_exists(&self, msg_id: &str) -> Result<bool> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM messages WHERE id = ?")
            .bind(msg_id)
            .fetch_one(&self.pool)
            .await?;
        Ok(row.0 > 0)
    }

    /// Deletes the whole direct-message history with `peer_id` and drops the
    /// still-undelivered outbox for that peer. Lookups use the deterministic
    /// hmac columns; encrypted `sender_id`/`receiver_id` are never matched
    /// directly.
    pub async fn delete_chat(&self, peer_id: &str) -> Result<()> {
        sqlx::query(
            "DELETE FROM messages WHERE sender_hmac = ? OR receiver_hmac = ?",
        )
        .bind(self.hmac("msg.sender", peer_id))
        .bind(self.hmac("msg.receiver", peer_id))
        .execute(&self.pool)
        .await?;
        sqlx::query("DELETE FROM pending_messages WHERE peer_hmac = ?")
            .bind(self.hmac("pending.peer", peer_id))
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
