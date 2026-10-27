use anyhow::Result;
use crate::db::database::Database;

impl Database {
    /// Store a mailbox message for offline delivery.
    /// `recipient`/`sender` peer ids are field-encrypted; lookups go through
    /// `recipient_hmac`/`sender_hmac` tokens.
    pub async fn store_mailbox_message(
        &self,
        id: &str,
        recipient: &str,
        sender: &str,
        content: &[u8],
        expires_at: &str,
        signature: &[u8],
    ) -> Result<()> {
        // INSERT OR REPLACE keyed on the plaintext-stable PK `id` is safe —
        // id is a random message uuid, not an encrypted field.
        // The sender signature is stored alongside so the recipient can
        // verify the envelope end-to-end (S6).
        sqlx::query(
            "INSERT OR REPLACE INTO mailbox_storage (id, recipient_peer_id, sender_peer_id, encrypted_content, expires_at, recipient_hmac, sender_hmac, signature) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(self.enc_text(recipient)?)
        .bind(self.enc_text(sender)?)
        .bind(content)
        .bind(expires_at)
        .bind(self.hmac("mailbox.recipient", recipient))
        .bind(self.hmac("mailbox.sender", sender))
        .bind(signature)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Get all mailbox messages for a recipient.
    pub async fn get_mailbox_messages(&self, recipient: &str) -> Result<Vec<crate::p2p::types::MailboxMessageItem>> {
        type RawMailboxRow = (String, String, Vec<u8>, String, Option<Vec<u8>>);
        let rows: Vec<RawMailboxRow> =
            sqlx::query_as("SELECT id, sender_peer_id, encrypted_content, timestamp, signature FROM mailbox_storage WHERE recipient_hmac = ? ORDER BY timestamp ASC")
                .bind(self.hmac("mailbox.recipient", recipient))
                .fetch_all(&self.pool)
                .await?;
        Ok(Self::collect_tolerant(
            rows.into_iter().map(|(id, sender, content, ts, signature)| {
                Ok(crate::p2p::types::MailboxMessageItem {
                    id,
                    sender: self.dec_text(&sender)?,
                    content,
                    timestamp: ts,
                    signature: signature.unwrap_or_default(),
                })
            }),
            "mailbox",
        ))
    }

    /// Delete a specific mailbox message by id.
    pub async fn delete_mailbox_message(&self, id: &str) -> Result<()> {
        sqlx::query("DELETE FROM mailbox_storage WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Delete all mailbox messages for a recipient (after retrieval).
    pub async fn delete_mailbox_messages_for_recipient(&self, recipient: &str) -> Result<u64> {
        let result = sqlx::query("DELETE FROM mailbox_storage WHERE recipient_hmac = ?")
            .bind(self.hmac("mailbox.recipient", recipient))
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    /// Cleanup expired mailbox messages. Returns count deleted.
    pub async fn cleanup_expired_mailbox(&self) -> Result<u64> {
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let result = sqlx::query("DELETE FROM mailbox_storage WHERE expires_at < ?")
            .bind(&now)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    /// Get count of mailbox messages for a recipient (for debugging/stats).
    pub async fn get_mailbox_message_count(&self, recipient: &str) -> Result<i64> {
        let row: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM mailbox_storage WHERE recipient_hmac = ?")
                .bind(self.hmac("mailbox.recipient", recipient))
                .fetch_one(&self.pool)
                .await?;
        Ok(row.0)
    }

    /// Count envelopes from one sender to one recipient — mailbox quota check.
    pub async fn get_mailbox_count_for_pair(&self, recipient: &str, sender: &str) -> Result<i64> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM mailbox_storage WHERE recipient_hmac = ? AND sender_hmac = ?",
        )
        .bind(self.hmac("mailbox.recipient", recipient))
        .bind(self.hmac("mailbox.sender", sender))
        .fetch_one(&self.pool)
        .await?;
        Ok(row.0)
    }

    /// Get (recipient_peer_id, sender_peer_id) for an envelope — used to
    /// authorize Delete: only the envelope's recipient or sender may remove it.
    pub async fn get_mailbox_message_parties(&self, id: &str) -> Result<Option<(String, String)>> {
        let row = sqlx::query_as::<_, (String, String)>(
            "SELECT recipient_peer_id, sender_peer_id FROM mailbox_storage WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        match row {
            Some((r, s)) => Ok(Some((self.dec_text(&r)?, self.dec_text(&s)?))),
            None => Ok(None),
        }
    }
}
