use anyhow::Result;
use crate::db::database::Database;

impl Database {
    /// Persist a ratchet session state. The peer id is field-encrypted and
    /// looked up through its deterministic `peer_hmac` token; the state blob
    /// (which contains private ratchet keys) is always field-encrypted.
    pub async fn save_ratchet_state(&self, peer_id: &str, state: &[u8]) -> Result<()> {
        // peer_id is the PK but stores randomized GCM ciphertext, so
        // upsert-by-PK cannot dedupe — delete by the deterministic hmac
        // first. CR-02: both writes run inside ONE transaction — a crash
        // between DELETE and INSERT used to lose the session outright,
        // and concurrent saves could interleave into duplicate rows.
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM ratchet_states WHERE peer_hmac = ?")
            .bind(self.hmac("ratchet.peer", peer_id))
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO ratchet_states (peer_id, state, updated_at, peer_hmac) VALUES (?, ?, ?, ?)",
        )
        .bind(self.enc_text(peer_id)?)
        .bind(self.enc_bytes(state)?)
        .bind(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
        .bind(self.hmac("ratchet.peer", peer_id))
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn get_ratchet_state(&self, peer_id: &str) -> Result<Option<Vec<u8>>> {
        // ORDER BY guards rows written before the peer_hmac UNIQUE index —
        // a stray older duplicate can never shadow the newest state.
        let row: Option<(Vec<u8>,)> = sqlx::query_as(
            "SELECT state FROM ratchet_states WHERE peer_hmac = ? ORDER BY updated_at DESC LIMIT 1",
        )
        .bind(self.hmac("ratchet.peer", peer_id))
        .fetch_optional(&self.pool)
        .await?;
        match row {
            Some((state,)) => Ok(Some(self.dec_bytes(&state)?)),
            None => Ok(None),
        }
    }

    pub async fn delete_ratchet_state(&self, peer_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM ratchet_states WHERE peer_hmac = ?")
            .bind(self.hmac("ratchet.peer", peer_id))
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
