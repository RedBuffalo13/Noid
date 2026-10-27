use anyhow::Result;
use crate::db::database::Database;

impl Database {
    /// Save the X3DH identity key pair (single row, id=1).
    /// The private key is field-encrypted when a cipher is attached.
    pub async fn save_identity_key(&self, pub_key: &[u8], priv_key: &[u8]) -> Result<()> {
        sqlx::query(
            "INSERT OR REPLACE INTO identity_key (id, public_key, private_key) VALUES (1, ?, ?)",
        )
        .bind(pub_key)
        .bind(self.enc_bytes(priv_key)?)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Load the X3DH identity key pair. Returns (public, private) or None.
    pub async fn get_identity_key(&self) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        let row: Option<(Vec<u8>, Vec<u8>)> =
            sqlx::query_as("SELECT public_key, private_key FROM identity_key WHERE id = 1")
                .fetch_optional(&self.pool)
                .await?;
        match row {
            Some((p, s)) => Ok(Some((p, self.dec_bytes(&s)?))),
            None => Ok(None),
        }
    }

    /// Save the signed prekey (replaces any existing one).
    pub async fn save_signed_prekey(&self, pub_key: &[u8], priv_key: &[u8]) -> Result<()> {
        // Delete existing signed prekey first
        sqlx::query("DELETE FROM prekeys WHERE key_type = 'signed_prekey'")
            .execute(&self.pool)
            .await?;
        sqlx::query(
            "INSERT INTO prekeys (key_type, public_key, private_key) VALUES ('signed_prekey', ?, ?)",
        )
        .bind(pub_key)
        .bind(self.enc_bytes(priv_key)?)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Load the signed prekey. Returns (public, private) or None.
    pub async fn get_signed_prekey(&self) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        let row: Option<(Vec<u8>, Vec<u8>)> =
            sqlx::query_as("SELECT public_key, private_key FROM prekeys WHERE key_type = 'signed_prekey' LIMIT 1")
                .fetch_optional(&self.pool)
                .await?;
        match row {
            Some((p, s)) => Ok(Some((p, self.dec_bytes(&s)?))),
            None => Ok(None),
        }
    }

    /// Add a one-time prekey. Returns the row id.
    pub async fn add_one_time_prekey(&self, pub_key: &[u8], priv_key: &[u8]) -> Result<i64> {
        let result = sqlx::query(
            "INSERT INTO prekeys (key_type, public_key, private_key) VALUES ('one_time_prekey', ?, ?)",
        )
        .bind(pub_key)
        .bind(self.enc_bytes(priv_key)?)
        .execute(&self.pool)
        .await?;
        Ok(result.last_insert_rowid())
    }

    /// Consume a one-time prekey by its public key (marks as consumed, returns private key).
    pub async fn consume_one_time_prekey(&self, pub_key: &[u8]) -> Result<Option<Vec<u8>>> {
        // First, try to find and mark as consumed
        let row: Option<(Vec<u8>, bool)> =
            sqlx::query_as("SELECT private_key, is_consumed FROM prekeys WHERE key_type = 'one_time_prekey' AND public_key = ? LIMIT 1")
                .bind(pub_key)
                .fetch_optional(&self.pool)
                .await?;

        match row {
            Some((priv_key, already_consumed)) => {
                if already_consumed {
                    log::warn!("One-time prekey already consumed");
                    return Ok(None);
                }
                // Mark as consumed
                sqlx::query("UPDATE prekeys SET is_consumed = 1 WHERE key_type = 'one_time_prekey' AND public_key = ?")
                    .bind(pub_key)
                    .execute(&self.pool)
                    .await?;
                Ok(Some(self.dec_bytes(&priv_key)?))
            }
            None => Ok(None),
        }
    }

    /// Read a one-time prekey's private key by public key WITHOUT consuming it.
    /// Returns None when the key is missing or already consumed. The consume
    /// step must happen separately, only after the X3DH session is installed —
    /// consuming first would lose the key if session establishment fails.
    pub async fn get_one_time_prekey(&self, pub_key: &[u8]) -> Result<Option<Vec<u8>>> {
        let row: Option<(Vec<u8>, bool)> =
            sqlx::query_as("SELECT private_key, is_consumed FROM prekeys WHERE key_type = 'one_time_prekey' AND public_key = ? LIMIT 1")
                .bind(pub_key)
                .fetch_optional(&self.pool)
                .await?;

        match row {
            Some((priv_key, false)) => Ok(Some(self.dec_bytes(&priv_key)?)),
            _ => Ok(None),
        }
    }

    /// Get count of available (unconsumed) one-time prekeys.
    pub async fn get_one_time_prekey_count(&self) -> Result<i64> {
        let row: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM prekeys WHERE key_type = 'one_time_prekey' AND is_consumed = 0")
                .fetch_one(&self.pool)
                .await?;
        Ok(row.0)
    }

    /// Up to `limit` available one-time prekey PUBLIC keys — the pool that
    /// gets advertised inside a PrekeyBundle (S1).
    pub async fn get_available_one_time_prekey_pubs(&self, limit: i64) -> Result<Vec<Vec<u8>>> {
        let rows: Vec<(Vec<u8>,)> = sqlx::query_as(
            "SELECT public_key FROM prekeys WHERE key_type = 'one_time_prekey' AND is_consumed = 0 LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(p,)| p).collect())
    }

    /// Get an available one-time prekey (public + private). Does not consume it.
    pub async fn get_available_one_time_prekey(&self) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        let row: Option<(Vec<u8>, Vec<u8>)> =
            sqlx::query_as("SELECT public_key, private_key FROM prekeys WHERE key_type = 'one_time_prekey' AND is_consumed = 0 LIMIT 1")
                .fetch_optional(&self.pool)
                .await?;
        match row {
            Some((p, s)) => Ok(Some((p, self.dec_bytes(&s)?))),
            None => Ok(None),
        }
    }

    /// Delete all prekeys (for KillPin wipe).
    pub async fn delete_all_prekeys(&self) -> Result<()> {
        sqlx::query("DELETE FROM prekeys")
            .execute(&self.pool)
            .await?;
        sqlx::query("DELETE FROM identity_key")
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
