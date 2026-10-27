use anyhow::Result;
use crate::db::database::Database;

impl Database {
    /// Profile fields are field-encrypted at rest (single row, id = 1).
    pub async fn get_profile(&self) -> Result<(String, Option<String>)> {
        let row = sqlx::query_as::<_, (String, Option<String>)>(
            "SELECT nickname, avatar FROM profile WHERE id = 1",
        )
        .fetch_one(&self.pool)
        .await?;
        Ok((
            self.dec_text(&row.0)?,
            match row.1 {
                Some(a) => Some(self.dec_text(&a)?),
                None => None,
            },
        ))
    }

    pub async fn update_profile(&self, nickname: &str, avatar: Option<&str>) -> Result<()> {
        // COALESCE: a save that carries no avatar (None) must keep the stored
        // one — previously it overwrote avatar with NULL on every name edit.
        sqlx::query("UPDATE profile SET nickname = ?, avatar = COALESCE(?, avatar) WHERE id = 1")
            .bind(self.enc_text(nickname)?)
            .bind(match avatar {
                Some(a) => Some(self.enc_text(a)?),
                None => None,
            })
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn get_username(&self) -> Result<Option<String>> {
        let row = sqlx::query_as::<_, (Option<String>,)>(
            "SELECT username FROM profile WHERE id = 1",
        )
        .fetch_one(&self.pool)
        .await?;
        match row.0 {
            Some(u) => Ok(Some(self.dec_text(&u)?)),
            None => Ok(None),
        }
    }

    pub async fn set_username(&self, username: &str) -> Result<()> {
        sqlx::query("UPDATE profile SET username = ? WHERE id = 1")
            .bind(self.enc_text(username)?)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn is_username_published(&self) -> Result<bool> {
        let row = sqlx::query_as::<_, (bool,)>(
            "SELECT username_published FROM profile WHERE id = 1",
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(row.0)
    }

    pub async fn set_username_published(&self, published: bool) -> Result<()> {
        sqlx::query("UPDATE profile SET username_published = ? WHERE id = 1")
            .bind(published)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// RC18: `last_sync_time` moved out of raw-SQL command files — the
    /// field-encrypted column lives behind enc/dec_text like every other
    /// profile field. Returns the epoch default when unset.
    pub async fn get_last_sync_time(&self) -> Result<String> {
        let row = sqlx::query_as::<_, (Option<String>,)>(
            "SELECT last_sync_time FROM profile WHERE id = 1",
        )
        .fetch_optional(&self.pool)
        .await?;
        match row.and_then(|r| r.0) {
            Some(s) => self.dec_text(&s),
            None => Ok("1970-01-01T00:00:00Z".to_string()),
        }
    }

    pub async fn set_last_sync_time(&self, ts: &str) -> Result<()> {
        sqlx::query("UPDATE profile SET last_sync_time = ? WHERE id = 1")
            .bind(self.enc_text(ts)?)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
