use anyhow::Result;
use crate::db::database::Database;

impl Database {
    /// `path` is field-encrypted at rest.
    pub async fn add_shared_folder(&self, id: &str, path: &str, is_public: bool) -> Result<()> {
        sqlx::query("INSERT INTO shared_folders (id, path, is_public, path_hmac) VALUES (?, ?, ?, ?)")
            .bind(id)
            .bind(self.enc_text(path)?)
            .bind(is_public)
            .bind(self.hmac("shared_folder.path", path))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn get_shared_folders(&self) -> Result<Vec<(String, String, bool)>> {
        let rows = sqlx::query_as::<_, (String, String, bool)>(
            "SELECT id, path, is_public FROM shared_folders",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(Self::collect_tolerant(
            rows.into_iter()
                .map(|(id, path, public)| Ok((id, self.dec_text(&path)?, public))),
            "shared_folder",
        ))
    }

    pub async fn update_folder_path(&self, id: &str, new_path: &str) -> Result<()> {
        sqlx::query("UPDATE shared_folders SET path = ?, path_hmac = ? WHERE id = ?")
            .bind(self.enc_text(new_path)?)
            .bind(self.hmac("shared_folder.path", new_path))
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn update_folder_visibility(&self, id: &str, is_public: bool) -> Result<()> {
        sqlx::query("UPDATE shared_folders SET is_public = ? WHERE id = ?")
            .bind(is_public)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn update_folder_password(&self, id: &str, password_hash: &str) -> Result<()> {
        sqlx::query("UPDATE shared_folders SET password_hash = ? WHERE id = ?")
            .bind(password_hash)
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn clear_folder_password(&self, id: &str) -> Result<()> {
        sqlx::query("UPDATE shared_folders SET password_hash = NULL WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn delete_shared_folder(&self, id: &str) -> Result<()> {
        sqlx::query("DELETE FROM shared_folders WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Paths are encrypted, so LIKE cannot run in SQL — decrypt and filter
    /// in memory (folder counts are small).
    pub async fn search_shared_folders(&self, query: &str) -> Result<Vec<(String, String, bool, Option<String>)>> {
        let rows = sqlx::query_as::<_, (String, String, bool, Option<String>)>(
            "SELECT id, path, is_public, password_hash FROM shared_folders",
        )
        .fetch_all(&self.pool)
        .await?;
        let needle = query.to_lowercase();
        Ok(Self::collect_tolerant(
            rows.into_iter()
                .map(|(id, path, public, pw)| Ok((id, self.dec_text(&path)?, public, pw)))
                .filter(|r| match r {
                    Ok((_, path, _, _)) => path.to_lowercase().contains(&needle),
                    Err(_) => true,
                }),
            "shared_folder",
        ))
    }
}
