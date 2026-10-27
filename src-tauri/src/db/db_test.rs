//! Test helpers for DB integration tests.
//!
//! Creates a temporary SQLite database with all migrations applied.

use crate::db::Database;
use anyhow::Result;
use tempfile::TempDir;

/// Create a temporary database with all migrations applied.
/// Returns (Database, TempDir) — keep TempDir alive to preserve the DB file.
pub async fn setup_test_db() -> Result<(Database, TempDir)> {
    let dir = tempfile::tempdir()?;
    let db_path = dir.path().join("test.db");
    let db = Database::new(&db_path).await?;
    Ok((db, dir))
}
