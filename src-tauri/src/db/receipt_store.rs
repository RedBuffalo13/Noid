//! META-02: dedup store for sealed-sender end-to-end delivery receipts.
//! Receipts echo the sender's `ref_id` inside the ratchet; a replayed or
//! k=2-duplicated receipt must reach the UI once.

use anyhow::Result;
use sqlx::Row;

use crate::db::database::Database;

const RECEIPT_TTL_DAYS: i64 = 30;
const MAX_RECEIPTS: i64 = 10_000;

impl Database {
    /// Record a receipt; `true` when it is new (INSERT OR IGNORE hit).
    /// Opportunistically prunes rows older than 30 days and caps the
    /// table at 10k entries.
    pub async fn record_delivery_receipt(&self, ref_id: &str, sender: &str) -> Result<bool> {
        let sender_hmac = self.hmac("receipt.sender", sender);
        let res = sqlx::query(
            "INSERT OR IGNORE INTO delivery_receipts (ref_id, sender_hmac) VALUES (?, ?)",
        )
        .bind(ref_id)
        .bind(&sender_hmac)
        .execute(&self.pool)
        .await?;
        let fresh = res.rows_affected() > 0;
        if fresh {
            // Bounded sweep — runs on insert, not per read.
            let _ = sqlx::query(
                "DELETE FROM delivery_receipts WHERE received_at < datetime('now', ?)",
            )
            .bind(format!("-{} days", RECEIPT_TTL_DAYS))
            .execute(&self.pool)
            .await;
            let count: i64 = sqlx::query("SELECT COUNT(*) AS c FROM delivery_receipts")
                .fetch_one(&self.pool)
                .await
                .map(|r| r.get::<i64, _>("c"))
                .unwrap_or(0);
            if count > MAX_RECEIPTS {
                let excess = count - MAX_RECEIPTS / 2;
                let _ = sqlx::query(
                    "DELETE FROM delivery_receipts WHERE rowid IN \
                     (SELECT rowid FROM delivery_receipts ORDER BY received_at ASC LIMIT ?)",
                )
                .bind(excess)
                .execute(&self.pool)
                .await;
            }
        }
        Ok(fresh)
    }
}
