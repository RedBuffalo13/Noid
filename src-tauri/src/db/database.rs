use anyhow::Result;
use sqlx::{sqlite::SqliteConnectOptions, Pool, Sqlite};
use std::path::Path;
use std::sync::Arc;

use crate::security::field_cipher::FieldCipher;

/// Clone yields a snapshot sharing the same connection pool and the cipher
/// attached at clone time. Never clone before `attach_cipher` ran — the copy
/// would silently write plaintext. Mailbox/event handlers clone once after
/// login precisely so they don't hold the global `AppState.db` mutex across
/// calls that re-lock it (RC1 deadlock fix).
#[derive(Clone)]
pub struct Database {
    pub pool: Pool<Sqlite>,
    /// Master-key field cipher, attached after login. Stores fall back to
    /// legacy plaintext mode when absent (unit tests, unmigrated relays).
    cipher: Option<Arc<FieldCipher>>,
}

impl Database {
    pub async fn new(path: &Path) -> Result<Self> {
        // DB17: `SqliteConnectOptions::new().filename()` instead of URL
        // formatting — `format!("sqlite:{}", lossy)` breaks on `?`, `#` and
        // non-UTF8 paths. Pragmas: sqlx leaves `journal_mode` at the SQLite
        // default (DELETE journal, synchronous=FULL) — WAL + NORMAL give
        // crash safety with far less fsync latency; foreign_keys enable the
        // cascades migrations declare; busy_timeout covers WAL read/write
        // contention instead of instant SQLITE_BUSY.
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .synchronous(sqlx::sqlite::SqliteSynchronous::Normal)
            .foreign_keys(true)
            .busy_timeout(std::time::Duration::from_secs(10))
            // DB23: overwritten pages are zeroed on delete instead of
            // lingering in freelist/-wal alongside the post-migration VACUUM.
            .pragma("secure_delete", "ON");

        // A single-writer workload never benefits from 10 connections; a
        // smaller pool also shortens lock contention in WAL mode.
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await?;

        sqlx::migrate!("./migrations").run(&pool).await?;

        Ok(Self {
            pool,
            cipher: None,
        })
    }

    /// Attach the master-key field cipher (post-login) and encrypt any
    /// legacy plaintext rows in a single migration pass. Fail-closed: if the
    /// migration fails the cipher is detached again, so no later write can
    /// land encrypted while legacy rows remain plaintext (or vice versa).
    pub async fn attach_cipher(&mut self, cipher: Arc<FieldCipher>) -> Result<()> {
        self.cipher = Some(cipher);
        match self.migrate_plaintext_fields().await {
            Ok(()) => Ok(()),
            Err(e) => {
                self.cipher = None;
                Err(e)
            }
        }
    }

    /// The field cipher, if attached.
    pub fn cipher(&self) -> Option<&Arc<FieldCipher>> {
        self.cipher.as_ref()
    }

    /// Encrypt a text field for storage (legacy passthrough without cipher).
    pub fn enc_text(&self, plaintext: &str) -> Result<String> {
        match &self.cipher {
            Some(c) => c.encrypt_text(plaintext),
            None => Ok(plaintext.to_string()),
        }
    }

    /// Decrypt a text field read from storage.
    pub fn dec_text(&self, stored: &str) -> Result<String> {
        match &self.cipher {
            Some(c) => c.decrypt_text(stored),
            None => Ok(stored.to_string()),
        }
    }

    /// Encrypt raw bytes for a BLOB column.
    pub fn enc_bytes(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        match &self.cipher {
            Some(c) => c.encrypt_bytes(plaintext),
            None => Ok(plaintext.to_vec()),
        }
    }

    /// Decrypt an optional text field — NULL stays NULL.
    pub fn dec_opt(&self, stored: Option<String>) -> Result<Option<String>> {
        stored.map(|s| self.dec_text(&s)).transpose()
    }

    /// Decrypt a BLOB read from storage.
    pub fn dec_bytes(&self, stored: &[u8]) -> Result<Vec<u8>> {
        match &self.cipher {
            Some(c) => c.decrypt_bytes(stored),
            None => Ok(stored.to_vec()),
        }
    }

    /// Deterministic HMAC lookup token for an equality-searchable column.
    /// Returns the plaintext itself in legacy mode (no cipher attached).
    pub fn hmac(&self, namespace: &str, value: &str) -> String {
        match &self.cipher {
            Some(c) => c.hmac_hex(namespace, value),
            None => value.to_string(),
        }
    }

    /// DB10: wire timestamps are untrusted input. A non-RFC3339 string
    /// breaks lexicographic `ORDER BY` / `>` comparisons; a far-future
    /// value parks the row as permanently "newest". Unparseable or
    /// >24h-future values are replaced by local now; the rest are
    /// > normalized to `...Z` milliseconds.
    pub fn sanitize_ts(ts: &str) -> String {
        let now = chrono::Utc::now();
        chrono::DateTime::parse_from_rfc3339(ts)
            .map(|d| {
                if d > now + chrono::Duration::hours(24) {
                    now
                } else {
                    d.with_timezone(&chrono::Utc)
                }
            })
            .unwrap_or(now)
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
    }

    /// DB4: one corrupt ciphertext must not poison a whole list read.
    /// Collects Ok rows and logs-and-skips decode failures instead of
    /// propagating the first error.
    pub(crate) fn collect_tolerant<T>(
        rows: impl IntoIterator<Item = Result<T>>,
        what: &str,
    ) -> Vec<T> {
        rows.into_iter()
            .filter_map(|r| match r {
                Ok(v) => Some(v),
                Err(e) => {
                    log::warn!("Skipping undecryptable {} row: {}", what, e);
                    None
                }
            })
            .collect()
    }

    /// Periodic maintenance — runs once per login from the gate task.
    /// - DB11: inbound messages from non-contacts are invisible to the UI
    ///   (it iterates the contact list) but kept so history appears when the
    ///   contact is added later; after 30 days they are dead weight — purge.
    ///   Outbound rows are protected by `receiver_hmac = me`.
    /// - DB24: `contact_requests` get a 30-day TTL plus a hard cap of 500
    ///   (avatars carry data-URLs — unbounded senders = unbounded rows).
    /// - DB25: `ratchet_states` accumulate for every X3DH peer, not just
    ///   contacts — prune non-contact states idle for 30 days.
    ///
    /// `contact_requests.timestamp` / `ratchet_states.updated_at` use SQLite
    /// CURRENT_TIMESTAMP format → `datetime('now', ...)` SQL-side; the
    /// `messages` timestamps are sanitized RFC3339 → string-compare cutoff.
    pub async fn maintenance_cleanup(&self, my_id: &str) -> Result<()> {
        let msg_cutoff = (chrono::Utc::now() - chrono::Duration::days(30))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let me_hmac = self.hmac("msg.receiver", my_id);
        let mut tx = self.pool.begin().await?;
        let r1 = sqlx::query(
            "DELETE FROM messages WHERE receiver_hmac = ? \
             AND sender_hmac NOT IN (SELECT id_hmac FROM contacts) \
             AND timestamp < ?",
        )
        .bind(&me_hmac)
        .bind(&msg_cutoff)
        .execute(&mut *tx)
        .await?;
        let r2 = sqlx::query(
            "DELETE FROM contact_requests WHERE timestamp < datetime('now', '-30 days')",
        )
        .execute(&mut *tx)
        .await?;
        let r3 = sqlx::query(
            "DELETE FROM contact_requests WHERE sender_id NOT IN \
             (SELECT sender_id FROM contact_requests ORDER BY timestamp DESC LIMIT 500)",
        )
        .execute(&mut *tx)
        .await?;
        let r4 = sqlx::query(
            "DELETE FROM ratchet_states WHERE peer_hmac NOT IN \
             (SELECT id_hmac FROM contacts) \
             AND updated_at < datetime('now', '-30 days')",
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        let total = r1.rows_affected() + r2.rows_affected() + r3.rows_affected() + r4.rows_affected();
        if total > 0 {
            log::info!(
                "Maintenance cleanup: {} orphan msgs, {} stale+overflow requests, {} orphan ratchet states",
                r1.rows_affected(),
                r2.rows_affected() + r3.rows_affected(),
                r4.rows_affected()
            );
        }
        Ok(())
    }

    /// One-pass migration: encrypt plaintext rows written before field
    /// encryption existed. Rows are detected by NULL hmac columns.
    /// Logs at info level only when rows were actually migrated — the pass
    /// runs on every login and is a no-op once the DB is fully encrypted.
    async fn migrate_plaintext_fields(&self) -> Result<()> {
        let Some(c) = &self.cipher else { return Ok(()) };
        let mut migrated = 0usize;

        // messages: encrypt sender_id/receiver_id, fill hmac columns
        let rows: Vec<(String, String, String)> = sqlx::query_as(
            "SELECT id, sender_id, receiver_id FROM messages WHERE sender_hmac IS NULL",
        )
        .fetch_all(&self.pool)
        .await?;
        migrated += rows.len();
        for (id, sender, receiver) in rows {
            sqlx::query(
                "UPDATE messages SET sender_id = ?, receiver_id = ?, sender_hmac = ?, receiver_hmac = ? WHERE id = ?",
            )
            .bind(c.encrypt_text(&sender)?)
            .bind(c.encrypt_text(&receiver)?)
            .bind(c.hmac_hex("msg.sender", &sender))
            .bind(c.hmac_hex("msg.receiver", &receiver))
            .bind(&id)
            .execute(&self.pool)
            .await?;
        }

        // pending_messages: encrypt peer_id, fill peer_hmac
        let rows: Vec<(i64, String)> = sqlx::query_as(
            "SELECT id, peer_id FROM pending_messages WHERE peer_hmac IS NULL AND peer_id IS NOT NULL",
        )
        .fetch_all(&self.pool)
        .await?;
        migrated += rows.len();
        for (id, peer) in rows {
            sqlx::query("UPDATE pending_messages SET peer_id = ?, peer_hmac = ? WHERE id = ?")
                .bind(c.encrypt_text(&peer)?)
                .bind(c.hmac_hex("pending.peer", &peer))
                .bind(id)
                .execute(&self.pool)
                .await?;
        }

        // mailbox_storage: encrypt peer ids, fill hmac lookup columns
        let rows: Vec<(String, String, String)> = sqlx::query_as(
            "SELECT id, recipient_peer_id, sender_peer_id FROM mailbox_storage WHERE recipient_hmac IS NULL",
        )
        .fetch_all(&self.pool)
        .await?;
        migrated += rows.len();
        for (id, recipient, sender) in rows {
            sqlx::query(
                "UPDATE mailbox_storage SET recipient_peer_id = ?, sender_peer_id = ?, recipient_hmac = ?, sender_hmac = ? WHERE id = ?",
            )
            .bind(c.encrypt_text(&recipient)?)
            .bind(c.encrypt_text(&sender)?)
            .bind(c.hmac_hex("mailbox.recipient", &recipient))
            .bind(c.hmac_hex("mailbox.sender", &sender))
            .bind(&id)
            .execute(&self.pool)
            .await?;
        }

        // ratchet_states: encrypt peer_id + state blob, fill peer_hmac
        let rows: Vec<(String, Vec<u8>)> = sqlx::query_as(
            "SELECT peer_id, state FROM ratchet_states WHERE peer_hmac IS NULL",
        )
        .fetch_all(&self.pool)
        .await?;
        migrated += rows.len();
        for (peer, state) in rows {
            sqlx::query(
                "UPDATE ratchet_states SET peer_id = ?, state = ?, peer_hmac = ? WHERE peer_id = ?",
            )
            .bind(c.encrypt_text(&peer)?)
            .bind(c.encrypt_bytes(&state)?)
            .bind(c.hmac_hex("ratchet.peer", &peer))
            .bind(&peer)
            .execute(&self.pool)
            .await?;
        }

        // identity_key + prekeys: encrypt private keys (public keys stay public)
        if let Some(row) = sqlx::query_as::<_, (Vec<u8>,)>(
            "SELECT private_key FROM identity_key WHERE id = 1",
        )
        .fetch_optional(&self.pool)
        .await?
        {
            // Already-encrypted rows decrypt fine; plaintext 32-byte rows don't.
            if c.decrypt_bytes(&row.0).is_err() {
                migrated += 1;
                sqlx::query("UPDATE identity_key SET private_key = ? WHERE id = 1")
                    .bind(c.encrypt_bytes(&row.0)?)
                    .execute(&self.pool)
                    .await?;
            }
        }
        let rows: Vec<(i64, Vec<u8>)> = sqlx::query_as(
            "SELECT id, private_key FROM prekeys",
        )
        .fetch_all(&self.pool)
        .await?;
        for (id, priv_key) in rows {
            if c.decrypt_bytes(&priv_key).is_err() {
                migrated += 1;
                sqlx::query("UPDATE prekeys SET private_key = ? WHERE id = ?")
                    .bind(c.encrypt_bytes(&priv_key)?)
                    .bind(id)
                    .execute(&self.pool)
                    .await?;
            }
        }

        // contacts: encrypt id/nickname/avatar, fill id_hmac.
        // avatar is a BLOB column carrying an utf8/base64 string — keep it
        // text-shaped so get_contacts can read it back as String.
        let rows: Vec<(String, Option<String>, Option<Vec<u8>>)> = sqlx::query_as(
            "SELECT id, nickname, avatar FROM contacts WHERE id_hmac IS NULL",
        )
        .fetch_all(&self.pool)
        .await?;
        migrated += rows.len();
        for (id, nickname, avatar) in rows {
            // DB18: a non-UTF8 avatar blob was silently nulled — keep it
            // via lossy decode instead of dropping user data.
            let avatar_txt = avatar
                .as_ref()
                .map(|a| String::from_utf8_lossy(a).into_owned());
            sqlx::query(
                "UPDATE contacts SET id = ?, nickname = ?, avatar = ?, id_hmac = ? WHERE id = ?",
            )
            .bind(c.encrypt_text(&id)?)
            .bind(match &nickname {
                Some(n) => Some(c.encrypt_text(n)?),
                None => None,
            })
            .bind(match &avatar_txt {
                Some(a) => Some(c.encrypt_text(a)?),
                None => None,
            })
            .bind(c.hmac_hex("contact.id", &id))
            .bind(&id)
            .execute(&self.pool)
            .await?;
        }

        // contact_requests: encrypt sender_id/message/nickname/avatar, fill
        // sender_hmac. DB6: avatar was missed — a legacy data-URL avatar made
        // dec_text fail and broke the whole request list permanently.
        type PlainReqRow = (String, Option<String>, Option<String>, Option<String>);
        let rows: Vec<PlainReqRow> = sqlx::query_as(
            "SELECT sender_id, message, nickname, avatar FROM contact_requests WHERE sender_hmac IS NULL",
        )
        .fetch_all(&self.pool)
        .await?;
        migrated += rows.len();
        for (sender, message, nickname, avatar) in rows {
            sqlx::query(
                "UPDATE contact_requests SET sender_id = ?, message = ?, nickname = ?, avatar = ?, sender_hmac = ? WHERE sender_id = ?",
            )
            .bind(c.encrypt_text(&sender)?)
            .bind(match &message {
                Some(m) => Some(c.encrypt_text(m)?),
                None => None,
            })
            .bind(match &nickname {
                Some(n) => Some(c.encrypt_text(n)?),
                None => None,
            })
            .bind(match &avatar {
                Some(a) => Some(c.encrypt_text(a)?),
                None => None,
            })
            .bind(c.hmac_hex("contact_request.sender", &sender))
            .bind(&sender)
            .execute(&self.pool)
            .await?;
        }

        // profile: encrypt nickname/username/avatar + last_sync_time (DB7 —
        // a legacy plaintext cursor used to fail dec_text permanently).
        if let Some(row) = sqlx::query_as::<_, (Option<String>, Option<String>, Option<String>, Option<String>)>(
            "SELECT nickname, username, avatar, last_sync_time FROM profile WHERE id = 1",
        )
        .fetch_optional(&self.pool)
        .await?
        {
            let (nickname, username, avatar, last_sync) = row;
            let enc_opt = |v: &Option<String>| -> Result<Option<String>> {
                match v {
                    // Re-encrypting is safe: detect plaintext by trial decrypt
                    Some(s) if c.decrypt_text(s).is_err() => Ok(Some(c.encrypt_text(s)?)),
                    other => Ok(other.clone()),
                }
            };
            sqlx::query("UPDATE profile SET nickname = ?, username = ?, avatar = ?, last_sync_time = ? WHERE id = 1")
                .bind(enc_opt(&nickname)?)
                .bind(enc_opt(&username)?)
                .bind(enc_opt(&avatar)?)
                .bind(enc_opt(&last_sync)?)
                .execute(&self.pool)
                .await?;
        }

        // shared_folders: encrypt path
        let rows: Vec<(String, String)> =
            sqlx::query_as("SELECT id, path FROM shared_folders WHERE path_hmac IS NULL")
                .fetch_all(&self.pool)
                .await?;
        migrated += rows.len();
        for (id, path) in rows {
            sqlx::query("UPDATE shared_folders SET path = ?, path_hmac = ? WHERE id = ?")
                .bind(c.encrypt_text(&path)?)
                .bind(c.hmac_hex("shared_folder.path", &path))
                .bind(&id)
                .execute(&self.pool)
                .await?;
        }

        // rooms: encrypt name (id is a key fingerprint — public by design)
        let rows: Vec<(String, String)> =
            sqlx::query_as("SELECT id, name FROM rooms WHERE name_hmac IS NULL")
                .fetch_all(&self.pool)
                .await?;
        migrated += rows.len();
        for (id, name) in rows {
            sqlx::query("UPDATE rooms SET name = ?, name_hmac = ? WHERE id = ?")
                .bind(c.encrypt_text(&name)?)
                .bind(c.hmac_hex("room.name", &name))
                .bind(&id)
                .execute(&self.pool)
                .await?;
        }

        // Repair: rooms created before name_hmac was written got their
        // already-encrypted name re-encrypted by the pass above — the stored
        // value decrypts to inner ciphertext, not the real name. Unwrap the
        // extra layers (bounded): AEAD verification makes a false positive
        // on a legit name practically impossible. Rows written in legacy
        // no-cipher mode carry name_hmac == name (identity hmac) — encrypt
        // those too.
        let rows: Vec<(String, String, String)> =
            sqlx::query_as("SELECT id, name, name_hmac FROM rooms WHERE name_hmac IS NOT NULL")
                .fetch_all(&self.pool)
                .await?;
        for (id, name, name_hmac) in rows {
            match c.decrypt_text(&name) {
                Ok(mut plain) => {
                    let mut repaired = false;
                    for _ in 0..2 {
                        match c.decrypt_text(&plain) {
                            Ok(inner) => {
                                plain = inner;
                                repaired = true;
                            }
                            Err(_) => break,
                        }
                    }
                    if repaired {
                        log::warn!("Repaired double-encrypted room name for {}", id);
                        migrated += 1;
                        sqlx::query("UPDATE rooms SET name = ?, name_hmac = ? WHERE id = ?")
                            .bind(c.encrypt_text(&plain)?)
                            .bind(c.hmac_hex("room.name", &plain))
                            .bind(&id)
                            .execute(&self.pool)
                            .await?;
                    }
                }
                Err(_) if name_hmac == name => {
                    // Legacy no-cipher write: both columns are plaintext.
                    log::warn!("Encrypting legacy plaintext room name for {}", id);
                    migrated += 1;
                    sqlx::query("UPDATE rooms SET name = ?, name_hmac = ? WHERE id = ?")
                        .bind(c.encrypt_text(&name)?)
                        .bind(c.hmac_hex("room.name", &name))
                        .bind(&id)
                        .execute(&self.pool)
                        .await?;
                }
                Err(_) => {
                    log::warn!("Room {} has an undecryptable name — needs manual repair", id);
                }
            }
        }

        // room_members: encrypt peer_id, fill peer_hmac
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT room_id, peer_id FROM room_members WHERE peer_hmac IS NULL",
        )
        .fetch_all(&self.pool)
        .await?;
        migrated += rows.len();
        for (room_id, peer) in rows {
            sqlx::query(
                "UPDATE room_members SET peer_id = ?, peer_hmac = ? WHERE room_id = ? AND peer_id = ?",
            )
            .bind(c.encrypt_text(&peer)?)
            .bind(c.hmac_hex("room.member", &peer))
            .bind(&room_id)
            .bind(&peer)
            .execute(&self.pool)
            .await?;
        }

        if migrated > 0 {
            // S17: the UPDATEs above leave the overwritten plaintext bytes
            // in SQLite freelist pages / -wal until reuse — VACUUM rebuilds
            // the database file so the old plaintext is actually gone.
            if let Err(e) = sqlx::query("VACUUM").execute(&self.pool).await {
                log::warn!("VACUUM after field migration failed: {}", e);
            }
            log::info!("Field-encryption migration complete ({} rows)", migrated);
        }
        Ok(())
    }
}
