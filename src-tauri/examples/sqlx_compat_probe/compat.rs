extern crate self as security;

#[path = "../../src/security/domains.rs"]
mod domains;
#[path = "../../src/security/field_cipher.rs"]
mod field_cipher;

pub use domains::derive_domain_key;

use anyhow::{bail, ensure, Result};
use base64::Engine;
use field_cipher::FieldCipher;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use std::io::{BufRead, Read};
use std::path::PathBuf;
use zeroize::Zeroizing;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(args.len() == 3, "Expected create|verify and temporary fixture path");
    let create = match args[1].as_str() {
        "create" => true,
        "verify" => false,
        _ => bail!("Unsupported fixture operation"),
    };
    let path = PathBuf::from(&args[2]);
    let parent = path.parent().ok_or_else(|| anyhow::anyhow!("Missing fixture parent"))?;
    ensure!(
        parent.canonicalize()?.starts_with(std::env::temp_dir().canonicalize()?)
            && parent.file_name().and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("noid-sqlx-compat-"))
            && path.file_name().and_then(|s| s.to_str()) == Some("fixture.db"),
        "Only a dedicated temporary fixture is permitted"
    );
    ensure!(path.exists() != create, "Refusing to overwrite or create an absent fixture");
    let pool = SqlitePoolOptions::new().max_connections(1).connect_with(
        SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(create)
            .journal_mode(SqliteJournalMode::Wal)
            .foreign_keys(true)
            .pragma("secure_delete", "ON"),
    ).await?;
    let schema_before: Vec<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT type, name, sql FROM sqlite_master ORDER BY type, name",
    ).fetch_all(&pool).await?;
    let migrations = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../migrations");
    let migrator = sqlx::migrate::Migrator::new(migrations.as_path()).await?;
    migrator.run(&pool).await?;
    let mut encoded = Zeroizing::new(String::new());
    std::io::stdin().lock().take(47).read_line(&mut encoded)?;
    let encoded = encoded.trim_end_matches(['\r', '\n']);
    ensure!(encoded.len() == 44, "Expected a temporary fixture key on stdin");
    let key = Zeroizing::new(base64::engine::general_purpose::STANDARD.decode(encoded)?);
    let key = Zeroizing::new(
        <[u8; 32]>::try_from(key.as_slice()).map_err(|_| anyhow::anyhow!("Invalid fixture key size"))?,
    );
    let cipher = FieldCipher::new(*key);
    let peer = "driver-compat-fixture-peer";
    let content = b"driver-compat-fixture-message";
    let ratchet = b"driver-compat-fixture-state";
    let queued = "driver-compat-fixture-envelope";
    if create {
        let mut tx = pool.begin().await?;
        sqlx::query("INSERT INTO contacts (id, nickname, id_hmac) VALUES (?, ?, ?)")
            .bind(cipher.encrypt_text(peer)?)
            .bind(cipher.encrypt_text("fixture-contact")?)
            .bind(cipher.hmac_hex("contact.id", peer))
            .execute(&mut *tx).await?;
        sqlx::query("INSERT INTO messages (id, sender_id, receiver_id, content) VALUES (?, ?, ?, ?)")
            .bind("fixture-message")
            .bind(cipher.encrypt_text(peer)?)
            .bind(cipher.encrypt_text("fixture-recipient")?)
            .bind(cipher.encrypt_bytes(content)?)
            .execute(&mut *tx).await?;
        sqlx::query("INSERT INTO ratchet_states (peer_id, state, peer_hmac) VALUES (?, ?, ?)")
            .bind(cipher.encrypt_text(peer)?)
            .bind(cipher.encrypt_bytes(ratchet)?)
            .bind(cipher.hmac_hex("ratchet.peer", peer))
            .execute(&mut *tx).await?;
        sqlx::query("INSERT INTO pending_messages (peer_id, content, message_id, peer_hmac) VALUES (?, ?, ?, ?)")
            .bind(cipher.encrypt_text(peer)?).bind(queued).bind("fixture-message")
            .bind(cipher.hmac_hex("pending.peer", peer))
            .execute(&mut *tx).await?;
        tx.commit().await?;
    }
    let contact: String = sqlx::query_scalar("SELECT nickname FROM contacts WHERE id_hmac = ?")
        .bind(cipher.hmac_hex("contact.id", peer)).fetch_one(&pool).await?;
    ensure!(cipher.decrypt_text(&contact)? == "fixture-contact", "Contact mismatch");
    let message: Vec<u8> = sqlx::query_scalar("SELECT content FROM messages WHERE id = ?")
        .bind("fixture-message").fetch_one(&pool).await?;
    ensure!(cipher.decrypt_bytes(&message)? == content, "Message mismatch");
    let state: Vec<u8> = sqlx::query_scalar("SELECT state FROM ratchet_states WHERE peer_hmac = ?")
        .bind(cipher.hmac_hex("ratchet.peer", peer)).fetch_one(&pool).await?;
    ensure!(cipher.decrypt_bytes(&state)? == ratchet, "Ratchet ciphertext mismatch");
    let pending: Vec<String> = sqlx::query_scalar(
        "SELECT content FROM pending_messages WHERE peer_hmac = ? AND message_id = ?",
    ).bind(cipher.hmac_hex("pending.peer", peer)).bind("fixture-message")
        .fetch_all(&pool).await?;
    ensure!(pending == [queued], "Outbox lost or duplicated");
    let applied: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations WHERE success = 1")
        .fetch_one(&pool).await?;
    ensure!(applied as usize == migrator.iter().count(), "Migration history mismatch");
    let integrity: String = sqlx::query_scalar("PRAGMA integrity_check").fetch_one(&pool).await?;
    ensure!(integrity == "ok", "SQLite integrity failure");
    if !create {
        let schema_after: Vec<(String, String, Option<String>)> = sqlx::query_as(
            "SELECT type, name, sql FROM sqlite_master ORDER BY type, name",
        ).fetch_all(&pool).await?;
        ensure!(schema_before == schema_after, "Driver upgrade changed schema");
        let mut tx = pool.begin().await?;
        sqlx::query("UPDATE pending_messages SET content = ? WHERE message_id = ?")
            .bind("rolled-back-fixture").bind("fixture-message")
            .execute(&mut *tx).await?;
        tx.rollback().await?;
        let restored: String = sqlx::query_scalar("SELECT content FROM pending_messages WHERE message_id = ?")
            .bind("fixture-message").fetch_one(&pool).await?;
        ensure!(restored == queued, "Rollback modified durable outbox");
    }
    pool.close().await;
    println!("fixture {}: encrypted contacts/message/state, durable outbox, migrations and integrity OK", args[1]);
    Ok(())
}
