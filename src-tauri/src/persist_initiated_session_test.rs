use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use rand::RngCore;
use tokio::sync::{oneshot, Mutex};
use tokio::time::timeout;
use x25519_dalek::StaticSecret;

use crate::db::db_test::setup_test_db;
use crate::persist_initiated_session::persist_initiated_session;
use crate::security::field_cipher::FieldCipher;
use crate::security::RatchetSessionManager;

#[tokio::test]
async fn initiated_session_persistence_releases_global_db_lock() -> Result<()> {
    let (mut db, _dir) = setup_test_db().await?;
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    db.attach_cipher(Arc::new(FieldCipher::new(key))).await?;
    let (remote_db, _remote_dir) = setup_test_db().await?;
    let sessions = Arc::new(RatchetSessionManager::init_from_db(&db).await?);
    let remote = RatchetSessionManager::init_from_db(&remote_db).await?;
    let mut bundle = remote.generate_and_store_prekeys(&remote_db).await?;
    bundle.one_time_prekey_public = None;
    bundle.one_time_prekeys.clear();
    let initial = sessions.initiate_session("remote", &bundle).await?;
    let db_state = Arc::new(Mutex::new(Some(db.clone())));

    // Block the first write so a task holding the global DB mutex cannot
    // hide behind fast SQLite I/O. History/other sends must still get a snapshot.
    let mut writer = db.pool.begin().await?;
    sqlx::query("UPDATE profile SET nickname = nickname")
        .execute(&mut *writer)
        .await?;
    let task_db = db_state.clone();
    let task_sessions = sessions.clone();
    let public_key = bundle.identity_public.clone();
    let (started_tx, started_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        let _ = started_tx.send(());
        persist_initiated_session(&task_db, &task_sessions, "remote", &public_key).await
    });
    // On this single-thread runtime, the task runs until the SQL await
    // before the receiver resumes; no scheduler-dependent sleep is needed.
    started_rx.await?;
    let available = timeout(Duration::from_millis(500), db_state.lock()).await;
    let unlocked = available.is_ok();
    drop(available);
    writer.rollback().await?;
    assert!(unlocked, "X3DH persistence must not hold the global DB mutex during SQL I/O");
    let snapshot = timeout(Duration::from_secs(3), task).await???;

    assert_eq!(
        snapshot.get_contact_public_key("remote").await?,
        Some(bundle.identity_public),
    );
    assert!(snapshot.get_ratchet_state("remote").await?.is_some());
    let restored = RatchetSessionManager::new();
    assert!(restored.load_session(&snapshot, "remote").await?);
    let (_, signed_prekey_secret) = remote_db
        .get_signed_prekey()
        .await?
        .ok_or_else(|| anyhow::anyhow!("missing signed prekey"))?;
    let secret_bytes: [u8; 32] = signed_prekey_secret.as_slice().try_into()?;
    remote.receive_session("me", &initial, &StaticSecret::from(secret_bytes), None).await?;
    let encrypted = restored.encrypt("remote", b"handshake regression").await?
        .ok_or_else(|| anyhow::anyhow!("missing restored session"))?;
    assert_eq!(remote.decrypt("me", &encrypted).await?, b"handshake regression");

    // This is the next operation in the production handler; it must not
    // re-lock a mutex still held by the preceding session save.
    timeout(Duration::from_secs(1), async {
        let db = db_state.lock().await.clone().ok_or_else(|| anyhow::anyhow!("missing DB"))?;
        db.add_pending_message_with_content("remote", "encrypted-init-fixture", "init-1").await?;
        db.add_message("chat-1", "me", "remote", b"encrypted-chat-fixture").await?;
        let history = db.get_messages_for_contact("remote").await?;
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].0, "chat-1");
        assert_eq!(db.get_pending_message_ids("remote").await?, vec!["init-1"]);
        Ok::<_, anyhow::Error>(())
    }).await??;
    Ok(())
}

#[tokio::test]
async fn initiated_session_persistence_requires_unlocked_db() {
    let db_state = Mutex::new(None);
    let sessions = RatchetSessionManager::new();
    let result = persist_initiated_session(&db_state, &sessions, "remote", &[]).await;
    assert!(result.is_err());
    assert!(db_state.try_lock().is_ok());
}
