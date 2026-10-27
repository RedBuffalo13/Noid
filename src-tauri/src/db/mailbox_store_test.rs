use super::db_test::setup_test_db;

#[tokio::test]
async fn test_store_and_get_mailbox_message() {
    let (db, _dir) = setup_test_db().await.unwrap();
    db.store_mailbox_message("msg1", "recipient1", "sender1", b"encrypted", "2024-12-31T23:59:59.000Z", b"sig").await.unwrap();
    let messages = db.get_mailbox_messages("recipient1").await.unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].id, "msg1");
    assert_eq!(messages[0].sender, "sender1");
    assert_eq!(messages[0].content, b"encrypted".to_vec());
    assert_eq!(messages[0].signature, b"sig".to_vec());
}

#[tokio::test]
async fn test_mailbox_signature_roundtrip() {
    let (db, _dir) = setup_test_db().await.unwrap();
    let sig = vec![0xAA; 64];
    db.store_mailbox_message("msg1", "r1", "s1", b"payload", "2099-01-01T00:00:00.000Z", &sig).await.unwrap();
    let messages = db.get_mailbox_messages("r1").await.unwrap();
    assert_eq!(messages[0].signature, sig);
    // Rows stored before the signature column / by older versions return empty.
    sqlx::query("UPDATE mailbox_storage SET signature = NULL WHERE id = 'msg1'")
        .execute(&db.pool).await.unwrap();
    let messages = db.get_mailbox_messages("r1").await.unwrap();
    assert!(messages[0].signature.is_empty());
}

#[tokio::test]
async fn test_store_mailbox_replaces_existing() {
    let (db, _dir) = setup_test_db().await.unwrap();
    db.store_mailbox_message("msg1", "r1", "s1", b"old", "2024-12-31T23:59:59.000Z", b"").await.unwrap();
    db.store_mailbox_message("msg1", "r1", "s1", b"new", "2024-12-31T23:59:59.000Z", b"").await.unwrap();
    let messages = db.get_mailbox_messages("r1").await.unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].content, b"new".to_vec());
}

#[tokio::test]
async fn test_get_mailbox_filters_by_recipient() {
    let (db, _dir) = setup_test_db().await.unwrap();
    db.store_mailbox_message("msg1", "r1", "s1", b"data1", "2024-01-01T00:00:00.000Z", b"").await.unwrap();
    db.store_mailbox_message("msg2", "r2", "s2", b"data2", "2024-01-01T00:00:00.000Z", b"").await.unwrap();
    let r1_messages = db.get_mailbox_messages("r1").await.unwrap();
    assert_eq!(r1_messages.len(), 1);
}

#[tokio::test]
async fn test_delete_mailbox_message() {
    let (db, _dir) = setup_test_db().await.unwrap();
    db.store_mailbox_message("msg1", "r1", "s1", b"data", "2024-01-01T00:00:00.000Z", b"").await.unwrap();
    db.delete_mailbox_message("msg1").await.unwrap();
    let messages = db.get_mailbox_messages("r1").await.unwrap();
    assert_eq!(messages.len(), 0);
}

#[tokio::test]
async fn test_delete_all_mailbox_for_recipient() {
    let (db, _dir) = setup_test_db().await.unwrap();
    db.store_mailbox_message("msg1", "r1", "s1", b"data1", "2024-01-01T00:00:00.000Z", b"").await.unwrap();
    db.store_mailbox_message("msg2", "r1", "s2", b"data2", "2024-01-01T00:00:00.000Z", b"").await.unwrap();
    let count = db.delete_mailbox_messages_for_recipient("r1").await.unwrap();
    assert_eq!(count, 2);
    let messages = db.get_mailbox_messages("r1").await.unwrap();
    assert_eq!(messages.len(), 0);
}

#[tokio::test]
async fn test_cleanup_expired_mailbox() {
    let (db, _dir) = setup_test_db().await.unwrap();
    // Expired message
    db.store_mailbox_message("msg1", "r1", "s1", b"expired", "2020-01-01T00:00:00.000Z", b"").await.unwrap();
    // Non-expired message
    db.store_mailbox_message("msg2", "r1", "s2", b"valid", "2099-12-31T23:59:59.000Z", b"").await.unwrap();
    let deleted = db.cleanup_expired_mailbox().await.unwrap();
    assert_eq!(deleted, 1);
    let messages = db.get_mailbox_messages("r1").await.unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].id, "msg2");
}

#[tokio::test]
async fn test_mailbox_message_count() {
    let (db, _dir) = setup_test_db().await.unwrap();
    db.store_mailbox_message("msg1", "r1", "s1", b"data1", "2099-01-01T00:00:00.000Z", b"").await.unwrap();
    db.store_mailbox_message("msg2", "r1", "s2", b"data2", "2099-01-01T00:00:00.000Z", b"").await.unwrap();
    assert_eq!(db.get_mailbox_message_count("r1").await.unwrap(), 2);
    assert_eq!(db.get_mailbox_message_count("r2").await.unwrap(), 0);
}
