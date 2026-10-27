use super::db_test::setup_test_db;

#[tokio::test]
async fn test_add_and_get_message() {
    let (db, _dir) = setup_test_db().await.unwrap();
    db.add_message("msg1", "alice", "bob", b"hello world").await.unwrap();
    let messages = db.get_messages_for_contact("alice").await.unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].0, "msg1");
    assert_eq!(messages[0].1, "alice");
    assert_eq!(messages[0].2, b"hello world".to_vec());
}

#[tokio::test]
async fn test_add_message_with_timestamp() {
    let (db, _dir) = setup_test_db().await.unwrap();
    db.add_message_with_timestamp("msg1", "alice", "bob", b"hi", "2024-01-01T00:00:00.000Z").await.unwrap();
    let messages = db.get_messages_for_contact("alice").await.unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].3, "2024-01-01T00:00:00.000Z");
}

#[tokio::test]
async fn test_get_messages_for_contact_both_directions() {
    let (db, _dir) = setup_test_db().await.unwrap();
    db.add_message("msg1", "alice", "bob", b"hello").await.unwrap();
    db.add_message("msg2", "bob", "alice", b"hi back").await.unwrap();
    db.add_message("msg3", "carol", "dave", b"private").await.unwrap();

    let alice_messages = db.get_messages_for_contact("alice").await.unwrap();
    assert_eq!(alice_messages.len(), 2);
}

#[tokio::test]
async fn test_get_messages_since() {
    let (db, _dir) = setup_test_db().await.unwrap();
    db.add_message_with_timestamp("msg1", "alice", "bob", b"old", "2024-01-01T00:00:00.000Z").await.unwrap();
    db.add_message_with_timestamp("msg2", "alice", "bob", b"new", "2024-06-01T00:00:00.000Z").await.unwrap();

    let since = db.get_messages_for_contact_since("alice", "2024-03-01T00:00:00.000Z").await.unwrap();
    assert_eq!(since.len(), 1);
    assert_eq!(since[0].0, "msg2");
}

#[tokio::test]
async fn test_message_exists() {
    let (db, _dir) = setup_test_db().await.unwrap();
    db.add_message("msg1", "alice", "bob", b"hello").await.unwrap();
    assert!(db.message_exists("msg1").await.unwrap());
    assert!(!db.message_exists("msg_nonexistent").await.unwrap());
}

#[tokio::test]
async fn test_duplicate_message_id_fails() {
    let (db, _dir) = setup_test_db().await.unwrap();
    db.add_message("msg1", "alice", "bob", b"hello").await.unwrap();
    let result = db.add_message("msg1", "alice", "bob", b"duplicate").await;
    assert!(result.is_err());
}
