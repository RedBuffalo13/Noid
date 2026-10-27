use super::db_test::setup_test_db;

#[tokio::test]
async fn test_add_and_get_contact() {
    let (db, _dir) = setup_test_db().await.unwrap();
    db.add_contact("peer1", "Alice", Some("avatar_data")).await.unwrap();
    let contacts = db.get_contacts().await.unwrap();
    assert_eq!(contacts.len(), 1);
    assert_eq!(contacts[0].0, "peer1");
    assert_eq!(contacts[0].1, Some("Alice".to_string()));
    assert_eq!(contacts[0].2, Some("avatar_data".to_string()));
}

#[tokio::test]
async fn test_add_contact_replaces_existing() {
    let (db, _dir) = setup_test_db().await.unwrap();
    db.add_contact("peer1", "Alice", None).await.unwrap();
    db.add_contact("peer1", "AliceUpdated", None).await.unwrap();
    let contacts = db.get_contacts().await.unwrap();
    assert_eq!(contacts.len(), 1);
    assert_eq!(contacts[0].1, Some("AliceUpdated".to_string()));
}

#[tokio::test]
async fn test_save_and_get_contact_public_key() {
    let (db, _dir) = setup_test_db().await.unwrap();
    db.add_contact("peer1", "Alice", None).await.unwrap();
    let key = vec![1u8; 32];
    db.save_contact_public_key("peer1", &key).await.unwrap();
    let loaded = db.get_contact_public_key("peer1").await.unwrap();
    assert_eq!(loaded, Some(key));
}

#[tokio::test]
async fn test_get_contact_public_key_nonexistent() {
    let (db, _dir) = setup_test_db().await.unwrap();
    let result = db.get_contact_public_key("nonexistent").await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn test_add_and_get_contact_request() {
    let (db, _dir) = setup_test_db().await.unwrap();
    db.add_contact_request("peer1", "Hi, add me", "Bob", Some("avatar")).await.unwrap();
    let requests = db.get_contact_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].0, "peer1");
    assert_eq!(requests[0].1, "Hi, add me");
    assert_eq!(requests[0].2, "Bob");
    assert_eq!(requests[0].3, Some("avatar".to_string()));
}

#[tokio::test]
async fn test_delete_contact_request() {
    let (db, _dir) = setup_test_db().await.unwrap();
    db.add_contact_request("peer1", "Hi", "Bob", None).await.unwrap();
    db.delete_contact_request("peer1").await.unwrap();
    let requests = db.get_contact_requests().await.unwrap();
    assert_eq!(requests.len(), 0);
}

/// Regression: `id` is stored field-encrypted, so `DELETE WHERE id = ?`
/// against the plaintext peer id matched nothing and contact deletion was a
/// silent no-op. `delete_contact` must go through the `id_hmac` token.
#[tokio::test]
async fn test_delete_contact_with_cipher() {
    let (mut db, _dir) = setup_test_db().await.unwrap();
    db.attach_cipher(std::sync::Arc::new(
        crate::security::field_cipher::FieldCipher::new([11u8; 32]),
    ))
    .await
    .unwrap();

    db.add_contact("peer1", "Alice", None).await.unwrap();
    db.add_contact_request("peer1", "Hi", "Alice", None).await.unwrap();
    db.add_message("m1", "peer1", "me", b"hello").await.unwrap();
    db.add_pending_message("peer1", "pm1").await.unwrap();
    db.save_ratchet_state("peer1", b"state").await.unwrap();
    db.add_contact("peer2", "Bob", None).await.unwrap();
    db.add_message("m2", "peer2", "me", b"keep").await.unwrap();

    db.delete_contact("peer1").await.unwrap();

    let contacts = db.get_contacts().await.unwrap();
    assert_eq!(contacts.len(), 1);
    assert_eq!(contacts[0].0, "peer2");
    assert!(db.get_contact_requests().await.unwrap().is_empty());
    assert!(db.get_messages_for_contact("peer1").await.unwrap().is_empty());
    assert!(db.get_pending_messages("peer1").await.unwrap().is_empty());
    assert!(db.get_ratchet_state("peer1").await.unwrap().is_none());
    // Other peers' history is untouched.
    assert_eq!(db.get_messages_for_contact("peer2").await.unwrap().len(), 1);
}

/// `delete_chat` clears the conversation but keeps the contact and the
/// ratchet session.
#[tokio::test]
async fn test_delete_chat_keeps_contact_and_ratchet() {
    let (mut db, _dir) = setup_test_db().await.unwrap();
    db.attach_cipher(std::sync::Arc::new(
        crate::security::field_cipher::FieldCipher::new([13u8; 32]),
    ))
    .await
    .unwrap();

    db.add_contact("peer1", "Alice", None).await.unwrap();
    db.add_message("m1", "peer1", "me", b"hello").await.unwrap();
    db.add_message("m2", "me", "peer1", b"hi").await.unwrap();
    db.add_pending_message("peer1", "pm1").await.unwrap();
    db.save_ratchet_state("peer1", b"state").await.unwrap();

    db.delete_chat("peer1").await.unwrap();

    assert_eq!(db.get_contacts().await.unwrap().len(), 1);
    assert!(db.get_messages_for_contact("peer1").await.unwrap().is_empty());
    assert!(db.get_pending_messages("peer1").await.unwrap().is_empty());
    assert!(db.get_ratchet_state("peer1").await.unwrap().is_some());
}
