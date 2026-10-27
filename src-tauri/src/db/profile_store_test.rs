use super::db_test::setup_test_db;

#[tokio::test]
async fn test_get_default_profile() {
    let (db, _dir) = setup_test_db().await.unwrap();
    let (nickname, avatar) = db.get_profile().await.unwrap();
    assert_eq!(nickname, "NoidUser");
    assert_eq!(avatar, None);
}

#[tokio::test]
async fn test_update_profile() {
    let (db, _dir) = setup_test_db().await.unwrap();
    db.update_profile("Alice", Some("avatar_data")).await.unwrap();
    let (nickname, avatar) = db.get_profile().await.unwrap();
    assert_eq!(nickname, "Alice");
    assert_eq!(avatar, Some("avatar_data".to_string()));
}

#[tokio::test]
async fn test_update_profile_encrypted_roundtrip() {
    // Real login path: cipher attached, save, reopen, re-attach, read back.
    // Regression: plaintext-mode tests cannot catch encryption/key issues.
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("noid.db");
    let cipher = || {
        std::sync::Arc::new(crate::security::field_cipher::FieldCipher::new([3u8; 32]))
    };
    {
        let mut db = crate::db::Database::new(&db_path).await.unwrap();
        db.attach_cipher(cipher()).await.unwrap();
        db.update_profile("Alice", None).await.unwrap();
        let (nickname, avatar) = db.get_profile().await.unwrap();
        assert_eq!(nickname, "Alice");
        assert_eq!(avatar, None);
    }
    {
        let mut db = crate::db::Database::new(&db_path).await.unwrap();
        db.attach_cipher(cipher()).await.unwrap();
        let (nickname, avatar) = db.get_profile().await.unwrap();
        assert_eq!(nickname, "Alice");
        assert_eq!(avatar, None);
    }
}

#[tokio::test]
async fn test_update_profile_none_avatar_preserves_existing() {
    let (db, _dir) = setup_test_db().await.unwrap();
    db.update_profile("Alice", Some("avatar_data")).await.unwrap();
    // Saving a new nickname without an avatar must not wipe the stored one.
    db.update_profile("Bob", None).await.unwrap();
    let (nickname, avatar) = db.get_profile().await.unwrap();
    assert_eq!(nickname, "Bob");
    assert_eq!(avatar, Some("avatar_data".to_string()));
}

#[tokio::test]
async fn test_get_and_set_username() {
    let (db, _dir) = setup_test_db().await.unwrap();
    let username = db.get_username().await.unwrap();
    assert_eq!(username, None);
    db.set_username("alice").await.unwrap();
    let username = db.get_username().await.unwrap();
    assert_eq!(username, Some("alice".to_string()));
}

#[tokio::test]
async fn test_username_published_flag() {
    let (db, _dir) = setup_test_db().await.unwrap();
    assert!(!db.is_username_published().await.unwrap());
    db.set_username_published(true).await.unwrap();
    assert!(db.is_username_published().await.unwrap());
    db.set_username_published(false).await.unwrap();
    assert!(!db.is_username_published().await.unwrap());
}
