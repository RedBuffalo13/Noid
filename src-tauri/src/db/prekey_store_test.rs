use super::db_test::setup_test_db;

#[tokio::test]
async fn test_save_and_get_identity_key() {
    let (db, _dir) = setup_test_db().await.unwrap();
    let pub_key = vec![1u8; 32];
    let priv_key = vec![2u8; 32];
    db.save_identity_key(&pub_key, &priv_key).await.unwrap();
    let loaded = db.get_identity_key().await.unwrap();
    assert!(loaded.is_some());
    let (loaded_pub, loaded_priv) = loaded.unwrap();
    assert_eq!(loaded_pub, pub_key);
    assert_eq!(loaded_priv, priv_key);
}

#[tokio::test]
async fn test_get_identity_key_nonexistent() {
    let (db, _dir) = setup_test_db().await.unwrap();
    let result = db.get_identity_key().await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn test_save_and_get_signed_prekey() {
    let (db, _dir) = setup_test_db().await.unwrap();
    let pub_key = vec![3u8; 32];
    let priv_key = vec![4u8; 32];
    db.save_signed_prekey(&pub_key, &priv_key).await.unwrap();
    let loaded = db.get_signed_prekey().await.unwrap();
    assert!(loaded.is_some());
    let (loaded_pub, loaded_priv) = loaded.unwrap();
    assert_eq!(loaded_pub, pub_key);
    assert_eq!(loaded_priv, priv_key);
}

#[tokio::test]
async fn test_save_signed_prekey_replaces_existing() {
    let (db, _dir) = setup_test_db().await.unwrap();
    db.save_signed_prekey(&[1u8; 32], &[2u8; 32]).await.unwrap();
    db.save_signed_prekey(&[3u8; 32], &[4u8; 32]).await.unwrap();
    let loaded = db.get_signed_prekey().await.unwrap().unwrap();
    assert_eq!(loaded.0, vec![3u8; 32]);
}

#[tokio::test]
async fn test_add_and_consume_one_time_prekey() {
    let (db, _dir) = setup_test_db().await.unwrap();
    let pub_key = vec![5u8; 32];
    let priv_key = vec![6u8; 32];
    db.add_one_time_prekey(&pub_key, &priv_key).await.unwrap();
    let consumed = db.consume_one_time_prekey(&pub_key).await.unwrap();
    assert_eq!(consumed, Some(priv_key));
    // Second consume returns None (already consumed)
    let second = db.consume_one_time_prekey(&pub_key).await.unwrap();
    assert_eq!(second, None);
}

#[tokio::test]
async fn test_consume_nonexistent_prekey() {
    let (db, _dir) = setup_test_db().await.unwrap();
    let result = db.consume_one_time_prekey(&[0u8; 32]).await.unwrap();
    assert_eq!(result, None);
}

#[tokio::test]
async fn test_one_time_prekey_count() {
    let (db, _dir) = setup_test_db().await.unwrap();
    assert_eq!(db.get_one_time_prekey_count().await.unwrap(), 0);
    db.add_one_time_prekey(&[1u8; 32], &[2u8; 32]).await.unwrap();
    db.add_one_time_prekey(&[3u8; 32], &[4u8; 32]).await.unwrap();
    assert_eq!(db.get_one_time_prekey_count().await.unwrap(), 2);
    db.consume_one_time_prekey(&[1u8; 32]).await.unwrap();
    assert_eq!(db.get_one_time_prekey_count().await.unwrap(), 1);
}

#[tokio::test]
async fn test_get_available_one_time_prekey() {
    let (db, _dir) = setup_test_db().await.unwrap();
    db.add_one_time_prekey(&[1u8; 32], &[2u8; 32]).await.unwrap();
    let available = db.get_available_one_time_prekey().await.unwrap();
    assert!(available.is_some());
    // Does not consume
    assert_eq!(db.get_one_time_prekey_count().await.unwrap(), 1);
}

#[tokio::test]
async fn test_delete_all_prekeys() {
    let (db, _dir) = setup_test_db().await.unwrap();
    db.save_identity_key(&[1u8; 32], &[2u8; 32]).await.unwrap();
    db.save_signed_prekey(&[3u8; 32], &[4u8; 32]).await.unwrap();
    db.add_one_time_prekey(&[5u8; 32], &[6u8; 32]).await.unwrap();
    db.delete_all_prekeys().await.unwrap();
    assert!(db.get_identity_key().await.unwrap().is_none());
    assert!(db.get_signed_prekey().await.unwrap().is_none());
    assert_eq!(db.get_one_time_prekey_count().await.unwrap(), 0);
}
