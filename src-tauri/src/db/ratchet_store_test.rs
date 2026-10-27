use super::db_test::setup_test_db;

#[tokio::test]
async fn test_save_and_get_ratchet_state() {
    let (db, _dir) = setup_test_db().await.unwrap();
    let state = vec![1, 2, 3, 4, 5];
    db.save_ratchet_state("peer1", &state).await.unwrap();
    let loaded = db.get_ratchet_state("peer1").await.unwrap();
    assert_eq!(loaded, Some(state));
}

#[tokio::test]
async fn test_get_ratchet_state_nonexistent() {
    let (db, _dir) = setup_test_db().await.unwrap();
    let result = db.get_ratchet_state("nonexistent").await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn test_save_ratchet_replaces_existing() {
    let (db, _dir) = setup_test_db().await.unwrap();
    db.save_ratchet_state("peer1", &[1, 2, 3]).await.unwrap();
    db.save_ratchet_state("peer1", &[4, 5, 6]).await.unwrap();
    let loaded = db.get_ratchet_state("peer1").await.unwrap().unwrap();
    assert_eq!(loaded, vec![4, 5, 6]);
}

#[tokio::test]
async fn test_delete_ratchet_state() {
    let (db, _dir) = setup_test_db().await.unwrap();
    db.save_ratchet_state("peer1", &[1, 2, 3]).await.unwrap();
    db.delete_ratchet_state("peer1").await.unwrap();
    let result = db.get_ratchet_state("peer1").await.unwrap();
    assert!(result.is_none());
}
