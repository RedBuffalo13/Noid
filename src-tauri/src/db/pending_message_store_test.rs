use super::db_test::setup_test_db;

#[tokio::test]
async fn test_add_and_get_pending_message() {
    let (db, _dir) = setup_test_db().await.unwrap();
    db.add_pending_message("peer1", "msg1").await.unwrap();
    let pending = db.get_pending_messages("peer1").await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].1, "msg1"); // content
    assert_eq!(pending[0].2, "msg1"); // message_id
}

#[tokio::test]
async fn test_add_pending_with_content() {
    let (db, _dir) = setup_test_db().await.unwrap();
    db.add_pending_message_with_content("peer1", "actual content", "msg1").await.unwrap();
    let pending = db.get_pending_messages("peer1").await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].1, "actual content");
    assert_eq!(pending[0].2, "msg1");
}

#[tokio::test]
async fn test_get_pending_filters_by_peer() {
    let (db, _dir) = setup_test_db().await.unwrap();
    db.add_pending_message("peer1", "msg1").await.unwrap();
    db.add_pending_message("peer2", "msg2").await.unwrap();
    let peer1_pending = db.get_pending_messages("peer1").await.unwrap();
    assert_eq!(peer1_pending.len(), 1);
}

#[tokio::test]
async fn test_delete_pending_by_id() {
    let (db, _dir) = setup_test_db().await.unwrap();
    db.add_pending_message("peer1", "msg1").await.unwrap();
    let pending = db.get_pending_messages("peer1").await.unwrap();
    db.delete_pending_message(pending[0].0).await.unwrap();
    let after = db.get_pending_messages("peer1").await.unwrap();
    assert_eq!(after.len(), 0);
}

#[tokio::test]
async fn test_delete_pending_by_message_id() {
    let (db, _dir) = setup_test_db().await.unwrap();
    db.add_pending_message("peer1", "msg1").await.unwrap();
    db.delete_pending_message_by_id("peer1", "msg1").await.unwrap();
    let after = db.get_pending_messages("peer1").await.unwrap();
    assert_eq!(after.len(), 0);
}

#[tokio::test]
async fn test_get_all_pending() {
    let (db, _dir) = setup_test_db().await.unwrap();
    db.add_pending_message_with_content("peer1", "content1", "msg1").await.unwrap();
    db.add_pending_message_with_content("peer2", "content2", "msg2").await.unwrap();
    let all = db.get_pending_messages_all().await.unwrap();
    assert_eq!(all.len(), 2);
}
