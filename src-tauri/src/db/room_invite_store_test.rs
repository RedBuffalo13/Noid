use super::db_test::setup_test_db;

#[tokio::test]
async fn test_add_and_get_pending_room_invite() {
    let (db, _dir) = setup_test_db().await.unwrap();
    db.add_pending_room_invite("room1", "inviter1", Some("Team"), Some("avatar"))
        .await
        .unwrap();
    let invites = db.get_pending_room_invites().await.unwrap();
    assert_eq!(invites.len(), 1);
    assert_eq!(invites[0].0, "room1");
    assert_eq!(invites[0].1, "inviter1");
    assert_eq!(invites[0].2, Some("Team".to_string()));
    assert_eq!(invites[0].3, Some("avatar".to_string()));
}

#[tokio::test]
async fn test_pending_room_invite_optional_fields() {
    let (db, _dir) = setup_test_db().await.unwrap();
    db.add_pending_room_invite("room1", "inviter1", None, None)
        .await
        .unwrap();
    let invites = db.get_pending_room_invites().await.unwrap();
    assert_eq!(invites.len(), 1);
    assert_eq!(invites[0].2, None);
    assert_eq!(invites[0].3, None);
}

#[tokio::test]
async fn test_re_offer_replaces_pending_invite() {
    let (db, _dir) = setup_test_db().await.unwrap();
    db.add_pending_room_invite("room1", "inviter1", Some("Old"), None)
        .await
        .unwrap();
    db.add_pending_room_invite("room1", "inviter2", Some("New"), None)
        .await
        .unwrap();
    let invites = db.get_pending_room_invites().await.unwrap();
    assert_eq!(invites.len(), 1);
    assert_eq!(invites[0].1, "inviter2");
    assert_eq!(invites[0].2, Some("New".to_string()));
}

#[tokio::test]
async fn test_get_pending_room_invite_inviter() {
    let (db, _dir) = setup_test_db().await.unwrap();
    db.add_pending_room_invite("room1", "inviter1", None, None)
        .await
        .unwrap();
    let inviter = db.get_pending_room_invite_inviter("room1").await.unwrap();
    assert_eq!(inviter, Some("inviter1".to_string()));
    let missing = db.get_pending_room_invite_inviter("nope").await.unwrap();
    assert!(missing.is_none());
}

#[tokio::test]
async fn test_delete_pending_room_invite() {
    let (db, _dir) = setup_test_db().await.unwrap();
    db.add_pending_room_invite("room1", "inviter1", None, None)
        .await
        .unwrap();
    db.delete_pending_room_invite("room1").await.unwrap();
    assert!(db.get_pending_room_invites().await.unwrap().is_empty());
    assert!(db
        .get_pending_room_invite_inviter("room1")
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn test_pending_invite_never_stores_key_material() {
    // Regression guard: the pending_invites table must not gain a key
    // column — the room key only ships after explicit acceptance.
    let (db, _dir) = setup_test_db().await.unwrap();
    let cols = sqlx::query_as::<_, (String,)>(
        "SELECT name FROM pragma_table_info('pending_room_invites')",
    )
    .fetch_all(&db.pool)
    .await
    .unwrap();
    let names: Vec<String> = cols.into_iter().map(|c| c.0).collect();
    assert!(names.contains(&"room_id".to_string()));
    assert!(names.contains(&"inviter_peer_id".to_string()));
    assert!(!names.iter().any(|n| n.contains("key")));
}
