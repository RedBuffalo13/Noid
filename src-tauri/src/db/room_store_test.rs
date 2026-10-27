use super::db_test::setup_test_db;

#[tokio::test]
async fn test_create_room() {
    let (db, _dir) = setup_test_db().await.unwrap();
    db.create_room("room1", "Test Room").await.unwrap();
    // Room created successfully if no error
}

#[tokio::test]
async fn test_add_room_member() {
    let (db, _dir) = setup_test_db().await.unwrap();
    db.create_room("room1", "Test Room").await.unwrap();
    db.add_room_member("room1", "peer1", false).await.unwrap();
    // Member added successfully if no error
}

#[tokio::test]
async fn test_add_room_member_approved() {
    let (db, _dir) = setup_test_db().await.unwrap();
    db.create_room("room1", "Test Room").await.unwrap();
    db.add_room_member("room1", "peer1", true).await.unwrap();
    // Approved member added successfully if no error
}

#[tokio::test]
async fn test_approve_member() {
    let (db, _dir) = setup_test_db().await.unwrap();
    db.create_room("room1", "Test Room").await.unwrap();
    db.add_room_member("room1", "peer1", false).await.unwrap();
    db.approve_member("room1", "peer1").await.unwrap();
    // Approval successful if no error
}

fn test_cipher() -> std::sync::Arc<crate::security::field_cipher::FieldCipher> {
    std::sync::Arc::new(crate::security::field_cipher::FieldCipher::new([5u8; 32]))
}

/// Regression: create_room* wrote `name` encrypted but left `name_hmac`
/// NULL — the plaintext-field migration then treated the ciphertext as a
/// legacy plaintext name and re-encrypted it, so after one relogin the room
/// name decrypted to inner ciphertext (mojibake) instead of the real name.
#[tokio::test]
async fn test_room_name_survives_cipher_reattach() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("noid.db");
    {
        let mut db = crate::db::Database::new(&db_path).await.unwrap();
        db.attach_cipher(test_cipher()).await.unwrap();
        db.create_room("r1", "Team Chat").await.unwrap();
        db.create_room_with_key("r2", "Keyed", &[7u8; 32]).await.unwrap();
        db.create_room_full("r3", "Full", &[9u8; 32], Some("owner1"), None, 0)
            .await
            .unwrap();
    }
    {
        // Relogin: attach_cipher runs migrate_plaintext_fields again — the
        // names must still decrypt to their originals afterwards.
        let mut db = crate::db::Database::new(&db_path).await.unwrap();
        db.attach_cipher(test_cipher()).await.unwrap();
        let rooms: std::collections::HashMap<_, _> =
            db.list_rooms().await.unwrap().into_iter().collect();
        assert_eq!(rooms["r1"], "Team Chat");
        assert_eq!(rooms["r2"], "Keyed");
        assert_eq!(rooms["r3"], "Full");
    }
}

/// Owner backfill: unconditional write plus the conditional
/// ownerless-only variant used by Meta{owner} convergence — a second
/// write loses once an owner exists (first-writer-wins).
#[tokio::test]
async fn test_set_room_owner_if_unset() {
    let (db, _dir) = setup_test_db().await.unwrap();
    db.create_room("r1", "Team").await.unwrap();
    // No owner recorded — legacy room.
    let won = db
        .set_room_owner_if_unset("r1", None, "peer-a")
        .await
        .unwrap();
    assert!(won);
    let info = db.get_room_info("r1").await.unwrap().unwrap();
    assert_eq!(info.owner.as_deref(), Some("peer-a"));
    // A second write must not overwrite — owner_hmac no longer matches
    // the pre-write state.
    let won2 = db
        .set_room_owner_if_unset("r1", None, "peer-b")
        .await
        .unwrap();
    assert!(!won2);
    let info2 = db.get_room_info("r1").await.unwrap().unwrap();
    assert_eq!(info2.owner.as_deref(), Some("peer-a"));
}

/// The conditional write also wins over a stale/garbage owner value
/// (e.g. a pre-P2P "Loading..." placeholder) — it keys on the CURRENT
/// stored owner hmac.
#[tokio::test]
async fn test_set_room_owner_if_unset_over_stale_owner() {
    let (db, _dir) = setup_test_db().await.unwrap();
    db.create_room_full("r1", "Team", &[1u8; 32], Some("Loading..."), None, 0)
        .await
        .unwrap();
    let won = db
        .set_room_owner_if_unset("r1", Some("Loading..."), "peer-a")
        .await
        .unwrap();
    assert!(won);
    let info = db.get_room_info("r1").await.unwrap().unwrap();
    assert_eq!(info.owner.as_deref(), Some("peer-a"));
}

/// Legacy owner backfill: a room where we are absent from the member
/// list was created locally before owner tracking → self-assign. A room
/// where we ARE a member stays ownerless — it converges via the real
/// creator's Meta{owner} control. A valid owner is never touched.
#[tokio::test]
async fn test_backfill_room_owners() {
    let (db, _dir) = setup_test_db().await.unwrap();
    // r1: ownerless, we are NOT a member → locally created.
    db.create_room_full("r1", "Mine", &[1u8; 32], None, None, 0)
        .await
        .unwrap();
    // r1b: invalid owner ("Loading..." placeholder), not a member → also self-assigns.
    db.create_room_full("r1b", "Stale", &[4u8; 32], Some("Loading..."), None, 0)
        .await
        .unwrap();
    db.add_room_member("r1", "peer-a", true).await.unwrap();
    // r2: ownerless, we ARE a member → wait for Meta{owner}.
    db.create_room_full("r2", "Invited", &[2u8; 32], None, None, 0)
        .await
        .unwrap();
    db.add_room_member("r2", "me", true).await.unwrap();
    // r3: valid owner → untouched.
    let real_owner = libp2p::PeerId::random().to_string();
    db.create_room_full("r3", "Owned", &[3u8; 32], Some(&real_owner), None, 0)
        .await
        .unwrap();

    let assigned = db.backfill_room_owners("me").await.unwrap();
    assert!(assigned.contains(&"r1".to_string()));
    assert!(assigned.contains(&"r1b".to_string()));
    assert_eq!(
        db.get_room_info("r1b").await.unwrap().unwrap().owner.as_deref(),
        Some("me")
    );
    assert_eq!(
        db.get_room_info("r1").await.unwrap().unwrap().owner.as_deref(),
        Some("me")
    );
    assert!(db.get_room_info("r2").await.unwrap().unwrap().owner.is_none());
    assert_eq!(
        db.get_room_info("r3").await.unwrap().unwrap().owner.as_deref(),
        Some(real_owner.as_str())
    );
}

/// Member profiles: set/get roundtrip through the encrypted columns.
#[tokio::test]
async fn test_member_profile_roundtrip() {
    let (db, _dir) = setup_test_db().await.unwrap();
    db.create_room("r1", "Team").await.unwrap();
    db.add_room_member("r1", "peer1", true).await.unwrap();
    db.set_member_profile("r1", "peer1", Some("Alice"), Some("ava"))
        .await
        .unwrap();
    let members = db.get_room_members("r1").await.unwrap();
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].peer_id, "peer1");
    assert_eq!(members[0].name.as_deref(), Some("Alice"));
    assert_eq!(members[0].avatar.as_deref(), Some("ava"));
    // Profiles only attach to existing member rows — a non-member's
    // announce is a no-op.
    db.set_member_profile("r1", "ghost", Some("Eve"), None)
        .await
        .unwrap();
    assert_eq!(db.get_room_members("r1").await.unwrap().len(), 1);
}

/// Repair pass: a row damaged by the old bug (name = enc(enc(P)),
/// name_hmac = hmac(enc(P))) must unwrap back to P on the next attach.
#[tokio::test]
async fn test_repair_double_encrypted_room_name() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("noid.db");
    let cipher = test_cipher();
    {
        let mut db = crate::db::Database::new(&db_path).await.unwrap();
        db.attach_cipher(cipher.clone()).await.unwrap();
        // Simulate the legacy damage: double-encrypted name + hmac of the
        // inner ciphertext (what the buggy migration produced).
        let inner = cipher.encrypt_text("Team").unwrap();
        let damaged = cipher.encrypt_text(&inner).unwrap();
        let bad_hmac = cipher.hmac_hex("room.name", &inner);
        sqlx::query("INSERT INTO rooms (id, name, name_hmac) VALUES (?, ?, ?)")
            .bind("r1")
            .bind(&damaged)
            .bind(&bad_hmac)
            .execute(&db.pool)
            .await
            .unwrap();
    }
    {
        let mut db = crate::db::Database::new(&db_path).await.unwrap();
        db.attach_cipher(cipher).await.unwrap();
        let rooms = db.list_rooms().await.unwrap();
        assert_eq!(rooms, vec![("r1".to_string(), "Team".to_string())]);
    }
}
