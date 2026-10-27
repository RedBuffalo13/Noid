use crate::db::db_test::setup_test_db;
use crate::security::ratchet_session::RatchetSessionManager;
use x25519_dalek::StaticSecret;

#[tokio::test]
async fn test_new_creates_identity() {
    let mgr = RatchetSessionManager::new();
    let pub_key = mgr.identity_public_bytes().await;
    assert_eq!(pub_key.len(), 32);
}

#[tokio::test]
async fn test_init_from_db_generates_new_identity() {
    let (db, _dir) = setup_test_db().await.unwrap();
    let mgr = RatchetSessionManager::init_from_db(&db).await.unwrap();
    let pub_key = mgr.identity_public_bytes().await;
    assert_eq!(pub_key.len(), 32);
    // Identity should be saved in DB
    let identity = db.get_identity_key().await.unwrap();
    assert!(identity.is_some());
}

#[tokio::test]
async fn test_init_from_db_loads_existing_identity() {
    let (db, _dir) = setup_test_db().await.unwrap();
    // First init generates and saves
    let mgr1 = RatchetSessionManager::init_from_db(&db).await.unwrap();
    let pub_key1 = mgr1.identity_public_bytes().await;
    // Second init should load the same key
    let mgr2 = RatchetSessionManager::init_from_db(&db).await.unwrap();
    let pub_key2 = mgr2.identity_public_bytes().await;
    assert_eq!(pub_key1, pub_key2);
}

#[tokio::test]
async fn test_generate_and_store_prekeys() {
    let (db, _dir) = setup_test_db().await.unwrap();
    let mgr = RatchetSessionManager::init_from_db(&db).await.unwrap();
    let bundle = mgr.generate_and_store_prekeys(&db).await.unwrap();
    assert_eq!(bundle.identity_public.len(), 32);
    assert_eq!(bundle.signed_prekey_public.len(), 32);
    // One-time prekey may or may not be present
    if let Some(otpk) = &bundle.one_time_prekey_public {
        assert_eq!(otpk.len(), 32);
    }
    // Signed prekey should be in DB
    let spk = db.get_signed_prekey().await.unwrap();
    assert!(spk.is_some());
}

#[tokio::test]
async fn test_has_session_false_initially() {
    let mgr = RatchetSessionManager::new();
    assert!(!mgr.has_session("peer1").await);
}

#[tokio::test]
async fn test_encrypt_without_session_returns_none() {
    let mgr = RatchetSessionManager::new();
    let result = mgr.encrypt("peer1", b"hello").await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn test_decrypt_without_session_errors() {
    let mgr = RatchetSessionManager::new();
    let msg = crate::security::ratchet::RatchetMessage {
        header: crate::security::ratchet::RatchetHeader {
            dh_public: vec![0u8; 32],
            pn: 0,
            n: 0,
        },
        ciphertext: vec![],
    };
    let result = mgr.decrypt("peer1", &msg).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_full_x3dh_and_ratchet_flow() {
    let (db_alice, _dir_a) = setup_test_db().await.unwrap();
    let (db_bob, _dir_b) = setup_test_db().await.unwrap();

    let alice = RatchetSessionManager::init_from_db(&db_alice).await.unwrap();
    let bob = RatchetSessionManager::init_from_db(&db_bob).await.unwrap();

    // Bob generates prekeys
    let mut bundle = bob.generate_and_store_prekeys(&db_bob).await.unwrap();
    // Don't use one-time prekey for this test (would need OTPK secret)
    bundle.one_time_prekey_public = None;
    bundle.one_time_prekeys.clear();

    // Bob needs signed prekey secret for receive_session
    let (_spk_pub, spk_priv) = db_bob.get_signed_prekey().await.unwrap().unwrap();
    let spk_secret_bytes: [u8; 32] = spk_priv.as_slice().try_into().unwrap();
    let bob_spk_secret = StaticSecret::from(spk_secret_bytes);

    // Alice initiates session
    let initial_msg = alice.initiate_session("bob", &bundle).await.unwrap();

    // Bob receives session
    bob.receive_session("alice", &initial_msg, &bob_spk_secret, None).await.unwrap();

    // Both should have sessions
    assert!(alice.has_session("bob").await);
    assert!(bob.has_session("alice").await);

    // Alice encrypts, Bob decrypts
    let plaintext = b"Hello Bob!";
    let encrypted = alice.encrypt("bob", plaintext).await.unwrap().unwrap();
    let decrypted = bob.decrypt("alice", &encrypted).await.unwrap();
    assert_eq!(plaintext.to_vec(), decrypted);
}

#[tokio::test]
async fn test_save_and_load_session() {
    let (db, _dir) = setup_test_db().await.unwrap();
    let mgr = RatchetSessionManager::init_from_db(&db).await.unwrap();

    // Create a session by doing X3DH with ourselves (simplified)
    let mut bundle = mgr.generate_and_store_prekeys(&db).await.unwrap();
    bundle.one_time_prekey_public = None;
    bundle.one_time_prekeys.clear();
    let (_spk_pub, spk_priv) = db.get_signed_prekey().await.unwrap().unwrap();
    let spk_secret_bytes: [u8; 32] = spk_priv.as_slice().try_into().unwrap();
    let spk_secret = StaticSecret::from(spk_secret_bytes);

    let initial_msg = mgr.initiate_session("peer1", &bundle).await.unwrap();
    mgr.receive_session("peer1", &initial_msg, &spk_secret, None).await.unwrap();

    // Save session
    mgr.save_session(&db, "peer1").await.unwrap();
    let state = db.get_ratchet_state("peer1").await.unwrap();
    assert!(state.is_some());

    // Load session into new manager
    let mgr2 = RatchetSessionManager::init_from_db(&db).await.unwrap();
    let loaded = mgr2.load_session(&db, "peer1").await.unwrap();
    assert!(loaded);
    assert!(mgr2.has_session("peer1").await);
}

#[tokio::test]
async fn test_load_session_nonexistent() {
    let (db, _dir) = setup_test_db().await.unwrap();
    let mgr = RatchetSessionManager::init_from_db(&db).await.unwrap();
    let loaded = mgr.load_session(&db, "nonexistent").await.unwrap();
    assert!(!loaded);
}
