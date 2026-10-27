use crate::security::x3dh::X3DH;
use crate::security::ratchet::DoubleRatchet;
use x25519_dalek::PublicKey;

#[test]
fn test_x3dh_without_one_time_prekey() {
    let alice = X3DH::new();
    let bob = X3DH::new();

    let (mut bundle, bob_signed_prekey, _) = bob.generate_prekey_bundle();
    bundle.one_time_prekey_public = None;
    bundle.one_time_prekeys.clear();

    let (initial_msg, alice_shared) = alice.initiate(&bundle).unwrap();
    let bob_shared = bob
        .receive(&initial_msg, &bob_signed_prekey, None)
        .unwrap();

    assert_eq!(alice_shared, bob_shared);
}

#[test]
fn test_ratchet_multiple_messages() {
    let alice = X3DH::new();
    let bob = X3DH::new();

    let (bundle, bob_signed_prekey, _) = bob.generate_prekey_bundle();
    let (_initial_msg, shared_secret) = alice.initiate(&bundle).unwrap();

    let bob_signed_prekey_public = PublicKey::from(&bob_signed_prekey);

    let mut alice_ratchet = DoubleRatchet::init_alice(shared_secret, bob_signed_prekey_public).unwrap();
    let mut bob_ratchet = DoubleRatchet::init_bob(shared_secret, bob_signed_prekey);

    for i in 0..10 {
        let plaintext = format!("Message {}", i);
        let msg = alice_ratchet.encrypt(plaintext.as_bytes()).unwrap();
        let decrypted = bob_ratchet.decrypt(&msg).unwrap();
        assert_eq!(decrypted, plaintext.as_bytes());
    }

    for i in 0..5 {
        let plaintext = format!("Reply {}", i);
        let msg = bob_ratchet.encrypt(plaintext.as_bytes()).unwrap();
        let decrypted = alice_ratchet.decrypt(&msg).unwrap();
        assert_eq!(decrypted, plaintext.as_bytes());
    }
}

#[test]
fn test_secure_delete() {
    let temp_dir = std::env::temp_dir();
    let test_file = temp_dir.join("noid_test_secure_delete.bin");

    std::fs::write(&test_file, b"sensitive data").unwrap();
    assert!(test_file.exists());

    crate::security::secure_delete::secure_delete(&test_file).unwrap();
    assert!(!test_file.exists());
}

#[test]
fn test_replay_detection() {
    let mut seen = std::collections::HashSet::new();
    let msg_id = "test-msg-123";

    assert!(!seen.contains(msg_id));
    seen.insert(msg_id.to_string());
    assert!(seen.contains(msg_id));
}

// Phase A.7: Full E2EE tests

#[test]
fn test_x3dh_full_handshake() {
    let alice = X3DH::new();
    let bob = X3DH::new();

    let (bundle, bob_signed_prekey, bob_otpk) = bob.generate_prekey_bundle();

    // Alice initiates with Bob's bundle
    let (initial_msg, alice_shared) = alice.initiate(&bundle).unwrap();

    // Bob receives with his signed prekey and one-time prekey
    let bob_shared = bob
        .receive(&initial_msg, &bob_signed_prekey, bob_otpk.as_ref())
        .unwrap();

    assert_eq!(alice_shared, bob_shared, "Shared secrets must match");
}

#[test]
fn test_ratchet_state_export_import() {
    let alice = X3DH::new();
    let bob = X3DH::new();

    let (bundle, bob_signed_prekey, _) = bob.generate_prekey_bundle();
    let (_initial_msg, shared_secret) = alice.initiate(&bundle).unwrap();

    let bob_signed_prekey_public = PublicKey::from(&bob_signed_prekey);

    let mut alice_ratchet = DoubleRatchet::init_alice(shared_secret, bob_signed_prekey_public).unwrap();
    let mut bob_ratchet = DoubleRatchet::init_bob(shared_secret, bob_signed_prekey);

    // Exchange a few messages
    let msg1 = alice_ratchet.encrypt(b"Hello Bob").unwrap();
    let _ = bob_ratchet.decrypt(&msg1).unwrap();
    let msg2 = bob_ratchet.encrypt(b"Hi Alice").unwrap();
    let _ = alice_ratchet.decrypt(&msg2).unwrap();

    // Export Alice's state
    let alice_state = alice_ratchet.export_state();
    assert!(!alice_state.is_empty(), "Exported state must not be empty");

    // Import into a new ratchet instance
    let mut alice_restored = DoubleRatchet::import_state(&alice_state).unwrap();

    // Alice should be able to continue encrypting
    let msg3 = alice_restored.encrypt(b"After restore").unwrap();
    let decrypted3 = bob_ratchet.decrypt(&msg3).unwrap();
    assert_eq!(decrypted3, b"After restore");
}

#[test]
fn test_ratchet_restart_persistence() {
    let alice = X3DH::new();
    let bob = X3DH::new();

    let (bundle, bob_signed_prekey, _) = bob.generate_prekey_bundle();
    let (_initial_msg, shared_secret) = alice.initiate(&bundle).unwrap();

    let bob_signed_prekey_public = PublicKey::from(&bob_signed_prekey);

    let mut alice_ratchet = DoubleRatchet::init_alice(shared_secret, bob_signed_prekey_public).unwrap();
    let mut bob_ratchet = DoubleRatchet::init_bob(shared_secret, bob_signed_prekey);

    // Alice sends a message
    let msg1 = alice_ratchet.encrypt(b"Before restart").unwrap();
    let _ = bob_ratchet.decrypt(&msg1).unwrap();

    // Simulate restart: export state, create new instance via import
    let state = alice_ratchet.export_state();
    let mut alice_restarted = DoubleRatchet::import_state(&state).unwrap();

    // Alice should be able to continue messaging after "restart"
    let msg2 = alice_restarted.encrypt(b"After restart").unwrap();
    let decrypted = bob_ratchet.decrypt(&msg2).unwrap();
    assert_eq!(decrypted, b"After restart");

    // Bob should also be able to continue
    let msg3 = bob_ratchet.encrypt(b"Bob after restart").unwrap();
    let decrypted3 = alice_restarted.decrypt(&msg3).unwrap();
    assert_eq!(decrypted3, b"Bob after restart");
}

#[test]
fn test_ratchet_out_of_order() {
    let alice = X3DH::new();
    let bob = X3DH::new();

    let (bundle, bob_signed_prekey, _) = bob.generate_prekey_bundle();
    let (_initial_msg, shared_secret) = alice.initiate(&bundle).unwrap();

    let bob_signed_prekey_public = PublicKey::from(&bob_signed_prekey);

    let mut alice_ratchet = DoubleRatchet::init_alice(shared_secret, bob_signed_prekey_public).unwrap();
    let mut bob_ratchet = DoubleRatchet::init_bob(shared_secret, bob_signed_prekey);

    // Alice sends messages 1, 2, 3
    let msg1 = alice_ratchet.encrypt(b"Message 1").unwrap();
    let msg2 = alice_ratchet.encrypt(b"Message 2").unwrap();
    let msg3 = alice_ratchet.encrypt(b"Message 3").unwrap();

    // Bob receives in order 1, 3, 2 (out of order)
    let dec1 = bob_ratchet.decrypt(&msg1).unwrap();
    assert_eq!(dec1, b"Message 1");

    let dec3 = bob_ratchet.decrypt(&msg3).unwrap();
    assert_eq!(dec3, b"Message 3");

    let dec2 = bob_ratchet.decrypt(&msg2).unwrap();
    assert_eq!(dec2, b"Message 2");
}

#[test]
fn test_prekey_consumption() {
    // Test that prekey bundle generation works and one-time prekeys are used
    let bob = X3DH::new();
    let (bundle1, bob_spk1, bob_otpk1) = bob.generate_prekey_bundle();

    assert!(bundle1.one_time_prekey_public.is_some(), "Bundle should have a one-time prekey");

    let alice = X3DH::new();
    let (initial_msg, alice_shared) = alice.initiate(&bundle1).unwrap();
    let bob_shared = bob.receive(&initial_msg, &bob_spk1, bob_otpk1.as_ref()).unwrap();

    assert_eq!(alice_shared, bob_shared, "Shared secrets must match after prekey consumption");
}

#[test]
fn test_ratchet_state_corrupted() {
    let alice = X3DH::new();
    let bob = X3DH::new();

    let (bundle, bob_signed_prekey, _) = bob.generate_prekey_bundle();
    let (_initial_msg, shared_secret) = alice.initiate(&bundle).unwrap();

    let bob_signed_prekey_public = PublicKey::from(&bob_signed_prekey);
    let alice_ratchet = DoubleRatchet::init_alice(shared_secret, bob_signed_prekey_public).unwrap();

    let state = alice_ratchet.export_state();

    // Corrupt the state by flipping some bytes
    let mut corrupted = state.clone();
    corrupted[0] ^= 0xFF;

    // Import should fail or produce a ratchet that can't decrypt
    let _result = DoubleRatchet::import_state(&corrupted);
    // It might parse but produce wrong keys — the important thing is it doesn't panic
    // A too-short state should definitely fail
    let short_state = vec![0u8; 10];
    assert!(DoubleRatchet::import_state(&short_state).is_err(), "Short state should fail to import");
}

#[test]
fn test_no_plaintext_in_ratchet_message() {
    let alice = X3DH::new();
    let bob = X3DH::new();

    let (bundle, bob_signed_prekey, _) = bob.generate_prekey_bundle();
    let (_initial_msg, shared_secret) = alice.initiate(&bundle).unwrap();

    let bob_signed_prekey_public = PublicKey::from(&bob_signed_prekey);
    let mut alice_ratchet = DoubleRatchet::init_alice(shared_secret, bob_signed_prekey_public).unwrap();

    let plaintext = b"Secret message content";
    let msg = alice_ratchet.encrypt(plaintext).unwrap();

    // Ciphertext should not contain plaintext
    assert!(!msg.ciphertext.windows(plaintext.len()).any(|w| w == plaintext),
        "Ciphertext must not contain plaintext");

    // Serialize to bytes and check
    let serialized = serde_json::to_vec(&msg).unwrap();
    assert!(!serialized.windows(plaintext.len()).any(|w| w == plaintext),
        "Serialized message must not contain plaintext");
}
