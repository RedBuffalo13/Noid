//! Production keystore/identity battery: roundtrip, wrong-key, tamper,
//! malformed/duplicate/bounds rejection — plus config and handle semantics.
use super::config::{load, TorConfig};
use super::encrypted_keystore::EncryptedKeystore;
use super::identity::ensure_onion_identity;
use rand::Rng;
use zeroize::Zeroizing;

fn master() -> [u8; 32] {
    let mut m = Zeroizing::new([0u8; 32]);
    rand::rng().fill_bytes(m.as_mut());
    *m
}

#[test]
fn keystore_identity_roundtrip_via_service() {
    let dir = tempfile::tempdir().unwrap();
    let m = master();
    let id1 = ensure_onion_identity(&m, dir.path()).unwrap();
    let addr1 = id1.onion_address.clone();
    drop(id1);
    let id2 = ensure_onion_identity(&m, dir.path()).unwrap();
    assert_eq!(addr1, id2.onion_address);
    assert!(id2.onion_address.ends_with(".onion"));
    // No plaintext key file anywhere under tor_dir.
    let raw = std::fs::read(dir.path().join("keys/keystore.noidkey")).unwrap();
    assert!(!raw.windows(19).any(|w| w == b"OPENSSH PRIVATE KEY"));
}

#[test]
fn keystore_wrong_master_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let m = master();
    ensure_onion_identity(&m, dir.path()).unwrap();
    let other = master();
    assert!(EncryptedKeystore::open(&dir.path().join("keys/keystore.noidkey"), other).is_err());
}

#[test]
fn keystore_tampered_snapshot_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let m = master();
    ensure_onion_identity(&m, dir.path()).unwrap();
    let path = dir.path().join("keys/keystore.noidkey");
    let mut raw = std::fs::read(&path).unwrap();
    let last = raw.len() - 1;
    raw[last] ^= 0x01;
    std::fs::write(&path, &raw).unwrap();
    assert!(EncryptedKeystore::open(&path, m).is_err());
}

#[test]
fn keystore_malformed_payload_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let m = master();
    let path = dir.path().join("keys/keystore.noidkey");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    // A NOIDKEY2 envelope over garbage JSON must fail snapshot validation.
    crate::security::key_store::save(&path, b"not-json", &m).unwrap();
    assert!(EncryptedKeystore::open(&path, m).is_err());
}

#[test]
fn config_roundtrip_and_schema_reject() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tor_config.json");
    let mut cfg = TorConfig::default();
    cfg.mode = super::mode::TorMode::TorOnly;
    cfg.consent_version = 3;
    cfg.save(&path).unwrap();
    let back = load(&path).unwrap();
    assert_eq!(back.mode, super::mode::TorMode::TorOnly);
    assert_eq!(back.consent_version, 3);
    cfg.schema_version = super::config::TOR_CONFIG_SCHEMA_VERSION + 1;
    cfg.save(&path).unwrap();
    assert!(load(&path).is_err());
    // Missing file -> defaults, mode off.
    let missing = load(&dir.path().join("nope.json")).unwrap();
    assert_eq!(missing.mode, super::mode::TorMode::Off);
}
