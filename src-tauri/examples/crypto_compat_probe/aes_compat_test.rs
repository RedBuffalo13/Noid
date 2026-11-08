use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm_legacy::aead::{Aead as LegacyAead, KeyInit as LegacyKeyInit};
use rand::Rng;
use zeroize::Zeroizing;

/// Identical inputs intentionally compare old/new implementations, not two writes.
#[test]
fn aes_gcm_old_and_new_have_identical_ciphertext_and_authentication() {
    let mut key = Zeroizing::new([0u8; 32]);
    let mut nonce = [0u8; 12];
    let mut plaintext = Zeroizing::new([0u8; 93]);
    rand::rng().fill_bytes(key.as_mut());
    rand::rng().fill_bytes(&mut nonce);
    rand::rng().fill_bytes(plaintext.as_mut());
    let aad = b"noid-cross-version-fixture";
    let old = aes_gcm_legacy::Aes256Gcm::new_from_slice(key.as_ref()).expect("32-byte test key");
    let new = aes_gcm::Aes256Gcm::new_from_slice(key.as_ref()).expect("32-byte test key");
    let legacy_payload = aes_gcm_legacy::aead::Payload { msg: plaintext.as_ref(), aad };
    let ciphertext = old.encrypt(&nonce.into(), legacy_payload).expect("valid fixture");
    let modern = new.encrypt(&nonce.into(), Payload { msg: plaintext.as_ref(), aad })
        .expect("valid fixture");
    assert_eq!(modern, ciphertext);
    let reopened = Zeroizing::new(new.decrypt(&nonce.into(), Payload { msg: &ciphertext, aad })
        .expect("old ciphertext is readable by new implementation"));
    assert_eq!(reopened.as_slice(), plaintext.as_ref());
    let legacy = Zeroizing::new(old.decrypt(&nonce.into(),
        aes_gcm_legacy::aead::Payload { msg: &modern, aad })
        .expect("new ciphertext is readable by old implementation"));
    assert_eq!(legacy.as_slice(), plaintext.as_ref());
    let mut tampered = modern;
    tampered[0] ^= 1;
    assert!(new.decrypt(&nonce.into(), Payload { msg: &tampered, aad }).is_err());
    assert!(old.decrypt(&nonce.into(),
        aes_gcm_legacy::aead::Payload { msg: &tampered, aad }).is_err());
}
