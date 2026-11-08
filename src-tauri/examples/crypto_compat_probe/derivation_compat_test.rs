use hmac::{KeyInit, Mac};
use hmac_legacy::Mac as LegacyMac;
use rand::Rng;
use sha2::Digest;
use sha2_legacy::Digest as LegacyDigest;
use zeroize::Zeroizing;

#[test]
fn hkdf_domain_keys_hmac_and_sha256_outputs_are_stable() {
    let mut master = Zeroizing::new([0u8; 32]);
    rand::rng().fill_bytes(master.as_mut());
    for domain in ["msg", "db-field", "audit", "keystore", "tor-keystore"] {
        let info = format!("noid-domain:{domain}");
        let mut old_key = Zeroizing::new([0u8; 32]);
        let mut new_key = Zeroizing::new([0u8; 32]);
        hkdf_legacy::Hkdf::<sha2_legacy::Sha256>::new(None, master.as_ref())
            .expand(info.as_bytes(), old_key.as_mut()).expect("32-byte HKDF output");
        hkdf::Hkdf::<sha2::Sha256>::new(None, master.as_ref())
            .expand(info.as_bytes(), new_key.as_mut()).expect("32-byte HKDF output");
        assert!(old_key.as_slice() == new_key.as_slice(), "Domain keys must match");
    }
    let payload = b"noid-signature-and-ratchet-fixture";
    let mut old_mac = hmac_legacy::Hmac::<sha2_legacy::Sha256>::new_from_slice(master.as_ref())
        .expect("HMAC accepts arbitrary key length");
    let mut new_mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(master.as_ref())
        .expect("HMAC accepts arbitrary key length");
    old_mac.update(payload);
    new_mac.update(payload);
    assert_eq!(old_mac.finalize().into_bytes().as_slice(), new_mac.finalize().into_bytes().as_slice());
    assert_eq!(sha2_legacy::Sha256::digest(payload).as_slice(), sha2::Sha256::digest(payload).as_slice());
}
