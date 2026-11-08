use argon2::{PasswordHasher, PasswordVerifier};
use argon2_legacy::{PasswordHasher as LegacyHasher, PasswordVerifier as LegacyVerifier};
use rand::Rng;
use zeroize::Zeroizing;

#[test]
fn argon2_defaults_kdf_and_phc_hashes_remain_cross_version_readable() {
    let mut salt = [0u8; 16];
    rand::rng().fill_bytes(&mut salt);
    let password = b"noid-public-test-password";
    let old_defaults = argon2_legacy::Params::default();
    let new_defaults = argon2::Params::default();
    assert_eq!((old_defaults.m_cost(), old_defaults.t_cost(), old_defaults.p_cost()),
        (new_defaults.m_cost(), new_defaults.t_cost(), new_defaults.p_cost()));
    let old = argon2_legacy::Argon2::new(
        argon2_legacy::Algorithm::Argon2id, argon2_legacy::Version::V0x13,
        argon2_legacy::Params::new(65536, 3, 1, None).expect("production parameters"));
    let new = argon2::Argon2::new(
        argon2::Algorithm::Argon2id, argon2::Version::V0x13,
        argon2::Params::new(65536, 3, 1, None).expect("same production parameters"));
    let mut old_key = Zeroizing::new([0u8; 32]);
    let mut new_key = Zeroizing::new([0u8; 32]);
    old.hash_password_into(password, &salt, old_key.as_mut()).expect("valid test inputs");
    new.hash_password_into(password, &salt, new_key.as_mut()).expect("valid test inputs");
    assert!(old_key.as_slice() == new_key.as_slice(), "KDF outputs must match");

    let legacy_salt = argon2_legacy::password_hash::SaltString::encode_b64(&salt)
        .expect("valid random salt");
    let old_hash = old.hash_password(password, &legacy_salt).expect("valid PHC inputs").to_string();
    assert!(new.verify_password(password, old_hash.as_str()).is_ok());
    assert!(new.verify_password(b"wrong-test-password", old_hash.as_str()).is_err());
    let new_hash = new.hash_password_with_salt(password, &salt)
        .expect("valid PHC inputs").to_string();
    let parsed = argon2_legacy::PasswordHash::new(&new_hash).expect("valid generated PHC");
    assert!(old.verify_password(password, &parsed).is_ok());
    assert!(old.verify_password(b"wrong-test-password", &parsed).is_err());
    assert_eq!(old_hash, new_hash);
}
