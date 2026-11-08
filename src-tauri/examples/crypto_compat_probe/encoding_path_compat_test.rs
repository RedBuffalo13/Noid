use base64::Engine;
use base64_legacy::Engine as LegacyEngine;
use rand::Rng;
use zeroize::Zeroizing;

/// Only queries platform paths; never opens the messenger's data directory.
#[test]
fn persisted_base64_and_platform_paths_remain_identical() {
    let mut sample = Zeroizing::new([0u8; 137]);
    rand::rng().fill_bytes(sample.as_mut());
    for (old, new) in [
        (base64_legacy::engine::general_purpose::STANDARD, base64::engine::general_purpose::STANDARD),
        (base64_legacy::engine::general_purpose::STANDARD_NO_PAD, base64::engine::general_purpose::STANDARD_NO_PAD),
        (base64_legacy::engine::general_purpose::URL_SAFE, base64::engine::general_purpose::URL_SAFE),
        (base64_legacy::engine::general_purpose::URL_SAFE_NO_PAD, base64::engine::general_purpose::URL_SAFE_NO_PAD),
    ] {
        let encoded = Zeroizing::new(old.encode(sample.as_ref()));
        let modern = Zeroizing::new(new.encode(sample.as_ref()));
        assert!(encoded.as_str() == modern.as_str(), "Base64 wire format must match");
        let restored = Zeroizing::new(new.decode(encoded.as_bytes()).expect("legacy base64"));
        let legacy = Zeroizing::new(old.decode(modern.as_bytes()).expect("modern base64"));
        assert!(restored.as_slice() == sample.as_ref());
        assert!(legacy.as_slice() == sample.as_ref());
    }
    assert_eq!(dirs_legacy::config_dir(), dirs::config_dir());
    assert_eq!(dirs_legacy::data_dir(), dirs::data_dir());
    assert_eq!(dirs_legacy::data_local_dir(), dirs::data_local_dir());
    assert_eq!(dirs_legacy::home_dir(), dirs::home_dir());
}
