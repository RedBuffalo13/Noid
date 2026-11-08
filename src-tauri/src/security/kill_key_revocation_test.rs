use rand::Rng;
use zeroize::Zeroizing;

use super::SecurityManager;

#[test]
fn kill_pin_revokes_key_for_missing_directory_and_filesystem_failure() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let bad_path = directory.path().join("not-a-directory");
    std::fs::write(&bad_path, b"public test fixture")?;
    for (path, should_succeed) in [(directory.path().join("missing"), true), (bad_path, false)] {
        let mut key = Zeroizing::new([0u8; 32]);
        rand::rng().fill_bytes(key.as_mut());
        let mut manager = SecurityManager::new(path);
        manager.set_master_key(*key);
        let result = manager.kill_everything();
        assert_eq!(result.is_ok(), should_succeed);
        assert!(
            manager.get_master_key().is_err(),
            "Wipe must always revoke the key"
        );
    }
    Ok(())
}
