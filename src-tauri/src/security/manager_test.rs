#[cfg(test)]
mod tests {
    use crate::security::manager::SecurityManager;
    use tempfile::tempdir;

    #[test]
    fn test_encrypt_decrypt() {
        let dir = tempdir().unwrap();
        let mut mgr = SecurityManager::new(dir.path().to_path_buf());
        mgr.derive_key("testpassword123").unwrap();

        let plaintext = b"Hello, World!";
        let encrypted = mgr.encrypt(plaintext).unwrap();
        let decrypted = mgr.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_wrong_pin_fails() {
        let dir = tempdir().unwrap();
        let mut mgr = SecurityManager::new(dir.path().to_path_buf());
        mgr.derive_key("correctpin123").unwrap();

        let encrypted = mgr.encrypt(b"secret").unwrap();

        let mut mgr2 = SecurityManager::new(dir.path().to_path_buf());
        mgr2.derive_key("wrongpin456").unwrap();
        assert!(mgr2.decrypt(&encrypted).is_err());
    }

    #[test]
    fn test_salt_persists() {
        let dir = tempdir().unwrap();

        let mut mgr1 = SecurityManager::new(dir.path().to_path_buf());
        mgr1.derive_key("mypin12345").unwrap();
        let encrypted = mgr1.encrypt(b"test data").unwrap();

        let mut mgr2 = SecurityManager::new(dir.path().to_path_buf());
        mgr2.derive_key("mypin12345").unwrap();
        let decrypted = mgr2.decrypt(&encrypted).unwrap();

        assert_eq!(b"test data".to_vec(), decrypted);
    }

    #[test]
    fn test_kill_pin() {
        let dir = tempdir().unwrap();
        let mut mgr = SecurityManager::new(dir.path().to_path_buf());
        mgr.derive_key("truepin12345").unwrap();
        mgr.set_kill_pin("killpin12345").unwrap();

        assert!(mgr.verify_kill_pin("killpin12345"));
        assert!(!mgr.verify_kill_pin("truepin12345"));
    }
}
