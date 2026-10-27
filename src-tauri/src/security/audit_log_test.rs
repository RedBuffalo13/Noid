use crate::security::audit_log::AuditLog;
use tempfile::tempdir;

#[test]
fn test_audit_log_creates_file() {
    let dir = tempdir().unwrap();
    let audit = AuditLog::new(dir.path());
    audit.log("TEST", "test event").unwrap();
    audit.flush().unwrap();
    let log_path = dir.path().join("audit.log");
    assert!(log_path.exists());
}

#[test]
fn test_log_writes_timestamp_event_details() {
    let dir = tempdir().unwrap();
    let audit = AuditLog::new(dir.path());
    audit.log("AUTH", "Login successful").unwrap();
    audit.flush().unwrap();
    let content = std::fs::read_to_string(dir.path().join("audit.log")).unwrap();
    assert!(content.contains("AUTH"));
    assert!(content.contains("Login successful"));
    assert!(content.starts_with('[')); // timestamp starts with [
}

#[test]
fn test_log_login_success() {
    let dir = tempdir().unwrap();
    let audit = AuditLog::new(dir.path());
    audit.log_login(true).unwrap();
    audit.flush().unwrap();
    let content = std::fs::read_to_string(dir.path().join("audit.log")).unwrap();
    assert!(content.contains("AUTH"));
    assert!(content.contains("Login successful"));
}

#[test]
fn test_log_login_failure() {
    let dir = tempdir().unwrap();
    let audit = AuditLog::new(dir.path());
    audit.log_login(false).unwrap();
    audit.flush().unwrap();
    let content = std::fs::read_to_string(dir.path().join("audit.log")).unwrap();
    assert!(content.contains("Login failed"));
}

#[test]
fn test_log_kill_pin() {
    let dir = tempdir().unwrap();
    let audit = AuditLog::new(dir.path());
    audit.log_kill_pin().unwrap();
    audit.flush().unwrap();
    let content = std::fs::read_to_string(dir.path().join("audit.log")).unwrap();
    assert!(content.contains("SECURITY"));
    assert!(content.contains("Kill PIN activated"));
}

#[test]
fn test_log_key_exchange() {
    let dir = tempdir().unwrap();
    let audit = AuditLog::new(dir.path());
    audit.log_key_exchange("peer123").unwrap();
    audit.flush().unwrap();
    let content = std::fs::read_to_string(dir.path().join("audit.log")).unwrap();
    assert!(content.contains("KEY_EXCHANGE"));
    assert!(content.contains("peer123"));
}

#[test]
fn test_log_dht_store() {
    let dir = tempdir().unwrap();
    let audit = AuditLog::new(dir.path());
    audit.log_dht_store("peer123").unwrap();
    audit.flush().unwrap();
    let content = std::fs::read_to_string(dir.path().join("audit.log")).unwrap();
    assert!(content.contains("DHT_STORE"));
    assert!(content.contains("peer123"));
}

#[test]
fn test_log_dht_retrieve() {
    let dir = tempdir().unwrap();
    let audit = AuditLog::new(dir.path());
    audit.log_dht_retrieve("peer123").unwrap();
    audit.flush().unwrap();
    let content = std::fs::read_to_string(dir.path().join("audit.log")).unwrap();
    assert!(content.contains("DHT_RETRIEVE"));
}

#[test]
fn test_log_replay_detected() {
    let dir = tempdir().unwrap();
    let audit = AuditLog::new(dir.path());
    audit.log_replay_detected("msg123").unwrap();
    audit.flush().unwrap();
    let content = std::fs::read_to_string(dir.path().join("audit.log")).unwrap();
    assert!(content.contains("REPLAY"));
    assert!(content.contains("msg123"));
}

#[test]
fn test_log_screenshot_protection_enabled() {
    let dir = tempdir().unwrap();
    let audit = AuditLog::new(dir.path());
    audit.log_screenshot_protection(true).unwrap();
    audit.flush().unwrap();
    let content = std::fs::read_to_string(dir.path().join("audit.log")).unwrap();
    assert!(content.contains("SCREENSHOT"));
    assert!(content.contains("Protection enabled"));
}

#[test]
fn test_log_screenshot_protection_disabled() {
    let dir = tempdir().unwrap();
    let audit = AuditLog::new(dir.path());
    audit.log_screenshot_protection(false).unwrap();
    audit.flush().unwrap();
    let content = std::fs::read_to_string(dir.path().join("audit.log")).unwrap();
    assert!(content.contains("Protection disabled"));
}

#[test]
fn test_multiple_log_entries_append() {
    let dir = tempdir().unwrap();
    let audit = AuditLog::new(dir.path());
    audit.log("EVENT1", "first").unwrap();
    audit.log("EVENT2", "second").unwrap();
    audit.log("EVENT3", "third").unwrap();
    audit.flush().unwrap();
    let content = std::fs::read_to_string(dir.path().join("audit.log")).unwrap();
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(lines.len(), 3);
    assert!(lines[0].contains("first"));
    assert!(lines[1].contains("second"));
    assert!(lines[2].contains("third"));
}

#[test]
fn test_sealed_details_after_key_set() {
    let dir = tempdir().unwrap();
    let audit = AuditLog::new(dir.path());
    audit.set_key([42u8; 32]);
    audit.log_key_exchange("peer-secret-id").unwrap();
    audit.flush().unwrap();
    let content = std::fs::read_to_string(dir.path().join("audit.log")).unwrap();
    // Event tag stays readable; the details payload must be sealed.
    assert!(content.contains("KEY_EXCHANGE"));
    assert!(content.contains("enc2:"));
    assert!(!content.contains("peer-secret-id"));
}

#[test]
fn test_concurrent_writes_no_corruption() {
    use std::sync::Arc;
    use std::thread;
    let dir = tempdir().unwrap();
    let audit = Arc::new(AuditLog::new(dir.path()));
    let mut handles = vec![];
    for i in 0..10 {
        let audit_clone = Arc::clone(&audit);
        handles.push(thread::spawn(move || {
            audit_clone.log("CONCURRENT", &format!("event_{}", i)).unwrap();
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    audit.flush().unwrap();
    let content = std::fs::read_to_string(dir.path().join("audit.log")).unwrap();
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(lines.len(), 10);
}
