use crate::auth::AuthManager;

#[tokio::test]
async fn test_new_starts_with_zero_attempts() {
    let mgr = AuthManager::new();
    assert_eq!(mgr.get_failed_attempts().await, 0);
    assert!(!mgr.is_locked_out().await);
}

#[tokio::test]
async fn test_increment_failed_attempt_returns_count() {
    let mgr = AuthManager::new();
    let count1 = mgr.increment_failed_attempt().await;
    assert_eq!(count1, 1);
    let count2 = mgr.increment_failed_attempt().await;
    assert_eq!(count2, 2);
    assert_eq!(mgr.get_failed_attempts().await, 2);
}

#[tokio::test]
async fn test_lockout_at_five_failures() {
    let mgr = AuthManager::new();
    for _ in 0..4 {
        mgr.increment_failed_attempt().await;
    }
    assert!(!mgr.is_locked_out().await);
    mgr.increment_failed_attempt().await;
    assert!(mgr.is_locked_out().await);
}

#[tokio::test]
async fn test_lockout_persists_beyond_five() {
    let mgr = AuthManager::new();
    for _ in 0..5 {
        mgr.increment_failed_attempt().await;
    }
    assert!(mgr.is_locked_out().await);
    mgr.increment_failed_attempt().await;
    assert!(mgr.is_locked_out().await);
    assert_eq!(mgr.get_failed_attempts().await, 6);
}

#[tokio::test]
async fn test_reset_attempts_clears_count() {
    let mgr = AuthManager::new();
    for _ in 0..3 {
        mgr.increment_failed_attempt().await;
    }
    mgr.reset_attempts().await;
    assert_eq!(mgr.get_failed_attempts().await, 0);
}

#[tokio::test]
async fn test_reset_unlocks() {
    let mgr = AuthManager::new();
    for _ in 0..5 {
        mgr.increment_failed_attempt().await;
    }
    assert!(mgr.is_locked_out().await);
    mgr.reset_attempts().await;
    assert!(!mgr.is_locked_out().await);
}

#[tokio::test]
async fn test_reset_after_lockout_allows_retry() {
    let mgr = AuthManager::new();
    for _ in 0..5 {
        mgr.increment_failed_attempt().await;
    }
    assert!(mgr.is_locked_out().await);
    mgr.reset_attempts().await;
    assert_eq!(mgr.get_failed_attempts().await, 0);
    let count = mgr.increment_failed_attempt().await;
    assert_eq!(count, 1);
    assert!(!mgr.is_locked_out().await);
}

#[tokio::test]
async fn test_concurrent_increments_are_safe() {
    use std::sync::Arc;
    let mgr = Arc::new(AuthManager::new());
    let mut handles = vec![];
    for _ in 0..10 {
        let mgr_clone = Arc::clone(&mgr);
        handles.push(tokio::spawn(async move {
            mgr_clone.increment_failed_attempt().await;
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
    assert_eq!(mgr.get_failed_attempts().await, 10);
    assert!(mgr.is_locked_out().await);
}

#[tokio::test]
async fn test_lockout_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    {
        let mgr = AuthManager::load(dir.path());
        for _ in 0..5 {
            mgr.increment_failed_attempt().await;
        }
        assert!(mgr.is_locked_out().await);
    }
    // A fresh instance (i.e. app restart) must still see the lockout —
    // otherwise every restart grants a new batch of brute-force attempts.
    let mgr2 = AuthManager::load(dir.path());
    assert!(mgr2.is_locked_out().await);
    assert_eq!(mgr2.get_failed_attempts().await, 5);
}

#[tokio::test]
async fn test_reset_attempts_removes_persisted_state() {
    let dir = tempfile::tempdir().unwrap();
    let mgr = AuthManager::load(dir.path());
    for _ in 0..3 {
        mgr.increment_failed_attempt().await;
    }
    mgr.reset_attempts().await;
    let mgr2 = AuthManager::load(dir.path());
    assert_eq!(mgr2.get_failed_attempts().await, 0);
    assert!(!mgr2.is_locked_out().await);
}

/// Regression: the login command checks `verify_kill_pin` BEFORE the
/// `is_locked_out` early-return — the wipe decision lives entirely in
/// SecurityManager and must stay reachable while AuthManager reports
/// lockout. This test pins the subsystem independence that ordering
/// relies on.
#[tokio::test]
async fn test_kill_pin_verifies_under_lockout() {
    let dir = tempfile::tempdir().unwrap();
    let auth = AuthManager::load(dir.path());
    for _ in 0..5 {
        auth.increment_failed_attempt().await;
    }
    assert!(auth.is_locked_out().await);

    let mut security = crate::security::manager::SecurityManager::new(dir.path().to_path_buf());
    security.derive_key("truepin12345").unwrap();
    security.set_kill_pin("killpin12345").unwrap();

    // Locked out, yet the kill pin still verifies — so the wipe path in
    // login()/kill_switch() runs before the lockout gate can reject it.
    assert!(security.verify_kill_pin("killpin12345"));
    assert!(auth.is_locked_out().await);
}
