//! Single-instance lockfile.
//!
//! `<dir>/<name>` is created atomically (`create_new`) and holds the owning
//! PID. A second process gets a clear error instead of silently competing
//! for the same listen ports. The file is removed on a clean shutdown via
//! `Drop`; after a kill the next start detects the stale lock by checking
//! whether the recorded PID is still alive.

use std::path::{Path, PathBuf};

/// Guard for an acquired instance lock — removes the file on drop.
#[derive(Debug)]
pub struct InstanceLock {
    path: PathBuf,
}

impl InstanceLock {
    /// Acquire `<dir>/<name>` for this process. Fails when another live
    /// process already holds it; a lock left behind by a dead PID is
    /// reclaimed automatically.
    pub fn acquire(dir: &Path, name: &str) -> std::io::Result<Self> {
        let path = dir.join(name);
        if path.exists() && lock_is_stale(&path) {
            // Best effort: if removal fails the create_new below reports
            // the conflict accurately anyway.
            let _ = std::fs::remove_file(&path);
        }
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut f) => {
                use std::io::Write;
                let _ = writeln!(f, "{}", std::process::id());
                Ok(Self { path })
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(std::io::Error::new(
                e.kind(),
                format!("another instance holds {}", path.display()),
            )),
            Err(e) => Err(e),
        }
    }
}

impl Drop for InstanceLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// A lock is stale when it contains a PID that no longer exists. An
/// unreadable or malformed lock is treated as LIVE — failing closed is
/// safer than two relays binding the same port.
fn lock_is_stale(path: &Path) -> bool {
    match std::fs::read_to_string(path) {
        Ok(content) => match content.trim().parse::<u32>() {
            Ok(pid) => !pid_alive(pid),
            Err(_) => false,
        },
        Err(_) => false,
    }
}

#[cfg(unix)]
fn pid_alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{}", pid)).exists()
}

/// Windows liveness probe via `tasklist` (TI-12): without it a crashed
/// relay's lockfile is never reclaimed and the next start is wedged.
/// Fail-closed on probe errors — two live instances is worse than one
/// manual lockfile removal.
#[cfg(windows)]
fn pid_alive(pid: u32) -> bool {
    std::process::Command::new("tasklist")
        .args(["/FI", &format!("PID eq {}", pid), "/NH", "/FO", "CSV"])
        .output()
        .map(|o| {
            let out = String::from_utf8_lossy(&o.stdout);
            // CSV row: "image.exe","<pid>","Session","#","Mem"
            out.lines().any(|l| {
                l.split(',').nth(1).is_some_and(|f| {
                    f.trim_matches('"') == pid.to_string()
                })
            })
        })
        .unwrap_or(true)
}

/// Other non-unix platforms lack a cheap liveness probe — assume the
/// holder is alive and require manual removal of a genuinely stale lock.
#[cfg(not(any(unix, windows)))]
fn pid_alive(_pid: u32) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_acquire_fails_while_first_lives() {
        let dir = tempfile::tempdir().unwrap();
        let _lock = InstanceLock::acquire(dir.path(), "test.lock").unwrap();
        let err = InstanceLock::acquire(dir.path(), "test.lock").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
    }

    #[test]
    fn drop_releases_the_lock() {
        let dir = tempfile::tempdir().unwrap();
        {
            let _lock = InstanceLock::acquire(dir.path(), "test.lock").unwrap();
            assert!(dir.path().join("test.lock").exists());
        }
        assert!(!dir.path().join("test.lock").exists());
        assert!(InstanceLock::acquire(dir.path(), "test.lock").is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn dead_pid_lock_is_reclaimed() {
        let dir = tempfile::tempdir().unwrap();
        let lock = dir.path().join("test.lock");
        // PID 2^22 is far past any real pid_max and never exists.
        std::fs::write(&lock, "4194304\n").unwrap();
        assert!(InstanceLock::acquire(dir.path(), "test.lock").is_ok());
    }
}
