//! Move a corrupt/unreadable file aside instead of deleting it.
//!
//! `<name>` becomes `<name>.corrupt-<unix_ts>` in the same directory — the
//! evidence survives for forensics while the caller regenerates a fresh file.
//! Never deletes data; a rename failure is reported to the caller.

use std::path::{Path, PathBuf};

/// Rename `path` to `<name>.corrupt-<unix_ts>` and return the new path.
/// Returns `Ok(None)` when the file does not exist (nothing to quarantine).
pub fn quarantine(path: &Path) -> std::io::Result<Option<PathBuf>> {
    if !path.exists() {
        return Ok(None);
    }
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut dest = path.to_path_buf();
    dest.set_file_name(format!(
        "{}.corrupt-{}",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file"),
        ts
    ));
    // Same-second collision with a previous quarantine: fall back to a
    // suffixed name rather than failing the heal.
    if dest.exists() {
        dest.set_file_name(format!(
            "{}.corrupt-{}-x",
            path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("file"),
            ts
        ));
    }
    std::fs::rename(path, &dest)?;
    log::warn!(
        "Quarantined unreadable file {} -> {}",
        path.display(),
        dest.display()
    );
    Ok(Some(dest))
}

/// Quarantine a SQLite database together with its sidecar files.
///
/// A corrupt `*.db` is unusable, but so are leftover `-journal`, `-wal` and
/// `-shm` files — SQLite replays them into the freshly recreated database
/// and the corruption comes back. All four move aside; missing sidecars
/// are skipped silently.
pub fn quarantine_sqlite(path: &Path) -> std::io::Result<()> {
    quarantine(path)?;
    for suffix in ["-journal", "-wal", "-shm"] {
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        quarantine(Path::new(&sidecar))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_is_noop() {
        let dir = tempfile::tempdir().unwrap();
        assert!(quarantine(&dir.path().join("nope.bin")).unwrap().is_none());
    }

    #[test]
    fn renames_and_preserves_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peer_cache.json");
        std::fs::write(&path, b"garbage").unwrap();
        let dest = quarantine(&path).unwrap().unwrap();
        assert!(!path.exists());
        assert!(dest.exists());
        let name = dest.file_name().unwrap().to_str().unwrap();
        assert!(name.starts_with("peer_cache.json.corrupt-"));
        assert_eq!(std::fs::read(&dest).unwrap(), b"garbage");
    }

    #[test]
    fn same_second_collision_gets_suffix() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.db");
        std::fs::write(&path, b"one").unwrap();
        let first = quarantine(&path).unwrap().unwrap();
        std::fs::write(&path, b"two").unwrap();
        let second = quarantine(&path).unwrap().unwrap();
        assert_ne!(first, second);
        assert!(first.exists() && second.exists());
    }

    #[test]
    fn quarantine_sqlite_moves_sidecars() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("noid.db");
        std::fs::write(&db, b"main").unwrap();
        for suffix in ["-journal", "-wal", "-shm"] {
            let mut p = db.as_os_str().to_os_string();
            p.push(suffix);
            std::fs::write(Path::new(&p), b"side").unwrap();
        }
        quarantine_sqlite(&db).unwrap();
        // Every file moved aside — nothing with the original names remains.
        assert!(!db.exists());
        for suffix in ["-journal", "-wal", "-shm"] {
            let mut p = db.as_os_str().to_os_string();
            p.push(suffix);
            assert!(!Path::new(&p).exists(), "sidecar {} left behind", suffix);
        }
        let moved: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(moved.len(), 4);
    }

    #[test]
    fn quarantine_sqlite_tolerates_missing_sidecars() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("noid.db");
        std::fs::write(&db, b"main").unwrap();
        quarantine_sqlite(&db).unwrap();
        assert!(!db.exists());
    }
}
