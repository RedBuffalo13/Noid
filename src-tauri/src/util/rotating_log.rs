//! Size-bounded append log for headless nodes — no external logrotate needed.
//!
//! `RotatingLog` writes to `<path>`; when the file would grow past `MAX_BYTES`
//! it is rotated: `name.2` is dropped, `name.1` → `name.2`, `name` → `name.1`,
//! and a fresh `name` is opened. Rotation is also attempted once at open so a
//! log left huge by a previous run is bounded immediately.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Rotate when the active file exceeds 10 MiB.
const MAX_BYTES: u64 = 10 * 1024 * 1024;
/// Archived copies kept next to the active log (`name.1`, `name.2`).
const KEEP_ARCHIVES: u32 = 2;

pub struct RotatingLog {
    path: PathBuf,
    file: File,
    written: u64,
    max_bytes: u64,
}

impl RotatingLog {
    /// Open (creating) `path` for append; rotate first if it is already huge.
    pub fn open(path: &Path) -> io::Result<Self> {
        Self::open_with_limit(path, MAX_BYTES)
    }

    /// Same as `open` with a caller-chosen cap — used by tests.
    fn open_with_limit(path: &Path, max_bytes: u64) -> io::Result<Self> {
        if path
            .metadata()
            .map(|m| m.len() > max_bytes)
            .unwrap_or(false)
        {
            rotate_files(path)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        let written = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(Self {
            path: path.to_path_buf(),
            file,
            written,
            max_bytes,
        })
    }
}

/// Shift `name` → `name.1`, `name.1` → `name.2`, … dropping the oldest.
fn rotate_files(path: &Path) -> io::Result<()> {
    for i in (1..=KEEP_ARCHIVES).rev() {
        let from = archive_name(path, i);
        let to = archive_name(path, i + 1);
        if i == KEEP_ARCHIVES {
            if from.exists() {
                std::fs::remove_file(&from)?;
            }
        } else if from.exists() {
            std::fs::rename(&from, &to)?;
        }
    }
    if path.exists() {
        std::fs::rename(path, archive_name(path, 1))?;
    }
    Ok(())
}

fn archive_name(path: &Path, n: u32) -> PathBuf {
    let mut p = path.to_path_buf();
    p.set_file_name(format!(
        "{}.{}",
        path.file_name().and_then(|f| f.to_str()).unwrap_or("log"),
        n
    ));
    p
}

impl Write for RotatingLog {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.written + buf.len() as u64 > self.max_bytes {
            rotate_files(&self.path)?;
            self.file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)?;
            self.written = 0;
        }
        let n = self.file.write(buf)?;
        self.written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotates_past_limit_and_keeps_archives() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay.log");
        let mut log = RotatingLog::open_with_limit(&path, 100).unwrap();
        // Three writes of 60 bytes → two rotations.
        for _ in 0..3 {
            log.write_all(&[b'x'; 60]).unwrap();
        }
        log.flush().unwrap();
        assert_eq!(path.metadata().unwrap().len(), 60);
        assert_eq!(archive_name(&path, 1).metadata().unwrap().len(), 60);
        assert_eq!(archive_name(&path, 2).metadata().unwrap().len(), 60);
    }

    #[test]
    fn huge_existing_file_rotates_on_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay.log");
        std::fs::write(&path, vec![b'y'; 500]).unwrap();
        let _log = RotatingLog::open_with_limit(&path, 100).unwrap();
        assert!(archive_name(&path, 1).exists());
        assert_eq!(path.metadata().unwrap().len(), 0);
    }
}
