use anyhow::{anyhow, Result};
use rand::RngCore;
use std::fs;
use std::io::Write;
use std::path::Path;

const CHUNK: usize = 64 * 1024;

/// Overwrite a file in place, then remove it.
///
/// Symlink-safe: metadata is taken via `symlink_metadata` and a symlink is
/// only unlinked — never opened for writing (opening a link for overwrite
/// would zero out the LINK TARGET, destroying an unrelated file).
/// Every pass ends with `sync_data` so the overwrite actually reaches the
/// media instead of lingering in the page cache until removal.
///
/// Limitation (audit S17): overwrite-in-place is not guaranteed on SSDs
/// (wear leveling remaps blocks) or copy-on-write/journaled filesystems —
/// forensic recovery from freed blocks cannot be ruled out. The wipe also
/// removes the data directory entirely, which is the strongest guarantee
/// available at this layer; full assurance requires device encryption.
pub fn secure_delete(path: &Path) -> Result<()> {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };

    if meta.file_type().is_symlink() {
        fs::remove_file(path)?;
        log::info!("Removed symlink without following: {}", path.display());
        return Ok(());
    }
    if !meta.is_file() {
        return Err(anyhow!(
            "secure_delete: {} is not a regular file",
            path.display()
        ));
    }

    let file_size = meta.len();

    // Pass 1: zeros. Pass 2: random. Both synced to media.
    for random in [false, true] {
        let file = fs::OpenOptions::new().write(true).open(path)?;
        let mut writer = std::io::BufWriter::new(file);
        let mut written = 0u64;
        let mut buf = vec![0u8; CHUNK.min(file_size.max(1) as usize)];
        while written < file_size {
            let n = std::cmp::min(buf.len() as u64, file_size - written) as usize;
            if random {
                rand::thread_rng().fill_bytes(&mut buf[..n]);
            }
            writer.write_all(&buf[..n])?;
            written += n as u64;
        }
        writer.flush()?;
        writer.get_ref().sync_data()?;
    }

    fs::remove_file(path)?;

    log::info!("Securely deleted: {}", path.display());
    Ok(())
}

pub fn secure_delete_dir(path: &Path) -> Result<()> {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    // A symlinked directory is unlinked, never traversed — recursing through
    // the link would wipe an unrelated directory tree.
    if meta.file_type().is_symlink() {
        fs::remove_file(path)?;
        return Ok(());
    }

    let mut failures = 0u32;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let entry_path = entry.path();
        let ft = entry.file_type()?;
        if ft.is_dir() && !ft.is_symlink() {
            if let Err(e) = secure_delete_dir(&entry_path) {
                failures += 1;
                log::error!("secure_delete_dir failed for {}: {}", entry_path.display(), e);
            }
        } else if let Err(e) = secure_delete(&entry_path) {
            // S17: a silent shred failure used to pass unnoticed — count it
            // so callers (wipe) can surface a partial-wipe condition.
            failures += 1;
            log::error!("secure_delete failed for {}: {}", entry_path.display(), e);
        }
    }

    if let Err(e) = fs::remove_dir(path) {
        log::error!("remove_dir failed for {}: {}", path.display(), e);
        return Err(e.into());
    }
    log::info!("Securely deleted directory: {}", path.display());
    if failures > 0 {
        return Err(anyhow!(
            "secure_delete_dir: {} entr{} failed to shred under {}",
            failures,
            if failures == 1 { "y" } else { "ies" },
            path.display()
        ));
    }
    Ok(())
}
