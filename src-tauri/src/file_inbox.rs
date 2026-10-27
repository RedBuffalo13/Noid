//! Inbound file-transfer reassembly (TI-15).
//!
//! Outbound sends a `FileOffer` then blasts `FileOffer`-typed chunks whose
//! `content` is `{"offer_id", "chunk_index", "total_chunks", "data"}` (the
//! chunk `data` is base64). The receiver buffers chunks per
//! `sender:offer_id` until the set is complete, then writes the file under
//! `<app_data>/received/` — a fixed, app-owned directory so a hostile
//! `file_name` can never escape it.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Abandoned transfers are dropped after 10 minutes.
const INBOX_TTL: Duration = Duration::from_secs(600);
/// At most 256 concurrent inbound transfers — bounds memory on flood.
const MAX_INBOX_ENTRIES: usize = 256;
/// Matches `commands::file_transfer::MAX_FILE_BYTES` — a chunk stream
/// declaring more is rejected before it can buffer gigabytes.
const MAX_FILE_BYTES: u64 = 64 << 20;
/// Single chunk cap — mirrors MAX_CHUNK_BYTES on the send side.
const MAX_CHUNK_BYTES: usize = 64 * 1024;

/// One in-progress inbound transfer.
pub struct FileInboxEntry {
    /// Sanitized display name (path components stripped).
    pub name: String,
    pub declared_size: u64,
    pub total_chunks: u32,
    pub chunks: HashMap<u32, Vec<u8>>,
    pub received_bytes: u64,
    pub updated_at: Instant,
}

impl FileInboxEntry {
    fn new(name: String, declared_size: u64, total_chunks: u32) -> Self {
        Self {
            name,
            declared_size,
            total_chunks,
            chunks: HashMap::new(),
            received_bytes: 0,
            updated_at: Instant::now(),
        }
    }
}

/// Strip path components / separators — the wire name is display data
/// only, never a filesystem path decision.
fn sanitize_name(raw: &str) -> String {
    let base = raw
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or("file")
        .chars()
        .filter(|c| !matches!(c, '\0' | ':' | '*' | '?' | '"' | '<' | '>' | '|'))
        .collect::<String>();
    let base = base.trim_matches(['.', ' '].as_ref());
    if base.is_empty() { "file".to_string() } else { base.chars().take(255).collect() }
}

/// Drop expired entries (called on each ingest — no extra timer).
fn gc(map: &mut HashMap<String, FileInboxEntry>) {
    map.retain(|_, e| e.updated_at.elapsed() < INBOX_TTL);
}

/// Register an offer — returns false when the entry cannot be accepted
/// (oversize, flood cap). Duplicate offers for the same key are idempotent.
pub fn register_offer(
    map: &mut HashMap<String, FileInboxEntry>,
    key: &str,
    name: &str,
    declared_size: u64,
) -> bool {
    gc(map);
    if declared_size == 0 || declared_size > MAX_FILE_BYTES {
        return false;
    }
    if map.contains_key(key) {
        return true;
    }
    if map.len() >= MAX_INBOX_ENTRIES {
        log::warn!("file_inbox full — dropping offer {}", key);
        return false;
    }
    map.insert(
        key.to_string(),
        FileInboxEntry::new(sanitize_name(name), declared_size, u32::MAX),
    );
    true
}

/// Ingest one chunk. Returns `Some(path)` once the file is complete and
/// written to `out_dir`.
pub fn ingest_chunk(
    map: &mut HashMap<String, FileInboxEntry>,
    key: &str,
    chunk_index: u32,
    total_chunks: u32,
    data: &[u8],
    out_dir: &Path,
) -> Option<PathBuf> {
    gc(map);
    if total_chunks == 0 || chunk_index >= total_chunks || data.is_empty()
        || data.len() > MAX_CHUNK_BYTES
    {
        return None;
    }
    let entry = match map.get_mut(key) {
        Some(e) => e,
        // Chunk without a registered offer — create a placeholder so a
        // lost offer packet does not orphan the whole transfer.
        None => {
            if map.len() >= MAX_INBOX_ENTRIES {
                return None;
            }
            map.insert(
                key.to_string(),
                FileInboxEntry::new("file".to_string(), MAX_FILE_BYTES, total_chunks),
            );
            map.get_mut(key)?
        }
    };
    if entry.total_chunks == u32::MAX {
        entry.total_chunks = total_chunks;
    }
    if entry.total_chunks != total_chunks {
        log::warn!("file_inbox {}: inconsistent total_chunks — dropped", key);
        map.remove(key);
        return None;
    }
    if entry.received_bytes + data.len() as u64 > MAX_FILE_BYTES.max(entry.declared_size) {
        log::warn!("file_inbox {}: received bytes exceed declared size", key);
        map.remove(key);
        return None;
    }
    if let std::collections::hash_map::Entry::Vacant(v) = entry.chunks.entry(chunk_index) {
        v.insert(data.to_vec());
        entry.received_bytes += data.len() as u64;
    }
    entry.updated_at = Instant::now();
    if entry.chunks.len() as u32 != entry.total_chunks {
        return None;
    }

    // Complete — write ordered bytes under `out_dir`.
    let entry = map.remove(key)?;
    let mut bytes = Vec::with_capacity(entry.received_bytes as usize);
    for i in 0..entry.total_chunks {
        match entry.chunks.get(&i) {
            Some(c) => bytes.extend_from_slice(c),
            // HashMap len==total but an index is missing → corrupt.
            None => return None,
        }
    }
    if let Err(e) = std::fs::create_dir_all(out_dir) {
        log::warn!("file_inbox: cannot create {}: {}", out_dir.display(), e);
        return None;
    }
    // Disambiguate same-name files without overwriting.
    let stem = Path::new(&entry.name)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("file")
        .to_string();
    let ext = Path::new(&entry.name)
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| format!(".{}", s))
        .unwrap_or_default();
    let mut path = out_dir.join(&entry.name);
    for n in 1..1000u32 {
        if !path.exists() { break; }
        path = out_dir.join(format!("{}-{}{}", stem, n, ext));
    }
    match std::fs::write(&path, &bytes) {
        Ok(()) => Some(path),
        Err(e) => {
            log::warn!("file_inbox: write {} failed: {}", path.display(), e);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reassembles_in_order() {
        let dir = std::env::temp_dir().join(format!("noid_inbox_{}", std::process::id()));
        let mut map = HashMap::new();
        assert!(register_offer(&mut map, "p:o", "hello.txt", 6));
        assert!(ingest_chunk(&mut map, "p:o", 0, 2, b"hel", &dir).is_none());
        let out = ingest_chunk(&mut map, "p:o", 1, 2, b"lo!", &dir).expect("complete");
        assert_eq!(std::fs::read(&out).unwrap(), b"hello!");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn strips_path_traversal() {
        assert_eq!(sanitize_name("../../etc/passwd"), "passwd");
        assert_eq!(sanitize_name("..\\..\\win.ini"), "win.ini");
        assert_eq!(sanitize_name(""), "file");
        assert_eq!(sanitize_name("a\0b.txt"), "ab.txt");
    }

    #[test]
    fn chunk_without_offer_reassembles() {
        let dir = std::env::temp_dir().join(format!("noid_inbox2_{}", std::process::id()));
        let mut map = HashMap::new();
        let out = ingest_chunk(&mut map, "p:o", 0, 1, b"x", &dir).expect("single chunk");
        assert_eq!(std::fs::read(&out).unwrap(), b"x");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn oversized_offer_rejected() {
        let mut map = HashMap::new();
        assert!(!register_offer(&mut map, "p:o", "big", MAX_FILE_BYTES + 1));
        assert!(register_offer(&mut map, "p:o", "ok", 100));
    }

    #[test]
    fn no_overwrite_existing() {
        let dir = std::env::temp_dir().join(format!("noid_inbox3_{}", std::process::id()));
        let mut map = HashMap::new();
        let p1 = ingest_chunk(&mut map, "p:1", 0, 1, b"a", &dir).unwrap();
        let p2 = ingest_chunk(&mut map, "p:2", 0, 1, b"b", &dir).unwrap();
        assert_ne!(p1, p2);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
