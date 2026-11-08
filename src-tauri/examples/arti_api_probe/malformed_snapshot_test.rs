use anyhow::{ensure, Result};

use super::snapshot_fixture::snapshot_fixture;
use crate::EncryptedKeystore;

#[test]
fn malformed_duplicate_and_oversized_snapshot_entries_fail_closed() -> Result<()> {
    let (master, snapshot) = snapshot_fixture()?;
    for invalid in [b"null".as_slice(), b"{}", b"[[", b"[[[],[]]]", &[0xff]] {
        ensure!(EncryptedKeystore::new(*master, Some(invalid)).is_err());
    }
    let entries: Vec<((String, String), Vec<u8>)> = serde_json::from_slice(&snapshot)?;
    let first = entries
        .first()
        .ok_or_else(|| anyhow::anyhow!("Missing fixture key"))?;
    for count in [2, 129] {
        let duplicate = serde_json::to_vec(&vec![first.clone(); count])?;
        ensure!(EncryptedKeystore::new(*master, Some(&duplicate)).is_err());
    }
    for (path, extension, body) in [
        (
            "invalid//path".to_string(),
            first.0 .1.clone(),
            first.1.clone(),
        ),
        ("x".repeat(257), first.0 .1.clone(), first.1.clone()),
        (first.0 .0.clone(), "x".repeat(65), first.1.clone()),
        (first.0 .0.clone(), first.0 .1.clone(), vec![0; 27]),
        (first.0 .0.clone(), first.0 .1.clone(), vec![0; 16385]),
    ] {
        let malformed = serde_json::to_vec(&vec![((path, extension), body)])?;
        ensure!(EncryptedKeystore::new(*master, Some(&malformed)).is_err());
    }
    Ok(())
}
