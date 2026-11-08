use anyhow::{ensure, Result};
use zeroize::Zeroizing;

use super::snapshot_fixture::snapshot_fixture;
use crate::EncryptedKeystore;

#[test]
fn wrong_key_tampering_and_name_relocation_fail_closed() -> Result<()> {
    let (master, snapshot) = snapshot_fixture()?;
    let mut wrong = Zeroizing::new(*master);
    wrong[0] ^= 1;
    ensure!(EncryptedKeystore::new(*wrong, Some(&snapshot)).is_err());
    let entries: Vec<((String, String), Vec<u8>)> = serde_json::from_slice(&snapshot)?;
    let mut tampered = entries.clone();
    let entry = tampered
        .first_mut()
        .ok_or_else(|| anyhow::anyhow!("Missing key"))?;
    let byte = entry
        .1
        .last_mut()
        .ok_or_else(|| anyhow::anyhow!("Missing ciphertext"))?;
    *byte ^= 1;
    ensure!(EncryptedKeystore::new(*master, Some(&serde_json::to_vec(&tampered)?)).is_err());
    let mut relocated = entries;
    let entry = relocated
        .first_mut()
        .ok_or_else(|| anyhow::anyhow!("Missing key"))?;
    entry.0 .0 = entry.0 .0.replace("noid-p0", "other-p0");
    ensure!(EncryptedKeystore::new(*master, Some(&serde_json::to_vec(&relocated)?)).is_err());
    ensure!(EncryptedKeystore::new(*master, Some(&vec![0u8; 1024 * 1024 + 1])).is_err());
    Ok(())
}
