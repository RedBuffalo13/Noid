use anyhow::{ensure, Result};
use rand::Rng;
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_persist::state_dir::StateDirectory;
use zeroize::Zeroizing;

use crate::{create_service, EncryptedKeystore};

#[test]
fn offline_custom_keystore_identity_survives_encrypted_snapshot() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let state_dir = StateDirectory::new(dir.path(), &fs_mistrust::Mistrust::default())?;
    let mut master = Zeroizing::new([0u8; 32]);
    rand::rng().fill_bytes(master.as_mut());
    let store = EncryptedKeystore::new(*master, None)?;
    let config = OnionServiceConfigBuilder::default()
        .nickname("noid-p0".parse()?).build()?;
    let service = create_service(config.clone(), Box::new(store.clone()), state_dir.clone())?;
    let address = service.generate_identity_key(Default::default())?;
    ensure!(service.onion_address() == Some(address));
    let snapshot = store.snapshot()?;
    ensure!(!snapshot.windows(19).any(|w| w == b"OPENSSH PRIVATE KEY"));
    let path = dir.path().join("encrypted-fixture.json");
    std::fs::write(&path, &snapshot)?;
    drop(service);
    drop(store);
    let restored = EncryptedKeystore::new(*master, Some(&std::fs::read(&path)?))?;
    let service = create_service(config, Box::new(restored), state_dir)?;
    ensure!(service.generate_identity_key(Default::default())? == address);
    Ok(())
}
