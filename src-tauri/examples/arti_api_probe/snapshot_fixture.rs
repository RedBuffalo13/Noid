use rand::Rng;
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_persist::state_dir::StateDirectory;
use zeroize::Zeroizing;

use crate::{create_service, EncryptedKeystore};

/// Generate a random-key fixture without creating a TorClient or launching a service.
pub(super) fn snapshot_fixture() -> anyhow::Result<(Zeroizing<[u8; 32]>, Vec<u8>)> {
    let dir = tempfile::tempdir()?;
    let state_dir = StateDirectory::new(dir.path(), &fs_mistrust::Mistrust::default())?;
    let mut master = Zeroizing::new([0u8; 32]);
    rand::rng().fill_bytes(master.as_mut());
    let store = EncryptedKeystore::new(*master, None)?;
    let config = OnionServiceConfigBuilder::default()
        .nickname("noid-p0".parse()?)
        .build()?;
    let service = create_service(config, Box::new(store.clone()), state_dir)?;
    service.generate_identity_key(Default::default())?;
    Ok((master, store.snapshot()?))
}
