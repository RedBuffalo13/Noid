use std::sync::Arc;
use tor_hsservice::{OnionService, OnionServiceConfig};
use tor_keymgr::{KeyMgrBuilder, Keystore};
use tor_persist::state_dir::StateDirectory;

/// Construct a service with an injected store without launching it or creating a TorClient.
pub fn create_service(
    config: OnionServiceConfig,
    store: Box<dyn Keystore>,
    state_dir: StateDirectory,
) -> anyhow::Result<OnionService> {
    let keymgr = Arc::new(KeyMgrBuilder::default().primary_store(store).build()?);
    Ok(OnionService::builder().config(config).keymgr(keymgr).state_dir(state_dir).build()?)
}
