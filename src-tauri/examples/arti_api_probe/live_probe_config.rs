use anyhow::Result;
use arti_client::config::{TorClientConfig, TorClientConfigBuilder};

/// Isolate live-test state from the user's Arti directories.
///
/// Scratch files use Arti's native keystore, not Noid's encrypted store. Retain
/// them for explicit cleanup: task/writer shutdown has not yet been proven.
pub(super) fn live_probe_config() -> Result<TorClientConfig> {
    let root = tempfile::Builder::new().prefix("noid-p0-live-").tempdir()?;
    let config = TorClientConfigBuilder::from_directories(
        root.path().join("state"),
        root.path().join("cache"),
    )
    .build()?;
    let _retained = root.keep();
    Ok(config)
}
