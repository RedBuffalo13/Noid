use std::sync::Arc;
use arti_client::TorClient;
use futures::Stream;
use tor_config_path::CfgPathResolver;
use tor_hsservice::{OnionService, RendRequest, RunningOnionService};
use tor_rtcompat::Runtime;

/// Compile-check direct service launch; offline tests deliberately never call this.
pub fn launch_service<R: Runtime>(
    client: &TorClient<R>,
    service: OnionService,
    resolver: Arc<CfgPathResolver>,
) -> anyhow::Result<Option<(Arc<RunningOnionService>, impl Stream<Item = RendRequest>)>> {
    Ok(service.launch(
        client.runtime().clone(), client.dirmgr()?, client.hs_circ_pool()?, resolver,
    )?)
}
