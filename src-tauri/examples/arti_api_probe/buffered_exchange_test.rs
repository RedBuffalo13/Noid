use anyhow::{Context, Result};
use futures::io::BufWriter;
use std::time::Duration;
use tokio_util::compat::TokioAsyncReadCompatExt;

/// Short frames must cross both write buffers without filling or closing them.
#[tokio::test]
async fn buffered_exchange_flushes_both_directions() -> Result<()> {
    let (client, server) = tokio::io::duplex(64);
    let client = BufWriter::with_capacity(64, client.compat());
    let server = BufWriter::with_capacity(64, server.compat());
    tokio::time::timeout(Duration::from_secs(2), async {
        futures::try_join!(
            super::probe_exchange::probe_exchange(client, true),
            super::probe_exchange::probe_exchange(server, false)
        )
    })
    .await
    .context("buffered exchange stalled (missing flush)")??;
    Ok(())
}
