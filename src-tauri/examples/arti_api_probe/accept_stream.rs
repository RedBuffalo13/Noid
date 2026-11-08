use arti_client::DataStream;
use tor_cell::relaycell::msg::{Connected, End};
use tor_hsservice::StreamRequest;
use tor_proto::stream::IncomingStreamRequest;

/// Accept only BEGIN for the Noid virtual port, with no client IP in CONNECTED.
pub async fn accept_stream(request: StreamRequest) -> anyhow::Result<DataStream> {
    if matches!(request.request(), IncomingStreamRequest::Begin(begin) if begin.port() == 4020) {
        return Ok(request.accept(Connected::new_empty()).await?);
    }
    request.reject(End::new_misc()).await?;
    anyhow::bail!("Unsupported onion virtual port or stream request")
}
