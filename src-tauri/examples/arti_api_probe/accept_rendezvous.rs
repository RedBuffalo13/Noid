use futures::Stream;
use tor_hsservice::{RendRequest, StreamRequest};

/// Compile-check rendezvous acceptance without fabricating a client network address.
pub async fn accept_rendezvous(
    request: RendRequest,
) -> anyhow::Result<impl Stream<Item = StreamRequest> + Unpin> {
    Ok(request.accept().await?)
}
