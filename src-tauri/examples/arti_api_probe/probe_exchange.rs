use anyhow::{ensure, Context, Result};
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Exchange a bounded probe frame, flushing short writes before awaiting replies.
pub(super) async fn probe_exchange<S>(mut stream: S, initiator: bool) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut frame = [0_u8; 4];
    if initiator {
        stream.write_all(b"PING").await.context("client write")?;
        stream.flush().await.context("client flush")?;
        stream.read_exact(&mut frame).await.context("client read")?;
        ensure!(&frame == b"PONG", "unexpected probe response");
    } else {
        stream.read_exact(&mut frame).await.context("server read")?;
        ensure!(&frame == b"PING", "unexpected probe request");
        stream.write_all(b"PONG").await.context("server write")?;
        stream.flush().await.context("server flush")?;
    }
    Ok(())
}
