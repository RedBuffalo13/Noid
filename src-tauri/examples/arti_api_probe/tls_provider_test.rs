use anyhow::{anyhow, ensure, Result};
use tor_rtcompat::tokio::TokioRustlsRuntime;

/// Exercise Arti's TLS constructor with both providers compiled, without a client.
#[test]
fn explicit_provider_initializes_arti_runtime_without_network() -> Result<()> {
    ensure!(
        rustls::crypto::CryptoProvider::get_default().is_none(),
        "The isolated provider test must own process-wide initialization"
    );
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow!("CryptoProvider initialization unexpectedly raced"))?;
    let tokio = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    // From<Handle> constructs RustlsProvider immediately; it must not panic
    // on the AWS-LC/Ring feature union. No TorClient or socket is created.
    let arti = TokioRustlsRuntime::from(tokio.handle().clone());
    ensure!(rustls::crypto::CryptoProvider::get_default().is_some());
    drop(arti);
    Ok(())
}
