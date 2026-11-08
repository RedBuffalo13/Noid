use crate::p2p::proxy_config::{NoidProxyConfig, ProxyMode};
use crate::AppState;
use std::time::Duration;
use tauri::State;

/// Connectivity check: TCP-connect to the configured proxy address with a
/// short timeout. Reports reachability — the full handshake is exercised
/// by the first real dial through it.
#[tauri::command]
pub async fn test_proxy(state: State<'_, AppState>) -> Result<String, String> {
    let cfg = NoidProxyConfig::load(&state.app_data_dir);
    if cfg.mode == ProxyMode::Off {
        return Err("proxy is off".to_string());
    }
    let t = cfg.to_transport().ok_or("invalid proxy address")?;
    let addr = t.addr;
    let start = std::time::Instant::now();
    match tokio::time::timeout(
        Duration::from_secs(8),
        tokio::net::TcpStream::connect(addr),
    )
    .await
    {
        Ok(Ok(_)) => Ok(format!("proxy {} reachable in {:?}", addr, start.elapsed())),
        Ok(Err(e)) => Err(format!("proxy {} unreachable: {}", addr, e)),
        Err(_) => Err(format!("proxy {} timed out", addr)),
    }
}
