//! INT-01: operator-supplied Tor bridges. The lines persist to
//! `tor_dir/bridges.txt` (one torrc-format bridge line per row) and the
//! next Tor generation build feeds them into `builder.bridges()` — a
//! network that blocks guard/directory IPs can't keep a bridged client
//! out. Same node-restart pattern as `set_tor_relay`.

use crate::AppState;
use crate::p2p::tor::status::TorStatus;
use tauri::State;

#[tauri::command]
pub async fn set_tor_bridges(
    lines: Vec<String>,
    state: State<'_, AppState>,
) -> Result<TorStatus, String> {
    // Cap input: 64 lines × 512 chars — a UI textarea can't legitimately
    // exceed that, and the file is parsed at every Tor build.
    let cleaned: Vec<String> = lines
        .iter()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#') && l.len() <= 512)
        .take(64)
        .collect();
    let path = state.tor.dir().join("bridges.txt");
    if cleaned.is_empty() {
        let _ = std::fs::remove_file(&path);
        log::info!("Tor bridges cleared");
    } else {
        std::fs::write(&path, cleaned.join("\n") + "\n").map_err(|e| e.to_string())?;
        log::info!("Tor bridges saved: {} lines", cleaned.len());
    }
    // Node-only restart — the next Tor generation picks the file up.
    state
        .network_generation
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    crate::gate_set(&state.p2p_start_tx, false);
    let tx = state.p2p_start_tx.clone();
    let h = tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        crate::gate_set(&tx, true);
    });
    state.session_tasks.lock().await.push(h);
    Ok(state.tor.status())
}

#[tauri::command]
pub async fn get_tor_bridges(state: State<'_, AppState>) -> Result<Vec<String>, String> {
    let raw = std::fs::read_to_string(state.tor.dir().join("bridges.txt"))
        .unwrap_or_default();
    Ok(raw
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect())
}
