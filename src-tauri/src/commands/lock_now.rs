//! INT-03: manual/auto lock — drops every secret held in RAM and takes
//! the node offline without touching disk state. KillPin's full wipe is
//! overkill for "step away from the desk" — this is the non-destructive
//! barrier: re-login with the main PIN restores the session.
use crate::AppState;
use tauri::State;

#[tauri::command]
pub async fn lock_now(state: State<'_, AppState>) -> Result<(), String> {
    // 1. Master key — zeroized; identity/dht/field ciphers die with the
    //    node task below (they were built from it).
    {
        let mut security = state.security.lock().await;
        security.clear_master_key();
    }
    // 2. Live ratchet sessions — chain keys in RAM.
    state.ratchet_sessions.clear_all().await;
    // 2b. Tor generation + retained onion identity: the keystore owner
    //     holds the master key, and a locked client must not keep the
    //     onion service answering circuits without it.
    let _ = state.tor.revoke().await;
    // 3. Close the gate — the watcher aborts the node task (all key
    //    material it holds is freed with it).
    crate::gate_set(&state.p2p_start_tx, false);
    // 4. Tracked session tasks (cover traffic, tor restarts, …).
    crate::drain_session_tasks(&state, std::time::Duration::from_secs(3)).await;
    // 5. Pending offers — decrypted names/ids must not linger.
    state.pending_file_offers.lock().await.clear();
    state.file_inbox.lock().await.clear();
    Ok(())
}
