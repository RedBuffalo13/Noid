use crate::commands::request_relay_status::request_relay_status;
use crate::p2p::{invite, PrivacyMode};
use crate::AppState;
use tauri::State;

/// Build this node's invite string for out-of-band sharing.
///
/// - `direct` privacy: bundles peer id + external addrs + relayed addrs.
/// - `relayed_only` privacy: only `/p2p-circuit` addrs — the invite must not
///   leak our direct/external addresses.
/// With no reachable addrs the invite is a bare `noid:<peerId>` (usable only
/// via LAN/DHT).
#[tauri::command]
pub async fn get_my_invite(state: State<'_, AppState>) -> Result<String, String> {
    let my_id = state.my_id.lock().await.clone();
    let peer = my_id
        .parse::<libp2p::PeerId>()
        .map_err(|_| "Node not initialized".to_string())?;

    // Live snapshot from the event loop — the cached state can lag by a
    // heartbeat tick, which is what produced bare invites at cold start.
    let status = request_relay_status(state.inner()).await;
    let (privacy, role) = {
        let cfg = state.relay_config.lock().await;
        (cfg.privacy, cfg.role)
    };

    let mut addrs = if privacy == PrivacyMode::RelayedOnly {
        let mut a = status.relayed_addrs;
        // A public relay's service address must be shareable — that is how
        // clients reach it. This never leaks a client node's direct addrs.
        // First-node case: with zero relays in the network there is nothing
        // to reserve on — without the external/STUN fallback the invite is a
        // bare PeerId nobody can dial, so the user-chosen invite carries the
        // dial candidates instead.
        if role == crate::p2p::NodeRole::Relay || a.is_empty() {
            a.extend(status.external_addrs);
        }
        a
    } else {
        let mut a = status.external_addrs;
        a.extend(status.relayed_addrs);
        a
    };
    // tor_only: direct/STUN hints never belong in the invite — the only
    // reachable path is our onion service. An onion hint is ALWAYS allowed
    // (it's a hint, not a promise of reachability).
    let tor_status = state.tor.status();
    let tor_only = tor_status.desired_mode == crate::p2p::tor::mode::TorMode::TorOnly;
    if let Some(onion) = &tor_status.onion_address {
        let host = onion.strip_suffix(".onion").unwrap_or(onion);
        let onion_addr = format!(
            "/onion3/{}:{}/p2p/{}",
            host,
            crate::p2p::tor::onion_addr::ONION_VPORT,
            peer
        );
        if !addrs.contains(&onion_addr) {
            addrs.push(onion_addr);
        }
    }
    // The STUN-mapped QUIC addr is a hole-punch dial candidate even while
    // AutoNAT is still unsure — a user-shared invite may carry it when the
    // list would otherwise be bare (Direct mode already has it via
    // external_addrs). Never in tor_only.
    if !tor_only {
        if let Some(ref stun) = status.stun_addr {
            if (privacy == PrivacyMode::Direct || addrs.is_empty()) && !addrs.contains(stun) {
                addrs.push(stun.clone());
            }
        }
    }
    // An invite is consumed by remote peers — loopback transports and
    // loopback-prefix circuits (reservations minted over the relay's
    // loopback listener) can only ever reach this host. Publishing them
    // poisons every address book that trusts the invite.
    let shareable: Vec<String> = addrs
        .iter()
        .filter(|a| {
            a.parse::<libp2p::Multiaddr>()
                .map(|m| {
                    matches!(
                        crate::p2p::classify_peer_addr::classify_peer_addr(&m, &peer),
                        crate::p2p::addr_class::AddrClass::PublicDirect
                            | crate::p2p::addr_class::AddrClass::Circuit
                            | crate::p2p::addr_class::AddrClass::Lan
                            | crate::p2p::addr_class::AddrClass::Onion3
                    )
                })
                .unwrap_or(false)
        })
        .cloned()
        .collect();
    Ok(invite::build_invite(&peer, &shareable))
}
