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
    // reachable path is our onion service. RV-05: the onion hint ships
    // ONLY when `publish_state == Published` — `is_fully_reachable` alone
    // left invites carrying onion addrs whose HSDir descriptor wasn't up
    // yet (the cold-dial timeouts seen in the thousandth-user test); the
    // self-connect probe is the real publication proof.
    let tor_status = state.tor.status();
    let tor_only = tor_status.desired_mode == crate::p2p::tor::mode::TorMode::TorOnly;
    let onion_published = tor_status.publish_state
        == crate::p2p::tor::status::PublishState::Published;
    if onion_published {
        if let Some(onion) = &tor_status.onion_address {
            let host = onion.strip_suffix(".onion").unwrap_or(onion);
            let onion_addr = format!(
                "/onion3/{}:{}/p2p/{}",
                host,
                crate::p2p::tor::onion_addr::ONION_VPORT,
                peer
            );
            if !addrs.contains(&onion_addr) {
                addrs.insert(0, onion_addr);
            }
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
    // RV-04: verified paths lead the dial plan — the hint cap then keeps
    // proven addrs and pushes unproven ones out of the top slots (they
    // remain valid fallbacks, just later/absent from the string).
    let shareable =
        crate::p2p::rank_invite_addrs::rank_invite_addrs(shareable, &peer, &status.addr_evidence);
    let mut out = invite::build_invite(&peer, &shareable);
    // SEC-1111-03: every invite carries a one-time rendezvous secret — the
    // node polls `H(rv)` for inbound announcers, so our public PeerId never
    // names a Mainline-DHT slot and a burned invite cannot be replayed to
    // find us later. The secret is REUSED for 20 minutes: the UI re-reads
    // the invite on every relay-status tick, and a fresh secret each read
    // invalidated the one just copied (and made the displayed invite flap).
    let secret = {
        let mut slot = state.invite_rv.lock().await;
        match slot.as_ref() {
            Some((s, ts)) if ts.elapsed() < std::time::Duration::from_secs(1200) => {
                s.clone()
            }
            _ => {
                let s = crate::p2p::direct_net_policy::fresh_rv_secret();
                *slot = Some((s.clone(), std::time::Instant::now()));
                s
            }
        }
    };
    if let Some(tx) = state.p2p() {
        let _ = crate::send_p2p_cmd(
            &tx,
            crate::p2p::P2PCommand::SetRendezvousSecret {
                secret: secret.clone(),
            },
        )
        .await;
    }
    out.push_str("?rv=");
    out.push_str(&secret);
    Ok(out)
}
