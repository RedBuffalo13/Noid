//! Direct listener binding phase of node build — extracted from node.rs (Q05/A5b). Bodies moved verbatim.

use anyhow::Result;
use libp2p::{Multiaddr, Swarm};

use crate::p2p::behaviour::NoidBehaviour;
use crate::p2p::relay_config::{NodeRole, RelayConfig};


/// Bind direct listeners by role — extracted verbatim from with_config:
/// fixed port for Auto/Relay (UPnP mapping stability, ephemeral fallback),
/// ephemeral for Client, nothing when !direct_net_ok (tor_only/proxy).
pub(crate) fn bind_direct_listeners(
    swarm: &mut Swarm<NoidBehaviour>,
    relay_config: &RelayConfig,
    direct_net_ok: bool,
) -> Result<(bool, u16)> {
        // Listen strategy by role:
        // - Client: ephemeral ports only (never relay, no need for stable port).
        // - Auto/Relay: fixed port so UPnP mappings and advertised addrs stay
        //   stable across restarts; fall back to ephemeral on conflict
        //   (e.g. two instances on one machine).
        // tor_only: the swarm has NO direct transports — every ip4/ip6
        // listen_on below would error out ("Multiaddr is not supported")
        // and take the whole node build down in a retry loop.
        let wants_fixed_port = direct_net_ok
            && relay_config.role != NodeRole::Client
            && relay_config.listen_port != 0;
        if relay_config.role == NodeRole::Relay && !direct_net_ok {
            log::warn!(
                "NodeRole::Relay with direct networking disabled — no public listeners bound; \
                 set privacy=direct (and no proxy) to actually relay traffic"
            );
        }
        let port = relay_config.listen_port;
        let mut bound = false;
        if wants_fixed_port {
            // TCP and WS must NOT share a port: both listeners bind with
            // SO_REUSEPORT, so the kernel hashes each inbound connection to
            // one of them. A plain-TCP dial landing on the WS socket stalls
            // during negotiation — and a dialer reusing its listen port hits
            // the same listener every time.
            let ws_port = port.checked_add(1).unwrap_or(0);
            bound = swarm
                .listen_on(format!("/ip4/0.0.0.0/tcp/{port}").parse()?)
                .is_ok()
                && swarm
                    .listen_on(format!("/ip4/0.0.0.0/tcp/{ws_port}/ws").parse()?)
                    .is_ok();
            if !bound {
                log::warn!("Port {} unavailable, falling back to ephemeral", port);
            }
        }
        if direct_net_ok {
            if !bound {
                swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;
                swarm.listen_on("/ip4/0.0.0.0/tcp/0/ws".parse()?)?;
            }
            // QUIC listener on the same numeric port — UDP and TCP port
            // namespaces are independent, so no clash. Best-effort: losing
            // the QUIC listener must not take down TCP.
            let quic_spec = format!(
                "/ip4/0.0.0.0/udp/{}/quic-v1",
                if bound { port } else { 0 }
            );
            match quic_spec.parse::<Multiaddr>() {
                Ok(m) => {
                    if let Err(e) = swarm.listen_on(m) {
                        // UDP should bind essentially always — a failure
                        // silently cuts hole-punch odds (DCUtR prefers QUIC).
                        log::warn!("QUIC listener {} unavailable: {}", quic_spec, e);
                    }
                }
                Err(e) => log::warn!("Bad QUIC listen spec {}: {}", quic_spec, e),
            }
            // IPv6 listeners — mobile carriers frequently hand out globally
            // routable v6 even where v4 sits behind CGNAT. A bound v6 listener
            // is what lets AutoNAT prove public reachability and an Auto node
            // (incl. Android) become a real relay. Best-effort: hosts/networks
            // without IPv6 simply skip these (sockets are IPV6_V6ONLY, so no
            // dual-stack port clash with the ip4 binds above).
            for spec in [
                format!("/ip6/::/tcp/{}", if bound { port } else { 0 }),
                format!(
                    "/ip6/::/tcp/{}/ws",
                    if bound { port.checked_add(1).unwrap_or(0) } else { 0 }
                ),
                format!("/ip6/::/udp/{}/quic-v1", if bound { port } else { 0 }),
            ] {
                match spec.parse::<Multiaddr>() {
                    Ok(m) => {
                        if let Err(e) = swarm.listen_on(m) {
                            log::debug!("IPv6 listener {} unavailable: {}", spec, e);
                        }
                    }
                    Err(e) => log::debug!("Bad IPv6 listen spec {}: {}", spec, e),
                }
            }
        }

        log::debug!(
            "Relay server capability enabled (circuit relay v2, role={:?}, port={})",
            relay_config.role,
            if bound { port } else { 0 }
        );

    Ok((bound, port))
}
