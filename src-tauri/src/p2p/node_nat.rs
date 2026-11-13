//! NAT-PMP/STUN probe phase of node build — extracted from node.rs (Q05/A5b). Bodies moved verbatim.

use libp2p::{kad, Multiaddr, Swarm};

use crate::p2p::behaviour::NoidBehaviour;
use crate::p2p::relay_config::RelayConfig;

/// NAT-PMP lease + STUN mapping probes — extracted verbatim from
/// with_config. Returns (nat_pmp_public, stun_mapping) feeding NatStatus.
/// Off unless Direct privacy with no outbound proxy (SEC-1111-03: both
/// broadcast our real IP).
pub(crate) async fn nat_probe(
    swarm: &mut Swarm<NoidBehaviour>,
    external_addrs: &mut Vec<Multiaddr>,
    relay_config: &RelayConfig,
    direct_net_ok: bool,
    bound: bool,
    port: u16,
    evidence: &mut crate::p2p::addr_evidence::EvidenceLedger,
) -> (bool, Option<libp2p_quic::stun_hook::StunMapping>) {
        let quic_port = libp2p_quic::stun_hook::observed_stun_mapping()
            .map(|m| m.local_port)
            .unwrap_or(if bound { port } else { 0 });
        let nat_pmp_lease = if direct_net_ok && quic_port != 0 {
            tokio::task::spawn_blocking(move || {
                crate::p2p::nat_pmp::probe_lan_nat_pmp(quic_port, quic_port)
            })
            .await
            .ok()
            .flatten()
        } else {
            None
        };
        // The lease's external IP must match STUN's observed IP — otherwise
        // the ISP double-NATs above the router and the mapping is reachable
        // only inside the ISP's inner network, not from the WAN.
        let nat_pmp_public = nat_pmp_lease
            .as_ref()
            .map(crate::p2p::nat_pmp::lease_confirms_public)
            .unwrap_or(false);
        if let Some(ref lease) = nat_pmp_lease {
            for addr in lease.to_multiaddrs() {
                log::info!(
                    "NAT-PMP lease via gateway {} → external {}{}",
                    lease.gateway, addr,
                    if nat_pmp_public { "" } else { " (double-NAT — candidate only)" }
                );
                swarm.add_external_address(addr.clone());
                external_addrs.push(addr);
            }
            if nat_pmp_public {
                swarm
                    .behaviour_mut()
                    .kademlia
                    .set_mode(Some(kad::Mode::Server));
                // The lease's external IP matched STUN — real public
                // reachability evidence for each mapped addr.
                for addr in lease.to_multiaddrs() {
                    evidence.mark(
                        &addr.to_string(),
                        crate::p2p::addr_evidence::EvidenceState::Verified,
                        crate::p2p::addr_evidence::EvidenceSource::NatPmp,
                    );
                }
            }
        }

        // STUN: the QUIC listener hook already probed during listen_on, so
        // the observed external mapping is usually populated here. The
        // mapped addr is a dial candidate for hole-punching invites —
        // registered as external WITHOUT claiming Public (AutoNAT dial-back
        // remains the arbiter of confirmed reachability).
        let stun_mapping = if direct_net_ok {
            crate::p2p::stun_keepalive::current_or_probe_mapping(quic_port)
        } else {
            None
        };
        if let Some(ref mapping) = stun_mapping {
            let addr = crate::p2p::stun_keepalive::mapping_to_quic_multiaddr(mapping);
            log::info!("STUN external mapping {:?}: {}", mapping.nat_kind, addr);
            // A mapping proves egress translation exists — not that inbound
            // filtering lets packets through. Candidate, never Verified;
            // under address/port-dependent filtering even the candidate
            // claim is weak (a cold peer cannot punch in blind).
            use libp2p_quic::stun_hook::StunFilterKind as F;
            match mapping.filter {
                F::AddressDependent | F::PortDependent => evidence.mark_failed_if_unverified(
                    &addr.to_string(),
                    crate::p2p::addr_evidence::EvidenceSource::StunMap,
                ),
                _ => evidence.mark(
                    &addr.to_string(),
                    crate::p2p::addr_evidence::EvidenceState::Candidate,
                    crate::p2p::addr_evidence::EvidenceSource::StunMap,
                ),
            }
            if !external_addrs.contains(&addr)
                && relay_config.privacy == crate::p2p::relay_config::PrivacyMode::Direct
            {
                swarm.add_external_address(addr.clone());
                external_addrs.push(addr);
            }
        }

    (nat_pmp_public, stun_mapping)
}
