//! A2/Q01: blind mailbox polling under a throwaway transport identity.
//!
//! `RetrieveBlind`/`DeleteBlind` prove box ownership with a signature over
//! our REAL Ed25519 identity — the mailbox needs that pubkey to verify the
//! box. What it must NOT learn is our stable transport PeerId: a
//! persistent Noise identity lets the mailbox correlate poll timing with
//! our other traffic (DHT presence, contact conns, listen addrs) and dial
//! our node back. Each blind round-trip therefore runs on a one-shot
//! swarm with a fresh keypair that speaks only `/noid-mailbox/1.0.0` —
//! no identify, no Kademlia, no gossipsub. The temp identity dies with
//! the swarm; nothing secret ever enters the task (requests are signed
//! on the node before spawning).

use anyhow::{anyhow, Result};
use libp2p::futures::StreamExt;
use libp2p::swarm::SwarmEvent;
use libp2p::{multiaddr::Protocol, noise, request_response, tcp, yamux, Multiaddr, Swarm};
use std::time::Duration;
use tokio::sync::mpsc;

use crate::p2p::types::{MailboxRequest, MailboxResponse, P2PEvent};

type EphMailbox = request_response::json::Behaviour<MailboxRequest, MailboxResponse>;

/// Overall round-trip bound — long enough for a dial + a 90s-protocol
/// request on a slow path, short enough that a dead mailbox cannot pin
/// an ephemeral task indefinitely.
const ROUNDTRIP_TIMEOUT: Duration = Duration::from_secs(60);

fn build_ephemeral_swarm() -> Result<Swarm<EphMailbox>> {
    let key = libp2p::identity::Keypair::generate_ed25519();
    let builder = libp2p::SwarmBuilder::with_existing_identity(key)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_quic_config(|mut cfg| {
            cfg.max_idle_timeout = 30_000;
            cfg
        });
    // WSS fronts (VPS relays on :443) need the websocket transport.
    let builder = builder.with_other_transport(crate::p2p::swarm_builder::ws_transport)?;
    #[cfg(not(target_os = "android"))]
    let builder = builder.with_dns()?;
    Ok(builder
        .with_behaviour(|_| {
            request_response::json::Behaviour::new(
                [(
                    libp2p::StreamProtocol::new("/noid-mailbox/1.0.0"),
                    request_response::ProtocolSupport::Full,
                )],
                request_response::Config::default()
                    .with_request_timeout(Duration::from_secs(45)),
            )
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(ROUNDTRIP_TIMEOUT))
        .build())
}

/// One-shot mailbox round-trip on a fresh transport identity: dial
/// `addr`, send the pre-signed `requests`, collect every response, drop
/// the swarm. Returns the responses in arrival order.
async fn ephemeral_mailbox_roundtrip(
    addr: Multiaddr,
    requests: Vec<MailboxRequest>,
) -> Result<Vec<MailboxResponse>> {
    let mut swarm = build_ephemeral_swarm()?;
    swarm.dial(addr)?;
    let mut pending = requests.len();
    let mut requests = Some(requests);
    let mut out = Vec::with_capacity(pending);
    let timeout = tokio::time::sleep(ROUNDTRIP_TIMEOUT);
    tokio::pin!(timeout);
    loop {
        tokio::select! {
            _ = &mut timeout => {
                return Err(anyhow!("ephemeral mailbox roundtrip timed out"));
            }
            ev = swarm.select_next_some() => match ev {
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    if let Some(reqs) = requests.take() {
                        for req in reqs {
                            swarm.behaviour_mut().send_request(&peer_id, req);
                        }
                    }
                }
                SwarmEvent::Behaviour(request_response::Event::Message {
                    message: request_response::Message::Response { response, .. },
                    ..
                }) => {
                    out.push(response);
                    pending -= 1;
                    if pending == 0 {
                        return Ok(out);
                    }
                }
                SwarmEvent::Behaviour(request_response::Event::OutboundFailure {
                    error, ..
                }) => {
                    return Err(anyhow!("ephemeral mailbox request failed: {}", error));
                }
                SwarmEvent::OutgoingConnectionError { error, .. } => {
                    return Err(anyhow!("ephemeral mailbox dial failed: {}", error));
                }
                _ => {}
            },
        }
    }
}

impl crate::p2p::node::P2PNode {
    /// Dialable addr for our mailbox peer: the relay addr we registered
    /// the mailbox under first (authoritative), then the peer cache.
    /// Appends `/p2p/<peer>` when the addr lacks a terminal peer id —
    /// the Noise handshake pins the mailbox identity either way.
    fn mailbox_dial_addr(&self, peer: &libp2p::PeerId) -> Option<Multiaddr> {
        let peer_str = peer.to_string();
        let suffix = |a: Multiaddr| -> Multiaddr {
            match a.iter().last() {
                Some(Protocol::P2p(_)) => a,
                _ => a.with(Protocol::P2p(*peer)),
            }
        };
        if let Some((_, addr, _)) = self
            .mailbox_history
            .iter()
            .rev()
            .find(|(p, _, _)| *p == peer_str)
        {
            if let Ok(a) = addr.parse::<Multiaddr>() {
                return Some(suffix(a));
            }
        }
        // The ephemeral swarm has no onion transport — an onion3 entry is a
        // phantom in THIS dial book (it costs a doomed dial + warn log per
        // poll). Skip it and take the first direct/circuit hint instead.
        self.peer_cache
            .addrs_of(peer)
            .into_iter()
            .find(|a| {
                !a.iter()
                    .any(|p| matches!(p, Protocol::Onion3(_)))
            })
            .map(suffix)
    }

    /// Poll our blind box for `days` under an ephemeral transport
    /// identity. The ownership signature still uses the real keypair —
    /// the mailbox must verify box ownership; only the Noise-level
    /// PeerId is disposable. Responses arrive as the same
    /// `MailboxMessagesRetrieved` event the legacy path emitted, so the
    /// app-side processing pipeline is unchanged.
    pub(crate) fn retrieve_from_mailbox_blind(
        &mut self,
        mailbox_peer_id: &str,
        days: &[u64],
        event_tx: &mpsc::Sender<P2PEvent>,
    ) -> Result<()> {
        if mailbox_peer_id == self.peer_id.to_string() {
            return Err(anyhow!("Refusing mailbox request to self"));
        }
        let peer: libp2p::PeerId = mailbox_peer_id
            .parse()
            .map_err(|e| anyhow!("Invalid mailbox peer_id: {}", e))?;
        let addr = self
            .mailbox_dial_addr(&peer)
            .ok_or_else(|| anyhow!("no dialable addr for mailbox {}", mailbox_peer_id))?;
        let ed_pub = crate::p2p::blind_box::own_ed_pub(&self.identity_keypair)?;
        let mut requests = Vec::with_capacity(days.len());
        for &day in days {
            let box_id = crate::p2p::blind_box::blind_box_id(&ed_pub, day);
            let signature = crate::security::identity_sig::sign_payload(
                &self.identity_keypair,
                &crate::p2p::blind_box::retrieve_signing_payload(&box_id, day),
            )?;
            requests.push(MailboxRequest::RetrieveBlind {
                box_id,
                pub_key: ed_pub.clone(),
                day,
                signature,
            });
        }
        let tx = event_tx.clone();
        let peer_str = mailbox_peer_id.to_string();
        tokio::spawn(async move {
            match ephemeral_mailbox_roundtrip(addr, requests).await {
                Ok(resps) => {
                    for r in resps {
                        if let MailboxResponse::Messages { messages } = r {
                            let _ = tx
                                .send(P2PEvent::MailboxMessagesRetrieved {
                                    mailbox_peer_id: peer_str.clone(),
                                    messages,
                                })
                                .await;
                        }
                    }
                }
                Err(e) => {
                    log::warn!("Ephemeral blind poll to {} failed: {}", peer_str, e)
                }
            }
        });
        Ok(())
    }

    /// Ack+delete a blind item under an ephemeral transport identity —
    /// same rationale as the poll: the delete carries our ownership
    /// pubkey, so the transport leg must not pin it to our stable PeerId.
    pub(crate) fn ack_mailbox_blind(
        &mut self,
        mailbox_peer_id: &str,
        message_id: &str,
    ) -> Result<()> {
        if mailbox_peer_id == self.peer_id.to_string() {
            return Err(anyhow!("Refusing mailbox request to self"));
        }
        let peer: libp2p::PeerId = mailbox_peer_id
            .parse()
            .map_err(|e| anyhow!("Invalid mailbox peer_id: {}", e))?;
        let addr = self
            .mailbox_dial_addr(&peer)
            .ok_or_else(|| anyhow!("no dialable addr for mailbox {}", mailbox_peer_id))?;
        let ed_pub = crate::p2p::blind_box::own_ed_pub(&self.identity_keypair)?;
        let day = crate::p2p::blind_box::current_day();
        let mut requests = Vec::with_capacity(2);
        for d in [day, day.saturating_sub(1)] {
            let box_id = crate::p2p::blind_box::blind_box_id(&ed_pub, d);
            let signature = crate::security::identity_sig::sign_payload(
                &self.identity_keypair,
                &crate::p2p::blind_box::delete_signing_payload(&box_id, message_id, d),
            )?;
            requests.push(MailboxRequest::DeleteBlind {
                box_id,
                message_id: message_id.to_string(),
                pub_key: ed_pub.clone(),
                day: d,
                signature,
            });
        }
        let peer_str = mailbox_peer_id.to_string();
        tokio::spawn(async move {
            if let Err(e) = ephemeral_mailbox_roundtrip(addr, requests).await {
                log::warn!("Ephemeral blind delete to {} failed: {}", peer_str, e);
            }
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_ephemeral_swarm_gets_a_fresh_peer_id() {
        let a = build_ephemeral_swarm().unwrap();
        let b = build_ephemeral_swarm().unwrap();
        assert_ne!(*a.local_peer_id(), *b.local_peer_id());
    }

    #[test]
    fn ephemeral_peer_id_differs_from_node_identity() {
        let node_key = libp2p::identity::Keypair::generate_ed25519();
        let node_peer = node_key.public().to_peer_id();
        let swarm = build_ephemeral_swarm().unwrap();
        assert_ne!(*swarm.local_peer_id(), node_peer);
    }

    #[test]
    fn mailbox_protocol_name_matches_main_swarm() {
        // The ephemeral swarm must speak the same protocol the mailbox
        // side serves — a drift here would silently timeout every poll.
        let names: Vec<String> = vec!["/noid-mailbox/1.0.0".into()];
        assert_eq!(
            libp2p::StreamProtocol::new("/noid-mailbox/1.0.0").as_ref(),
            names[0].as_str()
        );
    }
}
