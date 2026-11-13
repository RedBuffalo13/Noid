use libp2p::PeerId;
use tokio::sync::mpsc;
use crate::p2p::node::P2PNode;
use crate::p2p::types::{NoidMessage, P2PEvent};

impl P2PNode {
    /// Send a request-response message. When the peer is not connected and
    /// sits inside a dial-backoff window, the request is NOT issued — the
    /// behaviour would trigger another doomed dial (the storm this backoff
    /// exists to prevent). Instead a synthetic `MessageFailed` is emitted so
    /// the forwarder routes the message into pending/mailbox delivery.
    pub async fn send_request(
        &mut self,
        peer_id: PeerId,
        mut msg: NoidMessage,
        event_tx: &mpsc::Sender<P2PEvent>,
    ) {
        // S21: stamp the identity signature on X3DHInit here — the keypair
        // lives in the node, not in the app layer that builds the message.
        if let crate::p2p::types::MessageType::X3DHInit {
            identity_public,
            ephemeral_public,
            identity_signature,
            ..
        } = &mut msg.msg_type
        {
            if identity_signature.is_empty() {
                let payload = crate::p2p::types::x3dh_init_signing_payload(
                    identity_public,
                    ephemeral_public,
                );
                if let Ok(sig) =
                    crate::security::identity_sig::sign_payload(&self.identity_keypair, &payload)
                {
                    *identity_signature = sig;
                }
            }
        }
        if !self.connected_peers.contains(&peer_id) {
            if self.dial_is_backed_off(&peer_id) {
                let _ = event_tx
                    .send(P2PEvent::MessageFailed {
                        to: peer_id.to_string(),
                        request_id: String::new(),
                        error: "peer unreachable (dial backoff)".to_string(),
                        content: msg.content.clone(),
                        message_id: msg.id.clone(),
                        msg_type: msg.msg_type.clone(),
                    })
                    .await;
                return;
            }
            // The request-response dial resolves addresses through the swarm's
            // behaviour chain — Kademlia may have none after a cold start, so
            // feed every valid cached addr for this peer first. Without this a
            // send to an online-but-not-yet-connected peer fails instantly.
            self.seed_peer_addrs(&peer_id);
        }
        // B-1: a message without an id cannot be matched to its durable
        // pending row on failure ("no pending row" warn + silent loss).
        // Normalize here so every outbound wire message carries an id
        // the re-pend path can look up.
        let mut msg = msg;
        if msg.id.is_empty() {
            msg.id = uuid::Uuid::new_v4().to_string();
        }
        // META-05: a pinned 2-hop chain routes the request through
        // [entry → exit]: entry learns only the exit, exit learns only
        // the destination — neither sees both endpoints. The frame is
        // also inside a second Noise leg, so relays cannot correlate by
        // reading transport plaintext.
        if self.relay_config.hop_relays.len() >= 2
            && !self.relay_config.hop_relays.contains(&peer_id.to_string())
        {
            match serde_json::to_vec(&msg).map_err(|e| e.to_string()).and_then(|inner| {
                crate::p2p::hop::wrap(
                    &peer_id.to_string(),
                    &self.relay_config.hop_relays,
                    crate::p2p::hop::PROTO_NOID,
                    inner,
                )
            }) {
                Ok(frame) => {
                    // Entry may be given as a multiaddr (`/ip4/…/p2p/<id>`)
                    // or a bare PeerId — register the addr so the dial
                    // book resolves it, or seed the known peer.
                    let entry_str = self.relay_config.hop_relays[0].clone();
                    let entry = if let Ok(addr) = entry_str.parse::<libp2p::Multiaddr>() {
                        let pid = addr.iter().find_map(|p| match p {
                            libp2p::multiaddr::Protocol::P2p(id) => Some(id),
                            _ => None,
                        });
                        if let Some(id) = pid {
                            self.register_peer_addr(id, addr, "hop_relay", true);
                        }
                        pid
                    } else {
                        entry_str.parse::<PeerId>().ok()
                    };
                    if let Some(entry) = entry {
                        self.seed_peer_addrs(&entry);
                        let request_id = self
                            .swarm
                            .behaviour_mut()
                            .hop
                            .send_request(&entry, frame);
                        self.pending_messages
                            .insert(request_id.to_string(), msg);
                        self.hop_outbound_dest
                            .insert(request_id.to_string(), peer_id.to_string());
                        return;
                    }
                    log::warn!("Hop relay entry unparsable — falling back to direct send");
                }
                Err(e) => log::warn!("Hop wrap failed ({}) — falling back to direct send", e),
            }
        }
        let request_id = self.swarm
            .behaviour_mut()
            .request_response
            .send_request(&peer_id, msg.clone());

        self.pending_messages.insert(request_id.to_string(), msg);
    }

    pub async fn send_public_key(&mut self, peer_id: PeerId, event_tx: &mpsc::Sender<P2PEvent>) -> anyhow::Result<()> {
        let public_key = self.dht_cipher.get_public_key_bytes();

        let msg = NoidMessage {
            sender: self.peer_id.to_string(),
            content: "public_key_exchange".to_string(),
            msg_type: crate::p2p::types::MessageType::PublicKeyExchange { public_key },
            timestamp: Some(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
            id: uuid::Uuid::new_v4().to_string(),
        };

        self.send_request(peer_id, msg, event_tx).await;
        log::debug!("Sent public key to peer {}", peer_id);
        Ok(())
    }

}
