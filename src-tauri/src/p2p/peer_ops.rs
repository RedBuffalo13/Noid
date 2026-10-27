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
