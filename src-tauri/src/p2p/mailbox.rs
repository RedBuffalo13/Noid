//! Phase B: Mailbox protocol for offline message delivery through relay.
//!
//! Mailbox nodes store encrypted envelopes for offline recipients.
//! Messages are E2EE encrypted — mailbox nodes cannot decrypt content.

use anyhow::{anyhow, Result};
use libp2p::kad;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::p2p::node::P2PNode;
use crate::p2p::types::MailboxRequest;

impl P2PNode {
    pub(crate) fn mailbox_dht_key(peer_id: &str) -> kad::RecordKey {
        let prefix = format!("noid:mailbox:{}", peer_id);
        let mut hasher = Sha256::new();
        hasher.update(prefix.as_bytes());
        let key_hash = hasher.finalize();
        kad::RecordKey::new(&key_hash)
    }

    /// Phase B.3: Publish which node holds our mailbox in the DHT.
    /// Key is `noid:mailbox:<owner_peer_id>`; value is a `SignedMailboxRecord`
    /// signed by the owner's identity key — a malicious DHT peer cannot
    /// redirect someone else's envelopes to a hostile mailbox.
    /// Typically the mailbox peer is a relay we hold a reservation on.
    pub fn register_as_mailbox(&mut self, owner_peer_id: &str, mailbox_peer_id: &str, relay_addr: &str) -> Result<()> {
        let key = Self::mailbox_dht_key(owner_peer_id);

        // The record must be self-published: refuse to sign a record claiming
        // a different owner.
        if owner_peer_id != self.peer_id.to_string() {
            return Err(anyhow!("Mailbox record owner must be this node"));
        }
        let mut record = crate::p2p::types::SignedMailboxRecord {
            owner_peer_id: owner_peer_id.to_string(),
            mailbox_peer_id: mailbox_peer_id.to_string(),
            relay_addr: relay_addr.to_string(),
            signature: Vec::new(),
            published_at: Some(
                chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            ),
        };
        record.signature = crate::security::identity_sig::sign_payload(
            &self.identity_keypair,
            &crate::p2p::types::mailbox_record_signing_payload(&record),
        )?;
        let value = serde_json::to_vec(&record)?;
        if value.len() > crate::p2p::constants::MAX_DHT_RECORD_BYTES {
            return Err(anyhow!(
                "Mailbox record too large: {} bytes (max {})",
                value.len(),
                crate::p2p::constants::MAX_DHT_RECORD_BYTES
            ));
        }

        log::debug!("Registering mailbox node in DHT: owner={}, mailbox={}, relay={}", owner_peer_id, mailbox_peer_id, relay_addr);

        let mut record = kad::Record::new(key, value.clone());
        record.expires = Some(std::time::Instant::now() + std::time::Duration::from_secs(86400)); // 1 day
        // DHT-02: queue_dht_put tracks the query for retry AND parks the
        // record when Kademlia refuses synchronously (cold start, empty
        // routing table) — a failed publish used to leave the mailbox
        // record local-only until the next reservation renewal.
        self.queue_dht_put(record);

        // D21: our own mailbox record goes into the local fallback too —
        // while every DHT holder is down, self-lookup used to answer
        // "no mailbox" until the next renewal.
        self.local_dht_put(Self::mailbox_dht_key(owner_peer_id).to_vec(), value.clone());

        // D11: remember every mailbox we announced — envelopes parked on a
        // superseded node stay retrievable until their 7d expiry.
        self.mailbox_history
            .retain(|(p, _, ts)| p != mailbox_peer_id && ts.elapsed() < std::time::Duration::from_secs(7 * 86400));
        self.mailbox_history.push((
            mailbox_peer_id.to_string(),
            relay_addr.to_string(),
            std::time::Instant::now(),
        ));
        while self.mailbox_history.len() > 8 {
            self.mailbox_history.remove(0);
        }

        log::debug!("Mailbox node registered in DHT");
        Ok(())
    }

    /// Phase B.4: Send a message to a mailbox node for offline storage.
    /// The message is already E2EE encrypted by the caller; the envelope is
    /// additionally signed with our identity key so the mailbox can verify
    /// sender authenticity (the swarm peer must match sender_peer_id).
    /// `client_msg_id` tags the outbound request so the caller's pending row
    /// is only deleted once the mailbox's Ack arrives — a dial failure would
    /// otherwise lose the message silently.
    pub fn send_to_mailbox(
        &mut self,
        mailbox_peer_id: &str,
        recipient_peer_id: &str,
        sender_peer_id: &str,
        encrypted_content: Vec<u8>,
        client_msg_id: Option<String>,
    ) -> Result<()> {
        // The sender is always this node — refuse to spoof another identity.
        if sender_peer_id != self.peer_id.to_string() {
            return Err(anyhow!("Mailbox envelope sender must be this node"));
        }
        // A mailbox address pointing back at ourselves cannot be dialed —
        // a forged or stale record must not turn into a self-dial storm.
        if mailbox_peer_id == self.peer_id.to_string() {
            return Err(anyhow!("Refusing mailbox request to self"));
        }
        // Reject oversized envelopes client-side too — the mailbox would drop
        // the Store anyway, and the pending row would be stuck retrying a
        // message that can never succeed.
        if !crate::p2p::mailbox_guard::MailboxGuard::envelope_size_ok(&encrypted_content) {
            return Err(anyhow!(
                "Envelope too large: {} bytes (max {})",
                encrypted_content.len(),
                crate::p2p::mailbox_guard::MAX_ENVELOPE_BYTES
            ));
        }
        // The pending row key survives the request move below.
        let pending_msg_id = client_msg_id.clone();
        // F2: sign the v2 payload (covers the stable client_msg_id) when we
        // have one — legacy sends without an id keep the v1 payload.
        let signature = crate::security::identity_sig::sign_payload(
            &self.identity_keypair,
            &match &client_msg_id {
                Some(id) => crate::p2p::types::envelope_signing_payload_v2(
                    recipient_peer_id,
                    sender_peer_id,
                    id,
                    &encrypted_content,
                ),
                None => crate::p2p::types::envelope_signing_payload(
                    recipient_peer_id,
                    sender_peer_id,
                    &encrypted_content,
                ),
            },
        )?;
        let request = MailboxRequest::Store {
            recipient_peer_id: recipient_peer_id.to_string(),
            sender_peer_id: sender_peer_id.to_string(),
            encrypted_content,
            signature,
            client_msg_id,
        };

        let peer_id: libp2p::PeerId = mailbox_peer_id
            .parse()
            .map_err(|e| anyhow!("Invalid mailbox peer_id: {}", e))?;

        log::debug!("Sending message to mailbox node {} for recipient {}", mailbox_peer_id, recipient_peer_id);
        // A backed-off mailbox peer must not be redialed here — the internal
        // request-response dial bypasses P2PNode::dial. The pending row stays
        // and is retried after the window expires.
        if !self.connected_peers.contains(&peer_id) && self.dial_is_backed_off(&peer_id) {
            return Err(anyhow!("mailbox peer {} in dial backoff", mailbox_peer_id));
        }
        self.seed_peer_addrs(&peer_id);
        // DB31: bound in-flight mailbox sends — a retry storm must not
        // grow the map without bound; the row stays pending for next tick.
        if self.pending_mailbox_sends.len() >= 512 {
            return Err(anyhow!("pending mailbox sends full — retry later"));
        }
        let request_id = self.swarm
            .behaviour_mut()
            .mailbox
            .send_request(&peer_id, request);
        self.pending_mailbox_sends.insert(
            request_id.to_string(),
            (pending_msg_id, recipient_peer_id.to_string()),
        );

        Ok(())
    }

    /// Phase B.5: Retrieve messages from a mailbox node.
    pub fn retrieve_from_mailbox(&mut self, mailbox_peer_id: &str, recipient_peer_id: &str) -> Result<()> {
        // Dialing ourselves is pointless and noisy — a stale/forged record
        // naming us as our own mailbox must not trigger a self-dial.
        if mailbox_peer_id == self.peer_id.to_string() {
            return Err(anyhow!("Refusing mailbox request to self"));
        }
        let request = MailboxRequest::Retrieve {
            recipient_peer_id: recipient_peer_id.to_string(),
        };

        let peer_id: libp2p::PeerId = mailbox_peer_id
            .parse()
            .map_err(|e| anyhow!("Invalid mailbox peer_id: {}", e))?;

        log::debug!("Retrieving messages from mailbox node {} for recipient {}", mailbox_peer_id, recipient_peer_id);
        if !self.connected_peers.contains(&peer_id) && self.dial_is_backed_off(&peer_id) {
            return Err(anyhow!("mailbox peer {} in dial backoff", mailbox_peer_id));
        }
        self.seed_peer_addrs(&peer_id);
        self.swarm
            .behaviour_mut()
            .mailbox
            .send_request(&peer_id, request);

        Ok(())
    }

    /// Phase B.5: Acknowledge and delete a message from a mailbox node.
    pub fn ack_mailbox_message(&mut self, mailbox_peer_id: &str, message_id: &str) -> Result<()> {
        let request = MailboxRequest::Delete {
            message_id: message_id.to_string(),
        };

        let peer_id: libp2p::PeerId = mailbox_peer_id
            .parse()
            .map_err(|e| anyhow!("Invalid mailbox peer_id: {}", e))?;

        log::debug!("Acknowledging message {} at mailbox node {}", message_id, mailbox_peer_id);
        if !self.connected_peers.contains(&peer_id) && self.dial_is_backed_off(&peer_id) {
            return Err(anyhow!("mailbox peer {} in dial backoff", mailbox_peer_id));
        }
        self.seed_peer_addrs(&peer_id);
        self.swarm
            .behaviour_mut()
            .mailbox
            .send_request(&peer_id, request);

        Ok(())
    }

    /// Generate a unique message ID for mailbox storage.
    pub fn generate_mailbox_message_id() -> String {
        Uuid::new_v4().to_string()
    }

    /// Phase H.1: Find a mailbox node for a peer via DHT lookup.
    /// Result comes back as P2PEvent::MailboxNodeFound.
    pub fn find_mailbox_node(&mut self, peer_id: &str) -> libp2p::kad::QueryId {
        let key = Self::mailbox_dht_key(peer_id);
        log::debug!("Searching DHT for mailbox node of peer {}", peer_id);
        self.swarm
            .behaviour_mut()
            .kademlia
            .get_record(key)
    }
}
