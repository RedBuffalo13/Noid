//! Phase A.3: DHT operations for prekey bundles.
//!
//! Publishes and fetches X3DH prekey bundles in the DHT.
//! Key: SHA256("noid:prekeys:" || peer_id) → PrekeyBundle (serde_json)

use anyhow::{anyhow, Result};
use libp2p::kad;
use sha2::{Digest, Sha256};

use crate::p2p::node::P2PNode;
use crate::security::PrekeyBundle;

impl P2PNode {
    pub(crate) fn prekey_dht_key(peer_id: &str) -> kad::RecordKey {
        let prefix = format!("noid:prekeys:{}", peer_id);
        let mut hasher = Sha256::new();
        hasher.update(prefix.as_bytes());
        let key_hash = hasher.finalize();
        kad::RecordKey::new(&key_hash)
    }

    /// Publish our prekey bundle to the DHT — signed with the identity key
    /// and bound to our peer id so DHT peers cannot substitute keys (MITM).
    pub fn publish_prekey_bundle(&mut self, peer_id: &str, bundle: &PrekeyBundle) -> Result<()> {
        let key = Self::prekey_dht_key(peer_id);

        let mut signed = bundle.clone();
        signed.owner_peer_id = Some(self.peer_id.to_string());
        signed.identity_signature = Some(crate::security::identity_sig::sign_payload(
            &self.identity_keypair,
            &crate::security::x3dh::prekey_signing_payload(&signed),
        )?);

        let value = serde_json::to_vec(&signed)?;

        log::debug!(
            "Publishing prekey bundle to DHT: peer_id={}, bundle_size={} bytes",
            peer_id, value.len()
        );

        if value.len() > crate::p2p::constants::MAX_DHT_RECORD_BYTES {
            return Err(anyhow!(
                "Prekey bundle too large for DHT: {} bytes (max {} bytes)",
                value.len(),
                crate::p2p::constants::MAX_DHT_RECORD_BYTES
            ));
        }

        let mut record = kad::Record::new(key.clone(), value.clone());
        record.expires = Some(std::time::Instant::now() + std::time::Duration::from_secs(86400 * 7)); // 7 days
        // DHT-02: local fallback BEFORE the network put — a cold-start
        // put_record that returns Err early (`?`) used to skip the local
        // store entirely and leave us without any bundle on this node.
        self.local_dht_put(key.to_vec(), value);
        // Tracked so a PutRecord failure can be retried — and DEFERRED when
        // Kademlia refuses synchronously (empty routing table at cold
        // start); a silent skip used to leave us unpublished forever.
        self.queue_dht_put(record);
        log::debug!("Prekey bundle published to DHT (and stored locally as fallback)");
        Ok(())
    }

    /// Fetch a peer's prekey bundle — direct request AND DHT query run in
    /// parallel; whichever answers first resolves the fetch.
    /// Result comes back via P2PEvent::PrekeyBundleRetrieved.
    pub fn fetch_prekey_bundle(&mut self, peer_id: &str) {
        // Single-flight across both paths: a pending flush with N messages
        // to the same peer would otherwise spawn N identical queries.
        if self
            .pending_prekey_queries
            .values()
            .any(|p| p == peer_id)
            || self
                .pending_prekey_requests
                .values()
                .any(|p| p == peer_id)
        {
            log::debug!("Prekey fetch already in-flight for {}, skipping", peer_id);
            return;
        }
        if self.prekey_recently_resolved(peer_id) {
            return;
        }

        // X3DH-07: ask the peer directly. request_response auto-dials from
        // the address books, so this also reaches a peer whose connection
        // exists but whose DHT presence is gone — the exact failure mode
        // behind an empty routing table ("No known peers").
        if let Ok(peer) = peer_id.parse::<libp2p::PeerId>() {
            let req = crate::p2p::types::NoidMessage {
                sender: self.peer_id.to_string(),
                content: String::new(),
                msg_type: crate::p2p::types::MessageType::PrekeyBundleRequest,
                timestamp: Some(chrono::Utc::now().to_rfc3339_opts(
                    chrono::SecondsFormat::Millis,
                    true,
                )),
                id: uuid::Uuid::new_v4().to_string(),
            };
            let req_id = self
                .swarm
                .behaviour_mut()
                .request_response
                .send_request(&peer, req);
            self.pending_prekey_requests
                .insert(req_id.to_string(), peer_id.to_string());
            log::debug!("Direct prekey bundle request sent to {}", peer_id);
        }

        let key = Self::prekey_dht_key(peer_id);
        log::debug!("Fetching prekey bundle from DHT for peer {}", peer_id);

        let query_id = self.swarm
            .behaviour_mut()
            .kademlia
            .get_record(key);
        self.pending_prekey_queries.insert(query_id, peer_id.to_string());
    }

    /// X3DH-07: a verified bundle for this peer was emitted within the
    /// dedup window — a second answer (the losing race path) is dropped.
    pub(crate) fn prekey_recently_resolved(&mut self, peer_id: &str) -> bool {
        const WINDOW: std::time::Duration = std::time::Duration::from_secs(60);
        self.prekey_resolved_at.retain(|_, t| t.elapsed() < WINDOW);
        self.prekey_resolved_at.contains_key(peer_id)
    }

    pub(crate) fn mark_prekey_resolved(&mut self, peer_id: &str) {
        self.prekey_resolved_at
            .insert(peer_id.to_string(), std::time::Instant::now());
    }

    /// Any direct request still in flight for this peer?
    pub(crate) fn prekey_direct_pending(&self, peer_id: &str) -> bool {
        self.pending_prekey_requests
            .values()
            .any(|p| p == peer_id)
    }

    /// Any DHT query still in flight for this peer?
    pub(crate) fn prekey_dht_pending(&self, peer_id: &str) -> bool {
        self.pending_prekey_queries
            .values()
            .any(|p| p == peer_id)
    }
}
