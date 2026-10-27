use anyhow::{anyhow, Result};
use libp2p::kad;
use sha2::{Digest, Sha256};

use crate::p2p::node::P2PNode;
use crate::p2p::types::DHTUserRecord;

pub struct DHTUsernameKey;

impl DHTUsernameKey {
    pub fn compute(username: &str) -> Vec<u8> {
        let prefix = format!("noid:username:{}", username);
        let mut hasher = Sha256::new();
        hasher.update(prefix.as_bytes());
        hasher.finalize().to_vec()
    }
}

impl P2PNode {
    fn username_dht_key(username: &str) -> kad::RecordKey {
        let prefix = format!("noid:username:{}", username);
        let mut hasher = Sha256::new();
        hasher.update(prefix.as_bytes());
        let key_hash = hasher.finalize();
        kad::RecordKey::new(&key_hash)
    }

    pub fn publish_username(&mut self, username: &str, record: &DHTUserRecord) -> Result<()> {
        let key = Self::username_dht_key(username);

        // Sign the record with our identity key, bound to our peer id AND
        // the username key — DHT peers can then detect forged or replayed
        // (signed-for-another-name) claims.
        let mut signed = record.clone();
        signed.peer_id = self.peer_id.to_string();
        signed.username = username.to_string();
        signed.signature = Some(crate::security::identity_sig::sign_payload(
            &self.identity_keypair,
            &crate::p2p::types::user_record_signing_payload(&signed),
        )?);

        // The avatar (base64 image, often tens of KB) pushed the record past
        // kad's 16KiB PUT_VALUE packet cap — such records can never reach a
        // remote holder. Publish an avatar-less variant to the DHT and keep
        // the full record for the local fallback + UsernameAnnounce gossip.
        // The signature covers whatever record rides along, so the stripped
        // variant is signed on its own bytes (avatar absent from payload).
        let mut dht_rec = signed.clone();
        dht_rec.avatar = None;
        dht_rec.signature = Some(crate::security::identity_sig::sign_payload(
            &self.identity_keypair,
            &crate::p2p::types::user_record_signing_payload(&dht_rec),
        )?);
        let value = serde_json::to_vec(&dht_rec)?;

        log::debug!(
            "Publishing username '{}' to DHT: peer_id={}, nickname={}, short_id={}, record_size={} bytes",
            username, record.peer_id, record.nickname, record.short_id, value.len()
        );

        if value.len() > crate::p2p::constants::MAX_DHT_RECORD_BYTES {
            return Err(anyhow!(
                "Username record too large for DHT: {} bytes (max {} bytes)",
                value.len(),
                crate::p2p::constants::MAX_DHT_RECORD_BYTES
            ));
        }

        // D14: get-before-put — a blind publish makes the name last-writer-
        // wins and flaps forever between legitimate owners. Gate the put on
        // a lookup: commit only when no fresher valid record owned by
        // another peer exists (handled on query resolution in event_loop).
        if self.swarm.connected_peers().next().is_some() {
            let query_id = self
                .swarm
                .behaviour_mut()
                .kademlia
                .get_record(key.clone());
            self.pending_username_publishes
                .insert(query_id, (username.to_string(), value, signed));
            return Ok(());
        }
        // No peers to ask — nothing to conflict with; commit directly.
        self.commit_username_publish(username, value, signed)
    }

    /// D14: the actual put — reached only after the availability gate
    /// cleared (no record / our own record / forged or stale record).
    pub(crate) fn commit_username_publish(
        &mut self,
        username: &str,
        value: Vec<u8>,
        signed: DHTUserRecord,
    ) -> Result<()> {
        let key = Self::username_dht_key(username);
        let mut record = kad::Record::new(key.clone(), value.clone());
        record.expires = Some(std::time::Instant::now() + std::time::Duration::from_secs(86400));
        // DHT-02: queue_dht_put tracks the query AND defers the record on a
        // synchronous cold-start refusal — the `?` used to abort the whole
        // publish and skip the local fallback.
        self.queue_dht_put(record);

        // Also store locally as fallback (public IPFS nodes may reject PutRecord)
        self.local_dht_put(key.to_vec(), value);
        // Keep the SIGNED record for UsernameAnnounce gossip to new peers.
        self.my_username = Some((username.to_string(), signed));
        log::debug!("Username '{}' published in DHT (and stored locally as fallback)", username);
        Ok(())
    }

    /// D14: resolve a publish gate query. `existing` is the raw record the
    /// DHT returned; `None` means NotFound. Returns `true` when the put may
    /// proceed. An inconclusive query (timeout, empty table) is a refusal —
    /// we cannot tell a free name from a silenced conflict.
    pub(crate) fn username_publish_allowed(
        &self,
        username: &str,
        our_value: &[u8],
        existing: Option<&kad::PeerRecord>,
    ) -> bool {
        let Some(peer_record) = existing else {
            return true;
        };
        let Ok(stored) = serde_json::from_slice::<DHTUserRecord>(&peer_record.record.value) else {
            return true; // garbage under the key — overwrite it
        };
        let sig_ok = stored
            .signature
            .as_ref()
            .map(|sig| {
                crate::security::identity_sig::verify_payload(
                    &stored.peer_id,
                    &crate::p2p::types::user_record_signing_payload(&stored),
                    sig,
                )
            })
            .unwrap_or(false)
            && stored.username == username
            && !stored.revoked;
        if !sig_ok {
            return true; // forged/foreign record — overwrite it
        }
        if stored.peer_id == self.peer_id.to_string() {
            return true; // our own record — refresh it
        }
        // Valid record owned by someone else: only overwrite when ours is
        // strictly fresher — otherwise the two owners flap forever.
        
        serde_json::from_slice::<DHTUserRecord>(our_value)
            .map(|ours| {
                let new_ts = chrono::DateTime::parse_from_rfc3339(&ours.updated_at).ok();
                let old_ts = chrono::DateTime::parse_from_rfc3339(&stored.updated_at).ok();
                match (new_ts, old_ts) {
                    (Some(n), Some(o)) => n > o,
                    _ => false,
                }
            })
            .unwrap_or(false)
    }

    pub fn check_username_availability(&mut self, username: &str) {
        let key = Self::username_dht_key(username);
        log::debug!("Checking DHT availability for username '{}'", username);

        // Check local store first
        if let Some(value) = self.local_dht_get(&key.to_vec()) {
            if let Ok(_user_record) = serde_json::from_slice::<DHTUserRecord>(&value) {
                log::debug!("Found username '{}' in local DHT store", username);
            }
        }

        let query_id = self.swarm
            .behaviour_mut()
            .kademlia
            .get_record(key);
        self.pending_availability_queries
            .insert(query_id, username.to_string());
    }

    pub fn lookup_user(&mut self, username: &str) {
        let key = Self::username_dht_key(username);
        log::debug!("Looking up user '{}' in DHT", username);

        // Check local store first — maybe we've seen this user via mDNS/Identify
        if let Some(value) = self.local_dht_get(&key.to_vec()) {
            if let Ok(user_record) = serde_json::from_slice::<DHTUserRecord>(&value) {
                log::debug!("Found user '{}' in local DHT store (peer_id={})", username, user_record.peer_id);
                let _ = user_record;
            }
        }

        let query_id = self.swarm
            .behaviour_mut()
            .kademlia
            .get_record(key);
        self.pending_lookups.insert(query_id, username.to_string());
    }

    pub fn unpublish_username(&mut self, username: &str) -> Result<()> {
        let key = Self::username_dht_key(username);
        log::debug!("Removing username '{}' from DHT", username);
        self.swarm
            .behaviour_mut()
            .kademlia
            .remove_record(&key);
        // The local fallback copy and the gossip announcement must go too —
        // otherwise the old name keeps resolving (local store is consulted
        // on lookup) and keeps being announced to every new peer.
        self.local_dht_records.remove(&key.to_vec());
        self.local_dht_records_ts.remove(&key.to_vec());
        // D13: remove_record does not propagate — remote holders keep the
        // record alive until expiry and the name stays unregistrable.
        // Publish a signed tombstone instead: readers treat it as free.
        let mut tombstone = DHTUserRecord {
            peer_id: self.peer_id.to_string(),
            username: username.to_string(),
            nickname: String::new(),
            avatar: None,
            short_id: String::new(),
            updated_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            signature: None,
            revoked: true,
        };
        tombstone.signature = Some(crate::security::identity_sig::sign_payload(
            &self.identity_keypair,
            &crate::p2p::types::user_record_signing_payload(&tombstone),
        )?);
        if let Ok(value) = serde_json::to_vec(&tombstone) {
            if value.len() <= crate::p2p::constants::MAX_DHT_RECORD_BYTES {
                let mut record = kad::Record::new(key.clone(), value.clone());
                record.expires =
                    Some(std::time::Instant::now() + std::time::Duration::from_secs(86400));
                // DHT-02: tombstone must reach the DHT even when the
                // routing table is empty — defer instead of dropping.
                self.queue_dht_put(record);
                self.local_dht_put(key.to_vec(), value);
            }
        }
        if self
            .my_username
            .as_ref()
            .map(|(u, _)| u == username)
            .unwrap_or(false)
        {
            self.my_username = None;
        }
        log::debug!("Username '{}' removed from DHT and local store", username);
        Ok(())
    }
}
