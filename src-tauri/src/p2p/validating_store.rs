//! D15: validating Kademlia record store.
//!
//! `MemoryStore` overwrites any key unconditionally — a hostile peer could
//! `PUT_VALUE` garbage over someone's `noid:username:*` / `noid:prekeys:*` /
//! `noid:mailbox:*` record and the signature check on the reader side merely
//! turned that into "not found" (a silent takeover/DoS). This wrapper keeps
//! the in-memory store but accepts a record only when its value carries a
//! schema-recognizable noid record whose embedded owner field recomputes to
//! the record key AND whose signature verifies.
//!
//! Non-noid values (provider records use `add_provider`, not `put`) and
//! unsigned/forged/foreign-key records are refused.

use libp2p::kad::store::{MemoryStore, RecordStore};
use libp2p::kad::{ProviderRecord, Record, RecordKey as Key};
use libp2p::PeerId;
use sha2::{Digest, Sha256};
use std::borrow::Cow;

fn key_for(prefix: &str, id: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(format!("{}{}", prefix, id).as_bytes());
    hasher.finalize().to_vec()
}

/// Does `record` carry a well-formed, owner-signed noid record under the
/// correct key? Anything else is refused by the store.
fn is_valid_noid_record(record: &Record) -> bool {
    // META-03: a blinded descriptor is an opaque fixed-size AES-GCM blob —
    // the store cannot verify ownership without the owner's pubkey (that's
    // the point: the key reveals nothing). It is admitted on size alone;
    // the inner signed record is verified by the reader after unwrap, so
    // forged descriptors fail closed downstream, and the fixed 1 KiB bound
    // keeps spam cost low.
    if record.value.len() == crate::security::blind_descriptor::DESCRIPTOR_BYTES
        && serde_json::from_slice::<serde_json::Value>(&record.value).is_err()
    {
        return true;
    }
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&record.value) else {
        return false;
    };

    // Mailbox pointer record: { owner_peer_id, mailbox_peer_id, relay_addr, signature }
    if v.get("mailbox_peer_id").is_some() && v.get("owner_peer_id").is_some() {
        if let Ok(rec) = serde_json::from_slice::<crate::p2p::types::SignedMailboxRecord>(&record.value) {
            if key_for("noid:mailbox:", &rec.owner_peer_id) != record.key.as_ref() {
                return false;
            }
            // SEC-1111-01: far-future published_at would out-live every
            // honest republish under the key.
            if !crate::p2p::validate_record_timestamp::record_timestamp_acceptable(
                rec.published_at.as_deref(),
            ) {
                return false;
            }
            return crate::security::identity_sig::verify_payload(
                &rec.owner_peer_id,
                &crate::p2p::types::mailbox_record_signing_payload(&rec),
                &rec.signature,
            );
        }
        return false;
    }

    // Username record: { peerId, username, nickname, avatar, shortId, updatedAt, signature }
    // NOTE: DHTUserRecord serializes camelCase — probing snake_case field
    // names here used to fall through and refuse EVERY username record
    // (local put and remote PUT_VALUE alike), so names never propagated.
    if v.get("username").is_some()
        && (v.get("peerId").is_some() || v.get("peer_id").is_some())
        && (v.get("updatedAt").is_some() || v.get("updated_at").is_some())
    {
        if let Ok(rec) = serde_json::from_slice::<crate::p2p::types::DHTUserRecord>(&record.value) {
            // META-03: the record may live under the legacy key or the
            // Argon2id-blinded key — either must recompute to `record.key`.
            let legacy_ok = key_for("noid:username:", &rec.username) == record.key.as_ref();
            let blind_ok = crate::p2p::blind_username::username_blind_key(&rec.username)
                .map(|k| k.as_ref() == record.key.as_ref())
                .unwrap_or(false);
            if !legacy_ok && !blind_ok {
                return false;
            }
            // SEC-1111-01: a signed record dated 2099 must not lock the name.
            if !crate::p2p::validate_record_timestamp::record_timestamp_acceptable(
                Some(&rec.updated_at),
            ) {
                return false;
            }
            let sig_ok = rec
                .signature
                .as_ref()
                .map(|sig| {
                    crate::security::identity_sig::verify_payload(
                        &rec.peer_id,
                        &crate::p2p::types::user_record_signing_payload(&rec),
                        sig,
                    )
                })
                .unwrap_or(false);
            return sig_ok;
        }
        return false;
    }

    // Prekey bundle: { identity_public, signed_prekey_public, ..., owner_peer_id, identity_signature }
    if v.get("signed_prekey_public").is_some() {
        if let Ok(bundle) = serde_json::from_slice::<crate::security::PrekeyBundle>(&record.value) {
            let Some(owner) = bundle.owner_peer_id.clone() else {
                return false;
            };
            if key_for("noid:prekeys:", &owner) != record.key.as_ref() {
                return false;
            }
            // SEC-1111-01: far-future generated_at freezes the bundle slot.
            if !crate::p2p::validate_record_timestamp::record_timestamp_acceptable(
                bundle.generated_at.as_deref(),
            ) {
                return false;
            }
            return crate::security::x3dh::verify_prekey_bundle(&bundle);
        }
        return false;
    }

    false
}

pub struct ValidatingStore {
    inner: MemoryStore,
    /// B4: keys of recently-refused stale replays → last warn instant. A
    /// misbehaving republisher offers the same stale record every cycle;
    /// the record is always refused but the warn is emitted at most once
    /// per key per `STALE_WARN_INTERVAL` to keep log noise bounded.
    recent_stale: std::collections::HashMap<Vec<u8>, std::time::Instant>,
}

/// How long a stale-replay warn for a given key is suppressed.
const STALE_WARN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(600);
/// Cap on suppressed-key bookkeeping — a flood of distinct keys cannot
/// grow the map unboundedly.
const STALE_WARN_CAP: usize = 128;

impl ValidatingStore {
    pub fn new(peer_id: PeerId) -> Self {
        Self {
            inner: MemoryStore::new(peer_id),
            recent_stale: std::collections::HashMap::new(),
        }
    }

    /// Warn at most once per key per interval; returns true when the
    /// caller should log.
    fn stale_warn_allowed(&mut self, key: &[u8]) -> bool {
        let now = std::time::Instant::now();
        if let Some(last) = self.recent_stale.get(key) {
            if now.duration_since(*last) < STALE_WARN_INTERVAL {
                return false;
            }
        }
        if self.recent_stale.len() >= STALE_WARN_CAP {
            // Evict the oldest entries — keep the map bounded.
            let oldest: Vec<Vec<u8>> = self
                .recent_stale
                .iter()
                .map(|(k, t)| (k.clone(), *t))
                .collect::<Vec<_>>()
                .into_iter()
                .filter_map(|(k, t)| {
                    if now.duration_since(t) >= STALE_WARN_INTERVAL {
                        Some(k)
                    } else {
                        None
                    }
                })
                .collect();
            for k in oldest {
                self.recent_stale.remove(&k);
            }
            if self.recent_stale.len() >= STALE_WARN_CAP {
                return false;
            }
        }
        self.recent_stale.insert(key.to_vec(), now);
        true
    }
}

impl RecordStore for ValidatingStore {
    type RecordsIter<'a>
        = <MemoryStore as RecordStore>::RecordsIter<'a>
    where
        Self: 'a;
    type ProvidedIter<'a>
        = <MemoryStore as RecordStore>::ProvidedIter<'a>
    where
        Self: 'a;

    fn get(&self, k: &Key) -> Option<Cow<'_, Record>> {
        self.inner.get(k)
    }

    fn put(&mut self, r: Record) -> libp2p::kad::store::Result<()> {
        if !is_valid_noid_record(&r) {
            log::warn!("DHT store refused unsigned/foreign record (key {:x?})", r.key);
            return Err(libp2p::kad::store::Error::ValueTooLarge);
        }
        // DHT-03: freshness — an older replayed record must not roll back
        // a newer one under the same key. All three record types carry a
        // signed timestamp (mailbox published_at, username updatedAt,
        // prekey generated_at), so a rewind is detectable without trusting
        // the writer.
        if let Some(stored) = self.inner.get(&r.key) {
            // put_record inserts locally again before retrying replication.
            // An identical verified value is idempotent, not a rollback.
            // Keep existing metadata: a replay cannot extend its expiry.
            if stored.value == r.value {
                return Ok(());
            }
            let fresher = if let Ok(rec) =
                serde_json::from_slice::<crate::p2p::types::SignedMailboxRecord>(&r.value)
            {
                crate::p2p::types::mailbox_record_is_fresher(&stored.value, &rec)
            } else if let Ok(rec) =
                serde_json::from_slice::<crate::p2p::types::DHTUserRecord>(&r.value)
            {
                // SEC-1111-01: freshness alone is not enough — a live record
                // keeps its owner; only a revoked tombstone releases the
                // name to a different peer_id.
                match serde_json::from_slice::<crate::p2p::types::DHTUserRecord>(&stored.value)
                {
                    Ok(stored_rec) => {
                        crate::p2p::can_replace_user_record::can_replace_user_record(
                            &stored_rec, &rec,
                        )
                    }
                    Err(_) => true,
                }
            } else if let Ok(bundle) =
                serde_json::from_slice::<crate::security::PrekeyBundle>(&r.value)
            {
                let new_ts = bundle
                    .generated_at
                    .as_ref()
                    .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok());
                let old_ts = serde_json::from_slice::<crate::security::PrekeyBundle>(&stored.value)
                    .ok()
                    .and_then(|b| {
                        b.generated_at
                            .as_ref()
                            .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
                    });
                match (old_ts, new_ts) {
                    (Some(old), Some(new)) => new > old,
                    (Some(_), None) => false,
                    (None, _) => true,
                }
            } else {
                true
            };
            if !fresher {
                if self.stale_warn_allowed(r.key.as_ref()) {
                    log::warn!("DHT store refused stale record replay (key {:x?})", r.key);
                }
                return Err(libp2p::kad::store::Error::ValueTooLarge);
            }
        }
        self.inner.put(r)
    }

    fn remove(&mut self, k: &Key) {
        self.inner.remove(k)
    }

    fn records(&self) -> Self::RecordsIter<'_> {
        self.inner.records()
    }

    fn add_provider(&mut self, record: ProviderRecord) -> libp2p::kad::store::Result<()> {
        self.inner.add_provider(record)
    }

    fn providers(&self, key: &Key) -> Vec<ProviderRecord> {
        self.inner.providers(key)
    }

    fn provided(&self) -> Self::ProvidedIter<'_> {
        self.inner.provided()
    }

    fn remove_provider(&mut self, k: &Key, p: &PeerId) {
        self.inner.remove_provider(k, p)
    }
}

#[cfg(test)]
mod own_prekey_probe {
    use super::*;

    #[test]
    fn own_signed_prekey_is_accepted() {
        let kp = libp2p::identity::Keypair::generate_ed25519();
        let peer = PeerId::from(kp.public());
        let mut b = crate::security::PrekeyBundle {
            identity_public: vec![1u8; 32],
            signed_prekey_public: vec![2u8; 32],
            one_time_prekey_public: Some(vec![3u8; 32]),
            one_time_prekeys: vec![vec![4u8; 32]],
            owner_peer_id: Some(peer.to_string()),
            identity_signature: None,
            generated_at: Some("2026-10-26T00:00:00Z".to_string()),
        };
        let payload = crate::security::x3dh::prekey_signing_payload(&b);
        b.identity_signature = Some(
            crate::security::identity_sig::sign_payload(&kp, &payload).unwrap(),
        );
        let value = serde_json::to_vec(&b).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(format!("noid:prekeys:{}", peer).as_bytes());
        let key = Key::new(&hasher.finalize().to_vec());
        let rec = Record::new(key, value);
        let ok = is_valid_noid_record(&rec);
        assert!(ok, "own signed prekey record must be accepted");
    }
}
