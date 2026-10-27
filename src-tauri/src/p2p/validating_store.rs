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
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&record.value) else {
        return false;
    };

    // Mailbox pointer record: { owner_peer_id, mailbox_peer_id, relay_addr, signature }
    if v.get("mailbox_peer_id").is_some() && v.get("owner_peer_id").is_some() {
        if let Ok(rec) = serde_json::from_slice::<crate::p2p::types::SignedMailboxRecord>(&record.value) {
            if key_for("noid:mailbox:", &rec.owner_peer_id) != record.key.as_ref() {
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
            if key_for("noid:username:", &rec.username) != record.key.as_ref() {
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
            return crate::security::x3dh::verify_prekey_bundle(&bundle);
        }
        return false;
    }

    false
}

pub struct ValidatingStore {
    inner: MemoryStore,
}

impl ValidatingStore {
    pub fn new(peer_id: PeerId) -> Self {
        Self {
            inner: MemoryStore::new(peer_id),
        }
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
                crate::p2p::types::user_record_is_fresher(&stored.value, &rec)
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
                log::warn!("DHT store refused stale record replay (key {:x?})", r.key);
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
