use libp2p::kad;
use sha2::Digest;
use tokio::sync::mpsc;

use crate::p2p::node::P2PNode;
use crate::p2p::types::{DHTUserRecord, P2PEvent};

/// Resolve any leftover query state after a successful GetRecord completes.
///
/// In libp2p-kad 0.46, FinishedWithNoAdditionalRecord follows FoundRecord;
/// an empty query emits Err(NotFound). This event never proves absence.
/// FoundRecord normally consumed the pending entry already. Any leftover
/// username query is therefore inconclusive, not permission to publish.
///
/// Returns `true` when the query id was claimed by a pending map.
impl P2PNode {
    pub(crate) async fn resolve_get_record_miss(
        &mut self,
        id: &kad::QueryId,
        event_tx: &mpsc::Sender<P2PEvent>,
    ) -> bool {
        // Prekey bundle — the X3DH handshake (and with it every RatchetChat)
        // hinges on this answer.
        if let Some(peer_id) = self.pending_prekey_queries.remove(id) {
            // X3DH-07: a direct request may still answer — emitting None
            // here would fail the handshake while the peer is about to
            // reply; an already-resolved peer must not be re-emitted.
            if self.prekey_direct_pending(&peer_id)
                || self.prekey_recently_resolved(&peer_id)
            {
                return true;
            }
            let local = self
                .local_dht_get(&Self::prekey_dht_key(&peer_id).to_vec())
                .and_then(|v| {
                    serde_json::from_slice::<crate::security::PrekeyBundle>(&v)
                        .ok()
                        .filter(|b| {
                            b.owner_peer_id.as_deref() == Some(peer_id.as_str())
                                && crate::security::x3dh::verify_prekey_bundle(b)
                        })
                });
            if local.is_none() {
                log::warn!("Prekey bundle absent from DHT for peer {}", peer_id);
            } else {
                self.mark_prekey_resolved(&peer_id);
            }
            let _ = crate::p2p::event_loop::emit_ev(
                event_tx,
                P2PEvent::PrekeyBundleRetrieved {
                    peer_id,
                    bundle: local,
                },
            )
            .await;
            return true;
        }
        // Mailbox node lookup — offline delivery waits on this.
        if let Some(peer_id) = self.pending_mailbox_lookups.remove(id) {
            let local = self
                .local_dht_get(&Self::mailbox_dht_key(&peer_id).to_vec())
                .and_then(|v| {
                    serde_json::from_slice::<crate::p2p::types::SignedMailboxRecord>(&v)
                        .ok()
                        .filter(|rec| {
                            rec.owner_peer_id == peer_id
                                && crate::security::identity_sig::verify_payload(
                                    &rec.owner_peer_id,
                                    &crate::p2p::types::mailbox_record_signing_payload(rec),
                                    &rec.signature,
                                )
                        })
                });
            if let Some(rec) = local {
                self.mailbox_cache.insert(
                    peer_id.clone(),
                    (
                        rec.mailbox_peer_id.clone(),
                        rec.relay_addr.clone(),
                        std::time::Instant::now(),
                    ),
                );
                let _ = crate::p2p::event_loop::emit_ev(
                    event_tx,
                    P2PEvent::MailboxNodeFound {
                        peer_id,
                        mailbox_peer_id: rec.mailbox_peer_id,
                        relay_addr: rec.relay_addr,
                    },
                )
                .await;
            } else {
                let _ = crate::p2p::event_loop::emit_ev(
                    event_tx,
                    P2PEvent::MailboxNodeNotFound { peer_id },
                )
                .await;
            }
            return true;
        }
        // A successful query must not be interpreted as a free username.
        if let Some((pub_username, _value, _signed)) =
            self.pending_username_publishes.remove(id)
        {
            let _ = crate::p2p::event_loop::emit_ev(
                event_tx,
                P2PEvent::UsernameAvailabilityChecked {
                    username: pub_username,
                    available: false,
                    uncertain: true,
                },
            )
            .await;
            return true;
        }
        // Username availability / lookup queries.
        enum UsernameQueryKind {
            Availability,
            Lookup,
        }
        let (lookup_username, kind) =
            if let Some(u) = self.pending_availability_queries.remove(id) {
                (u, UsernameQueryKind::Availability)
            } else if let Some(u) = self.pending_lookups.remove(id) {
                (u, UsernameQueryKind::Lookup)
            } else {
                return false;
            };
        // Local fallback copy beats an empty network answer.
        let prefix = format!("noid:username:{}", lookup_username);
        let mut hasher = sha2::Sha256::new();
        sha2::Digest::update(&mut hasher, prefix.as_bytes());
        let key_hash = sha2::Digest::finalize(hasher);
        if let Some(value) = self.local_dht_get(&key_hash) {
            if let Ok(user_record) = serde_json::from_slice::<DHTUserRecord>(&value) {
                match kind {
                    UsernameQueryKind::Lookup => {
                        let _ = crate::p2p::event_loop::emit_ev(
                            event_tx,
                            P2PEvent::UserLookupResult {
                                username: lookup_username,
                                record: Some(user_record),
                            },
                        )
                        .await;
                    }
                    UsernameQueryKind::Availability => {
                        let _ = crate::p2p::event_loop::emit_ev(
                            event_tx,
                            P2PEvent::UsernameAvailabilityChecked {
                                username: lookup_username,
                                available: false,
                                uncertain: false,
                            },
                        )
                        .await;
                    }
                }
                return true;
            }
        }
        match kind {
            UsernameQueryKind::Availability => {
                let _ = crate::p2p::event_loop::emit_ev(
                    event_tx,
                    P2PEvent::UsernameAvailabilityChecked {
                        username: lookup_username,
                        available: false,
                        uncertain: true,
                    },
                )
                .await;
            }
            UsernameQueryKind::Lookup => {
                let _ = crate::p2p::event_loop::emit_ev(
                    event_tx,
                    P2PEvent::UserLookupResult {
                        username: lookup_username,
                        record: None,
                    },
                )
                .await;
            }
        }
        true
    }
}
