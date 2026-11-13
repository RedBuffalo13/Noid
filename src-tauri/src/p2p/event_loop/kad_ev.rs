//! Kademlia DHT arms — extracted from the event_loop megaloop (Q04/A5).
//! Behaviour-preserving move only.

use super::*;

impl P2PNode {
    pub(crate) async fn on_kad_event(
        &mut self,
        event: SwarmEvent<NoidBehaviourEvent>,
        ctx: &LoopCtx<'_>,
    ) -> LoopCtl {
        match event {
                    SwarmEvent::Behaviour(NoidBehaviourEvent::Kademlia(kad::Event::OutboundQueryProgressed {
                        id,
                        result: kad::QueryResult::GetRecord(Ok(kad::GetRecordOk::FoundRecord(peer_record))),
                        ..
                    })) => {
                        // Dispatch by PENDING-MAP OWNERSHIP first, payload
                        // shape second: a record stored under a queried key
                        // with an unexpected shape must still resolve its
                        // pending query — the UI waits on the result event
                        // and spins forever without one.
                        // META-03: blinded descriptor / blinded-username
                        // results unwrap (when applicable) and re-enter
                        // the exact same signed-record verification —
                        // encryption hides metadata, it does not skip auth.
                        if let Some((owner, kind, day)) = self.pending_blind_queries.remove(&id) {
                            match kind {
                                crate::p2p::blind_lookup::BlindKind::Prekey
                                | crate::p2p::blind_lookup::BlindKind::Mailbox => {
                                    let Ok(ed_pub) = crate::security::identity_sig::pubkey_from_peer_id(&owner)
                                        .and_then(|k| k.try_into_ed25519().map(|e| e.to_bytes().to_vec()).map_err(|_| anyhow::anyhow!("not ed25519")))
                                    else { return LoopCtl::Keep };
                                    let Some(inner) = crate::security::blind_descriptor::unwrap_descriptor(
                                        &ed_pub, day, &peer_record.record.value,
                                    ) else { return LoopCtl::Keep };
                                    match kind {
                                        crate::p2p::blind_lookup::BlindKind::Prekey => {
                                            if self.prekey_recently_resolved(&owner) {
                                                return LoopCtl::Keep;
                                            }
                                            match serde_json::from_slice::<crate::security::PrekeyBundle>(&inner) {
                                                Ok(bundle)
                                                    if bundle.owner_peer_id.as_deref() == Some(owner.as_str())
                                                        && crate::security::x3dh::verify_prekey_bundle(&bundle) =>
                                                {
                                                    self.mark_prekey_resolved(&owner);
                                                    let _ = emit_ev(ctx.event_tx, P2PEvent::PrekeyBundleRetrieved {
                                                        peer_id: owner,
                                                        bundle: Some(bundle),
                                                    }).await;
                                                }
                                                _ => log::warn!("Blind descriptor for {} held an invalid bundle", owner),
                                            }
                                        }
                                        _ => {
                                            match serde_json::from_slice::<crate::p2p::types::SignedMailboxRecord>(&inner) {
                                                Ok(rec)
                                                    if rec.owner_peer_id == owner
                                                        && crate::security::identity_sig::verify_payload(
                                                            &rec.owner_peer_id,
                                                            &crate::p2p::types::mailbox_record_signing_payload(&rec),
                                                            &rec.signature,
                                                        ) =>
                                                {
                                                    self.mailbox_cache.insert(
                                                        owner.clone(),
                                                        (rec.mailbox_peer_id.clone(), rec.relay_addr.clone(), std::time::Instant::now()),
                                                    );
                                                    let _ = emit_ev(ctx.event_tx, P2PEvent::MailboxNodeFound {
                                                        peer_id: owner,
                                                        mailbox_peer_id: rec.mailbox_peer_id,
                                                        relay_addr: rec.relay_addr,
                                                        backup_mailbox_peer_id: rec.backup_mailbox_peer_id,
                                                        backup_relay_addr: rec.backup_relay_addr,
                                                    }).await;
                                                }
                                                _ => log::warn!("Blind descriptor for {} held an invalid mailbox record", owner),
                                            }
                                        }
                                    }
                                }
                                crate::p2p::blind_lookup::BlindKind::Username => {
                                    // Same verify the legacy path runs —
                                    // a blinded key must not weaken it.
                                    match serde_json::from_slice::<crate::p2p::types::DHTUserRecord>(&peer_record.record.value) {
                                        Ok(rec)
                                            if rec.username == owner
                                                && !rec.revoked
                                                && rec.signature.as_ref().map(|s| crate::security::identity_sig::verify_payload(
                                                    &rec.peer_id,
                                                    &crate::p2p::types::user_record_signing_payload(&rec),
                                                    s,
                                                )).unwrap_or(false) =>
                                        {
                                            let _ = emit_ev(ctx.event_tx, P2PEvent::UserLookupResult {
                                                username: owner,
                                                record: Some(rec),
                                            }).await;
                                        }
                                        _ => log::warn!("Blinded username record for '{}' failed verification", owner),
                                    }
                                }
                            }
                            return LoopCtl::Keep;
                        }
                        if let Some(peer_id) = self.pending_prekey_queries.remove(&id) {
                            // Phase A.3: Prekey bundle retrieved from DHT.
                            // Must be signed by the queried peer's identity key —
                            // a forged bundle is a MITM attempt and is rejected.
                            // X3DH-07: the direct path may have resolved this
                            // peer already — a second emit would re-initiate
                            // the session just created.
                            if self.prekey_recently_resolved(&peer_id) {
                                return LoopCtl::Keep;
                            }
                            match serde_json::from_slice::<crate::security::PrekeyBundle>(&peer_record.record.value) {
                                Ok(bundle) => {
                                    let valid = bundle.owner_peer_id.as_deref() == Some(peer_id.as_str())
                                        && crate::security::x3dh::verify_prekey_bundle(&bundle);
                                    if valid {
                                        log::debug!("Verified prekey bundle from DHT for peer {}", peer_id);
                                        self.mark_prekey_resolved(&peer_id);
                                        let _ = emit_ev(ctx.event_tx, P2PEvent::PrekeyBundleRetrieved {
                                            peer_id,
                                            bundle: Some(bundle),
                                        }).await;
                                    } else {
                                        log::warn!("Rejected unverified prekey bundle for {}", peer_id);
                                        if let Some(ref log) = self.audit_log {
                                            let _ = log.log_replay_detected(&format!("prekey-forgery:{}", peer_id));
                                        }
                                        let _ = emit_ev(ctx.event_tx, P2PEvent::PrekeyBundleRetrieved {
                                            peer_id,
                                            bundle: None,
                                        }).await;
                                    }
                                }
                                Err(e) => {
                                    log::warn!("Failed to parse prekey bundle for {}: {}", peer_id, e);
                                    let _ = emit_ev(ctx.event_tx, P2PEvent::PrekeyBundleRetrieved {
                                        peer_id,
                                        bundle: None,
                                    }).await;
                                }
                            }
                        } else if let Some(peer_id) = self.pending_mailbox_lookups.remove(&id) {
                            // Phase H.1: Mailbox node record retrieved from DHT.
                            // Value is a SignedMailboxRecord — verify the owner's
                            // signature so a DHT peer cannot redirect envelopes.
                            match serde_json::from_slice::<crate::p2p::types::SignedMailboxRecord>(&peer_record.record.value) {
                                Ok(rec) => {
                                    let valid = rec.owner_peer_id == peer_id
                                        && crate::security::identity_sig::verify_payload(
                                            &rec.owner_peer_id,
                                            &crate::p2p::types::mailbox_record_signing_payload(&rec),
                                            &rec.signature,
                                        );
                                    if valid {
                                        log::debug!("Mailbox node found for {}: mailbox_peer={}", peer_id, rec.mailbox_peer_id);
                                        // D19: cache the verified pointer for
                                        // the retry tick (10min TTL).
                                        self.mailbox_cache.insert(
                                            peer_id.clone(),
                                            (
                                                rec.mailbox_peer_id.clone(),
                                                rec.relay_addr.clone(),
                                                std::time::Instant::now(),
                                            ),
                                        );
                                        let _ = emit_ev(ctx.event_tx, P2PEvent::MailboxNodeFound {
                                            peer_id,
                                            mailbox_peer_id: rec.mailbox_peer_id,
                                            relay_addr: rec.relay_addr,
                                            backup_mailbox_peer_id: rec.backup_mailbox_peer_id,
                                            backup_relay_addr: rec.backup_relay_addr,
                                        }).await;
                                    } else {
                                        log::warn!("Rejected unsigned/forged mailbox record for {}", peer_id);
                                        let _ = emit_ev(ctx.event_tx, P2PEvent::MailboxError {
                                            error: format!("Mailbox record for {} failed verification", peer_id),
                                        }).await;
                                    }
                                }
                                Err(e) => {
                                    log::warn!("Invalid mailbox record for {}: {}", peer_id, e);
                                    let _ = emit_ev(ctx.event_tx, P2PEvent::MailboxError {
                                        error: format!("Mailbox record for {} is unreadable", peer_id),
                                    }).await;
                                }
                            }
                        } else if let Some((pub_username, value, signed)) = self.pending_username_publishes.remove(&id) {
                            // D14: get-before-put gate — commit only when no
                            // fresher valid record owned by another peer.
                            if self.username_publish_allowed(&pub_username, &value, Some(&peer_record)) {
                                match self.commit_username_publish(&pub_username, value, signed) {
                                    Ok(_) => {
                                        let _ = emit_ev(ctx.event_tx, P2PEvent::UsernameAvailabilityChecked {
                                            username: pub_username,
                                            available: true,
                                            uncertain: false,
                                        }).await;
                                    }
                                    Err(e) => {
                                        log::error!("Username publish failed: {}", e);
                                        let _ = emit_ev(ctx.event_tx, P2PEvent::UsernameAvailabilityChecked {
                                            username: pub_username,
                                            available: false,
                                            uncertain: false,
                                        }).await;
                                    }
                                }
                            } else {
                                log::warn!("Username '{}' is held by another peer — refusing to publish", pub_username);
                                let _ = emit_ev(ctx.event_tx, P2PEvent::UsernameAvailabilityChecked {
                                    username: pub_username,
                                    available: false,
                                    uncertain: false,
                                }).await;
                            }
                        } else if let Some(avail_username) = self.pending_availability_queries.remove(&id) {
                            // D21: availability queries resolve as the
                            // availability event only — a search result must
                            // not pop into it, and vice versa.
                            match serde_json::from_slice::<DHTUserRecord>(&peer_record.record.value) {
                                Ok(user_record) => {
                                    // D13: a revoked record is a tombstone —
                                    // the owner released the name.
                                    let sig_ok = user_record.signature.as_ref().map(|sig| {
                                        crate::security::identity_sig::verify_payload(
                                            &user_record.peer_id,
                                            &crate::p2p::types::user_record_signing_payload(&user_record),
                                            sig,
                                        )
                                    }).unwrap_or(false)
                                        && user_record.username == avail_username
                                        && !user_record.revoked;
                                    let _ = emit_ev(ctx.event_tx, P2PEvent::UsernameAvailabilityChecked {
                                        username: avail_username,
                                        available: !sig_ok,
                                        uncertain: false,
                                    }).await;
                                }
                                Err(e) => {
                                    log::warn!("Malformed user record for '{}': {}", avail_username, e);
                                    let _ = emit_ev(ctx.event_tx, P2PEvent::UsernameAvailabilityChecked {
                                        username: avail_username,
                                        available: true,
                                        uncertain: false,
                                    }).await;
                                }
                            }
                        } else if let Some(lookup_username) = self.pending_lookups.remove(&id) {
                            // Username records must be signed by the claimed
                            // owner — unsigned/forged/malformed records resolve
                            // the lookup as "not found", never silently.
                            match serde_json::from_slice::<DHTUserRecord>(&peer_record.record.value) {
                                Ok(user_record) => {
                                    let sig_ok = user_record.signature.as_ref().map(|sig| {
                                        crate::security::identity_sig::verify_payload(
                                            &user_record.peer_id,
                                            &crate::p2p::types::user_record_signing_payload(&user_record),
                                            sig,
                                        )
                                    }).unwrap_or(false);
                                    // The username is inside the signed
                                    // payload — a record signed for another
                                    // name cannot be replayed under this key.
                                    // D13: a revoked record is a tombstone —
                                    // the owner released the name.
                                    let sig_ok = sig_ok && user_record.username == lookup_username
                                        && !user_record.revoked;
                                    if sig_ok {
                                        log::debug!("Received signed user record from DHT for username lookup '{}'", lookup_username);
                                        let _ = emit_ev(ctx.event_tx, P2PEvent::UserLookupResult {
                                            username: lookup_username,
                                            record: Some(user_record),
                                        }).await;
                                    } else {
                                        log::warn!("Rejected unsigned/forged user record for '{}'", lookup_username);
                                        let _ = emit_ev(ctx.event_tx, P2PEvent::UserLookupResult {
                                            username: lookup_username,
                                            record: None,
                                        }).await;
                                    }
                                }
                                Err(e) => {
                                    log::warn!("Malformed user record for '{}': {}", lookup_username, e);
                                    let _ = emit_ev(ctx.event_tx, P2PEvent::UserLookupResult {
                                        username: lookup_username,
                                        record: None,
                                    }).await;
                                }
                            }
                        } else {
                            log::debug!("Received non-DHT record from Kademlia, ignoring");
                        }
                    }
                    SwarmEvent::Behaviour(NoidBehaviourEvent::Kademlia(kad::Event::OutboundQueryProgressed {
                        id,
                        result: kad::QueryResult::GetRecord(Ok(kad::GetRecordOk::FinishedWithNoAdditionalRecord { .. })),
                        ..
                    })) => {
                        // Successful completion follows FoundRecord; it is
                        // not a NotFound result. Resolve only leftover state.
                        if self.resolve_get_record_miss(&id, TerminalCause::Completed, ctx.event_tx).await {
                            return LoopCtl::Keep;
                        }
                    }
                    SwarmEvent::Behaviour(NoidBehaviourEvent::Kademlia(kad::Event::OutboundQueryProgressed {
                        id,
                        result: kad::QueryResult::GetRecord(Err(e)),
                        ..
                    })) => {
                        // All failure variants end here — NotFound (queried,
                        // absent), Timeout, Failed, QuorumFailed. A query
                        // that ends in ANY error must still resolve its
                        // pending map: the UI spinner waits for the result
                        // event and hangs forever without one.
                        log::debug!("DHT GetRecord failed: {:?}", e);
                        // OPT-R02: same pending-map/local-fallback resolution as the
                        // completion arm — the cause only changes the username verdict:
                        // a real NotFound proves absence (name is free); every other
                        // failure is inconclusive, never permission to publish.
                        let cause = if matches!(e, kad::GetRecordError::NotFound { .. }) {
                            TerminalCause::NotFound
                        } else {
                            TerminalCause::Inconclusive
                        };
                        if self.resolve_get_record_miss(&id, cause, ctx.event_tx).await {
                            return LoopCtl::Keep;
                        }
                        // Other GetRecord queries (random walks) end here silently.
                    }
                    SwarmEvent::Behaviour(NoidBehaviourEvent::Kademlia(kad::Event::OutboundQueryProgressed {
                        id,
                        result: kad::QueryResult::PutRecord(Ok(_)),
                        ..
                    })) => {
                        self.pending_prekey_puts.remove(&id);
                        log::info!("DHT PutRecord succeeded — username/prekey/message published to the DHT");
                    }
                    SwarmEvent::Behaviour(NoidBehaviourEvent::Kademlia(kad::Event::OutboundQueryProgressed {
                        id,
                        result: kad::QueryResult::PutRecord(Err(e)),
                        ..
                    })) => {
                        log::warn!("DHT PutRecord failed — record is only stored locally, other nodes cannot see it: {:?}", e);
                        // A failed prekey publish is retried — without a
                        // published bundle no peer can initiate X3DH with us.
                        if let Some((record, attempts)) = self.pending_prekey_puts.remove(&id) {
                            // B2: an empty routing table makes every put
                            // fail instantly — re-park instead of storming
                            // retries; the deferred drain fires once a
                            // routing peer exists.
                            if attempts < 4 && self.routing_has_peers() {
                                match self.swarm.behaviour_mut().kademlia.put_record(record.clone(), kad::Quorum::One) {
                                    Ok(qid) => {
                                        self.pending_prekey_puts.insert(qid, (record, attempts + 1));
                                        log::info!("Retrying prekey bundle publish (attempt {})", attempts + 1);
                                    }
                                    Err(e2) => {
                                        log::warn!("Prekey publish retry could not be queued: {}", e2);
                                    }
                                }
                            } else if attempts < 4 {
                                // Re-park — drained when a routing peer appears.
                                if self.deferred_dht_puts.len() < 32 {
                                    self.deferred_dht_puts.push(record);
                                }
                            } else {
                                log::warn!("Prekey bundle publish gave up after {} attempts — next republish cycle retries", attempts + 1);
                            }
                        }
                    }
                    SwarmEvent::Behaviour(NoidBehaviourEvent::Kademlia(kad::Event::OutboundQueryProgressed {
                        result: kad::QueryResult::Bootstrap(Ok(_)),
                        ..
                    })) => {
                        log::debug!("DHT bootstrap query succeeded");
                    }
                    SwarmEvent::Behaviour(NoidBehaviourEvent::Kademlia(kad::Event::OutboundQueryProgressed {
                        result: kad::QueryResult::Bootstrap(Err(e)),
                        ..
                    })) => {
                        log::debug!("DHT bootstrap query failed: {:?}", e);
                    }
            ev => return self.on_kad_tail(ev, ctx).await,
        }
        LoopCtl::Keep
    }
}
