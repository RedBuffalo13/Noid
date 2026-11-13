//! Per-envelope mailbox processing — extracted from the lib.rs event loop
//! (SEC-1111-08 / S01) so the whole verify → freshness → dedup → decrypt →
//! dispatch → ack pipeline is unit-testable without a Tauri runtime.
//!
//! Freshness contract: the ONLY timestamp gate runs BEFORE decryption —
//! an envelope older than the 7-day mailbox TTL (+1d slack) or future-dated
//! beyond 1d slack is refused. The removed post-decrypt `age > 48h` check
//! mutated the Double Ratchet and then dropped valid 2–7-day-old offline
//! envelopes, desyncing the session while the mailbox still got its ack.
//!
//! META-02: items whose `sender` is the literal "sealed" are blind-box
//! envelopes — a fixed 4096 B ECIES blob for our X3DH identity key that
//! hides the real sender, the ratchet header and the stable ref id from
//! the mailbox. They open into a synthetic `MailboxMessageItem` and run
//! through the same pipeline; the AEAD tag stands in for the sender
//! signature, and the mailbox row is deleted via `DeleteBlind`.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tauri::{AppHandle, Manager};
use tokio::sync::Mutex;

use crate::db::Database;
use crate::p2p::types::MailboxMessageItem;
use crate::security::{DHTCipher, RatchetSessionManager, SecurityManager};

/// Context shared by every envelope of one retrieval batch — assembled
/// once in the event loop, then borrowed per item.
pub struct MailboxProcessCtx {
    pub handle: AppHandle,
    pub db: Database,
    pub sessions: Arc<RatchetSessionManager>,
    pub security: Arc<Mutex<SecurityManager>>,
    pub dht_cipher: Option<Arc<DHTCipher>>,
    pub p2p_tx: tokio::sync::watch::Sender<
        Option<tokio::sync::mpsc::Sender<crate::p2p::P2PCommand>>,
    >,
    pub decrypt_attempts: Arc<Mutex<HashMap<String, u8>>>,
    pub seen_hashes: Arc<Mutex<HashSet<String>>>,
    pub mailbox_peer_id: String,
    pub my_id: String,
}

/// Tell the mailbox courier the envelope reached its destination (or was
/// deliberately refused) — the remote row is deleted only after this.
async fn ack_envelope(ctx: &MailboxProcessCtx, msg_id: String) {
    if let Some(tx) = crate::p2p_sender(&ctx.p2p_tx) {
        let _ = crate::send_p2p_cmd(
            &tx,
            crate::p2p::P2PCommand::AckMailboxMessage {
                mailbox_peer_id: ctx.mailbox_peer_id.clone(),
                message_id: msg_id,
            },
        )
        .await;
    }
}

/// META-02: ack a blind item — the node signs an ownership proof and
/// sends `DeleteBlind` for both rotation-window days; only the one
/// matching the stored box applies.
async fn ack_blind(ctx: &MailboxProcessCtx, msg_id: String) {
    if let Some(tx) = crate::p2p_sender(&ctx.p2p_tx) {
        let _ = crate::send_p2p_cmd(
            &tx,
            crate::p2p::P2PCommand::AckMailboxBlind {
                mailbox_peer_id: ctx.mailbox_peer_id.clone(),
                message_id: msg_id,
            },
        )
        .await;
    }
}

/// META-02: end-to-end delivery receipt — after a sealed envelope is
/// durably processed, echo its `ref_id` back inside the ratchet so the
/// sender learns "delivered" while the mailbox sees nothing.
async fn send_delivery_receipt(ctx: &MailboxProcessCtx, peer: &str, ref_id: &str) {
    if ref_id.is_empty() {
        return;
    }
    let state = ctx.handle.state::<crate::AppState>();
    let payload = format!(
        "NOIDMETA1:{}",
        serde_json::json!({"kind": "delivered", "ref_id": ref_id})
    );
    if let Ok(msg) = crate::commands::file_transfer::wrap_ratchet_payload(
        &state,
        peer,
        &payload,
        &uuid::Uuid::new_v4().to_string(),
    )
    .await
    {
        if let Some(tx) = crate::p2p_sender(&ctx.p2p_tx) {
            let _ = crate::send_p2p_cmd(&tx, crate::p2p::P2PCommand::SendMessage {
                peer_id: peer.to_string(),
                msg,
            })
            .await;
        }
    }
}

/// NET-A03: mailbox timestamps arrive either RFC3339 (explicit writers) or
/// SQLite `YYYY-MM-DD HH:MM:SS` UTC (`CURRENT_TIMESTAMP` defaults). Parse
/// both; an unreadable format is NOT proof of staleness — the envelope
/// stays queued instead of being deleted on a parse error.
pub(crate) fn mailbox_ts_age_secs(ts: &str) -> Option<i64> {
    if let Ok(t) = chrono::DateTime::parse_from_rfc3339(ts) {
        return Some(
            (chrono::Utc::now() - t.with_timezone(&chrono::Utc)).num_seconds(),
        );
    }
    if let Ok(t) = chrono::NaiveDateTime::parse_from_str(ts, "%Y-%m-%d %H:%M:%S") {
        return Some((chrono::Utc::now().naive_utc() - t).num_seconds());
    }
    None
}

/// Process one retrieved mailbox envelope end-to-end. Sealed items are
/// unwrapped first, then share the pipeline; the row is acked exactly
/// once through the matching channel (Delete vs DeleteBlind).
pub async fn process_mailbox_item(ctx: &MailboxProcessCtx, item: MailboxMessageItem) {
    if item.sender == "sealed" {
        let secret = ctx.sessions.identity_secret_bytes().await;
        match crate::security::sealed_sender::open(&secret, &item.content) {
            Some((real_sender, ref_id, inner)) => {
                let item_id = if ref_id.is_empty() {
                    item.id.clone()
                } else {
                    ref_id.clone()
                };
                let inner_item = MailboxMessageItem {
                    id: item_id,
                    sender: real_sender.clone(),
                    content: inner,
                    timestamp: item.timestamp.clone(),
                    signature: Vec::new(),
                };
                if process_one(ctx, inner_item, true).await {
                    send_delivery_receipt(ctx, &real_sender, &ref_id).await;
                }
            }
            None => {
                log::warn!("Sealed mailbox item {} failed ECIES open — dropped", item.id);
            }
        }
        ack_blind(ctx, item.id).await;
        return;
    }

    if process_one(ctx, item.clone(), false).await {
        ack_envelope(ctx, item.id).await;
    }
}

/// Core pipeline: verify → freshness → dedup → decrypt → dispatch.
/// Returns `true` when the row may leave the mailbox (processed or
/// deliberately refused); `false` keeps it queued for a later retry.
/// `sealed` marks ECIES-authenticated items — their inner payload has no
/// Ed25519 signature by design (the AEAD tag already bound sender+content).
async fn process_one(
    ctx: &MailboxProcessCtx,
    item: MailboxMessageItem,
    sealed: bool,
) -> bool {
    let MailboxMessageItem {
        id: msg_id,
        sender,
        content,
        timestamp,
        signature,
    } = item;
    // S6: verify the sender's envelope signature end-to-end — the mailbox is
    // a courier, not an authority. Try the v2 payload (binds client_msg_id)
    // first, then legacy v1.
    let sig_ok = sealed || (!signature.is_empty()
        && (crate::security::identity_sig::verify_payload(
            &sender,
            &crate::p2p::types::envelope_signing_payload_v2(
                &ctx.my_id, &sender, &msg_id, &content,
            ),
            &signature,
        ) || crate::security::identity_sig::verify_payload(
            &sender,
            &crate::p2p::types::envelope_signing_payload(&ctx.my_id, &sender, &content),
            &signature,
        )));
    if !sig_ok {
        log::warn!(
            "Mailbox envelope {} from {} — signature missing/invalid, dropped",
            msg_id,
            sender
        );
        return true;
    }
    // Freshness — the ONLY timestamp gate, and it must stay BEFORE the
    // decrypt below: refusing after `sessions.decrypt` mutated the ratchet
    // killed valid 2–7-day-old envelopes and desynced the chain (SEC-1111-08).
    match mailbox_ts_age_secs(&timestamp) {
        Some(age) if !(-86400..=8 * 86400).contains(&age) => {
            log::warn!(
                "Mailbox envelope {} from {} — stale timestamp {}, dropped",
                msg_id,
                sender,
                timestamp
            );
            return true;
        }
        Some(_) => {}
        None => {
            log::warn!(
                "Mailbox envelope {} from {} — unreadable timestamp {}, left queued",
                msg_id,
                sender,
                timestamp
            );
            return false;
        }
    }
    // S6: content-hash dedup — a hostile mailbox can re-wrap the same
    // ciphertext under a fresh message id; the id-keyed check below
    // cannot catch that.
    let content_hash = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(&content);
        hex::encode(h.finalize())
    };
    {
        // MD-02: CHECK-ONLY here — inserting the hash before decryption made
        // a first failed attempt mark the envelope "seen", so the next
        // Retrieve acked it as replay WITHOUT decrypting.
        let seen = ctx.seen_hashes.lock().await;
        if seen.contains(&content_hash) {
            log::debug!("Skipping replayed mailbox content (msg {})", msg_id);
            return true;
        }
    }
    // Dedup: the same envelope can arrive from a second mailbox replica or
    // race with a direct resend — the mailbox still gets an ack, but we
    // don't re-process.
    if ctx.db.message_exists(&msg_id).await.unwrap_or(false) {
        log::debug!("Skipping duplicate mailbox message {}", msg_id);
        let mut seen = ctx.seen_hashes.lock().await;
        if seen.len() < 10_000 {
            seen.insert(content_hash.clone());
        }
        return true;
    }

    let plaintext_opt =
        crate::decrypt_mailbox_envelope::decrypt_mailbox_envelope(ctx, &sender, &content)
            .await;

    let processed = match plaintext_opt {
        Some(plaintext) => {
            crate::dispatch_mailbox_plaintext::dispatch_mailbox_plaintext(
                ctx, &sender, &msg_id, &timestamp, &plaintext,
            )
            .await
        }
        None => false,
    };

    if processed {
        // S6: attempts are keyed by content hash, not the mailbox-chosen id.
        ctx.decrypt_attempts.lock().await.remove(&content_hash);
        // MD-02: mark seen only now that the envelope was durably processed —
        // a failed decrypt stays unseen so the next Retrieve retries it.
        let mut seen = ctx.seen_hashes.lock().await;
        if seen.len() < 10_000 {
            seen.insert(content_hash.clone());
        }
        true
    } else {
        // A ciphertext from a dead ratchet state can never decrypt — after
        // enough attempts it is poison churning re-handshakes; ack+drop.
        const MAX_DECRYPT_ATTEMPTS: u8 = 6;
        // RC24: cap the attempts map — a flood of distinct poisoned envelopes
        // must not grow it without bound between GCs.
        const MAX_TRACKED: usize = 5000;
        let mut attempts = ctx.decrypt_attempts.lock().await;
        if attempts.len() >= MAX_TRACKED {
            attempts.clear();
        }
        let n = attempts.entry(content_hash.clone()).or_insert(0);
        *n = n.saturating_add(1);
        let exhausted = *n >= MAX_DECRYPT_ATTEMPTS;
        if exhausted {
            attempts.remove(&content_hash);
            log::warn!(
                "Dropping undecryptable mailbox message {} after {} attempts",
                msg_id,
                MAX_DECRYPT_ATTEMPTS
            );
        } else {
            log::warn!(
                "Keeping undecrypted mailbox message {} for retry ({}/{})",
                msg_id,
                n,
                MAX_DECRYPT_ATTEMPTS
            );
        }
        drop(attempts);
        exhausted
    }
}
