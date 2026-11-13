//! Attempt to decrypt one mailbox envelope — Double Ratchet first, legacy
//! ECDH `DHTEncryptedMessage` as fallback. On ratchet failure this module
//! owns the replay check and desync bookkeeping: a replayed envelope is
//! not a failure, but ≥3 genuine failures trigger a re-handshake fetch.

use crate::process_mailbox_item::MailboxProcessCtx;

/// Returns the decrypted plaintext, or `None` when the envelope is
/// undecryptable right now (caller decides retry vs. poison-drop).
pub async fn decrypt_mailbox_envelope(
    ctx: &MailboxProcessCtx,
    sender: &str,
    content: &[u8],
) -> Option<Vec<u8>> {
    if let Ok(ratchet_msg) =
        serde_json::from_slice::<crate::security::RatchetMessage>(content)
    {
        if !ctx.sessions.has_session(sender).await {
            let _ = ctx.sessions.load_session(&ctx.db, sender).await;
        }
        match ctx.sessions.decrypt(sender, &ratchet_msg).await {
            Ok(plaintext) => Some(plaintext),
            Err(e) => {
                log::warn!(
                    "Failed to decrypt mailbox message from {} as ratchet: {}",
                    sender,
                    e
                );
                // S5: replayed envelopes (hostile mailbox re-issuing old
                // ciphertext under a fresh mailbox id) fail AEAD on a
                // consumed position — not desync, don't count.
                if ctx.sessions.is_replay_message(sender, &ratchet_msg).await {
                    log::debug!(
                        "Ignoring replayed mailbox ratchet message from {}",
                        sender
                    );
                } else if ctx.sessions.has_session(sender).await {
                    // Count toward desync detection — the direct path does the
                    // same; mailbox-delivered desyncs otherwise never trigger
                    // recovery.
                    let fails = ctx.sessions.record_decrypt_failure(sender).await;
                    if fails >= 3 && ctx.sessions.should_rehandshake(sender).await {
                        log::info!(
                            "Ratchet desync with {} ({} mailbox failures) — re-handshaking",
                            sender,
                            fails
                        );
                        if let Some(tx) = crate::p2p_sender(&ctx.p2p_tx) {
                            let _ = crate::send_p2p_cmd(
                                &tx,
                                crate::p2p::P2PCommand::FetchPrekeyBundle {
                                    peer_id: sender.to_string(),
                                },
                            )
                            .await;
                        }
                    }
                }
                None
            }
        }
    } else {
        // ECDH envelope for our DHT key (senders without a ratchet session
        // use encrypt_for_recipient).
        match serde_json::from_slice::<crate::security::DHTEncryptedMessage>(content) {
            Ok(envelope) => match ctx.dht_cipher.as_ref() {
                Some(cipher) => match cipher.decrypt_message(&envelope) {
                    Ok(plaintext) => Some(plaintext),
                    Err(e) => {
                        log::warn!(
                            "Failed to decrypt mailbox envelope from {}: {}",
                            sender,
                            e
                        );
                        None
                    }
                },
                None => {
                    log::warn!("DHT cipher unavailable — cannot decrypt mailbox envelope");
                    None
                }
            },
            Err(e) => {
                log::warn!("Unrecognized mailbox envelope from {}: {}", sender, e);
                None
            }
        }
    }
}
