//! Route a decrypted mailbox plaintext: `NOIDMSG1:` typed payloads belong
//! to the room/contact/handshake control planes; everything else is a chat
//! message — encrypted for storage, persisted, emitted to the UI, and
//! surfaced to the OS notification bridge.

use crate::process_mailbox_item::MailboxProcessCtx;

/// Returns `true` when the plaintext was durably handled (stored or
/// consumed by a control plane) and the envelope may be acked.
pub async fn dispatch_mailbox_plaintext(
    ctx: &MailboxProcessCtx,
    sender: &str,
    msg_id: &str,
    timestamp: &str,
    plaintext: &[u8],
) -> bool {
    let text = String::from_utf8_lossy(plaintext).to_string();
    log::debug!("Decrypted mailbox message from {}", sender);
    // Save ratchet state so later restart can still decrypt subsequent
    // messages from this peer.
    let _ = ctx.sessions.save_session(&ctx.db, sender).await;

    // Typed messages (room control/invites, contact requests, re-handshakes)
    // are not chat — dispatch them through their own planes instead of
    // storing a JSON blob as a message.
    let typed_handled = match text.strip_prefix("NOIDMSG1:") {
        Some(json) => match serde_json::from_str::<crate::p2p::NoidMessage>(json) {
            Ok(msg) => match &msg.msg_type {
                crate::p2p::MessageType::RoomControl {
                    room_id,
                    wrapped_payload,
                } => {
                    crate::room_control::apply_room_control(
                        &ctx.handle,
                        room_id,
                        sender,
                        wrapped_payload,
                    )
                    .await
                }
                crate::p2p::MessageType::RoomChat { room_id, envelope } => {
                    crate::room_control::apply_room_chat(&ctx.handle, room_id, envelope)
                        .await;
                    true
                }
                crate::p2p::MessageType::RoomInvite {
                    room_id,
                    wrapped_key,
                } => {
                    crate::room_control::apply_room_invite(
                        &ctx.handle,
                        room_id,
                        sender,
                        wrapped_key,
                    )
                    .await
                }
                crate::p2p::MessageType::RoomInviteOffer {
                    room_id,
                    wrapped_meta,
                } => {
                    crate::room_control::apply_room_offer(
                        &ctx.handle,
                        room_id,
                        sender,
                        wrapped_meta,
                    )
                    .await
                }
                crate::p2p::MessageType::RoomInviteAccept { room_id } => {
                    crate::room_control::handle_room_invite_accept(
                        &ctx.handle,
                        room_id,
                        sender,
                    )
                    .await;
                    true
                }
                crate::p2p::MessageType::RoomInviteDecline { room_id } => {
                    crate::room_control::handle_room_invite_decline(
                        &ctx.handle,
                        room_id,
                        sender,
                    )
                    .await;
                    true
                }
                crate::p2p::MessageType::ContactRequest { .. }
                | crate::p2p::MessageType::ContactAccept { .. } => {
                    crate::contact_dispatch::dispatch_contact_message(
                        &ctx.handle,
                        sender,
                        &msg,
                    )
                    .await
                }
                // A mailbox-delivered handshake re-syncs a desynced pair —
                // handle it like the direct path instead of storing it as
                // chat text.
                crate::p2p::MessageType::X3DHInit {
                    identity_public,
                    ephemeral_public,
                    one_time_prekey_id,
                    identity_signature,
                } => {
                    crate::x3dh_dispatch::handle_x3dh_init(
                        &ctx.handle,
                        sender.to_string(),
                        identity_public,
                        ephemeral_public,
                        one_time_prekey_id,
                        identity_signature,
                    )
                    .await;
                    true
                }
                _ => false,
            },
            Err(_) => false,
        },
        None => false,
    };
    if typed_handled {
        return true;
    }

    let encrypted_for_storage = {
        let security_guard = ctx.security.lock().await;
        security_guard.encrypt(plaintext).ok()
    };
    match encrypted_for_storage {
        Some(enc) => {
            match ctx
                .db
                .add_message_if_absent(msg_id, sender, &ctx.my_id, &enc, timestamp)
                .await
            {
                Ok(true) => {
                    crate::safe_emit(
                        &ctx.handle,
                        "chat-msg",
                        serde_json::json!({
                            "from": sender,
                            "data": {
                                "content": &text,
                                "id": msg_id,
                                "sender": sender,
                                "timestamp": timestamp,
                            }
                        }),
                    );
                    crate::android_bridge::notify_new_message(&ctx.handle, sender);
                    true
                }
                Ok(false) => {
                    // Lost the insert race to another retrieval or a direct
                    // resend — already stored.
                    log::debug!("Mailbox message {} already stored", msg_id);
                    true
                }
                Err(e) => {
                    log::warn!("Failed to store mailbox message {}: {}", msg_id, e);
                    false
                }
            }
        }
        None => {
            log::warn!("Failed to encrypt mailbox message {} for storage", msg_id);
            false
        }
    }
}
