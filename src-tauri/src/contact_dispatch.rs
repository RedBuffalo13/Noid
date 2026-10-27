//! Dispatch for `ContactRequest`/`ContactAccept` messages.
//!
//! Shared between the direct `RequestReceived` path and offline delivery
//! (pending resend / mailbox retrieval), where the typed message arrives
//! re-pended as a serialized `NOIDMSG1:` envelope.

use crate::p2p::NoidMessage;
use crate::{safe_emit, AppState};
use tauri::Manager;

/// Handle a contact message from `from`. Returns `true` when `msg` was a
/// `ContactRequest`/`ContactAccept` and was dispatched (DB + `p2p-request`
/// event); `false` for any other message type.
pub(crate) async fn dispatch_contact_message(
    handle: &tauri::AppHandle,
    from: &str,
    msg: &NoidMessage,
) -> bool {
    match &msg.msg_type {
        crate::p2p::MessageType::ContactRequest {
            message,
            nickname,
            avatar,
        } => {
            let app_state = handle.state::<AppState>();
            // Save contact request first, then decide whether to send our key
            let should_send_key = {
                let db_state = app_state.db.lock().await;
                if let Some(db) = db_state.as_ref() {
                    let _ = db
                        .add_contact_request(from, message, nickname, avatar.as_deref())
                        .await;
                    // Only send our key if we don't already have theirs (avoid ping-pong)
                    matches!(db.get_contact_public_key(from).await, Ok(None))
                } else {
                    false
                }
            };
            safe_emit(handle, "p2p-request", (from.to_string(), msg.clone()));

            if should_send_key {
                if let Some(tx) = app_state.p2p() {
                    let _ = tx
                        .send(crate::p2p::P2PCommand::SendPublicKey {
                            peer_id: from.to_string(),
                        })
                        .await;
                    log::debug!("Sent public key to contact request sender {} (no key on file)", from);
                }
            }
            true
        }
        crate::p2p::MessageType::ContactAccept { nickname, avatar } => {
            let app_state = handle.state::<AppState>();
            let db_state = app_state.db.lock().await;
            if let Some(db) = db_state.as_ref() {
                // S16: an accept is only legit as a reply to a request WE
                // sent — an unsolicited accept is parked as a regular
                // contact request for the user to decide on.
                if db
                    .has_outgoing_contact_request(from)
                    .await
                    .unwrap_or(false)
                {
                    let _ = db.add_contact(from, nickname, avatar.as_deref()).await;
                    let _ = db.delete_outgoing_contact_request(from).await;
                } else {
                    log::warn!(
                        "Unsolicited ContactAccept from {} — parked as contact request",
                        from
                    );
                    let _ = db
                        .add_contact_request(from, "accepted contact request", nickname, avatar.as_deref())
                        .await;
                }
            }
            // TI-6: an accept is not a request — dedicated event so the UI
            // can say "request accepted" instead of "New contact request".
            safe_emit(handle, "contact-accepted", (from.to_string(), msg.clone()));
            true
        }
        _ => false,
    }
}
