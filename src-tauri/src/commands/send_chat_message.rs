use base64::Engine as _;
use crate::p2p::{MessageType, P2PCommand, NoidMessage};
use crate::security::RatchetMessage;
use crate::AppState;
use tauri::State;
use uuid::Uuid;

/// Validate message size and peer id at the IPC boundary — an invalid peer
/// id would be silently dropped in the event loop and the pending row would
/// linger forever.
fn validate_input(peer_id: &str, content: &str) -> Result<(), String> {
    if content.len() > crate::p2p::MAX_DHT_MESSAGE_SIZE {
        return Err(format!(
            "Message too large: {} bytes (max {} bytes)",
            content.len(),
            crate::p2p::MAX_DHT_MESSAGE_SIZE
        ));
    }
    if peer_id.len() > 128 || peer_id.parse::<libp2p::PeerId>().is_err() {
        return Err("Invalid peer id".into());
    }
    Ok(())
}

/// Persist the local copy of the sent message (history). Lock-order rule:
/// encrypt under `security` first, release, then write via a db snapshot —
/// never hold the db guard across `security.lock()` (RC2).
async fn persist_local_copy(msg_id: &str, my_id: &str, peer_id: &str, content: &str, state: &State<'_, AppState>) {
    let encrypted_for_storage = {
        let security = state.security.lock().await;
        match security.encrypt(content.as_bytes()) {
            Ok(enc) => Some(enc),
            Err(_) => {
                log::error!("Failed to encrypt message for storage");
                None
            }
        }
    };
    if let Some(encrypted_for_storage) = encrypted_for_storage {
        if let Ok(db) = state.require_db().await {
            if let Err(e) = db
                .add_message(msg_id, my_id, peer_id, &encrypted_for_storage)
                .await
            {
                log::error!("Failed to save message to database: {}", e);
            }
        }
    }
}

/// Outcome of preparing a wire ciphertext — the three failure modes have
/// different recoveries and must not collapse into one "try handshake".
enum WirePrepared {
    /// Ciphertext produced AND the advanced ratchet state durably saved.
    Encrypted(RatchetMessage),
    /// No session at all — queue and run X3DH.
    NoSession,
    /// A session exists but its send chain is not initialised (Bob before
    /// the first inbound DH ratchet) — queue; flush on readiness.
    NotReady,
    /// Encrypt advanced in-memory state but the durable save failed —
    /// emitting the ciphertext would let a restart reuse a stale chain
    /// position, so it must NOT be sent. Queue; the pending flush
    /// re-encrypts (skipped keys on the peer cover the unused position).
    PersistFailed,
}

/// Encrypt for the wire with Double Ratchet, lazily restoring the session
/// from the DB. SEC-A08: a wire ciphertext is only released once its
/// post-encrypt ratchet state is durably committed.
async fn encrypt_for_wire(peer_id: &str, content: &str, state: &State<'_, AppState>) -> WirePrepared {
    if !state.ratchet_sessions.has_session(peer_id).await {
        if let Ok(db) = state.require_db().await {
            let _ = state.ratchet_sessions.load_session(&db, peer_id).await;
        }
    }
    if !state.ratchet_sessions.has_session(peer_id).await {
        log::debug!("No ratchet session with {}, queuing message + initiating X3DH", peer_id);
        return WirePrepared::NoSession;
    }
    if !state.ratchet_sessions.can_send(peer_id).await {
        // NET-A01: Bob-side session waiting on the peer's first DH
        // ratchet — queue instead of emitting a public-derivable key or
        // starting a redundant handshake.
        return WirePrepared::NotReady;
    }
    match state.ratchet_sessions.encrypt(peer_id, content.as_bytes()).await {
        Ok(Some(ratchet_msg)) => {
            log::debug!("Message encrypted with Double Ratchet for {}", peer_id);
            let db = match state.require_db().await {
                Ok(db) => db,
                Err(e) => {
                    log::error!("Ratchet state save unavailable for {}: {} — refusing wire send", peer_id, e);
                    return WirePrepared::PersistFailed;
                }
            };
            if let Err(e) = state.ratchet_sessions.save_session(&db, peer_id).await {
                log::error!("Ratchet state persist failed for {}: {} — refusing wire send", peer_id, e);
                return WirePrepared::PersistFailed;
            }
            WirePrepared::Encrypted(ratchet_msg)
        }
        Ok(None) => WirePrepared::NoSession,
        Err(e) => {
            log::warn!("Ratchet encryption failed for {}: {}, queuing message", peer_id, e);
            WirePrepared::NotReady
        }
    }
}

/// Always save to pending_messages — cleared after delivery confirmation
/// (or mailbox ack). Stored AES-256-GCM encrypted under the "msg" domain
/// key ("enc2:" + base64) — no plaintext bodies at rest.
async fn persist_pending(peer_id: &str, content: &str, msg_id: &str, state: &State<'_, AppState>) {
    let stored_content = {
        let security = state.security.lock().await;
        security
            .encrypt(content.as_bytes())
            .ok()
            .map(|enc| format!("enc2:{}", base64::engine::general_purpose::STANDARD.encode(&enc)))
    };
    match stored_content {
        Some(enc_content) => {
            if let Ok(db) = state.require_db().await {
                let _ = db.add_pending_message_with_content(peer_id, &enc_content, msg_id).await;
            }
        }
        None => {
            // No master key — refuse to persist plaintext; the live send
            // below still proceeds, the message just won't survive a retry.
            log::error!("Cannot persist pending message for {}: master key unavailable", peer_id);
        }
    }
}

/// No session — the message stays pending while we fetch the peer's prekey
/// bundle from the DHT and run X3DH (Phase G.2 completes the send).
async fn request_handshake(peer_id: &str, state: &State<'_, AppState>) {
    if let Some(tx) = state.p2p() {
        log::info!("Fetching prekey bundle from DHT for {}", peer_id);
        let _ = crate::send_p2p_cmd(&tx, P2PCommand::FetchPrekeyBundle {
            peer_id: peer_id.to_string(),
        }).await;
    }
}

async fn dispatch_wire_message(
    peer_id: &str,
    my_id: String,
    msg_id: String,
    ratchet_msg: RatchetMessage,
    state: &State<'_, AppState>,
) -> Result<(), String> {
    let msg = NoidMessage {
        sender: my_id,
        // Plaintext never rides alongside ratchet ciphertext on the wire —
        // the receiver fills content after decrypting.
        content: String::new(),
        msg_type: MessageType::RatchetChat {
            ciphertext: ratchet_msg.ciphertext,
            header_dh_public: ratchet_msg.header.dh_public,
            header_pn: ratchet_msg.header.pn,
            header_n: ratchet_msg.header.n,
        },
        timestamp: Some(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
        id: msg_id,
    };
    let tx = state.require_p2p()?;
    log::info!("dispatch_wire_message: SendMessage queued for {}", peer_id);
    crate::send_p2p_cmd(&tx, P2PCommand::SendMessage {
        peer_id: peer_id.to_string(),
        msg,
    })
    .await
    .map_err(|e| format!("P2P channel closed: {}", e))
}

#[tauri::command]
/// Returns the generated message id — the frontend attaches it to the
/// optimistic bubble so `message-delivered`/`message-failed`/`message-read`
/// events match by id instead of content+timestamp (FE-23).
pub async fn send_chat_message(
    peer_id: String,
    content: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    log::info!("send_chat_message invoked for {}", peer_id);
    validate_input(&peer_id, &content)?;
    crate::ensure_peer_connection(&state, &peer_id).await?;
    log::info!("send_chat_message: connection ensured for {}", peer_id);

    let my_id = state.my_id.lock().await.clone();
    let msg_id = Uuid::new_v4().to_string();

    // Durable prepare order: pending row first (survives a crash before
    // the wire send), then encrypt + ratchet-state commit, then wire.
    persist_pending(&peer_id, &content, &msg_id, &state).await;
    log::info!("send_chat_message: outbox persistence finished id={}", msg_id);
    persist_local_copy(&msg_id, &my_id, &peer_id, &content, &state).await;
    log::info!("send_chat_message: history persistence finished id={}", msg_id);
    let prepared = encrypt_for_wire(&peer_id, &content, &state).await;

    match prepared {
        WirePrepared::NoSession => {
            log::info!("send_chat_message: no ratchet session for {} — handshake requested", peer_id);
            request_handshake(&peer_id, &state).await;
            Ok(msg_id)
        }
        WirePrepared::NotReady => {
            // Session exists but its send chain awaits the peer's first DH
            // ratchet — the pending flush retries once it is ready.
            log::info!("send_chat_message: session with {} not send-ready — message stays pending", peer_id);
            Ok(msg_id)
        }
        WirePrepared::PersistFailed => {
            log::error!("send_chat_message: ratchet state not durable for {} — message stays pending", peer_id);
            Ok(msg_id)
        }
        WirePrepared::Encrypted(ratchet_msg) => {
            log::info!("send_chat_message: dispatching RatchetChat to {}", peer_id);
            dispatch_wire_message(&peer_id, my_id, msg_id.clone(), ratchet_msg, &state)
                .await?;
            Ok(msg_id)
        }
    }
}
