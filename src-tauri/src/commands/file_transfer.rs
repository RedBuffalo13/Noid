use crate::p2p::{NoidMessage, MessageType};
use crate::AppState;
use tauri::State;
use base64::Engine;

/// S19: a 64 MiB offer cap — chunks ride FileOffer envelopes, so an
/// unbounded file would serialize/base64 multi-GB into the reqresp path.
const MAX_FILE_BYTES: u64 = 64 << 20;
/// Single wire chunk cap — reqresp frames are not sized for bigger blobs.
// MD-04: 64 KiB, not 1 MiB — the JSON request-response codec frame cap is
// 1 MiB and base64+envelope overhead expands a raw chunk ~1.4x, so a 1 MiB
// logical chunk could never cross the wire.
const MAX_CHUNK_BYTES: usize = 64 * 1024;

/// MD-04: file payloads are Double-Ratchet E2EE — each offer/chunk rides a
/// RatchetChat message whose plaintext is `NOIDFILE1:{json}`. A mailbox or
/// relay between the endpoints sees only ciphertext, and the receiver's
/// decrypt path routes the marker to `file_inbox` instead of the chat log.
const FILE_MARKER: &str = "NOIDFILE1:";

/// Ratchet-wrap `plaintext` for `peer_id`: lazy-load the session, encrypt,
/// persist the chain, and build the RatchetChat envelope. When no session
/// exists anywhere, kicks off FetchPrekeyBundle so the X3DH recovery cycle
/// starts — the caller still pends the message for the retry tick.
async fn wrap_ratchet_payload(
    state: &AppState,
    peer_id: &str,
    plaintext: &str,
    msg_id: &str,
) -> Result<NoidMessage, String> {
    if !state.ratchet_sessions.has_session(peer_id).await {
        if let Some(db) = state.db.lock().await.as_ref() {
            let _ = state.ratchet_sessions.load_session(db, peer_id).await;
        }
        if !state.ratchet_sessions.has_session(peer_id).await {
            // No session anywhere — start the X3DH cycle; the pending row
            // keeps the payload until the flush can encrypt for real.
            if let Some(tx) = state.p2p() {
                let _ = crate::send_p2p_cmd(&tx, crate::p2p::P2PCommand::FetchPrekeyBundle {
                    peer_id: peer_id.to_string(),
                })
                .await;
            }
            return Err("No E2EE session with this peer — X3DH started, retry shortly".to_string());
        }
    }
    let ratchet_msg = state
        .ratchet_sessions
        .encrypt(peer_id, plaintext.as_bytes())
        .await
        .map_err(|e| e.to_string())?
        .ok_or("No E2EE session with this peer")?;
    // Persist the advanced chain — a restart between encrypt and save used
    // to desync the pair (send_n rewound → peer's AEAD fails forever).
    if let Some(db) = state.db.lock().await.as_ref() {
        let _ = state.ratchet_sessions.save_session(db, peer_id).await;
    }
    let my_id = state.my_id.lock().await.clone();
    Ok(NoidMessage {
        sender: my_id,
        content: String::new(),
        msg_type: MessageType::RatchetChat {
            ciphertext: ratchet_msg.ciphertext,
            header_dh_public: ratchet_msg.header.dh_public,
            header_pn: ratchet_msg.header.pn,
            header_n: ratchet_msg.header.n,
        },
        timestamp: Some(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
        id: msg_id.to_string(),
    })
}

#[tauri::command]
pub async fn send_file_offer(
    peer_id: String,
    file_name: String,
    file_size: u64,
    state: State<'_, AppState>,
) -> Result<String, String> {
    crate::validation::parse_peer_id(&peer_id)?;
    crate::validation::bounded_str("file_name", &file_name, 256)?;
    if file_name.is_empty() || file_name.contains(['/', '\\', '\0']) {
        return Err("Invalid file name".to_string());
    }
    if file_size == 0 || file_size > MAX_FILE_BYTES {
        return Err(format!("File size must be 1..{} bytes", MAX_FILE_BYTES));
    }
    let offer_id = uuid::Uuid::new_v4().to_string();

    let offer_data = format!(
        "{}{}",
        FILE_MARKER,
        serde_json::json!({
            "kind": "offer",
            "offer_id": &offer_id,
            "file_name": &file_name,
            "file_size": file_size,
        })
    );

    let msg = wrap_ratchet_payload(&state, &peer_id, &offer_data, &offer_id).await?;

    // F13/MD-04: pending-first — the row stays until MessageDelivered, so a
    // dead conn or mailbox hop retries instead of losing the offer.
    crate::pend_typed_message(&state, &peer_id, &msg).await;
    let tx = state.require_p2p()?;
    crate::send_p2p_cmd(&tx, crate::p2p::P2PCommand::SendMessage { peer_id, msg })
        .await
        .map_err(|e| e.to_string())?;

    Ok(offer_id)
}

#[tauri::command]
pub async fn send_file_chunk(
    peer_id: String,
    offer_id: String,
    chunk_index: u32,
    total_chunks: u32,
    data: Vec<u8>,
    state: State<'_, AppState>,
) -> Result<(), String> {
    crate::validation::parse_peer_id(&peer_id)?;
    crate::validation::bounded_str("offer_id", &offer_id, 64)?;
    if total_chunks == 0 || chunk_index >= total_chunks {
        return Err("Invalid chunk index".to_string());
    }
    if data.is_empty() || data.len() > MAX_CHUNK_BYTES {
        return Err(format!("Chunk size must be 1..{} bytes", MAX_CHUNK_BYTES));
    }

    let chunk_data = format!(
        "{}{}",
        FILE_MARKER,
        serde_json::json!({
            "kind": "chunk",
            "offer_id": &offer_id,
            "chunk_index": chunk_index,
            "total_chunks": total_chunks,
            "data": base64::engine::general_purpose::STANDARD.encode(&data),
        })
    );

    let msg_id = format!("{}-{}", offer_id, chunk_index);
    let msg = wrap_ratchet_payload(&state, &peer_id, &chunk_data, &msg_id).await?;

    // Pending-first — the row is deleted on MessageDelivered/MailboxStoreAck,
    // giving the chunk mailbox + retry semantics for free.
    crate::pend_typed_message(&state, &peer_id, &msg).await;
    let tx = state.require_p2p()?;
    crate::send_p2p_cmd(&tx, crate::p2p::P2PCommand::SendMessage { peer_id, msg })
        .await
        .map_err(|e| e.to_string())?;

    Ok(())
}
