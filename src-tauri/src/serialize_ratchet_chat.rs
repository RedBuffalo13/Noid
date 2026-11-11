//! OPT-R05: wire `RatchetChat` → serialized `RatchetMessage` — one
//! conversion shared by the self-mailbox and remote-mailbox pending
//! encoders (it was spelled out twice).

use crate::p2p::MessageType;
use crate::security::{RatchetHeader, RatchetMessage};

/// Serialize a typed RatchetChat payload back into the stored wire
/// bytes. Returns `None` for any other message type — the caller
/// decides the policy for those (ECDH wrap or keep pending).
pub fn serialize_ratchet_chat(msg_type: &MessageType) -> Option<Vec<u8>> {
    if let MessageType::RatchetChat { ciphertext, header_dh_public, header_pn, header_n } = msg_type {
        serde_json::to_vec(&RatchetMessage {
            header: RatchetHeader {
                dh_public: header_dh_public.clone(),
                pn: *header_pn,
                n: *header_n,
            },
            ciphertext: ciphertext.clone(),
        })
        .ok()
    } else {
        None
    }
}
