use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DHTUserRecord {
    pub peer_id: String,
    /// The DHT key this record is published under — bound into the signature
    /// so a record signed for "alice" cannot be replayed under "bob".
    /// Older records lacked the field (deserialized as ""); they fail the v2
    /// signature check and are rejected.
    #[serde(default)]
    pub username: String,
    pub nickname: String,
    pub avatar: Option<String>,
    pub short_id: String,
    pub updated_at: String,
    /// Ed25519 signature by `peer_id`'s identity key over the record fields —
    /// prevents DHT username squatting/spoofing. Unsigned records are rejected.
    #[serde(default)]
    pub signature: Option<Vec<u8>>,
    /// D13: tombstone — the owner released this name. kad remove_record is
    /// local-only, so revocation rides a signed record readers honor.
    #[serde(default)]
    pub revoked: bool,
}

/// Canonical bytes covered by `DHTUserRecord::signature`.
pub fn user_record_signing_payload(record: &DHTUserRecord) -> Vec<u8> {
    let mut v = Vec::with_capacity(160);
    v.extend_from_slice(b"noid-userrecord-v2");
    v.extend_from_slice(record.username.as_bytes());
    v.extend_from_slice(record.peer_id.as_bytes());
    v.extend_from_slice(record.nickname.as_bytes());
    if let Some(a) = &record.avatar {
        v.extend_from_slice(a.as_bytes());
    }
    v.extend_from_slice(record.short_id.as_bytes());
    v.extend_from_slice(record.updated_at.as_bytes());
    // Appended only when set — records signed before the field existed
    // (revoked=false) keep byte-identical payloads.
    if record.revoked {
        v.extend_from_slice(b"revoked");
    }
    v
}

/// Whether `new_rec` is strictly newer than the record already stored under
/// the same key — updated_at is signed, so a replayed older record loses.
/// An unparseable timestamp on the NEW record always loses.
pub fn user_record_is_fresher(stored_value: &[u8], new_rec: &DHTUserRecord) -> bool {
    let new_ts = chrono::DateTime::parse_from_rfc3339(&new_rec.updated_at)
        .map(|t| t.with_timezone(&chrono::Utc));
    let Some(new_ts) = new_ts.ok() else {
        return false;
    };
    let old_ts = serde_json::from_slice::<DHTUserRecord>(stored_value)
        .ok()
        .and_then(|r| {
            chrono::DateTime::parse_from_rfc3339(&r.updated_at)
                .ok()
                .map(|t| t.with_timezone(&chrono::Utc))
        });
    match old_ts {
        Some(old) => new_ts > old,
        None => true,
    }
}

/// Signed mailbox-pointer DHT record: which node holds our offline envelopes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedMailboxRecord {
    pub owner_peer_id: String,
    pub mailbox_peer_id: String,
    pub relay_addr: String,
    /// DHT-03: signed publication timestamp — lets stores reject an older
    /// replayed record instead of rolling the pointer back (LWW). Absent
    /// on pre-DHT-03 records; such records keep working but lose freshness
    /// ordering to a timestamped record of the same owner.
    #[serde(default)]
    pub published_at: Option<String>,
    /// Ed25519 signature by `owner_peer_id` over the other fields.
    pub signature: Vec<u8>,
}

/// Canonical bytes covered by `SignedMailboxRecord::signature`.
/// DHT-03: `published_at` is appended when present — records signed before
/// the field existed keep their byte-identical payload.
pub fn mailbox_record_signing_payload(rec: &SignedMailboxRecord) -> Vec<u8> {
    let mut v = Vec::with_capacity(192);
    v.extend_from_slice(b"noid-mailbox-v1");
    v.extend_from_slice(rec.owner_peer_id.as_bytes());
    v.extend_from_slice(rec.mailbox_peer_id.as_bytes());
    v.extend_from_slice(rec.relay_addr.as_bytes());
    if let Some(ts) = &rec.published_at {
        v.extend_from_slice(ts.as_bytes());
    }
    v
}

/// DHT-03: whether `new_rec` is strictly newer than the record stored under
/// the same key — published_at is signed, so a replayed older record loses.
/// A missing timestamp on either side loses to a present one (a fresh
/// republish always carries it; a replayed legacy record does not).
pub fn mailbox_record_is_fresher(stored_value: &[u8], new_rec: &SignedMailboxRecord) -> bool {
    let new_ts = new_rec
        .published_at
        .as_ref()
        .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
        .map(|t| t.with_timezone(&chrono::Utc));
    let old_ts = serde_json::from_slice::<SignedMailboxRecord>(stored_value)
        .ok()
        .and_then(|r| {
            r.published_at
                .as_ref()
                .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
                .map(|t| t.with_timezone(&chrono::Utc))
        });
    match (old_ts, new_ts) {
        (Some(old), Some(new)) => new > old,
        // Fresh timestamped record beats a legacy one; a timestamped stored
        // record beats a legacy replay.
        (Some(_), None) => false,
        (None, Some(_)) => true,
        (None, None) => true,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoidMessage {
    pub sender: String,
    pub content: String,
    pub msg_type: MessageType,
    pub timestamp: Option<String>,
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageType {
    Chat(String),
    FileOffer {
        name: String,
        size: u64,
        id: String,
    },
    FileRequest {
        id: String,
    },
    /// Room invitation delivered over the established 1:1 ratchet session:
    /// `wrapped_key` is the ratchet ciphertext of the room's AES-256 key —
    /// the key never travels in plaintext even inside the Noise channel.
    RoomInvite {
        room_id: String,
        #[serde(default)]
        wrapped_key: Vec<u8>,
    },
    /// Encrypted room control message (key updates, membership notices,
    /// metadata). `wrapped_payload` is the ratchet ciphertext of a
    /// serialized `RoomControlPayload` — E2EE like `RoomInvite`, and safe
    /// to route through pending/mailbox because the inner payload is
    /// already wrapped at send time.
    RoomControl {
        room_id: String,
        #[serde(default)]
        wrapped_payload: Vec<u8>,
    },
    /// Two-phase room invite, phase 1: the offer carries ratchet-wrapped
    /// metadata (`RoomInviteOfferPayload`: name/avatar/owner) but NO room
    /// key. The key is only delivered via `RoomInvite` after the invitee
    /// accepts — an unaccepted invite grants zero access to room traffic.
    RoomInviteOffer {
        room_id: String,
        #[serde(default)]
        wrapped_meta: Vec<u8>,
    },
    /// Two-phase room invite, phase 2: the invitee accepted — the inviter
    /// answers with the wrapped `RoomInvite` carrying the room key.
    RoomInviteAccept { room_id: String },
    /// The invitee declined the offer — the inviter drops the pending
    /// (unapproved) member row.
    RoomInviteDecline { room_id: String },
    /// Offline-capable copy of a room message: `envelope` is the
    /// serialized sealed `RoomEnvelope` (AES-256-GCM under the room key +
    /// Ed25519 sender signature) — safe over direct transport and mailbox
    /// because it is already ciphertext. Sent to every approved member in
    /// addition to the gossipsub publish; receivers dedup by `msg_id`.
    RoomChat {
        room_id: String,
        #[serde(default)]
        envelope: Vec<u8>,
    },
    JoinRoom {
        room_id: String,
    },
    ContactRequest {
        message: String,
        nickname: String,
        avatar: Option<String>,
    },
    ContactAccept {
        nickname: String,
        avatar: Option<String>,
    },
    PublicKeyExchange {
        public_key: [u8; 32],
    },
    DHTAck {
        original_message_id: String,
    },
    ReadReceipt {
        message_id: String,
    },
    TypingIndicator,
    Ping,
    Pong,
    UsernameLookup {
        username: String,
    },
    UsernameAnnounce {
        username: String,
    },
    /// Phase 3.5: X3DH initial message — sent by initiator to establish E2EE session
    X3DHInit {
        identity_public: Vec<u8>,
        ephemeral_public: Vec<u8>,
        one_time_prekey_id: Option<Vec<u8>>,
        /// S21: Ed25519 signature by the sender's Noise identity over
        /// `x3dh_init_signing_payload(...)` — binds the X3DH identity key to
        /// the peer id so a session cannot be pinned under an arbitrary key.
        /// Empty = legacy peer (accepted with a warning).
        #[serde(default)]
        identity_signature: Vec<u8>,
    },
    /// Phase 3.5: Encrypted chat message via Double Ratchet
    /// content is base64(RatchetMessage)
    RatchetChat {
        ciphertext: Vec<u8>,
        header_dh_public: Vec<u8>,
        header_pn: u32,
        header_n: u32,
    },
    /// X3DH-07: ask the peer for its signed prekey bundle directly over
    /// request_response. The DHT get_record path cannot reach anyone when
    /// the routing table is empty ("No known peers") even while a live
    /// connection carries TypingIndicator/Ping just fine — an online peer
    /// must be able to answer without a healthy DHT.
    PrekeyBundleRequest,
    /// TI-18: a variant from a newer protocol version must not fail codec
    /// deserialization — it lands here and the dispatcher drops it with an
    /// ack instead of the whole request failing to parse.
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoidResponse {
    pub status: String,
    pub data: Option<Vec<u8>>,
}

pub enum P2PEvent {
    NewListenAddr(String),
    PeerDiscovered(String, String),
    PeerConnected(String),
    PeerDisconnected(String),
    PeerOnline(String),
    MessageReceived { from: String, data: NoidMessage },
    RequestReceived { from: String, data: NoidMessage },
    MessageFailed {
        to: String,
        request_id: String,
        error: String,
        content: String,
        /// Original NoidMessage.id — needed to re-pend a failed message under
        /// its stable id instead of a fresh UUID (dedup safety).
        message_id: String,
        /// Phase 1.8: message type so the forwarder can filter — only Chat messages
        /// should be added to pending/DHT. Control messages (Ping, DHTAck, etc.)
        /// should only be logged, not retried as chat messages.
        msg_type: MessageType,
    },
    /// Phase 1.3: Emitted when a direct message is confirmed delivered (response received with OK status).
    /// The forwarder deletes the corresponding pending_message by message_id.
    MessageDelivered {
        peer_id: String,
        message_id: String,
    },
    UsernameAvailabilityChecked {
        username: String,
        available: bool,
        /// D6: `true` when the DHT query itself failed (timeout / empty
        /// routing table) — the answer is "unknown", not "available".
        uncertain: bool,
    },
    UserLookupResult {
        username: String,
        record: Option<DHTUserRecord>,
    },
    /// Phase A.3: Prekey bundle fetched from DHT for E2EE handshake
    PrekeyBundleRetrieved {
        peer_id: String,
        bundle: Option<crate::security::PrekeyBundle>,
    },
    /// Phase B.5: Messages retrieved from a mailbox node
    MailboxMessagesRetrieved {
        mailbox_peer_id: String,
        messages: Vec<MailboxMessageItem>,
    },
    /// Phase B.4: Mailbox store acknowledgement
    MailboxStoreAck {
        success: bool,
        /// Pending-row message id the ack corresponds to — the pending row
        /// may only be deleted once the mailbox confirms the store.
        /// `None` for untagged sends and Retrieve/Delete responses.
        message_id: Option<String>,
        /// Recipient the stored envelope was addressed to — scoped delete
        /// key so a mailbox ack never clears another peer's pending row.
        recipient_peer_id: String,
    },
    /// Phase B.5: Mailbox retrieve failed
    MailboxError {
        error: String,
    },
    /// F12/F14: a pending row can never be delivered (oversized envelope,
    /// permanent mailbox rejection) — the app deletes the row and
    /// surfaces the failure instead of retrying forever.
    PendingUndeliverable {
        peer_id: String,
        message_id: Option<String>,
        reason: String,
    },
    /// Phase H.1: Mailbox node found in DHT for a peer
    MailboxNodeFound {
        peer_id: String,        // чей mailbox
        mailbox_peer_id: String, // кто хранит
        relay_addr: String,
    },
    /// D18: mailbox record lookup for a peer resolved with no usable node —
    /// pending rows stay queued until the next retry tick. Lets the app
    /// layer (and logs) distinguish "peer offline" from "resolver broken".
    MailboxNodeNotFound {
        peer_id: String,
    },
    /// Full relay status snapshot (emitted on changes and on request).
    /// TI-8: NAT transitions ride this too — `RelayStatus.natStatus` already
    /// carries them, so a separate `nat-status` event was a dead duplicate.
    RelayStatusChanged {
        status: crate::p2p::relay_status::RelayStatus,
    },
    /// A verified, decrypted room message (signature + AES-GCM open OK).
    RoomMessage {
        room_id: String,
        sender: String,
        content: String,
        msg_id: String,
        ts: String,
    },
    /// A verified, decrypted room control payload that arrived inside a
    /// room-topic envelope (serialized `RoomPayload`, non-Chat variant).
    /// Delivered to the app layer because membership/meta changes need
    /// DB access the node does not have.
    RoomControl {
        room_id: String,
        sender: String,
        payload: String,
    },
    /// A room envelope verified by signature but undecryptable with the
    /// current key — the stored key epoch is stale (missed a rekey).
    /// The app layer may re-request the key from the room owner.
    RoomKeyStale {
        room_id: String,
    },
}

pub enum P2PCommand {
    SendMessage {
        peer_id: String,
        msg: NoidMessage,
    },
    ConnectToPeer {
        peer_id: String,
        addr_hint: Option<String>,
    },
    /// Dial a raw multiaddr (invite/bootstrap entry). If the addr carries a
    /// `/p2p/<peer>` component it is also seeded into the Kademlia table.
    DialAddress {
        addr: String,
    },
    /// Seed a known addr for a peer (e.g. `relay_addr` learned from a
    /// verified mailbox record — F1). Registered as trusted so mailbox
    /// store/retrieve/ack have a dialable path instead of stalling.
    SeedPeerAddr {
        peer_id: String,
        addr: String,
    },
    SendPublicKey {
        peer_id: String,
    },
    /// Application-level ack for a `RequestReceived` message — the app layer
    /// sends this only after the payload reached durable state (persisted
    /// or dispatched). The node answers the parked response channel; an
    /// absent ack lets the sender's request time out and re-pend (TI-1).
    AckReceived {
        peer_id: String,
        message_id: String,
        /// Wire response status — "OK" | "DUPLICATE".
        status: String,
    },
    /// Subscribe to a room topic. `room_key` is the decrypted AES-256 room
    /// key — membership is proven by key possession, and the node signs every
    /// published envelope with its identity key.
    JoinRoom {
        room_id: String,
        room_key: Option<[u8; 32]>,
    },
    /// Publish a sealed RoomEnvelope — plaintext only leaves this node after
    /// AES-256-GCM encryption under the room key.
    SendRoomMessage {
        room_id: String,
        content: String,
    },
    /// Publish a typed room payload (Meta/Member*/KeyEpoch) as a sealed
    /// envelope — same wire path as `SendRoomMessage`.
    SendRoomPayload {
        room_id: String,
        payload: crate::p2p::RoomPayload,
    },
    /// Seal a Chat payload, publish to the room topic (best-effort —
    /// gossipsub may have no mesh peers), and return the serialized
    /// envelope so the caller can fan it out to members as direct
    /// `MessageType::RoomChat` messages for offline delivery.
    SendRoomChat {
        room_id: String,
        content: String,
        respond_to: tokio::sync::oneshot::Sender<Result<Vec<u8>, String>>,
    },
    /// Replace the room key after a rekey. The gossipsub topic stays
    /// subscribed — the room id is stable across key generations.
    UpdateRoomKey {
        room_id: String,
        room_key: [u8; 32],
    },
    /// Unsubscribe from a room topic and drop the stored key.
    LeaveRoom {
        room_id: String,
    },
    PublishUsername {
        username: String,
        record: DHTUserRecord,
    },
    CheckUsernameAvailability {
        username: String,
    },
    LookupUser {
        username: String,
    },
    UnpublishUsername {
        username: String,
    },
    /// Phase A.3: Publish our prekey bundle to DHT
    PublishPrekeyBundle {
        peer_id: String,
        bundle: crate::security::PrekeyBundle,
    },
    /// Phase A.3: Fetch a peer's prekey bundle from DHT
    FetchPrekeyBundle {
        peer_id: String,
    },
    /// Phase B.4: Send a message to a mailbox node for offline storage
    SendToMailbox {
        mailbox_peer_id: String,
        recipient_peer_id: String,
        sender_peer_id: String,
        encrypted_content: Vec<u8>,
        /// Local pending-row message id — echoed back in `MailboxStoreAck`
        /// so the row is deleted only after a real store confirmation,
        /// not when the command merely reached the node's channel.
        client_msg_id: Option<String>,
    },
    /// Phase B.5: Retrieve messages from a mailbox node
    RetrieveFromMailbox {
        mailbox_peer_id: String,
        recipient_peer_id: String,
    },
    /// Phase B.5: Acknowledge and delete a message from a mailbox node
    AckMailboxMessage {
        mailbox_peer_id: String,
        message_id: String,
    },
    /// Phase B.3: Publish our mailbox node in DHT
    RegisterAsMailbox {
        peer_id: String,         // owner — чей mailbox
        mailbox_peer_id: String, // кто хранит (обычно наш релей)
        relay_addr: String,
    },
    /// Phase H.1: Find a mailbox node for a peer via DHT
    FindMailboxNode {
        peer_id: String,  // recipient — чей mailbox
    },
    /// Discover relay nodes via DHT provider records.
    DiscoverRelays,
    /// Request a circuit reservation on a specific relay peer.
    RequestReservation {
        relay_peer_id: String,
        relay_addr: String,
    },
    /// Renew circuit reservations on all known relays.
    RefreshReservations,
    /// Report current relay/NAT status. The fresh snapshot is sent back
    /// through `respond_to` (and also broadcast as RelayStatusChanged so the
    /// shared cache/UI stay in sync) — callers must not read the cached state
    /// right after sending this, the event may not have been processed yet.
    ReportRelayStatus {
        respond_to: tokio::sync::oneshot::Sender<crate::p2p::RelayStatus>,
    },
    /// RC9: graceful exit — flush the peer cache and let `run()` return
    /// cleanly (swarm connections close on drop) instead of being aborted
    /// mid-poll on process exit.
    Shutdown,
    /// A6: the OS reports a default-network transition (Android
    /// ConnectivityManager callback / WorkManager wake). Direct external
    /// addrs belong to the dead interface and dial backoffs recorded on it
    /// are irrelevant on the new one — drop both, then re-reserve relays
    /// (the accept path republishes the mailbox record itself).
    NetworkChanged,
}

// Phase B.2: Mailbox protocol types for offline message delivery through relay
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MailboxRequest {
    /// Store an encrypted envelope for an offline recipient
    Store {
        recipient_peer_id: String,
        sender_peer_id: String,
        encrypted_content: Vec<u8>,
        /// Ed25519 signature by `sender_peer_id` over
        /// ("noid-envelope-v1" || recipient || sender || content). Empty for
        /// legacy senders — mailboxes must reject empty signatures.
        /// When `client_msg_id` is present, the signature must instead cover
        /// `envelope_signing_payload_v2` — the id is signed too.
        #[serde(default)]
        signature: Vec<u8>,
        /// Sender's stable message id — preserved end-to-end so the same
        /// envelope arriving both direct and via mailbox dedups at the
        /// recipient (F2). When present it must be covered by the v2
        /// signature payload.
        #[serde(default)]
        client_msg_id: Option<String>,
    },
    /// Retrieve all envelopes for a recipient
    Retrieve {
        recipient_peer_id: String,
    },
    /// Acknowledge and delete a specific message
    Delete {
        message_id: String,
    },
}

/// Canonical bytes covered by a Store envelope's `signature` when a
/// `client_msg_id` rides along — the id is bound to the envelope so a
/// mailbox or relay cannot rewrite dedup identity.
pub fn envelope_signing_payload_v2(
    recipient: &str,
    sender: &str,
    client_msg_id: &str,
    content: &[u8],
) -> Vec<u8> {
    let mut v = Vec::with_capacity(96 + content.len());
    v.extend_from_slice(b"noid-envelope-v2");
    v.extend_from_slice(recipient.as_bytes());
    v.extend_from_slice(sender.as_bytes());
    v.extend_from_slice(client_msg_id.as_bytes());
    v.extend_from_slice(content);
    v
}

/// Canonical bytes covered by a Store envelope's `signature`.
pub fn envelope_signing_payload(recipient: &str, sender: &str, content: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(64 + content.len());
    v.extend_from_slice(b"noid-envelope-v1");
    v.extend_from_slice(recipient.as_bytes());
    v.extend_from_slice(sender.as_bytes());
    v.extend_from_slice(content);
    v
}

/// Canonical bytes covered by an X3DHInit's `identity_signature` (S21):
/// the sender's Noise identity key attests the X3DH identity + ephemeral.
pub fn x3dh_init_signing_payload(identity_public: &[u8], ephemeral_public: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(80);
    v.extend_from_slice(b"noid-x3dh-init-v1");
    v.extend_from_slice(identity_public);
    v.extend_from_slice(ephemeral_public);
    v
}

/// A stored mailbox envelope returned to the recipient. `signature` is the
/// sender's Ed25519 signature over `envelope_signing_payload_v2` — the
/// recipient verifies it end-to-end so a hostile mailbox cannot forge or
/// re-wrap envelopes (S6). `#[serde(default)]` tolerates peers/mailboxes
/// that still answer with unsigned items.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailboxMessageItem {
    pub id: String,
    pub sender: String,
    pub content: Vec<u8>,
    pub timestamp: String,
    #[serde(default)]
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MailboxResponse {
    /// Acknowledgement of a store/delete operation
    Ack { success: bool },
    /// Retrieved messages for the requesting recipient.
    Messages { messages: Vec<MailboxMessageItem> },
}
