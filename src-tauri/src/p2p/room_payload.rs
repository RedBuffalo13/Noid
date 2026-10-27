//! Room wire payloads.
//!
//! Two channels carry room data:
//!
//! * `RoomPayload` — serialized JSON inside a sealed `RoomEnvelope` on the
//!   room's gossipsub topic. Readable by every current key holder.
//! * `RoomControlPayload` — serialized JSON ratchet-wrapped inside a direct
//!   `MessageType::RoomControl` request. Point-to-point E2EE between two
//!   peers — used for key distribution and membership notices that must
//!   reach exactly one peer (including offline via mailbox).
//!
//! Legacy envelopes whose plaintext does not parse as `RoomPayload` are
//! treated as `Chat` for backward compatibility.

use serde::{Deserialize, Serialize};

/// A room member's profile as exchanged inside invite/control payloads.
/// `peer_id` is the member's identity; name/avatar are best-effort
/// snapshots — refreshed later by `MemberProfile` self-announces.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoomMemberProfile {
    pub peer_id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub avatar: Option<String>,
}

/// Payload inside a sealed room-topic envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "camelCase")]
pub enum RoomPayload {
    /// Regular chat text.
    Chat {
        content: String,
    },
    /// Room metadata changed (name/avatar) — sent post-change.
    Meta {
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        avatar: Option<String>,
    },
    /// A member was added (announce under the key they already hold).
    /// name/avatar are the owner's view of the member's profile.
    MemberJoined {
        peer_id: String,
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        avatar: Option<String>,
    },
    /// A member announces its own profile (name/avatar) — self-published,
    /// receivers must verify `peer_id` equals the envelope sender.
    MemberProfile {
        peer_id: String,
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        avatar: Option<String>,
    },
    /// A member was kicked — published AFTER rekey under the new key so
    /// the removed peer cannot read it.
    MemberRemoved {
        peer_id: String,
    },
    /// A member left voluntarily.
    MemberLeft {
        peer_id: String,
    },
    /// Key rotated — lets a member that missed the direct KeyUpdate see
    /// that its stored epoch is stale.
    KeyEpoch {
        epoch: u32,
    },
}

/// Payload inside a ratchet-wrapped `MessageType::RoomControl` — the
/// control plane that survives offline delivery (pending/mailbox path).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "camelCase")]
pub enum RoomControlPayload {
    /// Owner → remaining member: new room key after a rekey.
    /// Applied only when `epoch` is newer than the locally stored epoch.
    KeyUpdate {
        epoch: u32,
        key: Vec<u8>,
    },
    /// Owner → kicked member: "you were removed". The member deletes the
    /// room locally and unsubscribes.
    Removed {
        by: String,
    },
    /// Member → owner: "I left" — triggers an owner-side rekey.
    MemberLeft {
        peer_id: String,
    },
    /// Owner → member: room metadata changed (name/avatar).
    /// `owner` is a self-declared owner for legacy ownerless rooms —
    /// applied only while the local record has no valid owner and only
    /// when it equals the (ratchet-authenticated) sender.
    Meta {
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        avatar: Option<String>,
        #[serde(default)]
        owner: Option<String>,
    },
    /// Owner → member: the room was deleted.
    Deleted,
    /// Member → owner: my stored epoch is stale — please resend the key.
    /// Sent when a signed envelope fails to open (missed a rekey while
    /// offline AND the reconnect-resend raced us).
    KeySyncRequest {
        epoch: u32,
    },
}

/// Room invite body — ratchet-wrapped key plus metadata so the invitee's
/// client can display the room immediately without a second round trip.
/// `key` is a Vec (not [u8;32]) for serde-tolerant length checking.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoomInvitePayload {
    pub key: Vec<u8>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub avatar: Option<String>,
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub epoch: u32,
    /// Owner's view of the current roster (owner + approved members) —
    /// lets the invitee populate its member list immediately.
    #[serde(default)]
    pub members: Vec<RoomMemberProfile>,
}

/// Room invite OFFER body — same metadata as [`RoomInvitePayload`] but no
/// key. Sent as the ratchet-wrapped payload of `RoomInviteOffer`; the key
/// only follows after the invitee accepts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoomInviteOfferPayload {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub avatar: Option<String>,
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub epoch: u32,
    /// Owner's view of the roster — shown in the pending-invite UI as
    /// "N members" before the invitee commits.
    #[serde(default)]
    pub members: Vec<RoomMemberProfile>,
}
