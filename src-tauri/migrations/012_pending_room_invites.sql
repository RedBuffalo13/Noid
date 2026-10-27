-- Pending room invites: a received RoomInviteOffer awaits explicit user
-- accept/decline. The room key is NOT stored here — it is only delivered
-- (ratchet-wrapped RoomInvite) after the user accepts, so an unaccepted
-- invite grants zero access to room traffic.

CREATE TABLE IF NOT EXISTS pending_room_invites (
    room_id TEXT PRIMARY KEY,
    inviter_peer_id TEXT NOT NULL,    -- field-encrypted
    inviter_hmac TEXT,                -- deterministic HMAC lookup token
    name TEXT,                        -- field-encrypted (room display name)
    avatar TEXT,                      -- field-encrypted (data-URL)
    received_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
