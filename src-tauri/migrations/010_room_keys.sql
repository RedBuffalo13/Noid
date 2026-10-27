-- Encrypted rooms: per-room key material + room message history.
-- key_material is field-encrypted (AES-256-GCM under the master key).

ALTER TABLE rooms ADD COLUMN key_material BLOB;
-- name is field-encrypted; name_hmac is a migration marker column.
ALTER TABLE rooms ADD COLUMN name_hmac TEXT;
-- room_members.peer_hmac already exists (added in 009_field_encryption).

CREATE TABLE IF NOT EXISTS room_messages (
    id TEXT PRIMARY KEY,
    room_id TEXT NOT NULL,
    sender_peer_id TEXT NOT NULL,   -- field-encrypted
    sender_hmac TEXT,
    content BLOB NOT NULL,          -- field-encrypted
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_room_messages_room ON room_messages(room_id);
