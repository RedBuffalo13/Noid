-- Room administration: stable room identity decoupled from the rotating
-- AES-256 room key, plus owner/avatar/epoch bookkeeping.
--
-- room_id is now a random identifier (no longer a key fingerprint) so the
-- gossipsub topic and message history survive key rotation after
-- membership changes. key_epoch tracks which generation of key_material
-- is current — members ignore KeyUpdates older than their stored epoch.

ALTER TABLE rooms ADD COLUMN owner_peer_id TEXT;  -- field-encrypted
ALTER TABLE rooms ADD COLUMN owner_hmac TEXT;     -- HMAC lookup token
ALTER TABLE rooms ADD COLUMN avatar TEXT;         -- field-encrypted (data-URL)
ALTER TABLE rooms ADD COLUMN key_epoch INTEGER NOT NULL DEFAULT 0;
