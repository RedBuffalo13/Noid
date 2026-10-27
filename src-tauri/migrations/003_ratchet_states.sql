-- Store ratchet states for forward secrecy
CREATE TABLE IF NOT EXISTS ratchet_states (
    peer_id TEXT PRIMARY KEY,
    state BLOB NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
