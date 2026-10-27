-- Phase A.1: Persistent prekey storage for X3DH
CREATE TABLE IF NOT EXISTS prekeys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_type TEXT NOT NULL,           -- 'signed_prekey' | 'one_time_prekey'
    public_key BLOB NOT NULL,          -- 32 bytes
    private_key BLOB NOT NULL,         -- 32 bytes (local only, protected by DB encryption)
    is_consumed BOOLEAN DEFAULT 0,    -- for one-time prekeys
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS identity_key (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    public_key BLOB NOT NULL,
    private_key BLOB NOT NULL
);
