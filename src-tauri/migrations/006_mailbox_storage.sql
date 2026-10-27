-- Phase B.1: Mailbox storage for offline messages
CREATE TABLE IF NOT EXISTS mailbox_storage (
    id TEXT PRIMARY KEY,              -- message UUID
    recipient_peer_id TEXT NOT NULL,  -- for whom
    sender_peer_id TEXT NOT NULL,     -- from whom
    encrypted_content BLOB NOT NULL,  -- ECDH-encrypted
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL      -- TTL 7 days
);
CREATE INDEX IF NOT EXISTS idx_mailbox_recipient ON mailbox_storage(recipient_peer_id);
