-- FE-A08: unread counters survive restarts. peer_id is field-encrypted;
-- equality lookups use the deterministic hmac column (unread.peer).
CREATE TABLE IF NOT EXISTS unread_counts (
    peer_id TEXT NOT NULL,
    peer_hmac TEXT PRIMARY KEY NOT NULL,
    count INTEGER NOT NULL DEFAULT 0
);
