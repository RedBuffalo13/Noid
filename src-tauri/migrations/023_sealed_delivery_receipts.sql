-- META-02 (S13): end-to-end delivery receipts for sealed-sender mailbox
-- items. The recipient echoes the sealed `ref_id` back inside the ratchet;
-- this table dedups receipts so a replayed or k=2-duplicated receipt only
-- updates the UI once. Rows prune via periodic cleanup.
CREATE TABLE IF NOT EXISTS delivery_receipts (
    ref_id        TEXT NOT NULL,
    sender_hmac   BLOB NOT NULL,
    received_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (ref_id, sender_hmac)
);
