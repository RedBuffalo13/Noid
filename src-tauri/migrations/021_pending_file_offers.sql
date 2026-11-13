-- SEC-1111-06: file offers wait for explicit user consent. A pending row
-- survives restarts so an offer received just before shutdown can still be
-- accepted (or declined) on next launch.
CREATE TABLE IF NOT EXISTS pending_file_offers (
    key        TEXT PRIMARY KEY,           -- "<sender_peer_id>:<offer_id>"
    sender     TEXT NOT NULL,
    name       TEXT NOT NULL,
    size       INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
