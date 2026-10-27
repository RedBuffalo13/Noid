-- Peer public keys decoupled from the contacts table (audit DB2):
-- save_contact_public_key used to UPDATE a contacts row that may not
-- exist yet (key arrives before ContactAccept) — a silent no-op that
-- lost the key and re-triggered PublicKeyExchange ping-pong.
-- peer_hmac is the deterministic HMAC token of the peer id — the same
-- lookup key the contacts table uses, no plaintext peer ids at rest.
CREATE TABLE IF NOT EXISTS peer_public_keys (
    peer_hmac TEXT PRIMARY KEY NOT NULL,
    public_key BLOB NOT NULL
);
