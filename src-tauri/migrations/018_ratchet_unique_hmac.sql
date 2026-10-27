-- CR-02: dedupe + uniqueness for ratchet_states.peer_hmac.
-- peer_id is randomized GCM ciphertext, so the PRIMARY KEY can never
-- dedupe saves — the deterministic peer_hmac is the real identity.
-- Pre-018 builds could leave duplicate rows (non-atomic DELETE+INSERT);
-- keep the freshest row per peer, then enforce uniqueness at the schema
-- level. COALESCE covers rows written before field encryption existed
-- (peer_hmac NULL — the plaintext peer_id distinguishes them).
DELETE FROM ratchet_states
WHERE rowid NOT IN (
    SELECT MAX(rowid)
    FROM ratchet_states
    GROUP BY COALESCE(peer_hmac, peer_id)
);

DROP INDEX IF EXISTS idx_ratchet_peer_hmac;
CREATE UNIQUE INDEX IF NOT EXISTS idx_ratchet_peer_hmac_unique
    ON ratchet_states(peer_hmac);
