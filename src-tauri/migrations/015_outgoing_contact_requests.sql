-- S16: track contact requests WE sent so an unsolicited ContactAccept can be
-- told apart from a legit reply (previously any peer could force-add itself).
CREATE TABLE IF NOT EXISTS outgoing_contact_requests (
    peer_id TEXT PRIMARY KEY,
    peer_hmac TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_outgoing_contact_requests_hmac ON outgoing_contact_requests(peer_hmac);
