-- Initial schema for Noid Messenger

CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    sender_id TEXT NOT NULL,
    receiver_id TEXT NOT NULL,
    content BLOB NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS contacts (
    id TEXT PRIMARY KEY,
    nickname TEXT,
    avatar BLOB,
    public_key BLOB,
    is_blocked BOOLEAN DEFAULT 0
);

CREATE TABLE IF NOT EXISTS rooms (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS room_members (
    room_id TEXT NOT NULL,
    peer_id TEXT NOT NULL,
    is_approved BOOLEAN DEFAULT 0,
    PRIMARY KEY (room_id, peer_id)
);

CREATE TABLE IF NOT EXISTS shared_folders (
    id TEXT PRIMARY KEY,
    path TEXT NOT NULL,
    is_public BOOLEAN DEFAULT 1,
    password_hash TEXT
);

CREATE TABLE IF NOT EXISTS contact_requests (
    sender_id TEXT PRIMARY KEY,
    message TEXT,
    nickname TEXT,
    avatar TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS profile (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    nickname TEXT,
    avatar TEXT
);

INSERT OR IGNORE INTO profile (id, nickname, avatar) VALUES (1, 'NoidUser', NULL);

CREATE TABLE IF NOT EXISTS pending_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    peer_id TEXT,
    content TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);
