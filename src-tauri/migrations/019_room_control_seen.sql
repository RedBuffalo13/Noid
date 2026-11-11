-- NET-A07: durable dedup for room control payloads. The in-memory
-- seen_room_msgs cache empties on restart — a re-published control op
-- within the 30-day freshness window would re-apply (e.g. re-remove a
-- re-added member). Persist applied control ids per room.
CREATE TABLE IF NOT EXISTS room_control_seen (
    room_id TEXT NOT NULL,
    control_id TEXT NOT NULL,
    applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (room_id, control_id)
);
CREATE INDEX IF NOT EXISTS idx_room_control_seen_time ON room_control_seen(applied_at);
