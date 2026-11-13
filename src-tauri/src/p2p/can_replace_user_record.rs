//! SEC-1111-01: ownership-continuity policy for `noid:username:*` records.
//!
//! A live (non-revoked) record keeps its owner for its TTL: only the SAME
//! `peer_id` may publish a fresher record — another peer's signed claim is
//! refused even when it carries a newer (bounded) timestamp. A `revoked`
//! tombstone signed by the former owner releases the name: a different
//! `peer_id` may then take it over with a strictly newer timestamp.
//!
//! Timestamps are signed fields; far-future values are rejected upstream
//! by `validate_record_timestamp` before this policy is consulted.

use crate::p2p::types::DHTUserRecord;

/// Whether `new_rec` may replace `stored` under the same username key.
pub fn can_replace_user_record(stored: &DHTUserRecord, new_rec: &DHTUserRecord) -> bool {
    if !stored.revoked && stored.peer_id != new_rec.peer_id {
        return false;
    }
    let new_ts = chrono::DateTime::parse_from_rfc3339(&new_rec.updated_at)
        .map(|t| t.with_timezone(&chrono::Utc));
    let old_ts = chrono::DateTime::parse_from_rfc3339(&stored.updated_at)
        .map(|t| t.with_timezone(&chrono::Utc));
    match (old_ts.ok(), new_ts.ok()) {
        (Some(old), Some(new)) => new > old,
        // An unparseable incoming timestamp never wins; an unparseable
        // stored one yields to anything signed and fresh-dated.
        (Some(_), None) => false,
        (None, _) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(peer: &str, updated_at: &str, revoked: bool) -> DHTUserRecord {
        DHTUserRecord {
            peer_id: peer.to_string(),
            username: "alice".to_string(),
            nickname: String::new(),
            avatar: None,
            short_id: String::new(),
            updated_at: updated_at.to_string(),
            signature: None,
            revoked,
        }
    }

    #[test]
    fn live_record_keeps_its_owner_regardless_of_timestamp() {
        let stored = rec("peerA", "2026-11-11T00:00:00Z", false);
        // Attack vector: signed-by-B record with a far-future date must not
        // displace A's live record (the skew check kills 2099 even earlier).
        let hijack = rec("peerB", "2026-11-12T00:00:00Z", false);
        assert!(!can_replace_user_record(&stored, &hijack));
        // Same-owner refresh stays allowed.
        let refresh = rec("peerA", "2026-11-11T01:00:00Z", false);
        assert!(can_replace_user_record(&stored, &refresh));
        // Same-owner STALE refresh still loses.
        let stale = rec("peerA", "2026-11-10T00:00:00Z", false);
        assert!(!can_replace_user_record(&stored, &stale));
    }

    #[test]
    fn tombstone_releases_the_name_to_a_newer_claim() {
        let tombstone = rec("peerA", "2026-11-11T00:00:00Z", true);
        let takeover = rec("peerB", "2026-11-11T01:00:00Z", false);
        assert!(can_replace_user_record(&tombstone, &takeover));
        // But not to an older/equal claim — a replayed pre-revocation record
        // cannot resurrect the name under another owner.
        let older = rec("peerB", "2026-11-10T00:00:00Z", false);
        assert!(!can_replace_user_record(&tombstone, &older));
    }
}
