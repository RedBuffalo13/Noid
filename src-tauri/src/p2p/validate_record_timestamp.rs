//! SEC-1111-01: bound acceptable clock skew on signed DHT record
//! timestamps. A far-future `updated_at` / `published_at` / `generated_at`
//! would otherwise out-live every honest republish under the same key and
//! freeze the slot under the attacker's control — signature validity alone
//! does not bound the writer's wall clock.

/// Maximum allowed future skew for signed record timestamps.
/// 5 minutes tolerates ordinary NTP drift while killing "year 2099" locks.
pub const MAX_FUTURE_SKEW_SECS: i64 = 300;

/// The RFC3339 timestamp must parse and not exceed `now + MAX_FUTURE_SKEW`.
/// A `None` timestamp is acceptable where the schema marks the field
/// optional (pre-DHT-03 records) — freshness ordering still applies on top
/// and disfavours untimestamped entries.
pub fn record_timestamp_acceptable(ts: Option<&str>) -> bool {
    let Some(ts) = ts else {
        return true;
    };
    match chrono::DateTime::parse_from_rfc3339(ts) {
        Ok(t) => {
            let skew = (t.with_timezone(&chrono::Utc) - chrono::Utc::now()).num_seconds();
            skew <= MAX_FUTURE_SKEW_SECS
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rfc3339_in(secs: i64) -> String {
        (chrono::Utc::now() + chrono::Duration::seconds(secs)).to_rfc3339()
    }

    #[test]
    fn accepts_past_and_near_future_timestamps() {
        assert!(record_timestamp_acceptable(Some(&rfc3339_in(-86400))));
        assert!(record_timestamp_acceptable(Some(&rfc3339_in(0))));
        assert!(record_timestamp_acceptable(Some(&rfc3339_in(60))));
        assert!(record_timestamp_acceptable(None));
    }

    #[test]
    fn rejects_far_future_and_garbage_timestamps() {
        // 10 minutes out — beyond the 5-minute NTP slack.
        assert!(!record_timestamp_acceptable(Some(&rfc3339_in(600))));
        // The SEC-1111-01 weaponized value.
        assert!(!record_timestamp_acceptable(Some("2099-12-31T00:00:00Z")));
        assert!(!record_timestamp_acceptable(Some("not-a-date")));
    }
}
