//! Privacy-preserving log redaction.
//!
//! Routine logs must not leak routable IP addresses or full PeerIds — a
//! shared log file (bug report, console capture) would otherwise reveal
//! who the user talks to and from where. `redact` is applied by every
//! logger in the app: tauri-plugin-log in the GUI and env_logger in
//! headless relay mode. The security audit_log is NOT routed through
//! this — it is an encrypted-dir journal wiped by KillPin, and its
//! forensic value depends on exact identifiers.

use regex::Regex;
use std::sync::OnceLock;

fn ipv4_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").expect("ipv4 regex"))
}

fn ipv6_candidate_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // Any hex/colon run with ≥2 colons, plus leading-compressed forms
    // (`::1`, `::ffff`) that can't carry a word boundary. Candidates are
    // post-filtered by `looks_like_ipv6` so RFC3339 times ("12:34:56")
    // survive.
    RE.get_or_init(|| {
        Regex::new(r"(?i)\b[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,}\b|::[0-9a-f:]{1,38}")
            .expect("ipv6 regex")
    })
}

/// A hex/colon run is an IPv6 address when it is compressed (contains
/// `::`) or spells out ≥4 groups — three plain groups like `12:34:56`
/// are far more likely a timestamp than an address.
fn looks_like_ipv6(candidate: &str) -> bool {
    candidate.contains("::") || candidate.matches(':').count() >= 3
}

fn peer_id_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // base58btc multihash peer ids: ed25519 `12D3KooW…` (~52 chars) and
    // legacy RSA `Qm…` (46 chars). 20+ trailing chars avoids matching
    // ordinary words that happen to share the prefix.
    RE.get_or_init(|| {
        Regex::new(r"\b(?:12D3KooW|Qm)[1-9A-HJ-NP-Za-km-z]{20,}\b").expect("peerid regex")
    })
}

/// Redact IPs and PeerIds in a log message.
/// - IPv4 / IPv6 literals → `<ip>`
/// - PeerIds → first 8 characters + `…`
pub fn redact(input: &str) -> String {
    let out = ipv4_re().replace_all(input, "<ip>");
    let out = ipv6_candidate_re().replace_all(&out, |caps: &regex::Captures| {
        if looks_like_ipv6(&caps[0]) {
            "<ip>".to_string()
        } else {
            caps[0].to_string()
        }
    });
    peer_id_re()
        .replace_all(&out, |caps: &regex::Captures| {
            format!("{}…", caps[0].chars().take(8).collect::<String>())
        })
        .into_owned()
}

/// Shared line format for both loggers: `[LEVEL target] message` with the
/// message body redacted.
pub fn format_record(record: &log::Record) -> String {
    format!(
        "[{} {}] {}",
        record.level(),
        record.target(),
        redact(&record.args().to_string())
    )
}
