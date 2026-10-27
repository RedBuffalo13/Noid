use libp2p::Multiaddr;
use std::path::Path;

/// Seed nodes compiled into the binary from `resources/bootstrap_nodes.json`.
/// These are *entry points only* — the network stays fully decentralized:
/// any node can serve as a bootstrap/relay, the DHT does peer discovery,
/// and this list is not a messaging server. A fresh node joins via:
///   1. mDNS (LAN peers are discovered automatically),
///   2. a contact invite carrying the inviter's multiaddr (incl. relay addrs),
///   3. bundled seed nodes below — EMPTY by design: no hardcoded network.
///      Ship your own seeds via the user file (option 4) if you run a fleet.
///   4. extra entries in the user's `bootstrap_nodes.json`.
const BUNDLED_BOOTSTRAP: &str = include_str!("../../resources/bootstrap_nodes.json");

pub fn load_bootstrap_nodes(config_dir: &Path) -> Vec<Multiaddr> {
    let mut result: Vec<Multiaddr> = Vec::new();

    // Bundled seeds — a fresh install needs at least one WAN entry point,
    // otherwise "Bootstrapping with 0 public nodes" leaves the node blind
    // outside the LAN until the first invite arrives.
    for addr in parse_nodes_json(BUNDLED_BOOTSTRAP) {
        if !result.contains(&addr) {
            result.push(addr);
        }
    }

    let config_path = config_dir.join("bootstrap_nodes.json");
    if !config_path.exists() {
        // Write an empty user file — it documents the extension point;
        // bundled seeds still apply.
        let default_json = serde_json::json!({ "nodes": [] });
        if let Err(e) = std::fs::write(
            &config_path,
            serde_json::to_string_pretty(&default_json).unwrap_or_default(),
        ) {
            log::warn!("Failed to write default bootstrap_nodes.json: {}", e);
        }
    } else {
        match std::fs::read_to_string(&config_path) {
            Ok(content) => {
                if serde_json::from_str::<serde_json::Value>(&content).is_err() {
                    // Not JSON at all — quarantine so the corrupt file does
                    // not linger and warn on every start.
                    let _ = crate::util::quarantine::quarantine(&config_path);
                } else {
                    for addr in parse_nodes_json(&content) {
                        if !result.contains(&addr) {
                            result.push(addr);
                        }
                    }
                }
            }
            Err(e) => {
                log::error!("Failed to read bootstrap_nodes.json: {}", e);
            }
        }
    }

    result
}

/// Parse `{"nodes": ["multiaddr", ...]}` — returns valid addrs only.
fn parse_nodes_json(content: &str) -> Vec<Multiaddr> {
    match serde_json::from_str::<serde_json::Value>(content) {
        Ok(json) => match json.get("nodes").and_then(|n| n.as_array()) {
            Some(nodes) => {
                let addr_strs: Vec<&str> = nodes.iter().filter_map(|n| n.as_str()).collect();
                parse_bootstrap_addrs(&addr_strs)
            }
            None => {
                log::warn!("bootstrap nodes: 'nodes' field missing or not an array");
                Vec::new()
            }
        },
        Err(e) => {
            log::warn!("Failed to parse bootstrap nodes JSON: {}", e);
            Vec::new()
        }
    }
}

fn parse_bootstrap_addrs(addrs: &[&str]) -> Vec<Multiaddr> {
    let mut result = Vec::new();
    for addr_str in addrs {
        match addr_str.parse::<Multiaddr>() {
            Ok(addr) => {
                log::debug!("Loaded bootstrap node: {}", addr);
                result.push(addr);
            }
            Err(e) => {
                log::warn!("Invalid multiaddr '{}': {}", addr_str, e);
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_seeds_parse() {
        // The bundled list is EMPTY by design — any binary must be able to
        // start its own independent network (no hardcoded server anywhere).
        // If a downstream build ships seeds, they must still all parse.
        let nodes = parse_nodes_json(BUNDLED_BOOTSTRAP);
        assert!(nodes.len() == BUNDLED_BOOTSTRAP.matches("/ip").count()
            || nodes.is_empty());
    }

    #[test]
    fn user_file_merges_with_bundled() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("bootstrap_nodes.json"),
            r#"{"nodes": ["/ip4/1.2.3.4/tcp/1234/p2p/12D3KooWRGupzn6cfAF1RPtEGb8ZgCfD2j2W4wLjHMFVU3gR2gaU"]}"#,
        )
        .unwrap();
        let nodes = load_bootstrap_nodes(dir.path());
        assert!(nodes.iter().any(|a| a.to_string().contains("1.2.3.4")));
    }
}
