//! Persistent cache of discovered peers for warm restarts.
//!
//! Without this every launch is a cold start: `known_relays` and the Kademlia
//! routing table live only in memory. The cache stores recently seen peers
//! (relays preferred) with their last-known addresses; on start we seed
//! Kademlia and dial a bounded subset so the node rejoins without an invite.

use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

const MAX_ENTRIES: usize = 200;
/// How many cached peers we dial on startup (relays first).
const MAX_STARTUP_DIALS: usize = 20;
/// Relays are stable infrastructure — keep their addrs for a month.
const RELAY_TTL_SECS: u64 = 30 * 24 * 3600;
/// Ordinary peers churn fast — a week is plenty for a warm-start hint.
const PEER_TTL_SECS: u64 = 7 * 24 * 3600;
const CACHE_FILE: &str = "peer_cache.json";
/// Magic prefix marking an encrypted (GCM) cache file. V2 writes carry a
/// config epoch so an address-policy or bootstrap-config change invalidates
/// previously persisted (possibly poisoned) addresses.
const CACHE_MAGIC: &[u8; 10] = b"NOIDCACHE2";
/// Legacy V1 caches are still read — `sanitize()` drops poisoned entries.
const CACHE_MAGIC_V1: &[u8; 10] = b"NOIDCACHE1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CachedPeer {
    pub peer_id: String,
    pub addrs: Vec<String>,
    #[serde(default)]
    pub is_relay: bool,
    #[serde(default)]
    pub last_seen: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerCache {
    pub peers: Vec<CachedPeer>,
    /// Fingerprint of the network configuration (bootstrap nodes + relay
    /// config) that produced this cache. A mismatch on load drops every
    /// entry — addresses learned under a different network topology are a
    /// liability, not a head start.
    #[serde(default)]
    pub config_epoch: u64,
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl PeerCache {
    /// Fingerprint of the effective network configuration. Covers the
    /// bootstrap list and the relay knobs that shape which addresses are
    /// meaningful — when any of them change, cached addresses from the old
    /// topology are dropped instead of replayed.
    pub fn config_epoch(
        relay_config: &crate::p2p::relay_config::RelayConfig,
        bootstrap: &[Multiaddr],
    ) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        // 2 = epoch format version; bump if the fingerprint inputs change.
        2u64.hash(&mut h);
        serde_json::to_vec(relay_config)
            .unwrap_or_default()
            .hash(&mut h);
        let mut nodes: Vec<String> = bootstrap.iter().map(|a| a.to_string()).collect();
        nodes.sort();
        nodes.hash(&mut h);
        h.finish()
    }

    /// Load the peer cache. With a `cipher` attached (post-login) the file is
    /// `NOIDCACHE2 || GCM(json)`; legacy `NOIDCACHE1` and plaintext JSON files
    /// are still read so warm-start survives the upgrade — they get rewritten
    /// in the new format on save. A `config_epoch` mismatch discards the cache.
    pub fn load(
        data_dir: &Path,
        cipher: Option<&crate::security::field_cipher::FieldCipher>,
        config_epoch: u64,
    ) -> Self {
        let path = data_dir.join(CACHE_FILE);
        let raw = match std::fs::read(&path) {
            Ok(r) => r,
            Err(_) => return Self::default(),
        };
        let mut cache: Self = if raw.starts_with(CACHE_MAGIC) || raw.starts_with(CACHE_MAGIC_V1) {
            let Some(c) = cipher else {
                log::warn!("Encrypted peer cache but no field cipher — starting cold");
                return Self::default();
            };
            match c
                .decrypt_bytes(&raw[CACHE_MAGIC.len()..])
                .ok()
                .and_then(|j| serde_json::from_slice::<Self>(&j).ok())
            {
                Some(cache) => cache,
                None => {
                    // Envelope present but undecryptable/corrupt — quarantine
                    // so the poisoned blob survives for analysis, then cold-start.
                    let _ = crate::util::quarantine::quarantine(&path);
                    Self::default()
                }
            }
        } else {
            match serde_json::from_slice::<Self>(&raw) {
                Ok(cache) => cache,
                Err(_) => {
                    // Neither a known envelope nor JSON — genuinely corrupt.
                    let _ = crate::util::quarantine::quarantine(&path);
                    Self::default()
                }
            }
        };
        if cache.config_epoch != config_epoch {
            if !cache.peers.is_empty() {
                log::info!(
                    "Peer cache dropped: config epoch changed ({} → {})",
                    cache.config_epoch,
                    config_epoch
                );
            }
            return Self {
                config_epoch,
                ..Self::default()
            };
        }
        cache.sanitize();
        cache
    }

    /// Drop entries that can never help a warm start: expired peers, undialable
    /// addrs (loopback/unspecified, nested circuits, foreign terminal ids),
    /// unparseable addr strings, and peers left with no addr at all.
    /// Caches written by older versions may contain such poison — filtering at
    /// load is cheaper than a format-version migration.
    fn sanitize(&mut self) {
        let now = now_secs();
        self.peers.retain(|p| {
            let ttl = if p.is_relay { RELAY_TTL_SECS } else { PEER_TTL_SECS };
            p.last_seen + ttl > now
        });
        for p in &mut self.peers {
            let Ok(pid) = p.peer_id.parse::<PeerId>() else {
                p.addrs.clear();
                continue;
            };
            p.addrs.retain(|a| {
                a.parse::<Multiaddr>()
                    .map(|m| crate::p2p::is_wan_cacheable::is_wan_cacheable(&m, &pid))
                    .unwrap_or(false)
            });
        }
        self.peers.retain(|p| !p.addrs.is_empty());
    }

    /// Persist the peer cache — encrypted when a cipher is attached,
    /// plaintext JSON otherwise (test/ephemeral nodes).
    pub fn save(&self, data_dir: &Path, cipher: Option<&crate::security::field_cipher::FieldCipher>) {
        let path = data_dir.join(CACHE_FILE);
        let Ok(json) = serde_json::to_vec(self) else { return };
        let bytes = match cipher {
            Some(c) => match c.encrypt_bytes(&json) {
                Ok(ct) => {
                    let mut v = Vec::with_capacity(CACHE_MAGIC.len() + ct.len());
                    v.extend_from_slice(CACHE_MAGIC);
                    v.extend_from_slice(&ct);
                    v
                }
                Err(e) => {
                    log::warn!("Failed to encrypt peer cache: {}", e);
                    return;
                }
            },
            None => json,
        };
        if let Err(e) = std::fs::write(&path, bytes) {
            log::warn!("Failed to write peer cache: {}", e);
        }
    }

    /// Record (or refresh) a peer. `is_relay` entries are kept longer —
    /// when over capacity, plain peers are evicted before relays.
    pub fn upsert(&mut self, peer_id: PeerId, addrs: Vec<Multiaddr>, is_relay: bool) {
        let id = peer_id.to_string();
        // Never persist undialable addrs (nested circuits, foreign terminal
        // peer id, loopback/unspecified) — they'd be re-dialed on every
        // startup otherwise.
        let mut addrs: Vec<String> = addrs
            .iter()
            .filter(|a| crate::p2p::is_wan_cacheable::is_wan_cacheable(a, &peer_id))
            .map(|a| a.to_string())
            .collect();
        // Keep the best addrs, not just the first-seen: public addresses
        // first so loopback/LAN discoveries don't truncate away the only
        // routable path.
        addrs.sort_by_key(|a| {
            a.parse::<Multiaddr>()
                .map(|m| !crate::p2p::invite::is_public_addr(&m))
                .unwrap_or(true)
        });
        addrs.truncate(5);
        match self.peers.iter_mut().find(|p| p.peer_id == id) {
            Some(p) => {
                p.last_seen = now_secs();
                p.is_relay |= is_relay;
                for a in addrs {
                    if !p.addrs.contains(&a) {
                        p.addrs.push(a);
                    }
                }
                p.addrs.sort_by_key(|a| {
                    a.parse::<Multiaddr>()
                        .map(|m| !crate::p2p::invite::is_public_addr(&m))
                        .unwrap_or(true)
                });
                p.addrs.truncate(5);
            }
            None => {
                self.peers.push(CachedPeer {
                    peer_id: id,
                    addrs,
                    is_relay,
                    last_seen: now_secs(),
                });
            }
        }
        if self.peers.len() > MAX_ENTRIES {
            // Evict oldest non-relay entries first.
            self.peers.sort_by_key(|p| (p.is_relay, p.last_seen));
            self.peers
                .drain(..self.peers.len() - MAX_ENTRIES);
        }
    }

    /// Peers to contact on startup: relays first, then most-recent peers.
    /// Returns `(peer_id, addr)` pairs ready for `kademlia.add_address` + dial.
    /// Up to `MAX_ADDRS_PER_PEER` addresses per peer — a single cached addr
    /// may be a stale loopback/LAN hint; public addrs are tried first.
    pub fn startup_peers(&self) -> Vec<(PeerId, Multiaddr)> {
        const MAX_ADDRS_PER_PEER: usize = 3;
        let mut sorted: Vec<&CachedPeer> = self.peers.iter().collect();
        sorted.sort_by_key(|p| (std::cmp::Reverse(p.is_relay), std::cmp::Reverse(p.last_seen)));
        let mut out = Vec::new();
        for entry in sorted {
            if out.len() >= MAX_STARTUP_DIALS {
                break;
            }
            let Ok(peer_id) = entry.peer_id.parse::<PeerId>() else {
                continue;
            };
            let mut parsed: Vec<Multiaddr> = entry
                .addrs
                .iter()
                .filter_map(|a| a.parse::<Multiaddr>().ok())
                .collect();
            parsed.sort_by_key(|a| !crate::p2p::invite::is_public_addr(a));
            for addr in parsed.into_iter().take(MAX_ADDRS_PER_PEER) {
                if out.len() >= MAX_STARTUP_DIALS {
                    break;
                }
                out.push((peer_id, addr));
            }
        }
        out
    }

    /// Merge in-memory maps (e.g. all known peers) before persisting.
    #[allow(dead_code)]
    pub fn merge_addrs(&mut self, map: &HashMap<PeerId, Vec<Multiaddr>>) {
        for (peer, addrs) in map {
            self.upsert(*peer, addrs.clone(), false);
        }
    }

    /// Canonical form for endpoint comparison: the protocol stack without a
    /// trailing `/p2p/<id>` component. `DialError::WrongPeerId` reports the
    /// endpoint *with* the p2p suffix while cached entries usually omit it
    /// (or vice versa) — exact string matching silently fails to evict the
    /// poisoned entry and it gets re-dialed forever.
    fn canonical_endpoint(addr: &Multiaddr) -> String {
        use libp2p::multiaddr::Protocol;
        let mut protos: Vec<Protocol> = addr.iter().collect();
        if matches!(protos.last(), Some(Protocol::P2p(_))) {
            protos.pop();
        }
        protos.iter().map(|p| p.to_string()).collect::<Vec<_>>().join("/")
    }

    /// Drop a cached addr that proved undialable — keeps stale listen
    /// ports from being re-dialed forever by Kademlia and warm-start.
    /// The addr is re-learned automatically on the next successful
    /// connection, so eviction is self-healing. Returns true if an
    /// entry was actually removed.
    pub fn remove_addr(&mut self, peer_id: &PeerId, addr: &Multiaddr) -> bool {
        let id = peer_id.to_string();
        let s = addr.to_string();
        let canon = Self::canonical_endpoint(addr);
        match self.peers.iter_mut().find(|p| p.peer_id == id) {
            Some(p) => {
                let before = p.addrs.len();
                p.addrs.retain(|a| {
                    if *a == s {
                        return false;
                    }
                    a.parse::<Multiaddr>()
                        .map(|m| Self::canonical_endpoint(&m) != canon)
                        .unwrap_or(true)
                });
                p.addrs.len() != before
            }
            None => false,
        }
    }

    /// Valid dialable addrs remembered for `peer_id` — feeds the
    /// request-response dial path when sending to a disconnected peer.
    pub fn addrs_of(&self, peer_id: &PeerId) -> Vec<Multiaddr> {
        let id = peer_id.to_string();
        self.peers
            .iter()
            .find(|p| p.peer_id == id)
            .map(|p| {
                p.addrs
                    .iter()
                    .filter_map(|a| a.parse::<Multiaddr>().ok())
                    .filter(|a| crate::p2p::is_wan_cacheable::is_wan_cacheable(a, peer_id))
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr_for(p: PeerId) -> Multiaddr {
        format!("/ip4/10.0.0.1/tcp/4001/p2p/{p}").parse().unwrap()
    }

    #[test]
    fn upsert_and_startup_roundtrip() {
        let mut cache = PeerCache::default();
        let p = PeerId::random();
        cache.upsert(p, vec![addr_for(p)], true);
        let peers = cache.startup_peers();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].0, p);
    }

    #[test]
    fn startup_peers_prefers_public_and_returns_multiple() {
        let mut cache = PeerCache::default();
        let p = PeerId::random();
        // Loopback is not WAN-cacheable — the policy drops it at upsert.
        let local: Multiaddr = format!("/ip4/127.0.0.1/tcp/4001/p2p/{p}").parse().unwrap();
        let public: Multiaddr = format!("/ip4/1.2.3.4/tcp/4001/p2p/{p}").parse().unwrap();
        let public2: Multiaddr = format!("/ip4/5.6.7.8/tcp/4001/p2p/{p}").parse().unwrap();
        cache.upsert(p, vec![local, public.clone(), public2], false);
        let peers = cache.startup_peers();
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].1, public);
    }

    #[test]
    fn relays_sorted_first() {
        let mut cache = PeerCache::default();
        let plain = PeerId::random();
        let relay = PeerId::random();
        cache.upsert(plain, vec![addr_for(plain)], false);
        cache.upsert(relay, vec![addr_for(relay)], true);
        assert_eq!(cache.startup_peers()[0].0, relay);
    }

    #[test]
    fn cap_evicts_plain_before_relays() {
        let mut cache = PeerCache::default();
        for _ in 0..210 {
            let p = PeerId::random();
            cache.upsert(p, vec![addr_for(p)], false);
        }
        let relay = PeerId::random();
        cache.upsert(relay, vec![addr_for(relay)], true);
        assert!(cache.peers.len() <= MAX_ENTRIES);
        // The fresh relay entry survives eviction.
        assert!(cache.peers.iter().any(|p| p.peer_id == relay.to_string()));
    }

    #[test]
    fn remove_addr_matches_with_and_without_p2p_suffix() {
        let mut cache = PeerCache::default();
        let p = PeerId::random();
        // Cached entry carries the /p2p/ suffix…
        cache.upsert(p, vec![addr_for(p)], true);
        // …but the failed endpoint may arrive without it.
        let bare: Multiaddr = "/ip4/10.0.0.1/tcp/4001".parse().unwrap();
        assert!(cache.remove_addr(&p, &bare));
        assert!(cache.addrs_of(&p).is_empty());

        // And vice versa: bare cached, suffixed failure report.
        cache.upsert(p, vec!["/ip4/10.0.0.1/tcp/4001".parse().unwrap()], true);
        assert!(cache.remove_addr(&p, &addr_for(p)));
        assert!(cache.addrs_of(&p).is_empty());
    }

    #[test]
    fn remove_addr_does_not_evict_other_endpoints() {
        let mut cache = PeerCache::default();
        let p = PeerId::random();
        let a: Multiaddr = format!("/ip4/1.2.3.4/tcp/4001/p2p/{p}").parse().unwrap();
        let b: Multiaddr = format!("/ip4/5.6.7.8/tcp/4001/p2p/{p}").parse().unwrap();
        cache.upsert(p, vec![a, b], true);
        assert!(cache.remove_addr(&p, &"/ip4/1.2.3.4/tcp/4001".parse().unwrap()));
        assert_eq!(cache.addrs_of(&p).len(), 1);
    }

    #[test]
    fn upsert_refreshes_existing() {
        let mut cache = PeerCache::default();
        let p = PeerId::random();
        cache.upsert(p, vec![addr_for(p)], false);
        cache.upsert(p, vec![addr_for(p)], true);
        assert_eq!(cache.peers.len(), 1);
        assert!(cache.peers[0].is_relay);
    }

    #[test]
    fn load_missing_dir_is_empty() {
        let cache = PeerCache::load(Path::new("/nonexistent-dir-xyz"), None, 0);
        assert!(cache.peers.is_empty());
    }

    #[test]
    fn save_load_roundtrip() {
        let dir = std::env::temp_dir().join(format!("noid-cache-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut cache = PeerCache::default();
        let p = PeerId::random();
        cache.upsert(p, vec![addr_for(p)], true);
        cache.save(&dir, None);
        // Cache was never stamped with an epoch — load with 0 to match.
        let loaded = PeerCache::load(&dir, None, 0);
        assert_eq!(loaded.peers.len(), 1);
        assert_eq!(loaded.peers[0].peer_id, p.to_string());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn encrypted_save_load_roundtrip() {
        let cipher = crate::security::field_cipher::FieldCipher::new([9u8; 32]);
        let dir = std::env::temp_dir().join(format!("noid-cache-enc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut cache = PeerCache::default();
        let p = PeerId::random();
        cache.upsert(p, vec![addr_for(p)], true);
        cache.save(&dir, Some(&cipher));
        // On disk it must be ciphertext — no plaintext peer ids or addrs.
        let raw = std::fs::read(dir.join(CACHE_FILE)).unwrap();
        assert!(raw.starts_with(CACHE_MAGIC));
        assert!(!raw.windows(p.to_string().len()).any(|w| w == p.to_string().as_bytes()));
        // Decrypts with the same key, not with another.
        let loaded = PeerCache::load(&dir, Some(&cipher), 0);
        assert_eq!(loaded.peers[0].peer_id, p.to_string());
        let wrong = crate::security::field_cipher::FieldCipher::new([8u8; 32]);
        assert!(PeerCache::load(&dir, Some(&wrong), 0).peers.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
