use anyhow::Result;
use libp2p::{kad, multiaddr::Protocol, Multiaddr, PeerId, Swarm};
use std::collections::HashSet;

use crate::p2p::behaviour::NoidBehaviour;
use crate::p2p::peer_cache::PeerCache;
use crate::p2p::relay_config::{NodeRole, PrivacyMode, RelayConfig};
use crate::p2p::relay_status::NatStatus;
use crate::p2p::swarm_builder::build_swarm;
use crate::p2p::types::NoidMessage;
use crate::security::DHTCipher;

pub struct P2PNode {
    pub swarm: Swarm<NoidBehaviour>,
    pub peer_id: PeerId,
    /// Identity keypair — signs DHT records we publish (prekey bundles,
    /// mailbox pointers, username records).
    pub identity_keypair: libp2p::identity::Keypair,
    pub dht_cipher: DHTCipher,
    pub(crate) pending_messages: std::collections::HashMap<String, NoidMessage>,
    pub(crate) seen_message_ids: std::collections::HashSet<String>,
    /// Insertion order for seen_message_ids — lets us evict the OLDEST ids
    /// instead of clearing the whole replay cache (which re-opens a replay
    /// window every 10k messages).
    pub(crate) seen_order: std::collections::VecDeque<String>,
    /// Response channels parked until the app layer finishes processing
    /// the inbound request — keyed by (peer, NoidMessage.id). The transport
    /// response doubles as the application-level "persisted" ack (TI-1):
    /// entries that are never acked are swept by age so the map stays
    /// bounded under sender timeouts.
    pub(crate) pending_app_acks: std::collections::HashMap<
        (String, String),
        (
            libp2p::request_response::ResponseChannel<crate::p2p::types::NoidResponse>,
            std::time::Instant,
        ),
    >,
    /// D21: lookup_user queries — resolved as `UserLookupResult` only.
    pub(crate) pending_lookups: std::collections::HashMap<libp2p::kad::QueryId, String>,
    /// D21: check_username_availability queries — resolved as
    /// `UsernameAvailabilityChecked` only. A shared map emitted both
    /// events per query and crossed the two flows.
    pub(crate) pending_availability_queries:
        std::collections::HashMap<libp2p::kad::QueryId, String>,
    /// D14: username publishes gated on get-before-put — query id →
    /// (username, signed record bytes). Committed only when the DHT holds
    /// no fresher valid record owned by another peer.
    pub(crate) pending_username_publishes:
        std::collections::HashMap<libp2p::kad::QueryId, (String, Vec<u8>, crate::p2p::types::DHTUserRecord)>,
    pub(crate) pending_dials: std::collections::HashMap<libp2p::kad::QueryId, PeerId>,
    /// Phase A.3: Pending prekey bundle fetches (query_id → peer_id)
    pub(crate) pending_prekey_queries: std::collections::HashMap<libp2p::kad::QueryId, String>,
    /// X3DH-07: direct prekey requests over request_response —
    /// request_id → peer_id. Runs alongside the DHT query: the DHT alone
    /// cannot reach anyone when the routing table is empty, even while
    /// the peer is connected and able to answer.
    pub(crate) pending_prekey_requests: std::collections::HashMap<String, String>,
    /// X3DH-07: peer_id → when a verified bundle was last emitted. The
    /// direct and DHT paths race; the loser must not emit a second event
    /// that would re-initiate a just-established ratchet session.
    pub(crate) prekey_resolved_at: std::collections::HashMap<String, std::time::Instant>,
    /// Phase H.1: Pending mailbox node lookups (query_id → peer_id whose mailbox we seek)
    pub(crate) pending_mailbox_lookups: std::collections::HashMap<libp2p::kad::QueryId, String>,
    /// D19: resolved mailbox pointers — peer_id → (mailbox_peer, relay_addr,
    /// resolved_at). A fresh cache hit serves FindMailboxNode without a
    /// DHT round-trip; entries expire after 10min so a migrated mailbox
    /// re-resolves.
    pub(crate) mailbox_cache:
        std::collections::HashMap<String, (String, String, std::time::Instant)>,
    /// D11: every mailbox node we ever published for ourselves —
    /// (mailbox_peer, relay_addr, registered_at). After a mailbox move,
    /// envelopes parked on the OLD node are unreachable via the current
    /// record; the retrieve loop walks this history (7d = envelope TTL).
    pub(crate) mailbox_history: Vec<(String, String, std::time::Instant)>,
    /// Outbound mailbox Store requests awaiting the mailbox's Ack —
    /// request_id → local pending-row message id. The pending row is only
    /// deleted once the mailbox confirms the store; an outbound failure
    /// leaves the row for the next retry.
    /// request_id → (client_msg_id, recipient_peer_id) — the store ack is
    /// correlated back to the scoped pending row (peer, message_id).
    pub(crate) pending_mailbox_sends:
        std::collections::HashMap<String, (Option<String>, String)>,
    /// Relay discovery: pending get_providers query ids
    pub(crate) pending_relay_provider_queries: HashSet<libp2p::kad::QueryId>,
    /// Relay discovery: pending get_closest_peers for provider addrs (query_id → relay peer)
    pub(crate) pending_relay_addr_lookups: std::collections::HashMap<libp2p::kad::QueryId, PeerId>,
    /// Passive addr refresh: after a circuit-addr dial fails (relay has no
    /// reservation for the destination — the peer likely moved to another
    /// relay) we re-resolve it via get_closest_peers. Results only update
    /// the address books — no dial, no backoff reset (unlike pending_dials).
    pub(crate) pending_addr_refresh: std::collections::HashMap<libp2p::kad::QueryId, PeerId>,
    pub(crate) local_dht_records: std::collections::HashMap<Vec<u8>, Vec<u8>>,
    /// D13: write-time per local DHT record — entries expire after the
    /// standard 24h record TTL instead of living for the whole session.
    pub(crate) local_dht_records_ts:
        std::collections::HashMap<Vec<u8>, std::time::Instant>,
    pub(crate) known_relays: Vec<(PeerId, Multiaddr)>,
    pub(crate) my_username: Option<(String, crate::p2p::types::DHTUserRecord)>,
    /// Phase B.2: Database reference for mailbox storage
    pub(crate) db: Option<std::sync::Arc<tokio::sync::Mutex<Option<crate::db::Database>>>>,
    /// Phase J.2: AuditLog reference for DHT/replay/screenshot logging
    pub(crate) audit_log: Option<std::sync::Arc<crate::security::audit_log::AuditLog>>,
    /// Relay configuration (role, privacy, limits) loaded at startup.
    pub relay_config: RelayConfig,
    /// Current NAT reachability as measured by AutoNAT/UPnP.
    pub(crate) nat_status: NatStatus,
    /// Confirmed public external addresses.
    pub(crate) external_addrs: Vec<Multiaddr>,
    /// Our `/p2p-circuit` addresses obtained via relay reservations.
    pub(crate) relayed_addrs: Vec<Multiaddr>,
    /// F17: the relay our published mailbox record currently points at —
    /// pinned so renewals on OTHER relays do not flap the record between
    /// them. Re-pinned when the pinned relay loses its reservation.
    pub(crate) mailbox_record_peer: Option<PeerId>,
    /// Live listeners per relayed addr. Parallel reservations on the same
    /// relay produce duplicate listeners for the same circuit addr; when
    /// libp2p dedups them, `ExpiredListenAddr` fires for one listener while
    /// another still serves the addr — the addr must stay advertised until
    /// its LAST listener expires.
    pub(crate) relayed_listener_refs: std::collections::HashMap<Multiaddr, usize>,
    /// Inbound reservations other peers hold on us (we act as relay).
    pub(crate) inbound_reservations: usize,
    /// Relay circuits currently passing through us.
    pub(crate) active_circuits: usize,
    /// Relays we currently hold a confirmed reservation on.
    pub(crate) reserved_relays: HashSet<PeerId>,
    /// Whether we have published a relay provider record to the DHT.
    pub(crate) relay_provider_announced: bool,
    /// Persisted peer cache for warm restarts (seeded at startup, flushed periodically).
    pub(crate) peer_cache: PeerCache,
    /// Set when the cache changed since the last flush.
    pub(crate) peer_cache_dirty: bool,
    /// Addresses the user explicitly provided (invites, contact addr hints).
    /// Explicit consent — dialable even under `PrivacyMode::RelayedOnly`.
    pub(crate) allowed_dial_addrs: HashSet<Multiaddr>,
    /// App data directory (peer_cache.json, identity.key, relay_config.json).
    pub(crate) data_dir: std::path::PathBuf,
    /// Rate limits + size caps for the mailbox store/forward service.
    pub(crate) mailbox_guard: crate::p2p::mailbox_guard::MailboxGuard,
    /// Master-key field cipher — encrypts mailbox.db peer ids and the
    /// on-disk peer cache. Present on production nodes (post-login).
    pub(crate) field_cipher: Option<std::sync::Arc<crate::security::field_cipher::FieldCipher>>,
    /// Room keys for joined rooms — AES-256 keys delivered via ratchet-
    /// encrypted invites. Envelopes on gossipsub are sealed/opened with these.
    pub(crate) room_keys: std::collections::HashMap<String, [u8; 32]>,
    /// Replay cache for room message ids (per room, FIFO-bounded).
    pub(crate) seen_room_msgs: std::collections::HashSet<String>,
    /// Insertion order for seen_room_msgs — HashSet eviction is unordered, so
    /// the FIFO deque ensures the OLDEST ids are evicted, not random fresh ones.
    pub(crate) seen_room_order: std::collections::VecDeque<String>,
    /// Peers with at least one live connection — the single source of truth
    /// for online status (connection facts, not ping probes).
    pub(crate) connected_peers: HashSet<PeerId>,
    /// Count of *direct* (non-relayed) connections per peer. A reservation
    /// requested while connected to a relay only through another relay's
    /// circuit produces an unusable nested `/p2p-circuit/…/p2p-circuit`
    /// listen address — such requests are skipped until a direct path exists.
    pub(crate) direct_conns: std::collections::HashMap<PeerId, u32>,
    /// Live relayed (circuit) connection ids per peer. A RESERVE request
    /// deduplicates onto *any* existing conn to the relay — including a
    /// relayed one, which yields an undialable nested-circuit listen addr.
    /// Once a direct conn to a known relay exists, these are closed so the
    /// dedup can only ever pick the direct conn.
    pub(crate) relayed_conn_ids: std::collections::HashMap<PeerId, std::collections::HashSet<libp2p::swarm::ConnectionId>>,
    /// Per-peer dial backoff — failures grow the window 30s → 5min.
    pub(crate) dial_backoffs: std::collections::HashMap<PeerId, crate::p2p::dial_backoff::DialBackoff>,
    /// Relays that denied/failed our reservation — retry no sooner than 10min.
    pub(crate) reservation_denied: std::collections::HashMap<PeerId, std::time::Instant>,
    /// In-flight RESERVE listeners (listener_id → relay peer) — a failed or
    /// closed reservation listener marks the relay denied for 10 minutes.
    pub(crate) pending_reservations: std::collections::HashMap<libp2p::core::transport::ListenerId, PeerId>,
    /// Bootstrap seed transports dialed WITHOUT a pinned `/p2p/` id (survives
    /// relay identity rotation): on ConnectionEstablished to one of these
    /// base addrs the learned peer id is registered into Kademlia and the
    /// relay book. Values are base transport addrs (no `/p2p/` suffix).
    pub(crate) blind_bootstrap_addrs: Vec<Multiaddr>,
    /// Pinned bootstrap seeds (peer id + full addr). Retried periodically
    /// while unconnected — a seed may sit behind a shared port (SO_REUSEPORT)
    /// where a pinned dial randomly lands on a different node and fails with
    /// WrongPeerId, and the one-shot bootstrap() never retries on its own.
    pub(crate) bootstrap_peers: Vec<(PeerId, Multiaddr)>,
    /// Per-seed rotation cursor: each redial uses the next transport in
    /// preference order (quic → tcp → ws) instead of dialing all at once —
    /// parallel flows starve carrier-NAT mappings on mobile networks.
    pub(crate) bootstrap_dial_cursor: std::collections::HashMap<PeerId, usize>,
    /// D8: exponential backoff for bootstrap re-dials — key is the pinned
    /// `PeerId` rendered as string, or the blind `Multiaddr` string for
    /// seeds without a pinned peer id. Value = (consecutive failures,
    /// instant of next allowed retry). Reset once the peer is connected.
    pub(crate) bootstrap_retry_state:
        std::collections::HashMap<String, (u32, std::time::Instant)>,
    /// Consecutive ping failures per connection — the conn is closed only
    /// after repeated failures, a single negotiation stall is tolerated.
    pub(crate) ping_failures:
        std::collections::HashMap<libp2p::swarm::ConnectionId, u8>,
    /// Transport of each live connection per peer (`true` = QUIC). Used to
    /// pin peers to QUIC once a QUIC conn exists: request-response picks an
    /// arbitrary conn per peer, and on CGNAT a TCP flow can be silently dead
    /// while QUIC (connection-ID migration) survives — sends must not ride
    /// the zombie conn.
    pub(crate) conn_quic:
        std::collections::HashMap<PeerId, std::collections::HashMap<libp2p::swarm::ConnectionId, bool>>,
    /// F8: conns scheduled for close after a grace period — pruning a conn
    /// instantly kills in-flight request-response exchanges ("closed before
    /// a response"); a 20s delay lets in-flight Store/Retrieve finish.
    /// The peer id rides along so the fire-time check can cancel the close
    /// when the conn became the LAST live path to that peer during grace.
    pub(crate) pending_conn_close:
        Vec<(tokio::time::Instant, PeerId, libp2p::swarm::ConnectionId)>,
    /// Direction of each live connection (`true` = we dialed it). Feeds the
    /// deterministic symmetric-survivor rule when two direct non-QUIC conns
    /// race: the smaller peer id keeps ITS outgoing conn, the larger keeps
    /// the inbound one — both sides converge on the same socket instead of
    /// each killing a different one.
    pub(crate) conn_dialer:
        std::collections::HashMap<libp2p::swarm::ConnectionId, bool>,
    /// Remote transport addr per live connection — lets reservation
    /// requests pick the PROVEN conn transport instead of the
    /// rank-preferred (possibly carrier-blocked) addr from the book.
    pub(crate) conn_remote:
        std::collections::HashMap<libp2p::swarm::ConnectionId, Multiaddr>,
    /// In-flight prekey-bundle `put_record` queries → (record, attempts).
    /// A failed put is retried — without it a one-shot publish at cold start
    /// (empty routing table) leaves us without a published bundle forever.
    /// NOTE: despite the name this tracks ALL put_record queries (mailbox,
    /// username, prekey) — the retry arm is record-agnostic.
    pub(crate) pending_prekey_puts:
        std::collections::HashMap<libp2p::kad::QueryId, (libp2p::kad::Record, u8)>,
    /// DHT-02: records whose `put_record` returned a synchronous error
    /// (empty routing table at cold start — Kademlia refuses to even queue
    /// the query). Drained on the status tick once peers exist.
    pub(crate) deferred_dht_puts: Vec<libp2p::kad::Record>,
    /// Consecutive dial failures per canonical transport addr — an addr that
    /// keeps failing is re-learned on every `identify` and immediately
    /// re-dialed (a poisoned-addr loop on CGNAT). Addresses marked dead are
    /// skipped by `register_peer_addr`/`seed_peer_addrs` until `dead_addrs`
    /// TTL expires.
    pub(crate) addr_failures: std::collections::HashMap<String, u8>,
    /// Canonical addr → `Instant` until which it must not be re-learned.
    /// `None`-style permanent marks use `Instant::now() + 24h`.
    pub(crate) dead_addrs: std::collections::HashMap<String, std::time::Instant>,
}

impl P2PNode {
    /// Ephemeral node for tests — fresh random keys, nothing written to disk.
    /// Production code never uses this: real nodes are created via
    /// `new_with_keys` after the key store is unlocked by a successful login.
    pub async fn new(data_dir: &std::path::Path) -> Result<Self> {
        let config = RelayConfig::load(data_dir);
        let local_key = libp2p::identity::Keypair::generate_ed25519();
        Self::with_config(data_dir, config, local_key, DHTCipher::new(), None).await
    }

    /// Ephemeral relay node for tests — fresh random keys.
    pub async fn new_relay(data_dir: &std::path::Path, port: Option<u16>) -> Result<Self> {
        let mut config = RelayConfig::load(data_dir);
        config.role = NodeRole::Relay;
        if let Some(p) = port {
            config.listen_port = p;
        }
        let local_key = libp2p::identity::Keypair::generate_ed25519();
        Self::with_config(data_dir, config, local_key, DHTCipher::new(), None).await
    }

    /// Production node — takes identity keys that were decrypted from the
    /// encrypted key store (NOIDKEY1 envelope) after a successful login, plus
    /// the PIN-derived master key used to field-encrypt mailbox.db and the
    /// peer cache. Key material is never read from or written to disk here
    /// in plaintext.
    pub async fn new_with_keys(
        data_dir: &std::path::Path,
        local_key: libp2p::identity::Keypair,
        dht_cipher: DHTCipher,
        master_key: [u8; 32],
    ) -> Result<Self> {
        let config = RelayConfig::load(data_dir);
        Self::with_config(data_dir, config, local_key, dht_cipher, Some(master_key)).await
    }

    /// Production headless relay — same key handling as `new_with_keys`,
    /// forced into `NodeRole::Relay`.
    pub async fn new_relay_with_keys(
        data_dir: &std::path::Path,
        local_key: libp2p::identity::Keypair,
        dht_cipher: DHTCipher,
        port: Option<u16>,
        master_key: [u8; 32],
    ) -> Result<Self> {
        let mut config = RelayConfig::load(data_dir);
        config.role = NodeRole::Relay;
        if let Some(p) = port {
            config.listen_port = p;
        }
        Self::with_config(data_dir, config, local_key, dht_cipher, Some(master_key)).await
    }

    async fn with_config(
        data_dir: &std::path::Path,
        relay_config: RelayConfig,
        local_key: libp2p::identity::Keypair,
        dht_cipher: DHTCipher,
        master_key: Option<[u8; 32]>,
    ) -> Result<Self> {
        let peer_id = PeerId::from(local_key.public());
        let identity_keypair = local_key.clone();
        log::debug!("Local peer id: {peer_id}");

        let mut swarm = build_swarm(local_key, &relay_config).await?;

        // Listen strategy by role:
        // - Client: ephemeral ports only (never relay, no need for stable port).
        // - Auto/Relay: fixed port so UPnP mappings and advertised addrs stay
        //   stable across restarts; fall back to ephemeral on conflict
        //   (e.g. two instances on one machine).
        let wants_fixed_port =
            relay_config.role != NodeRole::Client && relay_config.listen_port != 0;
        let port = relay_config.listen_port;
        let mut bound = false;
        if wants_fixed_port {
            // TCP and WS must NOT share a port: both listeners bind with
            // SO_REUSEPORT, so the kernel hashes each inbound connection to
            // one of them. A plain-TCP dial landing on the WS socket stalls
            // during negotiation — and a dialer reusing its listen port hits
            // the same listener every time.
            let ws_port = port.checked_add(1).unwrap_or(0);
            bound = swarm
                .listen_on(format!("/ip4/0.0.0.0/tcp/{port}").parse()?)
                .is_ok()
                && swarm
                    .listen_on(format!("/ip4/0.0.0.0/tcp/{ws_port}/ws").parse()?)
                    .is_ok();
            if !bound {
                log::warn!("Port {} unavailable, falling back to ephemeral", port);
            }
        }
        if !bound {
            swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;
            swarm.listen_on("/ip4/0.0.0.0/tcp/0/ws".parse()?)?;
        }
        // QUIC listener on the same numeric port — UDP and TCP port
        // namespaces are independent, so no clash. Best-effort: losing the
        // QUIC listener must not take down TCP.
        let quic_spec = format!(
            "/ip4/0.0.0.0/udp/{}/quic-v1",
            if bound { port } else { 0 }
        );
        match quic_spec.parse::<Multiaddr>() {
            Ok(m) => {
                if let Err(e) = swarm.listen_on(m) {
                    log::debug!("QUIC listener {} unavailable: {}", quic_spec, e);
                }
            }
            Err(e) => log::debug!("Bad QUIC listen spec {}: {}", quic_spec, e),
        }
        // IPv6 listeners — mobile carriers frequently hand out globally
        // routable v6 even where v4 sits behind CGNAT. A bound v6 listener
        // is what lets AutoNAT prove public reachability and an Auto node
        // (incl. Android) become a real relay. Best-effort: hosts/networks
        // without IPv6 simply skip these (sockets are IPV6_V6ONLY, so no
        // dual-stack port clash with the ip4 binds above).
        for spec in [
            format!("/ip6/::/tcp/{}", if bound { port } else { 0 }),
            format!(
                "/ip6/::/tcp/{}/ws",
                if bound { port.checked_add(1).unwrap_or(0) } else { 0 }
            ),
            format!("/ip6/::/udp/{}/quic-v1", if bound { port } else { 0 }),
        ] {
            match spec.parse::<Multiaddr>() {
                Ok(m) => {
                    if let Err(e) = swarm.listen_on(m) {
                        log::debug!("IPv6 listener {} unavailable: {}", spec, e);
                    }
                }
                Err(e) => log::debug!("Bad IPv6 listen spec {}: {}", spec, e),
            }
        }

        log::debug!(
            "Relay server capability enabled (circuit relay v2, role={:?}, port={})",
            relay_config.role,
            if bound { port } else { 0 }
        );

        // D1: Kademlia mode is decided by reachability, not unconditionally.
        // Forcing Server on every node made unreachable CGNAT mobiles into
        // DHT record holders whose only addresses are ephemeral circuits.
        // swarm_builder already forces Server for Relay role / configured
        // external_addr; everyone else gets automatic mode (promotes to
        // Server only after identify/AutoNAT confirms an external addr).
        if relay_config.role == crate::p2p::NodeRole::Relay
            || relay_config.external_addr.is_some()
        {
            swarm.behaviour_mut().kademlia.set_mode(Some(kad::Mode::Server));
            log::debug!("Kademlia DHT mode forced to Server (relay/external_addr)");
        } else {
            swarm.behaviour_mut().kademlia.set_mode(None);
            log::debug!("Kademlia DHT mode: automatic (Client until publicly confirmed)");
        }

        // Advertised external address (VPS relays with no AutoNAT observer yet).
        // Feeds invites, kad provider records and RESERVE responses.
        let mut external_addrs = Vec::new();
        if let Some(ref ext) = relay_config.external_addr {
            match ext.parse::<Multiaddr>() {
                Ok(addr) => {
                    log::debug!("External address configured: {}", addr);
                    swarm.add_external_address(addr.clone());
                    external_addrs.push(addr);
                }
                Err(e) => log::warn!("Invalid external_addr '{}': {}", ext, e),
            }
        }

        // Field cipher for local data at rest (mailbox.db ids, peer cache).
        // Present on production nodes (post-login / post-passphrase).
        let field_cipher =
            master_key.map(|k| std::sync::Arc::new(crate::security::field_cipher::FieldCipher::new(k)));

        // Mailbox serving uses a dedicated SQLite DB. Envelopes are E2EE,
        // and with a field cipher attached the recipient/sender peer ids are
        // encrypted at rest as well. KillPin still wipes it (same data_dir).
        // A corrupt mailbox.db must not wedge the node: quarantine it and
        // retry once against a fresh file — envelopes are an ephemeral cache.
        let mailbox_path = data_dir.join("mailbox.db");
        let db_open = match crate::db::Database::new(&mailbox_path).await {
            Ok(db) => Some(db),
            Err(e) => {
                log::error!("mailbox.db unreadable ({}), quarantining and recreating", e);
                // Sidecars (-journal/-wal/-shm) move too — stale ones would
                // be replayed into the fresh database.
                match crate::util::quarantine::quarantine_sqlite(&mailbox_path) {
                    Ok(_) => match crate::db::Database::new(&mailbox_path).await {
                        Ok(db) => Some(db),
                        Err(e2) => {
                            log::error!("mailbox.db recreate failed: {}", e2);
                            None
                        }
                    },
                    Err(qe) => {
                        log::error!("mailbox.db quarantine failed: {}", qe);
                        None
                    }
                }
            }
        };
        let db = match db_open {
            Some(mut db) => {
                let usable = match field_cipher.as_ref() {
                    Some(c) => match db.attach_cipher(c.clone()).await {
                        Ok(()) => true,
                        // Fail closed: a node that has a master key must not
                        // serve mailbox metadata from an unencrypted DB.
                        Err(e) => {
                            log::error!(
                                "Mailbox DB cipher attach failed — mailbox disabled: {}",
                                e
                            );
                            false
                        }
                    },
                    None => true,
                };
                if usable {
                    Some(std::sync::Arc::new(tokio::sync::Mutex::new(Some(db))))
                } else {
                    None
                }
            }
            None => {
                log::warn!("Node cannot serve mailbox requests");
                None
            }
        };

        // The epoch fingerprints bootstrap nodes + relay config — a topology
        // change invalidates cached addresses outright instead of replaying
        // them on warm start.
        let peer_cache = {
            let bootstrap = crate::p2p::load_bootstrap_nodes(data_dir);
            let epoch = PeerCache::config_epoch(&relay_config, &bootstrap);
            let mut cache = PeerCache::load(data_dir, field_cipher.as_deref(), epoch);
            // Fresh caches (missing file) carry epoch 0 — stamp the current
            // epoch so the first save survives the next load.
            cache.config_epoch = epoch;
            cache
        };

        // A node configured with an explicit public external addr — or
        // running as a dedicated relay — is reachable by construction; do
        // not leave it `Unknown` (UI shows "Behind the NAT", invites omit
        // the direct addrs and `should_relay()` stays off for Auto role).
        let nat_status = if relay_config.external_addr.is_some()
            || relay_config.role == crate::p2p::relay_config::NodeRole::Relay
        {
            NatStatus::Public
        } else {
            NatStatus::Unknown
        };

        Ok(Self {
            swarm,
            peer_id,
            identity_keypair,
            dht_cipher,
            pending_messages: std::collections::HashMap::new(),
            seen_message_ids: std::collections::HashSet::new(),
            seen_order: std::collections::VecDeque::new(),
            pending_app_acks: std::collections::HashMap::new(),
            pending_lookups: std::collections::HashMap::new(),
            pending_availability_queries: std::collections::HashMap::new(),
            pending_username_publishes: std::collections::HashMap::new(),
            pending_dials: std::collections::HashMap::new(),
            pending_addr_refresh: std::collections::HashMap::new(),
            pending_prekey_queries: std::collections::HashMap::new(),
            pending_prekey_requests: std::collections::HashMap::new(),
            prekey_resolved_at: std::collections::HashMap::new(),
            pending_mailbox_lookups: std::collections::HashMap::new(),
            mailbox_cache: std::collections::HashMap::new(),
            mailbox_history: Vec::new(),
            pending_mailbox_sends: std::collections::HashMap::new(),
            pending_relay_provider_queries: HashSet::new(),
            pending_relay_addr_lookups: std::collections::HashMap::new(),
            local_dht_records: std::collections::HashMap::new(),
            local_dht_records_ts: std::collections::HashMap::new(),
            known_relays: Vec::new(),
            my_username: None,
            db,
            audit_log: None,
            relay_config,
            nat_status,
            external_addrs,
            relayed_addrs: Vec::new(),
            mailbox_record_peer: None,
            relayed_listener_refs: std::collections::HashMap::new(),
            inbound_reservations: 0,
            active_circuits: 0,
            reserved_relays: HashSet::new(),
            relay_provider_announced: false,
            peer_cache,
            peer_cache_dirty: false,
            allowed_dial_addrs: HashSet::new(),
            data_dir: data_dir.to_path_buf(),
            mailbox_guard: crate::p2p::mailbox_guard::MailboxGuard::new(),
            field_cipher,
            room_keys: std::collections::HashMap::new(),
            seen_room_msgs: std::collections::HashSet::new(),
            seen_room_order: std::collections::VecDeque::new(),
            connected_peers: HashSet::new(),
            direct_conns: std::collections::HashMap::new(),
            relayed_conn_ids: std::collections::HashMap::new(),
            dial_backoffs: std::collections::HashMap::new(),
            reservation_denied: std::collections::HashMap::new(),
            pending_reservations: std::collections::HashMap::new(),
            blind_bootstrap_addrs: Vec::new(),
            bootstrap_peers: Vec::new(),
            bootstrap_dial_cursor: std::collections::HashMap::new(),
            bootstrap_retry_state: std::collections::HashMap::new(),
            ping_failures: std::collections::HashMap::new(),
            conn_quic: std::collections::HashMap::new(),
            pending_conn_close: Vec::new(),
            conn_dialer: std::collections::HashMap::new(),
            conn_remote: std::collections::HashMap::new(),
            addr_failures: std::collections::HashMap::new(),
            dead_addrs: std::collections::HashMap::new(),
            pending_prekey_puts: std::collections::HashMap::new(),
            deferred_dht_puts: Vec::new(),
        })
    }

    /// Record a message id in the replay cache. When the cache exceeds 10k
    /// entries the oldest 5k are evicted — never a full clear, which would
    /// reopen the replay window for everything seen before.
    pub(crate) fn mark_seen(&mut self, id: &str) {
        self.seen_message_ids.insert(id.to_string());
        self.seen_order.push_back(id.to_string());
        if self.seen_order.len() > 10_000 {
            let overflow = self.seen_order.len() - 5_000;
            for _ in 0..overflow {
                if let Some(old) = self.seen_order.pop_front() {
                    self.seen_message_ids.remove(&old);
                }
            }
            log::debug!("Evicted {} oldest ids from replay cache", overflow);
        }
    }

    /// Park an inbound request's response channel until the app layer
    /// acknowledges durable processing via `P2PCommand::AckReceived`
    /// (TI-1). Entries older than 30s — past the sender's 10s response
    /// timeout — are swept on insert; the map is capped at 512.
    pub(crate) fn park_app_ack(
        &mut self,
        peer_id: String,
        message_id: String,
        channel: libp2p::request_response::ResponseChannel<crate::p2p::types::NoidResponse>,
    ) {
        const MAX_AGE: std::time::Duration = std::time::Duration::from_secs(30);
        const MAX_PARKED: usize = 512;
        let now = std::time::Instant::now();
        self.pending_app_acks
            .retain(|_, (_, parked_at)| now.duration_since(*parked_at) < MAX_AGE);
        if self.pending_app_acks.len() >= MAX_PARKED {
            // Channel dropped — the sender times out and retries.
            log::warn!(
                "pending_app_acks full ({} parked) — dropping inbound request {}",
                MAX_PARKED,
                message_id
            );
            return;
        }
        self.pending_app_acks
            .insert((peer_id, message_id), (channel, now));
    }

    /// Persist the peer cache eagerly while the learned set is still small:
    /// the first peers/relay are exactly what makes warm start work, and a
    /// session shorter than the 30s flush tick must not lose them. Churn
    /// beyond the early set is flushed on the timer.
    pub(crate) fn maybe_flush_peer_cache(&mut self) {
        if self.peer_cache_dirty && self.peer_cache.peers.len() <= 10 {
            self.peer_cache
                .save(&self.data_dir.clone(), self.field_cipher.as_deref());
            self.peer_cache_dirty = false;
        }
    }

    /// Seed Kademlia and dial peers remembered from the previous session.
    /// Called once at startup alongside `bootstrap` — relays are dialed first,
    /// so a returning node rejoins its "circle" without needing a new invite.
    /// D13: write a local DHT fallback copy with a 24h expiry — records
    /// must not outlive their network TTL just because they are ours.
    pub(crate) fn local_dht_put(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.local_dht_records_ts
            .insert(key.clone(), std::time::Instant::now());
        self.local_dht_records.insert(key, value);
    }

    /// DHT-02: publish a record, tracking the query for retry — on a
    /// synchronous refusal (empty routing table at cold start) the record
    /// is parked in `deferred_dht_puts` and retried by the status tick.
    pub(crate) fn queue_dht_put(&mut self, record: libp2p::kad::Record) {
        match self
            .swarm
            .behaviour_mut()
            .kademlia
            .put_record(record.clone(), libp2p::kad::Quorum::One)
        {
            Ok(qid) => {
                self.pending_prekey_puts.insert(qid, (record, 0));
            }
            Err(e) => {
                if self.deferred_dht_puts.len() < 32 {
                    self.deferred_dht_puts.push(record);
                }
                log::warn!(
                    "DHT put deferred — no routing peers yet ({} queued): {}",
                    self.deferred_dht_puts.len(),
                    e
                );
            }
        }
    }

    /// DHT-02: retry parked records — drained once Kademlia actually has
    /// peers to seed a query. Records that STILL fail stay queued; the
    /// put_record cap (32) bounds the backlog.
    pub(crate) fn drain_deferred_dht_puts(&mut self) {
        if self.deferred_dht_puts.is_empty() {
            return;
        }
        let pending = std::mem::take(&mut self.deferred_dht_puts);
        for record in pending {
            match self
                .swarm
                .behaviour_mut()
                .kademlia
                .put_record(record.clone(), libp2p::kad::Quorum::One)
            {
                Ok(qid) => {
                    self.pending_prekey_puts.insert(qid, (record, 0));
                    log::info!("Deferred DHT record finally published");
                }
                Err(_) => self.deferred_dht_puts.push(record),
            }
        }
    }

    /// D13: read a local DHT fallback copy; returns `None` once the entry
    /// is older than the 24h record TTL (and prunes it). Entries written
    /// without a timestamp (tests) never expire.
    pub(crate) fn local_dht_get(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        const TTL: std::time::Duration = std::time::Duration::from_secs(24 * 3600);
        let expired = self
            .local_dht_records_ts
            .get(key)
            .is_some_and(|ts| ts.elapsed() > TTL);
        if expired {
            self.local_dht_records.remove(key);
            self.local_dht_records_ts.remove(key);
            return None;
        }
        self.local_dht_records.get(key).cloned()
    }

    pub fn seed_from_peer_cache(&mut self) {
        for (peer_id, addr) in self.peer_cache.startup_peers() {
            if peer_id == self.peer_id {
                continue;
            }
            // Cached addrs may be stale or malformed (nested circuits, an
            // addr terminating at a different peer, loopback/LAN hints) —
            // classify before dialing.
            if matches!(
                crate::p2p::classify_peer_addr::classify_peer_addr(&addr, &peer_id),
                crate::p2p::addr_class::AddrClass::Malformed
                    | crate::p2p::addr_class::AddrClass::Local
            ) {
                continue;
            }
            if self.is_own_listen_addr(&addr) {
                continue;
            }
            if !self.dial_allowed(&addr) {
                continue;
            }
            // D13: skip addrs that already proved dead this session —
            // otherwise every startup wastes a dial on each.
            if self.is_dead_addr(&addr) {
                continue;
            }
            // Cached relays re-join known_relays so the ConnectionEstablished
            // handler requests a fresh reservation on reconnect.
            let is_relay = self
                .peer_cache
                .peers
                .iter()
                .any(|p| p.peer_id == peer_id.to_string() && p.is_relay);
            // A cached circuit addr for a relay peer is poison from the
            // old relay→relay reservation chains — a relay is only useful
            // reached directly.
            if is_relay
                && addr.iter().any(|p| matches!(p, Protocol::P2pCircuit))
            {
                continue;
            }
            self.register_peer_addr(peer_id, addr.clone(), "cache", false);
            if is_relay
                && !self.known_relays.iter().any(|(p, _)| *p == peer_id)
            {
                self.known_relays.push((peer_id, addr.clone()));
            }
            // TR-06: warm-start dials are reserved for RELAYS — reconnecting
            // the reservation path is what makes the node reachable again.
            // Ordinary cached peers only feed the address books here: a
            // startup dial storm across every stale contact addr burned
            // dial-backoff budgets and produced a burst of failures on
            // mobile launch. Contact dials happen on demand (send /
            // reconnect_to_contacts).
            if !is_relay {
                continue;
            }
            // Always bind the dial to the cached peer id: a bare addr yields
            // OutgoingConnectionError{peer_id: None}, which skips eviction and
            // backoff — the dead addr is then retried on every startup.
            let dial_addr = if addr.iter().any(|p| matches!(p, Protocol::P2p(_))) {
                addr
            } else {
                addr.with(Protocol::P2p(peer_id))
            };
            let _ = self.swarm.dial(crate::p2p::dial_opts::dial_opts(
                Some(peer_id),
                dial_addr,
            ));
        }
    }

    pub fn bootstrap(&mut self, nodes: Vec<Multiaddr>) -> Result<()> {
        log::debug!("Starting bootstrap with {} nodes", nodes.len());
        for addr in &nodes {
            log::debug!("Bootstrap node: {}", addr);
        }
        // Group pinned seed addrs by peer — dialing every transport at once
        // opens parallel flows that starve carrier-NAT mappings on mobile
        // (Tele2 evicts old mappings as new conns form). One conn per seed
        // suffices; retries rotate transports via bootstrap_dial_cursor.
        let mut pinned: std::collections::HashMap<PeerId, Vec<Multiaddr>> =
            std::collections::HashMap::new();
        let mut blind: Vec<Multiaddr> = Vec::new();
        for addr in nodes {
            if let Some(peer_id) = addr.iter().find_map(|p| match p {
                Protocol::P2p(id) => Some(id),
                _ => None,
            }) {
                if peer_id != self.peer_id {
                    pinned.entry(peer_id).or_default().push(addr);
                }
            } else {
                blind.push(addr);
            }
        }
        for (peer_id, mut addrs) in pinned {
            addrs.sort_by_key(crate::p2p::transport_rank::transport_rank);
            for addr in &addrs {
                self.register_peer_addr(peer_id, addr.clone(), "bootstrap", true);
                // Only transport-level relay addresses are usable for
                // reservations — a relayed address here would compose into
                // a nested circuit, which we refuse to dial.
                if !addr.iter().any(|p| matches!(p, Protocol::P2pCircuit)) {
                    self.known_relays.push((peer_id, addr.clone()));
                    self.bootstrap_peers.push((peer_id, addr.clone()));
                }
            }
            // Dial the bootstrap node to establish connection.
            // NOTE: no relay reservation here — the reservation request
            // must be issued AFTER the connection exists, otherwise the
            // behaviour's internal dial races with this manual dial and
            // the RESERVE command is silently dropped (dial dedup).
            // The ConnectionEstablished handler issues the reservation.
            let preferred = addrs[0].clone();
            log::info!("Bootstrap: dialing {}", preferred);
            let _ = self.swarm.dial(crate::p2p::dial_opts::dial_opts(
                Some(peer_id),
                preferred,
            ));
            self.bootstrap_dial_cursor.insert(peer_id, 1);
        }
        for addr in blind {
            // Blind seed: no pinned peer id — survives relay identity
            // rotation. Dial the bare transport; ConnectionEstablished
            // registers the learned peer id into Kademlia + relay book.
            log::info!("Bootstrap: blind-dialing {} (no pinned peer id)", addr);
            self.blind_bootstrap_addrs.push(addr.clone());
            let _ = self.swarm.dial(crate::p2p::dial_opts::dial_opts(None, addr));
        }
        match self.swarm.behaviour_mut().kademlia.bootstrap() {
            Ok(query_id) => log::debug!("Bootstrap query started: {:?}", query_id),
            Err(e) => {
                // No known peers — expected on a fresh install. The network is
                // joined via mDNS (LAN) or a contact's address hint (WAN).
                log::debug!("Kademlia bootstrap deferred until first peer: {}", e);
            }
        }
        Ok(())
    }

    /// Whether dialing `addr` is allowed under the current privacy mode.
    /// In `RelayedOnly` mode we may still dial known relays directly (the relay
    /// inherently sees our IP) and LAN/private addresses — but never other
    /// WAN peers directly.
    pub(crate) fn dial_allowed(&self, addr: &Multiaddr) -> bool {
        if self.relay_config.privacy != PrivacyMode::RelayedOnly {
            return true;
        }
        if addr.iter().any(|p| matches!(p, Protocol::P2pCircuit)) {
            return true;
        }
        // Explicit user-provided address (invite/contact hint) — consent given.
        if self.allowed_dial_addrs.contains(addr) {
            return true;
        }
        if let Some(target) = addr.iter().find_map(|p| match p {
            Protocol::P2p(id) => Some(id),
            _ => None,
        }) {
            if self.known_relays.iter().any(|(p, _)| *p == target) {
                return true;
            }
        }
        // LAN/private addresses are fine — the local network sees our IP anyway.
        let mut only_local = true;
        for proto in addr.iter() {
            match proto {
                Protocol::Ip4(ip) => {
                    if !(ip.is_private() || ip.is_loopback() || ip.is_link_local()) {
                        only_local = false;
                    }
                }
                Protocol::Ip6(ip) => {
                    if !(ip.is_loopback() || ip.is_unicast_link_local()) {
                        only_local = false;
                    }
                }
                Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_) | Protocol::Dnsaddr(_) => {
                    only_local = false;
                }
                _ => {}
            }
        }
        only_local
    }

    /// Register an external (public) address: advertised to AutoNAT observers,
    /// included in invites and relay RESERVE responses.
    pub fn register_external_addr(&mut self, addr: Multiaddr) {
        self.swarm.add_external_address(addr.clone());
        if !self.external_addrs.contains(&addr) {
            self.external_addrs.push(addr);
        }
    }

    /// Whether `addr` plausibly identifies `peer` as a dialable address:
    /// - at most one `/p2p-circuit` — nested circuits are malformed;
    /// - if a circuit is present, the address must terminate at `peer`
    ///   (`…/p2p/<relay>/p2p-circuit/p2p/<peer>`). A relayed address ending
    ///   in a *different* peer id is that other peer's address, and one
    ///   ending in bare `/p2p-circuit` is a reservation-listen form, not a
    ///   peer address.
    pub fn is_valid_addr_for_peer(addr: &Multiaddr, peer: &PeerId) -> bool {
        let mut circuits = 0u8;
        let mut last_p2p: Option<PeerId> = None;
        for p in addr.iter() {
            match p {
                Protocol::P2pCircuit => circuits += 1,
                Protocol::P2p(id) => last_p2p = Some(id),
                _ => {}
            }
        }
        if circuits > 1 {
            return false;
        }
        circuits == 0 || last_p2p == Some(*peer)
    }

    /// True when `addr` targets one of our own listen sockets. Same-host
    /// instances and stale peer-cache entries leak our own addrs into the
    /// address book under foreign peer ids — dialing them can only reach
    /// ourselves (or fail outright: on Windows the shared listen port makes
    /// the outbound connect error with WSAEADDRINUSE/10048). Circuit addrs
    /// legitimately reuse a relay's ip:port — never self-matched.
    pub(crate) fn is_own_listen_addr(&self, addr: &Multiaddr) -> bool {
        // A circuit addr terminating at OUR peer id is ours too — without
        // this check a self-minted `/p2p-circuit/p2p/<self>` leaked into the
        // dial book and produced `tried to dial local peer id`.
        if crate::p2p::terminal_peer_id::terminal_peer_id(addr) == Some(self.peer_id) {
            return true;
        }
        if addr.iter().any(|p| matches!(p, Protocol::P2pCircuit)) {
            return false;
        }
        // An addr terminating at a *different* peer id cannot be our own
        // listen address: two devices behind the same NAT legitimately
        // advertise the same public ip:port shape, and ip-only matching
        // would drop a real sibling's addr as "self". A genuinely stale
        // leak of our own addr under a foreign id self-corrects — dialing
        // it reaches our listener and fails with UnexpectedPeerId, which
        // evicts the addr.
        if let Some(Protocol::P2p(id)) = addr.iter().last() {
            if id != self.peer_id {
                return false;
            }
        }
        let mut ip = None;
        let mut port = None;
        for p in addr.iter() {
            match p {
                Protocol::Ip4(v) => ip = Some(std::net::IpAddr::V4(v)),
                Protocol::Ip6(v) => ip = Some(std::net::IpAddr::V6(v)),
                Protocol::Tcp(v) => port = Some(v),
                _ => {}
            }
        }
        let (Some(ip), Some(port)) = (ip, port) else {
            return false;
        };
        // Loopback/unspecified remote ip can only ever reach this host — any
        // listener on the same port is ours.
        if ip.is_loopback() || ip.is_unspecified() {
            return self.swarm.listeners().any(|l| {
                l.iter().any(|p| matches!(p, Protocol::Tcp(v) if v == port))
            });
        }
        // Concrete remote ip: self only when it matches a *bound* listener ip
        // or one of our confirmed/provisioned external addresses. A wildcard
        // listener (0.0.0.0) does NOT make every same-port remote addr ours —
        // other hosts legitimately listen on the same port.
        self.swarm.listeners().any(|l| {
            let mut lip = None;
            let mut lport = None;
            for p in l.iter() {
                match p {
                    Protocol::Ip4(v) => lip = Some(std::net::IpAddr::V4(v)),
                    Protocol::Ip6(v) => lip = Some(std::net::IpAddr::V6(v)),
                    Protocol::Tcp(v) => lport = Some(v),
                    _ => {}
                }
            }
            lport == Some(port)
                && match lip {
                    Some(lip) if !lip.is_unspecified() => lip == ip,
                    _ => self.is_own_ip(ip),
                }
        })
    }

    /// True when `ip` belongs to this node: a confirmed external address or a
    /// provisioned `external_addr` from relay_config.
    fn is_own_ip(&self, ip: std::net::IpAddr) -> bool {
        self.external_addrs.iter().any(|a| {
            a.iter().any(|p| match p {
                Protocol::Ip4(v) => std::net::IpAddr::V4(v) == ip,
                Protocol::Ip6(v) => std::net::IpAddr::V6(v) == ip,
                _ => false,
            })
        })
    }

    /// Feed every valid cached addr for `peer` into the swarm's address
    /// sources so a queued request-response dial has something to try.
    /// Skipped while already connected (no dial will be issued anyway).
    pub(crate) fn seed_peer_addrs(&mut self, peer_id: &PeerId) {
        if self.connected_peers.contains(peer_id) {
            return;
        }
        // A reservation-eligible relay must be reached directly — feeding a
        // cached circuit addr for it could produce a relayed conn that a
        // later RESERVE deduplicates onto (nested-circuit listen addr).
        let is_relay = self.known_relays.iter().any(|(p, _)| p == peer_id);
        let mut addrs = self.peer_cache.addrs_of(peer_id);
        // Address order is the dial order. Same-NAT peers share our observed
        // public IP — the WAN hairpin path back through the router almost
        // never works, so their LAN addrs (learned via mDNS/Identify) must
        // be tried first. For WAN-only peers a stale LAN addr fails fast
        // (RST/ARP timeout), so ordering Lan-first unconditionally is safe.
        let shares_ext_ip = addrs.iter().any(|a| {
            a.iter().any(|p| match p {
                Protocol::Ip4(v) => self.is_own_ip(std::net::IpAddr::V4(v)),
                Protocol::Ip6(v) => self.is_own_ip(std::net::IpAddr::V6(v)),
                _ => false,
            })
        });
        if shares_ext_ip {
            addrs.sort_by_key(|a| {
                match crate::p2p::classify_peer_addr::classify_peer_addr(a, peer_id) {
                    crate::p2p::addr_class::AddrClass::Lan => 0,
                    _ => 1,
                }
            });
        }
        // QUIC first always: on carrier NAT (Tele2 evicts TCP flow mappings
        // mid-stream) a QUIC conn survives rebind via connection ID, while
        // every TCP flow is a ~30s ticking bomb. Feeding QUIC addrs first
        // means the parallel dial lands the resilient transport earliest.
        addrs.sort_by_key(|a| {
            crate::p2p::transport_rank::transport_rank(a)
        });
        // Cap how many addrs a single seed round feeds the swarm — a peer
        // with many stale addrs must not fan out into a dial burst per
        // retry cycle (small routers drown their conntrack on this).
        const MAX_SEED_ADDRS: usize = 6;
        let mut fed = 0usize;
        for addr in addrs {
            // Dead-marked addrs proved undialable — feeding them again just
            // re-arms the dial→fail→evict→re-learn loop.
            if self.is_dead_addr(&addr) {
                continue;
            }
            if is_relay
                && addr
                    .iter()
                    .any(|p| matches!(p, Protocol::P2pCircuit))
            {
                continue;
            }
            // Same-NAT siblings legitimately advertise our observed public
            // ip:port — the self-check must run on the addr *attributed to
            // this peer*, so a bare transport addr gets the /p2p/ suffix
            // first (foreign terminal id → not "ours"). These addrs are
            // dialed with an expected peer id anyway: a real self-leak fails
            // with WrongPeerId and is evicted.
            let tagged = match addr.iter().last() {
                Some(Protocol::P2p(_)) => addr.clone(),
                _ => addr.clone().with(Protocol::P2p(*peer_id)),
            };
            if self.is_own_listen_addr(&tagged) {
                continue;
            }
            match crate::p2p::classify_peer_addr::classify_peer_addr(&addr, peer_id) {
                crate::p2p::addr_class::AddrClass::Local
                | crate::p2p::addr_class::AddrClass::Malformed => continue,
                _ => {}
            }
            // F4: request-response/mailbox dial whatever is seeded here — the
            // explicit `dial()` privacy filter is bypassed. Enforce the same
            // policy so RelayedOnly never fans out direct WAN dials.
            if !self.dial_allowed(&tagged) {
                continue;
            }
            self.swarm.add_peer_address(*peer_id, addr);
            fed += 1;
            if fed >= MAX_SEED_ADDRS {
                break;
            }
        }
    }

    pub async fn dial(&mut self, addr: Multiaddr) -> Result<()> {
        if addr
            .iter()
            .filter(|p| matches!(p, Protocol::P2pCircuit))
            .count()
            > 1
        {
            log::debug!("Refusing to dial nested-circuit address: {}", addr);
            return Ok(());
        }
        // A circuit addr terminating at a known relay would create a *relayed*
        // conn to that relay — reservations issued on it later can be
        // deduplicated onto the circuit and produce undialable nested listen
        // addrs. A relay must be reached directly: substitute its transport
        // address.
        let has_circuit = addr
            .iter()
            .any(|p| matches!(p, Protocol::P2pCircuit));
        if has_circuit {
            let target = addr
                .iter()
                .filter_map(|p| match p {
                    Protocol::P2p(id) => Some(id),
                    _ => None,
                })
                .last();
            if let Some(target) = target {
                if self.known_relays.iter().any(|(p, _)| *p == target)
                    && !self.allowed_dial_addrs.contains(&addr)
                {
                    let direct = self.direct_addrs_of(&target);
                    if !direct.is_empty() {
                        log::debug!(
                            "Dial to relay {} via circuit refused — dialing {} direct transport(s)",
                            target,
                            direct.len()
                        );
                        if let Err(e) = self.swarm.dial(
                            crate::p2p::dial_opts::dial_opts_multi(target, direct),
                        ) {
                            log::debug!("Direct dial to relay {} failed: {}", target, e);
                        }
                    }
                    return Ok(());
                }
            }
        }
        if self.is_own_listen_addr(&addr) {
            log::debug!("Refusing to dial our own listen socket: {}", addr);
            return Ok(());
        }
        if !self.dial_allowed(&addr) {
            log::debug!(
                "RelayedOnly mode: blocked direct WAN dial to {} \
                 (not a known relay and not user-provided)",
                addr
            );
            return Ok(());
        }
        // Per-peer backoff: a recently unreachable peer is not redialed —
        // outgoing messages route through the mailbox path instead.
        let dial_peer = addr
            .iter()
            .filter_map(|p| match p {
                Protocol::P2p(id) => Some(id),
                _ => None,
            })
            .last();
        if let Some(target) = dial_peer {
            if target == self.peer_id {
                log::debug!("Refusing to dial our own peer id: {}", addr);
                return Ok(());
            }
            if self.dial_is_backed_off(&target) {
                log::debug!("Dial to {} skipped — peer in backoff window", target);
                return Ok(());
            }
            // Last line of defense for internal dial paths (kad/rr resolution)
            // that bypass the ingestion-time filter: never dial addrs that can
            // structurally never reach the peer. User-authorized addrs
            // (`allowed_dial_addrs`) are exempt — loopback dials are a legit
            // same-host/dev scenario.
            if !self.allowed_dial_addrs.contains(&addr)
                && matches!(
                    crate::p2p::classify_peer_addr::classify_peer_addr(&addr, &target),
                    crate::p2p::addr_class::AddrClass::Malformed
                        | crate::p2p::addr_class::AddrClass::Local
                )
            {
                log::debug!("Refusing to dial undialable addr for {}: {}", target, addr);
                return Ok(());
            }
        }
        let dial_peer = addr
            .iter()
            .filter_map(|p| match p {
                Protocol::P2p(id) => Some(id),
                _ => None,
            })
            .last();
        if let Err(e) = self
            .swarm
            .dial(crate::p2p::dial_opts::dial_opts(dial_peer, addr.clone()))
        {
            log::debug!("Dial {} failed to initiate: {}", addr, e);
        }
        Ok(())
    }
}
