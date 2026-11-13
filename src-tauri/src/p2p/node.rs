use libp2p::{Multiaddr, PeerId, Swarm};
use std::collections::HashSet;

use crate::p2p::behaviour::NoidBehaviour;
use crate::p2p::peer_cache::PeerCache;
use crate::p2p::relay_config::RelayConfig;
use crate::p2p::relay_status::NatStatus;
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
    /// META-05: pending hop forwards — outbound request_id (as string) →
    /// the inbound response channel to answer once the downstream hop
    /// replies. `hop_noid` for PROTO_NOID, `hop_hop` for nested chains.
    pub(crate) hop_pending_noid: std::collections::HashMap<
        String,
        libp2p::request_response::ResponseChannel<crate::p2p::hop::HopResponse>,
    >,
    pub(crate) hop_pending_hop: std::collections::HashMap<
        String,
        libp2p::request_response::ResponseChannel<crate::p2p::hop::HopResponse>,
    >,
    /// META-05: our outbound 2-hop sends — request_id → true destination
    /// peer string (the hop request_id belongs to the entry relay leg, so
    /// `to` for MessageFailed/MessageDelivered needs this).
    pub(crate) hop_outbound_dest: std::collections::HashMap<String, String>,
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
    /// META-03: pending blinded-descriptor queries —
    /// query_id → (peer_id, kind, day). Results unwrap to a signed inner
    /// record and re-enter the normal verification path.
    pub(crate) pending_blind_queries:
        std::collections::HashMap<libp2p::kad::QueryId, (String, crate::p2p::blind_lookup::BlindKind, u64)>,
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
    /// Connectivity policy — persistent vs on-demand contact conns.
    /// Loaded alongside `relay_config` from the app data dir; updated
    /// live by `P2PCommand::SetConnectivityConfig`.
    pub(crate) connectivity_config: crate::p2p::connectivity_config::ConnectivityConfig,
    /// Current NAT reachability as measured by AutoNAT/UPnP.
    pub(crate) nat_status: NatStatus,
    /// Platform-adaptive behavior policy (Mobile/Desktop/Headless).
    pub(crate) profile: crate::p2p::profile::NodeProfile,
    /// Confirmed public external addresses.
    pub(crate) external_addrs: Vec<Multiaddr>,
    /// Our own `/onion3/<host>:4020` listen addr when the Tor generation is
    /// up — included in the signed `EndpointAdvertise` sent on connect.
    pub(crate) own_onion_addr: Option<Multiaddr>,
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
    /// META-04: rotating-topic → room_id resolution for V2 envelopes.
    pub(crate) room_topics: std::collections::HashMap<String, String>,
    /// Day index the rotating subscriptions were last built for.
    pub(crate) room_topics_day: u64,
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
    /// SEC-1111-03/06: active one-time rendezvous secrets for OUR
    /// Mainline-DHT slots — peers holding a fresh invite announce at
    /// `H(rv)`; the public PeerId is never the slot key. A small ring of
    /// recently-issued secrets (TTL 30 min) keeps earlier invites valid
    /// while newer ones rotate in.
    pub(crate) rv_secrets:
        std::collections::VecDeque<(String, std::time::Instant)>,
    /// RV secrets learned from invites we dialed — peers we punch toward
    /// announce at `H(rv)` instead of `H(peer_id)`.
    pub(crate) pending_rv: std::collections::HashMap<PeerId, String>,
    /// X25519 public keys exchanged with contacts — each key derives the
    /// contact's persistent daily Mainline-DHT rendezvous slot (rv v2),
    /// which survives restarts without a fresh invite.
    pub(crate) peer_pubkeys: std::collections::HashMap<PeerId, [u8; 32]>,
    /// QUIC dials deferred by a short delay — the rendezvous arm dials
    /// once immediately (fails on unpunched CGNAT) and re-dials here
    /// after the mutual punch has had time to open both pinholes.
    pub(crate) deferred_dials: Vec<(std::time::Instant, Multiaddr)>,
    /// Confirmed contacts — SEC-1111-05: username announces and signed
    /// endpoint advertisements are sent only to this set; every other
    /// connected peer (DHT walkers, foreign relays) gets neither.
    pub(crate) contact_peers: HashSet<PeerId>,
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
    /// On-demand policy: last activity per Contact-class peer
    /// (connect, inbound request or outbound send resets it).
    /// Peers idle past `connectivity_config.idle_conn_ttl_secs` are
    /// disconnected — the next exchange re-dials on demand.
    pub(crate) contact_idle_since:
        std::collections::HashMap<PeerId, tokio::time::Instant>,
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
    /// RV: positive reachability evidence for OUR OWN advertised addrs —
    /// AutoNAT dial-backs, inbound conns, self-dial probes, gateway leases.
    /// Read by invite weighting and NAT display; in-memory only, never
    /// feeds `dead_addrs` and never gates a dial (unverified stays usable).
    pub(crate) addr_evidence: crate::p2p::addr_evidence::EvidenceLedger,
    /// RV-03: when the first external-addr candidate or first peer conn
    /// appeared — the AutoNAT probe window runs from here; expiry turns
    /// persistent `Unknown` into an honest "unreachable" UI state.
    pub(crate) nat_probe_opened_at: Option<std::time::Instant>,
    /// Set once the probe window expired while still `Unknown`.
    pub(crate) nat_probe_exhausted: bool,
    /// RV-06: results channel for spawned self-dial probes — armed in
    /// `run()` once the event loop owns the receive side.
    pub(crate) probe_tx:
        Option<tokio::sync::mpsc::Sender<crate::p2p::reach_probe::ProbeResult>>,
    /// RV-06: self-dial probe scheduling — last batch start and the count
    /// of results still outstanding (each received result decrements).
    pub(crate) probe_last_run: Option<std::time::Instant>,
    pub(crate) probe_in_flight: u8,
    /// B5: last handled `NetworkChanged` — Android ConnectivityManager can
    /// flap several times a minute; each flap drops every addr + every
    /// non-QUIC conn. Bursts are coalesced into one handler run.
    pub(crate) last_network_change: Option<std::time::Instant>,
    /// A debounced `NetworkChanged` is waiting for the coalesce tick.
    pub(crate) pending_network_change: bool,
    /// Tor lifecycle owner — MUST be held for the node's lifetime: the
    /// supervisor's `Running` (onion service + rend accept loop) lives in
    /// its `Inner`, and dropping the last handle tears the whole Tor
    /// generation down while the client survives in `client_slot` — a
    /// half-dead state (service gone, guards still up).
    #[allow(dead_code)]
    pub(crate) tor: Option<crate::p2p::tor::handle::TorHandle>,
}


