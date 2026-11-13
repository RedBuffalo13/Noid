//! P2PNode constructors (new/new_relay/with_config) — extracted from node.rs (Q05/A5b). Bodies moved verbatim.

use anyhow::Result;
use libp2p::{kad, Multiaddr, PeerId};
use std::collections::HashSet;

use crate::p2p::node::P2PNode;
use crate::p2p::peer_cache::PeerCache;
use crate::p2p::relay_config::{NodeRole, RelayConfig};
use crate::p2p::relay_status::NatStatus;
use crate::p2p::swarm_builder::build_swarm;
use crate::security::DHTCipher;

impl P2PNode {
    pub async fn new(data_dir: &std::path::Path) -> Result<Self> {
        let config = RelayConfig::load(data_dir);
        let local_key = libp2p::identity::Keypair::generate_ed25519();
        Self::with_config(data_dir, config, local_key, DHTCipher::new(), None, None).await
    }

    /// Ephemeral relay node for tests — fresh random keys.
    pub async fn new_relay(data_dir: &std::path::Path, port: Option<u16>) -> Result<Self> {
        let mut config = RelayConfig::load(data_dir);
        config.role = NodeRole::Relay;
        if let Some(p) = port {
            config.listen_port = p;
        }
        let local_key = libp2p::identity::Keypair::generate_ed25519();
        Self::with_config(data_dir, config, local_key, DHTCipher::new(), None, None).await
    }

    /// Production node — takes identity keys that were decrypted from the
    /// encrypted key store (NOIDKEY1 envelope) after a successful login, plus
    /// the PIN-derived master key used to field-encrypt mailbox.db and the
    /// peer cache. Key material is never read from or written to disk here
    /// in plaintext. `tor` (when Some) hooks the onion transport into the
    /// swarm — the node then dials `/onion3/` addrs via Tor.
    pub async fn new_with_keys(
        data_dir: &std::path::Path,
        local_key: libp2p::identity::Keypair,
        dht_cipher: DHTCipher,
        master_key: [u8; 32],
        tor: Option<crate::p2p::tor::handle::TorHandle>,
    ) -> Result<Self> {
        let config = RelayConfig::load(data_dir);
        Self::with_config(data_dir, config, local_key, dht_cipher, Some(master_key), tor).await
    }

    /// Production headless relay — same key handling as `new_with_keys`,
    /// forced into `NodeRole::Relay`.
    pub async fn new_relay_with_keys(
        data_dir: &std::path::Path,
        local_key: libp2p::identity::Keypair,
        dht_cipher: DHTCipher,
        port: Option<u16>,
        master_key: [u8; 32],
        tor: Option<crate::p2p::tor::handle::TorHandle>,
    ) -> Result<Self> {
        let mut config = RelayConfig::load(data_dir);
        config.role = NodeRole::Relay;
        if let Some(p) = port {
            config.listen_port = p;
        }
        Self::with_config(data_dir, config, local_key, dht_cipher, Some(master_key), tor).await
    }

    async fn with_config(
        data_dir: &std::path::Path,
        relay_config: RelayConfig,
        local_key: libp2p::identity::Keypair,
        dht_cipher: DHTCipher,
        master_key: Option<[u8; 32]>,
        tor: Option<crate::p2p::tor::handle::TorHandle>,
    ) -> Result<Self> {
        let peer_id = PeerId::from(local_key.public());
        let identity_keypair = local_key.clone();
        log::debug!("Local peer id: {peer_id}");

        // Onion transport: when a Tor generation is running, register the
        // TorTransport factory (dials /onion3/, inbound via accept channel)
        // and subscribe our service listen addr.
        let onion_factory = tor.as_ref().map(|t| {
            // The transport resolves the client lazily at dial time — safe
            // to register before bootstrap finishes (race fixed by
            // client_slot). The inbound sender is parked until a
            // generation's rend stream exists.
            let transport = crate::p2p::tor::transport::TorTransport::new(t.client_slot());
            t.wire_inbound(transport.accept_tx());
            Box::new(
                move |key: &libp2p::identity::Keypair| {
                    crate::p2p::tor::transport::upgrade(transport, key)
                },
            ) as crate::p2p::swarm_builder::UpgradedTransportFactory
        });

        // Field cipher for local data at rest (mailbox.db ids, peer cache,
        // proxy credentials). Present on production nodes (post-login).
        // Created before the policy gate below — proxy_config decryption
        // needs it.
        let field_cipher =
            master_key.map(|k| std::sync::Arc::new(crate::security::field_cipher::FieldCipher::new(k)));

        // Effective policy BEFORE the swarm is built (fail-closed): a
        // `tor_only` desired mode builds a swarm with zero direct
        // transports — TCP/QUIC/DNS/WS/mDNS/UPnP never exist, so nothing
        // can fall back to direct networking.
        let direct_allowed = tor.as_ref().is_none_or(|t| {
            t.status().desired_mode != crate::p2p::tor::mode::TorMode::TorOnly
        });
        // SEC-1111-03: the FULL direct-net policy — privacy mode + active
        // outbound proxy + Tor mode. Governs direct LISTENERS too: an open
        // TCP/QUIC socket under RelayedOnly or a proxy is fingerprintable
        // and accepts inbound flows the privacy mode says we must not have.
        let direct_net_ok = relay_config.privacy == crate::p2p::relay_config::PrivacyMode::Direct
            && crate::p2p::proxy_config::NoidProxyConfig::load_with_cipher(
                data_dir,
                field_cipher.as_deref(),
            )
            .mode
                == crate::p2p::proxy_config::ProxyMode::Off
            && direct_allowed;
        let onion_relay_enabled = tor.as_ref().is_some_and(|t| t.onion_relay_enabled());
        let mut swarm = build_swarm(local_key, &relay_config, onion_factory, direct_allowed, onion_relay_enabled).await?;

        let own_onion = tor.as_ref().and_then(|t| t.listen_multiaddr());
        if let Some(listen) = &own_onion {
            if let Err(e) = swarm.listen_on(listen.clone()) {
                log::warn!("onion listen_on failed for {}: {}", listen, e);
            }
        }

        let (bound, port) = crate::p2p::node_bind::bind_direct_listeners(
            &mut swarm,
            &relay_config,
            direct_net_ok,
        )?;
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

        // Case 1 (Wi-Fi router NAT): NAT-PMP port-mapping probe. Runs only
        // when a private LAN IPv4 exists (returns fast on direct/CGNAT
        // interfaces). A successful lease is *real* inbound reachability —
        // the router itself confirmed the mapping — so it also promotes the
        // node to Kademlia Server and NatStatus::Public below.
        // SEC-1111-03: every direct-network probe is OFF unless Direct
        // privacy AND no outbound proxy — NAT-PMP/STUN broadcast our real
        // IP and bypass any TCP proxy entirely.
        // (field_cipher and direct_net_ok are computed above — before the
        // listener binds they gate too.)
        let mut addr_evidence = crate::p2p::addr_evidence::EvidenceLedger::default();
        let (nat_pmp_public, stun_mapping) = crate::p2p::node_nat::nat_probe(
            &mut swarm,
            &mut external_addrs,
            &relay_config,
            direct_net_ok,
            bound,
            port,
            &mut addr_evidence,
        )
        .await;
        // Field cipher defined above (needed earlier by the direct-net
        // proxy check).

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

        // Platform-adaptive profile — picks behavior policy from the build
        // target + session type. `relay_config.profile_override` lets an
        // operator force a profile; auto = compile-time detection.
        let profile = crate::p2p::profile::NodeProfile::detect(None);
        log::info!("Node profile: {}", profile.name());

        // A node configured with an explicit public external addr — or
        // running as a dedicated relay — is reachable by construction; do
        // not leave it `Unknown` (UI shows "Behind the NAT", invites omit
        // the direct addrs and `should_relay()` stays off for Auto role).
        // On Mobile the Relay role does NOT confer reachability — a phone on
        // CGNAT cannot accept inbound, so treating role=Relay as assumed-Public
        // produced a fake "Public" badge while invites stayed empty.
        let relay_role_credible = relay_config.role
            == crate::p2p::relay_config::NodeRole::Relay
            && profile.kind != crate::p2p::profile::ProfileKind::Mobile;
        // A completed STUN probe PROVES we sit behind a NAT (the external
        // mapping exists only because a NAT rewrote the source). On mobile
        // AutoNAT dial-back may never run — leaving `Unknown` there meant a
        // permanent "Detecting…" badge. `Private` is the honest label until
        // a peer confirms reachability; `Unknown` is kept for the no-info
        // case (probe failed entirely).
        let nat_status = if relay_config.external_addr.is_some()
            || relay_role_credible
            || nat_pmp_public
        {
            NatStatus::Public
        } else if stun_mapping.is_some() {
            NatStatus::Private
        } else {
            NatStatus::Unknown
        };

        // Outbound proxy (proxy_config.json): default Off — a no-op when
        // absent or invalid, preserving stock dial behaviour.
        crate::p2p::proxy_config::NoidProxyConfig::load_with_cipher(
            data_dir,
            field_cipher.as_deref(),
        )
        .apply();

        Ok(Self {
            swarm,
            peer_id,
            identity_keypair,
            dht_cipher,
            pending_messages: std::collections::HashMap::new(),
            hop_pending_noid: std::collections::HashMap::new(),
            hop_pending_hop: std::collections::HashMap::new(),
            hop_outbound_dest: std::collections::HashMap::new(),
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
            pending_blind_queries: std::collections::HashMap::new(),
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
            connectivity_config: crate::p2p::connectivity_config::ConnectivityConfig::load(data_dir),
            nat_status,
            profile,
            external_addrs,
            own_onion_addr: own_onion,
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
            room_topics: std::collections::HashMap::new(),
            room_topics_day: 0,
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
            contact_peers: HashSet::new(),
            rv_secrets: std::collections::VecDeque::new(),
            pending_rv: std::collections::HashMap::new(),
            peer_pubkeys: std::collections::HashMap::new(),
            deferred_dials: Vec::new(),
            bootstrap_dial_cursor: std::collections::HashMap::new(),
            bootstrap_retry_state: std::collections::HashMap::new(),
            ping_failures: std::collections::HashMap::new(),
            conn_quic: std::collections::HashMap::new(),
            pending_conn_close: Vec::new(),
            contact_idle_since: std::collections::HashMap::new(),
            conn_dialer: std::collections::HashMap::new(),
            conn_remote: std::collections::HashMap::new(),
            addr_failures: std::collections::HashMap::new(),
            dead_addrs: std::collections::HashMap::new(),
            addr_evidence,
            nat_probe_opened_at: None,
            nat_probe_exhausted: false,
            probe_tx: None,
            probe_last_run: None,
            probe_in_flight: 0,
            pending_prekey_puts: std::collections::HashMap::new(),
            deferred_dht_puts: Vec::new(),
            last_network_change: None,
            pending_network_change: false,
            tor,
        })
}
}
