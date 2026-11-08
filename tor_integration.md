
## P2–P7 закрытие (2026-11-07)

**P2 transport:** onion_addr (canonical parse, RFC4648, v3 only), TorTransport (libp2p Transport over DataStream, 120s dial), accept_loop (rend→vport 4020→channel), upgrade (Noise→Yamux 30s), swarm_builder via with_other_transport+OptionalTransport, AddrClass::Onion3 в dial-book/cache (не Kademlia), node.with_config проводит фабрику + wire_inbound + listen_on.

**P3 policy:** build_behaviour.rs (direct_discovery гасит mDNS+UPnP через Toggle), две ветки build_swarm: direct (TCP+QUIC+WS+DNS) vs tor_only (onion-only, relay-client поверх onion, fail-closed без фабрики). network_generation отдельно от login_epoch — set_tor_mode пересоздаёт только ноду. B2 routing-guard (defer при пустой таблице), B4 stale-replay rate-limit в ValidatingStore, B5 debounce NetworkChanged.

**P4 endpoints:** EndpointRecord (≤8/≤4KiB/≤24h/skew 5мин, ed25519 verify, canonical noid-endpoints-v1) — 5/5 тестов. EndpointAdvertise по auth-каналу при коннекте → peer_cache (GCM) как hint. get_my_invite: onion3-hint всегда, STUN запрещён в tor_only. connect_to_addr: tor_consent_required при выключенном Tor. invite.rs: host.onion[:port]→/onion3/h:vport. B3 закрыт анализом (~500B << 12KiB; «value too large»=отказ стора).

**P5 relay:** to_onion_relay_config (4res/2circ/32MiB/30min), set_tor_relay (отдельные consent-флаги), onion_relay_enabled гейт (opt-in && consent && running), --tor-relay headless opt-in.

**P6 UI:** TorSettings.svelte (mode select + consent + status + relay toggles), NetworkStatusBar (B8 zero-peer баннер), i18n en+ru 26 ключей, B6 noid.log, svelte-check 0/0.

**P7:** оба wipe-пути — полный barrier (db close → epoch → gate → tor.stop → secure_delete → logs). vendor/arti-client LICENSE-MIT+LICENSE-APACHE+PATCH.md. Build: check/clippy ±feature чист, 353/356 тестов (3 ignored = live).

**Открытое поле приёмки (нужен реальный запуск):** swarm-level onion3-dial end-to-end, mode-switch на живом приложении, metered-детект Android (ConnectivityManager), B7 wakelock-политика, FGS timeout/resume, 1h soak + onion-прогон на JP1, signed APK (нужен keystore).
