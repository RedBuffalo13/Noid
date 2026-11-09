# Noid Messenger

![banner](docs/manual/assets/banner.svg)

**Decentralized, end-to-end-encrypted P2P messenger.** One binary is the
chat client, the Kademlia DHT node, the circuit relay and the offline
mailbox — no central server stores your messages, and there is no
separate relay service to run.

## Highlights

- **E2EE**: X3DH + Double Ratchet per contact; prekey bundles are
  Ed25519-signed and verified by every consumer.
- **PIN gate**: Argon2id → AES-256-GCM field encryption in SQLite;
  timed lockout on brute force; KillPIN wipes everything instantly.
- **Zero server**: Kademlia DHT for usernames, prekeys and mailbox
  pointers; `/p2p-circuit` relay for NAT traversal; offline envelopes
  parked on peer mailbox nodes.
- **Embedded Tor**: optional Arti client inside the same binary — every
  node can publish its own `.onion` service, dial peers over onion3,
  and run onion-relayed circuits. Three modes: off / additional /
  tor-only (fail-closed). Consent-gated, stable onion identity, no
  external tor daemon required.
- **Cross-platform**: Windows, Linux/VPS, Android — one Rust core
  (libp2p, Noise, QUIC/TCP/WebSocket, embedded Arti 0.48, mDNS, AutoNAT)
  + Svelte 5 + Tauri 2.

## Status

**v0.2.0 — Embedded Tor (2026-11-08).**

✅ **Verified live** on all platforms: Windows ↔ Linux VPS ↔ Android —
onion bootstrap, descriptor publishing, onion3 dials, relayed circuits
over onion, multi-path (onion + QUIC + TCP + WS) connectivity.

✅ **Android (JP1 field test):** full Tor bootstrap on a real device,
`gqd.onion` service published, stable identity across reinstalls,
PIN/mode/relay persistence — verified end-to-end.

⚠️ **Known limitation:** on networks with Tor DPI filtering (several
mobile carriers / ISPs), embedded Tor needs an external VPN tunnel or
bridges — bridges/pluggable transports are planned for a later release.
The normal P2P mesh works without Tor on any network.

## Embedded Tor — why, what, risks, usage

### Why we built onion in

A pure-P2P messenger still has weak spots without Tor:

- **Metadata exposure**: every direct connection reveals your IP to
  contacts, relays and anyone watching the wire.
- **Reachability**: behind CGNAT you depend on third-party relay
  circuits — an address others can always dial is not guaranteed.
- **Censorship**: a messenger that cannot survive blocked endpoints is
  a messenger that works only where it is allowed to.

Embedding Arti (the official Rust Tor client) directly into the binary
gives every node a first-class `.onion` identity — no external tor
daemon, no Orbot, no proxy config, no root.

### What it gives you

- **Your own hidden service**: a stable `*.onion` address derived from
  your persistent identity key — published to Tor HSDirs, reachable by
  any Noid user anywhere on earth, behind any NAT.
- **Onion invites**: your invite string automatically carries the
  `/onion3/…` endpoint alongside direct addresses — the receiver just
  pastes it; Noid chooses the best path.
- **Metadata resistance**: inside `tor_only` every circuit is 3-hop
  onion routing — contacts see an onion address, never your IP.
- **Onion-relayed circuits**: `/p2p-circuit` reservations can ride on
  top of onion transports — relayed reachability stays inside the Tor
  anonymity layer.
- **Fail-closed tor_only**: no direct listeners, no silent fallback —
  if Tor is down, nothing leaks to the raw internet.

### Risks and honest limitations

- **DPI blocking**: some carriers/ISPs drop Tor traffic entirely (we
  verified this live on a Russian LTE carrier). Workarounds: run Noid
  through an external VPN, use a non-filtering network, or wait for
  bridge support (pluggable transports — planned, not in v0.2.0).
- **Latency**: first bootstrap takes ~30–90 s (warm cache ~5 s);
  circuits add round-trips — messaging stays usable but slower.
- **Battery/data on Android**: Tor is off by default and requires
  explicit consent; the onion-relay opt-in is a separate switch with a
  separate metered-traffic consent.
- **Not a magic cloak**: onion hides the transport path, not the fact
  that your device runs Noid.

### How to use

1. Settings → **Tor** → pick a mode:
   - `off` — Tor disabled (default), ordinary networking only;
   - `additional` — onion service + dials alongside direct networking;
   - `tor_only` — onion-only, fail-closed, no direct listeners.
2. Accept the consent (versioned — asked once, persisted).
3. Wait for bootstrap → *Tor ready* — your invite now includes the
   `/onion3/` endpoint automatically.
4. Optional: **Onion relay** switch lets your node carry other users'
   circuits over Tor (separate metered-network consent on Android).

The Tor mode, consent and relay flags persist across restarts —
the node comes back in the mode you left it.

### What an observer can see

Message **content** is always E2E-encrypted (X3DH + Double Ratchet) on
every transport — direct and onion alike. What differs is the metadata.

**Passive wire observer (ISP / DPI):**

| Transport | Visible | Hidden |
|-----------|---------|--------|
| TCP / QUIC :4020, WS :4021 | Your IP ↔ peer IP, Noid-fingerprintable ports, WS HTTP Upgrade header, timing + volumes | Message content, both PeerIds (Noise XX encrypts identities) |
| `/onion3/` | "This IP talks to Tor" — guard IP, padded cells, timing | That it is Noid at all; the `.onion` destination; everything inside |

**Protocol participants:**

| Who sees | `off` | `additional` | `tor_only` |
|----------|-------|--------------|------------|
| Contacts | PeerId + your public IP | PeerId + IP (+ `.onion` if invited that way) | PeerId + `.onion` only — **IP never enters the protocol** |
| Relay nodes | Circuit: source↔dest PeerIds + volumes | Same, or onion-bound circuits | Same, no source IP |
| Mailbox node | Ciphertext envelopes + whose mailbox + delivery timing | Same | Same, no sender IP |
| DHT (any participant) | username→PeerId, prekey bundles, mailbox pointers | Same | Same |
| Active prober | Dials `IP:4020` → learns PeerId | Same + onion service exists for holders | Connection refused — no direct listener |

**Hiding your IP — available options:**

| Goal | Configuration |
|------|---------------|
| Hide IP from contacts | `relayed_only` privacy mode — all dial-outs ride `/p2p-circuit`; relays still see it |
| Hide IP from everyone | `tor_only` — only the Tor guard sees an IP, and it sees "Tor client", not Noid |
| Best speed/privacy mix | `additional` + share onion endpoint in invites |
| Outside Noid | VPN — peers see the VPN exit IP instead of yours |

Honest caveat: the first hop always sees an IP — the question is *who*
and *what else they learn*. `relayed_only` trusts your chosen relays;
`tor_only` makes it a random Tor guard that cannot even tell the traffic
is Noid. Residual correlation risks on every transport: stable
PeerId/onion pseudonymity, envelope-size timing — there is no traffic
padding yet.

## Manual / Руководство (EN + RU)

| Document | English | Русский |
|----------|---------|---------|
| Project description + current state | [PROJECT_DESCRIPTION_EN.md](docs/manual/PROJECT_DESCRIPTION_EN.md) | [PROJECT_DESCRIPTION_RU.md](docs/manual/PROJECT_DESCRIPTION_RU.md) |
| Presentation (text spec) | [PRESENTATION_EN.md](docs/manual/PRESENTATION_EN.md) | [PRESENTATION_RU.md](docs/manual/PRESENTATION_RU.md) |
| Installation & setup | [INSTALLATION_EN.md](docs/manual/INSTALLATION_EN.md) | [INSTALLATION_RU.md](docs/manual/INSTALLATION_RU.md) |
| Manual index | [docs/manual/README.md](docs/manual/README.md) | same |
| Graphics | [banner.svg](docs/manual/assets/banner.svg) · [architecture.svg](docs/manual/assets/architecture.svg) | same |

## Downloads

| Platform | Package | Notes |
|----------|---------|-------|
| Windows (x64) | [noid-windows-x64-setup.exe](https://github.com/RedBuffalo13/Noid/releases/download/v0.1.0-interim/noid-windows-x64-setup.exe) | NSIS installer — recommended. [All releases](https://github.com/RedBuffalo13/Noid/releases) |
| Windows (x64) | [noid-windows-x64.msi](https://github.com/RedBuffalo13/Noid/releases/download/v0.1.0-interim/noid-windows-x64.msi) | MSI package |
| Linux (x86_64) | [noid-linux-x86_64](https://github.com/RedBuffalo13/Noid/releases/download/v0.1.0-interim/noid-linux-x86_64) | Standalone binary — `chmod +x` |
| Android (arm64) | [noid-android-arm64.apk](https://github.com/RedBuffalo13/Noid/releases/download/v0.1.0-interim/noid-android-arm64.apk) | Sideload APK (debug-signed) |

## Quick start

```bash
git clone <repo> && cd noid && npm install
npm run tauri dev            # dev
npm run tauri build          # release bundle
```

Headless node: `cargo build --release --bin noid`, open ports
`4020/tcp+udp` and `4021/tcp`, run one process — it is the app, the
relay and the mailbox at once.

## Architecture

![architecture](docs/manual/assets/architecture.svg)

## Credits

Built by amissa_domo. Significant parts of the codebase, security audit,
connection-stability remediation and this documentation were developed
with **Devin** ([devin.ai](https://devin.ai)) — thank you to the Devin
team.

## Cooperation

I'm ready for co-development. Bring an ideas. Just want to do it full-work



## License

TBD.
