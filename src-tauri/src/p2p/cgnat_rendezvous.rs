//! Blind CGNAT Rendezvous over the global BitTorrent Mainline DHT (BEP-5).
//!
//! Why this exists:
//! When Phone A (Seed) and Phone B are **both** on mobile LTE behind CGNAT
//! with zero Noid relays in the network:
//! - Phone A knows its own external `IP_A:Port_A` via [`crate::p2p::stun_keepalive`]
//!   and puts it into its Invite string.
//! - Phone B receives Phone A's Invite and dials `IP_A:Port_A`, **but** Phone A's
//!   carrier CGNAT will drop Phone B's packets unless Phone A *also* sends a
//!   UDP packet toward Phone B's external `IP_B:Port_B`!
//!
//! How 1-click blind rendezvous works without any central server:
//! 1. Both phones compute a deterministic 20-byte rendezvous `info_hash`:
//!    `SHA256("noid:cgnat-rv:v1:" || seed_peer_id)[0..20]`.
//! 2. When Phone B dials Phone A's invite (`connect_to_addr`), Phone B sends a
//!    standard BEP-5 `get_peers` + `announce_peer(info_hash_A, port = Port_B)`
//!    UDP packet to the public Mainline DHT bootstrap nodes (`67.215.246.10:6881`,
//!    `87.98.162.88:6881`, `82.221.103.244:6881`).
//! 3. Phone A periodically queries `get_peers(info_hash_A)` on the Mainline DHT.
//!    As soon as Phone B's `IP_B:Port_B` appears in the `values` compact list,
//!    Phone A automatically fires [`crate::p2p::punch_assist::spawn_udp_punch_burst`]
//!    and `DialAddress(/ip4/IP_B/udp/Port_B/quic-v1/p2p/...)` back at Phone B!
//! 4. Both CGNATs now have matching outbound UDP state -> direct QUIC connects!

use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

/// Public BitTorrent Mainline DHT bootstrap nodes (IP literals — work even
/// when Android DNS wrapper is bypassed). Live-probed 2026-11-12: three of
/// the original six were dead/relocated, so the list carries DNS alternates
/// (`dht.transmissionbt.com` second A record, `dht.libtorrent.org`).
/// - `router.bittorrent.com`   -> `67.215.246.10:6881`
/// - `dht.transmissionbt.com`  -> `87.98.162.88:6881`, `212.129.33.59:6881`
/// - `router.utorrent.com`     -> `82.221.103.244:6881`
/// - `dht.libtorrent.org`      -> `185.157.221.247:25401`
/// - `router.magnets.im`       -> `86.105.4.36:6881`
pub const MAINLINE_DHT_NODES: &[SocketAddr] = &[
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(87, 98, 162, 88)), 6881),
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(212, 129, 33, 59)), 6881),
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(185, 157, 221, 247)), 25401),
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(67, 215, 246, 10)), 6881),
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(82, 221, 103, 244)), 6881),
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(86, 105, 4, 36)), 6881),
];

/// Compute the 20-byte rendezvous `info_hash` for a target `peer_id`.
pub fn rendezvous_info_hash(peer_id: &str) -> [u8; 20] {
    let mut h = Sha256::new();
    h.update(b"noid:cgnat-rv:v1:");
    h.update(peer_id.as_bytes());
    let digest = h.finalize();
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest[..20]);
    out
}

/// Persistent daily rendezvous slot for a contact (rv v2): derived from
/// the contact's exchanged X25519 public key, so a peer can be re-found
/// after restarts and CGNAT re-mapping WITHOUT a fresh invite. The slot
/// reveals nothing to parties who do not already hold the public key —
/// the public PeerId still never names a slot (SEC-1111-03), and the
/// daily rotation bounds the observability window.
pub fn daily_slot_label(public_key: &[u8; 32]) -> String {
    let mut h = Sha256::new();
    h.update(b"noid:rvseed:v2:");
    h.update(public_key);
    let seed = h.finalize();
    let day = chrono::Utc::now().format("%Y-%m-%d").to_string();
    format!("contact-rv2:{}:{}", to_hex(&seed[..16]), day)
}

/// Our own daily inbound slot — contacts announce at the slot derived
/// from OUR dht public key, so one label serves every contact.
pub fn own_daily_slot_label(public_key: &[u8; 32]) -> String {
    daily_slot_label(public_key)
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// XOR distance key between a Mainline node id and the rendezvous
/// info_hash — Kademlia's metric for iterative closest-node walks.
fn xor_key(node_id: &[u8; 20], info_hash: &[u8; 20]) -> [u8; 20] {
    let mut out = [0u8; 20];
    for i in 0..20 {
        out[i] = node_id[i] ^ info_hash[i];
    }
    out
}

/// Build a bencoded BEP-5 `get_peers` KRPC query packet.
pub fn build_get_peers_query(tx_id: &[u8; 2], sender_node_id: &[u8; 20], info_hash: &[u8; 20]) -> Vec<u8> {
    // d1:ad2:id20:<id>9:info_hash20:<hash>e1:q9:get_peers1:t2:<tx>1:y1:qe
    let mut pkt = Vec::with_capacity(104);
    pkt.extend_from_slice(b"d1:ad2:id20:");
    pkt.extend_from_slice(sender_node_id);
    pkt.extend_from_slice(b"9:info_hash20:");
    pkt.extend_from_slice(info_hash);
    pkt.extend_from_slice(b"e1:q9:get_peers1:t2:");
    pkt.extend_from_slice(tx_id);
    pkt.extend_from_slice(b"1:y1:qe");
    pkt
}

/// Build a bencoded BEP-5 `announce_peer` KRPC query packet announcing our
/// external STUN `port` under `info_hash` using the `token` returned by `get_peers`.
pub fn build_announce_peer_query(
    tx_id: &[u8; 2],
    sender_node_id: &[u8; 20],
    info_hash: &[u8; 20],
    port: u16,
    token: &[u8],
) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(140);
    pkt.extend_from_slice(b"d1:ad2:id20:");
    pkt.extend_from_slice(sender_node_id);
    pkt.extend_from_slice(b"12:implied_porti0e9:info_hash20:");
    pkt.extend_from_slice(info_hash);
    pkt.extend_from_slice(format!("4:porti{port}e5:token{}:", token.len()).as_bytes());
    pkt.extend_from_slice(token);
    pkt.extend_from_slice(b"e1:q13:announce_peer1:t2:");
    pkt.extend_from_slice(tx_id);
    pkt.extend_from_slice(b"1:y1:qe");
    pkt
}

/// Compact Mainline node entry: `(node_id, socket_addr)` — the id is
/// needed to sort candidates by XOR distance during the iterative walk.
pub type DhtNode = ([u8; 20], SocketAddr);

/// Extract compact IPv4 `SocketAddr` entries (`6:xxxxxx` inside `6:valuesl...e`)
/// and optional `token` / `nodes` (26-byte `id+ip+port`, ids kept — the
/// iterative walk sorts them by XOR distance to the info_hash) from a
/// bencoded `get_peers` KRPC response.
pub fn parse_get_peers_response(
    buf: &[u8],
) -> (Vec<SocketAddr>, Option<Vec<u8>>, Vec<DhtNode>) {
    let mut peers = Vec::new();
    let mut nodes = Vec::new();
    let token = extract_bencode_bytes(buf, b"5:token");

    // Parse `6:valuesl` list of 6-byte compact peer strings (`6:<4-byte-ip><2-byte-port>`)
    if let Some(mut pos) = find_subslice(buf, b"6:valuesl") {
        pos += b"6:valuesl".len();
        while pos + 8 <= buf.len() {
            if buf[pos] == b'e' {
                break;
            }
            if &buf[pos..pos + 2] == b"6:" {
                pos += 2;
                let ip = Ipv4Addr::new(buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]);
                let port = u16::from_be_bytes([buf[pos + 4], buf[pos + 5]]);
                if !ip.is_unspecified() && !ip.is_loopback() && port != 0 {
                    peers.push(SocketAddr::new(IpAddr::V4(ip), port));
                }
                pos += 6;
            } else {
                break;
            }
        }
    }

    // Parse `5:nodes` compact 26-byte entries (`20-byte-id + 4-byte-ip + 2-byte-port`)
    if let Some(raw_nodes) = extract_bencode_bytes(buf, b"5:nodes") {
        for chunk in raw_nodes.chunks_exact(26) {
            let ip = Ipv4Addr::new(chunk[20], chunk[21], chunk[22], chunk[23]);
            let port = u16::from_be_bytes([chunk[24], chunk[25]]);
            if !ip.is_unspecified() && !ip.is_private() && port != 0 {
                let mut id = [0u8; 20];
                id.copy_from_slice(&chunk[..20]);
                nodes.push((id, SocketAddr::new(IpAddr::V4(ip), port)));
            }
        }
    }

    (peers, token, nodes)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn extract_bencode_bytes(buf: &[u8], key: &[u8]) -> Option<Vec<u8>> {
    let mut pos = find_subslice(buf, key)? + key.len();
    let colon = buf[pos..].iter().position(|&b| b == b':')?;
    let len_str = std::str::from_utf8(&buf[pos..pos + colon]).ok()?;
    let len: usize = len_str.parse().ok()?;
    pos += colon + 1;
    if pos + len > buf.len() {
        return None;
    }
    Some(buf[pos..pos + len].to_vec())
}

/// Announce our external STUN `my_external_port` into the rendezvous slot for
/// `target_peer_id` and return any peer `SocketAddr`s already waiting in that slot.
pub fn announce_and_poll_rendezvous(
    target_peer_id: &str,
    _my_peer_id: &str,
    my_external_port: u16,
) -> Vec<SocketAddr> {
    // `my_external_port == 0` = poll-only mode (a seed node watching its own
    // rendezvous slot for inbound announcers must not announce anything).
    if std::env::var_os("NOID_DISABLE_STUN").is_some() {
        return Vec::new();
    }
    let Ok(sock) = UdpSocket::bind("0.0.0.0:0") else {
        return Vec::new();
    };
    let _ = sock.set_read_timeout(Some(Duration::from_millis(250)));
    let _ = sock.set_write_timeout(Some(Duration::from_millis(150)));

    let info_hash = rendezvous_info_hash(target_peer_id);
    // SEC-1111-04: fresh CSPRNG KRPC node id + transaction id per poll —
    // deriving node_id from our PeerId linked every Mainline-DHT query to
    // our noid identity, and the static b"rv" tx id was a protocol tag.
    let my_node_id: [u8; 20] = rand::random();
    let tx_id: [u8; 2] = rand::random();
    let q = build_get_peers_query(&tx_id, &my_node_id, &info_hash);

    // Iterative Kademlia-style walk: seed from the bootstrap list, then
    // re-query the nodes each response claims are XOR-closest to the
    // info_hash. A one-shot bootstrap query almost never lands on the
    // nodes that actually hold the slot — BEP-5 converges announce and
    // lookup only through this walk (bounded to ~2.5s total).
    let mut queried: std::collections::HashSet<SocketAddr> =
        std::collections::HashSet::new();
    for boot in MAINLINE_DHT_NODES {
        if queried.insert(*boot) {
            let _ = sock.send_to(&q, boot);
        }
    }

    let mut discovered_peers: Vec<SocketAddr> = Vec::new();
    let mut candidates: Vec<([u8; 20], SocketAddr)> = Vec::new();
    let mut tokens: std::collections::HashMap<SocketAddr, Vec<u8>> =
        std::collections::HashMap::new();
    let mut buf = [0u8; 1500];
    let deadline = std::time::Instant::now() + Duration::from_millis(2500);

    for round in 0..5 {
        // Drain replies until the socket idles, then (rounds 0..4) extend
        // the walk toward XOR-closest unqueried nodes.
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            let (peers, token, closer_nodes) = parse_get_peers_response(&buf[..n]);
            for p in peers {
                if !discovered_peers.contains(&p) {
                    discovered_peers.push(p);
                }
            }
            if let Some(tok) = token {
                tokens.insert(from, tok);
            }
            for (nid, sa) in closer_nodes {
                if !queried.contains(&sa)
                    && !candidates.iter().any(|(_, a)| *a == sa)
                {
                    candidates.push((nid, sa));
                }
            }
        }
        if std::time::Instant::now() >= deadline {
            break;
        }
        if round < 4 {
            candidates.sort_by(|a, b| {
                xor_key(&a.0, &info_hash).cmp(&xor_key(&b.0, &info_hash))
            });
            let mut picked = 0usize;
            for (_, sa) in candidates.iter() {
                if picked >= 8 {
                    break;
                }
                if queried.insert(*sa) {
                    let _ = sock.send_to(&q, sa);
                    picked += 1;
                }
            }
            if picked == 0 {
                break;
            }
        }
    }

    // Announce our external port to every node that issued a token —
    // the walk sorted them closest-first, so publication lands on (or
    // near) the slot's actual keepers.
    if my_external_port != 0 {
        for (sa, tok) in &tokens {
            let ann = build_announce_peer_query(
                &rand::random(),
                &my_node_id,
                &info_hash,
                my_external_port,
                tok,
            );
            let _ = sock.send_to(&ann, sa);
        }
    }
    discovered_peers
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bencoded_values_and_token() {
        // Fake response containing token "tok1" and one compact peer 85.140.1.2:4020 (0x0FB4)
        let mut resp = Vec::new();
        resp.extend_from_slice(b"d1:rd5:token4:tok16:valuesl6:");
        resp.extend_from_slice(&[85, 140, 1, 2, 0x0F, 0xB4]);
        resp.extend_from_slice(b"ee1:t2:rv1:y1:re");

        let (peers, token, _) = parse_get_peers_response(&resp);
        assert_eq!(token.as_deref(), Some(b"tok1".as_slice()));
        assert_eq!(peers, vec!["85.140.1.2:4020".parse().unwrap()]);
    }

    #[test]
    fn daily_slot_label_is_deterministic_and_key_bound() {
        let k1 = [7u8; 32];
        let k2 = [8u8; 32];
        assert_eq!(daily_slot_label(&k1), daily_slot_label(&k1));
        assert_ne!(daily_slot_label(&k1), daily_slot_label(&k2));
        assert!(daily_slot_label(&k1).starts_with("contact-rv2:"));
    }

    #[test]
    fn xor_key_orders_by_distance() {
        let target = [0u8; 20];
        let near = [0u8; 20];
        let mut far = [0u8; 20];
        far[0] = 0x80;
        assert!(xor_key(&near, &target) < xor_key(&far, &target));
    }

    #[test]
    fn parses_compact_nodes_with_ids() {
        // nodes = one 26-byte entry: id=0xAA*20, ip=85.140.1.2, port=0x1FB5 (4021)
        let mut nodes26 = Vec::new();
        nodes26.extend_from_slice(&[0xAAu8; 20]);
        nodes26.extend_from_slice(&[85, 140, 1, 2, 0x0F, 0xB5]);
        let mut resp = Vec::new();
        resp.extend_from_slice(b"d1:rd5:nodes26:");
        resp.extend_from_slice(&nodes26);
        resp.extend_from_slice(b"e1:t2:rv1:y1:re");

        let (_, _, nodes) = parse_get_peers_response(&resp);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].0, [0xAAu8; 20]);
        assert_eq!(nodes[0].1, "85.140.1.2:4021".parse().unwrap());
    }
}
