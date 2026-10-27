#[cfg(test)]
mod tests {
    use crate::log_redact::redact;

    #[test]
    fn redacts_ipv4() {
        assert_eq!(
            redact("dialing /ip4/203.0.113.7/tcp/4001 failed"),
            "dialing /ip4/<ip>/tcp/4001 failed"
        );
    }

    #[test]
    fn redacts_ipv4_mapped_and_plain() {
        assert_eq!(redact("from 10.0.0.1 to 192.168.1.5"), "from <ip> to <ip>");
    }

    #[test]
    fn redacts_ipv6_compressed_and_full() {
        assert_eq!(redact("addr fe80::1"), "addr <ip>");
        assert_eq!(redact("addr ::1"), "addr <ip>");
        assert_eq!(
            redact("addr 2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
            "addr <ip>"
        );
    }

    #[test]
    fn keeps_timestamps() {
        assert_eq!(
            redact("at 2026-06-09T12:34:56Z done"),
            "at 2026-06-09T12:34:56Z done"
        );
    }

    #[test]
    fn shortens_ed25519_peer_id() {
        assert_eq!(
            redact("peer 12D3KooWABCDefgh123456789ABCDefgh123456789ABC connected"),
            "peer 12D3KooW… connected"
        );
    }

    #[test]
    fn shortens_rsa_peer_id() {
        assert_eq!(
            redact("peer QmYyQSo1c1Ym7orWxLYvCrM2EmyFTTbE1vw1vR6d7LsDfg connected"),
            "peer QmYyQSo1… connected"
        );
    }

    #[test]
    fn ignores_short_lookalikes() {
        assert_eq!(redact("Qm foo 12D3KooW"), "Qm foo 12D3KooW");
    }

    #[test]
    fn combined_multiaddr() {
        assert_eq!(
            redact("/ip4/8.8.8.8/tcp/4001/p2p/12D3KooWABCDefgh123456789ABCDefgh123456789ABC"),
            "/ip4/<ip>/tcp/4001/p2p/12D3KooW…"
        );
    }
}
