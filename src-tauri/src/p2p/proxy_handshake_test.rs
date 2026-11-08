//! Integration test for the outbound proxy handshake: a stub SOCKS5
//! server verifies the greeting + CONNECT bytes, then echoes a marker —
//! proving the tunneled stream is usable end-to-end.

#[cfg(test)]
mod tests {
    use libp2p_tcp::proxy::{handshake, ProxyConfig};
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};

    /// Run a one-shot SOCKS5 server on an ephemeral port; returns its addr.
    fn spawn_stub_socks5(expected_target: std::net::SocketAddr) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            // Greeting: [0x05, nmethods, methods...] -> choose no-auth.
            let mut g = [0u8; 2];
            s.read_exact(&mut g).unwrap();
            assert_eq!(g[0], 0x05);
            let mut rest = vec![0u8; g[1] as usize];
            s.read_exact(&mut rest).unwrap();
            s.write_all(&[0x05, 0x00]).unwrap();

            // CONNECT: ver=5 cmd=1 rsv=0 atyp + addr + port.
            let mut h = [0u8; 4];
            s.read_exact(&mut h).unwrap();
            assert!(h[0] == 0x05 && h[1] == 0x01);
            let port = match h[3] {
                0x01 => {
                    let mut a = [0u8; 6];
                    s.read_exact(&mut a).unwrap();
                    u16::from_be_bytes([a[4], a[5]])
                }
                _ => panic!("unexpected atyp"),
            };
            assert_eq!(port, expected_target.port());
            // Reply success with a bound addr of 0.0.0.0:0.
            s.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .unwrap();
            // Echo a marker to prove the tunnel is usable.
            s.write_all(b"OK").unwrap();
        });
        addr
    }

    #[tokio::test]
    async fn socks5_handshake_tunnels_stream() {
        let target: std::net::SocketAddr = "93.184.216.34:4020".parse().unwrap();
        let proxy_addr = spawn_stub_socks5(target);

        let std_stream = TcpStream::connect(proxy_addr).unwrap();
        std_stream.set_nonblocking(true).unwrap();
        let tokio_stream = tokio::net::TcpStream::from_std(std_stream).unwrap();
        let mut stream = libp2p_tcp::tokio::TcpStream(tokio_stream);

        let cfg = ProxyConfig::socks5(proxy_addr, None, None);
        handshake(&mut stream, target, &cfg).await.unwrap();

        use futures::AsyncReadExt;
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"OK");
    }
}
