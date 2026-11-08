//! Outbound TCP proxying (HTTP CONNECT / SOCKS5).
//!
//! Noid patch: when a proxy is configured, [`crate::Transport::dial`]
//! connects the socket to the proxy address instead of the target, then
//! performs the proxy handshake on the established stream *before*
//! returning it to the caller. The caller (noise upgrade, WS upgrade)
//! sees a normal TCP stream — the tunnel is transparent.
//!
//! Scope notes:
//! - Outbound only. A proxy can never make the node *reachable* — inbound
//!   connectivity still comes from listeners, UPnP, IPv6, or relays.
//! - UDP/QUIC is unaffected (TCP transports only).
//! - Credentials are held in memory only and never logged.

use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p_core::multiaddr::Protocol;
use libp2p_core::Multiaddr;
use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::RwLock;

/// Cap on the HTTP CONNECT response header read.
const MAX_CONNECT_RESPONSE: usize = 8192;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyKind {
    HttpConnect,
    Socks5,
}

/// Active proxy configuration. `password` is intentionally skipped by
/// `Debug` — proxy credentials must never hit logs.
#[derive(Clone)]
pub struct ProxyConfig {
    pub kind: ProxyKind,
    /// Where to TCP-connect (the proxy itself).
    pub addr: SocketAddr,
    pub username: Option<String>,
    password: Option<String>,
}

impl fmt::Debug for ProxyConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyConfig")
            .field("kind", &self.kind)
            .field("addr", &self.addr)
            .field("username", &self.username.as_deref().map(|_| "***"))
            .field("password", &self.password.as_ref().map(|_| "***"))
            .finish()
    }
}

impl ProxyConfig {
    pub fn http(addr: SocketAddr) -> Self {
        Self {
            kind: ProxyKind::HttpConnect,
            addr,
            username: None,
            password: None,
        }
    }

    pub fn socks5(addr: SocketAddr, username: Option<String>, password: Option<String>) -> Self {
        Self {
            kind: ProxyKind::Socks5,
            addr,
            username,
            password,
        }
    }

    /// Attach Basic-auth credentials to an HTTP CONNECT config.
    pub fn with_auth(mut self, username: String, password: String) -> Self {
        self.username = Some(username);
        self.password = Some(password);
        self
    }
}

/// Process-wide proxy setting — `None` means direct dials (default,
/// preserving stock libp2p-tcp behaviour).
static PROXY: RwLock<Option<ProxyConfig>> = RwLock::new(None);

/// Install (or clear, with `None`) the outbound proxy.
pub fn set_proxy(cfg: Option<ProxyConfig>) {
    match PROXY.write() {
        Ok(mut g) => *g = cfg,
        Err(_) => tracing::error!("proxy config lock poisoned"),
    }
}

/// Current proxy configuration, if any.
pub fn active_proxy() -> Option<ProxyConfig> {
    PROXY.read().ok().and_then(|g| g.clone())
}

/// Run the proxy handshake on `stream`, asking the proxy to forward to
/// `target` (an IP-literal socket addr — noid only dials IP literals).
pub async fn handshake<S>(stream: &mut S, target: SocketAddr, cfg: &ProxyConfig) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match cfg.kind {
        ProxyKind::HttpConnect => http_connect(stream, target, cfg).await,
        ProxyKind::Socks5 => socks5_connect(stream, target, cfg).await,
    }
}

async fn http_connect<S>(stream: &mut S, target: SocketAddr, cfg: &ProxyConfig) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
    if let (Some(u), Some(p)) = (&cfg.username, &cfg.password) {
        let creds = base64_encode(format!("{u}:{p}").as_bytes());
        req.push_str(&format!("Proxy-Authorization: Basic {creds}\r\n"));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;

    // Read until end of headers. Bounded — a hostile/hung proxy can't make
    // us buffer forever.
    let mut buf = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        if buf.len() >= MAX_CONNECT_RESPONSE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HTTP CONNECT response too large",
            ));
        }
        if stream.read(&mut byte).await? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "proxy closed during CONNECT response",
            ));
        }
        buf.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&buf);
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    if !(200..300).contains(&status) {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("HTTP CONNECT failed with status {status}"),
        ));
    }
    Ok(())
}

async fn socks5_connect<S>(stream: &mut S, target: SocketAddr, cfg: &ProxyConfig) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // --- Greeting: offer no-auth, plus user/pass when creds present ---
    let with_auth = cfg.username.is_some() && cfg.password.is_some();
    let greeting: &[u8] = if with_auth {
        &[0x05, 0x02, 0x00, 0x02]
    } else {
        &[0x05, 0x01, 0x00]
    };
    stream.write_all(greeting).await?;
    stream.flush().await?;

    let mut sel = [0u8; 2];
    stream.read_exact(&mut sel).await?;
    if sel[0] != 0x05 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad SOCKS version"));
    }
    match sel[1] {
        0x00 => {}
        0x02 => {
            // RFC 1929 username/password auth.
            let u = cfg.username.as_deref().unwrap_or_default();
            let p = cfg.password.as_deref().unwrap_or_default();
            if u.len() > 255 || p.len() > 255 {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "SOCKS creds too long"));
            }
            let mut auth = Vec::with_capacity(3 + u.len() + p.len());
            auth.push(0x01);
            auth.push(u.len() as u8);
            auth.extend_from_slice(u.as_bytes());
            auth.push(p.len() as u8);
            auth.extend_from_slice(p.as_bytes());
            stream.write_all(&auth).await?;
            stream.flush().await?;
            let mut status = [0u8; 2];
            stream.read_exact(&mut status).await?;
            if status[1] != 0x00 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "SOCKS5 auth rejected",
                ));
            }
        }
        m => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("SOCKS5 required unsupported auth method {m}"),
            ))
        }
    }

    // --- CONNECT request (ATYP: 0x01 IPv4, 0x04 IPv6) ---
    let mut req = vec![0x05, 0x01, 0x00];
    match target.ip() {
        IpAddr::V4(v4) => {
            req.push(0x01);
            req.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            req.push(0x04);
            req.extend_from_slice(&v6.octets());
        }
    }
    req.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&req).await?;
    stream.flush().await?;

    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[1] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("SOCKS5 CONNECT refused, code {:#04x}", head[1]),
        ));
    }
    // Consume the bound-addr field (ATYP-dependent length).
    let skip = match head[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            len[0] as usize
        }
        t => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("SOCKS5 bad ATYP {t}"),
            ))
        }
    };
    let mut rest = vec![0u8; skip + 2];
    stream.read_exact(&mut rest).await?;
    Ok(())
}

/// Resolve the proxy's listen multiaddr for logging/status — kept for the
/// noid command layer.
pub fn proxy_multiaddr(cfg: &ProxyConfig) -> Multiaddr {
    let mut m = Multiaddr::empty();
    match cfg.addr.ip() {
        IpAddr::V4(v4) => m.push(Protocol::Ip4(v4)),
        IpAddr::V6(v6) => m.push(Protocol::Ip6(v6)),
    }
    m.push(Protocol::Tcp(cfg.addr.port()));
    m
}

/// Minimal RFC 4648 base64 (standard alphabet, with padding) — the vendor
/// crate carries no base64 dependency and doesn't need one for this.
fn base64_encode(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}
