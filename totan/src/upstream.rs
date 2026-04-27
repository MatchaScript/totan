use crate::http_proxy::{serve_http_connection, HttpProxyContext};
use crate::proxy::{HostAndPort, Proxies, Proxy, ProxyOrDirect};
use crate::utils::tolerant_copy_bidirectional;
use anyhow::{anyhow, Result};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};
use totan_common::{config::ErrorMitigationConfig, InterceptedConnection, TotanError};
use tracing::{debug, warn};

/// Distinguishes the two failure modes a PAC entry can hit:
/// - `Connect`: TCP-level failure (timeout, refused, unreachable). The proxy
///   itself may be down; falling back to DIRECT is a sensible last resort.
/// - `Handshake`: the proxy was reachable but rejected the tunnel (407, 403,
///   SOCKS5 non-success). A DIRECT fallback here would leak traffic the
///   operator intentionally routed through a proxy, so we refuse.
enum EstablishError {
    Connect(anyhow::Error),
    Handshake(anyhow::Error),
}

impl EstablishError {
    fn into_inner(self) -> anyhow::Error {
        match self {
            Self::Connect(e) | Self::Handshake(e) => e,
        }
    }
}

impl std::fmt::Display for EstablishError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect(e) => write!(f, "connect: {e}"),
            Self::Handshake(e) => write!(f, "handshake: {e}"),
        }
    }
}

pub struct UpstreamHandler {
    connect_timeout: Duration,
    mitigation: ErrorMitigationConfig,
    upstream_mark: u32,
}

impl UpstreamHandler {
    pub fn new(
        connect_timeout_ms: u64,
        mitigation: ErrorMitigationConfig,
        upstream_mark: u32,
    ) -> Result<Self> {
        Ok(Self {
            connect_timeout: Duration::from_millis(connect_timeout_ms),
            mitigation,
            upstream_mark,
        })
    }

    /// Walk the PAC failover list trying each entry until one succeeds. An
    /// entry is "committed" the moment we start relaying client bytes; up to
    /// that point a transport/handshake failure advances to the next entry.
    ///
    /// The HTTP-over-HTTP-proxy path (plain HTTP target with an HTTP proxy)
    /// is special: it's delegated to Pingora which owns both streams and
    /// can't be rolled back. That case ends the loop on the first match.
    pub async fn handle_connection(
        &self,
        intercepted_conn: InterceptedConnection,
        mut client_stream: TcpStream,
        proxies: Proxies,
    ) -> Result<()> {
        let mut last_err: Option<anyhow::Error> = None;
        // Any handshake-level rejection disables the DIRECT mitigation below:
        // a proxy that actively rejects the tunnel is a policy decision, not a
        // transport outage, and silently re-routing would leak traffic.
        let mut any_handshake_failure = false;

        for entry in &proxies {
            // Pingora path: client stream is consumed, no failover possible.
            if let ProxyOrDirect::Proxy(Proxy::Http(ep)) = entry {
                if intercepted_conn.original_dest.port() != 443 {
                    return self
                        .serve_http_via_pingora(&intercepted_conn, client_stream, ep)
                        .await;
                }
            }

            match self.try_establish(&intercepted_conn, entry).await {
                Ok(mut upstream) => {
                    let _ = client_stream.set_nodelay(true);
                    let _ = upstream.set_nodelay(true);
                    let _ = tolerant_copy_bidirectional(&mut client_stream, &mut upstream).await;
                    return Ok(());
                }
                Err(e) => {
                    warn!("upstream entry {} failed: {}", entry, e);
                    if matches!(e, EstablishError::Handshake(_)) {
                        any_handshake_failure = true;
                    }
                    last_err = Some(e.into_inner());
                }
            }
        }

        // Every entry exhausted. Last-resort DIRECT fallback only fires when
        // the PAC list didn't already contain DIRECT and every failure was a
        // transport-level connect failure.
        let has_direct_entry = proxies.iter().any(|e| matches!(e, ProxyOrDirect::Direct));
        if self.mitigation.try_direct_on_proxy_failure
            && !has_direct_entry
            && !any_handshake_failure
        {
            warn!("all PAC entries failed to connect; trying direct connection as mitigation");
            return self
                .handle_direct_connection(intercepted_conn, client_stream)
                .await;
        }
        if self.mitigation.rst_on_failure {
            self.send_rst_and_close(&mut client_stream).await;
        }
        Err(last_err.unwrap_or_else(|| anyhow!("empty proxy list")))
    }

    /// Pre-negotiate an upstream tunnel (or a direct connection) so the caller
    /// can relay bytes verbatim. Returns the ready-to-copy stream. Any retry
    /// (per mitigation) happens inside this call — callers see a single
    /// success/failure per entry.
    async fn try_establish(
        &self,
        intercepted: &InterceptedConnection,
        entry: &ProxyOrDirect,
    ) -> Result<TcpStream, EstablishError> {
        match entry {
            ProxyOrDirect::Direct => self
                .connect_with_retry(intercepted.original_dest, "direct")
                .await
                .map_err(EstablishError::Connect),
            ProxyOrDirect::Proxy(Proxy::Http(ep)) => {
                // Plain-HTTP targets via HTTP proxy are handled by Pingora in
                // the caller. Anything arriving here is therefore TLS (CONNECT).
                let mut upstream = self
                    .connect_to_proxy(ep)
                    .await
                    .map_err(EstablishError::Connect)?;
                self.http_connect_impl(intercepted, &mut upstream)
                    .await
                    .map_err(EstablishError::Handshake)?;
                Ok(upstream)
            }
            ProxyOrDirect::Proxy(Proxy::Socks5(ep)) => {
                let mut upstream = self
                    .connect_to_proxy(ep)
                    .await
                    .map_err(EstablishError::Connect)?;
                self.socks5_connect_impl(intercepted, &mut upstream)
                    .await
                    .map_err(EstablishError::Handshake)?;
                Ok(upstream)
            }
        }
    }

    async fn connect_to_proxy(&self, ep: &HostAndPort) -> Result<TcpStream> {
        let addr = ep.to_string();
        self.connect_with_retry(addr.as_str(), "proxy").await
    }

    async fn serve_http_via_pingora(
        &self,
        intercepted: &InterceptedConnection,
        stream: TcpStream,
        ep: &HostAndPort,
    ) -> Result<()> {
        let proxy_url = format!("http://{}", ep);
        let ctx = HttpProxyContext::new(intercepted.clone(), &proxy_url, self.upstream_mark)?;
        serve_http_connection(stream, ctx).await
    }

    async fn connect_with_retry<A>(&self, addr: A, what: &str) -> Result<TcpStream>
    where
        A: tokio::net::ToSocketAddrs + std::fmt::Display + Copy,
    {
        let max_attempts = self.mitigation.retry_attempts.saturating_add(1);
        let mut attempt: u32 = 0;
        loop {
            match timeout(
                self.connect_timeout,
                tcp_connect_marked(addr, self.upstream_mark),
            )
            .await
            {
                Ok(Ok(stream)) => return Ok(stream),
                Ok(Err(e)) => warn!(
                    "Failed to connect to {} {}: {} (attempt {}/{})",
                    what,
                    addr,
                    e,
                    attempt + 1,
                    max_attempts
                ),
                Err(_) => warn!(
                    "Timeout connecting to {} {} after {:?} (attempt {}/{})",
                    what,
                    addr,
                    self.connect_timeout,
                    attempt + 1,
                    max_attempts
                ),
            }
            attempt += 1;
            if attempt >= max_attempts {
                return Err(TotanError::Network(format!(
                    "{} connection to {} failed after {} attempts",
                    what, addr, max_attempts
                ))
                .into());
            }
            let delay = self.mitigation.retry_backoff_ms * (1u64 << (attempt - 1).min(8));
            sleep(Duration::from_millis(delay)).await;
        }
    }

    async fn handle_direct_connection(
        &self,
        intercepted_conn: InterceptedConnection,
        mut client_stream: TcpStream,
    ) -> Result<()> {
        debug!(
            "Establishing direct connection to {}",
            intercepted_conn.original_dest
        );
        let mut upstream = match self
            .connect_with_retry(intercepted_conn.original_dest, "direct")
            .await
        {
            Ok(s) => s,
            Err(e) => {
                if self.mitigation.rst_on_failure {
                    self.send_rst_and_close(&mut client_stream).await;
                }
                return Err(e);
            }
        };
        let _ = client_stream.set_nodelay(true);
        let _ = upstream.set_nodelay(true);
        let _ = tolerant_copy_bidirectional(&mut client_stream, &mut upstream).await;
        Ok(())
    }

    pub async fn http_connect_impl<U>(
        &self,
        intercepted: &InterceptedConnection,
        upstream_stream: &mut U,
    ) -> Result<()>
    where
        U: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let authority_host = intercepted
            .sni_hostname
            .clone()
            .unwrap_or_else(|| intercepted.original_dest.ip().to_string());
        let authority = format!("{}:{}", authority_host, intercepted.original_dest.port());
        debug!("HTTP proxy CONNECT to {}", authority);

        let connect_request = build_http_connect_request(&authority);
        upstream_stream
            .write_all(connect_request.as_bytes())
            .await?;

        // Read until \r\n\r\n so TCP-split responses are handled correctly.
        let mut response = Vec::with_capacity(256);
        let mut byte = [0u8; 1];
        loop {
            upstream_stream.read_exact(&mut byte).await.map_err(|e| {
                TotanError::UpstreamProxy(format!("Failed reading CONNECT response: {}", e))
            })?;
            response.push(byte[0]);
            if response.ends_with(b"\r\n\r\n") {
                break;
            }
            if response.len() > 8192 {
                return Err(
                    TotanError::UpstreamProxy("CONNECT response too large".to_string()).into(),
                );
            }
        }
        let response_str = String::from_utf8_lossy(&response);
        if response_str.starts_with("HTTP/1.1 200") || response_str.starts_with("HTTP/1.0 200") {
            debug!("HTTP proxy CONNECT successful");
            Ok(())
        } else {
            warn!(
                "HTTP proxy CONNECT rejected: {}",
                response_str.lines().next().unwrap_or("").trim()
            );
            Err(TotanError::UpstreamProxy("HTTP proxy CONNECT request failed".to_string()).into())
        }
    }

    pub async fn socks5_connect_impl<U>(
        &self,
        intercepted: &InterceptedConnection,
        upstream_stream: &mut U,
    ) -> Result<()>
    where
        U: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        // 1) Greeting: no-auth only
        upstream_stream.write_all(&[0x05u8, 0x01, 0x00]).await?;
        upstream_stream.flush().await?;
        let mut resp = [0u8; 2];
        upstream_stream.read_exact(&mut resp).await?;
        if resp[0] != 0x05 || resp[1] != 0x00 {
            return Err(TotanError::UpstreamProxy(format!(
                "SOCKS5 auth method unsupported: {:02x}",
                resp[1]
            ))
            .into());
        }

        // 2) CONNECT request: prefer the hostname (via SNI) so the proxy can
        // do its own resolution; fall back to the IP when there is no name.
        let req = build_socks5_connect_request(intercepted);
        upstream_stream.write_all(&req).await?;
        upstream_stream.flush().await?;

        // 3) Reply
        let mut head = [0u8; 4];
        upstream_stream.read_exact(&mut head).await?;
        if head[0] != 0x05 {
            return Err(
                TotanError::UpstreamProxy("Invalid SOCKS5 reply version".to_string()).into(),
            );
        }
        if head[1] != 0x00 {
            return Err(TotanError::UpstreamProxy(format!(
                "SOCKS5 CONNECT failed, code {:02x}",
                head[1]
            ))
            .into());
        }
        match head[3] {
            0x01 => {
                let mut rest = [0u8; 6];
                upstream_stream.read_exact(&mut rest).await?;
            }
            0x03 => {
                let mut len = [0u8; 1];
                upstream_stream.read_exact(&mut len).await?;
                let mut skip = vec![0u8; len[0] as usize + 2];
                upstream_stream.read_exact(&mut skip).await?;
            }
            0x04 => {
                let mut rest = [0u8; 18];
                upstream_stream.read_exact(&mut rest).await?;
            }
            _ => {}
        }
        Ok(())
    }

    async fn send_rst_and_close(&self, stream: &mut TcpStream) {
        if self.mitigation.rst_on_failure {
            #[cfg(unix)]
            {
                use socket2::Socket;
                use std::os::unix::io::{AsRawFd, FromRawFd};
                use std::time::Duration;

                let fd = stream.as_raw_fd();
                let socket = unsafe { Socket::from_raw_fd(fd) };
                let _ = socket.set_linger(Some(Duration::from_secs(0)));
                // Keep ownership of the fd on `stream` — drop the socket
                // wrapper without running its destructor.
                std::mem::forget(socket);
            }
        }
        let _ = stream.shutdown().await;
    }
}

/// Connect to `addr` with optional `SO_MARK`. Resolves hostnames and tries
/// each resulting address in turn, returning the first successful connection.
/// When `mark` is zero the socket is created without marking.
async fn tcp_connect_marked<A: tokio::net::ToSocketAddrs>(
    addr: A,
    mark: u32,
) -> std::io::Result<TcpStream> {
    use socket2::{Domain, Protocol, Socket, Type};
    use tokio::net::TcpSocket;

    let mut last_err = std::io::Error::new(
        std::io::ErrorKind::ConnectionRefused,
        "no addresses resolved",
    );
    for socket_addr in tokio::net::lookup_host(addr).await? {
        let domain = match socket_addr {
            SocketAddr::V4(_) => Domain::IPV4,
            SocketAddr::V6(_) => Domain::IPV6,
        };
        let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
        if mark != 0 {
            sock.set_mark(mark)?;
        }
        sock.set_nonblocking(true)?;
        let tcp_socket = TcpSocket::from_std_stream(std::net::TcpStream::from(sock));
        match tcp_socket.connect(socket_addr).await {
            Ok(stream) => return Ok(stream),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

fn build_http_connect_request(authority: &str) -> String {
    format!(
        "CONNECT {authority} HTTP/1.1\r\n\
         Host: {authority}\r\n\
         Proxy-Connection: keep-alive\r\n\
         Connection: keep-alive\r\n\r\n"
    )
}

fn build_socks5_connect_request(intercepted: &InterceptedConnection) -> Vec<u8> {
    let mut req: Vec<u8> = Vec::with_capacity(32);
    req.push(0x05); // Version 5
    req.push(0x01); // CONNECT command
    req.push(0x00); // Reserved

    if let Some(host) = &intercepted.sni_hostname {
        debug!(
            "SOCKS5 CONNECT to {}:{}",
            host,
            intercepted.original_dest.port()
        );
        let host_bytes = host.as_bytes();
        let len = host_bytes.len().min(255);
        req.push(0x03); // ATYP: DOMAINNAME
        req.push(len as u8);
        req.extend_from_slice(&host_bytes[..len]);
    } else {
        match intercepted.original_dest.ip() {
            std::net::IpAddr::V4(v4) => {
                debug!(
                    "SOCKS5 CONNECT to {}:{}",
                    v4,
                    intercepted.original_dest.port()
                );
                req.push(0x01); // ATYP: IP V4 address
                req.extend_from_slice(&v4.octets());
            }
            std::net::IpAddr::V6(v6) => {
                debug!(
                    "SOCKS5 CONNECT to {}:{}",
                    v6,
                    intercepted.original_dest.port()
                );
                req.push(0x04); // ATYP: IP V6 address
                req.extend_from_slice(&v6.octets());
            }
        }
    }
    req.extend_from_slice(&intercepted.original_dest.port().to_be_bytes());
    req
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use tokio::io::AsyncReadExt;

    fn test_conn() -> InterceptedConnection {
        InterceptedConnection {
            client_addr: "127.0.0.1:12345".parse().unwrap(),
            original_dest: "93.184.216.34:80".parse::<SocketAddr>().unwrap(),
            sni_hostname: None,
        }
    }

    #[tokio::test]
    async fn test_http_connect_tunnel() {
        let handler = UpstreamHandler::new(1000, ErrorMitigationConfig::default(), 0).unwrap();
        let (mut upstream, mut upstream_mock) = tokio::io::duplex(1024);

        let mut conn = test_conn();
        conn.original_dest = "93.184.216.34:443".parse().unwrap();
        conn.sni_hostname = Some("example.com".to_string());

        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let n = upstream_mock.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]);
            assert!(req.contains("CONNECT example.com:443 HTTP/1.1"));
            upstream_mock
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
            drop(upstream_mock);
        });

        let res = tokio::time::timeout(
            Duration::from_millis(100),
            handler.http_connect_impl(&conn, &mut upstream),
        )
        .await
        .expect("timed out");
        assert!(res.is_ok(), "CONNECT negotiation should succeed");
    }

    #[tokio::test]
    async fn test_socks5_tunnel() {
        let handler = UpstreamHandler::new(1000, ErrorMitigationConfig::default(), 0).unwrap();
        let (mut upstream, mut upstream_mock) = tokio::io::duplex(1024);

        let mut conn = test_conn();
        conn.sni_hostname = Some("example.com".to_string());

        tokio::spawn(async move {
            let mut buf = [0u8; 3];
            upstream_mock.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf, [0x05, 0x01, 0x00]);
            upstream_mock.write_all(&[0x05, 0x00]).await.unwrap();

            let mut buf = [0u8; 12];
            upstream_mock.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf[0], 0x05);
            assert_eq!(buf[1], 0x01);
            assert_eq!(buf[3], 0x03);

            upstream_mock
                .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 80])
                .await
                .unwrap();
            drop(upstream_mock);
        });

        let res = tokio::time::timeout(
            Duration::from_millis(100),
            handler.socks5_connect_impl(&conn, &mut upstream),
        )
        .await
        .expect("timed out");
        assert!(res.is_ok(), "SOCKS5 negotiation should succeed");
    }

    /// Multi-header CONNECT response split across TCP segments must still
    /// be parsed correctly before handing off to the byte-pipe.
    #[tokio::test]
    async fn test_connect_response_with_extra_headers() {
        let handler = UpstreamHandler::new(1000, ErrorMitigationConfig::default(), 0).unwrap();
        let (mut upstream, mut upstream_mock) = tokio::io::duplex(4096);

        let mut conn = test_conn();
        conn.original_dest = "93.184.216.34:443".parse().unwrap();
        conn.sni_hostname = Some("example.com".to_string());

        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let _ = upstream_mock.read(&mut buf).await.unwrap();
            upstream_mock
                .write_all(b"HTTP/1.1 200 Connection established\r\n")
                .await
                .unwrap();
            upstream_mock
                .write_all(b"Proxy-Agent: Squid/5.7\r\nDate: Mon, 01 Jan 2024 00:00:00 GMT\r\n\r\n")
                .await
                .unwrap();
            drop(upstream_mock);
        });

        let result = tokio::time::timeout(
            Duration::from_millis(200),
            handler.http_connect_impl(&conn, &mut upstream),
        )
        .await
        .expect("timed out");
        assert!(result.is_ok(), "CONNECT with trailing headers must succeed");
    }

    /// 407 (proxy auth required) surfaces as an error, not a silent tunnel.
    #[tokio::test]
    async fn test_connect_rejected_407() {
        let handler = UpstreamHandler::new(1000, ErrorMitigationConfig::default(), 0).unwrap();
        let (mut upstream, mut upstream_mock) = tokio::io::duplex(4096);

        let mut conn = test_conn();
        conn.original_dest = "93.184.216.34:443".parse().unwrap();
        conn.sni_hostname = Some("example.com".to_string());

        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let _ = upstream_mock.read(&mut buf).await.unwrap();
            upstream_mock
                .write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                      Proxy-Authenticate: Basic realm=\"corporate-proxy\"\r\n\
                      Content-Length: 0\r\n\r\n",
                )
                .await
                .unwrap();
            drop(upstream_mock);
        });

        let result = tokio::time::timeout(
            Duration::from_millis(200),
            handler.http_connect_impl(&conn, &mut upstream),
        )
        .await
        .expect("timed out");
        assert!(result.is_err(), "407 must be an error");
    }

    /// 403 from a chained corporate proxy also surfaces as an error.
    #[tokio::test]
    async fn test_connect_rejected_403() {
        let handler = UpstreamHandler::new(1000, ErrorMitigationConfig::default(), 0).unwrap();
        let (mut upstream, mut upstream_mock) = tokio::io::duplex(4096);

        let mut conn = test_conn();
        conn.original_dest = "93.184.216.34:443".parse().unwrap();
        conn.sni_hostname = Some("blocked.example.com".to_string());

        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let _ = upstream_mock.read(&mut buf).await.unwrap();
            upstream_mock
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            drop(upstream_mock);
        });

        let result = tokio::time::timeout(
            Duration::from_millis(200),
            handler.http_connect_impl(&conn, &mut upstream),
        )
        .await
        .expect("timed out");
        assert!(result.is_err(), "403 must be an error");
    }
}
