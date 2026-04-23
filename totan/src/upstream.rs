use crate::utils::tolerant_copy_bidirectional;
use anyhow::Result;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};
use totan_common::{config::ErrorMitigationConfig, InterceptedConnection, TotanError};
use tracing::{debug, warn};
use url::Url;

pub struct UpstreamHandler {
    default_proxy: Option<String>,
    connect_timeout: Duration,
    mitigation: ErrorMitigationConfig,
    upstream_mark: u32,
}

impl UpstreamHandler {
    pub fn new(
        default_proxy: Option<String>,
        connect_timeout_ms: u64,
        mitigation: ErrorMitigationConfig,
        upstream_mark: u32,
    ) -> Result<Self> {
        Ok(Self {
            default_proxy,
            connect_timeout: Duration::from_millis(connect_timeout_ms),
            mitigation,
            upstream_mark,
        })
    }

    pub async fn handle_connection(
        &self,
        intercepted_conn: InterceptedConnection,
        client_stream: TcpStream,
        upstream_proxy: Option<String>,
        allow_default_fallback: bool,
    ) -> Result<()> {
        let proxy_url = if upstream_proxy.is_some() {
            upstream_proxy
        } else if allow_default_fallback {
            self.default_proxy.clone()
        } else {
            None
        };

        match proxy_url {
            Some(proxy) => {
                self.handle_proxy_connection(intercepted_conn, client_stream, proxy)
                    .await
            }
            None => {
                self.handle_direct_connection(intercepted_conn, client_stream)
                    .await
            }
        }
    }

    async fn handle_proxy_connection(
        &self,
        intercepted_conn: InterceptedConnection,
        mut client_stream: TcpStream,
        proxy_url: String,
    ) -> Result<()> {
        let url = Url::parse(&proxy_url)
            .map_err(|e| TotanError::Config(format!("Invalid proxy URL '{}': {}", proxy_url, e)))?;

        let proxy_addr = format!(
            "{}:{}",
            url.host_str().unwrap_or("localhost"),
            url.port().unwrap_or(8080)
        );

        debug!(
            "Connecting to upstream proxy {} for {}",
            proxy_addr, intercepted_conn.original_dest
        );

        // Connect to upstream proxy with timeout and retries
        let mut attempt: u32 = 0;
        let max_attempts = self.mitigation.retry_attempts.saturating_add(1);
        let mut upstream_stream_opt: Option<TcpStream> = None;
        loop {
            match timeout(
                self.connect_timeout,
                tcp_connect_marked(&proxy_addr, self.upstream_mark),
            )
            .await
            {
                Ok(Ok(stream)) => {
                    upstream_stream_opt = Some(stream);
                    break;
                }
                Ok(Err(e)) => {
                    warn!(
                        "Failed to connect to upstream proxy {}: {} (attempt {}/{})",
                        proxy_addr,
                        e,
                        attempt + 1,
                        max_attempts
                    );
                }
                Err(_) => {
                    warn!(
                        "Timeout connecting to upstream proxy {} after {:?} (attempt {}/{})",
                        proxy_addr,
                        self.connect_timeout,
                        attempt + 1,
                        max_attempts
                    );
                }
            }
            attempt += 1;
            if attempt >= max_attempts {
                break;
            }
            // backoff
            let delay = self.mitigation.retry_backoff_ms * (1u64 << (attempt - 1).min(8));
            sleep(Duration::from_millis(delay)).await;
        }

        let upstream_stream = if let Some(s) = upstream_stream_opt {
            s
        } else {
            // Failed all attempts: optionally try direct fallback
            if self.mitigation.try_direct_on_proxy_failure {
                warn!("Proxy connect failed; trying direct connection as fallback");
                return self
                    .handle_direct_connection(intercepted_conn, client_stream)
                    .await;
            }
            if self.mitigation.rst_on_failure {
                self.send_rst_and_close(&mut client_stream).await;
            }
            return Err(TotanError::UpstreamProxy(format!(
                "Connection to {} failed after {} attempts",
                proxy_addr, max_attempts
            ))
            .into());
        };

        // Reduce small-packet latency on both ends
        let _ = client_stream.set_nodelay(true);

        match url.scheme() {
            "http" => {
                self.handle_http_proxy(intercepted_conn, client_stream, upstream_stream)
                    .await
            }
            "socks5" => {
                self.handle_socks5_proxy(intercepted_conn, client_stream, upstream_stream)
                    .await
            }
            scheme => {
                Err(TotanError::Config(format!("Unsupported proxy scheme: {}", scheme)).into())
            }
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

        // Connect directly to original destination with retries
        let mut attempt: u32 = 0;
        let max_attempts = self.mitigation.retry_attempts.saturating_add(1);
        let mut upstream_stream_opt: Option<TcpStream> = None;
        loop {
            match timeout(
                self.connect_timeout,
                tcp_connect_marked(intercepted_conn.original_dest, self.upstream_mark),
            )
            .await
            {
                Ok(Ok(stream)) => {
                    upstream_stream_opt = Some(stream);
                    break;
                }
                Ok(Err(e)) => {
                    warn!(
                        "Failed to connect directly to {}: {} (attempt {}/{})",
                        intercepted_conn.original_dest,
                        e,
                        attempt + 1,
                        max_attempts
                    );
                }
                Err(_) => {
                    warn!(
                        "Timeout connecting directly to {} after {:?} (attempt {}/{})",
                        intercepted_conn.original_dest,
                        self.connect_timeout,
                        attempt + 1,
                        max_attempts
                    );
                }
            }
            attempt += 1;
            if attempt >= max_attempts {
                break;
            }
            let delay = self.mitigation.retry_backoff_ms * (1u64 << (attempt - 1).min(8));
            sleep(Duration::from_millis(delay)).await;
        }
        let mut upstream_stream = if let Some(s) = upstream_stream_opt {
            s
        } else {
            if self.mitigation.rst_on_failure {
                self.send_rst_and_close(&mut client_stream).await;
            }
            return Err(TotanError::Network(format!(
                "Direct connection to {} failed after {} attempts",
                intercepted_conn.original_dest, max_attempts
            ))
            .into());
        };
        // Reduce latency
        let _ = client_stream.set_nodelay(true);
        let _ = upstream_stream.set_nodelay(true);

        // Start bidirectional data copying
        let _ = tolerant_copy_bidirectional(&mut client_stream, &mut upstream_stream).await;

        Ok(())
    }

    async fn handle_http_proxy(
        &self,
        intercepted_conn: InterceptedConnection,
        mut client_stream: TcpStream,
        mut upstream_stream: TcpStream,
    ) -> Result<()> {
        self.handle_http_proxy_impl(intercepted_conn, &mut client_stream, &mut upstream_stream)
            .await
    }

    pub async fn handle_http_proxy_impl<C, U>(
        &self,
        intercepted_conn: InterceptedConnection,
        client_stream: &mut C,
        upstream_stream: &mut U,
    ) -> Result<()>
    where
        C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
        U: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        // Reduce small-packet latency is done by caller on real TcpStream

        // Use CONNECT only for TLS targets (port 443). For plain HTTP, skip CONNECT and
        // send absolute-form requests directly to the proxy to avoid 403s and extra round trips.
        let is_tls = intercepted_conn.original_dest.port() == 443;
        if is_tls {
            let authority_host = intercepted_conn
                .sni_hostname
                .clone()
                .unwrap_or_else(|| intercepted_conn.original_dest.ip().to_string());
            let authority = format!(
                "{}:{}",
                authority_host,
                intercepted_conn.original_dest.port()
            );
            debug!("HTTP proxy CONNECT to {}", authority);
            let connect_request = format!(
                "CONNECT {} HTTP/1.1\r\nHost: {}\r\nProxy-Connection: keep-alive\r\nConnection: keep-alive\r\n\r\n",
                authority,
                authority
            );
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
                    return Err(TotanError::UpstreamProxy(
                        "CONNECT response too large".to_string(),
                    )
                    .into());
                }
            }
            let response_str = String::from_utf8_lossy(&response);
            if response_str.starts_with("HTTP/1.1 200") || response_str.starts_with("HTTP/1.0 200")
            {
                debug!("HTTP proxy CONNECT successful");
                // Tunnel data once CONNECT succeeds
                let _ = tolerant_copy_bidirectional(client_stream, upstream_stream).await;
                Ok(())
            } else {
                warn!(
                    "HTTP proxy CONNECT rejected: {}",
                    response_str.lines().next().unwrap_or("").trim()
                );
                self.send_rst_and_close_generic(client_stream).await;
                Err(
                    TotanError::UpstreamProxy("HTTP proxy CONNECT request failed".to_string())
                        .into(),
                )
            }
        } else {
            // Plain HTTP: rewrite origin-form to absolute-form and forward.
            if let Err(e) = self
                .rewrite_and_forward_http_request(client_stream, upstream_stream, &intercepted_conn)
                .await
            {
                warn!("Failed to rewrite HTTP request: {}", e);
                self.send_rst_and_close_generic(client_stream).await;
                return Err(e);
            }
            // After forwarding the first request, continue tunneling the rest.
            let _ = tolerant_copy_bidirectional(client_stream, upstream_stream).await;
            Ok(())
        }
    }

    async fn handle_socks5_proxy(
        &self,
        intercepted_conn: InterceptedConnection,
        mut client_stream: TcpStream,
        mut upstream_stream: TcpStream,
    ) -> Result<()> {
        self.handle_socks5_proxy_impl(intercepted_conn, &mut client_stream, &mut upstream_stream)
            .await
    }

    pub async fn handle_socks5_proxy_impl<C, U>(
        &self,
        intercepted_conn: InterceptedConnection,
        client_stream: &mut C,
        upstream_stream: &mut U,
    ) -> Result<()>
    where
        C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
        U: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        // 1) Greeting: no authentication supported
        // client: VER=5, NMETHODS=1, METHODS=[0x00]
        let greet = [0x05u8, 0x01, 0x00];
        upstream_stream.write_all(&greet).await?;
        upstream_stream.flush().await?;
        // server: VER=5, METHOD=0x00 (no auth) expected
        let mut resp = [0u8; 2];
        upstream_stream.read_exact(&mut resp).await?;
        if resp[0] != 0x05 || resp[1] != 0x00 {
            warn!(
                "SOCKS5 server requires unsupported auth method: {:02x}",
                resp[1]
            );
            self.send_rst_and_close_generic(client_stream).await;
            return Err(
                TotanError::UpstreamProxy("SOCKS5 auth method unsupported".to_string()).into(),
            );
        }

        // 2) CONNECT request to target
        // Build address field: prefer domain from SNI, else use IP (v4/v6)
        let mut req: Vec<u8> = Vec::with_capacity(32);
        req.push(0x05); // VER
        req.push(0x01); // CMD=CONNECT
        req.push(0x00); // RSV
        if let Some(host) = &intercepted_conn.sni_hostname {
            debug!(
                "SOCKS5 CONNECT to {}:{}",
                host,
                intercepted_conn.original_dest.port()
            );
            let host_bytes = host.as_bytes();
            let len = host_bytes.len().min(255);
            req.push(0x03); // ATYP=DOMAIN
            req.push(len as u8);
            req.extend_from_slice(&host_bytes[..len]);
        } else {
            match intercepted_conn.original_dest.ip() {
                std::net::IpAddr::V4(v4) => {
                    debug!(
                        "SOCKS5 CONNECT to {}:{}",
                        v4,
                        intercepted_conn.original_dest.port()
                    );
                    req.push(0x01); // ATYP=IPv4
                    req.extend_from_slice(&v4.octets());
                }
                std::net::IpAddr::V6(v6) => {
                    debug!(
                        "SOCKS5 CONNECT to {}:{}",
                        v6,
                        intercepted_conn.original_dest.port()
                    );
                    req.push(0x04); // ATYP=IPv6
                    req.extend_from_slice(&v6.octets());
                }
            }
        }
        req.extend_from_slice(&intercepted_conn.original_dest.port().to_be_bytes());
        upstream_stream.write_all(&req).await?;
        upstream_stream.flush().await?;

        // 3) Read CONNECT reply
        // VER, REP, RSV, ATYP, BND.ADDR..., BND.PORT
        let mut head = [0u8; 4];
        upstream_stream.read_exact(&mut head).await?;
        if head[0] != 0x05 {
            self.send_rst_and_close_generic(client_stream).await;
            return Err(
                TotanError::UpstreamProxy("Invalid SOCKS5 reply version".to_string()).into(),
            );
        }
        if head[1] != 0x00 {
            self.send_rst_and_close_generic(client_stream).await;
            return Err(TotanError::UpstreamProxy(format!(
                "SOCKS5 CONNECT failed, code {:02x}",
                head[1]
            ))
            .into());
        }
        // consume bound address based on ATYP
        let atyp = head[3];
        match atyp {
            0x01 => {
                // IPv4
                let mut rest = [0u8; 6]; // 4 addr + 2 port
                upstream_stream.read_exact(&mut rest).await?;
            }
            0x03 => {
                // DOMAIN
                let mut len = [0u8; 1];
                upstream_stream.read_exact(&mut len).await?;
                let mut skip = vec![0u8; len[0] as usize + 2];
                upstream_stream.read_exact(&mut skip).await?;
            }
            0x04 => {
                // IPv6
                let mut rest = [0u8; 18]; // 16 addr + 2 port
                upstream_stream.read_exact(&mut rest).await?;
            }
            _ => {}
        }

        // 4) Tunnel data
        let _ = tolerant_copy_bidirectional(client_stream, upstream_stream).await;
        Ok(())
    }

    async fn send_rst_and_close(&self, stream: &mut TcpStream) {
        if self.mitigation.rst_on_failure {
            // Send TCP RST by setting SO_LINGER to 0 and closing
            #[cfg(unix)]
            {
                use socket2::Socket;
                use std::os::unix::io::{AsRawFd, FromRawFd};
                use std::time::Duration;

                let fd = stream.as_raw_fd();
                let socket = unsafe { Socket::from_raw_fd(fd) };
                let _ = socket.set_linger(Some(Duration::from_secs(0)));
                std::mem::forget(socket); // Don't close the fd, stream owns it
            }
        }
        let _ = stream.shutdown().await; // graceful if RST disabled
    }

    async fn send_rst_and_close_generic<S>(&self, stream: &mut S)
    where
        S: tokio::io::AsyncWrite + Unpin,
    {
        // For generic streams (like mocks), just shutdown
        let _ = stream.shutdown().await;
    }

    // Read the first HTTP request from client, rewrite origin-form to absolute-form,
    // preserve keep-alive semantics, and forward it to the upstream HTTP proxy.
    // Any already-read body bytes are forwarded too.
    async fn rewrite_and_forward_http_request<C, U>(
        &self,
        client_stream: &mut C,
        upstream_stream: &mut U,
        intercepted_conn: &InterceptedConnection,
    ) -> Result<()>
    where
        C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
        U: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        // Read until end of headers (\r\n\r\n), with a safety cap
        let mut buf: Vec<u8> = Vec::with_capacity(8192);
        let mut tmp = [0u8; 4096];
        let mut header_end: Option<usize> = None;
        const MAX_HEADER_SIZE: usize = 64 * 1024; // 64KB

        while header_end.is_none() {
            let n = client_stream.read(&mut tmp).await?;
            if n == 0 {
                return Err(TotanError::Network(
                    "Client closed before sending HTTP headers".to_string(),
                )
                .into());
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.len() > MAX_HEADER_SIZE {
                return Err(TotanError::Network("HTTP header too large".to_string()).into());
            }
            // search for \r\n\r\n
            let mut i = 3; // minimum index where we can look back 3 bytes
            while i < buf.len() {
                if buf[i] == b'\n'
                    && i >= 3
                    && buf[i - 1] == b'\r'
                    && buf[i - 2] == b'\n'
                    && buf[i - 3] == b'\r'
                {
                    header_end = Some(i + 1);
                    break;
                }
                i += 1;
            }
        }
        let headers_end = header_end.unwrap();
        let (headers_bytes, rest) = buf.split_at(headers_end);
        let headers_str = String::from_utf8_lossy(headers_bytes);
        let mut lines = headers_str.split("\r\n");
        let request_line = lines.next().unwrap_or("");
        let mut parts = request_line.splitn(3, ' ');
        let method = parts.next().unwrap_or("");
        let target = parts.next().unwrap_or("");
        let version = parts.next().unwrap_or("");

        // Collect headers, track Host/Connection presence
        let mut host_header: Option<String> = None;
        let mut connection_header: Option<String> = None; // original value as sent by client
        let mut proxy_connection_header: Option<String> = None; // original value if present
        let mut other_headers: Vec<String> = Vec::new();
        for line in lines {
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                let name_trim = name.trim();
                let value_trim = value.trim();
                if name_trim.eq_ignore_ascii_case("Host") {
                    host_header = Some(value_trim.to_string());
                } else if name_trim.eq_ignore_ascii_case("Connection") {
                    connection_header = Some(value_trim.to_string());
                    // Preserve client's Connection header
                    other_headers.push(format!("Connection: {}", value_trim));
                } else if name_trim.eq_ignore_ascii_case("Proxy-Connection") {
                    // Preserve original; we'll also set one if needed
                    proxy_connection_header = Some(value_trim.to_string());
                    other_headers.push(format!("Proxy-Connection: {}", value_trim));
                } else {
                    other_headers.push(format!("{}: {}", name_trim, value_trim));
                }
            } else {
                // malformed header line, pass through as-is
                other_headers.push(line.to_string());
            }
        }

        // Determine host to use
        let host_for_abs = if let Some(h) = host_header.clone() {
            h
        } else {
            // Fallback to original destination host:port
            let host = intercepted_conn.original_dest.ip().to_string();
            let port = intercepted_conn.original_dest.port();
            if port == 80 {
                host
            } else {
                format!("{}:{}", host, port)
            }
        };

        let absolute_target_needed = target.starts_with('/') || target.starts_with("*");
        let (new_request_line, debug_url): (String, String) = if absolute_target_needed {
            let url = format!(
                "http://{}{}",
                host_for_abs,
                if target.starts_with('/') { target } else { "/" }
            );
            (format!("{} {} {}\r\n", method, url, version), url)
        } else {
            // already absolute or authority-form; keep as-is
            (
                format!("{} {} {}\r\n", method, target, version),
                target.to_string(),
            )
        };
        debug!("HTTP request: {} {}", method, debug_url);

        // Build final headers
        let mut rewritten = Vec::with_capacity(headers_bytes.len() + 64);
        rewritten.extend_from_slice(new_request_line.as_bytes());
        // Ensure Host header present (and keep/normalize it)
        let host_value = host_header.unwrap_or_else(|| host_for_abs.clone());
        rewritten.extend_from_slice(format!("Host: {}\r\n", host_value).as_bytes());
        for h in &other_headers {
            rewritten.extend_from_slice(h.as_bytes());
            rewritten.extend_from_slice(b"\r\n");
        }
        // If no Proxy-Connection was present, add a helpful one based on client's intent
        if proxy_connection_header.is_none() {
            // Determine desired persistence
            let wants_keep_alive = match connection_header.as_deref() {
                Some(v) if v.eq_ignore_ascii_case("keep-alive") => true,
                // HTTP/1.1 defaults to persistent connections
                None if version.eq_ignore_ascii_case("HTTP/1.1") => true,
                _ => false,
            };
            if wants_keep_alive {
                rewritten.extend_from_slice(b"Proxy-Connection: keep-alive\r\n");
            } else if matches!(connection_header.as_deref(), Some(v) if v.eq_ignore_ascii_case("close"))
            {
                rewritten.extend_from_slice(b"Proxy-Connection: close\r\n");
            }
        }
        // End of headers
        rewritten.extend_from_slice(b"\r\n");

        // Write to upstream
        upstream_stream.write_all(&rewritten).await?;
        // Forward any already-read body bytes
        if !rest.is_empty() {
            upstream_stream.write_all(rest).await?;
        }
        upstream_stream.flush().await?;

        Ok(())
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

    let mut last_err =
        std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "no addresses resolved");
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
    async fn test_rewrite_http_request() {
        let handler = UpstreamHandler::new(None, 1000, ErrorMitigationConfig::default(), 0).unwrap();
        let (mut client, mut client_mock) = tokio::io::duplex(1024);
        let (mut upstream, mut upstream_mock) = tokio::io::duplex(1024);

        let conn = test_conn();

        tokio::spawn(async move {
            client_mock
                .write_all(b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
                .await
                .unwrap();
        });

        handler
            .rewrite_and_forward_http_request(&mut client, &mut upstream, &conn)
            .await
            .unwrap();

        let mut buf = [0u8; 1024];
        let n = upstream_mock.read(&mut buf).await.unwrap();
        let request = String::from_utf8_lossy(&buf[..n]);

        assert!(request.contains("GET http://example.com/index.html HTTP/1.1"));
        assert!(request.contains("Host: example.com"));
    }

    #[tokio::test]
    async fn test_handle_http_proxy_connect() {
        let handler = UpstreamHandler::new(None, 1000, ErrorMitigationConfig::default(), 0).unwrap();
        let (mut client, _client_mock) = tokio::io::duplex(1024);
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
            // Drop upstream_mock to close the tunnel
            drop(upstream_mock);
        });

        // Use a timeout to prevent hanging forever
        let _ = tokio::time::timeout(
            Duration::from_millis(100),
            handler.handle_http_proxy_impl(conn, &mut client, &mut upstream),
        )
        .await;
    }

    #[tokio::test]
    async fn test_handle_socks5_proxy_connect() {
        let handler = UpstreamHandler::new(None, 1000, ErrorMitigationConfig::default(), 0).unwrap();
        let (mut client, _client_mock) = tokio::io::duplex(1024);
        let (mut upstream, mut upstream_mock) = tokio::io::duplex(1024);

        let mut conn = test_conn();
        conn.sni_hostname = Some("example.com".to_string());

        tokio::spawn(async move {
            // 1. Greet
            let mut buf = [0u8; 3];
            upstream_mock.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf, [0x05, 0x01, 0x00]);
            upstream_mock.write_all(&[0x05, 0x00]).await.unwrap();

            // 2. Connect
            let mut buf = [0u8; 12]; // VER, CMD, RSV, ATYP, LEN, "example.com", PORT(2)
            let _ = upstream_mock.read_exact(&mut buf).await.unwrap();
            assert_eq!(buf[0], 0x05); // VER
            assert_eq!(buf[1], 0x01); // CMD
            assert_eq!(buf[3], 0x03); // ATYP DOMAIN

            // 3. Reply
            upstream_mock
                .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 80])
                .await
                .unwrap();
            // Drop to close tunnel
            drop(upstream_mock);
        });

        let _ = tokio::time::timeout(
            Duration::from_millis(100),
            handler.handle_socks5_proxy_impl(conn, &mut client, &mut upstream),
        )
        .await;
    }

    // ── CONNECT response robustness ───────────────────────────────────────────

    /// A real upstream proxy (Squid, nginx, corporate gateway) typically adds
    /// extra headers after the 200 status line before the blank line:
    ///
    ///   HTTP/1.1 200 Connection established\r\n
    ///   Proxy-Agent: Squid\r\n
    ///   \r\n
    ///
    /// The response can also arrive in multiple TCP segments. Our byte-by-byte
    /// read loop must consume exactly up to \r\n\r\n and hand the tunnel to
    /// copy_bidirectional without discarding or leaking any bytes.
    #[tokio::test]
    async fn test_connect_response_with_extra_headers() {
        let handler = UpstreamHandler::new(None, 1000, ErrorMitigationConfig::default(), 0).unwrap();
        let (mut client, client_mock) = tokio::io::duplex(4096);
        let (mut upstream, mut upstream_mock) = tokio::io::duplex(4096);

        let mut conn = test_conn();
        conn.original_dest = "93.184.216.34:443".parse().unwrap();
        conn.sni_hostname = Some("example.com".to_string());

        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            upstream_mock.read(&mut buf).await.unwrap();

            // Simulate a Squid-style multi-header CONNECT response arriving in
            // two separate writes (TCP segment split after the status line).
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

        // Drop client_mock immediately so copy_bidirectional terminates as
        // soon as the CONNECT response is consumed and the tunnel opens.
        drop(client_mock);

        // Should succeed: 200 response even with extra headers and TCP split.
        let result = tokio::time::timeout(
            Duration::from_millis(200),
            handler.handle_http_proxy_impl(conn, &mut client, &mut upstream),
        )
        .await;
        assert!(result.is_ok(), "timed out waiting for CONNECT to complete");
    }

    /// Upstream proxy requires authentication (407). totan must surface this as
    /// an error and not attempt to tunnel into the 407 response body.
    #[tokio::test]
    async fn test_connect_rejected_407() {
        let handler = UpstreamHandler::new(None, 1000, ErrorMitigationConfig::default(), 0).unwrap();
        let (mut client, _client_mock) = tokio::io::duplex(4096);
        let (mut upstream, mut upstream_mock) = tokio::io::duplex(4096);

        let mut conn = test_conn();
        conn.original_dest = "93.184.216.34:443".parse().unwrap();
        conn.sni_hostname = Some("example.com".to_string());

        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            upstream_mock.read(&mut buf).await.unwrap();
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
            handler.handle_http_proxy_impl(conn, &mut client, &mut upstream),
        )
        .await
        .expect("timed out");

        assert!(result.is_err(), "407 must be returned as an error");
    }

    /// Corporate proxies that forward to a second-tier proxy may reject with
    /// 403 Forbidden when the target is not in the allow-list.
    #[tokio::test]
    async fn test_connect_rejected_403() {
        let handler = UpstreamHandler::new(None, 1000, ErrorMitigationConfig::default(), 0).unwrap();
        let (mut client, _client_mock) = tokio::io::duplex(4096);
        let (mut upstream, mut upstream_mock) = tokio::io::duplex(4096);

        let mut conn = test_conn();
        conn.original_dest = "93.184.216.34:443".parse().unwrap();
        conn.sni_hostname = Some("blocked.example.com".to_string());

        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            upstream_mock.read(&mut buf).await.unwrap();
            upstream_mock
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            drop(upstream_mock);
        });

        let result = tokio::time::timeout(
            Duration::from_millis(200),
            handler.handle_http_proxy_impl(conn, &mut client, &mut upstream),
        )
        .await
        .expect("timed out");

        assert!(result.is_err(), "403 must be returned as an error");
    }
}
