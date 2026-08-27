use anyhow::{anyhow, Result};
use async_trait::async_trait;
use pingora::apps::ServerApp;
use pingora::connectors::L4Connect;
use pingora::http::RequestHeader;
use pingora::proxy::{http_proxy, ProxyHttp, Session};
use pingora::server::configuration::ServerConf;
use pingora::upstreams::peer::HttpPeer;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use totan_common::InterceptedConnection;

use crate::proxy::{HostAndPort, Proxy, ProxyOrDirect};

#[derive(Clone)]
enum HttpRoute {
    Proxy(HostAndPort),
    Socks5(HostAndPort),
    Direct,
}

#[derive(Debug)]
struct Socks5Connector {
    proxy: HostAndPort,
    target: std::net::SocketAddr,
    upstream_mark: u32,
    connect_timeout: Duration,
    handshake_timeout: Duration,
}

#[async_trait]
impl L4Connect for Socks5Connector {
    async fn connect(
        &self,
        _addr: &pingora::protocols::l4::socket::SocketAddr,
    ) -> pingora::Result<pingora::protocols::l4::stream::Stream> {
        let proxy_addr = self.proxy.to_string();
        let mut stream = tokio::time::timeout(
            self.connect_timeout,
            crate::upstream::tcp_connect_marked(proxy_addr.as_str(), self.upstream_mark),
        )
        .await
        .map_err(|_| {
            pingora::Error::explain(
                pingora::ErrorType::ConnectTimedout,
                format!("SOCKS5 connect to {} timed out", self.proxy),
            )
        })?
        .map_err(|error| {
            pingora::Error::because(
                pingora::ErrorType::ConnectError,
                format!("SOCKS5 connect to {} failed", self.proxy),
                error,
            )
        })?;

        tokio::time::timeout(
            self.handshake_timeout,
            socks5_connect_ip(&mut stream, self.target),
        )
        .await
        .map_err(|_| {
            pingora::Error::explain(
                pingora::ErrorType::ConnectTimedout,
                format!("SOCKS5 handshake with {} timed out", self.proxy),
            )
        })?
        .map_err(|error| {
            pingora::Error::because(
                pingora::ErrorType::ConnectError,
                format!("SOCKS5 handshake with {} failed", self.proxy),
                error,
            )
        })?;
        Ok(pingora::protocols::l4::stream::Stream::from(stream))
    }
}

async fn socks5_connect_ip(stream: &mut TcpStream, target: std::net::SocketAddr) -> Result<()> {
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting != [0x05, 0x00] {
        return Err(anyhow!("SOCKS5 proxy rejected no-auth method"));
    }

    let mut request = vec![0x05, 0x01, 0x00];
    match target.ip() {
        std::net::IpAddr::V4(ip) => {
            request.push(0x01);
            request.extend_from_slice(&ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            request.push(0x04);
            request.extend_from_slice(&ip.octets());
        }
    }
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).await?;

    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != 0x05 || head[1] != 0x00 {
        return Err(anyhow!("SOCKS5 CONNECT failed with code {:02x}", head[1]));
    }
    let address_len = match head[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            len[0] as usize
        }
        atyp => return Err(anyhow!("SOCKS5 reply has invalid address type {atyp:02x}")),
    };
    let mut trailing = vec![0u8; address_len + 2];
    stream.read_exact(&mut trailing).await?;
    Ok(())
}

/// Context shared by all requests on a single downstream connection.
pub struct HttpProxyContext {
    pub intercepted: InterceptedConnection,
    pub upstream_mark: u32,
    routes: Vec<HttpRoute>,
    connect_timeout: Duration,
    handshake_timeout: Duration,
    idle_timeout: Duration,
}

impl HttpProxyContext {
    pub fn new(
        intercepted: InterceptedConnection,
        upstream_proxy_url: &str,
        upstream_mark: u32,
    ) -> Result<Arc<Self>> {
        let upstream_proxy = url::Url::parse(upstream_proxy_url)?;
        if upstream_proxy.scheme() != "http" {
            return Err(anyhow!(
                "Pingora HTTP pipeline requires http-scheme upstream"
            ));
        }
        let host = upstream_proxy
            .host_str()
            .ok_or_else(|| anyhow!("upstream proxy URL has no host"))?;
        let endpoint = HostAndPort::new(host, upstream_proxy.port().unwrap_or(80));
        Ok(Arc::new(Self {
            intercepted,
            upstream_mark,
            routes: vec![HttpRoute::Proxy(endpoint)],
            connect_timeout: Duration::from_secs(3),
            handshake_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(600),
        }))
    }

    pub(crate) fn from_entries<'a>(
        intercepted: InterceptedConnection,
        entries: impl Iterator<Item = &'a ProxyOrDirect>,
        upstream_mark: u32,
        connect_timeout: Duration,
        handshake_timeout: Duration,
        idle_timeout: Duration,
        append_direct_on_failure: bool,
    ) -> Result<Arc<Self>> {
        let mut routes = Vec::new();
        for entry in entries {
            match entry {
                ProxyOrDirect::Proxy(Proxy::Http(endpoint)) => {
                    routes.push(HttpRoute::Proxy(endpoint.clone()));
                }
                ProxyOrDirect::Direct => routes.push(HttpRoute::Direct),
                ProxyOrDirect::Proxy(Proxy::Socks5(endpoint)) => {
                    routes.push(HttpRoute::Socks5(endpoint.clone()));
                }
            }
        }
        if append_direct_on_failure
            && !routes
                .iter()
                .any(|route| matches!(route, HttpRoute::Direct))
        {
            routes.push(HttpRoute::Direct);
        }
        if routes.is_empty() {
            return Err(anyhow!("no HTTP-compatible upstream routes"));
        }
        Ok(Arc::new(Self {
            intercepted,
            upstream_mark,
            routes,
            connect_timeout,
            handshake_timeout,
            idle_timeout,
        }))
    }
}

/// Serve one intercepted plain HTTP connection using Pingora proxy.
pub async fn serve_http_connection(stream: TcpStream, ctx: Arc<HttpProxyContext>) -> Result<()> {
    let proxy_app = TotanHttpProxy {
        intercepted: ctx.intercepted.clone(),
        upstream_mark: ctx.upstream_mark,
        routes: ctx.routes.clone(),
        connect_timeout: ctx.connect_timeout,
        handshake_timeout: ctx.handshake_timeout,
        idle_timeout: ctx.idle_timeout,
    };

    let conf = ServerConf {
        max_retries: ctx.routes.len().max(1),
        ..ServerConf::default()
    };
    let proxy = Arc::new(http_proxy(&Arc::new(conf), proxy_app));

    let stream = pingora::protocols::l4::stream::Stream::from(stream);
    let (_tx, shutdown) = tokio::sync::watch::channel(false);

    // ServerApp owns the HTTP/1 connection loop. Calling process_new_http()
    // directly would process only one request and discard Pingora's reusable
    // stream, breaking downstream keep-alive.
    proxy.process_new(Box::new(stream), &shutdown).await;

    Ok(())
}

pub struct TotanHttpProxy {
    intercepted: InterceptedConnection,
    upstream_mark: u32,
    routes: Vec<HttpRoute>,
    connect_timeout: Duration,
    handshake_timeout: Duration,
    idle_timeout: Duration,
}

pub struct HttpRequestContext {
    route_index: usize,
}

#[async_trait]
impl ProxyHttp for TotanHttpProxy {
    type CTX = HttpRequestContext;
    fn new_ctx(&self) -> Self::CTX {
        HttpRequestContext { route_index: 0 }
    }

    async fn request_filter(
        &self,
        session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> pingora::Result<bool> {
        if !self.idle_timeout.is_zero() {
            session.set_keepalive(Some(self.idle_timeout.as_secs().max(1)));
        }
        Ok(false)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<Box<HttpPeer>> {
        let route = self.routes.get(ctx.route_index).ok_or_else(|| {
            pingora::Error::explain(
                pingora::ErrorType::ConnectError,
                "HTTP upstream route list exhausted",
            )
        })?;
        let mut peer = match route {
            HttpRoute::Proxy(endpoint) => HttpPeer::new(
                (endpoint.host().to_string(), endpoint.port()),
                false,
                "".to_string(),
            ),
            HttpRoute::Direct => {
                HttpPeer::new(self.intercepted.original_dest, false, "".to_string())
            }
            HttpRoute::Socks5(endpoint) => {
                let mut peer = HttpPeer::new(self.intercepted.original_dest, false, "".to_string());
                peer.options.custom_l4 = Some(Arc::new(Socks5Connector {
                    proxy: endpoint.clone(),
                    target: self.intercepted.original_dest,
                    upstream_mark: self.upstream_mark,
                    connect_timeout: self.connect_timeout,
                    handshake_timeout: self.handshake_timeout,
                }));
                peer
            }
        };
        peer.options.connection_timeout = Some(self.connect_timeout);
        peer.options.total_connection_timeout = Some(self.connect_timeout);
        if !self.idle_timeout.is_zero() {
            peer.options.read_timeout = Some(self.idle_timeout);
            peer.options.write_timeout = Some(self.idle_timeout);
            peer.options.idle_timeout = Some(self.idle_timeout);
        }

        // cgroup/connect4 skips totan's own upstream sockets by this SO_MARK.
        if self.upstream_mark != 0 {
            let mark = self.upstream_mark;
            peer.options.upstream_tcp_sock_tweak_hook = Some(Arc::new(move |sock| {
                socket2::SockRef::from(sock).set_mark(mark).map_err(|e| {
                    pingora::Error::because(
                        pingora::ErrorType::ConnectError,
                        "failed to set SO_MARK on upstream socket",
                        e,
                    )
                })
            }));
        }

        Ok(Box::new(peer))
    }

    fn fail_to_connect(
        &self,
        _session: &mut Session,
        _peer: &HttpPeer,
        ctx: &mut Self::CTX,
        mut error: Box<pingora::Error>,
    ) -> Box<pingora::Error> {
        if ctx.route_index + 1 < self.routes.len() {
            ctx.route_index += 1;
            error.set_retry(true);
        } else {
            error.set_retry(false);
        }
        error
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<()> {
        // RFC 7230 §5.3.2: a client speaking to a forward proxy MUST use the
        // absolute-form request-target (`GET http://host/path HTTP/1.1`).
        // pingora's H1 wire encoder emits `req.raw_path()`, which falls
        // through to `uri.path_and_query().as_str()`. Parsing
        // `"http://host/"` as a `http::Uri` puts everything except the path
        // into the scheme/authority — `path_and_query()` then returns just
        // `"/"` and we end up sending origin-form. To force the entire
        // absolute string onto the wire, build the Uri with the absolute
        // string as the *path-and-query* directly: it's stored verbatim and
        // surfaces unchanged from `path_and_query().as_str()`.
        let host = upstream_request
            .headers
            .get(http::header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                crate::utils::socket_authority_with_default(self.intercepted.original_dest, 80)
            });

        let path = upstream_request
            .uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");
        let wire_target = match self.routes.get(ctx.route_index) {
            Some(HttpRoute::Proxy(_)) => format!("http://{}{}", host, path),
            Some(HttpRoute::Direct | HttpRoute::Socks5(_)) => path.to_string(),
            None => {
                return Err(pingora::Error::explain(
                    pingora::ErrorType::InternalError,
                    "HTTP upstream route list exhausted",
                ));
            }
        };

        let new_uri = http::Uri::builder()
            .path_and_query(wire_target.as_str())
            .build()
            .map_err(|e| {
                pingora::Error::explain(pingora::ErrorType::InternalError, e.to_string())
            })?;
        upstream_request.set_uri(new_uri);

        upstream_request.insert_header("Host", host).map_err(|e| {
            pingora::Error::explain(pingora::ErrorType::InternalError, e.to_string())
        })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn read_http_message(stream: &mut TcpStream) -> Vec<u8> {
        let mut message = Vec::with_capacity(512);
        let mut byte = [0u8; 1];
        while !message.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).await.unwrap();
            message.push(byte[0]);
            assert!(message.len() <= 8192, "HTTP header exceeded test limit");
        }

        let text = String::from_utf8_lossy(&message);
        let content_length = text
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0);
        let header_len = message.len();
        message.resize(header_len + content_length, 0);
        stream.read_exact(&mut message[header_len..]).await.unwrap();
        message
    }

    #[tokio::test]
    async fn test_serve_http_connection() {
        let upstream_server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_server_addr = upstream_server.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut stream, _) = upstream_server.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let n = stream.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]);
            println!("RECEIVED REQUEST AT UPSTREAM: {:?}", req);
            // Forward-proxy semantics: the request-target on the wire MUST be
            // absolute-form (RFC 7230 §5.3.2), so the upstream proxy can route
            // without inspecting the Host header.
            assert!(
                req.contains("GET http://127.0.0.1:1234/path HTTP/1.1"),
                "expected absolute-form request-target, got: {req:?}"
            );
            assert!(req.contains("Host: 127.0.0.1:1234"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                .await
                .unwrap();
        });

        let upstream_proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_proxy_addr = upstream_proxy.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut client_stream, _) = upstream_proxy.accept().await.unwrap();
            let mut server_stream = TcpStream::connect(upstream_server_addr).await.unwrap();
            tokio::io::copy_bidirectional(&mut client_stream, &mut server_stream)
                .await
                .unwrap();
        });

        let intercepted = InterceptedConnection {
            client_addr: "127.0.0.1:55555".parse().unwrap(),
            original_dest: "127.0.0.1:1234".parse().unwrap(),
            sni_hostname: None,
        };
        let proxy_url = format!("http://127.0.0.1:{}", upstream_proxy_addr.port());
        let ctx = HttpProxyContext::new(intercepted, &proxy_url, 0).unwrap();

        let totan_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let totan_addr = totan_listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (stream, _) = totan_listener.accept().await.unwrap();
            if let Err(e) = serve_http_connection(stream, ctx).await {
                eprintln!("serve_http_connection failed: {}", e);
            }
        });

        let mut client = TcpStream::connect(totan_addr).await.unwrap();
        client
            .write_all(b"GET /path HTTP/1.1\r\nHost: 127.0.0.1:1234\r\n\r\n")
            .await
            .unwrap();

        let mut response = [0u8; 1024];
        let n = client.read(&mut response).await.unwrap();
        let res_str = String::from_utf8_lossy(&response[..n]);
        assert!(res_str.contains("HTTP/1.1 200 OK"));
        assert!(res_str.contains("OK"));
    }

    #[tokio::test]
    async fn downstream_keepalive_processes_multiple_requests() {
        let upstream_proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_proxy_addr = upstream_proxy.local_addr().unwrap();

        let proxy_task = tokio::spawn(async move {
            let (mut stream, _) = upstream_proxy.accept().await.unwrap();
            for path in ["/one", "/two"] {
                let request = read_http_message(&mut stream).await;
                let request = String::from_utf8_lossy(&request);
                assert!(
                    request.contains(&format!("GET http://example.com{} HTTP/1.1", path)),
                    "unexpected upstream request: {request:?}"
                );
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                    .await
                    .unwrap();
            }
        });

        let intercepted = InterceptedConnection {
            client_addr: "127.0.0.1:55555".parse().unwrap(),
            original_dest: "192.0.2.10:80".parse().unwrap(),
            sni_hostname: None,
        };
        let proxy_url = format!("http://127.0.0.1:{}", upstream_proxy_addr.port());
        let ctx = HttpProxyContext::new(intercepted, &proxy_url, 0).unwrap();

        let totan_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let totan_addr = totan_listener.local_addr().unwrap();
        let totan_task = tokio::spawn(async move {
            let (stream, _) = totan_listener.accept().await.unwrap();
            serve_http_connection(stream, ctx).await.unwrap();
        });

        let mut client = TcpStream::connect(totan_addr).await.unwrap();
        for path in ["/one", "/two"] {
            client
                .write_all(format!("GET {path} HTTP/1.1\r\nHost: example.com\r\n\r\n").as_bytes())
                .await
                .unwrap();
            let response = read_http_message(&mut client).await;
            assert!(response.ends_with(b"OK"));
        }
        client.shutdown().await.unwrap();

        tokio::time::timeout(std::time::Duration::from_secs(1), proxy_task)
            .await
            .expect("upstream proxy did not receive both requests")
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), totan_task)
            .await
            .expect("Pingora connection loop did not stop after client close")
            .unwrap();
    }

    #[tokio::test]
    async fn connect_failure_advances_to_next_http_proxy() {
        let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead.local_addr().unwrap();
        drop(dead);

        let live = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let live_addr = live.local_addr().unwrap();
        let live_task = tokio::spawn(async move {
            let (mut stream, _) = live.accept().await.unwrap();
            let request = read_http_message(&mut stream).await;
            assert!(
                String::from_utf8_lossy(&request).contains("GET http://failover.example/ HTTP/1.1")
            );
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                .await
                .unwrap();
        });

        let intercepted = InterceptedConnection {
            client_addr: "127.0.0.1:55555".parse().unwrap(),
            original_dest: "192.0.2.10:80".parse().unwrap(),
            sni_hostname: None,
        };
        let proxies: crate::proxy::Proxies = format!(
            "PROXY 127.0.0.1:{}; PROXY 127.0.0.1:{}",
            dead_addr.port(),
            live_addr.port()
        )
        .parse()
        .unwrap();
        let ctx = HttpProxyContext::from_entries(
            intercepted,
            proxies.iter(),
            0,
            Duration::from_millis(100),
            Duration::from_millis(100),
            Duration::from_secs(1),
            false,
        )
        .unwrap();

        let totan_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let totan_addr = totan_listener.local_addr().unwrap();
        let totan_task = tokio::spawn(async move {
            let (stream, _) = totan_listener.accept().await.unwrap();
            serve_http_connection(stream, ctx).await.unwrap();
        });

        let mut client = TcpStream::connect(totan_addr).await.unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: failover.example\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(String::from_utf8_lossy(&response).contains("200 OK"));

        tokio::time::timeout(Duration::from_secs(1), live_task)
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), totan_task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn http_failover_can_advance_to_socks5() {
        let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead.local_addr().unwrap();
        drop(dead);

        let socks = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_addr = socks.local_addr().unwrap();
        let socks_task = tokio::spawn(async move {
            let (mut stream, _) = socks.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [0x05, 0x01, 0x00]);
            stream.write_all(&[0x05, 0x00]).await.unwrap();

            let mut request = [0u8; 10];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request[..4], &[0x05, 0x01, 0x00, 0x01]);
            assert_eq!(&request[4..8], &[192, 0, 2, 10]);
            assert_eq!(u16::from_be_bytes([request[8], request[9]]), 80);
            stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 80])
                .await
                .unwrap();

            let request = read_http_message(&mut stream).await;
            assert!(String::from_utf8_lossy(&request).contains("GET /via-socks HTTP/1.1"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                .await
                .unwrap();
        });

        let intercepted = InterceptedConnection {
            client_addr: "127.0.0.1:55555".parse().unwrap(),
            original_dest: "192.0.2.10:80".parse().unwrap(),
            sni_hostname: None,
        };
        let proxies: crate::proxy::Proxies = format!(
            "PROXY 127.0.0.1:{}; SOCKS5 127.0.0.1:{}",
            dead_addr.port(),
            socks_addr.port()
        )
        .parse()
        .unwrap();
        let ctx = HttpProxyContext::from_entries(
            intercepted,
            proxies.iter(),
            0,
            Duration::from_millis(100),
            Duration::from_millis(100),
            Duration::from_secs(1),
            false,
        )
        .unwrap();

        let totan_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let totan_addr = totan_listener.local_addr().unwrap();
        let totan_task = tokio::spawn(async move {
            let (stream, _) = totan_listener.accept().await.unwrap();
            serve_http_connection(stream, ctx).await.unwrap();
        });

        let mut client = TcpStream::connect(totan_addr).await.unwrap();
        client
            .write_all(
                b"GET /via-socks HTTP/1.1\r\nHost: failover.example\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(String::from_utf8_lossy(&response).contains("200 OK"));

        tokio::time::timeout(Duration::from_secs(1), socks_task)
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), totan_task)
            .await
            .unwrap()
            .unwrap();
    }
}
