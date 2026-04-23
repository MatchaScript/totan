use anyhow::{anyhow, Result};
use async_trait::async_trait;
use pingora::apps::HttpServerApp;
use pingora::http::RequestHeader;
use pingora::proxy::{http_proxy, ProxyHttp, Session};
use pingora::server::configuration::ServerConf;
use pingora::upstreams::peer::HttpPeer;
use std::sync::Arc;
use tokio::net::TcpStream;
use url::Url;

use totan_common::InterceptedConnection;

/// Context shared by all requests on a single downstream connection.
pub struct HttpProxyContext {
    pub intercepted: InterceptedConnection,
    pub upstream_proxy: Url,
    pub upstream_mark: u32,
}

impl HttpProxyContext {
    pub fn new(
        intercepted: InterceptedConnection,
        upstream_proxy_url: &str,
        upstream_mark: u32,
    ) -> Result<Arc<Self>> {
        let upstream_proxy = Url::parse(upstream_proxy_url)?;
        if upstream_proxy.scheme() != "http" {
            return Err(anyhow!(
                "Pingora HTTP pipeline requires http-scheme upstream"
            ));
        }
        Ok(Arc::new(Self {
            intercepted,
            upstream_proxy,
            upstream_mark,
        }))
    }
}

/// Serve one intercepted plain HTTP connection using Pingora proxy.
pub async fn serve_http_connection(stream: TcpStream, ctx: Arc<HttpProxyContext>) -> Result<()> {
    let proxy_app = TotanHttpProxy {
        upstream_proxy: ctx.upstream_proxy.clone(),
        intercepted: ctx.intercepted.clone(),
        upstream_mark: ctx.upstream_mark,
    };

    let conf = Arc::new(ServerConf::default());
    let proxy = http_proxy(&conf, proxy_app);

    let stream = pingora::protocols::l4::stream::Stream::from(stream);
    let session = pingora::protocols::http::ServerSession::new_http1(Box::new(stream));

    let (_tx, shutdown) = tokio::sync::watch::channel(false);

    Arc::new(proxy).process_new_http(session, &shutdown).await;

    Ok(())
}

pub struct TotanHttpProxy {
    upstream_proxy: Url,
    intercepted: InterceptedConnection,
    upstream_mark: u32,
}

#[async_trait]
impl ProxyHttp for TotanHttpProxy {
    type CTX = ();
    fn new_ctx(&self) -> Self::CTX {}

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> pingora::Result<Box<HttpPeer>> {
        let host = self
            .upstream_proxy
            .host_str()
            .unwrap_or("localhost")
            .to_string();
        let port = self.upstream_proxy.port().unwrap_or(80);
        let mut peer = HttpPeer::new((host, port), false, "".to_string());

        // In netfilter mode the OUTPUT hook would re-intercept totan's own
        // upstream connection; SO_MARK tags it so the nftables rule skips it.
        // In eBPF mode upstream_mark is 0 and no hook is installed.
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

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        _ctx: &mut Self::CTX,
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
                let ip = self.intercepted.original_dest.ip().to_string();
                let port = self.intercepted.original_dest.port();
                if port == 80 {
                    ip
                } else {
                    format!("{}:{}", ip, port)
                }
            });

        let path = upstream_request
            .uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");
        let abs_uri = format!("http://{}{}", host, path);

        let new_uri = http::Uri::builder()
            .path_and_query(abs_uri.as_str())
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
}
