use std::io::Write as _;
use std::time::Duration;
use tempfile::NamedTempFile;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use totan::proxy::{proxies_from_url_str, Proxies, Proxy, ProxyOrDirect};
use totan_common::config::ErrorMitigationConfig;
use totan_common::InterceptedConnection;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn tls_conn(host: &str) -> InterceptedConnection {
    InterceptedConnection {
        client_addr: "127.0.0.1:9999".parse().unwrap(),
        original_dest: "93.184.216.34:443".parse().unwrap(),
        sni_hostname: Some(host.to_string()),
    }
}

fn http_conn() -> InterceptedConnection {
    InterceptedConnection {
        client_addr: "127.0.0.1:9999".parse().unwrap(),
        original_dest: "93.184.216.34:80".parse().unwrap(),
        sni_hostname: None,
    }
}

/// Create a connected local TCP pair: returns (totan_side, test_client_side).
/// `totan_side` is passed to `handle_connection`; `test_client_side` is used
/// by the test to write/read as if it were the original client.
async fn tcp_pair() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (client_side, server_side) =
        tokio::join!(tokio::net::TcpStream::connect(addr), listener.accept());
    (server_side.unwrap().0, client_side.unwrap())
}

// ── protocol-level tests ──────────────────────────────────────────────────────

#[tokio::test]
async fn test_socks5_handshake_on_duplex() {
    let handler =
        totan::upstream::UpstreamHandler::new(1000, ErrorMitigationConfig::default(), 0).unwrap();

    let (mut upstream, mut upstream_mock) = tokio::io::duplex(1024);

    tokio::spawn(async move {
        // Greet: no-auth
        let mut buf = [0u8; 3];
        upstream_mock.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, [0x05, 0x01, 0x00]);
        upstream_mock.write_all(&[0x05, 0x00]).await.unwrap();
        // Read and ignore the CONNECT request, then answer success.
        let mut buf = [0u8; 12];
        upstream_mock.read_exact(&mut buf).await.unwrap();
        upstream_mock
            .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 80])
            .await
            .unwrap();
        drop(upstream_mock);
    });

    let result = tokio::time::timeout(
        Duration::from_millis(200),
        handler.socks5_connect_impl::<tokio::io::DuplexStream>(
            &tls_conn("example.com"),
            &mut upstream,
        ),
    )
    .await
    .expect("timed out");
    assert!(result.is_ok());
}

// ── handle_connection level (real TCP on both sides) ──────────────────────────
//
// These tests exercise the complete UpstreamHandler::handle_connection path,
// including the TCP dial-out to the upstream proxy. The "client" side is a
// real TcpStream (required by handle_connection's signature); the upstream
// proxy is a real TcpListener so we can inspect what totan sends.

/// Upstream proxy returns 407 Proxy Auth Required → handle_connection must
/// surface an error, not forward the 407 body as tunnel data.
#[tokio::test]
async fn test_handle_connection_https_407_is_error() {
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = proxy.accept().await {
            let mut buf = [0u8; 2048];
            let _ = stream.read(&mut buf).await;
            let _ = stream
                .write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                      Proxy-Authenticate: Basic realm=\"corp\"\r\n\
                      Content-Length: 0\r\n\r\n",
                )
                .await;
        }
    });

    let proxy_url = format!("http://{}", proxy_addr);
    let proxies = proxies_from_url_str(&proxy_url).unwrap();
    let handler =
        totan::upstream::UpstreamHandler::new(1000, ErrorMitigationConfig::default(), 0).unwrap();

    let (totan_side, _test_client) = tcp_pair().await;

    let result = tokio::time::timeout(
        Duration::from_millis(500),
        handler.handle_connection(tls_conn("example.com"), totan_side, proxies),
    )
    .await
    .expect("timed out waiting for 407 handling");

    assert!(result.is_err(), "407 must propagate as an error");
}

/// Plain HTTP forwarded through a real upstream proxy: verifies the request is
/// rewritten to absolute form and the response body reaches the client.
#[tokio::test]
async fn test_handle_connection_http_end_to_end() {
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = proxy.accept().await {
            let mut buf = [0u8; 2048];
            let n = stream.read(&mut buf).await.unwrap_or(0);
            if String::from_utf8_lossy(&buf[..n]).contains("GET http://") {
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                    .await;
            }
            let _ = stream.shutdown().await;
        }
    });

    let proxy_url = format!("http://{}", proxy_addr);
    let proxies = proxies_from_url_str(&proxy_url).unwrap();
    let handler =
        totan::upstream::UpstreamHandler::new(1000, ErrorMitigationConfig::default(), 0).unwrap();

    let (totan_side, mut test_client) = tcp_pair().await;

    tokio::spawn(async move {
        let _ = test_client
            .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await;
        let mut buf = [0u8; 512];
        let n = test_client.read(&mut buf).await.unwrap_or(0);
        assert!(
            String::from_utf8_lossy(&buf[..n]).contains("OK"),
            "client must receive the proxy response"
        );
        let _ = test_client.shutdown().await;
    });

    let result = tokio::time::timeout(
        Duration::from_millis(500),
        handler.handle_connection(http_conn(), totan_side, proxies),
    )
    .await
    .expect("timed out");

    assert!(result.is_ok());
}

// ── PAC engine integration ────────────────────────────────────────────────────

/// Teams/O365 breakout PAC: cloud endpoints evaluate to DIRECT while
/// non-breakout hosts resolve to the corporate proxy. Apex domains and
/// subdomains must both be matched (real-world PAC requirement).
#[tokio::test]
async fn test_pac_direct_does_not_reach_proxy() {
    let mut pac_file = NamedTempFile::new().unwrap();
    pac_file
        .write_all(
            br#"
        function FindProxyForURL(url, host) {
            if (host === "teams.microsoft.com" ||
                shExpMatch(host, "*.teams.microsoft.com") ||
                shExpMatch(host, "*.office365.com")) {
                return "DIRECT";
            }
            return "PROXY 127.0.0.1:19999";
        }
    "#,
        )
        .unwrap();

    let engine = totan::pac::PacEvaluator::from_file(pac_file.path())
        .await
        .unwrap();

    for (url, host) in [
        ("https://teams.microsoft.com/", "teams.microsoft.com"),
        (
            "https://join.teams.microsoft.com/",
            "join.teams.microsoft.com",
        ),
        ("https://outlook.office365.com/", "outlook.office365.com"),
    ] {
        let p = engine.find_proxy(url, host).await.unwrap();
        assert_eq!(p, Proxies::direct(), "{host} should be DIRECT");
    }

    let p = engine
        .find_proxy("https://internal.corp.example/", "internal.corp.example")
        .await
        .unwrap();
    assert_eq!(
        p.first(),
        &ProxyOrDirect::Proxy(Proxy::Http("127.0.0.1:19999".parse().unwrap())),
        "non-breakout host must still use proxy"
    );
}
