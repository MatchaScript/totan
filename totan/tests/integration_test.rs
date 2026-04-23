use std::io::Write as _;
use std::time::Duration;
use tempfile::NamedTempFile;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
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

// ── handle_http_proxy_impl level (duplex) ─────────────────────────────────────

#[tokio::test]
async fn test_proxy_flow_simulated() {
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let proxy_url = format!("http://{}", proxy_addr);

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = proxy_listener.accept().await {
            let mut buf = [0u8; 1024];
            let n = stream.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]);
            if req.contains("GET http://example.com/ HTTP/1.1") {
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nHELO")
                    .await;
            }
            let _ = stream.shutdown().await;
        }
    });

    let handler = totan::upstream::UpstreamHandler::new(
        Some(proxy_url),
        1000,
        ErrorMitigationConfig::default(),
    )
    .unwrap();

    let (mut client, mut client_mock) = tokio::io::duplex(1024);
    let (mut upstream, _upstream_mock) = tokio::io::duplex(1024);

    tokio::spawn(async move {
        let _ = client_mock
            .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await;
        let mut buf = [0u8; 1024];
        let n = client_mock.read(&mut buf).await.unwrap_or(0);
        let resp = String::from_utf8_lossy(&buf[..n]);
        assert!(resp.contains("HELO"));
        let _ = client_mock.shutdown().await;
    });

    let _ = tokio::time::timeout(
        Duration::from_millis(200),
        handler.handle_http_proxy_impl::<tokio::io::DuplexStream, tokio::io::DuplexStream>(
            http_conn(),
            &mut client,
            &mut upstream,
        ),
    )
    .await;
}

#[tokio::test]
async fn test_socks5_flow_simulated() {
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let proxy_url = format!("socks5://{}", proxy_addr);

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = proxy_listener.accept().await {
            let mut buf = [0u8; 3];
            let _ = stream.read_exact(&mut buf).await;
            let _ = stream.write_all(&[0x05, 0x00]).await;

            let mut buf = [0u8; 12];
            let _ = stream.read_exact(&mut buf).await;
            let _ = stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 80])
                .await;

            let mut buf = [0u8; 4];
            let _ = stream.read_exact(&mut buf).await;
            if &buf == b"PING" {
                let _ = stream.write_all(b"PONG").await;
            }
            let _ = stream.shutdown().await;
        }
    });

    let handler = totan::upstream::UpstreamHandler::new(
        Some(proxy_url),
        1000,
        ErrorMitigationConfig::default(),
    )
    .unwrap();

    let (mut client, mut client_mock) = tokio::io::duplex(1024);
    let (mut upstream, _upstream_mock) = tokio::io::duplex(1024);

    tokio::spawn(async move {
        let _ = client_mock.write_all(b"PING").await;
        let mut buf = [0u8; 4];
        let _ = client_mock.read_exact(&mut buf).await;
        assert_eq!(&buf, b"PONG");
        let _ = client_mock.shutdown().await;
    });

    let _ = tokio::time::timeout(
        Duration::from_millis(200),
        handler.handle_socks5_proxy_impl::<tokio::io::DuplexStream, tokio::io::DuplexStream>(
            tls_conn("example.com"),
            &mut client,
            &mut upstream,
        ),
    )
    .await;
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
    let handler = totan::upstream::UpstreamHandler::new(
        Some(proxy_url),
        1000,
        ErrorMitigationConfig::default(),
    )
    .unwrap();

    let (totan_side, _test_client) = tcp_pair().await;

    let result = tokio::time::timeout(
        Duration::from_millis(500),
        handler.handle_connection(tls_conn("example.com"), totan_side, None, true),
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
    let handler = totan::upstream::UpstreamHandler::new(
        Some(proxy_url),
        1000,
        ErrorMitigationConfig::default(),
    )
    .unwrap();

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
        handler.handle_connection(http_conn(), totan_side, None, true),
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

    let engine = totan::pac::PacEngine::new(pac_file.path()).await.unwrap();

    for (url, host) in [
        ("https://teams.microsoft.com/", "teams.microsoft.com"),
        ("https://join.teams.microsoft.com/", "join.teams.microsoft.com"),
        ("https://outlook.office365.com/", "outlook.office365.com"),
    ] {
        assert_eq!(
            engine.find_proxy_for_url(url, host).await.unwrap(),
            None,
            "{host} should be DIRECT"
        );
    }

    assert_eq!(
        engine
            .find_proxy_for_url("https://internal.corp.example/", "internal.corp.example")
            .await
            .unwrap(),
        Some("http://127.0.0.1:19999".to_string()),
        "non-breakout host must still use proxy"
    );
}
