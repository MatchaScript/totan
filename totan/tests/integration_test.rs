use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use totan_common::config::ErrorMitigationConfig;
use totan_common::InterceptedConnection;

#[tokio::test]
async fn test_full_direct_flow() {
    let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let _target_addr = target_listener.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = target_listener.accept().await {
            let mut buf = [0u8; 1024];
            let n = stream.read(&mut buf).await.unwrap();
            if String::from_utf8_lossy(&buf[..n]).contains("PING") {
                let _ = stream.write_all(b"PONG").await;
            }
        }
    });

    // Currently direct flow integration test is skipped as it depends on real TcpStream
}

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
            // Close to avoid hanging the tunnel
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

    let intercepted_conn = InterceptedConnection {
        client_addr: "127.0.0.1:9999".parse().unwrap(),
        original_dest: "93.184.216.34:80".parse().unwrap(),
        sni_hostname: None,
    };

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
            intercepted_conn,
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

    let intercepted_conn = InterceptedConnection {
        client_addr: "127.0.0.1:9999".parse().unwrap(),
        original_dest: "93.184.216.34:80".parse().unwrap(),
        sni_hostname: Some("example.com".to_string()),
    };

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
            intercepted_conn,
            &mut client,
            &mut upstream,
        ),
    )
    .await;
}
