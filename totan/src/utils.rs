use anyhow::Result;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

/// Format a host and port as an RFC 3986 authority. IPv6 literals are
/// bracketed; DNS names and IPv4 literals are left as-is.
pub fn format_authority(host: &str, port: u16) -> String {
    let host = host.trim();
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);

    match host.parse::<IpAddr>() {
        Ok(IpAddr::V6(_)) => format!("[{}]:{}", host, port),
        _ => format!("{}:{}", host, port),
    }
}

/// Format an authority while omitting its port when it equals the scheme's
/// default. This is used for PAC target URLs and fallback HTTP Host values.
pub fn format_authority_with_default(host: &str, port: u16, default_port: u16) -> String {
    if port == default_port {
        let host = host.trim();
        let host = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host);
        match host.parse::<IpAddr>() {
            Ok(IpAddr::V6(_)) => format!("[{}]", host),
            _ => host.to_string(),
        }
    } else {
        format_authority(host, port)
    }
}

/// Format a socket address as an authority, preserving IPv6 brackets and its
/// scope identifier. `SocketAddr`'s Display implementation already provides
/// exactly the required host:port representation.
pub fn socket_authority(addr: SocketAddr) -> String {
    addr.to_string()
}

/// Format a socket address while omitting a default port.
pub fn socket_authority_with_default(addr: SocketAddr, default_port: u16) -> String {
    if addr.port() != default_port {
        return socket_authority(addr);
    }

    match addr {
        SocketAddr::V4(addr) => addr.ip().to_string(),
        SocketAddr::V6(addr) if addr.scope_id() == 0 => format!("[{}]", addr.ip()),
        SocketAddr::V6(addr) => format!("[{}%{}]", addr.ip(), addr.scope_id()),
    }
}

/// Extract SNI hostname from a TLS ClientHello on `stream` (peeked, not consumed).
pub async fn extract_sni_hostname(stream: &mut TcpStream) -> Result<String> {
    // 16 KiB matches Envoy's tls_inspector default max ClientHello size and
    // covers post-quantum keyshares that overflow a 4 KiB buffer.
    let mut buf = [0u8; 16384];

    // `peek()` does not consume the already-readable prefix, so calling it
    // again immediately returns that same prefix instead of waiting for the
    // next TCP segment. Poll with a short yield; the caller wraps this routine
    // in the configured handshake deadline.
    let n = loop {
        let n = stream.peek(&mut buf).await?;
        if n >= 5 {
            if buf[0] != 0x16 || buf[1] != 0x03 {
                break n; // Not TLS; let the parser produce the error.
            }
            let record_length = u16::from_be_bytes([buf[3], buf[4]]) as usize;
            let needed = 5 + record_length;
            if needed > buf.len() || n >= needed {
                break n; // Complete, or SNI must be parsed from the bounded prefix.
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    };

    extract_sni_from_bytes(&buf[..n])
}

/// Parse the SNI hostname out of the bytes of a (possibly truncated) TLS
/// ClientHello. The record-length header is advisory: parsing keys off the
/// bytes actually present, so an oversized ClientHello whose tail didn't fit or
/// hasn't arrived still yields its SNI, which sits near the front.
fn extract_sni_from_bytes(data: &[u8]) -> Result<String> {
    let n = data.len();
    if n < 5 {
        return Err(anyhow::anyhow!("Not enough data for TLS handshake"));
    }
    // TLS handshake record (type 22, version 3.x).
    if data[0] != 0x16 || data[1] != 0x03 {
        return Err(anyhow::anyhow!("Not a TLS handshake"));
    }

    let mut offset = 5; // Skip TLS record header.

    if offset + 4 > n {
        return Err(anyhow::anyhow!("Incomplete handshake header"));
    }
    // Handshake type 1 = ClientHello.
    if data[offset] != 0x01 {
        return Err(anyhow::anyhow!("Not a ClientHello message"));
    }
    offset += 4; // handshake type (1) + length (3)
    offset += 2; // client version

    if offset + 32 > n {
        return Err(anyhow::anyhow!("Incomplete ClientHello"));
    }
    offset += 32; // client random

    if offset + 1 > n {
        return Err(anyhow::anyhow!("Missing session ID length"));
    }
    let session_id_length = data[offset] as usize;
    offset += 1 + session_id_length;

    if offset + 2 > n {
        return Err(anyhow::anyhow!("Missing cipher suites length"));
    }
    let cipher_suites_length = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2 + cipher_suites_length;

    if offset + 1 > n {
        return Err(anyhow::anyhow!("Missing compression methods length"));
    }
    let compression_methods_length = data[offset] as usize;
    offset += 1 + compression_methods_length;

    if offset + 2 > n {
        return Err(anyhow::anyhow!("Missing extensions length"));
    }
    let extensions_length = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;

    let extensions_end = offset + extensions_length;
    while offset + 4 <= extensions_end && offset + 4 <= n {
        let extension_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let extension_length = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
        offset += 4;

        // SNI extension (type 0).
        if extension_type == 0 && offset + extension_length <= n {
            return parse_sni_extension(&data[offset..offset + extension_length]);
        }

        offset += extension_length;
    }

    Err(anyhow::anyhow!("SNI extension not found"))
}

fn parse_sni_extension(data: &[u8]) -> Result<String> {
    if data.len() < 2 {
        return Err(anyhow::anyhow!("SNI extension too short"));
    }

    // Skip server name list length
    let mut offset = 2;

    while offset + 3 < data.len() {
        let name_type = data[offset];
        let name_length = u16::from_be_bytes([data[offset + 1], data[offset + 2]]) as usize;
        offset += 3;

        if name_type == 0 && offset + name_length <= data.len() {
            // Hostname (type 0)
            let hostname = String::from_utf8(data[offset..offset + name_length].to_vec())
                .map_err(|_| anyhow::anyhow!("Invalid UTF-8 in SNI hostname"))?;
            return Ok(hostname);
        }

        offset += name_length;
    }

    Err(anyhow::anyhow!("No hostname in SNI extension"))
}

/// Extract the `Host` header hostname from a plain-HTTP request on `stream`
/// (peeked, not consumed) so PAC resolution can key off the domain instead of
/// the bare destination IP. Returns the hostname without any `:port` suffix.
pub async fn extract_http_host(stream: &mut TcpStream) -> Result<String> {
    let mut buf = [0u8; 4096];
    loop {
        let n = stream.peek(&mut buf).await?;
        if let Some(host) = parse_http_host(&buf[..n]) {
            return Ok(host);
        }
        if n >= buf.len() {
            return Err(anyhow::anyhow!("HTTP header exceeds 4096 bytes"));
        }
        if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
            return Err(anyhow::anyhow!("no Host header in request"));
        }
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
}

/// Parse the `Host` header out of (possibly partial) HTTP request bytes,
/// returning the hostname with any `:port` stripped.
fn parse_http_host(data: &[u8]) -> Option<String> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut req = httparse::Request::new(&mut headers);
    // Ignore completeness: headers parsed before the cutoff are still populated,
    // and the request line + Host arrive in the first segment in practice.
    let _ = req.parse(data);
    req.headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("host"))
        .and_then(|h| std::str::from_utf8(h.value).ok())
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .map(|v| {
            // Strip an optional :port. Bracketed IPv6 literals keep their
            // brackets' contents; plain host:port splits on the last colon.
            match v.strip_prefix('[').and_then(|r| r.split_once(']')) {
                Some((h6, _)) => h6.to_string(),
                None => v.rsplit_once(':').map(|(h, _)| h).unwrap_or(v).to_string(),
            }
        })
}

/// A tolerant version of tokio::io::copy_bidirectional that treats some
/// common socket errors as normal termination. This mitigates spurious
/// errors that transparent proxies often see when peers close abruptly.
pub async fn tolerant_copy_bidirectional<A, B>(a: &mut A, b: &mut B) -> std::io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    match tokio::io::copy_bidirectional(a, b).await {
        Ok(_) => Ok(()),
        Err(e) => {
            match e.kind() {
                // Connection reset/broken pipe are normal in half-close races
                ErrorKind::ConnectionReset
                | ErrorKind::BrokenPipe
                | ErrorKind::ConnectionAborted => Ok(()),
                // Timed out/UnexpectedEof often occur on FIN/RST edges
                ErrorKind::TimedOut | ErrorKind::UnexpectedEof => Ok(()),
                _ => Err(e),
            }
        }
    }
}

/// Relay both directions and close the pair when neither side produces data
/// for `idle`. A zero duration preserves the unbounded legacy behaviour.
pub async fn tolerant_copy_bidirectional_with_idle<A, B>(
    a: &mut A,
    b: &mut B,
    idle: std::time::Duration,
) -> std::io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    if idle.is_zero() {
        return tolerant_copy_bidirectional(a, b).await;
    }

    enum ReadEvent {
        A(std::io::Result<usize>),
        B(std::io::Result<usize>),
    }

    let mut a_open = true;
    let mut b_open = true;
    let mut a_buf = [0u8; 16 * 1024];
    let mut b_buf = [0u8; 16 * 1024];

    while a_open || b_open {
        let event = tokio::time::timeout(idle, async {
            tokio::select! {
                result = a.read(&mut a_buf), if a_open => ReadEvent::A(result),
                result = b.read(&mut b_buf), if b_open => ReadEvent::B(result),
            }
        })
        .await
        .map_err(|_| std::io::Error::new(ErrorKind::TimedOut, "connection idle timeout"))?;

        match event {
            ReadEvent::A(Ok(0)) => {
                a_open = false;
                let _ = tokio::time::timeout(idle, b.shutdown()).await;
            }
            ReadEvent::B(Ok(0)) => {
                b_open = false;
                let _ = tokio::time::timeout(idle, a.shutdown()).await;
            }
            ReadEvent::A(Ok(n)) => {
                tokio::time::timeout(idle, b.write_all(&a_buf[..n]))
                    .await
                    .map_err(|_| {
                        std::io::Error::new(ErrorKind::TimedOut, "upstream write timeout")
                    })??;
            }
            ReadEvent::B(Ok(n)) => {
                tokio::time::timeout(idle, a.write_all(&b_buf[..n]))
                    .await
                    .map_err(|_| {
                        std::io::Error::new(ErrorKind::TimedOut, "client write timeout")
                    })??;
            }
            ReadEvent::A(Err(error)) | ReadEvent::B(Err(error)) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_formats_hostnames_and_ip_literals() {
        assert_eq!(format_authority("example.com", 443), "example.com:443");
        assert_eq!(format_authority("192.0.2.1", 8080), "192.0.2.1:8080");
        assert_eq!(format_authority("2001:db8::1", 443), "[2001:db8::1]:443");
        assert_eq!(format_authority("[2001:db8::1]", 443), "[2001:db8::1]:443");
    }

    #[test]
    fn authority_omits_only_the_default_port() {
        assert_eq!(
            format_authority_with_default("example.com", 80, 80),
            "example.com"
        );
        assert_eq!(
            format_authority_with_default("2001:db8::1", 80, 80),
            "[2001:db8::1]"
        );
        assert_eq!(
            format_authority_with_default("2001:db8::1", 8080, 80),
            "[2001:db8::1]:8080"
        );
    }

    #[test]
    fn socket_authority_preserves_ipv6_scope() {
        let addr = SocketAddr::V6(std::net::SocketAddrV6::new(
            "fe80::1".parse().unwrap(),
            443,
            0,
            2,
        ));
        assert_eq!(socket_authority(addr), "[fe80::1%2]:443");
        assert_eq!(socket_authority_with_default(addr, 443), "[fe80::1%2]");
    }

    /// Build a minimal TLS ClientHello carrying a single SNI extension, with a
    /// caller-chosen value in the record-length header (so we can simulate a
    /// record whose declared length exceeds the bytes actually buffered).
    fn client_hello_with_sni(sni: &str, declared_record_len: u16) -> Vec<u8> {
        let name = sni.as_bytes();
        // SNI extension data: server_name_list.
        let mut ext_data = Vec::new();
        ext_data.extend_from_slice(&((3 + name.len()) as u16).to_be_bytes()); // list len
        ext_data.push(0x00); // name type = host_name
        ext_data.extend_from_slice(&(name.len() as u16).to_be_bytes());
        ext_data.extend_from_slice(name);

        // Extension TLV (type 0 = server_name).
        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0u16.to_be_bytes()); // ext type
        extensions.extend_from_slice(&(ext_data.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&ext_data);

        // Handshake body.
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // client version
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0x00); // session id len
        body.extend_from_slice(&2u16.to_be_bytes()); // cipher suites len
        body.extend_from_slice(&[0x00, 0x2f]); // one cipher suite
        body.push(0x01); // compression methods len
        body.push(0x00); // null compression
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        // Handshake header: type=ClientHello, 3-byte length.
        let mut handshake = vec![0x01];
        let hlen = body.len();
        handshake.extend_from_slice(&[(hlen >> 16) as u8, (hlen >> 8) as u8, hlen as u8]);
        handshake.extend_from_slice(&body);

        // TLS record header with the *declared* (possibly inflated) length.
        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&declared_record_len.to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn sni_extracted_from_well_formed_client_hello() {
        let hello = client_hello_with_sni("example.com", 0);
        // declared 0 is wrong on the wire, but parsing keys off available bytes.
        let hello = {
            let mut h = hello;
            let real = (h.len() - 5) as u16;
            h[3..5].copy_from_slice(&real.to_be_bytes());
            h
        };
        assert_eq!(extract_sni_from_bytes(&hello).unwrap(), "example.com");
    }

    #[test]
    fn sni_extracted_even_when_record_exceeds_available_bytes() {
        // Declared record length is far larger than the bytes we provide, as
        // happens when a large ClientHello (post-quantum keyshares) overflows
        // the read buffer. SNI sits near the front and must still be parsed.
        let hello = client_hello_with_sni("ex.com", 60000);
        assert_eq!(extract_sni_from_bytes(&hello).unwrap(), "ex.com");
    }

    #[test]
    fn http_host_parsed_from_request() {
        let req = b"GET /path HTTP/1.1\r\nHost: example.com\r\nUser-Agent: x\r\n\r\n";
        assert_eq!(parse_http_host(req).as_deref(), Some("example.com"));
    }

    #[test]
    fn http_host_strips_port() {
        let req = b"GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n";
        assert_eq!(parse_http_host(req).as_deref(), Some("example.com"));
    }

    #[test]
    fn http_host_absent_returns_none() {
        let req = b"GET / HTTP/1.1\r\n\r\n";
        assert_eq!(parse_http_host(req), None);
    }

    #[tokio::test]
    async fn sni_waits_for_a_later_tcp_segment() {
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;

        let hello = client_hello_with_sni("split.example", 0);
        let hello = {
            let mut h = hello;
            let real = (h.len() - 5) as u16;
            h[3..5].copy_from_slice(&real.to_be_bytes());
            h
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let writer = tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            stream.write_all(&hello[..20]).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            stream.write_all(&hello[20..]).await.unwrap();
        });
        let (mut stream, _) = listener.accept().await.unwrap();
        let host = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            extract_sni_hostname(&mut stream),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(host, "split.example");
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn http_host_waits_for_a_later_tcp_segment() {
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let writer = tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            stream.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            stream
                .write_all(b"Host: split.example\r\n\r\n")
                .await
                .unwrap();
        });
        let (mut stream, _) = listener.accept().await.unwrap();
        let host = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            extract_http_host(&mut stream),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(host, "split.example");
        writer.await.unwrap();
    }

    #[test]
    fn test_parse_sni_extension() {
        // google.com payload
        let data = [
            0x00, 0x0d, // server name list length
            0x00, // name type (host_name = 0)
            0x00, 0x0a, // host name length (10)
            0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, // google.com
        ];
        let hostname = parse_sni_extension(&data).unwrap();
        assert_eq!(hostname, "google.com");
    }

    #[test]
    fn test_parse_sni_extension_multiple() {
        // Example with multiple names (unlikely in SNI but allowed by spec)
        let data = [
            0x00, 0x11, // server name list length (17)
            0x01, 0x00, 0x01, 0xff, // unknown type (type 1, len 1)
            0x00, 0x00, 0x0a, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63, 0x6f,
            0x6d, // google.com
        ];
        let hostname = parse_sni_extension(&data).unwrap();
        assert_eq!(hostname, "google.com");
    }

    #[tokio::test]
    async fn bidirectional_relay_enforces_idle_timeout() {
        let (_client, mut relay_client) = tokio::io::duplex(128);
        let (mut relay_upstream, _server) = tokio::io::duplex(128);
        let error = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            tolerant_copy_bidirectional_with_idle(
                &mut relay_client,
                &mut relay_upstream,
                std::time::Duration::from_millis(20),
            ),
        )
        .await
        .expect("relay must enforce its own idle timeout")
        .expect_err("idle relay must close with a timeout");
        assert_eq!(error.kind(), ErrorKind::TimedOut);
    }
}
