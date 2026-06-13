use anyhow::Result;
use std::io::ErrorKind;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

/// Extract SNI hostname from a TLS ClientHello on `stream` (peeked, not consumed).
pub async fn extract_sni_hostname(stream: &mut TcpStream) -> Result<String> {
    // 16 KiB matches Envoy's tls_inspector default max ClientHello size and
    // covers post-quantum keyshares that overflow a 4 KiB buffer.
    let mut buf = [0u8; 16384];

    // Peek in a loop: the ClientHello may arrive in multiple TCP segments.
    // Stop once we have the whole record (or as much as will fit) or give up
    // after a few retries.
    let n = {
        let mut n = stream.peek(&mut buf).await?;
        for _ in 0..8 {
            if n < 5 {
                n = stream.peek(&mut buf).await?;
                continue;
            }
            if buf[0] != 0x16 || buf[1] != 0x03 {
                break; // Not TLS; let the parser produce the error.
            }
            let record_length = u16::from_be_bytes([buf[3], buf[4]]) as usize;
            let needed = 5 + record_length;
            if needed > buf.len() || n >= needed {
                break; // We have it all, or it can't fully fit — parse what we have.
            }
            n = stream.peek(&mut buf).await?;
        }
        n
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
