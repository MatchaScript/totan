use anyhow::Result;
use std::io::ErrorKind;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

/// Extract SNI hostname from TLS ClientHello message
pub async fn extract_sni_hostname(stream: &mut TcpStream) -> Result<String> {
    let mut buf = [0u8; 1024];

    // Peek at the first packet to extract SNI
    let n = stream.peek(&mut buf).await?;

    if n < 5 {
        return Err(anyhow::anyhow!("Not enough data for TLS handshake"));
    }

    // Check if this is a TLS handshake (type 22, version 3.x)
    if buf[0] != 0x16 || buf[1] != 0x03 {
        return Err(anyhow::anyhow!("Not a TLS handshake"));
    }

    // Parse TLS record length
    let record_length = u16::from_be_bytes([buf[3], buf[4]]) as usize;

    if n < 5 + record_length.min(n - 5) {
        return Err(anyhow::anyhow!("Incomplete TLS record"));
    }

    // Start parsing handshake message
    let mut offset = 5; // Skip TLS record header

    if offset + 4 > n {
        return Err(anyhow::anyhow!("Incomplete handshake header"));
    }

    // Check handshake type (should be 1 for ClientHello)
    if buf[offset] != 0x01 {
        return Err(anyhow::anyhow!("Not a ClientHello message"));
    }

    // Skip handshake length (3 bytes)
    offset += 4;

    // Skip client version (2 bytes)
    offset += 2;

    if offset + 32 > n {
        return Err(anyhow::anyhow!("Incomplete ClientHello"));
    }

    // Skip client random (32 bytes)
    offset += 32;

    if offset + 1 > n {
        return Err(anyhow::anyhow!("Missing session ID length"));
    }

    // Skip session ID
    let session_id_length = buf[offset] as usize;
    offset += 1 + session_id_length;

    if offset + 2 > n {
        return Err(anyhow::anyhow!("Missing cipher suites length"));
    }

    // Skip cipher suites
    let cipher_suites_length = u16::from_be_bytes([buf[offset], buf[offset + 1]]) as usize;
    offset += 2 + cipher_suites_length;

    if offset + 1 > n {
        return Err(anyhow::anyhow!("Missing compression methods length"));
    }

    // Skip compression methods
    let compression_methods_length = buf[offset] as usize;
    offset += 1 + compression_methods_length;

    if offset + 2 > n {
        return Err(anyhow::anyhow!("Missing extensions length"));
    }

    // Parse extensions
    let extensions_length = u16::from_be_bytes([buf[offset], buf[offset + 1]]) as usize;
    offset += 2;

    let extensions_end = offset + extensions_length;

    while offset + 4 <= extensions_end && offset + 4 <= n {
        let extension_type = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let extension_length = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]) as usize;
        offset += 4;

        // Check for SNI extension (type 0)
        if extension_type == 0 && offset + extension_length <= n {
            return parse_sni_extension(&buf[offset..offset + extension_length]);
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
