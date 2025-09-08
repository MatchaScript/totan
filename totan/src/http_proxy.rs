use std::{collections::HashSet, sync::Arc};
use anyhow::{anyhow, Result};
use hyper::{Request, Response, body::Incoming, server::conn::http1, service::service_fn, Method};
use hyper::header::{HOST, CONNECTION, TRANSFER_ENCODING, UPGRADE, TE, TRAILER, HeaderName, HeaderValue};
use http_body_util::Full;
use bytes::Bytes;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tracing::{warn, trace};
use url::Url;

use totan_common::InterceptedConnection;

use tokio::io::{AsyncWriteExt, AsyncReadExt};
use tokio::net::TcpStream as TokioTcpStream;
use tokio::sync::Mutex;

/// Context shared by all requests on a single downstream connection.
pub struct HttpProxyContext {
    pub intercepted: InterceptedConnection,
    pub upstream_proxy: Url,
    pub hop_by_hop: Arc<HashSet<HeaderName>>,
    pub upstream_conn: Mutex<Option<TokioTcpStream>>, // persistent upstream connection
    pub upstream_buffer: Mutex<Vec<u8>>, // leftover bytes from previous response
}

impl HttpProxyContext {
    pub fn new(intercepted: InterceptedConnection, upstream_proxy_url: &str) -> Result<Arc<Self>> {
    let upstream_proxy = Url::parse(upstream_proxy_url)?;
    if upstream_proxy.scheme() != "http" {
            return Err(anyhow!("Phase 1 only supports http scheme upstream proxy"));
        }
        let hop_by_hop: HashSet<HeaderName> = [
            CONNECTION, TRANSFER_ENCODING, UPGRADE, TE, TRAILER,
        ].into_iter().collect();
    Ok(Arc::new(Self { intercepted, upstream_proxy, hop_by_hop: Arc::new(hop_by_hop), upstream_conn: Mutex::new(None), upstream_buffer: Mutex::new(Vec::new()) }))
    }
}

/// Serve one intercepted plain HTTP connection using hyper server.
pub async fn serve_http_connection(stream: TcpStream, ctx: Arc<HttpProxyContext>) -> Result<()> {
    let io = TokioIo::new(stream);
    http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(false)
        .serve_connection(io, service_fn(move |req| {
            let ctx = ctx.clone();
            async move { handle_request(req, ctx).await }
        }))
        .with_upgrades() // (future use for WebSocket, not yet implemented)
        .await
        .map_err(|e| anyhow!("hyper serve_connection error: {}", e))
}

async fn handle_request(req: Request<Incoming>, ctx: Arc<HttpProxyContext>) -> Result<Response<Full<Bytes>>> {
    trace!("Downstream request received: {:?} {:?}", req.method(), req.uri());
    // Method gate (Phase 1 extended: add POST)
    if !(matches!(req.method(), &Method::GET | &Method::HEAD | &Method::POST) || (req.method() == Method::OPTIONS && req.uri().path() == "*")) {
        return Ok(Response::builder().status(501).body(Full::new(Bytes::from_static(b"Not Implemented (GET/HEAD/POST/OPTIONS * only in Phase1)")))?);
    }

    // Determine host
    let mut host = req.headers().get(HOST).and_then(|v| v.to_str().ok()).map(|s| s.to_string());
    if host.is_none() {
        let ip_host = ctx.intercepted.original_dest.ip().to_string();
        let port = ctx.intercepted.original_dest.port();
        host = Some(if port == 80 { ip_host } else { format!("{}:{}", ip_host, port) });
    }
    let host_for_abs = host.clone().unwrap();

    // Build absolute-form URI (except OPTIONS *)
    let abs_uri = if req.method() == Method::OPTIONS && req.uri().path() == "*" {
        // Keep * form
        "*".to_string()
    } else {
        let path_q = req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/");
        format!("http://{}{}", host_for_abs, path_q)
    };
    trace!("Absolute-form target: {}", abs_uri);

    // Build upstream request
    // Collect and sanitize headers for upstream forwarding
    let mut upstream_headers: Vec<(HeaderName, HeaderValue)> = Vec::new();
    let mut content_length_header: Option<usize> = None;
    let mut _transfer_encoding_chunked = false; // reserved for future use
    for (name, value) in req.headers().iter() {
        if ctx.hop_by_hop.contains(name) { continue; }
    if name == HOST { continue; } // we'll force host
        if name == &hyper::header::CONTENT_LENGTH {
            if let Ok(vstr) = value.to_str() { if let Ok(n) = vstr.parse::<usize>() { content_length_header = Some(n); } }
            // skip for rebuild (we may recompute)
            continue;
        }
        if name == &hyper::header::TRANSFER_ENCODING {
            if let Ok(vstr) = value.to_str() { if vstr.to_ascii_lowercase().contains("chunked") { _transfer_encoding_chunked = true; } }
            continue; // we'll normalize to Content-Length after aggregation
        }
        upstream_headers.push((name.clone(), value.clone()));
    }
    // Always push Host header first
    upstream_headers.insert(0, (HOST, HeaderValue::from_str(host_for_abs.as_str()).unwrap()));

    // Aggregate body if needed (GET/HEAD typically empty, POST may have body)
    let mut body_bytes: Vec<u8> = Vec::new();
    let method_clone = req.method().clone();
    if method_clone == Method::POST {
        const MAX_BODY_SIZE: usize = 8 * 1024 * 1024; // 8MB limit
        let whole = http_body_util::BodyExt::collect(req.into_body()).await.map_err(|e| anyhow!("Body read error: {}", e))?;
        let collected = whole.to_bytes();
        if collected.len() > MAX_BODY_SIZE { return Ok(Response::builder().status(413).body(Full::new(Bytes::from_static(b"Payload Too Large")))?); }
        body_bytes.extend_from_slice(&collected);
        if let Some(cl) = content_length_header { if cl != body_bytes.len() { return Ok(Response::builder().status(400).body(Full::new(Bytes::from_static(b"Bad Request: Content-Length mismatch")))?); } }
        upstream_headers.push((hyper::header::CONTENT_LENGTH, HeaderValue::from_str(&body_bytes.len().to_string()).unwrap()));
    } else {
    if method_clone == Method::GET || method_clone == Method::HEAD { let _ = req.into_body(); }
    }

    // Execute upstream call
    // Manual upstream fetch
    match forward_upstream(ctx.clone(), &method_clone, abs_uri.as_str(), &upstream_headers, &body_bytes).await {
        Ok((status_line, headers, body_bytes)) => {
            // Parse status code
            let mut parts_iter = status_line.split_whitespace();
            let _http_ver = parts_iter.next().unwrap_or("HTTP/1.1");
            let code_str = parts_iter.next().unwrap_or("502");
            let code: u16 = code_str.parse().unwrap_or(502);
            let mut resp_builder = Response::builder().status(code);
            for (name, value) in headers.iter() {
                if ctx.hop_by_hop.contains(name) { continue; }
                resp_builder = resp_builder.header(name, value);
            }
            let resp = resp_builder.body(Full::new(body_bytes.into()))
                .unwrap_or_else(|_| Response::new(Full::new(Bytes::from_static(b"Internal error"))));
            Ok(resp)
        }
        Err(e) => {
            warn!("Upstream request error: {}", e);
            Ok(Response::builder().status(502).body(Full::new(Bytes::from_static(b"Bad Gateway")))?)
        }
    }
}

async fn forward_upstream(ctx: Arc<HttpProxyContext>, method: &Method, abs_uri: &str, headers: &[(HeaderName, HeaderValue)], body: &[u8]) -> Result<(String, Vec<(HeaderName, HeaderValue)>, Vec<u8>)> {
    // Get or establish persistent upstream connection.
    let host = ctx.upstream_proxy.host_str().unwrap_or("localhost");
    let port = ctx.upstream_proxy.port().unwrap_or(8080);
    let addr = format!("{}:{}", host, port);
    // Acquire stream (take ownership temporarily)
    let opt_stream = {
        let mut guard = ctx.upstream_conn.lock().await;
        if guard.is_none() {
            let s = TokioTcpStream::connect(&addr).await?;
            s.set_nodelay(true).ok();
            *guard = Some(s);
        }
        guard.take()
    };
    let mut stream = opt_stream.expect("stream just inserted");
    // Compose GET request with absolute-form already in abs_uri
    // Compose request line and headers
    let mut req_buf = Vec::with_capacity(1024 + body.len());
    req_buf.extend_from_slice(format!("{} {} HTTP/1.1\r\n", method.as_str(), abs_uri).as_bytes());
    let mut saw_conn = false;
    let mut saw_proxy_conn = false;
    for (name, value) in headers.iter() {
        if name == &CONNECTION { saw_conn = true; }
        if name.as_str().eq_ignore_ascii_case("proxy-connection") { saw_proxy_conn = true; }
        req_buf.extend_from_slice(name.as_str().as_bytes());
        req_buf.extend_from_slice(b": ");
        req_buf.extend_from_slice(value.as_bytes());
        req_buf.extend_from_slice(b"\r\n");
    }
    if !saw_conn { req_buf.extend_from_slice(b"Connection: keep-alive\r\n"); }
    if !saw_proxy_conn { req_buf.extend_from_slice(b"Proxy-Connection: keep-alive\r\n"); }
    req_buf.extend_from_slice(b"\r\n");
    if !body.is_empty() { req_buf.extend_from_slice(body); }
    if let Err(e) = stream.write_all(&req_buf).await { // reconnect once if write fails
        tracing::warn!("upstream write failed (will retry once): {}", e);
        stream = TokioTcpStream::connect(&addr).await?;
        stream.set_nodelay(true).ok();
        stream.write_all(&req_buf).await?;
    }
    stream.flush().await?;
    // Read headers (prepend any leftover from prior response)
    let mut leftover_guard = ctx.upstream_buffer.lock().await;
    let mut buf = std::mem::take(&mut *leftover_guard);
    if buf.capacity() < 4096 { buf.reserve(4096 - buf.capacity()); }
    let mut tmp = [0u8;1024];
    let status_line;
    let mut header_block_end = None;
    while header_block_end.is_none() {
        let n = stream.read(&mut tmp).await?;
        if n==0 { return Err(anyhow!("EOF before headers complete")); }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_double_crlf(&buf) { header_block_end = Some(pos); }
        if buf.len()> 64*1024 { return Err(anyhow!("Header too large")); }
    }
    let split_at = header_block_end.unwrap();
    let header_bytes = &buf[..split_at];
    let rest_initial = &buf[split_at..];
    let header_text = String::from_utf8_lossy(header_bytes);
    let mut lines = header_text.split("\r\n");
    status_line = lines.next().unwrap_or("").to_string();
    let mut headers: Vec<(HeaderName, HeaderValue)> = Vec::new();
    for line in lines {
        if line.is_empty() { break; }
        if let Some((name, value)) = line.split_once(':') {
            if let Ok(hn) = HeaderName::from_bytes(name.trim().as_bytes()) {
                if let Ok(hv) = HeaderValue::from_str(value.trim()) { headers.push((hn,hv)); }
            }
        }
    }
    // Body handling (Content-Length or chunked decoding)
    let mut body: Vec<u8>;
    let mut content_len: Option<usize> = headers.iter()
        .find(|(n,_)| n == &hyper::header::CONTENT_LENGTH)
        .and_then(|(_,v)| v.to_str().ok()?.parse::<usize>().ok());
    let is_chunked = headers.iter().any(|(n,_)| n == &hyper::header::TRANSFER_ENCODING && {
        headers.iter().find(|(n2,_)| n2 == &hyper::header::TRANSFER_ENCODING)
            .and_then(|(_,v)| v.to_str().ok())
            .map(|s| s.to_ascii_lowercase().contains("chunked"))
            .unwrap_or(false)
    });
    let mut final_headers: Vec<(HeaderName, HeaderValue)> = headers.iter().cloned().collect();
    if let Some(len) = content_len {
        body = Vec::with_capacity(len);
        // consume from rest_initial first
        if rest_initial.len() >= len {
            body.extend_from_slice(&rest_initial[..len]);
            // leftover bytes go back to buffer
            leftover_guard.extend_from_slice(&rest_initial[len..]);
        } else {
            body.extend_from_slice(rest_initial);
            while body.len() < len {
                let n = stream.read(&mut tmp).await?;
                if n == 0 { break; }
                let need = len - body.len();
                if n as usize <= need {
                    body.extend_from_slice(&tmp[..n]);
                } else {
                    body.extend_from_slice(&tmp[..need]);
                    leftover_guard.extend_from_slice(&tmp[need..n]);
                }
            }
        }
        body.truncate(len.min(body.len()));
    } else if is_chunked {
        // decode chunked with possible overflow into leftover_guard
        body = Vec::new();
        let mut chunk_buf: Vec<u8> = rest_initial.to_vec();
        let mut pos = 0usize;
        loop {
            let size_line_end = loop {
                if let Some(e) = find_crlf_from(&chunk_buf, pos) { break e; }
                let n = stream.read(&mut tmp).await?;
                if n == 0 { return Err(anyhow!("EOF before chunk size")); }
                chunk_buf.extend_from_slice(&tmp[..n]);
                if chunk_buf.len() > 32*1024*1024 { return Err(anyhow!("Chunked body exceeds limit")); }
            };
            let line = std::str::from_utf8(&chunk_buf[pos..size_line_end-2]).map_err(|_| anyhow!("Invalid UTF-8 in chunk size"))?;
            let size_hex = line.split(';').next().unwrap_or("").trim();
            let size = usize::from_str_radix(size_hex, 16).map_err(|_| anyhow!("Invalid chunk size"))?;
            pos = size_line_end;
            if size == 0 { // trailers
                loop {
                    if let Some(end_rel) = find_double_crlf(&chunk_buf[pos..]) { pos += end_rel; break; }
                    let n = stream.read(&mut tmp).await?;
                    if n == 0 { break; }
                    chunk_buf.extend_from_slice(&tmp[..n]);
                    if chunk_buf.len() > 32*1024*1024 { return Err(anyhow!("Chunked body exceeds limit")); }
                }
                if pos < chunk_buf.len() { leftover_guard.extend_from_slice(&chunk_buf[pos..]); }
                break;
            }
            while chunk_buf.len() < pos + size + 2 {
                let n = stream.read(&mut tmp).await?;
                if n == 0 { return Err(anyhow!("EOF mid chunk")); }
                chunk_buf.extend_from_slice(&tmp[..n]);
                if chunk_buf.len() > 32*1024*1024 { return Err(anyhow!("Chunked body exceeds limit")); }
            }
            body.extend_from_slice(&chunk_buf[pos .. pos+size]);
            pos += size + 2;
        }
        content_len = Some(body.len());
        // rebuild headers: remove TE & old CL, add new CL
        final_headers.retain(|(n,_)| n != &hyper::header::TRANSFER_ENCODING && n != &hyper::header::CONTENT_LENGTH);
        final_headers.push((hyper::header::CONTENT_LENGTH, HeaderValue::from_str(&body.len().to_string())?));
    // normalized (no longer treated as chunked after decoding)
    } else {
        // read-until-close (safety cap)
        const MAX_NO_LENGTH: usize = 8 * 1024 * 1024;
        body = rest_initial.to_vec();
        while body.len() < MAX_NO_LENGTH {
            let n = stream.read(&mut tmp).await?;
            if n == 0 { break; }
            body.extend_from_slice(&tmp[..n]);
        }
        content_len = Some(body.len());
        // ensure Content-Length is set for downstream
        final_headers.retain(|(n,_)| n != &hyper::header::CONTENT_LENGTH);
        final_headers.push((hyper::header::CONTENT_LENGTH, HeaderValue::from_str(&body.len().to_string())?));
    }
    let connection_close = final_headers.iter().any(|(n,v)| n == &CONNECTION && v.to_str().ok().map(|s| s.eq_ignore_ascii_case("close")).unwrap_or(false));
    let keep_connection = !connection_close && content_len.is_some();
    let headers: Vec<(HeaderName, HeaderValue)> = final_headers;
    // Verify body length vs Content-Length
    if let Some(cl) = content_len {
        if cl != body.len() {
            tracing::warn!("upstream content-length mismatch expected={} actual={} closing connection", cl, body.len());
        }
    }
    // Put back or drop
    let mut guard = ctx.upstream_conn.lock().await;
    if keep_connection { *guard = Some(stream); } else { *guard = None; leftover_guard.clear(); }
    Ok((status_line, headers, body))
}

fn find_double_crlf(buf:&[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w==b"\r\n\r\n").map(|p| p+4)
}

fn find_crlf_from(buf:&[u8], start: usize) -> Option<usize> {
    let mut i = start;
    while i + 1 < buf.len() {
        if buf[i] == b'\r' && buf[i+1] == b'\n' { return Some(i+2); }
        i += 1;
    }
    None
}


