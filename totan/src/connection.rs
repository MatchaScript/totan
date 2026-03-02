use anyhow::Result;
use std::net::{SocketAddr, SocketAddrV4};
use std::sync::Arc;
use tokio::net::TcpStream;
use totan_common::{config::TotanConfig, InterceptedConnection};
use tracing::debug;

use crate::http_proxy::{serve_http_connection, HttpProxyContext};
use crate::pac::PacEngine;
use crate::upstream::UpstreamHandler;
use crate::utils::extract_sni_hostname;

pub struct ConnectionManager {
    config: TotanConfig,
    pac_engine: Option<Arc<PacEngine>>,
    upstream_handler: UpstreamHandler,
}

impl ConnectionManager {
    pub async fn new(config: TotanConfig) -> Result<Self> {
        // Initialize PAC engine if PAC file is specified
        let pac_engine = if let Some(pac_file) = &config.pac_file {
            let engine = PacEngine::new(pac_file)
                .await?
                .with_cache(config.pac_cache_ttl_secs, config.pac_cache_max_entries);
            Some(Arc::new(engine))
        } else {
            None
        };

        let upstream_handler = UpstreamHandler::new(
            config.default_proxy.clone(),
            config.timeouts.upstream_connect_ms,
            config.mitigation.clone(),
        )?;

        Ok(Self {
            config,
            pac_engine,
            upstream_handler,
        })
    }

    pub async fn handle_connection(
        &self,
        mut stream: TcpStream,
        client_addr: SocketAddr,
    ) -> Result<()> {
        // Get original destination from SO_ORIGINAL_DST
        let original_dest = get_original_destination(&stream)?;

        debug!(
            "Intercepted connection: {} -> {} (original: {})",
            client_addr,
            stream.local_addr()?,
            original_dest
        );

        // For TLS connections, try to extract SNI hostname
        let sni_hostname = if original_dest.port() == 443 {
            extract_sni_hostname(&mut stream).await.ok()
        } else {
            None
        };

        let intercepted_conn = InterceptedConnection {
            client_addr,
            original_dest,
            sni_hostname: sni_hostname.clone(),
        };
        // Build a human-readable target URL for logging and PAC resolution
        let hostname_for_url = sni_hostname
            .clone()
            .unwrap_or_else(|| intercepted_conn.original_dest.ip().to_string());
        let scheme = if intercepted_conn.original_dest.port() == 443 {
            "https"
        } else {
            "http"
        };
        let default_port = if scheme == "https" { 443 } else { 80 };
        let authority = if intercepted_conn.original_dest.port() == default_port {
            hostname_for_url.clone()
        } else {
            format!(
                "{}:{}",
                hostname_for_url,
                intercepted_conn.original_dest.port()
            )
        };
        let target_url = format!("{}://{}/", scheme, authority);

        debug!(
            "Target URL candidate: {}{}",
            target_url,
            sni_hostname
                .as_ref()
                .map(|s| format!(" (SNI: {})", s))
                .unwrap_or_default()
        );

        // Determine upstream proxy using PAC engine or default proxy
        let upstream_proxy = if let Some(pac_engine) = &self.pac_engine {
            pac_engine
                .find_proxy_for_url(&target_url, &hostname_for_url)
                .await?
        } else {
            self.config.default_proxy.clone()
        };

        match &upstream_proxy {
            Some(p) => debug!("Upstream route: PROXY {}", p),
            None => debug!("Upstream route: DIRECT"),
        }

        // Experimental Pingora-based HTTP pipeline branch (plain HTTP only)
        if self.config.experimental_hyper_http && upstream_proxy.is_some() {
            if let Some(proxy_url) = &upstream_proxy {
                match HttpProxyContext::new(intercepted_conn.clone(), proxy_url) {
                    Ok(ctx) => {
                        return serve_http_connection(stream, ctx).await;
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to init Pingora HTTP context: {} (falling back to legacy path)",
                            e
                        );
                    }
                }
            }
        }

        // Handle the connection through upstream handler
        self.upstream_handler
            .handle_connection(
                intercepted_conn,
                stream,
                upstream_proxy,
                // If PAC is configured, do not fall back to default proxy when it says DIRECT
                self.pac_engine.is_none(),
            )
            .await
    }
}

fn get_original_destination(stream: &TcpStream) -> Result<SocketAddr> {
    #[cfg(target_os = "linux")]
    {
        use nix::sys::socket::{getsockopt, sockopt::OriginalDst};
        use std::os::fd::BorrowedFd;
        use std::os::unix::io::AsRawFd;

        let fd = stream.as_raw_fd();
        let borrowed_fd = unsafe { BorrowedFd::borrow_raw(fd) };
        let orig_dst = getsockopt(&borrowed_fd, OriginalDst)?;
        let addr = SocketAddrV4::new(
            std::net::Ipv4Addr::from(orig_dst.sin_addr.s_addr.to_be()),
            orig_dst.sin_port.to_be(),
        );
        Ok(SocketAddr::V4(addr))
    }

    #[cfg(not(target_os = "linux"))]
    {
        // Fallback for non-Linux platforms
        // This won't work for transparent proxying, but prevents compilation errors
        stream
            .peer_addr()
            .map_err(|e| anyhow::anyhow!("Cannot get original destination: {}", e))
    }
}
