use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use totan_common::{config::TotanConfig, InterceptedConnection, InterceptionMode};
use tracing::debug;

use crate::pac::PacEngine;
use crate::upstream::UpstreamHandler;
use crate::utils::extract_sni_hostname;

enum ProxyResolver {
    Pac(Arc<PacEngine>),
    Fixed(Option<String>),
}

impl ProxyResolver {
    async fn resolve(&self, url: &str, host: &str) -> Result<Option<String>> {
        match self {
            Self::Pac(engine) => engine.find_proxy_for_url(url, host).await,
            Self::Fixed(proxy) => Ok(proxy.clone()),
        }
    }
}

pub struct ConnectionManager {
    resolver: ProxyResolver,
    upstream_handler: UpstreamHandler,
}

impl ConnectionManager {
    pub async fn new(config: TotanConfig) -> Result<Self> {
        // PAC takes precedence: if a PAC file is configured, default_proxy is
        // ignored (PAC scripts encode their own DIRECT fallback). Without PAC,
        // every connection is dispatched by the fixed default_proxy (or goes
        // DIRECT when that is also None).
        let resolver = if let Some(pac_file) = &config.pac_file {
            let engine = PacEngine::new(pac_file)
                .await?
                .with_cache(config.pac_cache_ttl_secs, config.pac_cache_max_entries);
            ProxyResolver::Pac(Arc::new(engine))
        } else {
            ProxyResolver::Fixed(config.default_proxy.clone())
        };

        // SO_MARK on upstream sockets is only needed in netfilter mode: the
        // OUTPUT hook would otherwise re-intercept the proxy's own connections.
        // In eBPF mode the interception is on ingress (tc hook), so upstream
        // connections are never redirected — and using the eBPF fwmark here
        // would accidentally match the policy-routing rule and route packets
        // to loopback.
        let upstream_mark = match config.interception_mode {
            InterceptionMode::Netfilter => config.netfilter.fwmark,
            #[cfg(feature = "ebpf")]
            InterceptionMode::Ebpf => 0,
        };

        let upstream_handler = UpstreamHandler::new(
            config.timeouts.upstream_connect_ms,
            config.mitigation.clone(),
            upstream_mark,
        )?;

        Ok(Self {
            resolver,
            upstream_handler,
        })
    }

    pub async fn handle_connection(
        &self,
        mut stream: TcpStream,
        client_addr: SocketAddr,
        original_dest: SocketAddr,
    ) -> Result<()> {
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

        let upstream_proxy = self
            .resolver
            .resolve(&target_url, &hostname_for_url)
            .await?;

        match &upstream_proxy {
            Some(p) => debug!("Upstream route: PROXY {}", p),
            None => debug!("Upstream route: DIRECT"),
        }

        self.upstream_handler
            .handle_connection(intercepted_conn, stream, upstream_proxy)
            .await
    }
}
