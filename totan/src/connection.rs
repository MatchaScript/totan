use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use totan_common::{config::TotanConfig, InterceptedConnection, InterceptionMode};
use tracing::{debug, warn};

use crate::pac::PacEvaluator;
use crate::proxy::{proxies_from_url_str, Proxies};
use crate::upstream::UpstreamHandler;
use crate::utils::{extract_http_host, extract_sni_hostname};

enum ProxyResolver {
    Pac(Arc<PacEvaluator>),
    Fixed(Proxies),
}

impl ProxyResolver {
    async fn resolve(&self, url: &str, host: &str) -> Result<Proxies> {
        match self {
            Self::Pac(engine) => engine.find_proxy(url, host).await,
            Self::Fixed(proxies) => Ok(proxies.clone()),
        }
    }
}

pub struct ConnectionManager {
    resolver: ProxyResolver,
    upstream_handler: UpstreamHandler,
    handshake_timeout: std::time::Duration,
}

impl ConnectionManager {
    pub async fn new(config: TotanConfig) -> Result<Self> {
        // PAC takes precedence: if a PAC file is configured, default_proxy is
        // ignored (PAC scripts encode their own DIRECT fallback). Without PAC,
        // every connection is dispatched by the fixed default_proxy (or goes
        // DIRECT when that is also None).
        let resolver = if let Some(pac_file) = &config.pac_file {
            let engine = PacEvaluator::from_file(pac_file)
                .await?
                .with_cache(config.pac_cache_ttl_secs, config.pac_cache_max_entries);
            ProxyResolver::Pac(Arc::new(engine))
        } else if let Some(url) = config.default_proxy.as_deref() {
            let proxies = proxies_from_url_str(url).map_err(|e| {
                totan_common::TotanError::Config(format!("invalid default_proxy '{url}': {e}"))
            })?;
            ProxyResolver::Fixed(proxies)
        } else {
            ProxyResolver::Fixed(Proxies::direct())
        };

        // SO_MARK on upstream sockets prevents our own egress from being
        // re-intercepted. In netfilter mode the OUTPUT hook matches the fwmark
        // and returns early. In eBPF mode the tc-ingress path never sees our
        // egress, but the cgroup `connect4` host hook does — so when host hooks
        // are enabled we tag upstream sockets with the dedicated self-mark
        // (distinct from the fwmark, so it can't trigger policy routing) and
        // connect4 skips them. Without host hooks, no marking is needed.
        let upstream_mark = match config.interception_mode {
            InterceptionMode::Netfilter => config.netfilter.fwmark,
            #[cfg(feature = "ebpf")]
            InterceptionMode::Ebpf => {
                if config.ebpf.host_hooks.is_some() {
                    crate::cgroup::HOST_HOOK_SELF_MARK
                } else {
                    0
                }
            }
        };

        let upstream_handler = UpstreamHandler::new(
            config.timeouts.upstream_connect_ms,
            config.timeouts.handshake_ms,
            config.mitigation.clone(),
            upstream_mark,
        )?;

        Ok(Self {
            resolver,
            upstream_handler,
            handshake_timeout: std::time::Duration::from_millis(config.timeouts.handshake_ms),
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

        // For TLS connections, try to extract SNI hostname. Bound by the
        // handshake timeout so a client that connects to :443 and then stalls
        // can't pin this task forever.
        let sni_hostname = if original_dest.port() == 443 {
            tokio::time::timeout(self.handshake_timeout, extract_sni_hostname(&mut stream))
                .await
                .ok()
                .and_then(|r| r.ok())
        } else {
            None
        };

        // For plain HTTP, recover the intended hostname from the Host header so
        // PAC rules match on the domain rather than the bare destination IP.
        let http_host = if original_dest.port() != 443 {
            tokio::time::timeout(self.handshake_timeout, extract_http_host(&mut stream))
                .await
                .ok()
                .and_then(|r| r.ok())
        } else {
            None
        };

        let intercepted_conn = InterceptedConnection {
            client_addr,
            original_dest,
            sni_hostname: sni_hostname.clone(),
        };
        // Build a human-readable target URL for logging and PAC resolution.
        // Prefer the TLS SNI name, then the HTTP Host, then the bare IP.
        let hostname_for_url = sni_hostname
            .clone()
            .or_else(|| http_host.clone())
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

        let proxies = match self.resolver.resolve(&target_url, &hostname_for_url).await {
            Ok(p) => p,
            Err(e) => {
                warn!("proxy resolution failed ({e}); falling back to DIRECT");
                Proxies::direct()
            }
        };
        debug!("Upstream route: {}", proxies);

        self.upstream_handler
            .handle_connection(intercepted_conn, stream, proxies)
            .await
    }
}
