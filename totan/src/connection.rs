use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;
use totan_common::{config::TotanConfig, InterceptedConnection};
use tracing::{debug, warn};

use crate::pac::PacEvaluator;
use crate::proxy::{proxies_from_url_str, Proxies};
use crate::upstream::UpstreamHandler;
use crate::utils::{
    extract_http_host, extract_sni_hostname, format_authority_with_default,
    socket_authority_with_default,
};

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
    try_direct_on_proxy_failure: bool,
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

        // Mark totan's own outbound sockets so `cgroup/connect4` recognises and
        // skips them. This value must not match any policy-routing rule.
        let upstream_mark = crate::ebpf::DEFAULT_SELF_MARK;

        let upstream_handler = UpstreamHandler::new(
            config.timeouts.upstream_connect_ms,
            config.timeouts.handshake_ms,
            config.mitigation.clone(),
            upstream_mark,
        )?
        .with_client_idle_timeout(config.timeouts.client_idle_secs);

        Ok(Self {
            resolver,
            upstream_handler,
            handshake_timeout: std::time::Duration::from_millis(config.timeouts.handshake_ms),
            try_direct_on_proxy_failure: config.mitigation.try_direct_on_proxy_failure,
        })
    }

    async fn resolve_proxies(&self, target_url: &str, host: &str) -> Result<Proxies> {
        match self.resolver.resolve(target_url, host).await {
            Ok(proxies) => Ok(proxies),
            Err(error) if self.try_direct_on_proxy_failure => {
                warn!("proxy resolution failed ({error}); falling back to DIRECT by configuration");
                Ok(Proxies::direct())
            }
            Err(error) => Err(error
                .context("proxy resolution failed and try_direct_on_proxy_failure is disabled")),
        }
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
        let authority = if sni_hostname.is_some() || http_host.is_some() {
            format_authority_with_default(
                &hostname_for_url,
                intercepted_conn.original_dest.port(),
                default_port,
            )
        } else {
            socket_authority_with_default(intercepted_conn.original_dest, default_port)
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

        let proxies = self.resolve_proxies(&target_url, &hostname_for_url).await?;
        debug!("Upstream route: {}", proxies);

        self.upstream_handler
            .handle_connection(intercepted_conn, stream, proxies)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    async fn manager_with_failing_pac(allow_direct: bool) -> ConnectionManager {
        let mut pac = tempfile::NamedTempFile::new().unwrap();
        pac.write_all(
            br#"function FindProxyForURL(url, host) { throw new Error("evaluation failed"); }"#,
        )
        .unwrap();
        let mut config = TotanConfig {
            pac_file: Some(pac.path().to_path_buf()),
            ..TotanConfig::default()
        };
        config.mitigation.try_direct_on_proxy_failure = allow_direct;
        ConnectionManager::new(config).await.unwrap()
    }

    #[tokio::test]
    async fn pac_failure_is_fail_closed_when_direct_fallback_is_disabled() {
        let manager = manager_with_failing_pac(false).await;
        assert!(manager
            .resolve_proxies("https://example.com/", "example.com")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn pac_failure_uses_direct_only_when_enabled() {
        let manager = manager_with_failing_pac(true).await;
        assert_eq!(
            manager
                .resolve_proxies("https://example.com/", "example.com")
                .await
                .unwrap(),
            Proxies::direct()
        );
    }
}
