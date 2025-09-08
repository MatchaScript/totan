use std::net::SocketAddr;
use serde::{Deserialize, Serialize};

/// Represents the intercepted connection information
#[derive(Debug, Clone)]
pub struct InterceptedConnection {
    pub client_addr: SocketAddr,
    pub original_dest: SocketAddr,
    pub sni_hostname: Option<String>,
}

/// Proxy mode enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InterceptionMode {
    Netfilter,
    #[cfg(feature = "ebpf")]
    Ebpf,
}

impl Default for InterceptionMode {
    fn default() -> Self {
        Self::Netfilter
    }
}

/// Upstream proxy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub url: url::Url,
    pub auth: Option<ProxyAuth>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyAuth {
    pub username: String,
    pub password: String,
}

/// PAC script result
#[derive(Debug, Clone, PartialEq)]
pub enum PacResult {
    Direct,
    Proxy(String),
    Socks(String),
}

impl PacResult {
    pub fn parse(pac_string: &str) -> Vec<Self> {
        pac_string
            .split(';')
            .filter_map(|s| {
                let s = s.trim();
                if s.is_empty() {
                    return None;
                }
                
                if s.eq_ignore_ascii_case("DIRECT") {
                    Some(PacResult::Direct)
                } else if let Some(proxy) = s.strip_prefix("PROXY ") {
                    Some(PacResult::Proxy(proxy.trim().to_string()))
                } else if let Some(socks) = s.strip_prefix("SOCKS ") {
                    Some(PacResult::Socks(socks.trim().to_string()))
                } else if let Some(socks5) = s.strip_prefix("SOCKS5 ") {
                    Some(PacResult::Socks(socks5.trim().to_string()))
                } else {
                    None
                }
            })
            .collect()
    }
}
