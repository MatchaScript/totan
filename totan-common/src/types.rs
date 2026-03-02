use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

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
#[derive(Default)]
pub enum InterceptionMode {
    #[default]
    Netfilter,
    #[cfg(feature = "ebpf")]
    Ebpf,
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
                } else {
                    s.strip_prefix("SOCKS5 ")
                        .map(|socks5| PacResult::Socks(socks5.trim().to_string()))
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pac_result_parse() {
        let input = "PROXY proxy.example.com:8080; SOCKS5 localhost:1080; DIRECT";
        let results = PacResult::parse(input);
        assert_eq!(results.len(), 3);
        assert_eq!(
            results[0],
            PacResult::Proxy("proxy.example.com:8080".to_string())
        );
        assert_eq!(results[1], PacResult::Socks("localhost:1080".to_string()));
        assert_eq!(results[2], PacResult::Direct);

        let input = "DIRECT;  INVALID; PROXY 1.2.3.4:80";
        let results = PacResult::parse(input);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0], PacResult::Direct);
        assert_eq!(results[1], PacResult::Proxy("1.2.3.4:80".to_string()));
    }
}
