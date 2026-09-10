use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// Represents the intercepted connection information
#[derive(Debug, Clone)]
pub struct InterceptedConnection {
    pub client_addr: SocketAddr,
    pub original_dest: SocketAddr,
    pub sni_hostname: Option<String>,
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
