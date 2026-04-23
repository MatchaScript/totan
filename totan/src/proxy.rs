//! Typed `FindProxyForURL` return value: an ordered failover list of
//! `Proxy` / `Direct` entries. Parsed from the PAC string syntax
//! (`PROXY host:port; SOCKS5 host:port; DIRECT`) and consumed by the
//! upstream handler, which walks the list until one entry succeeds.

use std::fmt;
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProxyParseError {
    #[error("missing ':port' in host specification '{0}'")]
    MissingPort(String),
    #[error("invalid port in '{0}'")]
    InvalidPort(String),
    #[error("empty host in '{0}'")]
    EmptyHost(String),
    #[error("unknown directive '{0}', expected DIRECT, PROXY, HTTP, SOCKS, or SOCKS5")]
    UnknownDirective(String),
    #[error("empty proxy list")]
    Empty,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HostAndPort {
    host: String,
    port: u16,
}

impl HostAndPort {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

impl fmt::Display for HostAndPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // IPv6 literals need bracketing so "::1:8080" parses back round-trip.
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

impl FromStr for HostAndPort {
    type Err = ProxyParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let raw = s.trim();
        // "[ipv6]:port" form
        if let Some(rest) = raw.strip_prefix('[') {
            let (host, tail) = rest
                .split_once(']')
                .ok_or_else(|| ProxyParseError::MissingPort(raw.to_string()))?;
            let port_str = tail
                .strip_prefix(':')
                .ok_or_else(|| ProxyParseError::MissingPort(raw.to_string()))?;
            let port: u16 = port_str
                .parse()
                .map_err(|_| ProxyParseError::InvalidPort(raw.to_string()))?;
            if host.is_empty() {
                return Err(ProxyParseError::EmptyHost(raw.to_string()));
            }
            return Ok(Self::new(host, port));
        }
        // "host:port" / "ipv4:port"
        let (host, port_str) = raw
            .rsplit_once(':')
            .ok_or_else(|| ProxyParseError::MissingPort(raw.to_string()))?;
        if host.is_empty() {
            return Err(ProxyParseError::EmptyHost(raw.to_string()));
        }
        let port: u16 = port_str
            .parse()
            .map_err(|_| ProxyParseError::InvalidPort(raw.to_string()))?;
        Ok(Self::new(host, port))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Proxy {
    Http(HostAndPort),
    Socks5(HostAndPort),
}

impl Proxy {
    pub fn endpoint(&self) -> &HostAndPort {
        match self {
            Self::Http(e) | Self::Socks5(e) => e,
        }
    }
}

impl fmt::Display for Proxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http(ep) => write!(f, "HTTP {}", ep),
            Self::Socks5(ep) => write!(f, "SOCKS5 {}", ep),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ProxyOrDirect {
    Direct,
    Proxy(Proxy),
}

impl fmt::Display for ProxyOrDirect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Direct => f.write_str("DIRECT"),
            Self::Proxy(p) => p.fmt(f),
        }
    }
}

impl FromStr for ProxyOrDirect {
    type Err = ProxyParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        if trimmed.eq_ignore_ascii_case("DIRECT") {
            return Ok(Self::Direct);
        }
        // PAC directives: case-insensitive keyword, then whitespace, then host:port.
        let (kw, rest) = trimmed
            .split_once(|c: char| c.is_ascii_whitespace())
            .ok_or_else(|| ProxyParseError::UnknownDirective(trimmed.to_string()))?;
        let endpoint: HostAndPort = rest.trim().parse()?;
        let kw_upper = kw.to_ascii_uppercase();
        match kw_upper.as_str() {
            // `PROXY` and `HTTP` are interchangeable aliases for an HTTP proxy.
            "PROXY" | "HTTP" => Ok(Self::Proxy(Proxy::Http(endpoint))),
            // HTTPS (TLS to the proxy itself) isn't implemented yet — fall back
            // to plain HTTP semantics. Swap for a dedicated variant when added.
            "HTTPS" => Ok(Self::Proxy(Proxy::Http(endpoint))),
            "SOCKS" | "SOCKS5" => Ok(Self::Proxy(Proxy::Socks5(endpoint))),
            _ => Err(ProxyParseError::UnknownDirective(kw.to_string())),
        }
    }
}

/// Ordered failover list returned by PAC / derived from `default_proxy`.
///
/// At least one entry is guaranteed on construction (the `FromStr` impl rejects
/// empty input), so iteration always yields progress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proxies(Vec<ProxyOrDirect>);

impl Proxies {
    pub fn new(entries: Vec<ProxyOrDirect>) -> Self {
        Self(entries)
    }

    pub fn direct() -> Self {
        Self(vec![ProxyOrDirect::Direct])
    }

    pub fn iter(&self) -> std::slice::Iter<'_, ProxyOrDirect> {
        self.0.iter()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn first(&self) -> &ProxyOrDirect {
        // `Proxies` constructors never produce an empty list.
        self.0.first().expect("Proxies is never empty")
    }
}

impl IntoIterator for Proxies {
    type Item = ProxyOrDirect;
    type IntoIter = std::vec::IntoIter<ProxyOrDirect>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a Proxies {
    type Item = &'a ProxyOrDirect;
    type IntoIter = std::slice::Iter<'a, ProxyOrDirect>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl fmt::Display for Proxies {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, entry) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str("; ")?;
            }
            entry.fmt(f)?;
        }
        Ok(())
    }
}

impl FromStr for Proxies {
    type Err = ProxyParseError;

    /// Parse the PAC "FindProxyForURL" return string.
    ///
    /// Unknown directives are dropped (a misconfigured PAC entry shouldn't
    /// take down the whole chain — mirrors browser behaviour). An empty
    /// post-filter list is an error.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let entries: Vec<ProxyOrDirect> = s
            .split(';')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .filter_map(|s| s.parse::<ProxyOrDirect>().ok())
            .collect();
        if entries.is_empty() {
            Err(ProxyParseError::Empty)
        } else {
            Ok(Self(entries))
        }
    }
}

/// Build a `Proxies` with a single entry from a URL-shaped configuration
/// value like `http://proxy:3128` or `socks5://127.0.0.1:1080`.
pub fn proxies_from_url_str(url_str: &str) -> Result<Proxies, ProxyParseError> {
    let url = url::Url::parse(url_str)
        .map_err(|_| ProxyParseError::UnknownDirective(url_str.to_string()))?;
    let host = url
        .host_str()
        .ok_or_else(|| ProxyParseError::EmptyHost(url_str.to_string()))?;
    let scheme = url.scheme();
    let default_port = match scheme {
        "http" | "https" => 80,
        "socks5" | "socks" => 1080,
        _ => return Err(ProxyParseError::UnknownDirective(scheme.to_string())),
    };
    let port = url.port().unwrap_or(default_port);
    let endpoint = HostAndPort::new(host, port);
    let proxy = match scheme {
        "http" | "https" => Proxy::Http(endpoint),
        "socks5" | "socks" => Proxy::Socks5(endpoint),
        _ => return Err(ProxyParseError::UnknownDirective(scheme.to_string())),
    };
    Ok(Proxies::new(vec![ProxyOrDirect::Proxy(proxy)]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_single_direct() {
        let p: Proxies = "DIRECT".parse().unwrap();
        assert_eq!(p, Proxies::direct());
    }

    #[test]
    fn parse_proxy_aliases() {
        let cases = [
            "PROXY 127.0.0.1:3128",
            "HTTP 127.0.0.1:3128",
            "proxy  127.0.0.1:3128",
        ];
        for c in cases {
            let p: Proxies = c.parse().unwrap();
            assert_eq!(p.len(), 1);
            assert_eq!(
                p.first(),
                &ProxyOrDirect::Proxy(Proxy::Http("127.0.0.1:3128".parse().unwrap()))
            );
        }
    }

    #[test]
    fn parse_socks_aliases() {
        for kw in ["SOCKS", "SOCKS5"] {
            let p: Proxies = format!("{kw} 127.0.0.1:1080").parse().unwrap();
            assert_eq!(
                p.first(),
                &ProxyOrDirect::Proxy(Proxy::Socks5("127.0.0.1:1080".parse().unwrap()))
            );
        }
    }

    #[test]
    fn parse_failover_list() {
        let p: Proxies = "PROXY a:8080; SOCKS5 b:1080; DIRECT".parse().unwrap();
        let entries: Vec<_> = p.iter().cloned().collect();
        assert_eq!(
            entries,
            vec![
                ProxyOrDirect::Proxy(Proxy::Http("a:8080".parse().unwrap())),
                ProxyOrDirect::Proxy(Proxy::Socks5("b:1080".parse().unwrap())),
                ProxyOrDirect::Direct,
            ]
        );
    }

    #[test]
    fn unknown_entries_skipped_not_fatal() {
        // Browsers tolerate garbage entries as long as something parses.
        let p: Proxies = "FROB nope; PROXY good:80".parse().unwrap();
        assert_eq!(p.len(), 1);
        assert_eq!(
            p.first(),
            &ProxyOrDirect::Proxy(Proxy::Http("good:80".parse().unwrap()))
        );
    }

    #[test]
    fn empty_or_all_bad_is_error() {
        assert_eq!("".parse::<Proxies>(), Err(ProxyParseError::Empty));
        assert_eq!(";  ;".parse::<Proxies>(), Err(ProxyParseError::Empty));
        assert_eq!(
            "FROB nope; MEH".parse::<Proxies>(),
            Err(ProxyParseError::Empty)
        );
    }

    #[test]
    fn ipv6_endpoint_roundtrip() {
        let ep: HostAndPort = "[::1]:8080".parse().unwrap();
        assert_eq!(ep.host(), "::1");
        assert_eq!(ep.port(), 8080);
        assert_eq!(ep.to_string(), "[::1]:8080");
    }

    #[test]
    fn display_roundtrip() {
        let p: Proxies = "PROXY a:80; SOCKS5 b:1080; DIRECT".parse().unwrap();
        assert_eq!(p.to_string(), "HTTP a:80; SOCKS5 b:1080; DIRECT");
    }

    #[test]
    fn url_style_default_proxy() {
        let p = proxies_from_url_str("http://127.0.0.1:3128").unwrap();
        assert_eq!(
            p.first(),
            &ProxyOrDirect::Proxy(Proxy::Http("127.0.0.1:3128".parse().unwrap()))
        );
        let p = proxies_from_url_str("socks5://127.0.0.1:1080").unwrap();
        assert_eq!(
            p.first(),
            &ProxyOrDirect::Proxy(Proxy::Socks5("127.0.0.1:1080".parse().unwrap()))
        );
    }
}
