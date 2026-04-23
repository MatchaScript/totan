use anyhow::Result;
use boa_engine::{Context, Source};
use lru::LruCache;
use std::{
    num::NonZeroUsize,
    path::Path,
    sync::Mutex,
    time::{Duration, Instant},
};
use tokio::fs;
use tokio::time::timeout;
use totan_common::{PacResult, TotanError};
use tracing::{debug, info};

pub struct PacEngine {
    script_content: String,
    cache: Mutex<PacCache>,
    pac_timeout: Duration,
}

struct PacCache {
    ttl: Duration,
    lru: LruCache<(String, String), (Instant, Option<String>)>,
}

impl PacEngine {
    pub async fn new(pac_file: &Path) -> Result<Self> {
        let script_content = fs::read_to_string(pac_file).await?;
        info!("Loaded PAC file: {}", pac_file.display());

        let mut context = Context::default();
        let source = Source::from_bytes(&script_content);
        context
            .eval(source)
            .map_err(|e| TotanError::PacScript(format!("PAC script validation failed: {}", e)))?;

        let cache = PacCache {
            ttl: Duration::from_secs(60),
            lru: LruCache::new(NonZeroUsize::new(4096).unwrap()),
        };
        Ok(Self {
            script_content,
            cache: Mutex::new(cache),
            pac_timeout: Duration::from_secs(30),
        })
    }

    pub fn with_cache(self, ttl_secs: u64, max_entries: usize) -> Self {
        let mut guard = self.cache.lock().unwrap();
        guard.ttl = Duration::from_secs(ttl_secs);
        guard.lru.resize(NonZeroUsize::new(max_entries.max(1)).unwrap());
        drop(guard);
        self
    }

    pub fn with_pac_timeout(mut self, secs: u64) -> Self {
        self.pac_timeout = Duration::from_secs(secs);
        self
    }

    pub async fn find_proxy_for_url(&self, url: &str, host: &str) -> Result<Option<String>> {
        let key = (url.to_string(), host.to_string());
        let now = Instant::now();

        // Check cache
        if let Some(hit) = {
            let mut guard = self.cache.lock().unwrap();
            if guard.ttl.as_secs() > 0 {
                let cached = guard.lru.peek(&key).map(|(ts, val)| (*ts, val.clone()));
                match cached {
                    Some((ts, val)) if now.duration_since(ts) <= guard.ttl => {
                        guard.lru.get(&key); // promote to MRU
                        debug!("PAC cache hit: {} (host: {})", url, host);
                        Some(val)
                    }
                    Some(_) => {
                        guard.lru.pop(&key);
                        None
                    }
                    None => None,
                }
            } else {
                None
            }
        } {
            return Ok(hit);
        }

        let script_content = self.script_content.clone();
        let url_val = url.to_string();
        let host_val = host.to_string();

        let join_result = timeout(self.pac_timeout, tokio::task::spawn_blocking(move || -> Result<String> {
            let mut context = Context::default();

            Self::register_helpers(&mut context)?;

            let source = Source::from_bytes(&script_content);
            context.eval(source).map_err(|e| {
                TotanError::PacScript(format!("PAC script evaluation failed: {}", e))
            })?;

            let find_proxy = context
                .global_object()
                .get(boa_engine::JsString::from("FindProxyForURL"), &mut context)
                .map_err(|e| {
                    TotanError::PacScript(format!("Failed to get FindProxyForURL: {}", e))
                })?;

            if !find_proxy.is_callable() {
                return Err(
                    TotanError::PacScript("FindProxyForURL is not a function".to_string()).into(),
                );
            }

            let args = [
                boa_engine::value::JsValue::from(boa_engine::JsString::from(url_val)),
                boa_engine::value::JsValue::from(boa_engine::JsString::from(host_val)),
            ];

            let result_val = find_proxy
                .as_callable()
                .unwrap()
                .call(
                    &boa_engine::value::JsValue::undefined(),
                    &args,
                    &mut context,
                )
                .map_err(|e| {
                    TotanError::PacScript(format!("FindProxyForURL call failed: {}", e))
                })?;

            let result_str = result_val.to_string(&mut context).map_err(|e| {
                TotanError::PacScript(format!("Failed to convert PAC result to string: {}", e))
            })?;

            Ok(result_str.to_std_string_escaped())
        }))
        .await
        .map_err(|_| anyhow::anyhow!("PAC script execution timed out"))?;
        let result = join_result??;

        debug!("PAC result for {} ({}): {}", url, host, result);

        let pac_results = PacResult::parse(&result);
        let computed = pac_results
            .into_iter()
            .map(|pac_result| match pac_result {
                PacResult::Direct => None,
                PacResult::Proxy(proxy) => Some(format!("http://{}", proxy)),
                PacResult::Socks(socks) => Some(format!("socks5://{}", socks)),
            })
            .next()
            .flatten();

        {
            let mut guard = self.cache.lock().unwrap();
            if guard.ttl.as_secs() > 0 {
                guard.lru.put(key, (now, computed.clone()));
            }
        }

        Ok(computed)
    }

    fn register_helpers(context: &mut Context) -> Result<()> {
        use boa_engine::native_function::NativeFunction;
        use std::net::ToSocketAddrs;

        fn dns_resolve_binding(
            _this: &boa_engine::JsValue,
            args: &[boa_engine::JsValue],
            _context: &mut Context,
        ) -> boa_engine::JsResult<boa_engine::JsValue> {
            let host = args
                .first()
                .and_then(|v| v.as_string())
                .map(|s| s.to_std_string_escaped())
                .unwrap_or_default();
            let resolved = format!("{}:80", host)
                .to_socket_addrs()
                .ok()
                .and_then(|mut iter| iter.next())
                .map(|addr| addr.ip().to_string());

            Ok(match resolved {
                Some(ip) => boa_engine::JsValue::from(boa_engine::JsString::from(ip)),
                None => boa_engine::JsValue::null(),
            })
        }

        fn my_ip_address_binding(
            _this: &boa_engine::JsValue,
            _args: &[boa_engine::JsValue],
            _context: &mut Context,
        ) -> boa_engine::JsResult<boa_engine::JsValue> {
            // Use a UDP connect (no packets sent) to discover the outbound local IP
            use std::net::UdpSocket;
            let ip = UdpSocket::bind("0.0.0.0:0")
                .ok()
                .and_then(|sock| {
                    sock.connect("8.8.8.8:80").ok()?;
                    sock.local_addr().ok()
                })
                .map(|addr| addr.ip().to_string())
                .unwrap_or_else(|| "127.0.0.1".to_string());
            Ok(boa_engine::JsValue::from(boa_engine::JsString::from(ip)))
        }

        context
            .register_global_builtin_callable(
                "dnsResolve".into(),
                1,
                NativeFunction::from_fn_ptr(dns_resolve_binding),
            )
            .map_err(|e| TotanError::PacScript(format!("Failed to register dnsResolve: {}", e)))?;

        context
            .register_global_builtin_callable(
                "myIpAddress".into(),
                0,
                NativeFunction::from_fn_ptr(my_ip_address_binding),
            )
            .map_err(|e| TotanError::PacScript(format!("Failed to register myIpAddress: {}", e)))?;

        const JS_HELPERS: &str = r#"
            function isPlainHostName(h) { return h.indexOf('.') === -1; }
            function dnsDomainIs(h, d) { if (!h || !d) return false; return h === d || h.endsWith('.' + d); }
            function localHostOrDomainIs(h, d) { return h === d || h.startsWith(d + "."); }
            function isResolvable(h) { return dnsResolve(h) !== null; }
            function dnsDomainLevels(h) { return h.split('.').length - 1; }
            function shExpMatch(str, shexp) {
                var re = new RegExp('^' + shexp
                    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
                    .replace(/\*/g, '.*')
                    .replace(/\?/g, '.')
                    + '$');
                return re.test(str);
            }
            function isInNet(h, pattern, mask) {
                var ip = dnsResolve(h);
                if (!ip) return false;
                function toIpInt(ip_str) {
                    var p = ip_str.split('.').map(Number);
                    if (p.length !== 4 || p.some(isNaN)) return null;
                    return ((p[0] << 24) >>> 0) | ((p[1] << 16) >>> 0) | ((p[2] << 8) >>> 0) | (p[3] >>> 0);
                }
                var hip = toIpInt(ip);
                var pat = toIpInt(pattern);
                var m = toIpInt(mask);
                if (hip === null || pat === null || m === null) return false;
                return (hip & m) === (pat & m);
            }
        "#;
        context
            .eval(Source::from_bytes(JS_HELPERS))
            .map_err(|e| TotanError::PacScript(format!("Failed to evaluate JS helpers: {}", e)))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_pac_engine() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(
            r#"
            function FindProxyForURL(url, host) {
                if (host === "example.com") {
                    return "PROXY proxy.example.com:8080";
                }
                if (host === "google.com") {
                    return "SOCKS5 127.0.0.1:1080; DIRECT";
                }
                return "DIRECT";
            }
        "#
            .as_bytes(),
        )
        .unwrap();

        let engine = PacEngine::new(file.path()).await.unwrap();

        let res = engine
            .find_proxy_for_url("http://example.com/", "example.com")
            .await
            .unwrap();
        assert_eq!(res, Some("http://proxy.example.com:8080".to_string()));

        let res = engine
            .find_proxy_for_url("http://google.com/", "google.com")
            .await
            .unwrap();
        assert_eq!(res, Some("socks5://127.0.0.1:1080".to_string()));

        let res = engine
            .find_proxy_for_url("http://other.com/", "other.com")
            .await
            .unwrap();
        assert_eq!(res, None);
    }
    #[tokio::test]
    async fn test_pac_engine_cache() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(
            r#"
            function FindProxyForURL(url, host) {
                return "PROXY " + host + ":8080";
            }
        "#
            .as_bytes(),
        )
        .unwrap();

        let engine = PacEngine::new(file.path())
            .await
            .unwrap()
            .with_cache(60, 10);

        let res1 = engine
            .find_proxy_for_url("http://a.com/", "a.com")
            .await
            .unwrap();
        assert_eq!(res1, Some("http://a.com:8080".to_string()));

        let res2 = engine
            .find_proxy_for_url("http://a.com/", "a.com")
            .await
            .unwrap();
        assert_eq!(res2, Some("http://a.com:8080".to_string()));
    }

    // ── Enterprise PAC scenarios ──────────────────────────────────────────────

    /// Teams / O365 / SharePoint style split-tunneling: cloud collaboration
    /// endpoints go DIRECT while everything else is proxied. This is the most
    /// common enterprise breakout pattern.
    #[tokio::test]
    async fn test_pac_direct_breakout_teams_style() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(
            r#"
            function FindProxyForURL(url, host) {
                // Real enterprise PAC must match both apex and subdomains.
                if (host === "teams.microsoft.com" ||
                    shExpMatch(host, "*.teams.microsoft.com") ||
                    shExpMatch(host, "*.office365.com") ||
                    host === "login.microsoftonline.com" ||
                    shExpMatch(host, "*.sharepoint.com")) {
                    return "DIRECT";
                }
                return "PROXY 127.0.0.1:8080";
            }
        "#
            .as_bytes(),
        )
        .unwrap();

        let engine = PacEngine::new(file.path()).await.unwrap();

        // Cloud collaboration → DIRECT (None)
        for (url, host) in [
            ("https://teams.microsoft.com/", "teams.microsoft.com"),
            ("https://join.teams.microsoft.com/", "join.teams.microsoft.com"),
            ("https://contoso.sharepoint.com/", "contoso.sharepoint.com"),
            ("https://login.microsoftonline.com/", "login.microsoftonline.com"),
            ("https://outlook.office365.com/", "outlook.office365.com"),
        ] {
            assert_eq!(
                engine.find_proxy_for_url(url, host).await.unwrap(),
                None,
                "{host} should be DIRECT"
            );
        }

        // Everything else → proxy
        assert_eq!(
            engine
                .find_proxy_for_url("https://example.com/", "example.com")
                .await
                .unwrap(),
            Some("http://127.0.0.1:8080".to_string())
        );
    }

    /// Region-based multi-proxy routing: APAC, EU, and default proxy tiers.
    #[tokio::test]
    async fn test_pac_multi_proxy_by_region() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(
            r#"
            function FindProxyForURL(url, host) {
                if (shExpMatch(host, "*.jp") || shExpMatch(host, "*.cn") ||
                    shExpMatch(host, "*.au") || shExpMatch(host, "*.sg")) {
                    return "PROXY 127.0.0.1:8882";
                }
                if (shExpMatch(host, "*.de") || shExpMatch(host, "*.fr") ||
                    shExpMatch(host, "*.uk") || shExpMatch(host, "*.nl")) {
                    return "PROXY 127.0.0.1:8881";
                }
                return "PROXY 127.0.0.1:8880";
            }
        "#
            .as_bytes(),
        )
        .unwrap();

        let engine = PacEngine::new(file.path()).await.unwrap();

        let cases = [
            ("https://example.jp/", "example.jp", "http://127.0.0.1:8882"),
            ("https://example.cn/", "example.cn", "http://127.0.0.1:8882"),
            ("https://example.au/", "example.au", "http://127.0.0.1:8882"),
            ("https://example.de/", "example.de", "http://127.0.0.1:8881"),
            ("https://example.fr/", "example.fr", "http://127.0.0.1:8881"),
            ("https://example.com/", "example.com", "http://127.0.0.1:8880"),
            ("https://example.org/", "example.org", "http://127.0.0.1:8880"),
        ];
        for (url, host, expected_proxy) in cases {
            assert_eq!(
                engine.find_proxy_for_url(url, host).await.unwrap(),
                Some(expected_proxy.to_string()),
                "{host} should use {expected_proxy}"
            );
        }
    }

    /// DIRECT results (None) must be cached the same as proxy results.
    #[tokio::test]
    async fn test_pac_direct_result_is_cached() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(
            r#"
            function FindProxyForURL(url, host) {
                if (shExpMatch(host, "*.direct.internal")) return "DIRECT";
                return "PROXY 127.0.0.1:8080";
            }
        "#
            .as_bytes(),
        )
        .unwrap();

        let engine = PacEngine::new(file.path())
            .await
            .unwrap()
            .with_cache(60, 100);

        let r1 = engine
            .find_proxy_for_url("https://svc.direct.internal/", "svc.direct.internal")
            .await
            .unwrap();
        assert_eq!(r1, None);

        // Second call must hit the cache and return the same DIRECT decision.
        let r2 = engine
            .find_proxy_for_url("https://svc.direct.internal/", "svc.direct.internal")
            .await
            .unwrap();
        assert_eq!(r2, None);
    }

    /// Mixed DIRECT + proxied traffic in the same session — the cache key is
    /// a (url, host) tuple so distinct hosts must not share cache entries.
    #[tokio::test]
    async fn test_pac_cache_key_isolation() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(
            r#"
            function FindProxyForURL(url, host) {
                if (host === "direct.test") return "DIRECT";
                return "PROXY 127.0.0.1:8080";
            }
        "#
            .as_bytes(),
        )
        .unwrap();

        let engine = PacEngine::new(file.path())
            .await
            .unwrap()
            .with_cache(60, 100);

        let direct = engine
            .find_proxy_for_url("https://direct.test/", "direct.test")
            .await
            .unwrap();
        let proxied = engine
            .find_proxy_for_url("https://other.test/", "other.test")
            .await
            .unwrap();

        assert_eq!(direct, None, "direct.test must be DIRECT");
        assert_eq!(
            proxied,
            Some("http://127.0.0.1:8080".to_string()),
            "other.test must use proxy"
        );

        // Verify subsequent calls (cache hit) return the same decisions.
        assert_eq!(
            engine
                .find_proxy_for_url("https://direct.test/", "direct.test")
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            engine
                .find_proxy_for_url("https://other.test/", "other.test")
                .await
                .unwrap(),
            Some("http://127.0.0.1:8080".to_string())
        );
    }

    #[tokio::test]
    async fn test_pac_js_helpers() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(
            r#"
            function FindProxyForURL(url, host) {
                if (isPlainHostName(host)) return "PROXY plain:8080";
                if (dnsDomainIs(host, "google.com")) return "PROXY google:8080";
                if (shExpMatch(host, "*.apple.com")) return "PROXY apple:8080";
                if (dnsDomainLevels(host) > 2) return "PROXY deep:8080";
                return "DIRECT";
            }
        "#
            .as_bytes(),
        )
        .unwrap();

        let engine = PacEngine::new(file.path()).await.unwrap();

        assert_eq!(
            engine
                .find_proxy_for_url("http://localhost/", "localhost")
                .await
                .unwrap(),
            Some("http://plain:8080".to_string())
        );
        assert_eq!(
            engine
                .find_proxy_for_url("http://www.google.com/", "www.google.com")
                .await
                .unwrap(),
            Some("http://google:8080".to_string())
        );
        assert_eq!(
            engine
                .find_proxy_for_url("http://sub.apple.com/", "sub.apple.com")
                .await
                .unwrap(),
            Some("http://apple:8080".to_string())
        );
        assert_eq!(
            engine
                .find_proxy_for_url("http://a.b.c.d.com/", "a.b.c.d.com")
                .await
                .unwrap(),
            Some("http://deep:8080".to_string())
        );
    }
}
