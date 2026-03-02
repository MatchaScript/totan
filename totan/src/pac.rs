use anyhow::Result;
use boa_engine::{Context, Source};
use std::{
    collections::{HashMap, VecDeque},
    path::Path,
    sync::Mutex,
    time::{Duration, Instant},
};
use tokio::fs;
use totan_common::{PacResult, TotanError};
use tracing::{debug, info};

pub struct PacEngine {
    script_content: String,
    cache: Mutex<PacCache>,
}

struct PacCache {
    ttl: Duration,
    max_entries: usize,
    // Keyed by (url, host) joined with '\u0001' to avoid collision
    map: HashMap<String, (Instant, Option<String>)>,
    order: VecDeque<String>, // simple LRU order: front = oldest
}

impl PacEngine {
    pub async fn new(pac_file: &Path) -> Result<Self> {
        let script_content = fs::read_to_string(pac_file).await?;
        info!("Loaded PAC file: {}", pac_file.display());

        // Validate PAC script by creating a test context
        let mut context = Context::default();
        let source = Source::from_bytes(&script_content);
        context
            .eval(source)
            .map_err(|e| TotanError::PacScript(format!("PAC script validation failed: {}", e)))?;

        // Defaults until wired by caller via builder-like methods
        let cache = PacCache {
            ttl: Duration::from_secs(60),
            max_entries: 4096,
            map: HashMap::new(),
            order: VecDeque::new(),
        };
        Ok(Self {
            script_content,
            cache: Mutex::new(cache),
        })
    }

    pub fn with_cache(self, ttl_secs: u64, max_entries: usize) -> Self {
        let mut guard = self.cache.lock().unwrap();
        guard.ttl = Duration::from_secs(ttl_secs);
        guard.max_entries = max_entries.max(1);
        drop(guard);
        self
    }

    pub async fn find_proxy_for_url(&self, url: &str, host: &str) -> Result<Option<String>> {
        // Check cache first
        let key = format!("{url}\u{0001}{host}");
        let now = Instant::now();
        if let Some(hit) = {
            let mut guard = self.cache.lock().unwrap();
            if guard.ttl.as_secs() > 0 {
                if let Some((ts, val)) = guard.map.get(&key) {
                    if now.duration_since(*ts) <= guard.ttl {
                        debug!("PAC cache hit: {} (host: {})", url, host);
                        Some(val.clone())
                    } else {
                        // stale -> remove
                        guard.map.remove(&key);
                        if let Some(pos) = guard.order.iter().position(|k| k == &key) {
                            guard.order.remove(pos);
                        }
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            }
        } {
            return Ok(hit);
        }

        // Execute PAC script in isolated context
        let script_content = self.script_content.clone();
        let url_val = url.to_string();
        let host_val = host.to_string();

        let result = tokio::task::spawn_blocking(move || -> Result<String> {
            let mut context = Context::default();

            // Register PAC helpers
            Self::register_helpers(&mut context)?;

            // Evaluate user script
            let source = Source::from_bytes(&script_content);
            context.eval(source).map_err(|e| {
                TotanError::PacScript(format!("PAC script evaluation failed: {}", e))
            })?;

            // Try to call FindProxyForURL
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
        })
        .await??;

        debug!("PAC result for {} ({}): {}", url, host, result);

        // Parse PAC result and return first valid proxy
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

        // Save to cache
        {
            let mut guard = self.cache.lock().unwrap();
            if guard.ttl.as_secs() > 0 {
                // Evict if over capacity
                if guard.map.len() >= guard.max_entries {
                    if let Some(old_key) = guard.order.pop_front() {
                        guard.map.remove(&old_key);
                    }
                }
                if let Some(pos) = guard.order.iter().position(|k| k == &key) {
                    guard.order.remove(pos);
                }
                guard.order.push_back(key.clone());
                guard.map.insert(key, (now, computed.clone()));
            }
        }

        Ok(computed)
    }

    fn register_helpers(context: &mut Context) -> Result<()> {
        // DNS helpers using Rust bindings
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
            Ok(boa_engine::JsValue::from(boa_engine::JsString::from(
                "127.0.0.1",
            )))
        }

        // dnsResolve(host)
        context
            .register_global_builtin_callable(
                "dnsResolve".into(),
                1,
                NativeFunction::from_fn_ptr(dns_resolve_binding),
            )
            .map_err(|e| TotanError::PacScript(format!("Failed to register dnsResolve: {}", e)))?;

        // myIpAddress()
        context
            .register_global_builtin_callable(
                "myIpAddress".into(),
                0,
                NativeFunction::from_fn_ptr(my_ip_address_binding),
            )
            .map_err(|e| TotanError::PacScript(format!("Failed to register myIpAddress: {}", e)))?;

        // Standard PAC JS helpers
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
