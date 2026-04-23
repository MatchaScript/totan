//! PAC (Proxy Auto-Configuration) evaluation.
//!
//! Architecture (mirrors proxydetox's split):
//! - [`PacEngine`] owns a `boa_engine::Context` and lives on a dedicated OS
//!   thread. The Context is built once — native bindings, DNS cache,
//!   `pac_utils.js`, and the user PAC script are all evaluated up front and
//!   reused for every `FindProxyForURL` call.
//! - [`PacEvaluator`] is the async facade. It sends requests to the worker
//!   over a channel, enforces a per-call timeout, and memoises results in an
//!   LRU keyed by `(url, host)`.
//!
//! Why a dedicated thread? `boa_engine::Context` is `!Send + !Sync`, and PAC
//! scripts can call back into native helpers that mutate per-engine state
//! (the DNS cache). The worker-thread pattern gives us safe shared access
//! without locking the Context on every call and without rebuilding it.

use crate::proxy::Proxies;
use anyhow::Result;
use boa_engine::{
    class::Class, js_string, Context, JsData, JsNativeError, JsResult, JsString, JsValue,
    NativeFunction, Source,
};
use boa_gc::{Finalize, Trace};
use lru::LruCache;
use once_cell::sync::OnceCell;
use std::{
    collections::HashMap,
    num::NonZeroUsize,
    path::Path,
    sync::Mutex,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::fs;
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;
use totan_common::TotanError;
use tracing::{debug, info, warn};

const PAC_UTILS: &str = include_str!("pac_utils.js");
const DEFAULT_PAC_SCRIPT: &str = "function FindProxyForURL(url, host) { return \"DIRECT\"; }";
const DNS_ENTRY_TTL_SECS: u64 = 5 * 60;

// ─── Worker-thread engine ────────────────────────────────────────────────

struct PacEngine {
    js: Context,
}

impl PacEngine {
    fn new(pac_script: &str) -> Result<Self, TotanError> {
        let mut js = build_context();
        js.eval(Source::from_bytes(pac_script))
            .map_err(|e| TotanError::PacScript(format!("PAC script evaluation failed: {e}")))?;
        Ok(Self { js })
    }

    fn find_proxy(&mut self, url: &str, host: &str) -> Result<Proxies, TotanError> {
        let raw = self.call_find_proxy_for_url(url, host)?;
        raw.parse::<Proxies>()
            .map_err(|e| TotanError::PacScript(format!("FindProxyForURL returned '{raw}': {e}")))
    }

    fn call_find_proxy_for_url(&mut self, url: &str, host: &str) -> Result<String, TotanError> {
        let find_proxy = self
            .js
            .global_object()
            .get(js_string!("FindProxyForURL"), &mut self.js)
            .map_err(|e| TotanError::PacScript(format!("Failed to get FindProxyForURL: {e}")))?;

        let callable = find_proxy
            .as_callable()
            .ok_or_else(|| TotanError::PacScript("FindProxyForURL is not a function".into()))?;

        let args = [
            JsValue::from(JsString::from(url)),
            JsValue::from(JsString::from(host)),
        ];
        let result = callable
            .call(&JsValue::null(), &args, &mut self.js)
            .map_err(|e| TotanError::PacScript(format!("FindProxyForURL call failed: {e}")))?;

        let s = result
            .to_string(&mut self.js)
            .map_err(|e| TotanError::PacScript(format!("PAC result not stringifiable: {e}")))?;
        Ok(s.to_std_string_escaped())
    }
}

fn build_context() -> Context {
    let mut js = Context::default();

    js.register_global_class::<DnsCache>()
        .expect("register _DnsCache class");

    js.register_global_builtin_callable(
        js_string!("alert"),
        1,
        NativeFunction::from_fn_ptr(native_alert),
    )
    .expect("register alert");

    js.register_global_builtin_callable(
        js_string!("dnsResolve"),
        1,
        NativeFunction::from_fn_ptr(native_dns_resolve),
    )
    .expect("register dnsResolve");

    js.register_global_builtin_callable(
        js_string!("shExpMatch"),
        2,
        NativeFunction::from_fn_ptr(native_sh_exp_match),
    )
    .expect("register shExpMatch");

    js.register_global_builtin_callable(
        js_string!("myIpAddress"),
        0,
        NativeFunction::from_fn_ptr(native_my_ip_address),
    )
    .expect("register myIpAddress");

    // One shared DNS cache instance per Context, stashed on the global object
    // under `_dnsCache`. The native `dnsResolve` looks it up each call.
    let dns_cache_obj = js
        .eval(Source::from_bytes("new _DnsCache();"))
        .expect("instantiate _DnsCache");
    js.register_global_property(
        js_string!("_dnsCache"),
        dns_cache_obj,
        boa_engine::property::Attribute::all(),
    )
    .expect("register _dnsCache");

    js.eval(Source::from_bytes(PAC_UTILS))
        .expect("evaluate pac_utils.js");
    js.eval(Source::from_bytes(DEFAULT_PAC_SCRIPT))
        .expect("evaluate default PAC");

    js
}

// ─── DNS cache exposed to JS as `_DnsCache` ─────────────────────────────

type DnsMap = HashMap<String, DnsEntry>;

#[derive(Debug, Trace, Finalize, JsData)]
struct DnsEntry {
    ip: Option<String>,
    // Absolute expiry (unix seconds). `u64` is Trace/Finalize-safe as a leaf.
    expires_at: u64,
}

#[derive(Default, Debug, Trace, Finalize, JsData)]
struct DnsCache {
    map: DnsMap,
    // Next time to sweep expired entries. Deferred so a burst of misses
    // doesn't quadratic-ally scan the table on every insert.
    next_cleanup_at: u64,
}

impl DnsCache {
    fn lookup(&mut self, host: &str) -> Option<String> {
        let now = unix_now();
        let expire_at = now + DNS_ENTRY_TTL_SECS;

        let resolved = match self.map.get(host) {
            Some(entry) if entry.expires_at > now => entry.ip.clone(),
            _ => {
                let ip = resolve_host_blocking(host);
                self.map.insert(
                    host.to_string(),
                    DnsEntry {
                        ip: ip.clone(),
                        expires_at: expire_at,
                    },
                );
                ip
            }
        };

        if self.next_cleanup_at <= now {
            self.map.retain(|_, e| e.expires_at > now);
            self.next_cleanup_at = expire_at;
        }

        resolved
    }
}

impl Class for DnsCache {
    const NAME: &'static str = "_DnsCache";

    fn data_constructor(
        _this: &JsValue,
        _args: &[JsValue],
        _context: &mut Context,
    ) -> JsResult<Self> {
        Ok(Self::default())
    }

    fn init(_class: &mut boa_engine::class::ClassBuilder<'_>) -> JsResult<()> {
        Ok(())
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn resolve_host_blocking(host: &str) -> Option<String> {
    use std::net::ToSocketAddrs;
    (host, 0u16)
        .to_socket_addrs()
        .ok()
        .and_then(|mut a| a.next())
        .map(|a| a.ip().to_string())
}

// ─── Native PAC bindings ─────────────────────────────────────────────────

fn native_alert(_this: &JsValue, args: &[JsValue], _ctx: &mut Context) -> JsResult<JsValue> {
    let msg = args
        .first()
        .and_then(|v| v.as_string())
        .map(|s| s.to_std_string_escaped())
        .unwrap_or_default();
    tracing::info!(target: "pac", "alert: {msg}");
    Ok(JsValue::undefined())
}

fn native_dns_resolve(
    _this: &JsValue,
    args: &[JsValue],
    context: &mut Context,
) -> JsResult<JsValue> {
    let host_arg = args
        .first()
        .ok_or_else(|| JsNativeError::typ().with_message("dnsResolve: host argument required"))?;
    let host = host_arg.to_string(context)?.to_std_string_escaped();

    let dns_cache_val = context
        .global_object()
        .get(js_string!("_dnsCache"), context)?;
    let dns_cache_obj = dns_cache_val
        .as_object()
        .ok_or_else(|| JsNativeError::typ().with_message("_dnsCache missing"))?;
    let mut cache = dns_cache_obj
        .downcast_mut::<DnsCache>()
        .ok_or_else(|| JsNativeError::typ().with_message("_dnsCache is wrong type"))?;

    Ok(match cache.lookup(&host) {
        Some(ip) => JsValue::from(JsString::from(ip)),
        None => JsValue::null(),
    })
}

fn native_sh_exp_match(_this: &JsValue, args: &[JsValue], _ctx: &mut Context) -> JsResult<JsValue> {
    let s = args
        .first()
        .and_then(|v| v.as_string())
        .map(|s| s.to_std_string_escaped())
        .unwrap_or_default();
    let pat = args
        .get(1)
        .and_then(|v| v.as_string())
        .map(|s| s.to_std_string_escaped())
        .unwrap_or_default();

    // Invalid globs match nothing rather than throwing — matches browser
    // behaviour and keeps a typo in one rule from blowing up the whole chain.
    let matched = glob::Pattern::new(&pat)
        .map(|p| p.matches(&s))
        .unwrap_or(false);
    Ok(JsValue::from(matched))
}

fn native_my_ip_address(
    _this: &JsValue,
    _args: &[JsValue],
    _ctx: &mut Context,
) -> JsResult<JsValue> {
    // Process-wide cache: totan's primary interface doesn't change over its
    // lifetime, and the UDP-connect trick is a syscall cluster we'd rather
    // not repeat on every PAC call. If the probe ever fails we still return
    // something useful (127.0.0.1) so the PAC can fall through to a default.
    static CACHED: OnceCell<String> = OnceCell::new();
    let ip = CACHED.get_or_init(|| {
        use std::net::UdpSocket;
        UdpSocket::bind("0.0.0.0:0")
            .ok()
            .and_then(|sock| {
                sock.connect("8.8.8.8:80").ok()?;
                sock.local_addr().ok()
            })
            .map(|addr| addr.ip().to_string())
            .unwrap_or_else(|| "127.0.0.1".into())
    });
    Ok(JsValue::from(JsString::from(ip.clone())))
}

// ─── Async facade: worker thread + LRU cache ─────────────────────────────

enum Action {
    FindProxy {
        url: String,
        host: String,
        tx: oneshot::Sender<Result<Proxies, TotanError>>,
    },
}

struct PacCache {
    ttl: Duration,
    lru: LruCache<(String, String), (Instant, Proxies)>,
}

pub struct PacEvaluator {
    sender: mpsc::UnboundedSender<Action>,
    _worker: thread::JoinHandle<()>,
    cache: Mutex<PacCache>,
    pac_timeout: Duration,
}

impl PacEvaluator {
    pub async fn from_file(pac_file: &Path) -> Result<Self> {
        let script = fs::read_to_string(pac_file).await?;
        info!("Loaded PAC file: {}", pac_file.display());
        Self::from_script(script)
    }

    fn from_script(script: String) -> Result<Self> {
        // Parse-validate synchronously before spawning the worker so a broken
        // PAC file surfaces as an error from `from_file` rather than a silent
        // worker that never answers.
        {
            let _validate = PacEngine::new(&script)?;
        }

        let (sender, mut receiver) = mpsc::unbounded_channel::<Action>();
        let worker = thread::Builder::new()
            .name("pac-eval-worker".into())
            .spawn(move || {
                let mut engine = match PacEngine::new(&script) {
                    Ok(e) => e,
                    Err(e) => {
                        warn!("pac-eval-worker: failed to init engine: {e}");
                        return;
                    }
                };
                while let Some(action) = receiver.blocking_recv() {
                    match action {
                        Action::FindProxy { url, host, tx } => {
                            let r = engine.find_proxy(&url, &host);
                            let _ = tx.send(r);
                        }
                    }
                }
            })
            .expect("spawn pac-eval-worker");

        Ok(Self {
            sender,
            _worker: worker,
            cache: Mutex::new(PacCache {
                ttl: Duration::from_secs(60),
                lru: LruCache::new(NonZeroUsize::new(4096).unwrap()),
            }),
            pac_timeout: Duration::from_secs(30),
        })
    }

    pub fn with_cache(self, ttl_secs: u64, max_entries: usize) -> Self {
        let mut g = self.cache.lock().unwrap();
        g.ttl = Duration::from_secs(ttl_secs);
        g.lru.resize(NonZeroUsize::new(max_entries.max(1)).unwrap());
        drop(g);
        self
    }

    pub fn with_pac_timeout(mut self, secs: u64) -> Self {
        self.pac_timeout = Duration::from_secs(secs);
        self
    }

    pub async fn find_proxy(&self, url: &str, host: &str) -> Result<Proxies> {
        let key = (url.to_string(), host.to_string());
        let now = Instant::now();

        // Cache probe: the Context reuse already makes evaluation cheap, but
        // a cache hit saves the round-trip to the worker thread entirely —
        // worth it for PAC files that are called many times per second on
        // a handful of hot hosts.
        if let Some(hit) = self.cache_get(&key, now) {
            debug!("PAC cache hit: {} (host: {})", url, host);
            return Ok(hit);
        }

        let (tx, rx) = oneshot::channel();
        self.sender
            .send(Action::FindProxy {
                url: url.to_string(),
                host: host.to_string(),
                tx,
            })
            .map_err(|_| TotanError::PacScript("PAC worker is gone".into()))?;

        let received = timeout(self.pac_timeout, rx)
            .await
            .map_err(|_| TotanError::PacScript("PAC script execution timed out".into()))?
            .map_err(|_| TotanError::PacScript("PAC worker dropped response".into()))?;
        let proxies = received?;

        debug!("PAC result for {} ({}): {}", url, host, proxies);
        self.cache_put(key, now, proxies.clone());
        Ok(proxies)
    }

    fn cache_get(&self, key: &(String, String), now: Instant) -> Option<Proxies> {
        let mut g = self.cache.lock().unwrap();
        if g.ttl.is_zero() {
            return None;
        }
        match g.lru.peek(key) {
            Some((ts, val)) if now.duration_since(*ts) <= g.ttl => {
                let v = val.clone();
                g.lru.get(key); // promote to MRU
                Some(v)
            }
            Some(_) => {
                g.lru.pop(key);
                None
            }
            None => None,
        }
    }

    fn cache_put(&self, key: (String, String), now: Instant, val: Proxies) {
        let mut g = self.cache.lock().unwrap();
        if g.ttl.is_zero() {
            return;
        }
        g.lru.put(key, (now, val));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::{Proxy, ProxyOrDirect};
    use std::io::Write;
    use tempfile::NamedTempFile;

    async fn engine_for(script: &str) -> PacEvaluator {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(script.as_bytes()).unwrap();
        PacEvaluator::from_file(f.path()).await.unwrap()
    }

    #[tokio::test]
    async fn basic_direct_and_proxy() {
        let engine = engine_for(
            r#"
            function FindProxyForURL(url, host) {
                if (host === "example.com") return "PROXY proxy.example.com:8080";
                if (host === "google.com")  return "SOCKS5 127.0.0.1:1080; DIRECT";
                return "DIRECT";
            }
            "#,
        )
        .await;

        let p = engine
            .find_proxy("http://example.com/", "example.com")
            .await
            .unwrap();
        assert_eq!(
            p.first(),
            &ProxyOrDirect::Proxy(Proxy::Http("proxy.example.com:8080".parse().unwrap()))
        );

        let p = engine
            .find_proxy("http://google.com/", "google.com")
            .await
            .unwrap();
        let entries: Vec<_> = p.iter().cloned().collect();
        assert_eq!(
            entries,
            vec![
                ProxyOrDirect::Proxy(Proxy::Socks5("127.0.0.1:1080".parse().unwrap())),
                ProxyOrDirect::Direct,
            ]
        );

        let p = engine
            .find_proxy("http://other.com/", "other.com")
            .await
            .unwrap();
        assert_eq!(p, Proxies::direct());
    }

    #[tokio::test]
    async fn js_helpers_cover_common_cases() {
        let engine = engine_for(
            r#"
            function FindProxyForURL(url, host) {
                if (isPlainHostName(host)) return "PROXY plain:8080";
                if (dnsDomainIs(host, "google.com")) return "PROXY google:8080";
                if (shExpMatch(host, "*.apple.com")) return "PROXY apple:8080";
                if (dnsDomainLevels(host) > 2) return "PROXY deep:8080";
                return "DIRECT";
            }
            "#,
        )
        .await;
        let first = |p: &Proxies| match p.first() {
            ProxyOrDirect::Proxy(Proxy::Http(ep)) => ep.to_string(),
            _ => "DIRECT".into(),
        };

        let p = engine
            .find_proxy("http://localhost/", "localhost")
            .await
            .unwrap();
        assert_eq!(first(&p), "plain:8080");

        let p = engine
            .find_proxy("http://www.google.com/", "www.google.com")
            .await
            .unwrap();
        assert_eq!(first(&p), "google:8080");

        let p = engine
            .find_proxy("http://sub.apple.com/", "sub.apple.com")
            .await
            .unwrap();
        assert_eq!(first(&p), "apple:8080");

        let p = engine
            .find_proxy("http://a.b.c.d.com/", "a.b.c.d.com")
            .await
            .unwrap();
        assert_eq!(first(&p), "deep:8080");
    }

    /// Teams/O365/SharePoint split-tunnel: the common enterprise breakout pattern.
    #[tokio::test]
    async fn enterprise_direct_breakout_teams_style() {
        let engine = engine_for(
            r#"
            function FindProxyForURL(url, host) {
                if (host === "teams.microsoft.com" ||
                    shExpMatch(host, "*.teams.microsoft.com") ||
                    shExpMatch(host, "*.office365.com") ||
                    host === "login.microsoftonline.com" ||
                    shExpMatch(host, "*.sharepoint.com")) {
                    return "DIRECT";
                }
                return "PROXY 127.0.0.1:8080";
            }
            "#,
        )
        .await;

        for (url, host) in [
            ("https://teams.microsoft.com/", "teams.microsoft.com"),
            (
                "https://join.teams.microsoft.com/",
                "join.teams.microsoft.com",
            ),
            ("https://contoso.sharepoint.com/", "contoso.sharepoint.com"),
            (
                "https://login.microsoftonline.com/",
                "login.microsoftonline.com",
            ),
            ("https://outlook.office365.com/", "outlook.office365.com"),
        ] {
            let p = engine.find_proxy(url, host).await.unwrap();
            assert_eq!(p, Proxies::direct(), "{host} should be DIRECT");
        }

        let p = engine
            .find_proxy("https://example.com/", "example.com")
            .await
            .unwrap();
        assert_eq!(
            p.first(),
            &ProxyOrDirect::Proxy(Proxy::Http("127.0.0.1:8080".parse().unwrap()))
        );
    }

    /// Region-based tiering: APAC / EU / default proxies.
    #[tokio::test]
    async fn multi_proxy_by_region() {
        let engine = engine_for(
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
            "#,
        )
        .await;

        let cases = [
            ("example.jp", "127.0.0.1:8882"),
            ("example.cn", "127.0.0.1:8882"),
            ("example.de", "127.0.0.1:8881"),
            ("example.fr", "127.0.0.1:8881"),
            ("example.com", "127.0.0.1:8880"),
            ("example.org", "127.0.0.1:8880"),
        ];
        for (host, expected) in cases {
            let p = engine
                .find_proxy(&format!("https://{host}/"), host)
                .await
                .unwrap();
            assert_eq!(
                p.first(),
                &ProxyOrDirect::Proxy(Proxy::Http(expected.parse().unwrap())),
                "{host} should route to {expected}"
            );
        }
    }

    /// Cache correctness: DIRECT and proxy results share no storage even when
    /// hosts differ only slightly.
    #[tokio::test]
    async fn cache_key_isolation_and_direct_caching() {
        let engine = engine_for(
            r#"
            function FindProxyForURL(url, host) {
                if (host === "direct.test") return "DIRECT";
                return "PROXY 127.0.0.1:8080";
            }
            "#,
        )
        .await
        .with_cache(60, 100);

        let d1 = engine
            .find_proxy("https://direct.test/", "direct.test")
            .await
            .unwrap();
        let p1 = engine
            .find_proxy("https://other.test/", "other.test")
            .await
            .unwrap();
        assert_eq!(d1, Proxies::direct());
        assert_eq!(
            p1.first(),
            &ProxyOrDirect::Proxy(Proxy::Http("127.0.0.1:8080".parse().unwrap()))
        );

        // Second round should come from the cache and be identical.
        let d2 = engine
            .find_proxy("https://direct.test/", "direct.test")
            .await
            .unwrap();
        let p2 = engine
            .find_proxy("https://other.test/", "other.test")
            .await
            .unwrap();
        assert_eq!(d1, d2);
        assert_eq!(p1, p2);
    }

    /// A busted PAC should fail fast at load time, not at first request.
    #[tokio::test]
    async fn broken_script_rejected_at_load() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"function FindProxyForURL(u, h) {").unwrap();
        let err = PacEvaluator::from_file(f.path()).await;
        assert!(err.is_err(), "syntactically broken PAC must fail to load");
    }
}
