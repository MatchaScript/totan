use anyhow::Result;
use boa_engine::{Context, Source};
use std::{collections::{HashMap, VecDeque}, path::Path, sync::Mutex, time::{Duration, Instant}};
use tokio::fs;
use tracing::{debug, info, warn};
use totan_common::{PacResult, TotanError};

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
        context.eval(source).map_err(|e| {
            TotanError::PacScript(format!("PAC script validation failed: {}", e))
        })?;
        
        // Defaults until wired by caller via builder-like methods
        let cache = PacCache {
            ttl: Duration::from_secs(60),
            max_entries: 4096,
            map: HashMap::new(),
            order: VecDeque::new(),
        };
        Ok(Self { script_content, cache: Mutex::new(cache) })
    }

    pub fn with_cache(self, ttl_secs: u64, max_entries: usize) -> Self {
        let mut guard = self.cache.lock().unwrap();
        guard.ttl = Duration::from_secs(ttl_secs);
        guard.max_entries = max_entries.max(1);
        drop(guard);
        self
    }
    
        pub async fn find_proxy_for_url(&self, url: &str, host: &str) -> Result<Option<String>> {
            // Minimal PAC helper functions to support common PAC usage
            // Note: These are IPv4-oriented and provide basic behavior sufficient for most rules.
            const PAC_HELPERS: &str = r#"
            function isPlainHostName(h) { return h.indexOf('.') === -1; }
            function dnsDomainIs(h, d) { if (!h || !d) return false; return h === d || h.endsWith('.' + d); }
            function shExpMatch(str, shexp) {
                var re = new RegExp('^' + shexp.replace(/[.()+^$|]/g, '\\$&').replace(/\\*/g, '.*').replace(/\\?/g, '.') + '$');
                return re.test(str);
            }
            function myIpAddress() { return '127.0.0.1'; }
            function dnsResolve(h) { return h; }
            function isInNet(h, pattern, mask) {
                function toIpInt(ip) { var p = ip.split('.').map(Number); if (p.length!==4||p.some(isNaN)) return null; return ((p[0]<<24)>>>0)|((p[1]<<16)>>>0)|((p[2]<<8)>>>0)|(p[3]>>>0); }
                var hip = toIpInt(h); var pat = toIpInt(pattern); var m = toIpInt(mask); if (hip===null||pat===null||m===null) return false; return (hip & m) === (pat & m);
            }
            "#;

            let script_with_call = format!(
                r#"
                {helpers}
                {user}
                try {{
                    FindProxyForURL('{url}', '{host}');
                }} catch (e) {{
                    'DIRECT';
                }}
                "#,
                helpers = PAC_HELPERS,
                user = self.script_content,
                url = url,
                host = host,
            );
        
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
                        if let Some(pos) = guard.order.iter().position(|k| k == &key) { guard.order.remove(pos); }
                        None
                    }
                } else { None }
            } else { None }
        } {
            return Ok(hit);
        }

        // Execute PAC script in isolated context
        let result = tokio::task::spawn_blocking(move || -> Result<String> {
            let mut context = Context::default();
            let source = Source::from_bytes(&script_with_call);
            
            match context.eval(source) {
                Ok(result) => {
                    let result_str = result.to_string(&mut context)
                        .map_err(|e| TotanError::PacScript(format!("Failed to convert PAC result: {}", e)))?;
                    Ok(result_str.to_std_string_escaped())
                }
                Err(e) => {
                    warn!("PAC script execution failed: {}, using DIRECT", e);
                    Ok("DIRECT".to_string())
                }
            }
        }).await??;
        
        debug!("PAC result for {} ({}): {}", url, host, result);
        
        // Parse PAC result and return first valid proxy
        let pac_results = PacResult::parse(&result);
        let computed = pac_results.into_iter().find_map(|pac_result| match pac_result {
            PacResult::Direct => Some(None),
            PacResult::Proxy(proxy) => Some(Some(format!("http://{}", proxy))),
            PacResult::Socks(socks) => Some(Some(format!("socks5://{}", socks))),
        }).unwrap_or(None);

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
}
