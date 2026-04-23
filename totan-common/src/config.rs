use crate::types::InterceptionMode;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

fn default_listen_port() -> u16 {
    3129
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotanConfig {
    /// The local port for totan to listen on
    #[serde(default = "default_listen_port")]
    pub listen_port: u16,

    /// The default upstream proxy URL
    pub default_proxy: Option<String>,

    /// Path to the PAC file for dynamic proxy resolution
    pub pac_file: Option<PathBuf>,

    /// PAC result cache TTL in seconds (0 to disable caching)
    #[serde(default = "default_pac_cache_ttl_secs")]
    pub pac_cache_ttl_secs: u64,

    /// PAC result cache maximum number of entries
    #[serde(default = "default_pac_cache_max_entries")]
    pub pac_cache_max_entries: usize,

    /// Packet interception mode: "netfilter" or "ebpf"
    #[serde(default)]
    pub interception_mode: InterceptionMode,

    /// Logging configuration
    #[serde(default)]
    pub logging: LoggingConfig,

    /// Timeout configuration
    #[serde(default)]
    pub timeouts: TimeoutConfig,

    /// Error mitigation configuration
    #[serde(default)]
    pub mitigation: ErrorMitigationConfig,

    /// Netfilter-specific configuration (only consulted when `interception_mode = "netfilter"`)
    #[serde(default)]
    pub netfilter: NetfilterConfig,

    /// eBPF-specific configuration (only consulted when `interception_mode = "ebpf"`)
    #[serde(default)]
    pub ebpf: EbpfConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EbpfConfig {
    /// Interface names or glob patterns (supports `*` and `?`) for the
    /// host-side peers of client network devices (veth / netkit). The tc
    /// ingress classifier is attached to every matching interface at startup,
    /// and newly-appearing interfaces that match are picked up automatically.
    ///
    /// Examples:
    ///   `["lxc*"]`        — all Cilium pod veth pairs
    ///   `["eth0", "ens*"]` — specific + wildcard
    #[serde(default)]
    pub ingress_interfaces: Vec<String>,

    /// Localhost TPROXY listener port. The tc ingress program assigns matching
    /// flows to the listener at `127.0.0.1:<tproxy_port>` via `bpf_sk_assign`.
    /// Defaults to the top-level `listen_port` when unset.
    #[serde(default)]
    pub tproxy_port: Option<u16>,

    /// fwmark placed on packets after `bpf_sk_assign` so the kernel's policy
    /// routing delivers them locally instead of forwarding. The loader
    /// automatically installs `ip rule fwmark <N> lookup 100` and
    /// `ip route local 0.0.0.0/0 dev lo table 100` at startup.
    /// Must not overlap with Cilium's mark range (0x0200–0x0E00).
    /// Default: 0x7474.
    #[serde(default = "default_fwmark")]
    pub fwmark: u32,
}

fn default_fwmark() -> u32 {
    0x7474 // "tt" for totan; distinct from Cilium's 0x0200–0x0E00 range
}

impl Default for EbpfConfig {
    fn default() -> Self {
        Self {
            ingress_interfaces: Vec::new(),
            tproxy_port: None,
            fwmark: default_fwmark(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level: "trace", "debug", "info", "warn", or "error"
    #[serde(default = "default_log_level")]
    pub level: String,

    /// Log format: "text" for human-readable, "json" for machine-readable
    #[serde(default = "default_log_format")]
    pub format: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
        }
    }
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_format() -> String {
    "text".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeoutConfig {
    /// Upstream connection timeout in milliseconds
    #[serde(default = "default_upstream_connect_ms")]
    pub upstream_connect_ms: u64,

    /// Client connection idle timeout in seconds
    #[serde(default = "default_client_idle_secs")]
    pub client_idle_secs: u64,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            upstream_connect_ms: default_upstream_connect_ms(),
            client_idle_secs: default_client_idle_secs(),
        }
    }
}

fn default_upstream_connect_ms() -> u64 {
    3000
}

fn default_client_idle_secs() -> u64 {
    600
}

impl Default for TotanConfig {
    fn default() -> Self {
        Self {
            listen_port: 3129,
            default_proxy: None,
            pac_file: None,
            pac_cache_ttl_secs: default_pac_cache_ttl_secs(),
            pac_cache_max_entries: default_pac_cache_max_entries(),
            interception_mode: Default::default(),
            logging: Default::default(),
            timeouts: Default::default(),
            mitigation: Default::default(),
            netfilter: Default::default(),
            ebpf: Default::default(),
        }
    }
}

/// Netfilter-mode rule management configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetfilterConfig {
    /// When `true`, totan installs nftables OUTPUT rules that redirect all
    /// outbound TCP traffic on `redirect_ports` to its listener. Packets marked
    /// with `fwmark` (set on totan's own upstream sockets via `SO_MARK`) are
    /// excluded to prevent redirect loops — this works regardless of the
    /// running user.
    ///
    /// When `false` (default), totan does not touch nftables — manage rules
    /// externally (e.g. via a system nftables config or Ansible).
    #[serde(default)]
    pub manage_rules: bool,

    /// Socket mark (`SO_MARK`) applied to totan's own upstream TCP connections
    /// and matched by `meta mark` in the nftables rule to prevent redirect
    /// loops. Must not overlap with Cilium's mark range (0x0200–0x0E00).
    /// Default: 0x7474.
    #[serde(default = "default_fwmark")]
    pub fwmark: u32,

    /// TCP destination ports to intercept. Default: [80, 443].
    #[serde(default = "default_redirect_ports")]
    pub redirect_ports: Vec<u16>,
}

impl Default for NetfilterConfig {
    fn default() -> Self {
        Self {
            manage_rules: false,
            fwmark: default_fwmark(),
            redirect_ports: default_redirect_ports(),
        }
    }
}

fn default_redirect_ports() -> Vec<u16> {
    vec![80, 443]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorMitigationConfig {
    /// Number of retry attempts on upstream connect failures (0 = no retry)
    #[serde(default = "default_retry_attempts")]
    pub retry_attempts: u32,

    /// Base backoff in milliseconds between retries (exponential backoff)
    #[serde(default = "default_retry_backoff_ms")]
    pub retry_backoff_ms: u64,

    /// Send TCP RST to client on failure to trigger client retry
    #[serde(default = "default_rst_on_failure")]
    pub rst_on_failure: bool,

    /// If proxy connection fails, try direct connection as a fallback
    #[serde(default = "default_try_direct_on_proxy_failure")]
    pub try_direct_on_proxy_failure: bool,
}

impl Default for ErrorMitigationConfig {
    fn default() -> Self {
        Self {
            retry_attempts: default_retry_attempts(),
            retry_backoff_ms: default_retry_backoff_ms(),
            rst_on_failure: default_rst_on_failure(),
            try_direct_on_proxy_failure: default_try_direct_on_proxy_failure(),
        }
    }
}

fn default_retry_attempts() -> u32 {
    2
}
fn default_retry_backoff_ms() -> u64 {
    200
}
fn default_rst_on_failure() -> bool {
    true
}
fn default_try_direct_on_proxy_failure() -> bool {
    true
}

fn default_pac_cache_ttl_secs() -> u64 {
    60
}
fn default_pac_cache_max_entries() -> usize {
    4096
}
