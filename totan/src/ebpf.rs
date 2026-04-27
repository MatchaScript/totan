//! Aya loader for the tc ingress classifier that hijacks TCP/80 and TCP/443
//! arriving from clients (e.g. pod-facing veth or netkit host peer) and
//! delivers them to a local TPROXY listener via `bpf_sk_assign`.
//!
//! ## Required host setup
//!
//! After `Loader::load_and_attach`, the caller (or a cluster administrator)
//! must ensure the following policy routing rules are present. Without them
//! `ip_route_input()` won't find a local route for external dst IPs, and the
//! `sk_assign`-tagged packets will be forwarded/dropped instead of delivered
//! to the TPROXY socket:
//!
//! ```text
//! ip rule add fwmark <FWMARK> lookup 100 priority 100
//! ip route add local 0.0.0.0/0 dev lo table 100
//! ```
//!
//! `Loader::setup_policy_routing` applies these rules automatically at startup
//! and removes them on drop if `cleanup_on_drop` is set.
//!
//! ## Why tc ingress
//!
//! `bpf_sk_assign` is gated in the kernel to the tc ingress path
//! (`net/core/filter.c`: `if (!skb_at_tc_ingress(skb)) return -EOPNOTSUPP;`).
//! For client-originated traffic, tc ingress of the host-side peer of the
//! client's network pair device (veth / netkit) is the first tc hook the
//! packet reaches on the host and is the natural attach point.

use std::net::Ipv4Addr;
use std::process::Command;

use aya::{
    include_bytes_aligned,
    maps::Array,
    programs::{tc::TcAttachOptions, LinkOrder, SchedClassifier, TcAttachType},
    Ebpf, EbpfLoader,
};
use aya_log::EbpfLogger;
use tracing::{info, warn};

/// Default fwmark placed on redirected packets. Distinct from Cilium's mark
/// range (0x0200–0x0E00) and IPTables connmark ranges.
pub const DEFAULT_FWMARK: u32 = 0x7474; // "tt" for totan

/// Layout-compatible mirror of the kernel-side `TproxyConfig` in
/// `totan-ebpf/src/main.rs`. Both sides **must** be updated in lock-step.
///
/// Layout: `[u32 tproxy_ipv4_be][u16 tproxy_port_be][u16 _pad0][u32 fwmark][u32 _pad1]`
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct TproxyConfig {
    pub tproxy_ipv4_be: u32,
    pub tproxy_port_be: u16,
    pub _pad0: u16,
    pub fwmark: u32,
    pub _pad1: u32,
}

// SAFETY: #[repr(C)], all fields are integers, explicit padding zeroes the
// trailing bytes — the kernel verifier will see a fully initialised struct.
unsafe impl aya::Pod for TproxyConfig {}

pub struct Loader {
    // Held for RAII: dropping `_ebpf` detaches all programs and tears down maps.
    _ebpf: Ebpf,
    // Each element keeps one tcx attachment alive; drop = detach.
    links: Vec<aya::programs::tc::SchedClassifierLink>,
    fwmark: u32,
    owned_routing: bool,
}

impl Loader {
    /// Load the tc ingress program, configure the `TOTAN_CONFIG` map, then
    /// tcx-attach it to every interface in `ingress_ifaces` with first-position
    /// ordering. Policy routing is also configured automatically.
    pub fn load_and_attach(
        ingress_ifaces: &[&str],
        tproxy_addr: Ipv4Addr,
        tproxy_port: u16,
        fwmark: u32,
    ) -> anyhow::Result<Self> {
        let elf = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/totan_bpf"));

        let mut ebpf = EbpfLoader::new().load(elf)?;

        if let Err(e) = EbpfLogger::init(&mut ebpf) {
            warn!("aya-log init skipped (no log map in totan-ebpf yet): {}", e);
        }

        let mut config_map: Array<_, TproxyConfig> = Array::try_from(
            ebpf.map_mut("TOTAN_CONFIG")
                .ok_or_else(|| anyhow::anyhow!("TOTAN_CONFIG map not found in ELF"))?,
        )?;
        let cfg = TproxyConfig {
            tproxy_ipv4_be: u32::from(tproxy_addr).to_be(),
            tproxy_port_be: tproxy_port.to_be(),
            _pad0: 0,
            fwmark,
            _pad1: 0,
        };
        config_map.set(0, cfg, 0)?;

        let program: &mut SchedClassifier = ebpf
            .program_mut("totan_tc_ingress")
            .ok_or_else(|| anyhow::anyhow!("totan_tc_ingress not found in ELF"))?
            .try_into()?;
        program.load()?;

        // tcx attach with first-position ordering for Cilium coexistence.
        // `LinkOrder::first()` installs us before any existing tcx programs on
        // the same hook so sk_assign runs before downstream policy/NAT.
        let mut links = Vec::with_capacity(ingress_ifaces.len());
        for iface in ingress_ifaces {
            let link_id = program.attach_with_options(
                iface,
                TcAttachType::Ingress,
                TcAttachOptions::TcxOrder(LinkOrder::first()),
            )?;
            links.push(program.take_link(link_id)?);
            info!(
                interface = iface,
                tproxy = %format!("{}:{}", tproxy_addr, tproxy_port),
                fwmark = format!("0x{:04X}", fwmark),
                "totan eBPF tc ingress attached"
            );
        }

        let owned = setup_policy_routing(fwmark)?;
        Ok(Self {
            _ebpf: ebpf,
            links,
            fwmark,
            owned_routing: owned,
        })
    }

    /// Attach the already-loaded tc program to an additional interface.
    /// Called by the interface watcher when a new matching device appears.
    pub fn attach_interface(&mut self, iface: &str) -> anyhow::Result<()> {
        let program: &mut SchedClassifier = self
            ._ebpf
            .program_mut("totan_tc_ingress")
            .ok_or_else(|| anyhow::anyhow!("totan_tc_ingress not found"))?
            .try_into()?;
        let link_id = program.attach_with_options(
            iface,
            TcAttachType::Ingress,
            TcAttachOptions::TcxOrder(LinkOrder::first()),
        )?;
        self.links.push(program.take_link(link_id)?);
        info!(
            interface = iface,
            "totan eBPF tc ingress attached to new interface"
        );
        Ok(())
    }
}

impl Drop for Loader {
    fn drop(&mut self) {
        // _link drop detaches the tcx program automatically.
        if self.owned_routing {
            teardown_policy_routing(self.fwmark);
        }
    }
}

/// Install `ip rule` + `ip route` entries that make fwmark-tagged packets
/// delivered locally regardless of their destination IP.
///
/// Returns `true` if we installed the rules (so `Drop` can clean them up),
/// `false` if they were already present.
fn setup_policy_routing(fwmark: u32) -> anyhow::Result<bool> {
    // `ip rule add fwmark <N> lookup 100 priority 100`
    let rule_check = Command::new("ip")
        .args(["rule", "show", "lookup", "100"])
        .output()?;
    let already_present =
        String::from_utf8_lossy(&rule_check.stdout).contains(&format!("0x{:x}", fwmark));

    if !already_present {
        let s = run_cmd(&[
            "ip",
            "rule",
            "add",
            "fwmark",
            &format!("0x{:x}", fwmark),
            "lookup",
            "100",
            "priority",
            "100",
        ])?;
        if !s.success() {
            return Err(anyhow::anyhow!(
                "`ip rule add fwmark` failed — is CAP_NET_ADMIN granted?"
            ));
        }
        run_cmd(&[
            "ip",
            "route",
            "add",
            "local",
            "0.0.0.0/0",
            "dev",
            "lo",
            "table",
            "100",
        ])
        .ok(); // may already exist
        info!(
            fwmark = format!("0x{:04X}", fwmark),
            "policy routing configured"
        );
        Ok(true)
    } else {
        info!(
            fwmark = format!("0x{:04X}", fwmark),
            "policy routing already present"
        );
        Ok(false)
    }
}

fn teardown_policy_routing(fwmark: u32) {
    run_cmd(&[
        "ip",
        "rule",
        "del",
        "fwmark",
        &format!("0x{:x}", fwmark),
        "lookup",
        "100",
    ])
    .ok();
    // Leave table 100 route in place — other consumers may share it.
}

fn run_cmd(args: &[&str]) -> anyhow::Result<std::process::ExitStatus> {
    Ok(Command::new(args[0]).args(&args[1..]).status()?)
}

/// Enumerate `/sys/class/net` and return all interface names that match at
/// least one of the given patterns. Patterns support `*` (any sequence) and
/// `?` (any single character); a pattern with no wildcards is an exact match.
pub async fn resolve_interfaces(patterns: &[String]) -> Vec<String> {
    let mut entries = match tokio::fs::read_dir("/sys/class/net").await {
        Ok(entries) => entries,
        Err(_) => return vec![],
    };

    let mut matched: Vec<String> = Vec::new();
    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name().to_string_lossy().into_owned();
        if patterns
            .iter()
            .any(|p| glob_match(p.as_bytes(), name.as_bytes()))
        {
            matched.push(name);
        }
    }
    matched.sort_unstable();
    matched
}

fn glob_match(pattern: &[u8], name: &[u8]) -> bool {
    match pattern.first() {
        None => name.is_empty(),
        Some(b'*') => {
            glob_match(&pattern[1..], name) || (!name.is_empty() && glob_match(pattern, &name[1..]))
        }
        Some(b'?') => !name.is_empty() && glob_match(&pattern[1..], &name[1..]),
        Some(&c) => name.first() == Some(&c) && glob_match(&pattern[1..], &name[1..]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(pattern: &str, name: &str) -> bool {
        glob_match(pattern.as_bytes(), name.as_bytes())
    }

    #[test]
    fn glob_exact() {
        assert!(m("eth0", "eth0"));
        assert!(!m("eth0", "eth1"));
        assert!(!m("eth0", "eth"));
        assert!(!m("eth0", "eth00"));
    }

    #[test]
    fn glob_star() {
        assert!(m("lxc*", "lxc12345678"));
        assert!(m("lxc*", "lxc"));
        assert!(!m("lxc*", "vlxc1"));
        assert!(m("*", "eth0"));
        assert!(m("*", "lo"));
        assert!(m("*", ""));
        assert!(m("eth*0", "eth0"));
        assert!(m("eth*0", "eth123450"));
        assert!(!m("eth*0", "eth1"));
    }

    #[test]
    fn glob_question() {
        assert!(m("eth?", "eth0"));
        assert!(m("eth?", "etha"));
        assert!(!m("eth?", "eth"));
        assert!(!m("eth?", "eth12"));
        assert!(m("lxc????????", "lxc12345678"));
        assert!(!m("lxc????????", "lxc1234567"));
    }

    #[test]
    fn glob_empty_pattern() {
        assert!(m("", ""));
        assert!(!m("", "a"));
    }

    #[test]
    fn glob_multiple_stars() {
        assert!(m("**", "anything"));
        assert!(m("l*x*", "lxc1"));
        assert!(m("l*x*", "loopbackxyz"));
        assert!(!m("l*x*", "eth0"));
    }

    #[tokio::test]
    async fn resolve_lo_exact() {
        // `lo` is present on every Linux host; sanity-check resolve_interfaces.
        let result = resolve_interfaces(&["lo".to_string()]).await;
        assert!(
            result.contains(&"lo".to_string()),
            "lo must be in /sys/class/net"
        );
    }

    #[tokio::test]
    async fn resolve_star_includes_lo() {
        let result = resolve_interfaces(&["*".to_string()]).await;
        assert!(result.contains(&"lo".to_string()));
    }

    #[tokio::test]
    async fn resolve_no_match() {
        let result = resolve_interfaces(&["__no_such_iface__".to_string()]).await;
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn resolve_sorted() {
        let result = resolve_interfaces(&["*".to_string()]).await;
        let mut sorted = result.clone();
        sorted.sort_unstable();
        assert_eq!(
            result, sorted,
            "resolve_interfaces must return sorted names"
        );
    }

    #[tokio::test]
    async fn resolve_multiple_patterns() {
        // "lo" exact + "*" wildcard — no duplicates expected from real /sys/class/net
        // because HashSet dedup is not used; but sorted uniqueness: lo appears once.
        let result = resolve_interfaces(&["lo".to_string(), "*".to_string()]).await;
        let lo_count = result.iter().filter(|n| n.as_str() == "lo").count();
        // With `any()` filtering each name once, lo appears exactly once.
        assert_eq!(lo_count, 1);
    }
}
