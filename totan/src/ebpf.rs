//! Aya loader for the tc egress classifier that hijacks TCP/80 and TCP/443 to
//! a local TPROXY listener.
//!
//! ## Required host setup
//!
//! After `Loader::load_and_attach`, the caller (or a cluster administrator)
//! must ensure the following policy routing rules are present. Without them
//! `ip_route_input()` won't find a local route for external dst IPs, and the
//! bpf_redirect'd packets will be forwarded/dropped instead of delivered to
//! the TPROXY socket:
//!
//! ```text
//! ip rule add fwmark <FWMARK> lookup 100 priority 100
//! ip route add local 0.0.0.0/0 dev lo table 100
//! ```
//!
//! `Loader::setup_policy_routing` applies these rules automatically at startup
//! and removes them on drop if `cleanup_on_drop` is set.

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
    // Held for RAII: dropping `Ebpf` detaches all programs and tears down maps.
    _ebpf: Ebpf,
    _link: aya::programs::tc::SchedClassifierLink,
    fwmark: u32,
    owned_routing: bool,
}

impl Loader {
    /// Load the tc egress program, configure the `TOTAN_CONFIG` map, tcx-attach
    /// it to `uplink` with first-position ordering, then configure policy routing
    /// so fwmark-tagged packets are delivered locally.
    pub fn load_and_attach(
        uplink: &str,
        tproxy_addr: Ipv4Addr,
        tproxy_port: u16,
        fwmark: u32,
    ) -> anyhow::Result<Self> {
        let elf = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/totan-ebpf"));

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
            .program_mut("totan_tc_egress")
            .ok_or_else(|| anyhow::anyhow!("totan_tc_egress not found in ELF"))?
            .try_into()?;
        program.load()?;

        // tcx attach with first-position ordering for Cilium coexistence.
        // `LinkOrder::first()` installs us before any existing tcx programs on
        // the same hook so bpf_sk_assign runs before downstream masquerade.
        let link_id = program.attach_with_options(
            uplink,
            TcAttachType::Egress,
            TcAttachOptions::TcxOrder(LinkOrder::first()),
        )?;
        let link = program.take_link(link_id)?;

        info!(
            interface = uplink,
            tproxy = %format!("{}:{}", tproxy_addr, tproxy_port),
            fwmark = format!("0x{:04X}", fwmark),
            "totan eBPF tc egress attached"
        );

        let owned = setup_policy_routing(fwmark)?;
        Ok(Self {
            _ebpf: ebpf,
            _link: link,
            fwmark,
            owned_routing: owned,
        })
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
