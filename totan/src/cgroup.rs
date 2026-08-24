//! Cgroup-based interception for host-originated egress.
//!
//! Loads the `cgroup/connect4`, `cgroup/connect6`, and `sockops` BPF programs from the same
//! ELF as the tc ingress classifier (a separate `Ebpf` instance owns the
//! maps independently) and attaches them to the cgroup directories listed
//! in `HostHooksConfig::slices`.
//!
//! The two programs together rewrite outbound `connect(2)` to TCP/80
//! and TCP/443 to a local listener and record the original destination
//! keyed by the ephemeral source port the kernel binds. Userspace
//! recovers it by looking up `peer_addr.port()` (in network byte order)
//! after `accept`.
//!
//! ## Why not the root cgroup
//!
//! Attaching to `/sys/fs/cgroup` would intercept pod traffic too,
//! double-processing what `tc ingress` already handles and breaking the
//! pod-internal loopback rewrite (the rewritten `127.0.0.1:port` would
//! resolve to the pod netns loopback, where totan does not listen). The
//! default slice list (`system.slice`, `user.slice`) covers systemd
//! services and login sessions while leaving `kubepods.slice` untouched.

use std::fs::File;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use aya::{
    include_bytes_aligned,
    maps::{Array, HashMap as AyaHashMap, MapData},
    programs::{CgroupAttachMode, CgroupSockAddr, SockOps},
    Ebpf, EbpfLoader,
};
use aya_log::EbpfLogger;
use tokio::sync::Mutex;
use tracing::{info, warn};

/// Layout-compatible mirror of the kernel-side `HostHookConfig` in
/// `totan-ebpf/src/main.rs`. Both sides MUST be updated together.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct HostHookConfig {
    pub redirect_ipv4_be: u32,
    pub redirect_ipv6_be: [u32; 4],
    pub redirect_port_be: u16,
    pub _pad: u16,
    pub self_mark: u32,
}
// SAFETY: #[repr(C)], all fields are integers, explicit padding zeroes the
// trailing bytes — the kernel verifier sees a fully initialised struct.
unsafe impl aya::Pod for HostHookConfig {}

/// Layout-compatible mirror of the kernel-side `OrigDst`.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct OrigDst {
    pub family: u32,
    pub addr_be: [u32; 4],
    pub port_be: u16,
    pub _pad: u16,
}
unsafe impl aya::Pod for OrigDst {}

const AF_INET: u32 = 2;
const AF_INET6: u32 = 10;

impl OrigDst {
    pub fn to_socket_addr(self) -> Result<SocketAddr> {
        let port = u16::from_be(self.port_be);
        match self.family {
            AF_INET => Ok(SocketAddr::new(
                Ipv4Addr::from(u32::from_be(self.addr_be[0])).into(),
                port,
            )),
            AF_INET6 => {
                let mut octets = [0u8; 16];
                for (chunk, word) in octets.chunks_exact_mut(4).zip(self.addr_be) {
                    chunk.copy_from_slice(&u32::from_be(word).to_be_bytes());
                }
                Ok(SocketAddr::new(Ipv6Addr::from(octets).into(), port))
            }
            family => anyhow::bail!("unsupported original-destination family {family}"),
        }
    }
}

/// Layout-compatible mirror of the kernel-side sport-map key.
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SportKey {
    pub family: u32,
    pub port_be: u16,
    pub _pad: u16,
}
unsafe impl aya::Pod for SportKey {}

impl SportKey {
    pub fn from_peer(peer: SocketAddr) -> Self {
        Self {
            family: match peer {
                SocketAddr::V4(_) => AF_INET,
                SocketAddr::V6(_) => AF_INET6,
            },
            port_be: peer.port().to_be(),
            _pad: 0,
        }
    }
}

/// Shared handle into the `TOTAN_OD_BY_SPORT` map. The accept loop calls
/// `lock().await` per accepted connection — contention is minimal because
/// each map op is a single bpf syscall.
pub type SportMap = Arc<Mutex<AyaHashMap<MapData, SportKey, OrigDst>>>;

/// Owns the loaded ELF, attached cgroup links, and the sport-keyed map.
/// Drop tears down all attachments and the map fd.
pub struct HostLoader {
    _ebpf: Ebpf,
    _connect4_links: Vec<aya::programs::cgroup_sock_addr::CgroupSockAddrLink>,
    _connect6_links: Vec<aya::programs::cgroup_sock_addr::CgroupSockAddrLink>,
    _sockops_links: Vec<aya::programs::sock_ops::SockOpsLink>,
    sport_map: SportMap,
}

impl HostLoader {
    /// Verify kernel/cgroup prerequisites without loading anything. Call
    /// before `load_and_attach` to fail fast with a clear error.
    pub fn check_prereqs() -> Result<()> {
        if !Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
            anyhow::bail!(
                "cgroup v2 unified hierarchy not detected at /sys/fs/cgroup. \
                 Host hooks require cgroup v2."
            );
        }
        let kv = aya::util::KernelVersion::current()
            .map_err(|e| anyhow::anyhow!("failed to read kernel version: {}", e))?;
        let min = aya::util::KernelVersion::new(5, 7, 0);
        if kv < min {
            anyhow::bail!(
                "kernel {:?} is too old for the cgroup BPF link API; need >= 5.7",
                kv
            );
        }
        Ok(())
    }

    pub fn load_and_attach(
        slices: &[PathBuf],
        redirect_ipv4: Ipv4Addr,
        redirect_ipv6: Ipv6Addr,
        redirect_port: u16,
        self_mark: u32,
    ) -> Result<Self> {
        Self::check_prereqs()?;

        if slices.is_empty() {
            anyhow::bail!("HostHooksConfig::slices must not be empty");
        }
        for p in slices {
            if !p.is_dir() {
                anyhow::bail!("cgroup slice path is not a directory: {}", p.display());
            }
        }

        // totan tags its own egress with self_mark and connect4 skips it, so
        // running inside a hooked slice no longer loops. We still warn because
        // it relies on self_mark being applied to every interceptable outbound
        // socket; surfacing it helps diagnose any future leak.
        if let Some(offending) = totan_self_in_slice(slices) {
            warn!(
                slice = %offending.display(),
                "totan is running inside a hooked slice; relying on self_mark \
                 self-exclusion to avoid a connect4 self-loop"
            );
        }

        let elf = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/totan_bpf"));
        let mut ebpf = EbpfLoader::new().load(elf)?;
        if let Err(e) = EbpfLogger::init(&mut ebpf) {
            warn!("aya-log init skipped on host-hook ebpf: {}", e);
        }

        // Configure TOTAN_HOST_CFG before any program is attached, so the
        // first hook firing already sees the redirect target.
        {
            let mut cfg_map: Array<_, HostHookConfig> = Array::try_from(
                ebpf.map_mut("TOTAN_HOST_CFG")
                    .ok_or_else(|| anyhow::anyhow!("TOTAN_HOST_CFG map missing in ELF"))?,
            )?;
            cfg_map.set(
                0,
                HostHookConfig {
                    redirect_ipv4_be: u32::from(redirect_ipv4).to_be(),
                    redirect_ipv6_be: ipv6_to_be_words(redirect_ipv6),
                    redirect_port_be: redirect_port.to_be(),
                    _pad: 0,
                    self_mark,
                },
                0,
            )?;
        }

        let connect4_links = attach_connect4(&mut ebpf, slices)?;
        let connect6_links = attach_connect6(&mut ebpf, slices)?;
        let sockops_links = attach_sockops(&mut ebpf, slices)?;

        // Take ownership of the sport map so the accept loop can consume from it.
        let sport_map_data = ebpf
            .take_map("TOTAN_OD_BY_SPORT")
            .ok_or_else(|| anyhow::anyhow!("TOTAN_OD_BY_SPORT map missing in ELF"))?;
        let sport_map: AyaHashMap<MapData, SportKey, OrigDst> =
            AyaHashMap::try_from(sport_map_data)?;

        info!(
            redirect_ipv4 = %format!("{}:{}", redirect_ipv4, redirect_port),
            redirect_ipv6 = %format!("[{}]:{}", redirect_ipv6, redirect_port),
            slices = slices.len(),
            "totan cgroup host-hooks loaded"
        );

        Ok(Self {
            _ebpf: ebpf,
            _connect4_links: connect4_links,
            _connect6_links: connect6_links,
            _sockops_links: sockops_links,
            sport_map: Arc::new(Mutex::new(sport_map)),
        })
    }

    /// Clone-able handle into the sport→OrigDst map.
    pub fn sport_map(&self) -> SportMap {
        self.sport_map.clone()
    }
}

fn ipv6_to_be_words(addr: Ipv6Addr) -> [u32; 4] {
    let octets = addr.octets();
    let mut words = [0u32; 4];
    for (word, chunk) in words.iter_mut().zip(octets.chunks_exact(4)) {
        *word = u32::from_be_bytes(chunk.try_into().expect("IPv6 chunks are four bytes")).to_be();
    }
    words
}

fn attach_connect4(
    ebpf: &mut Ebpf,
    slices: &[PathBuf],
) -> Result<Vec<aya::programs::cgroup_sock_addr::CgroupSockAddrLink>> {
    let prog: &mut CgroupSockAddr = ebpf
        .program_mut("totan_connect4")
        .ok_or_else(|| anyhow::anyhow!("totan_connect4 program missing in ELF"))?
        .try_into()?;
    prog.load()?;
    let mut links = Vec::with_capacity(slices.len());
    for slice in slices {
        let f = File::open(slice).with_context(|| format!("opening cgroup {}", slice.display()))?;
        // `Single` here means `link_create.flags == 0`, NOT "only one program".
        // check_prereqs() guarantees kernel >= 5.7, so aya takes the bpf_link
        // path, where the kernel requires the flags field to be zero and applies
        // multi semantics to links internally — so links still coexist with
        // Cilium's cgroup programs. Passing AllowMultiple (BPF_F_ALLOW_MULTI)
        // here is rejected with EINVAL by kernels that predate cgroup-link flag
        // support. Cilium itself attaches its connect4 link with flags == 0.
        let id = prog
            .attach(f, CgroupAttachMode::Single)
            .with_context(|| format!("attaching connect4 to {}", slice.display()))?;
        links.push(prog.take_link(id)?);
        info!(slice = %slice.display(), "cgroup/connect4 attached");
    }
    Ok(links)
}

fn attach_connect6(
    ebpf: &mut Ebpf,
    slices: &[PathBuf],
) -> Result<Vec<aya::programs::cgroup_sock_addr::CgroupSockAddrLink>> {
    let prog: &mut CgroupSockAddr = ebpf
        .program_mut("totan_connect6")
        .ok_or_else(|| anyhow::anyhow!("totan_connect6 program missing in ELF"))?
        .try_into()?;
    prog.load()?;
    let mut links = Vec::with_capacity(slices.len());
    for slice in slices {
        let f = File::open(slice).with_context(|| format!("opening cgroup {}", slice.display()))?;
        let id = prog
            .attach(f, CgroupAttachMode::Single)
            .with_context(|| format!("attaching connect6 to {}", slice.display()))?;
        links.push(prog.take_link(id)?);
        info!(slice = %slice.display(), "cgroup/connect6 attached");
    }
    Ok(links)
}

fn attach_sockops(
    ebpf: &mut Ebpf,
    slices: &[PathBuf],
) -> Result<Vec<aya::programs::sock_ops::SockOpsLink>> {
    let prog: &mut SockOps = ebpf
        .program_mut("totan_sockops")
        .ok_or_else(|| anyhow::anyhow!("totan_sockops program missing in ELF"))?
        .try_into()?;
    prog.load()?;
    let mut links = Vec::with_capacity(slices.len());
    for slice in slices {
        let f = File::open(slice).with_context(|| format!("opening cgroup {}", slice.display()))?;
        let id = prog
            .attach(f, CgroupAttachMode::Single) // flags == 0; see attach_connect4
            .with_context(|| format!("attaching sockops to {}", slice.display()))?;
        links.push(prog.take_link(id)?);
        info!(slice = %slice.display(), "sockops attached");
    }
    Ok(links)
}

/// totan's own cgroup-v2 path from `/proc/self/cgroup`, e.g.
/// `/system.slice/totan.service`. `None` on non-cgroup-v2 / unreadable.
fn totan_self_cgroup() -> Option<String> {
    let content = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    content
        .lines()
        .find_map(|l| l.strip_prefix("0::").map(|p| p.trim().to_string()))
}

/// Map a configured slice path (`/sys/fs/cgroup/system.slice`) to its
/// cgroup-relative form (`/system.slice`).
fn slice_to_cgroup_rel(slice: &Path) -> Option<String> {
    let rel = slice.strip_prefix("/sys/fs/cgroup").ok()?;
    Some(format!(
        "/{}",
        rel.to_string_lossy().trim_start_matches('/')
    ))
}

/// True if `self_cgroup` is `slice_rel` itself or a descendant of it (compared
/// on path segments, so `/system.sliceX` is not "within" `/system.slice`).
fn cgroup_within(self_cgroup: &str, slice_rel: &str) -> bool {
    let slice = slice_rel.trim_end_matches('/');
    self_cgroup == slice || self_cgroup.starts_with(&format!("{slice}/"))
}

/// The first configured slice that totan's own process lives within (or at), if
/// any — meaning host hooks would loop totan's own egress back into itself.
fn totan_self_in_slice(slices: &[PathBuf]) -> Option<PathBuf> {
    let self_cg = totan_self_cgroup()?;
    slices
        .iter()
        .find(|slice| {
            slice_to_cgroup_rel(slice)
                .map(|rel| cgroup_within(&self_cg, &rel))
                .unwrap_or(false)
        })
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_prereqs_does_not_panic() {
        // Smoke test: on CI hosts cgroup v2 is present, on dev hosts it
        // varies. Either Ok or Err is acceptable; the only failure mode
        // we guard against is panic.
        let _ = HostLoader::check_prereqs();
    }

    /// Verifier smoke test for the IPv4/IPv6 cgroup hooks. Loading runs the
    /// verifier without attaching to any cgroup. Requires root (BPF_PROG_LOAD).
    /// Ignored by default; run with:
    ///   sudo -E $(which cargo) test -p totan load_connect4_verifies -- --ignored --nocapture
    #[test]
    #[ignore]
    fn load_connect_hooks_verify() {
        let elf = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/totan_bpf"));
        let mut ebpf = EbpfLoader::new().load(elf).expect("load ELF + maps");
        for name in ["totan_connect4", "totan_connect6"] {
            let prog: &mut CgroupSockAddr = ebpf
                .program_mut(name)
                .unwrap_or_else(|| panic!("{name} present"))
                .try_into()
                .expect("program is CgroupSockAddr");
            prog.load()
                .unwrap_or_else(|error| panic!("{name} must pass verifier: {error}"));
        }
    }

    #[test]
    fn host_hook_config_layout_is_stable() {
        // The kernel verifier rejects struct mismatches between the BPF
        // ELF's BTF and the userspace map definition. Pin the layout.
        assert_eq!(core::mem::size_of::<HostHookConfig>(), 28);
        assert_eq!(core::mem::align_of::<HostHookConfig>(), 4);
    }

    #[test]
    fn cgroup_within_detects_membership() {
        assert!(cgroup_within(
            "/system.slice/totan.service",
            "/system.slice"
        ));
        assert!(cgroup_within("/system.slice", "/system.slice"));
        assert!(cgroup_within(
            "/system.slice/totan.service",
            "/system.slice/"
        ));
        assert!(cgroup_within("/anything", "/")); // root contains everything
        assert!(!cgroup_within("/user.slice/app.service", "/system.slice"));
        // Prefix that is not a path segment must not count as "within".
        assert!(!cgroup_within("/system.sliceX/foo", "/system.slice"));
    }

    #[test]
    fn slice_path_maps_to_cgroup_relative() {
        assert_eq!(
            slice_to_cgroup_rel(Path::new("/sys/fs/cgroup/system.slice")).as_deref(),
            Some("/system.slice")
        );
        assert_eq!(
            slice_to_cgroup_rel(Path::new("/sys/fs/cgroup")).as_deref(),
            Some("/")
        );
    }

    #[test]
    fn original_destination_abi_and_conversion_are_dual_stack() {
        assert_eq!(core::mem::size_of::<OrigDst>(), 24);
        assert_eq!(core::mem::align_of::<OrigDst>(), 4);
        assert_eq!(core::mem::size_of::<SportKey>(), 8);
        assert_eq!(core::mem::align_of::<SportKey>(), 4);

        let ipv4 = OrigDst {
            family: AF_INET,
            addr_be: [u32::from(Ipv4Addr::new(192, 0, 2, 10)).to_be(), 0, 0, 0],
            port_be: 80u16.to_be(),
            _pad: 0,
        };
        assert_eq!(
            ipv4.to_socket_addr().unwrap(),
            "192.0.2.10:80".parse().unwrap()
        );

        let ipv6_addr: Ipv6Addr = "2001:db8::10".parse().unwrap();
        let ipv6 = OrigDst {
            family: AF_INET6,
            addr_be: ipv6_to_be_words(ipv6_addr),
            port_be: 443u16.to_be(),
            _pad: 0,
        };
        assert_eq!(
            ipv6.to_socket_addr().unwrap(),
            "[2001:db8::10]:443".parse().unwrap()
        );
    }

    #[test]
    fn sport_key_includes_address_family() {
        let v4 = SportKey::from_peer("127.0.0.1:12345".parse().unwrap());
        let v6 = SportKey::from_peer("[::1]:12345".parse().unwrap());
        assert_ne!(v4, v6);
        assert_eq!(v4.port_be, v6.port_be);
    }
}
