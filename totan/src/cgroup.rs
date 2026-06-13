//! Cgroup-based interception for host-originated egress.
//!
//! Loads `cgroup/connect4`, `sockops`, and `cgroup/sock_release` BPF
//! programs from the same ELF as the tc ingress classifier (a separate
//! `Ebpf` instance owns the maps independently) and attaches them to the
//! cgroup directories listed in `HostHooksConfig::slices`.
//!
//! The three programs together rewrite outbound `connect(2)` to TCP/80
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
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use aya::{
    include_bytes_aligned,
    maps::{Array, HashMap as AyaHashMap, MapData},
    programs::{CgroupAttachMode, CgroupSock, CgroupSockAddr, SockOps},
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
    pub redirect_port_be: u16,
    pub _pad: u16,
}
// SAFETY: #[repr(C)], all fields are integers, explicit padding zeroes the
// trailing bytes — the kernel verifier sees a fully initialised struct.
unsafe impl aya::Pod for HostHookConfig {}

/// Layout-compatible mirror of the kernel-side `OrigDst`.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct OrigDst {
    pub addr_be: u32,
    pub port_be: u16,
    pub _pad: u16,
}
unsafe impl aya::Pod for OrigDst {}

/// Shared handle into the `TOTAN_OD_BY_SPORT` map. The accept loop calls
/// `lock().await` per accepted connection — contention is minimal because
/// each map op is a single bpf syscall.
pub type SportMap = Arc<Mutex<AyaHashMap<MapData, u16, OrigDst>>>;

/// Owns the loaded ELF, attached cgroup links, and the sport-keyed map.
/// Drop tears down all attachments and the map fd.
pub struct HostLoader {
    _ebpf: Ebpf,
    _connect4_links: Vec<aya::programs::cgroup_sock_addr::CgroupSockAddrLink>,
    _sockops_links: Vec<aya::programs::sock_ops::SockOpsLink>,
    _sock_release_links: Vec<aya::programs::cgroup_sock::CgroupSockLink>,
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
        redirect_addr: Ipv4Addr,
        redirect_port: u16,
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

        // Refuse to attach if totan itself lives inside a hooked slice: connect4
        // would rewrite totan's own :80/:443 egress to the local listener, which
        // re-accepts and reconnects out, looping forever (a self-inflicted DoS).
        // Run totan in a dedicated slice outside the configured host-hook slices.
        if let Some(offending) = totan_self_in_slice(slices) {
            anyhow::bail!(
                "totan is running inside hooked slice {} — connect4 would redirect \
                 totan's own egress into its own listener and loop forever. Run totan \
                 in a slice that is not listed in (or under) `ebpf.host_hooks.slices`.",
                offending.display()
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
                    redirect_ipv4_be: u32::from(redirect_addr).to_be(),
                    redirect_port_be: redirect_port.to_be(),
                    _pad: 0,
                },
                0,
            )?;
        }

        let connect4_links = attach_connect4(&mut ebpf, slices)?;
        let sockops_links = attach_sockops(&mut ebpf, slices)?;
        let sock_release_links = attach_sock_release(&mut ebpf, slices)?;

        // Take ownership of the sport map so the accept loop can consume from it.
        let sport_map_data = ebpf
            .take_map("TOTAN_OD_BY_SPORT")
            .ok_or_else(|| anyhow::anyhow!("TOTAN_OD_BY_SPORT map missing in ELF"))?;
        let sport_map: AyaHashMap<MapData, u16, OrigDst> = AyaHashMap::try_from(sport_map_data)?;

        info!(
            redirect = %format!("{}:{}", redirect_addr, redirect_port),
            slices = slices.len(),
            "totan cgroup host-hooks loaded"
        );

        Ok(Self {
            _ebpf: ebpf,
            _connect4_links: connect4_links,
            _sockops_links: sockops_links,
            _sock_release_links: sock_release_links,
            sport_map: Arc::new(Mutex::new(sport_map)),
        })
    }

    /// Clone-able handle into the sport→OrigDst map.
    pub fn sport_map(&self) -> SportMap {
        self.sport_map.clone()
    }
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

fn attach_sock_release(
    ebpf: &mut Ebpf,
    slices: &[PathBuf],
) -> Result<Vec<aya::programs::cgroup_sock::CgroupSockLink>> {
    let prog: &mut CgroupSock = ebpf
        .program_mut("totan_sock_release")
        .ok_or_else(|| anyhow::anyhow!("totan_sock_release program missing in ELF"))?
        .try_into()?;
    prog.load()?;
    let mut links = Vec::with_capacity(slices.len());
    for slice in slices {
        let f = File::open(slice).with_context(|| format!("opening cgroup {}", slice.display()))?;
        let id = prog
            .attach(f, CgroupAttachMode::Single) // flags == 0; see attach_connect4
            .with_context(|| format!("attaching sock_release to {}", slice.display()))?;
        links.push(prog.take_link(id)?);
        info!(slice = %slice.display(), "cgroup/sock_release attached");
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

    #[test]
    fn host_hook_config_size_is_8_bytes() {
        // The kernel verifier rejects struct mismatches between the BPF
        // ELF's BTF and the userspace map definition. Pin the layout.
        assert_eq!(core::mem::size_of::<HostHookConfig>(), 8);
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
    fn orig_dst_size_is_8_bytes() {
        assert_eq!(core::mem::size_of::<OrigDst>(), 8);
        assert_eq!(core::mem::align_of::<OrigDst>(), 4);
    }
}
