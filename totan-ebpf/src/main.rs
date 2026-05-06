//! totan-ebpf — kernel-side BPF programs for transparent TCP/80 and TCP/443 proxy.
//!
//! Two independent interception subsystems share this ELF:
//!
//! ## Subsystem A: tc ingress for client-originated traffic (pod / VM)
//!
//! 1. Packet from a client (e.g. pod, container) arrives on the host side of
//!    the pair device (veth / netkit) where this program is attached as tcx
//!    ingress.
//! 2. If dst port is 80 or 443, look up the TPROXY listener socket via
//!    `bpf_skc_lookup_tcp`.
//! 3. Assign the socket with `bpf_sk_assign` and set `skb->mark` to the
//!    configured fwmark, then return `TC_ACT_OK` so the packet continues into
//!    the IP stack.
//! 4. Userspace policy routing (`ip rule fwmark <N> lookup 100` +
//!    `ip route add local 0.0.0.0/0 dev lo table 100`) makes the kernel treat
//!    the packet as locally destined; `tcp_v4_rcv` then picks up the
//!    pre-assigned socket via `__inet_lookup_skb` and delivers the SYN to the
//!    TPROXY listener.
//!
//! `bpf_sk_assign` is **tc-ingress only** at the kernel level
//! (`net/core/filter.c`: `if (!skb_at_tc_ingress(skb)) return -EOPNOTSUPP;`).
//! Attaching this program to tc egress would make every `sk_assign` call
//! return -95 and the interception would silently no-op.
//!
//! ## Subsystem B: cgroup hooks for host-originated traffic
//!
//! tc ingress only catches packets traversing a tc hook on the host. Host
//! processes (kubelet, containerd, dnf, ssh sessions) emit packets directly
//! via the physical NIC's egress and never hit any `lxc*` ingress, so they
//! would escape totan entirely. To capture them we hook `connect(2)` itself
//! at the cgroup layer:
//!
//! 1. `cgroup/connect4` (`totan_connect4`) fires before the kernel issues
//!    the SYN. It saves the original (`user_ip4`, `user_port`) keyed by
//!    socket cookie, then rewrites those fields to `127.0.0.1:redirect_port`
//!    so the kernel actually connects to the local listener.
//! 2. `sockops` (`totan_sockops`) fires at `BPF_SOCK_OPS_TCP_CONNECT_CB`
//!    once the kernel has bound an ephemeral source port. It re-keys the
//!    saved original-dst from cookie → ephemeral source port (host byte
//!    order) so userspace can recover it via `peer_addr.port()`.
//! 3. `cgroup/sock_release` (`totan_sock_release`) evicts the sport entry
//!    when the kernel destroys the socket. The accept loop also evicts
//!    eagerly after reading; this hook is the safety net for connections
//!    where accept never read the entry.
//!
//! Pattern lifted from Cilium socketLB (`reference/cilium/bpf/bpf_sock.c`),
//! adapted for the transparent-proxy case where userspace **must** know the
//! original destination (whereas Cilium hides it in the kernel via
//! `cgroup/recvmsg4` reverse-NAT).

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{bpf_sock_tuple, TC_ACT_OK},
    helpers::gen::{bpf_get_socket_cookie, bpf_sk_assign, bpf_sk_release, bpf_skc_lookup_tcp},
    macros::{cgroup_sock, cgroup_sock_addr, classifier, map, sock_ops},
    maps::{Array, LruHashMap},
    programs::{SockAddrContext, SockContext, SockOpsContext, TcContext},
};
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
};

/// Layout-compatible mirror of the userspace `TproxyConfig` in
/// `totan/src/ebpf.rs`. Both sides must be updated together.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct TproxyConfig {
    /// Listener IPv4 address in network byte order (127.0.0.1 → 0x0100007F).
    pub tproxy_ipv4_be: u32,
    /// Listener TCP port in network byte order.
    pub tproxy_port_be: u16,
    pub _pad0: u16,
    /// fwmark placed on matched packets. Userspace must configure
    /// `ip rule fwmark <N> lookup 100` + `ip route local 0.0.0.0/0 dev lo`
    /// so the mark triggers local delivery instead of forwarding.
    pub fwmark: u32,
    pub _pad1: u32,
}

#[map(name = "TOTAN_CONFIG")]
static TOTAN_CONFIG: Array<TproxyConfig> = Array::<TproxyConfig>::with_max_entries(1, 0);

/// Mirror of the userspace `HostHookConfig` in `totan/src/cgroup.rs`.
/// Both sides MUST be updated together.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct HostHookConfig {
    /// Redirect target IPv4 in network byte order (typically 127.0.0.1 → 0x0100007F).
    pub redirect_ipv4_be: u32,
    /// Redirect target TCP port in network byte order.
    pub redirect_port_be: u16,
    pub _pad: u16,
}

#[map(name = "TOTAN_HOST_CFG")]
static TOTAN_HOST_CFG: Array<HostHookConfig> = Array::<HostHookConfig>::with_max_entries(1, 0);

/// Original destination preserved across the cgroup hook → sockops → accept
/// pipeline. Layout-compatible with the userspace `OrigDst` in
/// `totan/src/cgroup.rs`.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct OrigDst {
    /// Original destination IPv4 in network byte order.
    pub addr_be: u32,
    /// Original destination port in network byte order.
    pub port_be: u16,
    pub _pad: u16,
}

/// Stage 1: connect4 stores `socket_cookie -> OrigDst`. The cookie is the
/// only stable identifier available before the kernel has bound an
/// ephemeral source port. LRU evicts stale entries automatically — pattern
/// from Cilium `cilium_lb4_reverse_sk` (`bpf/lib/sock.h`).
#[map(name = "TOTAN_OD_BY_COOKIE")]
static TOTAN_OD_BY_COOKIE: LruHashMap<u64, OrigDst> =
    LruHashMap::<u64, OrigDst>::with_max_entries(65536, 0);

/// Stage 2: sockops re-keys to `sport_be -> OrigDst` once the kernel has
/// bound the ephemeral source port. Userspace accept reads `peer_addr.port()`
/// from the accepted localhost connection, converts it to network byte
/// order, and looks it up here.
#[map(name = "TOTAN_OD_BY_SPORT")]
static TOTAN_OD_BY_SPORT: LruHashMap<u16, OrigDst> =
    LruHashMap::<u16, OrigDst>::with_max_entries(65536, 0);

/// `BPF_F_CURRENT_NETNS` (-1L cast to u64): look up socket in the current netns.
const BPF_F_CURRENT_NETNS: u64 = u64::MAX;

/// Linux ABI: SOCK_STREAM = 1.
const SOCK_STREAM: u32 = 1;

/// `bpf_sock_addr->type` is set for connect4; for AF_INET non-TCP we bail
/// to keep UDP/QUIC out of the rewrite path.
const IPPROTO_TCP: u32 = 6;

/// sockops `op` codes from `include/uapi/linux/bpf.h`.
const BPF_SOCK_OPS_TCP_CONNECT_CB: u32 = 3;

#[classifier]
pub fn totan_tc_ingress(ctx: TcContext) -> i32 {
    try_ingress(&ctx).unwrap_or(TC_ACT_OK as i32)
}

#[inline(always)]
fn try_ingress(ctx: &TcContext) -> Result<i32, ()> {
    let eth: EthHdr = ctx.load(0).map_err(|_| ())?;
    // Copy out the packed field before comparing — taking &eth.ether_type
    // on a #[repr(C, packed)] struct is UB under rustc ≥ 1.94 (E0793).
    let ether_type = eth.ether_type;
    if ether_type != EtherType::Ipv4.into() {
        return Ok(TC_ACT_OK as i32);
    }

    let ipv4: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
    if ipv4.proto != IpProto::Tcp.into() {
        return Ok(TC_ACT_OK as i32);
    }

    // Bail on IPv4 options (IHL > 5); the TcpHdr offset would shift and we'd
    // parse garbage. Standard HTTP/HTTPS traffic never carries IP options.
    if ipv4.ihl() as usize != Ipv4Hdr::LEN {
        return Ok(TC_ACT_OK as i32);
    }

    let tcp: TcpHdr = ctx.load(EthHdr::LEN + Ipv4Hdr::LEN).map_err(|_| ())?;
    let dst_port = u16::from_be_bytes(tcp.dest);
    if dst_port != 80 && dst_port != 443 {
        return Ok(TC_ACT_OK as i32);
    }

    let cfg = TOTAN_CONFIG.get(0).ok_or(())?;
    let raw_skb: *mut aya_ebpf::bindings::__sk_buff = ctx.skb.skb;
    let skb: *mut core::ffi::c_void = raw_skb as *mut _;

    // Tag every matching packet so the fwmark policy rule routes it to
    // `local 0.0.0.0/0 dev lo` — otherwise the kernel tries to forward
    // packets addressed to the external dst and drops them.
    unsafe { (*raw_skb).mark = cfg.fwmark };

    // Only hijack the initial SYN via sk_assign(listener). Once the SYN is
    // assigned, the kernel creates a reqsk in its ehash keyed on the full
    // 4-tuple; subsequent packets (ACK / data / FIN) are found by the
    // standard ehash lookup — first as TCP_NEW_SYN_RECV, then as the child
    // TCP_ESTABLISHED socket — as long as they carry the fwmark that keeps
    // them on the local-delivery path.
    //
    // Forcing sk_assign(listener) on a pure ACK would hand the packet to
    // tcp_rcv_state_process() in TCP_LISTEN state, which treats "ACK without
    // SYN" as invalid and triggers a RST, blowing up the connection.
    if tcp.syn() == 0 || tcp.ack() != 0 {
        return Ok(TC_ACT_OK as i32);
    }

    // Build a 4-tuple keyed only on the listener (src fields zeroed): this
    // matches the passively-listening TPROXY socket regardless of the flow.
    let mut tuple: bpf_sock_tuple = unsafe { mem::zeroed() };
    // Writes to Copy union fields are safe (RFC 1444); no unsafe block needed.
    tuple.__bindgen_anon_1.ipv4.saddr = 0;
    tuple.__bindgen_anon_1.ipv4.sport = 0;
    tuple.__bindgen_anon_1.ipv4.daddr = cfg.tproxy_ipv4_be;
    tuple.__bindgen_anon_1.ipv4.dport = cfg.tproxy_port_be;
    let tuple_size = mem::size_of_val(unsafe { &tuple.__bindgen_anon_1.ipv4 }) as u32;

    let sk = unsafe {
        bpf_skc_lookup_tcp(
            skb,
            &mut tuple as *mut bpf_sock_tuple,
            tuple_size,
            BPF_F_CURRENT_NETNS,
            0,
        )
    };
    if sk.is_null() {
        return Ok(TC_ACT_OK as i32);
    }

    let _ = unsafe { bpf_sk_assign(skb, sk as *mut _, 0) };
    unsafe { bpf_sk_release(sk as *mut _) };

    Ok(TC_ACT_OK as i32)
}

// ---------------------------------------------------------------------------
// Subsystem B: cgroup hooks for host-originated traffic
// ---------------------------------------------------------------------------

/// `cgroup/connect4` fires from `__cgroup_bpf_run_filter_sock_addr` during
/// `connect(2)` for IPv4 sockets in the attached cgroup. Returning 1 lets
/// connect proceed with the (possibly mutated) sockaddr; 0 makes the kernel
/// return -EPERM. We always return 1 so non-matching connections are
/// untouched.
#[cgroup_sock_addr(connect4)]
pub fn totan_connect4(ctx: SockAddrContext) -> i32 {
    try_connect4(&ctx).unwrap_or(1)
}

#[inline(always)]
fn try_connect4(ctx: &SockAddrContext) -> Result<i32, ()> {
    // SAFETY: ctx.sock_addr is a valid kernel-managed pointer for the
    // lifetime of the hook invocation. All accesses below are on
    // kernel-provided memory; no userspace pointers are dereferenced.
    let sa = unsafe { &mut *ctx.sock_addr };

    // Filter: TCP only.
    if sa.type_ != SOCK_STREAM || sa.protocol != IPPROTO_TCP {
        return Ok(1);
    }

    // Read user_port through a volatile to placate the verifier's narrow-
    // access check on the kernel context. Pattern from Cilium
    // `bpf/bpf_sock.c:50-72` (`ctx_dst_port`). user_port is stored in
    // network byte order despite the __u32 type.
    let raw_user_port: u32 = unsafe { core::ptr::read_volatile(&sa.user_port as *const u32) };
    let dst_port_be: u16 = raw_user_port as u16;
    let dst_port_host = u16::from_be(dst_port_be);
    if dst_port_host != 80 && dst_port_host != 443 {
        return Ok(1);
    }

    let cfg = TOTAN_HOST_CFG.get(0).ok_or(())?;

    let orig = OrigDst {
        addr_be: sa.user_ip4,
        port_be: dst_port_be,
        _pad: 0,
    };
    let cookie = unsafe { bpf_get_socket_cookie(ctx.sock_addr as *mut _) };

    // Best-effort insert; the LRU evicts on pressure so insert never fails
    // for capacity reasons, only for verifier/permission errors.
    let _ = TOTAN_OD_BY_COOKIE.insert(&cookie, &orig, 0);

    // Rewrite destination to the local listener.
    sa.user_ip4 = cfg.redirect_ipv4_be;
    sa.user_port = u32::from(cfg.redirect_port_be);

    Ok(1)
}

/// Sockops re-keys cookie → ephemeral source port at active-connect time.
/// The cgroup must be the same one we attached `connect4` to so the cookie
/// matches.
#[sock_ops]
pub fn totan_sockops(ctx: SockOpsContext) -> u32 {
    let _ = try_sockops(&ctx);
    0
}

#[inline(always)]
fn try_sockops(ctx: &SockOpsContext) -> Result<(), ()> {
    if ctx.op() != BPF_SOCK_OPS_TCP_CONNECT_CB {
        return Ok(());
    }
    let cookie = unsafe { bpf_get_socket_cookie(ctx.ops as *mut _) };
    // SAFETY: LruHashMap::get returns a reference valid for the program
    // duration; we copy out before any mutation.
    let orig = match unsafe { TOTAN_OD_BY_COOKIE.get(&cookie) } {
        Some(v) => *v,
        None => return Ok(()), // not one of ours
    };
    // local_port is host byte order; map key is network byte order to match
    // what userspace gets from `peer_addr.port().to_be()`.
    let sport_be: u16 = (ctx.local_port() as u16).to_be();
    let _ = TOTAN_OD_BY_SPORT.insert(&sport_be, &orig, 0);
    let _ = TOTAN_OD_BY_COOKIE.remove(&cookie);
    Ok(())
}

/// `cgroup/sock_release` fires when the kernel destroys the socket struct.
/// Pattern from Cilium `bpf/bpf_sock.c:1287-1323`. The accept loop's eager
/// `remove()` is the primary cleanup path; this hook is the safety net for
/// connections where accept never read the entry (totan crash mid-flow,
/// connection refused, etc.).
#[cgroup_sock(sock_release)]
pub fn totan_sock_release(ctx: SockContext) -> i32 {
    // SAFETY: ctx.sock is a valid kernel pointer for the hook lifetime.
    let sk = unsafe { &*ctx.sock };
    // src_port is host byte order (per include/uapi/linux/bpf.h);
    // convert to BE to match the map's key encoding.
    let sport_be: u16 = (sk.src_port as u16).to_be();
    let _ = TOTAN_OD_BY_SPORT.remove(&sport_be);
    1 // SK_PASS / proceed
}

// ---------------------------------------------------------------------------

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// GPL license section required for bpf_sk_assign and bpf_skc_lookup_tcp helpers.
#[link_section = "license"]
#[used]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
