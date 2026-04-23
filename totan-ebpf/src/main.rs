//! totan-ebpf — tc ingress classifier for transparent TCP/80 and TCP/443 proxy.
//!
//! **Flow overview**
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

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{bpf_sock_tuple, TC_ACT_OK},
    helpers::gen::{bpf_sk_assign, bpf_sk_release, bpf_skc_lookup_tcp},
    macros::{classifier, map},
    maps::Array,
    programs::TcContext,
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

/// `BPF_F_CURRENT_NETNS` (-1L cast to u64): look up socket in the current netns.
const BPF_F_CURRENT_NETNS: u64 = u64::MAX;

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
    if (ipv4.ihl() as usize) * 4 != Ipv4Hdr::LEN {
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

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// GPL license section required for bpf_sk_assign and bpf_skc_lookup_tcp helpers.
#[link_section = "license"]
#[used]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
