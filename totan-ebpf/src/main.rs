//! totan-ebpf — tc egress classifier for transparent TCP/80 and TCP/443 proxy.
//!
//! **Flow overview**
//!
//! 1. Packet leaves a pod via the uplink (tc egress hook).
//! 2. If dst port is 80 or 443, look up the TPROXY listener socket via
//!    `bpf_skc_lookup_tcp`.
//! 3. Assign the socket with `bpf_sk_assign`, set `skb->mark` to the
//!    configured fwmark, then `bpf_redirect(ifindex, BPF_F_INGRESS)` to push
//!    the packet back into the rx path.
//! 4. Userspace must set up policy routing so the fwmark routes all
//!    destinations as local, enabling delivery even for non-local dst IPs:
//!
//!    ```text
//!    ip rule add fwmark <FWMARK> lookup 100 priority 100
//!    ip route add local 0.0.0.0/0 dev lo table 100
//!    ```
//!
//!    Without step 4, `ip_route_input()` won't find a local route for the
//!    external destination and the packet will be forwarded or dropped rather
//!    than delivered to the TPROXY socket.

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{bpf_sock_tuple, TC_ACT_OK},
    helpers::gen::{bpf_redirect, bpf_sk_assign, bpf_sk_release, bpf_skc_lookup_tcp},
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
    /// fwmark placed on matched packets before `bpf_redirect`.
    /// Userspace must configure `ip rule` + `ip route` for this mark.
    pub fwmark: u32,
    pub _pad1: u32,
}

#[map(name = "TOTAN_CONFIG")]
static TOTAN_CONFIG: Array<TproxyConfig> = Array::<TproxyConfig>::with_max_entries(1, 0);

/// `BPF_F_CURRENT_NETNS` (-1L cast to u64): look up socket in the current netns.
const BPF_F_CURRENT_NETNS: u64 = u64::MAX;

/// `BPF_F_INGRESS` (bit 0 of the flags to `bpf_redirect`): redirect into the
/// rx / ingress path of the target interface.
const BPF_F_INGRESS: u64 = 1;

#[classifier]
pub fn totan_tc_egress(ctx: TcContext) -> i32 {
    try_egress(&ctx).unwrap_or(TC_ACT_OK as i32)
}

#[inline(always)]
fn try_egress(ctx: &TcContext) -> Result<i32, ()> {
    let eth: EthHdr = ctx.load(0).map_err(|_| ())?;
    if eth.ether_type != EtherType::Ipv4 {
        return Ok(TC_ACT_OK as i32);
    }

    let ipv4: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
    if ipv4.proto != IpProto::Tcp {
        return Ok(TC_ACT_OK as i32);
    }

    // Bail on IPv4 options (IHL > 5); the TcpHdr offset would shift and we'd
    // parse garbage. Standard HTTP/HTTPS traffic never carries IP options.
    if (ipv4.ihl() as usize) * 4 != Ipv4Hdr::LEN {
        return Ok(TC_ACT_OK as i32);
    }

    let tcp: TcpHdr = ctx.load(EthHdr::LEN + Ipv4Hdr::LEN).map_err(|_| ())?;
    let dst_port = u16::from_be(tcp.dest);
    if dst_port != 80 && dst_port != 443 {
        return Ok(TC_ACT_OK as i32);
    }

    let cfg = TOTAN_CONFIG.get(0).ok_or(())?;

    // Build a 4-tuple keyed only on the listener (src fields zeroed): this
    // matches the passively-listening TPROXY socket regardless of the flow.
    let mut tuple: bpf_sock_tuple = unsafe { mem::zeroed() };
    unsafe {
        tuple.__bindgen_anon_1.ipv4.saddr = 0;
        tuple.__bindgen_anon_1.ipv4.sport = 0;
        tuple.__bindgen_anon_1.ipv4.daddr = cfg.tproxy_ipv4_be;
        tuple.__bindgen_anon_1.ipv4.dport = cfg.tproxy_port_be;
    }
    let tuple_size = mem::size_of_val(unsafe { &tuple.__bindgen_anon_1.ipv4 }) as u32;

    // Keep a typed pointer for field access (mark, ifindex) and a void pointer
    // for the helper FFI calls that take `*mut c_void`.
    let raw_skb: *mut aya_ebpf::bindings::__sk_buff = ctx.skb.skb;
    let skb: *mut core::ffi::c_void = raw_skb as *mut _;

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

    let assign_ret = unsafe { bpf_sk_assign(skb, sk as *mut _, 0) };
    unsafe { bpf_sk_release(sk as *mut _) };

    if assign_ret != 0 {
        // sk_assign can fail if another program already assigned a socket.
        return Ok(TC_ACT_OK as i32);
    }

    // Mark the packet so userspace policy routing (`ip rule fwmark`) routes
    // the redirected ingress copy to the local table. Without this mark,
    // ip_route_input() treats the external dst IP as non-local and forwards
    // the packet away instead of delivering it to the TPROXY socket.
    unsafe { (*raw_skb).mark = cfg.fwmark };

    // Push the packet back into the rx path of the same interface. On ingress,
    // ip_route_input() respects the fwmark policy rule, routes to local, and
    // tcp_v4_rcv() finds the pre-assigned socket via __inet_lookup_skb().
    let ifindex = unsafe { (*raw_skb).ifindex };
    Ok(unsafe { bpf_redirect(ifindex, BPF_F_INGRESS) } as i32)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// GPL license section required for bpf_sk_assign and bpf_redirect helpers.
#[link_section = "license"]
#[used]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
