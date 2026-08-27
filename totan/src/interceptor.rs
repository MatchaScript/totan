use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use totan_common::config::TotanConfig;
use tracing::{error, info};

use crate::connection::ConnectionManager;

pub struct PacketInterceptor {
    config: TotanConfig,
}

impl PacketInterceptor {
    pub fn new(config: TotanConfig) -> Result<Self> {
        Ok(Self { config })
    }

    pub async fn run(self, connection_manager: Arc<ConnectionManager>) -> Result<()> {
        self.run_ebpf(connection_manager).await
    }

    async fn run_ebpf(self, connection_manager: Arc<ConnectionManager>) -> Result<()> {
        // Decide which subsystems to run from configuration alone. Interface
        // *absence* is never fatal here — only the total absence of both tc
        // ingress and host hooks is.
        let plan = resolve_ebpf_plan(
            !self.config.ebpf.ingress_interfaces.is_empty(),
            self.config.ebpf.host_hooks.is_some(),
        )?;

        // One shared limiter caps total concurrent connections across whatever
        // accept loops are active (tc TPROXY + cgroup host hooks).
        let limiter = Arc::new(Semaphore::new(self.config.max_connections.max(1)));

        let mut listeners = Vec::with_capacity(4);
        let mut tc_state = if plan.tc {
            let (tc_listeners, loader, patterns, initial) = setup_tc(&self.config)?;
            listeners.extend(tc_listeners);
            Some((loader, patterns, initial))
        } else {
            None
        };
        // Kept alive for RAII detach while the accept loops run.
        let _host_loader = if plan.host {
            let (loader, host_listeners) = setup_host(&self.config)?;
            listeners.extend(host_listeners);
            Some(loader)
        } else {
            None
        };

        let accept_loops = run_accept_loops(listeners, connection_manager, limiter);
        if let Some((loader, patterns, initial)) = tc_state.as_mut() {
            tokio::select! {
                result = accept_loops => result,
                _ = watch_new_interfaces(patterns, loader, std::mem::take(initial)) => Ok(()),
            }
        } else {
            accept_loops.await
        }
    }
}

/// Which eBPF subsystems to run, decided from configuration alone (before any
/// interface resolution). Interface *absence* is never fatal — only the total
/// absence of both subsystems is.
#[derive(Debug, PartialEq, Eq)]
struct EbpfPlan {
    tc: bool,
    host: bool,
}

fn resolve_ebpf_plan(interfaces_configured: bool, host_configured: bool) -> Result<EbpfPlan> {
    if !interfaces_configured && !host_configured {
        anyhow::bail!(
            "nothing to intercept: set `ebpf.ingress_interfaces` and/or `ebpf.host_hooks`"
        );
    }
    Ok(EbpfPlan {
        tc: interfaces_configured,
        host: host_configured,
    })
}

/// Set up the tc ingress subsystem: bind the TPROXY listener, attach the tc
/// program to whatever interfaces currently match (possibly none — the watcher
/// attaches the rest as they appear). The returned `Loader` must outlive the
/// accept loop so RAII detaches the program on shutdown.
type TcSetup = (
    Vec<(TcpListener, OriginalDstSource)>,
    crate::ebpf::Loader,
    Vec<String>,
    Vec<String>,
);

fn setup_tc(config: &TotanConfig) -> Result<TcSetup> {
    use crate::ebpf::{resolve_interfaces, Loader};
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    let patterns = config.ebpf.ingress_interfaces.clone();
    let initial = resolve_interfaces(&patterns);
    if initial.is_empty() {
        tracing::warn!(
            patterns = ?patterns,
            "no interfaces match yet; starting with none and watching for new ones"
        );
    }
    let tproxy_port = config.ebpf.tproxy_port.unwrap_or(config.listen_port);

    // Bind the TPROXY listener *before* attaching the eBPF program so packets
    // that arrive between attach and bind don't hit a "socket not found" path.
    let listener_v4 = bind_listener(
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, tproxy_port)),
        true,
    )?;
    let listener_v6 = bind_listener(
        SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, tproxy_port, 0, 0)),
        true,
    )?;
    info!(
        "TPROXY listeners (IP_TRANSPARENT) on 127.0.0.1:{} and [::1]:{}",
        tproxy_port, tproxy_port
    );

    let iface_refs: Vec<&str> = initial.iter().map(String::as_str).collect();
    let loader = Loader::load_and_attach(
        &iface_refs,
        Ipv4Addr::LOCALHOST,
        Ipv6Addr::LOCALHOST,
        tproxy_port,
        config.ebpf.fwmark,
    )?;
    Ok((
        vec![
            (listener_v4, OriginalDstSource::SkAssign),
            (listener_v6, OriginalDstSource::SkAssign),
        ],
        loader,
        patterns,
        initial,
    ))
}

/// Set up the cgroup host-hook subsystem: bind the redirect listener, then
/// attach `connect4`/`sockops` to the configured slices.
fn setup_host(
    config: &TotanConfig,
) -> Result<(
    crate::cgroup::HostLoader,
    Vec<(TcpListener, OriginalDstSource)>,
)> {
    use crate::cgroup::HostLoader;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    let hh = config
        .ebpf
        .host_hooks
        .as_ref()
        .expect("host plan implies host_hooks is Some");
    let listener_v4 = bind_listener(
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, hh.redirect_port)),
        false,
    )?;
    let listener_v6 = bind_listener(
        SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::LOCALHOST,
            hh.redirect_port,
            0,
            0,
        )),
        false,
    )?;
    info!(
        "Cgroup host-hook listeners on 127.0.0.1:{} and [::1]:{}",
        hh.redirect_port, hh.redirect_port
    );
    let loader = HostLoader::load_and_attach(
        &hh.slices,
        Ipv4Addr::LOCALHOST,
        Ipv6Addr::LOCALHOST,
        hh.redirect_port,
        crate::ebpf::DEFAULT_SELF_MARK,
    )?;
    let source = OriginalDstSource::CgroupSportMap(loader.sport_map());
    Ok((
        loader,
        vec![(listener_v4, source.clone()), (listener_v6, source)],
    ))
}

/// How to derive `original_dest` from an accepted connection.
#[derive(Clone)]
enum OriginalDstSource {
    /// eBPF `bpf_sk_assign` into an `IP_TRANSPARENT` listener: the original
    /// dst is preserved as the socket's own bound address, so `getsockname()`
    /// (== `TcpStream::local_addr`) is authoritative.
    SkAssign,
    /// Cgroup `connect4`/`connect6` rewrote the dst to a local port; the original dst
    /// was stashed by `sockops` keyed by the ephemeral source port. Look it
    /// up in the BPF map by `peer_addr.port().to_be()`.
    CgroupSportMap(crate::cgroup::SportMap),
}

async fn run_accept_loops(
    listeners: Vec<(TcpListener, OriginalDstSource)>,
    connection_manager: Arc<ConnectionManager>,
    limiter: Arc<Semaphore>,
) -> Result<()> {
    let mut tasks = tokio::task::JoinSet::new();
    for (listener, source) in listeners {
        tasks.spawn(accept_loop(
            listener,
            Arc::clone(&connection_manager),
            source,
            Arc::clone(&limiter),
        ));
    }

    match tasks.join_next().await {
        Some(Ok(result)) => result,
        Some(Err(error)) => Err(anyhow::anyhow!("accept loop task failed: {error}")),
        None => Err(anyhow::anyhow!("no interception listeners configured")),
    }
}

async fn accept_loop(
    listener: TcpListener,
    connection_manager: Arc<ConnectionManager>,
    source: OriginalDstSource,
    limiter: Arc<Semaphore>,
) -> Result<()> {
    loop {
        // Acquire a slot *before* accepting so that at capacity we apply
        // backpressure (the kernel holds pending SYNs in the listen backlog)
        // instead of spawning per-connection tasks without bound until EMFILE.
        let permit = Arc::clone(&limiter)
            .acquire_owned()
            .await
            .expect("connection semaphore is never closed");
        match listener.accept().await {
            Ok((stream, client_addr)) => {
                let connection_manager = Arc::clone(&connection_manager);
                let source = source.clone();

                tokio::spawn(async move {
                    // Held for the connection's lifetime; released on completion.
                    let _permit = permit;
                    let original_dest = match resolve_original_dest(&stream, &source).await {
                        Ok(addr) => addr,
                        Err(e) => {
                            error!(
                                "Failed to resolve original destination for {}: {}",
                                client_addr, e
                            );
                            return;
                        }
                    };

                    if let Err(e) = connection_manager
                        .handle_connection(stream, client_addr, original_dest)
                        .await
                    {
                        error!("Error handling connection from {}: {}", client_addr, e);
                    }
                });
            }
            Err(e) => {
                drop(permit);
                error!("Failed to accept connection: {}", e);
                // Back off briefly to avoid spinning at 100% CPU on persistent
                // errors such as EMFILE (too many open files).
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }
    }
}

async fn resolve_original_dest(
    stream: &TcpStream,
    source: &OriginalDstSource,
) -> Result<SocketAddr> {
    match source {
        OriginalDstSource::SkAssign => stream
            .local_addr()
            .map_err(|e| anyhow::anyhow!("getsockname() failed: {}", e)),
        OriginalDstSource::CgroupSportMap(map) => {
            let peer = stream.peer_addr()?;
            let key = crate::cgroup::SportKey::from_peer(peer);
            let mut guard = map.lock().await;
            let od = guard.get(&key, 0).map_err(|e| {
                anyhow::anyhow!(
                    "no original-dst entry for peer {} (cgroup hook race or non-hooked source?): {}",
                    peer,
                    e
                )
            })?;
            // Eager remove so the LRU stays warm with live entries. This is
            // the only cleanup path: entries for connections that are never
            // accepted age out of the LRU map instead.
            let _ = guard.remove(&key);
            od.to_socket_addr()
        }
    }
}

/// Poll `/sys/class/net` every 5 seconds for interfaces that match `patterns`
/// but haven't been attached yet, and attach on discovery.
/// Never returns; cancelled by `tokio::select!` on shutdown.
async fn watch_new_interfaces(
    patterns: &[String],
    loader: &mut crate::ebpf::Loader,
    initial: Vec<String>,
) {
    use crate::ebpf::resolve_interfaces;
    use std::collections::HashSet;

    let mut attached: HashSet<String> = initial.into_iter().collect();
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
    interval.tick().await; // skip the immediate first tick
    loop {
        interval.tick().await;
        for iface in resolve_interfaces(patterns) {
            if !attached.contains(&iface) {
                match loader.attach_interface(&iface) {
                    Ok(()) => {
                        attached.insert(iface);
                    }
                    Err(e) => {
                        tracing::warn!("Failed to attach to new interface {}: {}", iface, e);
                    }
                }
            }
        }
    }
}

/// Build a family-specific listener. IPv6 sockets are forced to v6-only so
/// IPv4 and IPv6 can bind the same port without platform-default ambiguity.
fn bind_listener(addr: SocketAddr, transparent: bool) -> Result<TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};

    let ipv6 = addr.is_ipv6();
    let domain = if ipv6 { Domain::IPV6 } else { Domain::IPV4 };
    let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    sock.set_nonblocking(true)?;
    sock.set_reuse_address(true)?;
    if ipv6 {
        sock.set_only_v6(true)?;
    }
    if transparent {
        set_ip_transparent(&sock, ipv6)?;
        set_ip_freebind(&sock, ipv6)?;
    }

    sock.bind(&addr.into())?;
    sock.listen(1024)?;

    let std_listener: std::net::TcpListener = sock.into();
    std_listener.set_nonblocking(true)?;
    Ok(TcpListener::from_std(std_listener)?)
}

fn set_ip_transparent(sock: &socket2::Socket, ipv6: bool) -> Result<()> {
    use std::os::fd::AsRawFd;
    let enable: libc::c_int = 1;
    // SAFETY: passing a valid fd owned by `sock` and a stack-allocated int.
    let ret = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            if ipv6 {
                libc::IPPROTO_IPV6
            } else {
                libc::IPPROTO_IP
            },
            if ipv6 {
                libc::IPV6_TRANSPARENT
            } else {
                libc::IP_TRANSPARENT
            },
            &enable as *const _ as *const libc::c_void,
            std::mem::size_of_val(&enable) as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error()).map_err(|e| {
            anyhow::anyhow!(
                "{} setsockopt failed (need CAP_NET_ADMIN): {}",
                if ipv6 {
                    "IPV6_TRANSPARENT"
                } else {
                    "IP_TRANSPARENT"
                },
                e
            )
        });
    }
    Ok(())
}

fn set_ip_freebind(sock: &socket2::Socket, ipv6: bool) -> Result<()> {
    use std::os::fd::AsRawFd;
    let enable: libc::c_int = 1;
    // SAFETY: same rationale as `set_ip_transparent`.
    let ret = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            if ipv6 {
                libc::IPPROTO_IPV6
            } else {
                libc::IPPROTO_IP
            },
            if ipv6 {
                libc::IPV6_FREEBIND
            } else {
                libc::IP_FREEBIND
            },
            &enable as *const _ as *const libc::c_void,
            std::mem::size_of_val(&enable) as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error()).map_err(|e| {
            anyhow::anyhow!(
                "{} setsockopt failed: {}",
                if ipv6 { "IPV6_FREEBIND" } else { "IP_FREEBIND" },
                e
            )
        });
    }
    Ok(())
}

#[cfg(test)]
mod plan_tests {
    use super::{resolve_ebpf_plan, EbpfPlan};

    #[test]
    fn tc_and_host() {
        assert_eq!(
            resolve_ebpf_plan(true, true).unwrap(),
            EbpfPlan {
                tc: true,
                host: true
            }
        );
    }

    #[test]
    fn tc_only() {
        assert_eq!(
            resolve_ebpf_plan(true, false).unwrap(),
            EbpfPlan {
                tc: true,
                host: false
            }
        );
    }

    #[test]
    fn host_only() {
        assert_eq!(
            resolve_ebpf_plan(false, true).unwrap(),
            EbpfPlan {
                tc: false,
                host: true
            }
        );
    }

    #[test]
    fn neither_is_error() {
        assert!(resolve_ebpf_plan(false, false).is_err());
    }
}

#[cfg(test)]
mod listener_tests {
    use super::bind_listener;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

    #[tokio::test]
    async fn ipv4_and_ipv6_listeners_can_share_a_port() {
        let ipv4 = bind_listener(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
            false,
        )
        .unwrap();
        let port = ipv4.local_addr().unwrap().port();
        let ipv6 = bind_listener(
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, port, 0, 0)),
            false,
        )
        .unwrap();

        assert_eq!(ipv4.local_addr().unwrap().port(), port);
        assert_eq!(ipv6.local_addr().unwrap().port(), port);
    }
}
