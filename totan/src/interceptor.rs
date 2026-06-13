use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use totan_common::{config::TotanConfig, InterceptionMode};
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
        match self.config.interception_mode {
            InterceptionMode::Netfilter => self.run_netfilter(connection_manager).await,
            #[cfg(feature = "ebpf")]
            InterceptionMode::Ebpf => self.run_ebpf(connection_manager).await,
        }
    }

    async fn run_netfilter(self, connection_manager: Arc<ConnectionManager>) -> Result<()> {
        // Install nftables rules when redirect_uids is configured; the RAII
        // guard removes them on drop (clean shutdown or panic unwind).
        let _nft = crate::netfilter::NetfilterManager::setup(
            self.config.listen_port,
            &self.config.netfilter,
        )?;

        let listener = TcpListener::bind(format!("0.0.0.0:{}", self.config.listen_port)).await?;
        info!(
            "Netfilter interceptor listening on port {}",
            self.config.listen_port
        );

        let limiter = Arc::new(Semaphore::new(self.config.max_connections.max(1)));
        accept_loop(
            listener,
            connection_manager,
            OriginalDstSource::SoOriginalDst,
            limiter,
        )
        .await
    }

    #[cfg(feature = "ebpf")]
    async fn run_ebpf(self, connection_manager: Arc<ConnectionManager>) -> Result<()> {
        use crate::cgroup::HostLoader;
        use crate::ebpf::{resolve_interfaces, Loader};
        use std::net::Ipv4Addr;

        let patterns = self.config.ebpf.ingress_interfaces.clone();
        if patterns.is_empty() {
            anyhow::bail!(
                "`ebpf.ingress_interfaces` must not be empty when interception_mode = ebpf"
            );
        }

        let initial_ifaces = resolve_interfaces(&patterns);
        if initial_ifaces.is_empty() {
            anyhow::bail!(
                "No interfaces matched {:?} — check `ebpf.ingress_interfaces`",
                patterns
            );
        }

        let tproxy_port = self
            .config
            .ebpf
            .tproxy_port
            .unwrap_or(self.config.listen_port);

        // Bind the TPROXY listener *before* attaching the eBPF program so
        // packets that arrive between attach and bind don't hit a "socket not
        // found" path.
        let tproxy_listener = bind_tproxy_listener(Ipv4Addr::LOCALHOST, tproxy_port)?;
        info!(
            "TPROXY listener (IP_TRANSPARENT) on 127.0.0.1:{}",
            tproxy_port
        );

        let fwmark = self.config.ebpf.fwmark;
        let iface_refs: Vec<&str> = initial_ifaces.iter().map(String::as_str).collect();
        let mut tc_loader =
            Loader::load_and_attach(&iface_refs, Ipv4Addr::LOCALHOST, tproxy_port, fwmark)?;

        // Optional cgroup host hooks: load only when the config opts in.
        // Same lifecycle pattern — bind listener first, then attach BPF.
        let host = match &self.config.ebpf.host_hooks {
            Some(hh) => {
                let host_listener =
                    TcpListener::bind(format!("127.0.0.1:{}", hh.redirect_port)).await?;
                info!(
                    "Cgroup host-hook listener on 127.0.0.1:{}",
                    hh.redirect_port
                );
                let loader = HostLoader::load_and_attach(
                    &hh.slices,
                    Ipv4Addr::LOCALHOST,
                    hh.redirect_port,
                    crate::cgroup::HOST_HOOK_SELF_MARK,
                )?;
                let source = OriginalDstSource::CgroupSportMap(loader.sport_map());
                Some((loader, host_listener, source))
            }
            None => None,
        };

        // One shared limiter caps total concurrent connections across both
        // accept loops (tc TPROXY + cgroup host hooks).
        let limiter = Arc::new(Semaphore::new(self.config.max_connections.max(1)));

        // Run the accept loop(s) and the interface watcher concurrently.
        // When any branch exits (shutdown or error) the select cancels the
        // others, which drops the loaders and detaches all programs.
        match host {
            Some((_host_loader, host_listener, host_source)) => {
                let cm2 = Arc::clone(&connection_manager);
                let limiter2 = Arc::clone(&limiter);
                tokio::select! {
                    result = accept_loop(tproxy_listener, connection_manager, OriginalDstSource::SkAssign, limiter) => result,
                    result = accept_loop(host_listener, cm2, host_source, limiter2) => result,
                    _ = watch_new_interfaces(&patterns, &mut tc_loader, initial_ifaces) => Ok(()),
                }
            }
            None => {
                tokio::select! {
                    result = accept_loop(tproxy_listener, connection_manager, OriginalDstSource::SkAssign, limiter) => result,
                    _ = watch_new_interfaces(&patterns, &mut tc_loader, initial_ifaces) => Ok(()),
                }
            }
        }
    }
}

/// How to derive `original_dest` from an accepted connection.
#[derive(Clone)]
enum OriginalDstSource {
    /// Netfilter redirect: read `SO_ORIGINAL_DST` off the accepted socket.
    SoOriginalDst,
    /// eBPF `bpf_sk_assign` into an `IP_TRANSPARENT` listener: the original
    /// dst is preserved as the socket's own bound address, so `getsockname()`
    /// (== `TcpStream::local_addr`) is authoritative.
    #[cfg(feature = "ebpf")]
    SkAssign,
    /// Cgroup `connect4` rewrote the dst to a local port; the original dst
    /// was stashed by `sockops` keyed by the ephemeral source port. Look it
    /// up in the BPF map by `peer_addr.port().to_be()`.
    #[cfg(feature = "ebpf")]
    CgroupSportMap(crate::cgroup::SportMap),
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
        OriginalDstSource::SoOriginalDst => so_original_dst(stream),
        #[cfg(feature = "ebpf")]
        OriginalDstSource::SkAssign => stream
            .local_addr()
            .map_err(|e| anyhow::anyhow!("getsockname() failed: {}", e)),
        #[cfg(feature = "ebpf")]
        OriginalDstSource::CgroupSportMap(map) => {
            let peer = stream.peer_addr()?;
            let sport_be = peer.port().to_be();
            let mut guard = map.lock().await;
            let od = guard.get(&sport_be, 0).map_err(|e| {
                anyhow::anyhow!(
                    "no original-dst entry for sport {} (cgroup hook race or non-hooked source?): {}",
                    peer.port(),
                    e
                )
            })?;
            // Eager remove so the LRU stays warm with live entries.
            // sock_release is the safety-net, not the primary cleanup.
            let _ = guard.remove(&sport_be);
            Ok(SocketAddr::V4(std::net::SocketAddrV4::new(
                std::net::Ipv4Addr::from(u32::from_be(od.addr_be)),
                u16::from_be(od.port_be),
            )))
        }
    }
}

fn so_original_dst(stream: &TcpStream) -> Result<SocketAddr> {
    #[cfg(target_os = "linux")]
    {
        use nix::sys::socket::{getsockopt, sockopt::OriginalDst};
        use std::net::SocketAddrV4;
        use std::os::fd::BorrowedFd;
        use std::os::unix::io::AsRawFd;

        let fd = stream.as_raw_fd();
        let borrowed_fd = unsafe { BorrowedFd::borrow_raw(fd) };
        let orig_dst = getsockopt(&borrowed_fd, OriginalDst)?;
        let addr = SocketAddrV4::new(
            std::net::Ipv4Addr::from(orig_dst.sin_addr.s_addr.to_be()),
            orig_dst.sin_port.to_be(),
        );
        Ok(SocketAddr::V4(addr))
    }

    #[cfg(not(target_os = "linux"))]
    {
        stream
            .peer_addr()
            .map_err(|e| anyhow::anyhow!("Cannot get original destination: {}", e))
    }
}

/// Poll `/sys/class/net` every 5 seconds for interfaces that match `patterns`
/// but haven't been attached yet, and attach on discovery.
/// Never returns; cancelled by `tokio::select!` on shutdown.
#[cfg(feature = "ebpf")]
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
            if attached.insert(iface.clone()) {
                if let Err(e) = loader.attach_interface(&iface) {
                    tracing::warn!("Failed to attach to new interface {}: {}", iface, e);
                }
            }
        }
    }
}

/// Build a TPROXY-capable TCP listener bound to `addr:port`. Requires
/// `CAP_NET_ADMIN` (for `IP_TRANSPARENT`).
#[cfg(feature = "ebpf")]
fn bind_tproxy_listener(addr: std::net::Ipv4Addr, port: u16) -> Result<TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    use std::net::SocketAddrV4;

    let sock = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    sock.set_nonblocking(true)?;
    sock.set_reuse_address(true)?;
    set_ip_transparent(&sock)?;
    set_ip_freebind(&sock)?;

    sock.bind(&SocketAddrV4::new(addr, port).into())?;
    sock.listen(1024)?;

    let std_listener: std::net::TcpListener = sock.into();
    std_listener.set_nonblocking(true)?;
    Ok(TcpListener::from_std(std_listener)?)
}

#[cfg(feature = "ebpf")]
fn set_ip_transparent(sock: &socket2::Socket) -> Result<()> {
    use std::os::fd::AsRawFd;
    let enable: libc::c_int = 1;
    // SAFETY: passing a valid fd owned by `sock` and a stack-allocated int.
    let ret = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_TRANSPARENT,
            &enable as *const _ as *const libc::c_void,
            std::mem::size_of_val(&enable) as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error()).map_err(|e| {
            anyhow::anyhow!(
                "IP_TRANSPARENT setsockopt failed (need CAP_NET_ADMIN): {}",
                e
            )
        });
    }
    Ok(())
}

#[cfg(feature = "ebpf")]
fn set_ip_freebind(sock: &socket2::Socket) -> Result<()> {
    use std::os::fd::AsRawFd;
    let enable: libc::c_int = 1;
    // SAFETY: same rationale as `set_ip_transparent`.
    let ret = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_FREEBIND,
            &enable as *const _ as *const libc::c_void,
            std::mem::size_of_val(&enable) as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error())
            .map_err(|e| anyhow::anyhow!("IP_FREEBIND setsockopt failed: {}", e));
    }
    Ok(())
}
