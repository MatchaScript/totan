use anyhow::Result;
use std::sync::Arc;
use tokio::net::TcpListener;
use totan_common::InterceptionMode;
use tracing::{error, info};

use crate::connection::ConnectionManager;

pub struct PacketInterceptor {
    mode: InterceptionMode,
    listen_addr: String,
    port: u16,
}

impl PacketInterceptor {
    pub fn new(mode: InterceptionMode, listen_addr: String, port: u16) -> Result<Self> {
        Ok(Self {
            mode,
            listen_addr,
            port,
        })
    }

    pub async fn run(self, connection_manager: Arc<ConnectionManager>) -> Result<()> {
        match self.mode {
            InterceptionMode::Netfilter => self.run_netfilter(connection_manager).await,
            #[cfg(feature = "ebpf")]
            InterceptionMode::Ebpf => self.run_ebpf(connection_manager).await,
        }
    }

    async fn run_netfilter(self, connection_manager: Arc<ConnectionManager>) -> Result<()> {
        let listener = TcpListener::bind(format!("{}:{}", self.listen_addr, self.port)).await?;
        info!(
            "Netfilter interceptor listening on {}:{}",
            self.listen_addr, self.port
        );

        loop {
            match listener.accept().await {
                Ok((stream, client_addr)) => {
                    let connection_manager = Arc::clone(&connection_manager);

                    tokio::spawn(async move {
                        if let Err(e) = connection_manager
                            .handle_connection(stream, client_addr)
                            .await
                        {
                            error!("Error handling connection from {}: {}", client_addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                    continue;
                }
            }
        }
    }

    #[cfg(feature = "ebpf")]
    async fn run_ebpf(self, _connection_manager: Arc<ConnectionManager>) -> Result<()> {
        // TODO: Implement eBPF-based packet interception
        // This would involve:
        // 1. Loading eBPF program
        // 2. Attaching to appropriate hook points
        // 3. Setting up communication channel with userspace
        // 4. Processing intercepted packets

        Err(anyhow::anyhow!("eBPF mode not yet implemented"))
    }
}
