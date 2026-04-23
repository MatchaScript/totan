//! Automatic nftables rule management for netfilter interception mode.
//!
//! [`NetfilterManager::setup`] installs a `table ip totan` with an OUTPUT
//! nat hook that redirects outbound TCP traffic on the configured ports to
//! totan's listener. Packets already marked with `cfg.fwmark` via `SO_MARK`
//! (set on totan's own upstream sockets) are returned early, preventing
//! redirect loops regardless of which user the process runs as. RFC-1918 and
//! loopback destinations are also excluded.
//!
//! Rules are removed when [`NetfilterManager`] is dropped, so Ctrl-C or a
//! normal process exit always leaves the system clean.

use std::io::Write as _;
use std::process::{Command, Stdio};

use anyhow::Result;
use tracing::{info, warn};

use totan_common::config::NetfilterConfig;

const TABLE: &str = "totan";

const PRIVATE_NETS: &str =
    "127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16";

/// RAII guard that installs nftables rules on construction and removes them
/// on drop.
pub struct NetfilterManager;

impl NetfilterManager {
    /// Install redirect rules.
    ///
    /// Returns `None` when `cfg.manage_rules` is false (caller manages rules).
    pub fn setup(listen_port: u16, cfg: &NetfilterConfig) -> Result<Option<Self>> {
        if !cfg.manage_rules {
            return Ok(None);
        }

        let fwmark = cfg.fwmark;
        let port_set = cfg
            .redirect_ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(", ");

        // Remove any stale table left by a previous crash, then create fresh.
        nft(&format!("delete table ip {TABLE}")).ok();

        nft(&format!(
            "table ip {TABLE} {{\
             \n\tchain output {{\
             \n\t\ttype nat hook output priority -100; policy accept;\
             \n\t\tmeta mark {fwmark:#010x} return\
             \n\t\tip daddr {{ {PRIVATE_NETS} }} return\
             \n\t\ttcp dport {{ {port_set} }} redirect to :{listen_port}\
             \n\t}}\
             \n}}"
        ))?;

        info!(
            fwmark,
            ports = ?cfg.redirect_ports,
            listen_port,
            "nftables redirect rules installed"
        );
        Ok(Some(Self))
    }
}

impl Drop for NetfilterManager {
    fn drop(&mut self) {
        match nft(&format!("delete table ip {TABLE}")) {
            Ok(_) => info!("nftables table {TABLE} removed"),
            Err(e) => warn!("Failed to remove nftables table {TABLE}: {e}"),
        }
    }
}

fn nft(script: &str) -> Result<()> {
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to spawn nft: {e}"))?;

    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(script.as_bytes())?;

    let output = child.wait_with_output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("nft script failed:\n{script}\n{stderr}"));
    }
    Ok(())
}
