//! Automatic nftables rule management for netfilter interception mode.
//!
//! [`NetfilterManager::setup`] installs a `table ip totan` with an OUTPUT
//! nat hook that redirects matching UIDs' TCP traffic to totan's listener.
//! The rules are removed when the [`NetfilterManager`] is dropped, so Ctrl-C
//! or a normal process exit always leaves the system clean.
//!
//! If `redirect_uids` is empty the caller should manage nftables rules
//! externally; `setup` returns `None` in that case.

use std::io::Write as _;
use std::process::{Command, Stdio};

use anyhow::Result;
use tracing::{info, warn};

use totan_common::config::NetfilterConfig;

const TABLE: &str = "totan";

/// RAII guard that installs nftables rules on construction and removes them
/// on drop.
pub struct NetfilterManager;

impl NetfilterManager {
    /// Install redirect rules for the given configuration.
    ///
    /// Returns `None` when `cfg.redirect_uids` is empty (caller manages rules).
    pub fn setup(listen_port: u16, cfg: &NetfilterConfig) -> Result<Option<Self>> {
        if cfg.redirect_uids.is_empty() {
            return Ok(None);
        }

        let uid_set = cfg
            .redirect_uids
            .iter()
            .map(|u| u.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let port_set = cfg
            .redirect_ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(", ");

        // Remove any stale table left by a previous crash before creating ours.
        nft(&format!("delete table ip {TABLE}")).ok();

        nft(&format!(
            "table ip {TABLE} {{\
             \n\tchain output {{\
             \n\t\ttype nat hook output priority -100; policy accept;\
             \n\t\tmeta skuid {{ {uid_set} }} tcp dport {{ {port_set} }} redirect to :{listen_port}\
             \n\t}}\
             \n}}"
        ))?;

        info!(
            uids = ?cfg.redirect_uids,
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

/// Feed `script` to `nft -f -` via stdin.
fn nft(script: &str) -> Result<()> {
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to spawn nft: {e}"))?;

    child
        .stdin
        .as_mut()
        .expect("stdin is piped")
        .write_all(script.as_bytes())?;

    let status = child.wait()?;
    if !status.success() {
        return Err(anyhow::anyhow!("nft script failed:\n{script}"));
    }
    Ok(())
}
