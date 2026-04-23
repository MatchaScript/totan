//! Automatic nftables rule management for netfilter interception mode.
//!
//! [`NetfilterManager::setup`] installs a `table ip totan` with an OUTPUT
//! nat hook that redirects **all** outbound TCP traffic on the configured
//! ports to totan's listener, excluding totan's own UID (auto-detected) to
//! prevent redirect loops and any additional UIDs listed in `exclude_uids`.
//!
//! Rules are removed when [`NetfilterManager`] is dropped, so Ctrl-C or a
//! normal process exit always leaves the system clean.

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
    /// Install redirect rules.
    ///
    /// Returns `None` when `cfg.manage_rules` is false (caller manages rules).
    pub fn setup(listen_port: u16, cfg: &NetfilterConfig) -> Result<Option<Self>> {
        if !cfg.manage_rules {
            return Ok(None);
        }

        let own_uid = nix::unistd::getuid().as_raw();

        // Build the exclude set: totan's own UID + any user-specified UIDs.
        let mut excluded: Vec<u32> = vec![own_uid];
        excluded.extend_from_slice(&cfg.exclude_uids);
        excluded.dedup();
        let exclude_set = excluded
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

        // Remove any stale table left by a previous crash, then create fresh.
        nft(&format!("delete table ip {TABLE}")).ok();

        nft(&format!(
            "table ip {TABLE} {{\
             \n\tchain output {{\
             \n\t\ttype nat hook output priority -100; policy accept;\
             \n\t\tmeta skuid {{ {exclude_set} }} return\
             \n\t\ttcp dport {{ {port_set} }} redirect to :{listen_port}\
             \n\t}}\
             \n}}"
        ))?;

        info!(
            own_uid,
            exclude_uids = ?excluded,
            ports = ?cfg.redirect_ports,
            listen_port,
            "nftables redirect rules installed (all traffic except excluded UIDs)"
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
