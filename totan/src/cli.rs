use clap::{Parser, ValueEnum};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct CliArgs {
    /// Port to listen on
    #[arg(short, long)]
    pub port: Option<u16>,

    /// Default upstream proxy URL (e.g., http://proxy.example.com:8080)
    #[arg(long)]
    pub proxy: Option<String>,

    /// Path to PAC file for dynamic proxy resolution
    #[arg(long)]
    pub pac_file: Option<PathBuf>,

    /// PAC result cache TTL in seconds (0 disables caching)
    #[arg(long)]
    pub pac_cache_ttl: Option<u64>,

    /// PAC result cache maximum number of entries
    #[arg(long)]
    pub pac_cache_size: Option<usize>,

    /// Packet interception mode
    #[arg(short, long, value_enum)]
    pub mode: Option<InterceptionModeArg>,

    /// Configuration file path
    #[arg(short, long)]
    pub config: Option<PathBuf>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long)]
    pub log_level: Option<String>,

    /// Log format: text or json
    #[arg(long)]
    pub log_format: Option<String>,
}

#[derive(Clone, Debug, ValueEnum)]
pub enum InterceptionModeArg {
    Netfilter,
    #[cfg(feature = "ebpf")]
    Ebpf,
}

impl From<InterceptionModeArg> for totan_common::InterceptionMode {
    fn from(mode: InterceptionModeArg) -> Self {
        match mode {
            InterceptionModeArg::Netfilter => totan_common::InterceptionMode::Netfilter,
            #[cfg(feature = "ebpf")]
            InterceptionModeArg::Ebpf => totan_common::InterceptionMode::Ebpf,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn test_cli_parsing_basic() {
        let args = CliArgs::try_parse_from([
            "totan",
            "--port",
            "8080",
            "--proxy",
            "http://localhost:3128",
        ])
        .unwrap();
        assert_eq!(args.port, Some(8080));
        assert_eq!(args.proxy, Some("http://localhost:3128".to_string()));
    }

    #[test]
    fn test_cli_parsing_pac() {
        let args = CliArgs::try_parse_from([
            "totan",
            "--pac-file",
            "/etc/proxy.pac",
            "--pac-cache-ttl",
            "300",
        ])
        .unwrap();
        assert_eq!(args.pac_file, Some(PathBuf::from("/etc/proxy.pac")));
        assert_eq!(args.pac_cache_ttl, Some(300));
    }

    #[test]
    fn test_cli_parsing_mode() {
        let args = CliArgs::try_parse_from(["totan", "--mode", "netfilter"]).unwrap();
        match args.mode {
            Some(InterceptionModeArg::Netfilter) => (),
            _ => panic!("Expected Netfilter mode"),
        }
    }
}
