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
