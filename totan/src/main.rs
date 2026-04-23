use totan::cli::CliArgs;
use totan::connection::ConnectionManager;
use totan::interceptor::PacketInterceptor;

use clap::Parser;
use std::sync::Arc;
use tokio::signal;
use totan_common::config::TotanConfig;
use tracing::{error, info};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = CliArgs::parse();

    // Load configuration (CLI overrides applied inside)
    let config = load_config(&args)?;

    // Setup logging from (merged) config
    setup_logging(&config)?;

    info!("Starting totan transparent proxy");
    info!("Configuration loaded successfully");

    // Create packet interceptor based on mode
    let mode = config.interception_mode;
    let interceptor = PacketInterceptor::new(config.clone())?;
    info!("Packet interceptor initialized in {:?} mode", mode);

    // Create connection manager
    let connection_manager = Arc::new(ConnectionManager::new(config.clone()).await?);
    info!("Connection manager initialized");

    // Setup graceful shutdown
    let shutdown_signal = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install CTRL+C signal handler");
    };

    // Start the proxy server
    info!("Listening on port {}", config.listen_port);

    tokio::select! {
        result = interceptor.run(connection_manager) => {
            if let Err(e) = result {
                error!("Interceptor error: {}", e);
                return Err(e);
            }
        }
        _ = shutdown_signal => {
            info!("Received shutdown signal");
        }
    }

    info!("Shutting down totan");
    Ok(())
}

fn setup_logging(config: &TotanConfig) -> anyhow::Result<()> {
    use tracing_subscriber::fmt;
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

    let log_level = config.logging.level.as_str();
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level));
    let base = tracing_subscriber::registry().with(env_filter);
    if config.logging.format.eq_ignore_ascii_case("json") {
        base.with(fmt::layer().event_format(fmt::format().json()))
            .init();
    } else {
        base.with(fmt::layer()).init();
    }
    Ok(())
}

fn load_config(args: &CliArgs) -> anyhow::Result<TotanConfig> {
    let mut config = if let Some(config_path) = &args.config {
        let config_str = std::fs::read_to_string(config_path)?;
        toml::from_str::<TotanConfig>(&config_str)?
    } else {
        TotanConfig::default()
    };

    // Override config with CLI arguments
    if let Some(port) = args.port {
        config.listen_port = port;
    }

    if let Some(proxy) = &args.proxy {
        config.default_proxy = Some(proxy.clone());
    }

    if let Some(pac_file) = &args.pac_file {
        config.pac_file = Some(pac_file.clone());
    }
    if let Some(ttl) = args.pac_cache_ttl {
        config.pac_cache_ttl_secs = ttl;
    }
    if let Some(size) = args.pac_cache_size {
        config.pac_cache_max_entries = size;
    }

    if let Some(mode) = &args.mode {
        config.interception_mode = mode.clone().into();
    }
    // Logging overrides
    if let Some(lvl) = &args.log_level {
        config.logging.level = lvl.clone();
    }
    if let Some(fmt) = &args.log_format {
        config.logging.format = fmt.clone();
    }

    // Validate configuration
    if config.default_proxy.is_none() && config.pac_file.is_none() {
        return Err(anyhow::anyhow!(
            "Either default proxy (--proxy) or PAC file (--pac-file) must be specified"
        ));
    }

    Ok(config)
}
