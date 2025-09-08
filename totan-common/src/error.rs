use thiserror::Error;

#[derive(Error, Debug)]
pub enum TotanError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Configuration error: {0}")]
    Config(String),
    
    #[error("Network error: {0}")]
    Network(String),
    
    #[error("PAC script error: {0}")]
    PacScript(String),
    
    #[error("Upstream proxy error: {0}")]
    UpstreamProxy(String),
    
    #[error("Interception error: {0}")]
    Interception(String),
}
