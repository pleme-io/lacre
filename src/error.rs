use thiserror::Error;

#[derive(Debug, Error)]
pub enum LacreError {
    #[error("cartorio request failed: {0}")]
    CartorioRequest(String),

    #[error("backend request failed: {0}")]
    BackendRequest(String),

    #[error("manifest body too large: {0} bytes (max {1})")]
    ManifestTooLarge(usize, usize),

    #[error("config error: {0}")]
    Config(String),
}

pub type Result<T> = std::result::Result<T, LacreError>;
