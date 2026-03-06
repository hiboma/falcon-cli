use thiserror::Error;

#[derive(Debug, Error)]
pub enum FalconError {
    #[error("authentication failed: {0}")]
    Auth(String),

    #[error("API request failed: {0}")]
    Api(String),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("configuration error: {0}")]
    Config(String),
}

pub type Result<T> = std::result::Result<T, FalconError>;
