use crate::error::{FalconError, Result};

#[derive(Debug, Clone)]
pub struct Config {
    pub client_id: String,
    pub client_secret: String,
    pub base_url: String,
    pub member_cid: Option<String>,
}

impl Config {
    /// Build config from environment variables.
    /// CLI options should override these values before calling this.
    pub fn from_env() -> Result<Self> {
        let client_id = std::env::var("FALCON_CLIENT_ID")
            .map_err(|_| FalconError::Config("FALCON_CLIENT_ID is not set".into()))?;
        let client_secret = std::env::var("FALCON_CLIENT_SECRET")
            .map_err(|_| FalconError::Config("FALCON_CLIENT_SECRET is not set".into()))?;
        let base_url = std::env::var("FALCON_BASE_URL")
            .unwrap_or_else(|_| "https://api.crowdstrike.com".into());
        let member_cid = std::env::var("FALCON_MEMBER_CID").ok();

        Ok(Self {
            client_id,
            client_secret,
            base_url,
            member_cid,
        })
    }
}
