use serde::{Deserialize, Serialize};
use time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtConfig {
    pub access_token_secret: String,
    pub refresh_token_secret: String,
    pub access_token_duration: Duration,
    pub refresh_token_duration: Duration,
    pub refresh_token_renewal_threshold: Duration,
    pub issuer: Option<String>,
    pub audience: Option<String>,
}

impl JwtConfig {
    pub fn new(
        access_token_secret: String,
        refresh_token_secret: String,
        access_token_duration: Duration,
        refresh_token_duration: Duration,
        refresh_token_renewal_threshold: Duration,
    ) -> Self {
        Self {
            access_token_secret,
            refresh_token_secret,
            access_token_duration,
            refresh_token_duration,
            refresh_token_renewal_threshold,
            issuer: None,
            audience: None,
        }
    }

    pub fn with_issuer(mut self, issuer: String) -> Self {
        self.issuer = Some(issuer);
        self
    }

    pub fn with_audience(mut self, audience: String) -> Self {
        self.audience = Some(audience);
        self
    }
}
