use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    config::JwtConfig,
    error::{AuthError, Result},
};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Claims<T = Value> {
    pub sub: Uuid,
    pub exp: i64,
    pub iat: i64,
    pub iss: Option<String>,
    pub aud: Option<String>,
    pub token_type: TokenType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum TokenType {
    Access,
    Refresh,
}

#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub session_id: Uuid,
    pub user_id: String,
    pub access_expires_at: OffsetDateTime,
    pub refresh_expires_at: OffsetDateTime,
}

pub struct TokenGenerator {
    config: JwtConfig,
    encoding_key_access: EncodingKey,
    encoding_key_refresh: EncodingKey,
    decoding_key_access: DecodingKey,
    decoding_key_refresh: DecodingKey,
}

impl TokenGenerator {
    pub fn new(config: JwtConfig) -> Self {
        let encoding_key_access = EncodingKey::from_secret(config.access_token_secret.as_bytes());
        let encoding_key_refresh = EncodingKey::from_secret(config.refresh_token_secret.as_bytes());
        let decoding_key_access = DecodingKey::from_secret(config.access_token_secret.as_bytes());
        let decoding_key_refresh = DecodingKey::from_secret(config.refresh_token_secret.as_bytes());

        Self {
            config,
            encoding_key_access,
            encoding_key_refresh,
            decoding_key_access,
            decoding_key_refresh,
        }
    }

    pub fn generate_token_pair<T: Serialize>(
        &self,
        session_id: Uuid,
        user_id: String,
        session_data: Option<T>,
    ) -> Result<TokenPair> {
        let now = OffsetDateTime::now_utc();
        let access_expires_at = now + self.config.access_token_duration;
        let refresh_expires_at = now + self.config.refresh_token_duration;

        // Convert session data to Value if provided
        let session_data_value = session_data
            .map(|data| serde_json::to_value(data))
            .transpose()
            .map_err(|e| {
                AuthError::TokenGenerationError(format!("Failed to serialize session data: {e}"))
            })?;

        let access_claims = Claims {
            sub: session_id,
            exp: access_expires_at.unix_timestamp(),
            iat: now.unix_timestamp(),
            iss: self.config.issuer.clone(),
            aud: self.config.audience.clone(),
            token_type: TokenType::Access,
            session_data: session_data_value,
            user_id: Some(user_id.clone()),
        };

        let refresh_claims = Claims::<Value> {
            sub: session_id,
            exp: refresh_expires_at.unix_timestamp(),
            iat: now.unix_timestamp(),
            iss: self.config.issuer.clone(),
            aud: self.config.audience.clone(),
            token_type: TokenType::Refresh,
            session_data: None, // Refresh tokens don't carry session data
            user_id: Some(user_id.clone()),
        };

        let access_token = encode(
            &Header::default(),
            &access_claims,
            &self.encoding_key_access,
        )
        .map_err(|e| AuthError::TokenGenerationError(e.to_string()))?;

        let refresh_token = encode(
            &Header::default(),
            &refresh_claims,
            &self.encoding_key_refresh,
        )
        .map_err(|e| AuthError::TokenGenerationError(e.to_string()))?;

        Ok(TokenPair {
            access_token,
            refresh_token,
            session_id,
            user_id,
            access_expires_at,
            refresh_expires_at,
        })
    }

    pub fn verify_access_token(&self, token: &str) -> Result<Claims<Value>> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&self.config.issuer.clone().into_iter().collect::<Vec<_>>());
        validation.set_audience(&self.config.audience.clone().into_iter().collect::<Vec<_>>());

        let token_data = decode::<Claims<Value>>(token, &self.decoding_key_access, &validation)
            .map_err(|e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => AuthError::TokenExpired,
                _ => AuthError::InvalidToken,
            })?;

        if token_data.claims.token_type != TokenType::Access {
            return Err(AuthError::InvalidToken);
        }

        Ok(token_data.claims)
    }

    pub fn verify_refresh_token(&self, token: &str) -> Result<Claims<Value>> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&self.config.issuer.clone().into_iter().collect::<Vec<_>>());
        validation.set_audience(&self.config.audience.clone().into_iter().collect::<Vec<_>>());

        let token_data = decode::<Claims<Value>>(token, &self.decoding_key_refresh, &validation)
            .map_err(|e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => AuthError::TokenExpired,
                _ => AuthError::InvalidRefreshToken,
            })?;

        if token_data.claims.token_type != TokenType::Refresh {
            return Err(AuthError::InvalidRefreshToken);
        }

        Ok(token_data.claims)
    }

    pub fn should_renew_refresh_token(&self, claims: &Claims<Value>) -> bool {
        let expiry =
            OffsetDateTime::from_unix_timestamp(claims.exp).unwrap_or(OffsetDateTime::now_utc());
        let now = OffsetDateTime::now_utc();
        let time_until_expiry = expiry - now;

        time_until_expiry <= self.config.refresh_token_renewal_threshold
    }
}
