use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::{HeaderMap, header},
    middleware::Next,
    response::Response,
};

use crate::{
    error::{AuthError, Result},
    refresher::SessionDataRefresher,
    storage::SessionStorage,
    token::{Claims, TokenGenerator},
};
use serde_json::Value;

#[derive(Clone)]
pub struct AuthState<S: SessionStorage, R: SessionDataRefresher> {
    pub token_generator: Arc<TokenGenerator>,
    pub storage: Arc<S>,
    pub refresher: Arc<R>,
}

#[derive(Clone, Copy, Default)]
pub struct AuthConfig {
    pub require_refresh_token: bool,
}

impl AuthConfig {
    pub fn require_refresh_token() -> Self {
        Self {
            require_refresh_token: true,
        }
    }
}

pub async fn auth_middleware<S: SessionStorage, R: SessionDataRefresher>(
    State(state): State<AuthState<S, R>>,
    State(config): State<AuthConfig>,
    mut request: Request,
    next: Next,
) -> Result<Response> {
    let (access_claims, refresh_claims) =
        extract_and_verify_tokens(&state, request.headers(), config.require_refresh_token)?;

    // Only check refresh token existence if we have a refresh token
    if let Some(ref refresh_claims) = refresh_claims {
        // Extract user_id from refresh token claims
        let user_id = refresh_claims
            .user_id
            .as_ref()
            .ok_or(AuthError::InvalidRefreshToken)?;

        if !state
            .storage
            .user_session_exists(user_id, &refresh_claims.sub)
            .await?
        {
            return Err(AuthError::SessionNotFound);
        }
    }

    request.extensions_mut().insert(access_claims);
    if let Some(refresh_claims) = refresh_claims {
        request.extensions_mut().insert(refresh_claims);
    }

    Ok(next.run(request).await)
}

fn extract_and_verify_tokens<S: SessionStorage, R: SessionDataRefresher>(
    state: &AuthState<S, R>,
    headers: &HeaderMap,
    require_refresh: bool,
) -> Result<(Claims<Value>, Option<Claims<Value>>)> {
    let access_token = extract_token_from_header(headers, header::AUTHORIZATION)?;
    let access_claims = state.token_generator.verify_access_token(&access_token)?;

    let refresh_claims = if require_refresh {
        let refresh_token = extract_token_from_header(headers, "X-Refresh-Token")
            .map_err(|_| AuthError::RefreshTokenRequired)?;
        let claims = state.token_generator.verify_refresh_token(&refresh_token)?;

        if claims.sub != access_claims.sub {
            return Err(AuthError::InvalidToken);
        }

        Some(claims)
    } else {
        None
    };

    Ok((access_claims, refresh_claims))
}

fn extract_token_from_header(headers: &HeaderMap, header_name: impl AsRef<str>) -> Result<String> {
    let header_value = headers
        .get(header_name.as_ref())
        .ok_or(AuthError::MissingAuthHeader)?
        .to_str()
        .map_err(|_| AuthError::InvalidAuthHeaderFormat)?;

    if header_name.as_ref() == header::AUTHORIZATION.as_str() {
        header_value
            .strip_prefix("Bearer ")
            .ok_or(AuthError::InvalidAuthHeaderFormat)
            .map(|s| s.to_string())
    } else {
        Ok(header_value.to_string())
    }
}

/// Middleware that requires a valid refresh token.
///
/// This middleware checks for a refresh token in either:
/// - The `X-Refresh-Token` header
/// - The `Authorization` header with `Bearer` prefix
///
/// If a valid refresh token is not provided, the request is rejected.
/// This is useful for protecting sensitive endpoints that require extra authentication.
pub async fn require_refresh_token<S: SessionStorage, R: SessionDataRefresher>(
    State(state): State<AuthState<S, R>>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Result<Response> {
    // Try to extract refresh token from custom header first
    let token = if let Some(header_value) = headers.get("X-Refresh-Token") {
        header_value
            .to_str()
            .map_err(|_| AuthError::InvalidAuthHeaderFormat)?
            .to_string()
    } else {
        // Fall back to Authorization header
        extract_token_from_header(&headers, header::AUTHORIZATION)?
    };

    // Verify refresh token
    let claims = state.token_generator.verify_refresh_token(&token)?;

    // Verify refresh token exists
    let user_id = claims
        .user_id
        .as_ref()
        .ok_or(AuthError::InvalidRefreshToken)?;

    if !state
        .storage
        .user_session_exists(user_id, &claims.sub)
        .await?
    {
        return Err(AuthError::SessionNotFound);
    }

    // Insert claims into request extensions for extractors to use
    request.extensions_mut().insert(claims);

    Ok(next.run(request).await)
}
