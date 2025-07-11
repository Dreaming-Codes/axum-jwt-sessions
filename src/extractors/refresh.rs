use axum::{
    extract::FromRequestParts,
    http::{header, request::Parts},
};
use serde::de::DeserializeOwned;
use uuid::Uuid;

use crate::{
    error::{AuthError, Result},
    middleware::AuthState,
    refresher::SessionDataRefresher,
    storage::SessionStorage,
};

/// Extractor that requires a valid refresh token.
///
/// This extractor validates the refresh token from either:
/// - The `X-Refresh-Token` header
/// - The `Authorization` header with `Bearer` prefix
///
/// If a valid refresh token is provided, the session is loaded.
/// This is useful for sensitive operations that require extra authentication.
pub struct RefreshSession<T> {
    pub session_id: Uuid,
    pub data: T,
}

/// Optional version of RefreshSession that doesn't fail if no refresh token is provided
pub struct OptionalRefreshSession<T>(pub Option<RefreshSession<T>>);

impl<S, R, T> FromRequestParts<AuthState<S, R>> for RefreshSession<T>
where
    S: SessionStorage,
    R: SessionDataRefresher,
    T: Send + Sync + DeserializeOwned,
{
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AuthState<S, R>,
    ) -> std::result::Result<Self, Self::Rejection> {
        // Extract refresh token
        let refresh_token = if let Some(header_value) = parts.headers.get("X-Refresh-Token") {
            header_value
                .to_str()
                .map_err(|_| AuthError::InvalidAuthHeaderFormat)?
                .to_string()
        } else {
            // Fall back to Authorization header
            extract_token_from_authorization_header(parts)?
        };

        // Verify refresh token
        let refresh_claims = state.token_generator.verify_refresh_token(&refresh_token)?;

        // Check if refresh token exists in storage (for revocation)
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

        // For refresh token paths, we need to get session data from the access token
        // Extract access token from Authorization header
        let auth_header = parts
            .headers
            .get(header::AUTHORIZATION)
            .ok_or(AuthError::MissingAuthHeader)?;

        let auth_str = auth_header
            .to_str()
            .map_err(|_| AuthError::InvalidAuthHeaderFormat)?;

        let token = auth_str
            .strip_prefix("Bearer ")
            .ok_or(AuthError::InvalidAuthHeaderFormat)?;

        // Verify access token and extract session data
        let access_claims = state
            .token_generator
            .verify_access_token(token)
            .map_err(|_| AuthError::InvalidToken)?;

        // Verify that the subjects match
        if access_claims.sub != refresh_claims.sub {
            return Err(AuthError::InvalidToken);
        }

        let session_data = access_claims
            .session_data
            .ok_or(AuthError::SessionNotFound)?;

        let session_data =
            serde_json::from_value::<T>(session_data).map_err(|_| AuthError::InvalidToken)?;

        Ok(RefreshSession {
            session_id: refresh_claims.sub,
            data: session_data,
        })
    }
}

impl<S, R, T> FromRequestParts<AuthState<S, R>> for OptionalRefreshSession<T>
where
    S: SessionStorage,
    R: SessionDataRefresher,
    T: Send + Sync + DeserializeOwned,
{
    type Rejection = AuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AuthState<S, R>,
    ) -> std::result::Result<Self, Self::Rejection> {
        // Try to extract the RefreshSession using the existing implementation
        match RefreshSession::<T>::from_request_parts(parts, state).await {
            Ok(session) => Ok(OptionalRefreshSession(Some(session))),
            Err(_) => Ok(OptionalRefreshSession(None)),
        }
    }
}

fn extract_token_from_authorization_header(parts: &Parts) -> Result<String> {
    let header_value = parts
        .headers
        .get(header::AUTHORIZATION)
        .ok_or(AuthError::MissingAuthHeader)?;

    let auth_str = header_value
        .to_str()
        .map_err(|_| AuthError::InvalidAuthHeaderFormat)?;

    if !auth_str.starts_with("Bearer ") {
        return Err(AuthError::InvalidAuthHeaderFormat);
    }

    Ok(auth_str[7..].to_string())
}
