use axum::{extract::State, http::HeaderMap, Json};
use serde::{Deserialize, Serialize};

use crate::{
    error::{AuthError, Result},
    middleware::AuthState,
    refresher::SessionDataRefresher,
    storage::SessionStorage,
};

#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RefreshResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub access_expires_at: i64,
    pub refresh_expires_at: Option<i64>,
}

pub async fn refresh_handler<S: SessionStorage, R: SessionDataRefresher>(
    State(state): State<AuthState<S, R>>,
    _headers: HeaderMap,
    Json(payload): Json<RefreshRequest>,
) -> Result<Json<RefreshResponse>> {
    // Verify refresh token
    let refresh_claims = state
        .token_generator
        .verify_refresh_token(&payload.refresh_token)?;

    // Extract user_id from refresh token claims
    let user_id = refresh_claims
        .user_id
        .as_ref()
        .ok_or(AuthError::InvalidRefreshToken)?
        .clone();

    // Check if this specific session exists for the user
    if !state
        .storage
        .user_session_exists(&user_id, &refresh_claims.sub)
        .await?
    {
        return Err(AuthError::SessionNotFound);
    }

    // Get session data for this specific session
    let _session_data = state
        .storage
        .get_session_data(&user_id, &refresh_claims.sub)
        .await?
        .ok_or(AuthError::SessionNotFound)?;

    // Refresh session data using the user_id
    let fresh_session_data = state.refresher.refresh_session_data(&user_id).await?;

    // Generate new token pair with fresh session data
    let token_pair = state.token_generator.generate_token_pair(
        refresh_claims.sub,
        user_id.clone(),
        fresh_session_data,
    )?;

    let (new_refresh_token, new_refresh_expires_at) = if state
        .token_generator
        .should_renew_refresh_token(&refresh_claims)
    {
        // Revoke the old session
        state
            .storage
            .revoke_user_session(&user_id, &refresh_claims.sub)
            .await?;

        // Create new session for the user
        state
            .storage
            .create_user_session(
                user_id.clone(),
                refresh_claims.sub,
                token_pair.refresh_expires_at,
            )
            .await?;

        (
            Some(token_pair.refresh_token.clone()),
            Some(token_pair.refresh_expires_at.unix_timestamp()),
        )
    } else {
        (None, None)
    };

    Ok(Json(RefreshResponse {
        access_token: token_pair.access_token,
        refresh_token: new_refresh_token,
        access_expires_at: token_pair.access_expires_at.unix_timestamp(),
        refresh_expires_at: new_refresh_expires_at,
    }))
}

/// Macro to create a typed refresh handler for use with OpenAPI and routes! macro
///
/// # Example
/// ```rust
/// use axum_jwt_sessions::typed_refresh_handler;
///
/// // Create a typed refresh handler for your storage types
/// typed_refresh_handler!(my_refresh_handler, MyStorage, MyRefresher);
///
/// // Use it with utoipa-axum routes! macro
/// let (router, api) = OpenApiRouter::new()
///     .routes(routes!(my_refresh_handler))
///     .with_state(auth_state)
///     .split_for_parts();
/// ```
#[cfg(feature = "openapi")]
#[macro_export]
macro_rules! typed_refresh_handler {
    ($name:ident, $storage:ty, $refresher:ty) => {
        #[utoipa::path(
                post,
                path = "/refresh",
                request_body = $crate::handlers::RefreshRequest,
                responses(
                    (status = 200, description = "Tokens refreshed successfully", body = $crate::handlers::RefreshResponse),
                    (status = 401, description = "Invalid refresh token", body = $crate::error::ErrorResponse),
                    (status = 401, description = "Session not found", body = $crate::error::ErrorResponse),
                ),
                tag = "auth"
        )]
        pub async fn $name(
            state: ::axum::extract::State<$crate::middleware::AuthState<$storage, $refresher>>,
            headers: ::axum::http::HeaderMap,
            payload: ::axum::Json<$crate::handlers::RefreshRequest>,
        ) -> $crate::error::Result<::axum::Json<$crate::handlers::RefreshResponse>> {
            $crate::handlers::refresh_handler(state, headers, payload).await
        }
    };
}
