use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use thiserror::Error;

/// Error response returned to clients
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ErrorResponse {
    /// Error type identifier
    pub error: &'static str,
    /// Human-readable error message
    pub message: &'static str,
}

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("Invalid token")]
    InvalidToken,

    #[error("Token expired")]
    TokenExpired,

    #[error("Missing authorization header")]
    MissingAuthHeader,

    #[error("Invalid authorization header format")]
    InvalidAuthHeaderFormat,

    #[error("Session not found")]
    SessionNotFound,

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Token generation failed: {0}")]
    TokenGenerationError(String),

    #[error("Invalid refresh token")]
    InvalidRefreshToken,

    #[error("Refresh token required")]
    RefreshTokenRequired,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AuthError::InvalidToken => (StatusCode::UNAUTHORIZED, "Invalid token"),
            AuthError::TokenExpired => (StatusCode::UNAUTHORIZED, "Token expired"),
            AuthError::MissingAuthHeader => {
                (StatusCode::UNAUTHORIZED, "Missing authorization header")
            }
            AuthError::InvalidAuthHeaderFormat => (
                StatusCode::BAD_REQUEST,
                "Invalid authorization header format",
            ),
            AuthError::SessionNotFound => (StatusCode::UNAUTHORIZED, "Session not found"),
            AuthError::StorageError(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Storage error"),
            AuthError::TokenGenerationError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Token generation failed")
            }
            AuthError::InvalidRefreshToken => (StatusCode::UNAUTHORIZED, "Invalid refresh token"),
            AuthError::RefreshTokenRequired => (
                StatusCode::FORBIDDEN,
                "Refresh token required for this endpoint",
            ),
        };

        let error_response = ErrorResponse {
            error: match self {
                AuthError::InvalidToken => "invalid_token",
                AuthError::TokenExpired => "token_expired",
                AuthError::MissingAuthHeader => "missing_authorization_header",
                AuthError::InvalidAuthHeaderFormat => "invalid_authorization_header",
                AuthError::SessionNotFound => "session_not_found",
                AuthError::StorageError(_) => "storage_error",
                AuthError::TokenGenerationError(_) => "token_generation_error",
                AuthError::InvalidRefreshToken => "invalid_refresh_token",
                AuthError::RefreshTokenRequired => "refresh_token_required",
            },
            message,
        };

        (status, axum::Json(error_response)).into_response()
    }
}

pub type Result<T> = std::result::Result<T, AuthError>;
