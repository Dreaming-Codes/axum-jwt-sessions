use axum::{
    extract::FromRequestParts,
    http::{header, request::Parts},
};
use serde::de::DeserializeOwned;
use serde_json::Value;
use uuid::Uuid;

use crate::{
    error::{AuthError, Result},
    middleware::AuthState,
    refresher::SessionDataRefresher,
    storage::SessionStorage,
    token::Claims,
};

pub struct Session<T> {
    pub session_id: Uuid,
    pub data: T,
}

pub struct OptionalSession<T>(pub Option<Session<T>>);

impl<S, R, T> FromRequestParts<AuthState<S, R>> for Session<T>
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
        let claims = if let Some(claims) = parts.extensions.get::<Claims<Value>>() {
            claims.clone()
        } else {
            let token = extract_token_from_parts(parts)?;
            state.token_generator.verify_access_token(&token)?
        };

        // Extract session data from JWT claims
        let data = if let Some(session_data) = &claims.session_data {
            serde_json::from_value::<T>(session_data.clone())
                .map_err(|_| AuthError::InvalidToken)?
        } else {
            return Err(AuthError::SessionNotFound);
        };

        Ok(Session {
            session_id: claims.sub,
            data,
        })
    }
}

impl<S, R, T> FromRequestParts<AuthState<S, R>> for OptionalSession<T>
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
        match Session::<T>::from_request_parts(parts, state).await {
            Ok(session) => Ok(OptionalSession(Some(session))),
            Err(_) => Ok(OptionalSession(None)),
        }
    }
}

fn extract_token_from_parts(parts: &Parts) -> Result<String> {
    let header_value = parts
        .headers
        .get(header::AUTHORIZATION)
        .ok_or(AuthError::MissingAuthHeader)?
        .to_str()
        .map_err(|_| AuthError::InvalidAuthHeaderFormat)?;

    header_value
        .strip_prefix("Bearer ")
        .ok_or(AuthError::InvalidAuthHeaderFormat)
        .map(|s| s.to_string())
}
