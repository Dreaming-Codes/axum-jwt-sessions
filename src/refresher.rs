use crate::error::Result;
use serde::Serialize;

/// Trait for refreshing session data during token refresh.
///
/// This trait allows you to fetch fresh session data when refreshing tokens,
/// ensuring that the new access token contains up-to-date information.
///
/// # Example Implementation
///
/// ```rust
/// use serde::{Deserialize, Serialize};
/// use std::sync::Arc;
/// use axum_jwt_sessions::{SessionDataRefresher, Result};
///
/// #[derive(Serialize, Deserialize)]
/// struct UserSession {
///     user_id: String,
///     email: String,
///     roles: Vec<String>,
/// }
///
/// struct User {
///     id: String,
///     email: String,
///     roles: Vec<String>,
/// }
///
/// struct UserRepository;
///
/// impl UserRepository {
///     async fn find_by_id(&self, _id: &str) -> std::result::Result<Option<User>, Box<dyn std::error::Error>> {
///         Ok(None)
///     }
/// }
///
/// struct MyRefresher {
///     user_repository: Arc<UserRepository>,
/// }
///
/// impl SessionDataRefresher for MyRefresher {
///     type SessionData = UserSession;
///
///     async fn refresh_session_data(&self, user_id: &str) -> Result<Option<Self::SessionData>> {
///         // Fetch fresh user data from database
///         let user_result = self.user_repository.find_by_id(user_id).await
///             .map_err(|e| axum_jwt_sessions::AuthError::StorageError(e.to_string()))?;
///         if let Some(user) = user_result {
///             Ok(Some(UserSession {
///                 user_id: user.id,
///                 email: user.email,
///                 roles: user.roles,
///                 // ... other fresh data
///             }))
///         } else {
///             Ok(None)
///         }
///     }
/// }
/// ```
pub trait SessionDataRefresher: Send + Sync {
    type SessionData: Serialize + Send + Sync;

    /// Refresh session data for the given user ID.
    ///
    /// This method is called during token refresh to fetch the latest session data
    /// based on the user ID stored with the refresh token.
    /// Return `None` if the user no longer exists or should not be refreshed.
    fn refresh_session_data(
        &self,
        user_id: &str,
    ) -> impl std::future::Future<Output = Result<Option<Self::SessionData>>> + Send;
}
