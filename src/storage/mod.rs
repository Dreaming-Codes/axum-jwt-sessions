use crate::error::Result;
use time::OffsetDateTime;
use uuid::Uuid;

/// Data structure representing a session within a user's session array
#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SessionData {
    pub session_id: Uuid,
    pub expires_at: OffsetDateTime,
}

/// Trait for session storage backends.
///
/// With the JWT-based session data approach, the storage is now responsible
/// for managing refresh tokens organized by user_id. Each user can have multiple
/// active sessions stored as an array. Session data is stored directly in the JWT access token.
///
/// All methods are async and return Send futures, allowing them to be used
/// safely across thread boundaries in async contexts.
///
/// # Example Implementation
///
/// ```rust
/// use std::collections::HashMap;
/// use std::sync::Arc;
/// use tokio::sync::RwLock;
/// use time::OffsetDateTime;
/// use uuid::Uuid;
/// use axum_jwt_sessions::error::Result;
/// use axum_jwt_sessions::{SessionData, SessionStorage};
///
/// struct UserSessionStorage {
///     user_sessions: Arc<RwLock<HashMap<String, Vec<SessionData>>>>,
/// }
///
/// impl SessionStorage for UserSessionStorage {
///     async fn create_user_session(&self, user_id: String, session_id: Uuid, expires_at: OffsetDateTime) -> Result<()> {
///         let mut sessions = self.user_sessions.write().await;
///         let user_sessions = sessions.entry(user_id).or_insert_with(Vec::new);
///
///         user_sessions.push(SessionData {
///             session_id,
///             expires_at,
///         });
///
///         Ok(())
///     }
///
///     async fn get_user_sessions(&self, user_id: &str) -> Result<Vec<SessionData>> {
///         let sessions = self.user_sessions.read().await;
///         let now = OffsetDateTime::now_utc();
///
///         if let Some(user_sessions) = sessions.get(user_id) {
///             // Return only non-expired sessions
///             let active_sessions: Vec<SessionData> = user_sessions
///                 .iter()
///                 .filter(|session| session.expires_at > now)
///                 .cloned()
///                 .collect();
///             Ok(active_sessions)
///         } else {
///             Ok(Vec::new())
///         }
///     }
///
///     async fn revoke_user_session(&self, user_id: &str, session_id: &Uuid) -> Result<()> {
///         let mut sessions = self.user_sessions.write().await;
///         if let Some(user_sessions) = sessions.get_mut(user_id) {
///             user_sessions.retain(|session| session.session_id != *session_id);
///             if user_sessions.is_empty() {
///                 sessions.remove(user_id);
///             }
///         }
///         Ok(())
///     }
///
///     async fn revoke_all_user_sessions(&self, user_id: &str) -> Result<()> {
///         self.user_sessions.write().await.remove(user_id);
///         Ok(())
///     }
/// }
/// ```
pub trait SessionStorage: Send + Sync {
    /// Create a new session for a user
    fn create_user_session(
        &self,
        user_id: String,
        session_id: Uuid,
        expires_at: OffsetDateTime,
    ) -> impl std::future::Future<Output = Result<()>> + Send;

    /// Get all active sessions for a user (excludes expired sessions)
    fn get_user_sessions(
        &self,
        user_id: &str,
    ) -> impl std::future::Future<Output = Result<Vec<SessionData>>> + Send;

    /// Revoke a specific session for a user
    fn revoke_user_session(
        &self,
        user_id: &str,
        session_id: &Uuid,
    ) -> impl std::future::Future<Output = Result<()>> + Send;

    /// Revoke all sessions for a user
    fn revoke_all_user_sessions(
        &self,
        user_id: &str,
    ) -> impl std::future::Future<Output = Result<()>> + Send;

    /// Check if a specific session exists for a user (not revoked or expired)
    fn user_session_exists(
        &self,
        user_id: &str,
        session_id: &Uuid,
    ) -> impl std::future::Future<Output = Result<bool>> + Send {
        async move {
            let sessions = self.get_user_sessions(user_id).await?;
            Ok(sessions
                .iter()
                .any(|session| session.session_id == *session_id))
        }
    }

    /// Get session data for a specific session_id within a user's sessions
    fn get_session_data(
        &self,
        user_id: &str,
        session_id: &Uuid,
    ) -> impl std::future::Future<Output = Result<Option<SessionData>>> + Send {
        async move {
            let sessions = self.get_user_sessions(user_id).await?;
            Ok(sessions
                .into_iter()
                .find(|session| session.session_id == *session_id))
        }
    }

    /// Clean up expired sessions for a user
    fn cleanup_expired_sessions(
        &self,
        user_id: &str,
    ) -> impl std::future::Future<Output = Result<()>> + Send {
        async move {
            let sessions = self.get_user_sessions(user_id).await?;
            let now = OffsetDateTime::now_utc();

            // Remove expired sessions
            for session in sessions {
                if session.expires_at <= now {
                    self.revoke_user_session(user_id, &session.session_id)
                        .await?;
                }
            }

            Ok(())
        }
    }
}
