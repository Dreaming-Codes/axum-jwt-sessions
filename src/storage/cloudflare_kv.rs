use crate::error::{AuthError, Result};

use crate::storage::{SessionData, SessionStorage};
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::pin::Pin;
use time::OffsetDateTime;
use uuid::Uuid;
use worker::kv::KvStore;

/// Session storage implementation using Cloudflare Workers KV.
///
/// This implementation stores user sessions in Cloudflare's key-value store,
/// with each user's sessions stored as a JSON array under user id as key
///
/// # Key Structure
/// - User sessions: `{user_id}` -> `Vec<SessionData>`
///
/// # Example Usage
///
/// ```rust,no_run
/// use worker::kv::KvStore;
/// use axum_jwt_sessions::storage::CloudflareKvStorage;
/// # use worker::{Env, Result};
///
/// // In your Cloudflare Worker
/// # fn example(env: Env) -> Result<()> {
/// let kv = env.kv("MY_KV_NAMESPACE")?;
/// let storage = CloudflareKvStorage::new(kv);
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct CloudflareKvStorage {
    kv: KvStore,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredUserSessions {
    sessions: Vec<SessionData>,
    last_updated: OffsetDateTime,
}

impl CloudflareKvStorage {
    /// Create a new CloudflareKvStorage instance.
    ///
    /// # Arguments
    /// * `kv` - The Cloudflare KV namespace to use for storage
    pub fn new(kv: KvStore) -> Self {
        Self { kv }
    }

    /// Create a new CloudflareKvStorage instance with a custom key prefix.
    ///
    /// # Arguments
    /// * `kv` - The Cloudflare KV namespace to use for storage
    pub fn with_prefix(kv: KvStore) -> Self {
        Self { kv }
    }

    /// Get stored user sessions from KV, filtering out expired ones
    async fn get_stored_user_sessions(&self, user_id: &str) -> Result<Vec<SessionData>> {
        match self.kv.get(user_id).text().await {
            Ok(Some(data)) => {
                let stored: StoredUserSessions = serde_json::from_str(&data).map_err(|e| {
                    AuthError::StorageError(format!("Failed to deserialize sessions: {}", e))
                })?;

                let now = OffsetDateTime::now_utc();
                let active_sessions: Vec<SessionData> = stored
                    .sessions
                    .into_iter()
                    .filter(|session| session.expires_at > now)
                    .collect();

                Ok(active_sessions)
            }
            Ok(None) => Ok(Vec::new()),
            Err(e) => Err(AuthError::StorageError(format!("KV get error: {:?}", e))),
        }
    }

    /// Store user sessions to KV
    async fn store_user_sessions(&self, user_id: &str, sessions: Vec<SessionData>) -> Result<()> {
        let stored = StoredUserSessions {
            sessions,
            last_updated: OffsetDateTime::now_utc(),
        };

        let serialized = serde_json::to_string(&stored)
            .map_err(|e| AuthError::StorageError(format!("Failed to serialize sessions: {}", e)))?;

        self.kv
            .put(user_id, serialized)
            .map_err(|e| AuthError::StorageError(format!("KV put error: {:?}", e)))?
            .execute()
            .await
            .map_err(|e| AuthError::StorageError(format!("KV execute error: {:?}", e)))?;

        Ok(())
    }
}

impl SessionStorage for CloudflareKvStorage {
    fn create_user_session(
        &self,
        user_id: String,
        session_id: Uuid,
        expires_at: OffsetDateTime,
    ) -> impl Future<Output = Result<()>> + Send {
        let storage = self.clone();
        Box::pin(async move {
            // SAFETY: Cloudflare Workers run in single-threaded environment
            // The Send bound is required by the trait but KV operations are inherently safe
            // in the Workers runtime despite not implementing Send
            let fut = async move {
                let mut sessions = storage.get_stored_user_sessions(&user_id).await?;

                // Add the new session
                sessions.push(SessionData {
                    session_id,
                    expires_at,
                });

                storage.store_user_sessions(&user_id, sessions).await
            };

            unsafe { SendWrapper::new(fut).await }
        })
    }

    fn get_user_sessions(
        &self,
        user_id: &str,
    ) -> impl Future<Output = Result<Vec<SessionData>>> + Send {
        let storage = self.clone();
        let user_id = user_id.to_string();
        Box::pin(async move {
            // SAFETY: Same as above - Workers are single-threaded
            let fut = storage.get_stored_user_sessions(&user_id);
            unsafe { SendWrapper::new(fut).await }
        })
    }

    fn revoke_user_session(
        &self,
        user_id: &str,
        session_id: &Uuid,
    ) -> impl Future<Output = Result<()>> + Send {
        let storage = self.clone();
        let user_id = user_id.to_string();
        let session_id = *session_id;
        Box::pin(async move {
            // SAFETY: Same as above
            let fut = async move {
                let mut sessions = storage.get_stored_user_sessions(&user_id).await?;

                // Remove the specific session
                sessions.retain(|session| session.session_id != session_id);

                if sessions.is_empty() {
                    // If no sessions left, delete the key entirely
                    storage.kv.delete(&user_id).await.map_err(|e| {
                        AuthError::StorageError(format!("KV delete error: {:?}", e))
                    })?;
                } else {
                    // Otherwise, store the updated sessions
                    storage.store_user_sessions(&user_id, sessions).await?;
                }

                Ok(())
            };

            unsafe { SendWrapper::new(fut).await }
        })
    }

    fn revoke_all_user_sessions(&self, user_id: &str) -> impl Future<Output = Result<()>> + Send {
        let storage = self.clone();
        let user_id = user_id.to_string();
        Box::pin(async move {
            // SAFETY: Same as above
            let fut = async move {
                storage
                    .kv
                    .delete(&user_id)
                    .await
                    .map_err(|e| AuthError::StorageError(format!("KV delete error: {:?}", e)))
            };

            unsafe { SendWrapper::new(fut).await }
        })
    }

    fn cleanup_expired_sessions(&self, user_id: &str) -> impl Future<Output = Result<()>> + Send {
        let storage = self.clone();
        let user_id = user_id.to_string();
        Box::pin(async move {
            // SAFETY: Same as above
            let fut = async move {
                let sessions = storage.get_stored_user_sessions(&user_id).await?;

                if sessions.is_empty() {
                    // If all sessions were expired and filtered out, delete the key
                    storage.kv.delete(&user_id).await.map_err(|e| {
                        AuthError::StorageError(format!("KV delete error: {:?}", e))
                    })?;
                } else {
                    // Store the filtered (non-expired) sessions back
                    storage.store_user_sessions(&user_id, sessions).await?;
                }

                Ok(())
            };

            unsafe { SendWrapper::new(fut).await }
        })
    }
}

/// A wrapper to make non-Send futures appear as Send in single-threaded environments
///
/// # Safety
/// This is only safe to use in single-threaded environments like Cloudflare Workers
/// where futures won't actually be sent across threads despite the Send bound requirement.
struct SendWrapper<T>(T);

impl<T> SendWrapper<T> {
    unsafe fn new(inner: T) -> Self {
        Self(inner)
    }
}

unsafe impl<T> Send for SendWrapper<T> {}

impl<T: Future> Future for SendWrapper<T> {
    type Output = T::Output;

    fn poll(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        // SAFETY: We're just forwarding the poll call
        let inner = unsafe { self.map_unchecked_mut(|s| &mut s.0) };
        inner.poll(cx)
    }
}
