use std::{collections::HashMap, sync::Arc};

use axum_jwt_sessions::prelude::*;
use serde::{Deserialize, Serialize};
use time::Duration;
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct TestSession {
    user_id: String,
    name: String,
}

struct TestStorage {
    user_sessions: Arc<RwLock<HashMap<String, Vec<SessionData>>>>,
}

impl TestStorage {
    fn new() -> Self {
        Self {
            user_sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl SessionStorage for TestStorage {
    async fn create_user_session(
        &self,
        user_id: String,
        session_id: Uuid,
        expires_at: time::OffsetDateTime,
    ) -> Result<()> {
        let mut sessions = self.user_sessions.write().await;
        let user_sessions = sessions.entry(user_id).or_insert_with(Vec::new);

        user_sessions.push(SessionData {
            session_id,
            expires_at,
        });

        Ok(())
    }

    async fn get_user_sessions(&self, user_id: &str) -> Result<Vec<SessionData>> {
        let sessions = self.user_sessions.read().await;
        let now = time::OffsetDateTime::now_utc();

        if let Some(user_sessions) = sessions.get(user_id) {
            // Return only non-expired sessions
            let active_sessions: Vec<SessionData> = user_sessions
                .iter()
                .filter(|session| session.expires_at > now)
                .cloned()
                .collect();
            Ok(active_sessions)
        } else {
            Ok(Vec::new())
        }
    }

    async fn revoke_user_session(&self, user_id: &str, session_id: &Uuid) -> Result<()> {
        let mut sessions = self.user_sessions.write().await;
        if let Some(user_sessions) = sessions.get_mut(user_id) {
            user_sessions.retain(|session| session.session_id != *session_id);
            if user_sessions.is_empty() {
                sessions.remove(user_id);
            }
        }
        Ok(())
    }

    async fn revoke_all_user_sessions(&self, user_id: &str) -> Result<()> {
        self.user_sessions.write().await.remove(user_id);
        Ok(())
    }
}

#[tokio::test]
async fn test_token_generation_and_verification() {
    let config = JwtConfig::new(
        "test-access-secret".to_string(),
        "test-refresh-secret".to_string(),
        Duration::minutes(15),
        Duration::days(7),
        Duration::days(1),
    );

    let generator = TokenGenerator::new(config);
    let session_id = Uuid::new_v4();
    let session_data = TestSession {
        user_id: "test-user".to_string(),
        name: "Test User".to_string(),
    };

    let token_pair = generator
        .generate_token_pair(
            session_id,
            session_data.user_id.clone(),
            Some(session_data.clone()),
        )
        .unwrap();

    let access_claims = generator
        .verify_access_token(&token_pair.access_token)
        .unwrap();
    assert_eq!(access_claims.sub, session_id);
    assert_eq!(access_claims.token_type, TokenType::Access);

    // Verify session data is in the access token
    assert!(access_claims.session_data.is_some());
    let stored_data: TestSession =
        serde_json::from_value(access_claims.session_data.unwrap()).unwrap();
    assert_eq!(stored_data, session_data);

    let refresh_claims = generator
        .verify_refresh_token(&token_pair.refresh_token)
        .unwrap();
    assert_eq!(refresh_claims.sub, session_id);
    assert_eq!(refresh_claims.token_type, TokenType::Refresh);

    // Verify refresh token doesn't contain session data
    assert!(refresh_claims.session_data.is_none());
}

#[tokio::test]
async fn test_session_storage() {
    let storage = TestStorage::new();
    let session_id = Uuid::new_v4();
    let user_id = "test-user";

    // Create user session with expiration
    let expires_at = time::OffsetDateTime::now_utc() + time::Duration::days(7);
    storage
        .create_user_session(user_id.to_string(), session_id, expires_at)
        .await
        .unwrap();

    // Check it exists
    assert!(
        storage
            .user_session_exists(user_id, &session_id)
            .await
            .unwrap()
    );

    // Get user sessions
    let sessions = storage.get_user_sessions(user_id).await.unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].session_id, session_id);

    // Get specific session data
    let session_data = storage
        .get_session_data(user_id, &session_id)
        .await
        .unwrap();
    assert!(session_data.is_some());
    assert_eq!(session_data.unwrap().session_id, session_id);

    // Revoke the session
    storage
        .revoke_user_session(user_id, &session_id)
        .await
        .unwrap();

    // Check it no longer exists
    assert!(
        !storage
            .user_session_exists(user_id, &session_id)
            .await
            .unwrap()
    );
    let sessions = storage.get_user_sessions(user_id).await.unwrap();
    assert_eq!(sessions.len(), 0);
}

#[tokio::test]
async fn test_multiple_user_sessions() {
    let storage = TestStorage::new();
    let user_id = "test-user";
    let session_id1 = Uuid::new_v4();
    let session_id2 = Uuid::new_v4();

    let expires_at = time::OffsetDateTime::now_utc() + time::Duration::days(7);

    // Create multiple sessions for the same user
    storage
        .create_user_session(user_id.to_string(), session_id1, expires_at)
        .await
        .unwrap();
    storage
        .create_user_session(user_id.to_string(), session_id2, expires_at)
        .await
        .unwrap();

    // Check both exist
    let sessions = storage.get_user_sessions(user_id).await.unwrap();
    assert_eq!(sessions.len(), 2);

    // Revoke one session
    storage
        .revoke_user_session(user_id, &session_id1)
        .await
        .unwrap();

    // Check only one remains
    let sessions = storage.get_user_sessions(user_id).await.unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].session_id, session_id2);

    // Revoke all sessions
    storage.revoke_all_user_sessions(user_id).await.unwrap();

    // Check no sessions remain
    let sessions = storage.get_user_sessions(user_id).await.unwrap();
    assert_eq!(sessions.len(), 0);
}

#[tokio::test]
async fn test_expired_session_filtering() {
    let storage = TestStorage::new();
    let user_id = "test-user";
    let session_id1 = Uuid::new_v4();
    let session_id2 = Uuid::new_v4();

    // Create one expired and one valid session
    let expired_time = time::OffsetDateTime::now_utc() - time::Duration::days(1);
    let valid_time = time::OffsetDateTime::now_utc() + time::Duration::days(7);

    storage
        .create_user_session(user_id.to_string(), session_id1, expired_time)
        .await
        .unwrap();
    storage
        .create_user_session(user_id.to_string(), session_id2, valid_time)
        .await
        .unwrap();

    // get_user_sessions should only return non-expired sessions
    let sessions = storage.get_user_sessions(user_id).await.unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].session_id, session_id2);

    // user_session_exists should return false for expired session
    assert!(
        !storage
            .user_session_exists(user_id, &session_id1)
            .await
            .unwrap()
    );
    assert!(
        storage
            .user_session_exists(user_id, &session_id2)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn test_refresh_token_renewal_threshold() {
    let config = JwtConfig::new(
        "test-access-secret".to_string(),
        "test-refresh-secret".to_string(),
        Duration::minutes(15),
        Duration::seconds(10),
        Duration::seconds(5),
    );

    let generator = TokenGenerator::new(config);
    let session_id = Uuid::new_v4();

    let token_pair = generator
        .generate_token_pair(session_id, "test-user".to_string(), None::<TestSession>)
        .unwrap();
    let claims = generator
        .verify_refresh_token(&token_pair.refresh_token)
        .unwrap();

    assert!(!generator.should_renew_refresh_token(&claims));

    tokio::time::sleep(tokio::time::Duration::from_secs(6)).await;

    assert!(generator.should_renew_refresh_token(&claims));
}
