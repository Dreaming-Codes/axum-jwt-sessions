use axum::{
    Json, Router,
    extract::State,
    routing::{get, post},
};
use axum_jwt_sessions::prelude::*;
use axum_jwt_sessions::storage::SessionData;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use time::Duration;
use time::OffsetDateTime;
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UserSession {
    user_id: String,
    email: String,
}

#[derive(Debug, Deserialize)]
struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Debug, Serialize)]
struct LoginResponse {
    access_token: String,
    refresh_token: String,
}

#[derive(Debug, Serialize)]
struct SessionInfo {
    session_id: uuid::Uuid,
    expires_at: OffsetDateTime,
}

// In-memory storage implementation for user-based sessions
#[derive(Clone)]
struct InMemoryStorage {
    // Store sessions by user_id -> Vec<SessionData>
    user_sessions: Arc<RwLock<HashMap<String, Vec<SessionData>>>>,
    // Store user session data for the refresher (by user_id)
    session_data: Arc<RwLock<HashMap<String, UserSession>>>,
}

impl InMemoryStorage {
    fn new() -> Self {
        Self {
            user_sessions: Arc::new(RwLock::new(HashMap::new())),
            session_data: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl SessionStorage for InMemoryStorage {
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
        // Also remove cached session data
        self.session_data.write().await.remove(user_id);
        Ok(())
    }
}

impl SessionDataRefresher for InMemoryStorage {
    type SessionData = UserSession;

    async fn refresh_session_data(&self, user_id: &str) -> Result<Option<Self::SessionData>> {
        Ok(self.session_data.read().await.get(user_id).cloned())
    }
}

async fn login(
    State(state): State<AuthState<InMemoryStorage, InMemoryStorage>>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>> {
    // In a real app, verify credentials here
    if req.password != "secret" {
        return Err(AuthError::InvalidToken); // Using InvalidToken as a generic auth error
    }

    let session_id = Uuid::new_v4();
    let user_id = "user123".to_string();
    let session_data = UserSession {
        user_id: user_id.clone(),
        email: req.email,
    };

    // Store session data for refresher (by user_id)
    state
        .storage
        .session_data
        .write()
        .await
        .insert(user_id.clone(), session_data.clone());

    // Generate tokens with session data embedded in the access token
    let token_pair = state.token_generator.generate_token_pair(
        session_id,
        user_id.clone(),
        Some(session_data),
    )?;

    // Create session in user-based storage
    state
        .storage
        .create_user_session(user_id, session_id, token_pair.refresh_expires_at)
        .await?;

    Ok(Json(LoginResponse {
        access_token: token_pair.access_token,
        refresh_token: token_pair.refresh_token,
    }))
}

async fn protected(session: Session<UserSession>) -> Json<UserSession> {
    Json(session.data)
}

async fn optional_protected(session: OptionalSession<UserSession>) -> &'static str {
    if session.0.is_some() {
        "Authenticated"
    } else {
        "Not authenticated"
    }
}

async fn logout(
    State(state): State<AuthState<InMemoryStorage, InMemoryStorage>>,
    session: Session<UserSession>,
) -> Result<&'static str> {
    // Revoke the specific session
    state
        .storage
        .revoke_user_session(&session.data.user_id, &session.session_id)
        .await?;
    Ok("Logged out successfully")
}

async fn logout_all(
    State(state): State<AuthState<InMemoryStorage, InMemoryStorage>>,
    session: Session<UserSession>,
) -> Result<&'static str> {
    // Revoke all sessions for this user
    state
        .storage
        .revoke_all_user_sessions(&session.data.user_id)
        .await?;
    Ok("Logged out from all devices successfully")
}

async fn list_sessions(
    State(state): State<AuthState<InMemoryStorage, InMemoryStorage>>,
    session: Session<UserSession>,
) -> Result<Json<Vec<SessionInfo>>> {
    let sessions = state
        .storage
        .get_user_sessions(&session.data.user_id)
        .await?;

    let session_infos: Vec<SessionInfo> = sessions
        .into_iter()
        .map(|s| SessionInfo {
            session_id: s.session_id,
            expires_at: s.expires_at,
        })
        .collect();

    Ok(Json(session_infos))
}

#[tokio::main]
async fn main() {
    // Configure JWT
    let config = JwtConfig {
        access_token_secret: "your-access-secret-key".to_string(),
        refresh_token_secret: "your-refresh-secret-key".to_string(),
        issuer: Some("my-app".to_string()),
        audience: Some("my-app-users".to_string()),
        access_token_duration: Duration::minutes(15),
        refresh_token_duration: Duration::days(7),
        refresh_token_renewal_threshold: Duration::days(1),
    };

    // Create storage and auth state
    let storage = Arc::new(InMemoryStorage::new());
    let token_generator = Arc::new(TokenGenerator::new(config));
    let auth_state = AuthState {
        token_generator,
        storage: storage.clone(),
        refresher: storage,
    };

    // Build router
    let app = Router::new()
        // Public routes
        .route("/login", post(login))
        .route(
            "/refresh",
            post(refresh_handler::<InMemoryStorage, InMemoryStorage>),
        )
        // Protected routes
        .route("/protected", get(protected))
        .route("/logout", post(logout))
        .route("/logout-all", post(logout_all))
        .route("/sessions", get(list_sessions))
        // Optional auth route
        .route("/optional", get(optional_protected))
        .with_state(auth_state);

    // Run server
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();

    println!("Server running on http://0.0.0.0:3000");
    println!("\nExample requests:");
    println!(
        "  Login: curl -X POST http://localhost:3000/login -H 'Content-Type: application/json' -d '{{\"email\":\"user@example.com\",\"password\":\"secret\"}}'"
    );
    println!(
        "  Protected: curl http://localhost:3000/protected -H 'Authorization: Bearer <access_token>'"
    );
    println!(
        "  Refresh: curl -X POST http://localhost:3000/refresh -H 'Content-Type: application/json' -d '{{\"refresh_token\":\"<refresh_token>\"}}'"
    );
    println!(
        "  List Sessions: curl http://localhost:3000/sessions -H 'Authorization: Bearer <access_token>'"
    );
    println!(
        "  Logout: curl -X POST http://localhost:3000/logout -H 'Authorization: Bearer <access_token>'"
    );
    println!(
        "  Logout All: curl -X POST http://localhost:3000/logout-all -H 'Authorization: Bearer <access_token>'"
    );

    axum::serve(listener, app).await.unwrap();
}
