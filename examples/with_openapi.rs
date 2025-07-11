use axum::{extract::State, routing::get, Json};
use axum_jwt_sessions::error::ErrorResponse;
use axum_jwt_sessions::openapi::JwtSecurityScheme;
use axum_jwt_sessions::prelude::*;
use axum_jwt_sessions::storage::SessionData;
use axum_jwt_sessions::typed_refresh_handler;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use time::Duration;
use time::OffsetDateTime;
use tokio::sync::RwLock;
use utoipa::{OpenApi, ToSchema};
use utoipa_axum::{router::OpenApiRouter, routes};
use utoipa_scalar::{Scalar, Servable};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
struct UserSession {
    user_id: String,
    email: String,
}

#[derive(Debug, Deserialize, ToSchema)]
struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Debug, Serialize, ToSchema)]
struct LoginResponse {
    access_token: String,
    refresh_token: String,
}

#[derive(Debug, Serialize, ToSchema)]
struct SessionInfo {
    session_id: uuid::Uuid,
    expires_at: OffsetDateTime,
}

// In-memory storage implementation
#[derive(Clone)]
struct InMemoryStorage {
    user_sessions: Arc<RwLock<HashMap<String, Vec<SessionData>>>>,
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

// Handler functions with OpenAPI documentation
#[utoipa::path(
    post,
    path = "/login",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login successful", body = LoginResponse),
        (status = 401, description = "Invalid credentials", body = ErrorResponse),
    ),
    tag = "auth"
)]
async fn login(
    State(state): State<AuthState<InMemoryStorage, InMemoryStorage>>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>> {
    if req.password != "secret" {
        return Err(AuthError::InvalidToken);
    }

    let session_id = Uuid::new_v4();
    let user_id = "user123".to_string();
    let session_data = UserSession {
        user_id: user_id.clone(),
        email: req.email,
    };

    state
        .storage
        .session_data
        .write()
        .await
        .insert(user_id.clone(), session_data.clone());

    let token_pair = state.token_generator.generate_token_pair(
        session_id,
        user_id.clone(),
        Some(session_data),
    )?;

    state
        .storage
        .create_user_session(user_id, session_id, token_pair.refresh_expires_at)
        .await?;

    Ok(Json(LoginResponse {
        access_token: token_pair.access_token,
        refresh_token: token_pair.refresh_token,
    }))
}

#[utoipa::path(
    get,
    path = "/protected",
    responses(
        (status = 200, description = "Access granted", body = UserSession),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "auth"
)]
async fn protected(session: Session<UserSession>) -> Json<UserSession> {
    Json(session.data)
}

#[utoipa::path(
    post,
    path = "/logout",
    responses(
        (status = 200, description = "Logout successful"),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "auth"
)]
async fn logout(
    State(state): State<AuthState<InMemoryStorage, InMemoryStorage>>,
    session: Session<UserSession>,
) -> Result<&'static str> {
    state
        .storage
        .revoke_user_session(&session.data.user_id, &session.session_id)
        .await?;
    Ok("Logged out successfully")
}

#[utoipa::path(
    get,
    path = "/sessions",
    responses(
        (status = 200, description = "List of active sessions", body = Vec<SessionInfo>),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "auth"
)]
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

// Concrete refresh handler for this example
typed_refresh_handler!(refresh, InMemoryStorage, InMemoryStorage);

// Define the OpenAPI documentation
#[derive(OpenApi)]
#[openapi(
    info(
        title = "JWT Sessions Example API",
        version = "1.0.0",
        description = "Example API demonstrating axum-jwt-sessions with OpenAPI documentation"
    ),
    modifiers(&JwtSecurityScheme),
    tags(
        (name = "auth", description = "Authentication endpoints")
    )
)]
struct ApiDoc;

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

    // Build router with OpenAPI support using utoipa-axum
    let (router, api) = OpenApiRouter::with_openapi(ApiDoc::openapi())
        .routes(routes!(login))
        .routes(routes!(refresh))
        .routes(routes!(protected))
        .routes(routes!(logout))
        .routes(routes!(list_sessions))
        .with_state(auth_state)
        .split_for_parts();

    // Create the complete app with OpenAPI endpoints
    let api_json = serde_json::to_value(api.clone()).expect("Failed to convert api to JSON");
    let app = router
        .route(
            "/api-docs/openapi.json",
            get(move || async { Json(api_json) }),
        )
        .merge(Scalar::with_url("/scalar", api));

    // Run server
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();

    println!("Server running on http://0.0.0.0:3000");
    println!("\nAPI Documentation:");
    println!("  OpenAPI JSON: http://0.0.0.0:3000/api-docs/openapi.json");
    println!("  Scalar UI: http://0.0.0.0:3000/scalar");
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

    axum::serve(listener, app).await.unwrap();
}
