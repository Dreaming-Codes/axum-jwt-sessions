use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
};
use axum_jwt_sessions::prelude::*;
use axum_jwt_sessions::storage::SessionData;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use time::Duration;
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UserSession {
    user_id: String,
    email: String,
    permissions: Vec<String>,
}

#[derive(Clone)]
struct SimpleStorage {
    // Store sessions by user_id -> Vec<SessionData>
    user_sessions: Arc<RwLock<HashMap<String, Vec<SessionData>>>>,
    // Store session data for refresher (by user_id)
    session_data: Arc<RwLock<HashMap<String, UserSession>>>,
}

#[derive(Clone)]
struct SimpleRefresher;

impl SessionDataRefresher for SimpleRefresher {
    type SessionData = UserSession;

    async fn refresh_session_data(&self, user_id: &str) -> Result<Option<Self::SessionData>> {
        // In a real app, you'd fetch fresh data from database
        let session_data = UserSession {
            user_id: user_id.to_string(),
            email: format!("{user_id}@example.com"),
            permissions: vec!["read".to_string()],
        };
        Ok(Some(session_data))
    }
}

impl SimpleStorage {
    fn new() -> Self {
        Self {
            user_sessions: Arc::new(RwLock::new(HashMap::new())),
            session_data: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl SessionStorage for SimpleStorage {
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

// Request handlers
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

async fn login(
    State(state): State<AuthState<SimpleStorage, SimpleRefresher>>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>> {
    // Simple auth check
    let (user_id, permissions) = match req.email.as_str() {
        "admin@example.com" if req.password == "admin" => (
            "admin-1".to_string(),
            vec![
                "read".to_string(),
                "write".to_string(),
                "delete".to_string(),
            ],
        ),
        "editor@example.com" if req.password == "editor" => (
            "editor-1".to_string(),
            vec!["read".to_string(), "write".to_string()],
        ),
        "viewer@example.com" if req.password == "viewer" => {
            ("viewer-1".to_string(), vec!["read".to_string()])
        }
        _ => return Err(AuthError::InvalidToken),
    };

    let session_id = Uuid::new_v4();
    let session_data = UserSession {
        user_id: user_id.clone(),
        email: req.email,
        permissions,
    };

    // Store session data for refresher (by user_id)
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

    // Create session in user-based storage
    state
        .storage
        .create_user_session(user_id.clone(), session_id, token_pair.refresh_expires_at)
        .await?;

    Ok(Json(LoginResponse {
        access_token: token_pair.access_token,
        refresh_token: token_pair.refresh_token,
    }))
}

async fn read_data(session: Session<UserSession>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "message": "Reading data",
        "user": session.data.email,
        "permissions": session.data.permissions
    }))
}

async fn write_data(session: Session<UserSession>) -> Result<Json<serde_json::Value>> {
    // Check permission manually in handler
    if !session.data.permissions.contains(&"write".to_string()) {
        return Err(AuthError::InvalidToken);
    }

    Ok(Json(serde_json::json!({
        "message": "Writing data",
        "user": session.data.email
    })))
}

async fn delete_data(session: Session<UserSession>) -> Result<StatusCode> {
    // Check permission manually in handler
    if !session.data.permissions.contains(&"delete".to_string()) {
        return Err(AuthError::InvalidToken);
    }

    Ok(StatusCode::NO_CONTENT)
}

async fn public_endpoint() -> &'static str {
    "This is a public endpoint"
}

// Custom middleware that logs requests
async fn logging_middleware(request: axum::extract::Request, next: Next) -> Response {
    let method = request.method().clone();
    let uri = request.uri().clone();

    println!("Incoming request: {method} {uri}");

    let response = next.run(request).await;

    println!("Response status: {}", response.status());

    response
}

#[tokio::main]
async fn main() {
    // Configure JWT
    let config = JwtConfig {
        access_token_secret: "middleware-example-access-secret".to_string(),
        refresh_token_secret: "middleware-example-refresh-secret".to_string(),
        issuer: Some("middleware-example".to_string()),
        audience: Some("api-users".to_string()),
        access_token_duration: Duration::minutes(15),
        refresh_token_duration: Duration::days(7),
        refresh_token_renewal_threshold: Duration::days(1),
    };

    // Create storage and auth state
    let storage = SimpleStorage::new();
    let refresher = SimpleRefresher;
    let token_generator = Arc::new(TokenGenerator::new(config));
    let auth_state = AuthState {
        token_generator,
        storage: Arc::new(storage),
        refresher: Arc::new(refresher),
    };

    // Build router with middleware
    let app = Router::new()
        // Public routes
        .route("/public", get(public_endpoint))
        .route("/auth/login", post(login))
        .route(
            "/auth/refresh",
            post(refresh_handler::<SimpleStorage, SimpleRefresher>),
        )
        // Protected routes with different permission requirements
        .route("/api/read", get(read_data))
        .route("/api/write", post(write_data))
        .route("/api/delete", axum::routing::delete(delete_data))
        // Add logging middleware to all routes
        .layer(middleware::from_fn(logging_middleware))
        .with_state(auth_state);

    // Run server
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();

    println!("JWT Sessions with Middleware Example");
    println!("====================================");
    println!("Server running on http://0.0.0.0:3000");
    println!("\nTest Users:");
    println!("  Admin:  admin@example.com / admin   (permissions: read, write, delete)");
    println!("  Editor: editor@example.com / editor (permissions: read, write)");
    println!("  Viewer: viewer@example.com / viewer (permissions: read)");
    println!("\nExample requests:");
    println!("\n1. Public endpoint (no auth required):");
    println!("   curl http://localhost:3000/public");
    println!("\n2. Login as editor:");
    println!("   curl -X POST http://localhost:3000/auth/login \\");
    println!("     -H 'Content-Type: application/json' \\");
    println!("     -d '{{\"email\":\"editor@example.com\",\"password\":\"editor\"}}'");
    println!("\n3. Read data (requires 'read' permission):");
    println!("   curl http://localhost:3000/api/read \\");
    println!("     -H 'Authorization: Bearer <access_token>'");
    println!("\n4. Write data (requires 'write' permission):");
    println!("   curl -X POST http://localhost:3000/api/write \\");
    println!("     -H 'Authorization: Bearer <access_token>'");
    println!("\n5. Delete data (requires 'delete' permission):");
    println!("   curl -X DELETE http://localhost:3000/api/delete \\");
    println!("     -H 'Authorization: Bearer <access_token>'");

    axum::serve(listener, app).await.unwrap();
}
