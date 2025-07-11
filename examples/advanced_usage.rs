use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, get, post, put},
};
use axum_jwt_sessions::prelude::*;
use axum_jwt_sessions::storage::SessionData;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use time::{Duration, OffsetDateTime};
use tokio::sync::RwLock;
use uuid::Uuid;

// Domain models
#[derive(Debug, Clone, Serialize, Deserialize)]
struct User {
    id: String,
    email: String,
    name: String,
    role: UserRole,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
enum UserRole {
    Admin,
    User,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UserSession {
    user: User,
    login_time: OffsetDateTime,
    last_activity: OffsetDateTime,
}

// Request/Response models
#[derive(Debug, Deserialize)]
struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Debug, Serialize)]
struct LoginResponse {
    user: User,
    access_token: String,
    refresh_token: String,
}

#[derive(Debug, Deserialize)]
struct UpdateProfileRequest {
    name: Option<String>,
}

// In-memory storage with user database
#[derive(Clone)]
struct AppStorage {
    // Store sessions by user_id -> Vec<SessionData>
    user_sessions: Arc<RwLock<HashMap<String, Vec<SessionData>>>>,
    // Store session data for refresher (by user_id)
    session_data: Arc<RwLock<HashMap<String, UserSession>>>,
    // User database
    users: Arc<RwLock<HashMap<String, (User, String)>>>, // email -> (user, password)
}

#[derive(Clone)]
struct AppRefresher {
    storage: AppStorage,
}

impl SessionDataRefresher for AppRefresher {
    type SessionData = UserSession;

    async fn refresh_session_data(&self, user_id: &str) -> Result<Option<Self::SessionData>> {
        // Get cached session data or refresh from user database
        if let Some(session_data) = self.storage.session_data.read().await.get(user_id) {
            let mut updated_session = session_data.clone();
            updated_session.last_activity = OffsetDateTime::now_utc();

            // Update the cached session data
            self.storage
                .session_data
                .write()
                .await
                .insert(user_id.to_string(), updated_session.clone());

            return Ok(Some(updated_session));
        }

        // If not in cache, look up from user database
        let users = self.storage.users.read().await;
        for (user, _) in users.values() {
            if user.id == user_id {
                let session_data = UserSession {
                    user: user.clone(),
                    login_time: OffsetDateTime::now_utc(),
                    last_activity: OffsetDateTime::now_utc(),
                };

                // Cache the session data
                self.storage
                    .session_data
                    .write()
                    .await
                    .insert(user_id.to_string(), session_data.clone());

                return Ok(Some(session_data));
            }
        }
        Ok(None)
    }
}

impl AppStorage {
    fn new() -> Self {
        let mut users = HashMap::new();

        // Add some test users
        users.insert(
            "admin@example.com".to_string(),
            (
                User {
                    id: "admin-123".to_string(),
                    email: "admin@example.com".to_string(),
                    name: "Admin User".to_string(),
                    role: UserRole::Admin,
                },
                "admin123".to_string(),
            ),
        );

        users.insert(
            "user@example.com".to_string(),
            (
                User {
                    id: "user-456".to_string(),
                    email: "user@example.com".to_string(),
                    name: "Regular User".to_string(),
                    role: UserRole::User,
                },
                "user123".to_string(),
            ),
        );

        Self {
            user_sessions: Arc::new(RwLock::new(HashMap::new())),
            session_data: Arc::new(RwLock::new(HashMap::new())),
            users: Arc::new(RwLock::new(users)),
        }
    }

    async fn verify_credentials(&self, email: &str, password: &str) -> Option<User> {
        let users = self.users.read().await;
        users
            .get(email)
            .filter(|(_, pwd)| pwd == password)
            .map(|(user, _)| user.clone())
    }
}

impl SessionStorage for AppStorage {
    async fn create_user_session(
        &self,
        user_id: String,
        session_id: Uuid,
        expires_at: OffsetDateTime,
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
        let now = OffsetDateTime::now_utc();

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

// Handlers
async fn login(
    State(state): State<AuthState<AppStorage, AppRefresher>>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>> {
    // Verify credentials
    let user = state
        .storage
        .verify_credentials(&req.email, &req.password)
        .await
        .ok_or(AuthError::InvalidToken)?;

    let session_id = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();
    let session_data = UserSession {
        user: user.clone(),
        login_time: now,
        last_activity: now,
    };

    // Store session data for refresher (by user_id)
    state
        .storage
        .session_data
        .write()
        .await
        .insert(user.id.clone(), session_data.clone());

    // Generate tokens with session data
    let token_pair = state.token_generator.generate_token_pair(
        session_id,
        user.id.clone(),
        Some(session_data),
    )?;

    // Create session in user-based storage
    state
        .storage
        .create_user_session(user.id.clone(), session_id, token_pair.refresh_expires_at)
        .await?;

    Ok(Json(LoginResponse {
        user,
        access_token: token_pair.access_token,
        refresh_token: token_pair.refresh_token,
    }))
}

async fn get_profile(session: Session<UserSession>) -> Json<User> {
    Json(session.data.user)
}

async fn update_profile(
    _state: State<AuthState<AppStorage, AppRefresher>>,
    session: Session<UserSession>,
    Json(req): Json<UpdateProfileRequest>,
) -> Result<Json<User>> {
    let mut user = session.data.user;

    if let Some(name) = req.name {
        user.name = name;
    }

    // Note: In a JWT-based system, profile updates would typically require
    // the client to refresh their token to get the updated data
    Ok(Json(user))
}

async fn logout(
    State(state): State<AuthState<AppStorage, AppRefresher>>,
    session: Session<UserSession>,
) -> Result<StatusCode> {
    state
        .storage
        .revoke_user_session(&session.data.user.id, &session.session_id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn logout_all(
    State(state): State<AuthState<AppStorage, AppRefresher>>,
    session: Session<UserSession>,
) -> Result<StatusCode> {
    state
        .storage
        .revoke_all_user_sessions(&session.data.user.id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_user_sessions(
    State(state): State<AuthState<AppStorage, AppRefresher>>,
    session: Session<UserSession>,
) -> Result<Json<Vec<SessionInfo>>> {
    let sessions = state
        .storage
        .get_user_sessions(&session.data.user.id)
        .await?;

    let session_list: Vec<SessionInfo> = sessions
        .into_iter()
        .map(|data| SessionInfo {
            session_id: data.session_id,
            user_email: session.data.user.email.clone(),
            expires_at: data.expires_at,
            is_current: data.session_id == session.session_id,
        })
        .collect();

    Ok(Json(session_list))
}

async fn list_all_sessions(
    State(state): State<AuthState<AppStorage, AppRefresher>>,
    session: Session<UserSession>,
) -> Result<Json<Vec<AdminSessionInfo>>> {
    // Only admins can list all sessions
    if session.data.user.role != UserRole::Admin {
        return Err(AuthError::InvalidToken); // Using as unauthorized error
    }

    let all_sessions = state.storage.user_sessions.read().await;
    let session_data = state.storage.session_data.read().await;

    let mut admin_session_list = Vec::new();

    for (user_id, sessions) in all_sessions.iter() {
        if let Some(user_session) = session_data.get(user_id) {
            for session in sessions {
                admin_session_list.push(AdminSessionInfo {
                    session_id: session.session_id,
                    user_id: user_id.clone(),
                    user_email: user_session.user.email.clone(),
                    user_name: user_session.user.name.clone(),
                    expires_at: session.expires_at,
                });
            }
        }
    }

    Ok(Json(admin_session_list))
}

async fn delete_user_session(
    State(state): State<AuthState<AppStorage, AppRefresher>>,
    session: Session<UserSession>,
    Path((user_id, session_id)): Path<(String, Uuid)>,
) -> Result<StatusCode> {
    // Only admins can delete other users' sessions
    if session.data.user.role != UserRole::Admin {
        return Err(AuthError::InvalidToken);
    }

    state
        .storage
        .revoke_user_session(&user_id, &session_id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn health_check(session: OptionalSession<UserSession>) -> Json<HealthStatus> {
    Json(HealthStatus {
        status: "healthy".to_string(),
        authenticated: session.0.is_some(),
        timestamp: OffsetDateTime::now_utc(),
    })
}

#[derive(Debug, Serialize)]
struct SessionInfo {
    session_id: Uuid,
    user_email: String,
    expires_at: OffsetDateTime,
    is_current: bool,
}

#[derive(Debug, Serialize)]
struct AdminSessionInfo {
    session_id: Uuid,
    user_id: String,
    user_email: String,
    user_name: String,
    expires_at: OffsetDateTime,
}

#[derive(Debug, Serialize)]
struct HealthStatus {
    status: String,
    authenticated: bool,
    timestamp: OffsetDateTime,
}

#[tokio::main]
async fn main() {
    // Configure JWT with different secrets for access and refresh tokens
    let config = JwtConfig {
        access_token_secret: "super-secret-access-key-change-in-production".to_string(),
        refresh_token_secret: "super-secret-refresh-key-change-in-production".to_string(),
        issuer: Some("my-awesome-app".to_string()),
        audience: Some("my-app-users".to_string()),
        access_token_duration: Duration::minutes(15),
        refresh_token_duration: Duration::days(7),
        refresh_token_renewal_threshold: Duration::days(1),
    };

    // Create storage and auth state
    let storage = AppStorage::new();
    let refresher = AppRefresher {
        storage: storage.clone(),
    };
    let token_generator = Arc::new(TokenGenerator::new(config));
    let auth_state = AuthState {
        token_generator,
        storage: Arc::new(storage),
        refresher: Arc::new(refresher),
    };

    // Build router with different route groups
    let app = Router::new()
        // Public routes
        .route("/health", get(health_check))
        .route("/auth/login", post(login))
        .route(
            "/auth/refresh",
            post(refresh_handler::<AppStorage, AppRefresher>),
        )
        // Protected user routes
        .route("/user/profile", get(get_profile))
        .route("/user/profile", put(update_profile))
        .route("/user/sessions", get(list_user_sessions))
        .route("/auth/logout", post(logout))
        .route("/auth/logout-all", post(logout_all))
        // Admin routes
        .route("/admin/sessions", get(list_all_sessions))
        .route(
            "/admin/sessions/:user_id/:session_id",
            delete(delete_user_session),
        )
        .with_state(auth_state);

    // Run server
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();

    println!("Advanced JWT Sessions Example Server (User-Based Storage)");
    println!("=========================================================");
    println!("Server running on http://0.0.0.0:3000");
    println!("\nTest Users:");
    println!("  Admin: admin@example.com / admin123");
    println!("  User:  user@example.com / user123");
    println!("\nExample requests:");
    println!("\n1. Login as admin:");
    println!("   curl -X POST http://localhost:3000/auth/login \\");
    println!("     -H 'Content-Type: application/json' \\");
    println!("     -d '{{\"email\":\"admin@example.com\",\"password\":\"admin123\"}}'");
    println!("\n2. Get profile (requires auth):");
    println!("   curl http://localhost:3000/user/profile \\");
    println!("     -H 'Authorization: Bearer <access_token>'");
    println!("\n3. List user's own sessions:");
    println!("   curl http://localhost:3000/user/sessions \\");
    println!("     -H 'Authorization: Bearer <access_token>'");
    println!("\n4. List all sessions (admin only):");
    println!("   curl http://localhost:3000/admin/sessions \\");
    println!("     -H 'Authorization: Bearer <admin_access_token>'");
    println!("\n5. Refresh token:");
    println!("   curl -X POST http://localhost:3000/auth/refresh \\");
    println!("     -H 'Content-Type: application/json' \\");
    println!("     -d '{{\"refresh_token\":\"<refresh_token>\"}}'");
    println!("\n6. Logout from current session:");
    println!("   curl -X POST http://localhost:3000/auth/logout \\");
    println!("     -H 'Authorization: Bearer <access_token>'");
    println!("\n7. Logout from all sessions:");
    println!("   curl -X POST http://localhost:3000/auth/logout-all \\");
    println!("     -H 'Authorization: Bearer <access_token>'");

    axum::serve(listener, app).await.unwrap();
}
