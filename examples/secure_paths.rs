use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post, put},
    Json, Router,
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
    balance: f64,
    two_factor_enabled: bool,
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

#[derive(Debug, Serialize)]
struct BalanceResponse {
    balance: f64,
}

#[derive(Debug, Deserialize)]
struct TransferRequest {
    to_user_id: String,
    amount: f64,
}

#[derive(Debug, Serialize)]
struct TransferResponse {
    new_balance: f64,
    transaction_id: Uuid,
}

#[derive(Debug, Deserialize)]
struct ProfileUpdateRequest {
    name: Option<String>,
    two_factor_enabled: Option<bool>,
}

// Storage implementation
#[derive(Clone)]
struct SecureStorage {
    // Store sessions by user_id -> Vec<SessionData>
    user_sessions: Arc<RwLock<HashMap<String, Vec<SessionData>>>>,
    // Store session data for refresher (by user_id)
    session_data: Arc<RwLock<HashMap<String, UserSession>>>,
    // User database
    users: Arc<RwLock<HashMap<String, (User, String)>>>, // email -> (user, password)
}

#[derive(Clone)]
struct SecureRefresher {
    storage: SecureStorage,
}

impl SessionDataRefresher for SecureRefresher {
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
        // For this example, we'll use hardcoded users
        let user = match user_id {
            "user-001" => User {
                id: "user-001".to_string(),
                email: "alice@example.com".to_string(),
                name: "Alice Smith".to_string(),
                balance: 10000.0,
                two_factor_enabled: true,
            },
            "user-002" => User {
                id: "user-002".to_string(),
                email: "bob@example.com".to_string(),
                name: "Bob Johnson".to_string(),
                balance: 5000.0,
                two_factor_enabled: false,
            },
            _ => return Ok(None),
        };

        {
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

            Ok(Some(session_data))
        }
    }
}

impl SecureStorage {
    fn new() -> Self {
        let mut users = HashMap::new();

        users.insert(
            "alice@example.com".to_string(),
            (
                User {
                    id: "user-001".to_string(),
                    email: "alice@example.com".to_string(),
                    name: "Alice Smith".to_string(),
                    balance: 10000.0,
                    two_factor_enabled: true,
                },
                "secure123".to_string(),
            ),
        );

        users.insert(
            "bob@example.com".to_string(),
            (
                User {
                    id: "user-002".to_string(),
                    email: "bob@example.com".to_string(),
                    name: "Bob Johnson".to_string(),
                    balance: 5000.0,
                    two_factor_enabled: false,
                },
                "password123".to_string(),
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
            .filter(|(_, stored_password)| stored_password == password)
            .map(|(user, _)| user.clone())
    }

    async fn update_balance(&self, user_id: &str, amount: f64) -> Result<()> {
        // For this example, we'll just update the cached session data
        let mut session_data = self.session_data.write().await;
        if let Some(session) = session_data.get_mut(user_id) {
            session.user.balance += amount;
            Ok(())
        } else {
            Err(AuthError::SessionNotFound)
        }
    }
}

impl SessionStorage for SecureStorage {
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
    State(state): State<AuthState<SecureStorage, SecureRefresher>>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>> {
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

async fn get_balance(session: Session<UserSession>) -> Json<BalanceResponse> {
    Json(BalanceResponse {
        balance: session.data.user.balance,
    })
}

async fn transfer_money(
    State(state): State<AuthState<SecureStorage, SecureRefresher>>,
    session: RefreshSession<UserSession>,
    Json(req): Json<TransferRequest>,
) -> Result<Json<TransferResponse>> {
    // This endpoint requires a valid refresh token for extra security

    if req.amount <= 0.0 {
        return Err(AuthError::InvalidToken);
    }

    if session.data.user.balance < req.amount {
        return Err(AuthError::InvalidToken);
    }

    // Deduct from sender
    state
        .storage
        .update_balance(&session.data.user.id, -req.amount)
        .await?;

    // Add to receiver (simplified - in real app, verify receiver exists)
    state
        .storage
        .update_balance(&req.to_user_id, req.amount)
        .await?;

    Ok(Json(TransferResponse {
        new_balance: session.data.user.balance - req.amount,
        transaction_id: Uuid::new_v4(),
    }))
}

async fn update_profile(
    State(state): State<AuthState<SecureStorage, SecureRefresher>>,
    session: RefreshSession<UserSession>,
    Json(req): Json<ProfileUpdateRequest>,
) -> Result<Json<User>> {
    // This endpoint requires a valid refresh token for extra security

    // For this example, we'll just update the cached session data
    let mut session_data = state.storage.session_data.write().await;
    if let Some(session) = session_data.get_mut(&session.data.user.id) {
        if let Some(name) = req.name {
            session.user.name = name;
        }
        if let Some(two_factor) = req.two_factor_enabled {
            session.user.two_factor_enabled = two_factor;
        }
        Ok(Json(session.user.clone()))
    } else {
        Err(AuthError::SessionNotFound)
    }
}

async fn logout(
    State(state): State<AuthState<SecureStorage, SecureRefresher>>,
    session: RefreshSession<UserSession>,
) -> Result<StatusCode> {
    state
        .storage
        .revoke_user_session(&session.data.user.id, &session.session_id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[tokio::main]
async fn main() {
    // Configure JWT with shorter access token duration for security
    let config = JwtConfig {
        access_token_secret: "secure-example-access-secret-key".to_string(),
        refresh_token_secret: "secure-example-refresh-secret-key".to_string(),
        issuer: Some("secure-bank-api".to_string()),
        audience: Some("bank-customers".to_string()),
        access_token_duration: Duration::minutes(5), // Short duration for security
        refresh_token_duration: Duration::hours(1),  // Also shorter for security
        refresh_token_renewal_threshold: Duration::minutes(10),
    };

    // Create storage and auth state
    let storage = SecureStorage::new();
    let refresher = SecureRefresher {
        storage: storage.clone(),
    };
    let token_generator = Arc::new(TokenGenerator::new(config));
    let auth_state = AuthState {
        token_generator,
        storage: Arc::new(storage),
        refresher: Arc::new(refresher),
    };

    // Build router with different security levels
    let app = Router::new()
        // Public routes
        .route("/auth/login", post(login))
        .route(
            "/auth/refresh",
            post(refresh_handler::<SecureStorage, SecureRefresher>),
        )
        // Regular protected routes (only need access token)
        .route("/account/balance", get(get_balance))
        .route("/auth/logout", post(logout))
        // Secure routes that require refresh token
        .route("/account/transfer", post(transfer_money))
        .route("/account/profile", put(update_profile))
        .with_state(auth_state);

    // Run server
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();

    println!("Secure JWT Sessions Example");
    println!("===========================");
    println!("Server running on http://0.0.0.0:3000");
    println!("\nTest Users:");
    println!("  Alice: alice@example.com / secure123 (2FA enabled)");
    println!("  Bob:   bob@example.com / password123 (2FA disabled)");
    println!("\nExample requests:");
    println!("\n1. Login as Alice:");
    println!("   curl -X POST http://localhost:3000/auth/login \\");
    println!("     -H 'Content-Type: application/json' \\");
    println!("     -d '{{\"email\":\"alice@example.com\",\"password\":\"secure123\"}}'");
    println!("\n2. Check balance (regular auth):");
    println!("   curl http://localhost:3000/account/balance \\");
    println!("     -H 'Authorization: Bearer <access_token>'");
    println!("\n3. Transfer money (requires refresh token):");
    println!("   curl -X POST http://localhost:3000/account/transfer \\");
    println!("     -H 'Authorization: Bearer <access_token>' \\");
    println!("     -H 'X-Refresh-Token: <refresh_token>' \\");
    println!("     -H 'Content-Type: application/json' \\");
    println!("     -d '{{\"to_account\":\"target-account\",\"amount\":100.0}}'");
    println!("\n4. Update profile (requires refresh token):");
    println!("   curl -X PUT http://localhost:3000/account/profile \\");
    println!("     -H 'Authorization: Bearer <access_token>' \\");
    println!("     -H 'X-Refresh-Token: <refresh_token>' \\");
    println!("     -H 'Content-Type: application/json' \\");
    println!("     -d '{{\"name\":\"New Name\",\"two_factor_enabled\":true}}'");

    axum::serve(listener, app).await.unwrap();
}
