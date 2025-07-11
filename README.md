# Axum JWT Sessions

A flexible JWT authentication library for Axum with refresh token support and user-based session management.

## Features

- **User-based session storage** - Sessions are organized by user_id with multiple sessions per user
- **Stateless session data** stored directly in JWT tokens (following JWT best practices)
- **Configurable token durations** for both access and refresh tokens
- **Automatic refresh token renewal** when approaching expiration
- **Multiple session management** - Users can have multiple active sessions across devices
- **Flexible middleware** with optional refresh token requirements
- **Session extractors** for both required and optional authentication
- **Type-safe session data** with user-defined types
- **Secure refresh token paths** with automatic subject verification

## Installation

```toml
[dependencies]
axum-jwt-sessions = "0.1.0"
```

## Quick Start

```rust
use axum_jwt_sessions::prelude::*;
use time::Duration;
use uuid::Uuid;

// Define your session data
#[derive(Debug, Clone, Serialize, Deserialize)]
struct UserSession {
    user_id: String,
    email: String,
    roles: Vec<String>,
}

// Implement SessionStorage trait for user-based session management
struct MyStorage;

impl SessionStorage for MyStorage {
    // Create a new session for a user
    async fn create_user_session(
        &self,
        user_id: String,
        session_id: Uuid,
        expires_at: OffsetDateTime,
    ) -> Result<()> {
        // Store session data in user's session array
        Ok(())
    }

    // Get all active sessions for a user
    async fn get_user_sessions(&self, user_id: &str) -> Result<Vec<SessionData>> {
        // Return all active sessions for this user
        Ok(vec![])
    }

    // Revoke a specific session for a user
    async fn revoke_user_session(&self, user_id: &str, session_id: &Uuid) -> Result<()> {
        // Remove specific session from user's session array
        Ok(())
    }

    // Revoke all sessions for a user
    async fn revoke_all_user_sessions(&self, user_id: &str) -> Result<()> {
        // Clear all sessions for this user
        Ok(())
    }
}

// Implement SessionDataRefresher to fetch fresh data during token refresh
impl SessionDataRefresher for MyStorage {
    type SessionData = UserSession;

    async fn refresh_session_data(&self, user_id: &str) -> Result<Option<Self::SessionData>> {
        // Fetch fresh user data from your database using user_id
        // This ensures tokens always have up-to-date information
        Ok(Some(UserSession {
            user_id: user_id.to_string(),
            email: "user@example.com".to_string(),
            roles: vec!["user".to_string()],
        }))
    }
}

// Configure JWT settings
let jwt_config = JwtConfig {
    access_token_secret: "access-secret".to_string(),
    refresh_token_secret: "refresh-secret".to_string(),
    issuer: Some("my-app".to_string()),
    audience: Some("my-app-users".to_string()),
    access_token_duration: Duration::minutes(15),
    refresh_token_duration: Duration::days(7),
    refresh_token_renewal_threshold: Duration::days(1),
};

// Create auth state
let storage = Arc::new(MyStorage);
let auth_state = AuthState {
    token_generator: Arc::new(TokenGenerator::new(jwt_config)),
    storage: storage.clone(),
    refresher: storage,
};

// Login endpoint
async fn login(State(state): State<AuthState<MyStorage, MyStorage>>) -> Result<Json<TokenResponse>> {
    let user_id = "user-123".to_string();
    let session_data = UserSession {
        user_id: user_id.clone(),
        email: "user@example.com".to_string(),
        roles: vec!["user".to_string()],
    };

    let session_id = Uuid::new_v4();

    // Generate tokens with session data embedded in access token
    let tokens = state.token_generator.generate_token_pair(
        session_id,
        user_id.clone(),
        Some(session_data),
    )?;

    // Create session in user-based storage
    state.storage.create_user_session(
        user_id,
        session_id,
        tokens.refresh_expires_at,
    ).await?;

    Ok(Json(TokenResponse {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
    }))
}

// Use in routes - session data comes from the JWT
async fn protected_route(session: Session<UserSession>) -> String {
    format!("Hello, {}", session.data.email)
}

async fn optional_auth_route(session: OptionalSession<UserSession>) -> String {
    match session.0 {
        Some(s) => format!("Hello, {}", s.data.email),
        None => "Hello, anonymous".to_string(),
    }
}
```

## User-Based Session Management

The library now organizes sessions by user_id, allowing multiple sessions per user:

```rust
// List all sessions for a user
async fn list_user_sessions(
    State(state): State<AuthState<MyStorage, MyStorage>>,
    session: Session<UserSession>,
) -> Result<Json<Vec<SessionData>>> {
    let sessions = state.storage.get_user_sessions(&session.data.user_id).await?;
    Ok(Json(sessions))
}

// Logout from current session only
async fn logout(
    State(state): State<AuthState<MyStorage, MyStorage>>,
    session: Session<UserSession>,
) -> Result<&'static str> {
    state.storage.revoke_user_session(
        &session.data.user_id,
        &session.session_id,
    ).await?;
    Ok("Logged out successfully")
}

// Logout from all sessions (all devices)
async fn logout_all(
    State(state): State<AuthState<MyStorage, MyStorage>>,
    session: Session<UserSession>,
) -> Result<&'static str> {
    state.storage.revoke_all_user_sessions(&session.data.user_id).await?;
    Ok("Logged out from all devices")
}
```

## Middleware Configuration

The library provides flexible middleware configuration:

```rust
// Standard authentication (access token only)
.layer(middleware::from_fn_with_state(
    auth_state.clone(),
    auth_middleware,
))

// High-security endpoints (requires refresh token)
.layer(middleware::from_fn_with_state(
    auth_state.clone(),
    require_refresh_token,
))
```

## Token Refresh

The library includes a built-in refresh handler that fetches fresh session data when refreshing tokens:

```rust
app.route("/refresh", post(refresh_handler::<MyStorage, MyStorage>))
```

The refresh handler:
1. Verifies the refresh token contains a valid user_id
2. Checks if the specific session exists for that user
3. Uses the `SessionDataRefresher` trait to fetch up-to-date session data
4. Generates new tokens with fresh session data
5. Optionally rotates the refresh token if approaching expiration

## SessionData Structure

Each session is represented by a `SessionData` struct:

```rust
#[derive(Debug, Clone, Serialize)]
pub struct SessionData {
    pub session_id: Uuid,
    pub expires_at: OffsetDateTime,
}
```

## Architecture

This library follows JWT best practices by storing session data directly in the JWT access token, while using user-based storage for refresh token management. This approach provides:

- **Better scalability** - No database queries for session data on each request
- **Stateless operation** - Session data travels with the token
- **Multi-device support** - Users can have multiple active sessions
- **Granular control** - Revoke specific sessions or all sessions for a user
- **Reduced latency** - No round-trip to storage for session data

The storage layer is used for:
- Tracking refresh tokens organized by user_id
- Managing multiple sessions per user
- Preventing use of revoked refresh tokens
- Supporting logout from specific devices or all devices

## JWT Token Structure

### Access Token Claims
```json
{
  "sub": "session-uuid",
  "user_id": "user-123",
  "exp": 1234567890,
  "iat": 1234567890,
  "token_type": "access",
  "session_data": {
    "user_id": "user-123",
    "email": "user@example.com",
    "roles": ["user"]
  }
}
```

### Refresh Token Claims
```json
{
  "sub": "session-uuid",
  "user_id": "user-123",
  "exp": 1234567890,
  "iat": 1234567890,
  "token_type": "refresh"
}
```

## Security Considerations

- **Refresh token paths**: When using `RefreshSession` extractor, both access and refresh tokens must be provided and have matching subjects
- **Token size**: Keep session data minimal as it increases token size
- **Sensitive data**: Don't store sensitive information in JWT claims
- **Token rotation**: Refresh tokens are automatically rotated when approaching expiration
- **Session isolation**: Each session is tracked independently, allowing selective revocation

## Examples

See the `examples/` directory for complete working examples:
- `basic_usage.rs` - Simple authentication setup with user-based sessions
- `advanced_usage.rs` - User management with roles and multiple session handling
- `with_middleware.rs` - Using authentication middleware
- `secure_paths.rs` - Implementing high-security endpoints with refresh token requirements
- `with_openapi.rs` - OpenAPI documentation with utoipa and Scalar UI

## OpenAPI Documentation Support

The library provides built-in OpenAPI documentation support through the `utoipa` crate when the `openapi` feature is enabled.

### Enabling OpenAPI

Add the `openapi` feature to your dependencies:

```toml
[dependencies]
axum-jwt-sessions = { version = "0.1", features = ["openapi"] }
```

### Automatic Schema Generation

When the `openapi` feature is enabled, the following types automatically implement `ToSchema`:

- `RefreshRequest` - Request body for token refresh
- `RefreshResponse` - Response from token refresh
- `SessionData` - Session information
- `ErrorResponse` - Authentication error responses
- `TokenType` - Token type enumeration (access/refresh)

### Example Usage

```rust
use utoipa::{OpenApi, ToSchema};
use axum_jwt_sessions::openapi::JwtSecurityScheme;
use axum_jwt_sessions::typed_refresh_handler;
use utoipa_axum::{router::OpenApiRouter, routes};

// Define your session data with ToSchema
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
struct UserSession {
    user_id: String,
    email: String,
}

// Document your endpoints
#[utoipa::path(
    post,
    path = "/login",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Success", body = LoginResponse),
        (status = 401, description = "Invalid credentials"),
    ),
    tag = "auth"
)]
async fn login(/* ... */) -> Result<Json<LoginResponse>> {
    // Implementation
}

// Create the base OpenAPI documentation
#[derive(OpenApi)]
#[openapi(
    modifiers(&JwtSecurityScheme),
    tags(
        (name = "auth", description = "Authentication endpoints")
    )
)]
struct ApiDoc;

// Create a typed refresh handler (required for routes! macro)
typed_refresh_handler!(refresh, MyStorage, MyRefresher);

// Build router with automatic path collection
let (router, api) = OpenApiRouter::new()
    .routes(routes!(login))
    .routes(routes!(refresh))
    .routes(routes!(logout))
    .routes(routes!(protected))
    .with_state(auth_state)
    .split_for_parts();

// Merge the generated API with base documentation
let mut api_doc = ApiDoc::openapi();
api_doc.merge(api);

// Serve the OpenAPI JSON and Scalar UI
let api_doc = Arc::new(api_doc);
let app = router
    .route("/api-docs/openapi.json", get({
        let doc = api_doc.clone();
        move || async move { Json(doc.as_ref().clone()) }
    }))
    .merge(Scalar::with_url("/scalar", api_doc.as_ref().clone()));
```

Add the necessary dependencies:
```toml
[dependencies]
utoipa-axum = "0.2"
utoipa-scalar = { version = "0.3", features = ["axum"] }
```

### JWT Security Scheme

The library provides `JwtSecurityScheme` which automatically adds JWT Bearer authentication to your OpenAPI documentation:

```rust
#[utoipa::path(
    get,
    path = "/protected",
    responses(
        (status = 200, description = "Success", body = UserData),
        (status = 401, description = "Unauthorized", body = ErrorResponse),
    ),
    security(("bearer_auth" = [])),
    tag = "auth"
)]
async fn protected(session: Session<UserData>) -> Json<UserData> {
    Json(session.data)
}
```

### Interactive API Documentation with Scalar

The example uses `utoipa-axum` for automatic path collection and `utoipa-scalar` for beautiful, interactive API documentation:

```rust
use utoipa_axum::{router::OpenApiRouter, routes};
use utoipa_scalar::{Scalar, Servable};
use axum_jwt_sessions::typed_refresh_handler;

// Create a typed refresh handler for use with routes!
typed_refresh_handler!(refresh, MyStorage, MyRefresher);

// Build router with automatic OpenAPI integration
let (router, api) = OpenApiRouter::new()
    .routes(routes!(your_endpoints))
    .routes(routes!(refresh))
    .with_state(auth_state)
    .split_for_parts();
```

This provides:
- Automatic path collection from your handlers
- Type-safe refresh handler with OpenAPI support via `typed_refresh_handler!` macro
- Clean integration with Axum's router
- Modern API documentation interface at `/scalar`
- Interactive request/response examples
- Dark/light theme support
- Search functionality
- Try-it-out capabilities

For a complete example, see `examples/with_openapi.rs`.

## Migration from Session-Based to User-Based Storage

If upgrading from a session-based storage implementation, you need to:

1. Update your storage implementation to use the new trait methods
2. Change from `session_id` primary keys to `user_id` primary keys
3. Store sessions as arrays within user records
4. Update refresh token generation to include `user_id`
5. Modify logout handlers to specify which session to revoke

The library maintains backward compatibility for the JWT token structure while providing the new user-based storage capabilities.
