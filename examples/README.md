# Axum JWT Sessions Examples

This directory contains examples demonstrating how to use the `axum-jwt-sessions` library.

## Examples

### 1. Basic Usage (`basic_usage.rs`)

A simple example showing the core functionality:
- User login with JWT token generation
- Protected routes using the `Session` extractor
- Optional authentication with `OptionalSession`
- Token refresh endpoint
- Logout functionality

Run with:
```bash
cargo run --example basic_usage
```

### 2. Advanced Usage (`advanced_usage.rs`)

A more comprehensive example featuring:
- Role-based access control (Admin/User roles)
- User profile management
- Session listing (admin only)
- Activity tracking
- Multiple user accounts with different permissions

Run with:
```bash
cargo run --example advanced_usage
```

Test users:
- Admin: `admin@example.com` / `admin123`
- User: `user@example.com` / `user123`

### 3. With Middleware (`with_middleware.rs`)

Demonstrates integration with Axum middleware:
- Custom logging middleware
- Permission-based access control
- Manual permission checking in handlers
- Different permission levels (read, write, delete)

Run with:
```bash
cargo run --example with_middleware
```

Test users:
- Admin: `admin@example.com` / `admin` (all permissions)
- Editor: `editor@example.com` / `editor` (read, write)
- Viewer: `viewer@example.com` / `viewer` (read only)

### 4. Secure Paths (`secure_paths.rs`)

Advanced example showing extra security for sensitive operations:
- Routes that require both access AND refresh tokens
- Custom `SecureSession` extractor
- Two-factor authentication support
- Re-authentication for sensitive operations
- Different security levels for different endpoints
- Financial transaction example with balance checks

Run with:
```bash
cargo run --example secure_paths
```

Test users:
- Alice: `alice@example.com` / `secure123` (2FA enabled, code: `123456`)
- Bob: `bob@example.com` / `password123` (2FA disabled)

Security levels:
- `/account/*` - Requires only access token
- `/secure/*` - Requires both access and refresh tokens
- `/admin/*` - Requires both access and refresh tokens

## Testing the Examples

All examples include curl commands in their console output showing how to interact with the API. Here are some common patterns:

### Login
```bash
curl -X POST http://localhost:3000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"user@example.com","password":"password"}'
```

### Access Protected Route
```bash
curl http://localhost:3000/protected \
  -H 'Authorization: Bearer <access_token>'
```

### Refresh Token
```bash
curl -X POST http://localhost:3000/auth/refresh \
  -H 'Content-Type: application/json' \
  -d '{"refresh_token":"<refresh_token>"}'
```

## Key Concepts Demonstrated

1. **Session Storage**: All examples implement the `SessionStorage` trait with in-memory storage
2. **Token Generation**: Using separate secrets for access and refresh tokens
3. **Protected Routes**: Using `Session<T>` extractor for authentication
4. **Optional Auth**: Using `OptionalSession<T>` for routes that work with or without auth
5. **Error Handling**: Proper error responses using the `AuthError` type
6. **Rust 2024**: Examples use native async traits without the `async-trait` crate