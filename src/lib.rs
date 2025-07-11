pub mod config;
pub mod error;
pub mod extractors;
pub mod handlers;
pub mod middleware;
pub mod refresher;
pub mod storage;
pub mod token;

#[cfg(feature = "openapi")]
pub mod openapi;

pub use config::JwtConfig;
pub use error::{AuthError, Result};
pub use extractors::{OptionalRefreshSession, OptionalSession, RefreshSession, Session};
pub use handlers::{refresh_handler, RefreshRequest, RefreshResponse};
pub use middleware::{auth_middleware, require_refresh_token, AuthConfig, AuthState};
pub use refresher::SessionDataRefresher;
pub use storage::{SessionData, SessionStorage};
pub use token::{Claims, TokenGenerator, TokenPair, TokenType};

pub mod prelude {
    pub use crate::{
        config::JwtConfig,
        error::{AuthError, Result},
        extractors::{OptionalRefreshSession, OptionalSession, RefreshSession, Session},
        handlers::{refresh_handler, RefreshRequest, RefreshResponse},
        middleware::{auth_middleware, require_refresh_token, AuthConfig, AuthState},
        refresher::SessionDataRefresher,
        storage::{SessionData, SessionStorage},
        token::{Claims, TokenGenerator, TokenPair, TokenType},
    };
}
