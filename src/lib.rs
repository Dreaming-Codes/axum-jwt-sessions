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
pub use handlers::{RefreshRequest, RefreshResponse, refresh_handler};
pub use middleware::{AuthConfig, AuthState, auth_middleware, require_refresh_token};
pub use refresher::SessionDataRefresher;
#[cfg(feature = "cloudflare-kv")]
pub use storage::CloudflareKvStorage;
pub use storage::{SessionData, SessionStorage};
pub use token::{Claims, TokenGenerator, TokenPair, TokenType};

pub mod prelude {
    pub use crate::{
        config::JwtConfig,
        error::{AuthError, Result},
        extractors::{OptionalRefreshSession, OptionalSession, RefreshSession, Session},
        handlers::{RefreshRequest, RefreshResponse, refresh_handler},
        middleware::{AuthConfig, AuthState, auth_middleware, require_refresh_token},
        refresher::SessionDataRefresher,
        storage::{SessionData, SessionStorage},
        token::{Claims, TokenGenerator, TokenPair, TokenType},
    };

    #[cfg(feature = "cloudflare-kv")]
    pub use crate::storage::CloudflareKvStorage;
}
