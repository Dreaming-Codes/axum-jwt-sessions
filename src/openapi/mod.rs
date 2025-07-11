use utoipa::{openapi::security::SecurityScheme, Modify, OpenApi};

/// JWT Bearer Authentication security scheme for OpenAPI documentation
pub struct JwtSecurityScheme;

impl Modify for JwtSecurityScheme {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer_auth",
                SecurityScheme::Http(utoipa::openapi::security::Http::new(
                    utoipa::openapi::security::HttpAuthScheme::Bearer,
                )),
            );
        }
    }
}
