pub mod auth;
pub mod graphql;
pub mod health;
pub mod jwks;

use axum::{
    http::{header, Method},
    routing::{get, post},
    Router,
};
use std::sync::Arc;
use tower_cookies::CookieManagerLayer;
use tower_http::cors::{AllowOrigin, CorsLayer};

use crate::state::AppState;

pub fn router(state: Arc<AppState>) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::list([
            "http://localhost:3301".parse().unwrap(),
            "http://localhost:3300".parse().unwrap(),
        ]))
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION, header::COOKIE])
        .allow_credentials(true);

    Router::new()
        .route("/health", get(health::handler))
        .route("/.well-known/jwks.json", get(jwks::handler))
        .route("/api/login", post(auth::login))
        .route("/api/logout", post(auth::logout))
        .route("/api/me", get(auth::me))
        .route("/api/roles", get(auth::roles))
        .route("/api/switch-role", post(auth::switch_role))
        .route("/api/forgot-password", post(auth::forgot_password))
        .route(
            "/api/forgot-password/verify",
            post(auth::forgot_password_verify),
        )
        .route(
            "/api/forgot-password/reset",
            post(auth::forgot_password_reset),
        )
        .route("/graphql", post(graphql::handler))
        .layer(CookieManagerLayer::new())
        .layer(cors)
        .with_state(state)
}
