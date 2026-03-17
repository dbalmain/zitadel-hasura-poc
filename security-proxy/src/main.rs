mod config;
mod db;
mod error;
mod jwt;
mod kratos;
mod recovery;
mod routes;
mod session;
mod state;

use anyhow::Result;
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = config::Config::from_env()?;

    tracing::info!("Connecting to database...");
    let db = PgPoolOptions::new()
        .max_connections(10)
        .connect(&config.database_url)
        .await?;

    tracing::info!("Generating RSA key pair...");
    let jwt_keys = Arc::new(jwt::JwtKeys::generate()?);
    tracing::info!("RSA key pair ready");

    let kratos = Arc::new(kratos::KratosClient::new(
        &config.kratos_public_url,
        &config.kratos_admin_url,
    ));

    let recovery_store = Arc::new(recovery::RecoveryStore::new());

    let http_client = reqwest::Client::new();

    let state = Arc::new(state::AppState {
        db,
        kratos,
        jwt_keys,
        recovery_store,
        hasura_url: config.hasura_url,
        jwt_issuer: config.jwt_issuer,
        http_client,
    });

    let app = routes::router(state);

    let addr = format!("0.0.0.0:{}", config.port);
    tracing::info!("Listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
