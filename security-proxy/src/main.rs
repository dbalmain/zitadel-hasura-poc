mod config;
mod db;
mod error;
mod idp;
mod jwt;
mod kratos;
mod oidc_state;
mod recovery;
mod routes;
mod session;
mod state;
mod zitadel;

use anyhow::Result;
use sqlx::postgres::PgPoolOptions;
use std::collections::HashMap;
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

    // Build IdP registry — "kratos" is the default provider
    let mut providers: HashMap<String, Arc<dyn idp::IdentityProvider>> = HashMap::new();
    let mut domain_map: HashMap<String, String> = HashMap::new();

    let kratos = Arc::new(kratos::KratosProvider::new(
        &config.kratos_public_url,
        &config.kratos_admin_url,
    ));
    providers.insert("kratos".to_string(), kratos);

    if let Some(ref zc) = config.zitadel {
        let zitadel_provider = Arc::new(zitadel::ZitadelProvider::new(
            &zc.client_id,
            &zc.public_url,
            &zc.internal_url,
        ));
        providers.insert("zitadel".to_string(), zitadel_provider);
        for domain in &zc.domains {
            domain_map.insert(domain.clone(), "zitadel".to_string());
        }
        tracing::info!("Zitadel integration enabled for domains: {:?}", zc.domains);
    }

    let idp_registry = Arc::new(state::IdpRegistry::new(
        providers,
        domain_map,
        "kratos".to_string(),
    ));

    let oidc_states = Arc::new(oidc_state::OidcStateStore::new());
    let recovery_store = Arc::new(recovery::RecoveryStore::new());
    let http_client = reqwest::Client::new();

    let app_state = Arc::new(state::AppState {
        db,
        idp_registry,
        oidc_states,
        jwt_keys,
        recovery_store,
        hasura_url: config.hasura_url,
        jwt_issuer: config.jwt_issuer,
        oidc_callback_url: config.oidc_callback_url,
        frontend_url: config.frontend_url,
        http_client,
    });

    let app = routes::router(app_state);

    let addr = format!("0.0.0.0:{}", config.port);
    tracing::info!("Listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
