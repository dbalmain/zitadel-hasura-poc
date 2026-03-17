use sqlx::PgPool;
use std::sync::Arc;

use crate::{jwt::JwtKeys, kratos::KratosClient, recovery::RecoveryStore};

pub struct AppState {
    pub db: PgPool,
    pub kratos: Arc<KratosClient>,
    pub jwt_keys: Arc<JwtKeys>,
    pub recovery_store: Arc<RecoveryStore>,
    pub hasura_url: String,
    pub jwt_issuer: String,
    pub http_client: reqwest::Client,
}
