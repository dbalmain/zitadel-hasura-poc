use std::collections::HashMap;
use std::sync::Arc;

use sqlx::PgPool;

use crate::{idp::IdentityProvider, jwt::JwtKeys, oidc_state::OidcStateStore, recovery::RecoveryStore};

pub struct IdpRegistry {
    providers: HashMap<String, Arc<dyn IdentityProvider>>,
    domain_map: HashMap<String, String>,
    default_key: String,
}

impl IdpRegistry {
    pub fn new(
        providers: HashMap<String, Arc<dyn IdentityProvider>>,
        domain_map: HashMap<String, String>,
        default_key: String,
    ) -> Self {
        Self {
            providers,
            domain_map,
            default_key,
        }
    }

    /// Look up the provider for the given email address.
    pub fn for_email(&self, email: &str) -> Arc<dyn IdentityProvider> {
        let key = self.key_for_email(email);
        self.providers[&key].clone()
    }

    /// Return the provider key for the given email address.
    pub fn key_for_email(&self, email: &str) -> String {
        let domain = email.split('@').nth(1).unwrap_or("");
        self.domain_map
            .get(domain)
            .cloned()
            .unwrap_or_else(|| self.default_key.clone())
    }

    /// Look up a provider by its key (e.g. "kratos", "zitadel").
    pub fn by_key(&self, key: &str) -> Option<Arc<dyn IdentityProvider>> {
        self.providers.get(key).cloned()
    }
}

pub struct AppState {
    pub db: PgPool,
    pub idp_registry: Arc<IdpRegistry>,
    pub oidc_states: Arc<OidcStateStore>,
    pub jwt_keys: Arc<JwtKeys>,
    pub recovery_store: Arc<RecoveryStore>,
    pub hasura_url: String,
    pub jwt_issuer: String,
    pub oidc_callback_url: String,
    pub frontend_url: String,
    pub http_client: reqwest::Client,
}
