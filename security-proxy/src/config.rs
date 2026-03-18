use anyhow::{Context, Result};

#[derive(serde::Deserialize)]
pub struct ZitadelConfig {
    pub client_id: String,
    pub public_url: String,
    pub internal_url: String,
    pub domains: Vec<String>,
}

pub struct Config {
    pub database_url: String,
    pub kratos_public_url: String,
    pub kratos_admin_url: String,
    pub hasura_url: String,
    pub port: u16,
    pub jwt_issuer: String,
    pub oidc_callback_url: String,
    pub frontend_url: String,
    pub zitadel: Option<ZitadelConfig>,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let zitadel_config_path = std::env::var("ZITADEL_CONFIG_FILE")
            .unwrap_or_else(|_| "/zitadel-config/zitadel.json".to_string());

        let zitadel = if std::path::Path::new(&zitadel_config_path).exists() {
            let content = std::fs::read_to_string(&zitadel_config_path)
                .with_context(|| format!("Failed to read Zitadel config: {}", zitadel_config_path))?;
            Some(
                serde_json::from_str::<ZitadelConfig>(&content)
                    .context("Failed to parse Zitadel config JSON")?,
            )
        } else {
            None
        };

        Ok(Self {
            database_url: std::env::var("DATABASE_URL").context("DATABASE_URL not set")?,
            kratos_public_url: std::env::var("KRATOS_PUBLIC_URL")
                .context("KRATOS_PUBLIC_URL not set")?,
            kratos_admin_url: std::env::var("KRATOS_ADMIN_URL")
                .context("KRATOS_ADMIN_URL not set")?,
            hasura_url: std::env::var("HASURA_URL").context("HASURA_URL not set")?,
            port: std::env::var("PORT")
                .unwrap_or_else(|_| "3300".to_string())
                .parse()
                .context("PORT must be a number")?,
            jwt_issuer: std::env::var("JWT_ISSUER")
                .unwrap_or_else(|_| "security-proxy".to_string()),
            oidc_callback_url: std::env::var("OIDC_CALLBACK_URL")
                .unwrap_or_else(|_| "http://localhost:3300/api/auth/callback".to_string()),
            frontend_url: std::env::var("FRONTEND_URL")
                .unwrap_or_else(|_| "http://localhost:3301".to_string()),
            zitadel,
        })
    }
}
