use anyhow::{Context, Result};

pub struct Config {
    pub database_url: String,
    pub kratos_public_url: String,
    pub kratos_admin_url: String,
    pub hasura_url: String,
    pub port: u16,
    pub jwt_issuer: String,
}

impl Config {
    pub fn from_env() -> Result<Self> {
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
        })
    }
}
