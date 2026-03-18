use anyhow::{anyhow, Result};
use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::RngCore;
use reqwest::Client;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::idp::{AuthFlow, IdentityProvider};

pub struct ZitadelProvider {
    client: Client,
    client_id: String,
    public_url: String,
    internal_url: String,
}

impl ZitadelProvider {
    pub fn new(client_id: &str, public_url: &str, internal_url: &str) -> Self {
        Self {
            client: Client::new(),
            client_id: client_id.to_string(),
            public_url: public_url.to_string(),
            internal_url: internal_url.to_string(),
        }
    }
}

/// Generate a PKCE (code_verifier, code_challenge) pair.
/// verifier: 32 random bytes, base64url-encoded (no padding)
/// challenge: BASE64URL_NOPAD(SHA256(verifier))
pub fn generate_pkce() -> (String, String) {
    let mut verifier_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut verifier_bytes);
    let code_verifier = URL_SAFE_NO_PAD.encode(verifier_bytes);

    let mut hasher = Sha256::new();
    hasher.update(code_verifier.as_bytes());
    let hash = hasher.finalize();
    let code_challenge = URL_SAFE_NO_PAD.encode(hash);

    (code_verifier, code_challenge)
}

#[async_trait]
impl IdentityProvider for ZitadelProvider {
    fn auth_flow(&self) -> AuthFlow {
        AuthFlow::OidcRedirect
    }

    fn authorize_url(&self, state: &str, code_challenge: &str, redirect_uri: &str) -> String {
        let base = format!("{}/oauth/v2/authorize", self.public_url);
        let mut url = reqwest::Url::parse(&base).expect("valid Zitadel public_url");
        url.query_pairs_mut()
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("response_type", "code")
            .append_pair("scope", "openid email profile")
            .append_pair("state", state)
            .append_pair("code_challenge", code_challenge)
            .append_pair("code_challenge_method", "S256");
        url.to_string()
    }

    async fn exchange_code(
        &self,
        code: &str,
        code_verifier: &str,
        redirect_uri: &str,
    ) -> Result<(String, String)> {
        // Token exchange via internal proxy (Host header rewritten to localhost:8080)
        let params = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("client_id", self.client_id.as_str()),
            ("code_verifier", code_verifier),
        ];

        let token_resp = self
            .client
            .post(format!("{}/oauth/v2/token", self.internal_url))
            .form(&params)
            .send()
            .await?;

        if !token_resp.status().is_success() {
            let text = token_resp.text().await.unwrap_or_default();
            return Err(anyhow!("Token exchange failed: {}", text));
        }

        let token_body: Value = token_resp.json().await?;
        let access_token = token_body["access_token"]
            .as_str()
            .ok_or_else(|| anyhow!("no access_token in token response"))?
            .to_string();

        // Fetch userinfo to get the subject (Zitadel user ID)
        let userinfo_resp = self
            .client
            .get(format!("{}/oidc/v1/userinfo", self.internal_url))
            .bearer_auth(&access_token)
            .send()
            .await?;

        if !userinfo_resp.status().is_success() {
            let text = userinfo_resp.text().await.unwrap_or_default();
            return Err(anyhow!("Userinfo request failed: {}", text));
        }

        let userinfo: Value = userinfo_resp.json().await?;
        let sub = userinfo["sub"]
            .as_str()
            .ok_or_else(|| anyhow!("no sub in userinfo response"))?
            .to_string();

        Ok((sub, access_token))
    }

    async fn authenticate(&self, _email: &str, _password: &str) -> Result<(String, String)> {
        Err(anyhow!("Zitadel uses OIDC redirect flow, not credentials"))
    }

    async fn revoke_session(&self, access_token: &str) -> Result<()> {
        let params = [
            ("token", access_token),
            ("client_id", self.client_id.as_str()),
        ];
        let resp = self
            .client
            .post(format!("{}/oauth/v2/revoke", self.internal_url))
            .form(&params)
            .send()
            .await?;

        // 200 = success; 401 = already revoked/invalid — both are acceptable
        if resp.status().is_success() || resp.status() == 401 {
            Ok(())
        } else {
            Err(anyhow!("Failed to revoke Zitadel token: {}", resp.status()))
        }
    }

    async fn begin_recovery(&self, _email: &str) -> Result<String> {
        Err(anyhow!(
            "Password recovery is not supported for Zitadel users — use Zitadel's own password reset"
        ))
    }

    async fn verify_recovery_code(&self, _flow_state: &str, _code: &str) -> Result<()> {
        Err(anyhow!("Password recovery is not supported for Zitadel users"))
    }

    async fn set_password(
        &self,
        _identity_id: &str,
        _email: &str,
        _new_password: &str,
    ) -> Result<()> {
        Err(anyhow!("Password reset is not supported for Zitadel users"))
    }
}
