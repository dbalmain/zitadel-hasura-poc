use anyhow::Result;
use async_trait::async_trait;

pub enum AuthFlow {
    Credentials,
    OidcRedirect,
}

#[async_trait]
pub trait IdentityProvider: Send + Sync {
    /// Returns the authentication flow type for this provider.
    fn auth_flow(&self) -> AuthFlow;

    /// Authenticate with email + password (Credentials flow only).
    /// Returns (identity_id, external_session_id).
    async fn authenticate(&self, email: &str, password: &str) -> Result<(String, String)>;

    /// Revoke an external session (called on logout).
    /// Must tolerate the session already being gone.
    async fn revoke_session(&self, session_id: &str) -> Result<()>;

    /// Initiate password recovery for the given email and send a code.
    /// Returns opaque flow_state to be passed to verify_recovery_code.
    /// Must NOT reveal whether the email exists.
    async fn begin_recovery(&self, email: &str) -> Result<String>;

    /// Verify a recovery code. flow_state was returned by begin_recovery.
    async fn verify_recovery_code(&self, flow_state: &str, code: &str) -> Result<()>;

    /// Set a new password for the given identity.
    async fn set_password(&self, identity_id: &str, email: &str, new_password: &str) -> Result<()>;

    /// Build an OIDC authorization URL (OidcRedirect flow only).
    fn authorize_url(&self, state: &str, code_challenge: &str, redirect_uri: &str) -> String;

    /// Exchange an authorization code for (user_id, access_token) (OidcRedirect flow only).
    async fn exchange_code(
        &self,
        code: &str,
        code_verifier: &str,
        redirect_uri: &str,
    ) -> Result<(String, String)>;
}
