use anyhow::{anyhow, Result};
use reqwest::Client;
use serde_json::{json, Value};

pub struct KratosClient {
    client: Client,
    public_url: String,
    admin_url: String,
}

impl KratosClient {
    pub fn new(public_url: &str, admin_url: &str) -> Self {
        Self {
            client: Client::new(),
            public_url: public_url.to_string(),
            admin_url: admin_url.to_string(),
        }
    }

    /// Perform Kratos native login. Returns (kratos_identity_id, kratos_session_id).
    pub async fn login(&self, email: &str, password: &str) -> Result<(String, String)> {
        // Step 1: Create login flow
        let flow: Value = self
            .client
            .get(format!("{}/self-service/login/api", self.public_url))
            .send()
            .await?
            .json()
            .await?;

        let action_url = flow["ui"]["action"]
            .as_str()
            .ok_or_else(|| anyhow!("no action url in login flow"))?
            .to_string();

        // Step 2: Submit credentials
        let resp = self
            .client
            .post(&action_url)
            .json(&json!({
                "method": "password",
                "identifier": email,
                "password": password,
            }))
            .send()
            .await?;

        if !resp.status().is_success() {
            let body: Value = resp.json().await.unwrap_or_default();
            let msg = body["ui"]["messages"][0]["text"]
                .as_str()
                .unwrap_or("Invalid credentials")
                .to_string();
            return Err(anyhow!("{}", msg));
        }

        let body: Value = resp.json().await?;
        let identity_id = body["session"]["identity"]["id"]
            .as_str()
            .ok_or_else(|| anyhow!("no identity id in login response"))?
            .to_string();
        let session_id = body["session"]["id"]
            .as_str()
            .ok_or_else(|| anyhow!("no session id in login response"))?
            .to_string();

        Ok((identity_id, session_id))
    }

    /// Revoke a Kratos session via admin API.
    pub async fn revoke_session(&self, session_id: &str) -> Result<()> {
        let resp = self
            .client
            .delete(format!("{}/admin/sessions/{}", self.admin_url, session_id))
            .send()
            .await?;

        if resp.status().is_success() || resp.status() == 404 {
            Ok(())
        } else {
            Err(anyhow!("Failed to revoke session: {}", resp.status()))
        }
    }

    /// Initiate password recovery (code flow). Returns action_url for subsequent steps.
    pub async fn start_recovery(&self) -> Result<String> {
        let flow: Value = self
            .client
            .get(format!("{}/self-service/recovery/api", self.public_url))
            .send()
            .await?
            .json()
            .await?;

        let action_url = flow["ui"]["action"]
            .as_str()
            .ok_or_else(|| anyhow!("no action url in recovery flow"))?
            .to_string();

        Ok(action_url)
    }

    /// Submit email to recovery flow. Returns updated action_url.
    pub async fn submit_recovery_email(&self, action_url: &str, email: &str) -> Result<String> {
        let resp = self
            .client
            .post(action_url)
            .json(&json!({
                "method": "code",
                "email": email,
            }))
            .send()
            .await?;

        let body: Value = resp.json().await.unwrap_or_default();
        // Kratos returns the updated flow; use its action URL for the next step
        let updated_action = body["ui"]["action"]
            .as_str()
            .unwrap_or(action_url)
            .to_string();

        Ok(updated_action)
    }

    /// Submit recovery code. Returns Ok(()) on success.
    ///
    /// Kratos v1.x returns HTTP 422 "browser_location_change_required" on
    /// successful code verification, with no session token available.
    /// We simply confirm success and let the caller use the admin API to
    /// set a new password.
    pub async fn submit_recovery_code(&self, action_url: &str, code: &str) -> Result<()> {
        let resp = self
            .client
            .post(action_url)
            .json(&json!({
                "method": "code",
                "code": code,
            }))
            .send()
            .await?;

        let status = resp.status();
        let body: Value = resp.json().await.unwrap_or_default();

        tracing::debug!(
            "submit_recovery_code: status={} body={}",
            status,
            body
        );

        // Kratos v1.x returns 422 "browser_location_change_required" on success.
        if status == 422 {
            let error_id = body["error"]["id"].as_str().unwrap_or("");
            if error_id == "browser_location_change_required" {
                return Ok(());
            }
        }

        if status.is_success() {
            return Ok(());
        }

        // Error — extract human-readable message from the flow UI
        let msg = body["ui"]["messages"][0]["text"]
            .as_str()
            .unwrap_or("Invalid or expired recovery code")
            .to_string();
        Err(anyhow!("{}", msg))
    }

    /// Directly set a user's password via the Kratos admin API.
    /// `identity_id` is the Kratos UUID (= app users.id).
    /// `email` is the user's email address (needed to preserve traits).
    pub async fn admin_set_password(
        &self,
        identity_id: &str,
        email: &str,
        new_password: &str,
    ) -> Result<()> {
        let resp = self
            .client
            .put(format!("{}/admin/identities/{}", self.admin_url, identity_id))
            .json(&json!({
                "schema_id": "default",
                "traits": { "email": email },
                "credentials": {
                    "password": {
                        "config": { "password": new_password }
                    }
                }
            }))
            .send()
            .await?;

        if resp.status().is_success() {
            Ok(())
        } else {
            let status = resp.status();
            let body: Value = resp.json().await.unwrap_or_default();
            tracing::debug!("admin_set_password error: status={} body={}", status, body);
            let msg = body["error"]["message"]
                .as_str()
                .unwrap_or("Failed to set password")
                .to_string();
            Err(anyhow!("{}", msg))
        }
    }
}
