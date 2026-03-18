use anyhow::anyhow;
use axum::{
    extract::{Query, State},
    response::Redirect,
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use tower_cookies::{cookie::SameSite, Cookie, Cookies};
use uuid::Uuid;

use crate::{
    db,
    error::AppError,
    idp::AuthFlow,
    session::{Session, SESSION_COOKIE_NAME},
    state::AppState,
    zitadel,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn require_session(cookies: &Cookies, db: &sqlx::PgPool) -> Result<Session, AppError> {
    let session_id = cookies
        .get(SESSION_COOKIE_NAME)
        .map(|c| c.value().to_string())
        .ok_or(AppError::Unauthorized)?;

    db::get_session(db, &session_id)
        .await
        .map_err(AppError::Internal)?
        .ok_or(AppError::Unauthorized)
}

fn make_session_cookie(session_id: String) -> Cookie<'static> {
    let mut cookie = Cookie::new(SESSION_COOKIE_NAME, session_id);
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Strict);
    cookie.set_path("/");
    cookie
}

fn clear_session_cookie() -> Cookie<'static> {
    let mut cookie = Cookie::new(SESSION_COOKIE_NAME, "");
    cookie.set_path("/");
    cookie.set_max_age(time::Duration::ZERO);
    cookie
}

// ---------------------------------------------------------------------------
// Auth Init — resolves IdP from email domain
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct AuthInitRequest {
    email: String,
}

pub async fn auth_init(
    State(state): State<Arc<AppState>>,
    Json(body): Json<AuthInitRequest>,
) -> Result<Json<Value>, AppError> {
    let provider = state.idp_registry.for_email(&body.email);
    match provider.auth_flow() {
        AuthFlow::Credentials => Ok(Json(json!({ "type": "credentials" }))),
        AuthFlow::OidcRedirect => {
            let (code_verifier, code_challenge) = zitadel::generate_pkce();
            let oidc_state = Uuid::new_v4().to_string();
            let provider_key = state.idp_registry.key_for_email(&body.email);
            state
                .oidc_states
                .store(oidc_state.clone(), code_verifier, provider_key);
            let url =
                provider.authorize_url(&oidc_state, &code_challenge, &state.oidc_callback_url);
            Ok(Json(json!({ "type": "redirect", "url": url })))
        }
    }
}

// ---------------------------------------------------------------------------
// Auth Callback — OIDC authorization-code exchange
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct CallbackParams {
    code: String,
    state: String,
}

pub async fn auth_callback(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    Query(params): Query<CallbackParams>,
) -> Result<Redirect, AppError> {
    let oidc_entry = state
        .oidc_states
        .take(&params.state)
        .ok_or_else(|| AppError::BadRequest("Invalid or expired OIDC state".to_string()))?;

    let provider = state
        .idp_registry
        .by_key(&oidc_entry.provider_key)
        .ok_or_else(|| {
            AppError::Internal(anyhow!(
                "unknown provider key: {}",
                oidc_entry.provider_key
            ))
        })?;

    let (user_id, access_token) = provider
        .exchange_code(&params.code, &oidc_entry.code_verifier, &state.oidc_callback_url)
        .await
        .map_err(|e| AppError::BadRequest(format!("OIDC code exchange failed: {}", e)))?;

    let user = db::get_user_by_id(&state.db, &user_id)
        .await
        .map_err(AppError::Internal)?
        .ok_or_else(|| AppError::BadRequest("User not found in application database".to_string()))?;

    let user_roles = db::get_user_roles(&state.db, &user.id)
        .await
        .map_err(AppError::Internal)?;
    let default_role = user_roles
        .first()
        .ok_or_else(|| AppError::BadRequest("User has no roles assigned".to_string()))?;

    let session_id = Uuid::new_v4().to_string();
    db::create_session(
        &state.db,
        &session_id,
        &user.id,
        &default_role.role,
        &default_role.branch_id,
        Some(&access_token),
    )
    .await
    .map_err(AppError::Internal)?;

    cookies.add(make_session_cookie(session_id));
    Ok(Redirect::to(&state.frontend_url))
}

// ---------------------------------------------------------------------------
// Login (Kratos credentials only)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Serialize)]
pub struct MeResponse {
    user_id: String,
    email: String,
    active_role: String,
    active_branch_id: String,
}

pub async fn login(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    Json(body): Json<LoginRequest>,
) -> Result<Json<MeResponse>, AppError> {
    let provider = state.idp_registry.for_email(&body.email);
    if let AuthFlow::OidcRedirect = provider.auth_flow() {
        return Err(AppError::BadRequest(
            "This account uses SSO login. Please use the Continue button.".to_string(),
        ));
    }

    let (identity_id, kratos_session_id) = provider
        .authenticate(&body.email, &body.password)
        .await
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    let user = db::get_user_by_id(&state.db, &identity_id)
        .await?
        .ok_or_else(|| AppError::BadRequest("User not found in application database".to_string()))?;

    let user_roles = db::get_user_roles(&state.db, &user.id).await?;
    let default_role = user_roles
        .first()
        .ok_or_else(|| AppError::BadRequest("User has no roles assigned".to_string()))?;

    let session_id = Uuid::new_v4().to_string();
    db::create_session(
        &state.db,
        &session_id,
        &user.id,
        &default_role.role,
        &default_role.branch_id,
        Some(&kratos_session_id),
    )
    .await?;

    cookies.add(make_session_cookie(session_id));

    Ok(Json(MeResponse {
        user_id: user.id,
        email: user.email,
        active_role: default_role.role.clone(),
        active_branch_id: default_role.branch_id.clone(),
    }))
}

// ---------------------------------------------------------------------------
// Logout
// ---------------------------------------------------------------------------

pub async fn logout(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
) -> Json<Value> {
    if let Some(cookie) = cookies.get(SESSION_COOKIE_NAME) {
        let session_id = cookie.value().to_string();
        if let Ok(Some(session)) = db::get_session(&state.db, &session_id).await {
            if let Some(ref ext_session_id) = session.kratos_session_id {
                if let Ok(Some(user)) = db::get_user_by_id(&state.db, &session.user_id).await {
                    let provider = state.idp_registry.for_email(&user.email);
                    let _ = provider.revoke_session(ext_session_id).await;
                }
            }
            let _ = db::delete_session(&state.db, &session_id).await;
        }
    }
    cookies.remove(clear_session_cookie());
    Json(json!({ "ok": true }))
}

// ---------------------------------------------------------------------------
// Me
// ---------------------------------------------------------------------------

pub async fn me(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
) -> Result<Json<MeResponse>, AppError> {
    let session = require_session(&cookies, &state.db).await?;
    let user = db::get_user_by_id(&state.db, &session.user_id)
        .await?
        .ok_or_else(|| AppError::Internal(anyhow!("user not found")))?;

    Ok(Json(MeResponse {
        user_id: session.user_id,
        email: user.email,
        active_role: session.active_role,
        active_branch_id: session.active_branch_id,
    }))
}

// ---------------------------------------------------------------------------
// Roles
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct RoleEntry {
    role: String,
    branch_id: String,
    branch_name: String,
}

pub async fn roles(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
) -> Result<Json<Value>, AppError> {
    let session = require_session(&cookies, &state.db).await?;
    let rows = db::get_user_roles(&state.db, &session.user_id).await?;
    let role_list: Vec<RoleEntry> = rows
        .into_iter()
        .map(|r| RoleEntry {
            role: r.role,
            branch_id: r.branch_id,
            branch_name: r.branch_name,
        })
        .collect();
    Ok(Json(json!({ "roles": role_list })))
}

// ---------------------------------------------------------------------------
// Switch Role
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SwitchRoleRequest {
    role: String,
    branch_id: String,
}

pub async fn switch_role(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    Json(body): Json<SwitchRoleRequest>,
) -> Result<Json<MeResponse>, AppError> {
    let session = require_session(&cookies, &state.db).await?;

    let valid = db::has_role(&state.db, &session.user_id, &body.role, &body.branch_id).await?;
    if !valid {
        return Err(AppError::BadRequest(
            "Role not assigned to this user on this branch".to_string(),
        ));
    }

    db::update_session_role(&state.db, &session.id, &body.role, &body.branch_id).await?;

    let user = db::get_user_by_id(&state.db, &session.user_id)
        .await?
        .ok_or_else(|| AppError::Internal(anyhow!("user not found")))?;

    Ok(Json(MeResponse {
        user_id: session.user_id,
        email: user.email,
        active_role: body.role,
        active_branch_id: body.branch_id,
    }))
}

// ---------------------------------------------------------------------------
// Forgot Password — always returns 200 (no email enumeration)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ForgotPasswordRequest {
    email: String,
}

pub async fn forgot_password(
    State(state): State<Arc<AppState>>,
    Json(body): Json<ForgotPasswordRequest>,
) -> Json<Value> {
    let recovery_token = Uuid::new_v4().to_string();
    let provider = state.idp_registry.for_email(&body.email);
    let flow_state_result = provider.begin_recovery(&body.email).await;

    match flow_state_result {
        Ok(flow_state) => {
            state
                .recovery_store
                .store_recovery(recovery_token.clone(), flow_state, body.email.clone());
        }
        Err(e) => {
            tracing::warn!("Recovery flow error (suppressed for enumeration safety): {}", e);
            // Store an empty flow_state — verify step will return a generic error
            state
                .recovery_store
                .store_recovery(recovery_token.clone(), String::new(), body.email.clone());
        }
    }

    Json(json!({ "recovery_token": recovery_token }))
}

// ---------------------------------------------------------------------------
// Forgot Password — Verify code
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ForgotPasswordVerifyRequest {
    recovery_token: String,
    code: String,
}

pub async fn forgot_password_verify(
    State(state): State<Arc<AppState>>,
    Json(body): Json<ForgotPasswordVerifyRequest>,
) -> Result<Json<Value>, AppError> {
    let entry = state
        .recovery_store
        .take_recovery(&body.recovery_token)
        .ok_or_else(|| AppError::BadRequest("Invalid or expired recovery token".to_string()))?;

    if entry.flow_state.is_empty() {
        return Err(AppError::BadRequest("Invalid recovery code".to_string()));
    }

    let provider = state.idp_registry.for_email(&entry.email);
    provider
        .verify_recovery_code(&entry.flow_state, &body.code)
        .await
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    let user = db::get_user_by_email(&state.db, &entry.email)
        .await
        .map_err(AppError::Internal)?
        .ok_or_else(|| AppError::BadRequest("User not found".to_string()))?;

    let reset_token = Uuid::new_v4().to_string();
    state.recovery_store.store_reset(reset_token.clone(), user.id);

    Ok(Json(json!({ "reset_token": reset_token })))
}

// ---------------------------------------------------------------------------
// Forgot Password — Reset with new password
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ForgotPasswordResetRequest {
    reset_token: String,
    new_password: String,
}

pub async fn forgot_password_reset(
    State(state): State<Arc<AppState>>,
    Json(body): Json<ForgotPasswordResetRequest>,
) -> Result<Json<Value>, AppError> {
    let entry = state
        .recovery_store
        .take_reset(&body.reset_token)
        .ok_or_else(|| AppError::BadRequest("Invalid or expired reset token".to_string()))?;

    let user = db::get_user_by_id(&state.db, &entry.user_id)
        .await
        .map_err(AppError::Internal)?
        .ok_or_else(|| AppError::Internal(anyhow!("user not found")))?;

    let provider = state.idp_registry.for_email(&user.email);
    provider
        .set_password(&entry.user_id, &user.email, &body.new_password)
        .await
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    Ok(Json(json!({ "ok": true })))
}
