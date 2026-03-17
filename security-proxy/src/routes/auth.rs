use anyhow::anyhow;
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use tower_cookies::{cookie::SameSite, Cookie, Cookies};
use uuid::Uuid;

use crate::{
    db,
    error::AppError,
    session::{Session, SESSION_COOKIE_NAME},
    state::AppState,
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
// Login
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
    let (identity_id, kratos_session_id) = state
        .kratos
        .login(&body.email, &body.password)
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
            if let Some(ref kratos_sid) = session.kratos_session_id {
                let _ = state.kratos.revoke_session(kratos_sid).await;
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

    let action_url_result: anyhow::Result<String> = async {
        let action_url = state.kratos.start_recovery().await?;
        let updated_action = state
            .kratos
            .submit_recovery_email(&action_url, &body.email)
            .await?;
        Ok(updated_action)
    }
    .await;

    match action_url_result {
        Ok(action_url) => {
            state
                .recovery_store
                .store_recovery(recovery_token.clone(), action_url, body.email.clone());
        }
        Err(e) => {
            tracing::warn!("Recovery flow error (suppressed for enumeration safety): {}", e);
            // Store an empty action_url — verify step will return a generic error
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

    if entry.action_url.is_empty() {
        return Err(AppError::BadRequest(
            "Invalid recovery code".to_string(),
        ));
    }

    state
        .kratos
        .submit_recovery_code(&entry.action_url, &body.code)
        .await
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    // Look up user by email to get the Kratos identity UUID
    let user = db::get_user_by_email(&state.db, &entry.email)
        .await
        .map_err(AppError::Internal)?
        .ok_or_else(|| AppError::BadRequest("User not found".to_string()))?;

    let reset_token = Uuid::new_v4().to_string();
    state
        .recovery_store
        .store_reset(reset_token.clone(), user.id);

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

    // Look up email for the user (needed by admin API to preserve traits)
    let user = db::get_user_by_id(&state.db, &entry.user_id)
        .await
        .map_err(AppError::Internal)?
        .ok_or_else(|| AppError::Internal(anyhow!("user not found")))?;

    state
        .kratos
        .admin_set_password(&entry.user_id, &user.email, &body.new_password)
        .await
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    Ok(Json(json!({ "ok": true })))
}
