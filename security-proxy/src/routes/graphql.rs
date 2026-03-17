use axum::{
    body::Bytes,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use std::sync::Arc;
use tower_cookies::Cookies;

use crate::{db, error::AppError, session::SESSION_COOKIE_NAME, state::AppState};

pub async fn handler(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    body: Bytes,
) -> Result<Response, AppError> {
    let session_id = cookies
        .get(SESSION_COOKIE_NAME)
        .map(|c| c.value().to_string())
        .ok_or(AppError::Unauthorized)?;

    let session = db::get_session(&state.db, &session_id)
        .await?
        .ok_or(AppError::Unauthorized)?;

    let jwt = state
        .jwt_keys
        .mint_hasura_jwt(
            &session.user_id,
            &session.active_role,
            &session.active_branch_id,
            &state.jwt_issuer,
        )
        .map_err(AppError::Internal)?;

    let resp = state
        .http_client
        .post(&state.hasura_url)
        .header("Authorization", format!("Bearer {}", jwt))
        .header("Content-Type", "application/json")
        .body(body.to_vec())
        .send()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Hasura request failed: {}", e)))?;

    let status = StatusCode::from_u16(resp.status().as_u16())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json")
        .to_string();
    let response_body = resp
        .bytes()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Failed to read Hasura response: {}", e)))?;

    Ok(Response::builder()
        .status(status)
        .header("Content-Type", ct)
        .body(axum::body::Body::from(response_body))
        .unwrap())
}
