use axum::{
    extract::State,
    http::header,
    response::{IntoResponse, Response},
    Json,
};
use std::sync::Arc;

use crate::state::AppState;

pub async fn handler(State(state): State<Arc<AppState>>) -> Response {
    let jwks = state.jwt_keys.jwks_document().clone();
    (
        [(
            header::CACHE_CONTROL,
            "max-age=60, must-revalidate",
        )],
        Json(jwks),
    )
        .into_response()
}
