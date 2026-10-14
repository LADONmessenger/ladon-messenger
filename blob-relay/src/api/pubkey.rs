use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::AppState;

pub async fn handle(State(state): State<Arc<AppState>>) -> Response {
    let pk = state.capability_signer.verifying_key().to_bytes();
    let body = serde_json::json!({
        "pubkey": hex::encode(pk),
        "algorithm": "ed25519",
        "version": "blob-relay-0.1.0",
    });
    (StatusCode::OK, axum::Json(body)).into_response()
}
