use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

pub async fn handle() -> Response {
    let body = serde_json::json!({
        "status": "ok",
        "version": "blob-relay-0.1.0",
    });
    (StatusCode::OK, axum::Json(body)).into_response()
}
