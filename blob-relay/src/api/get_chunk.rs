use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;

use crate::capability::{verify, OP_READ};
use crate::errors::{err_response, ErrorSlug};
use crate::util::{now_secs, parse_blob_id};
use crate::AppState;

pub async fn handle(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path((id_hex, index)): Path<(String, u32)>,
    headers: HeaderMap,
) -> Response {
    let client = crate::util::client_ip(&headers, peer.ip());
    if !state.ip_limiter_read.check(client) {
        return err_response(ErrorSlug::RateLimit);
    }
    let blob_id = match parse_blob_id(&id_hex) {
        Some(v) => v,
        None => return err_response(ErrorSlug::BadRequest),
    };

    let cap_tok = match headers
        .get("x-ladon-blob-capability")
        .and_then(|h| h.to_str().ok())
    {
        Some(v) => v.to_string(),
        None => return err_response(ErrorSlug::AuthFailed),
    };
    if verify(
        &state.capability_signer,
        &cap_tok,
        OP_READ,
        &blob_id,
        Some(index),
        now_secs(),
    )
    .is_err()
    {
        return err_response(ErrorSlug::AuthFailed);
    }

    let meta = match state.storage.get_meta(&blob_id) {
        Some(m) => m,
        None => return err_response(ErrorSlug::NotFound),
    };
    if meta.expires_at < now_secs() {
        return err_response(ErrorSlug::Gone);
    }

    match state.storage.get_chunk(&blob_id, index) {
        Ok(bytes) => {
            let len = bytes.len();
            let mut resp = Response::new(Body::from(bytes));
            *resp.status_mut() = StatusCode::OK;
            let headers = resp.headers_mut();
            headers.insert(
                "content-type",
                axum::http::HeaderValue::from_static("application/octet-stream"),
            );
            if let Ok(cl) = axum::http::HeaderValue::from_str(&len.to_string()) {
                headers.insert("content-length", cl);
            }
            resp
        }
        Err(crate::storage::StorageError::NotFound) => err_response(ErrorSlug::NotFound),
        Err(crate::storage::StorageError::ChunkOutOfRange) => err_response(ErrorSlug::BadRequest),
        Err(_) => err_response(ErrorSlug::ServerError),
    }
}
