use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::capability::{verify, OP_UPLOAD};
use crate::errors::{err_response, ErrorSlug};
use crate::util::{now_secs, parse_blob_id, FULL_CHUNK_WIRE_BYTES};
use crate::AppState;

/// Absolute upper bound on chunk body (spec §6.2). Also used as the
/// router-wide `DefaultBodyLimit` (#18) — the chunk PUT is the largest body
/// any endpoint legitimately accepts.
pub const MAX_CHUNK_BODY_BYTES: usize = 800_000;

pub async fn handle(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path((id_hex, index)): Path<(String, u32)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // P7-BLOB-13: XFF-aware client IP.
    let client = crate::util::client_ip(&headers, peer.ip());
    if !state.ip_limiter.check(client) {
        return err_response(ErrorSlug::RateLimit);
    }
    let blob_id = match parse_blob_id(&id_hex) {
        Some(v) => v,
        None => return err_response(ErrorSlug::BadRequest),
    };

    if body.len() > MAX_CHUNK_BODY_BYTES {
        return err_response(ErrorSlug::BadRequest);
    }

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
        OP_UPLOAD,
        &blob_id,
        Some(index),
        now_secs(),
    )
    .is_err()
    {
        return err_response(ErrorSlug::AuthFailed);
    }

    // Concurrency gate.
    let _permit = match state.put_gate.try_acquire(client) {
        Some(p) => p,
        None => return err_response(ErrorSlug::Unavailable),
    };

    let meta = match state.storage.get_meta(&blob_id) {
        Some(m) => m,
        None => return err_response(ErrorSlug::NotFound),
    };
    if meta.sealed {
        return err_response(ErrorSlug::Gone);
    }
    if index >= meta.chunk_count as u32 {
        return err_response(ErrorSlug::BadRequest);
    }

    // Shape check for non-final chunks.
    let is_last = (index as u16) + 1 == meta.chunk_count;
    if !is_last && body.len() != FULL_CHUNK_WIRE_BYTES {
        return err_response(ErrorSlug::BadRequest);
    }

    match state.storage.put_chunk(&blob_id, index, &body) {
        Ok(()) => (StatusCode::OK, "ok").into_response(),
        Err(crate::storage::StorageError::ChunkConflict) => err_response(ErrorSlug::Conflict),
        Err(crate::storage::StorageError::Sealed) => err_response(ErrorSlug::Gone),
        Err(crate::storage::StorageError::ChunkOutOfRange) => err_response(ErrorSlug::BadRequest),
        Err(crate::storage::StorageError::NotFound) => err_response(ErrorSlug::NotFound),
        Err(_) => err_response(ErrorSlug::ServerError),
    }
}
