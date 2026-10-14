use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::capability::{verify, OP_UPLOAD};
use crate::errors::{err_response, ErrorSlug};
use crate::util::{now_secs, parse_blob_id};
use crate::AppState;

#[derive(Deserialize)]
struct FinalizeBody {
    digest: String,
}

pub async fn handle(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(id_hex): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // P7-BLOB-13: use real client IP when behind a trusted proxy.
    let client = crate::util::client_ip(&headers, peer.ip());
    if !state.ip_limiter.check(client) {
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
        OP_UPLOAD,
        &blob_id,
        None,
        now_secs(),
    )
    .is_err()
    {
        return err_response(ErrorSlug::AuthFailed);
    }

    let parsed: FinalizeBody = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return err_response(ErrorSlug::BadRequest),
    };
    let expected = match hex::decode(&parsed.digest) {
        Ok(v) if v.len() == 32 => v,
        _ => return err_response(ErrorSlug::BadRequest),
    };

    let meta = match state.storage.get_meta(&blob_id) {
        Some(m) => m,
        None => return err_response(ErrorSlug::NotFound),
    };

    // P7-BLOB-09 fix (2026-05-12): hold the global PUT concurrency gate
    // during finalize. /finalize streams every frame from disk and hashes it;
    // before this fix a single client could spawn `chunk_count` * N concurrent
    // finalize requests that each loaded the full blob into RAM (no gate, no
    // per-IP cap on this path). The PUT gate (`global=256`, `per_ip=8`) is
    // the right backpressure: finalize and put-chunk both consume disk read/
    // write IO and OOM budget. If the gate is saturated we return 503 so the
    // client retries.
    let _permit = match state.put_gate.try_acquire(client) {
        Some(p) => p,
        None => return err_response(ErrorSlug::Unavailable),
    };

    // P7-BLOB-09 streaming finalize: instead of loading every frame into RAM
    // (256 KiB \u00d7 1024 = 256 MiB worst case), fold each frame into its leaf
    // hash on the fly and only keep the 32-byte digests.
    let leaves = match state
        .storage
        .fold_frames_to_leaves(&blob_id, crate::merkle::leaf_hash)
    {
        Ok(v) => v,
        Err(crate::storage::StorageError::NotFound) => return err_response(ErrorSlug::BadRequest),
        Err(_) => return err_response(ErrorSlug::ServerError),
    };
    if leaves.len() != meta.chunk_count as usize {
        return err_response(ErrorSlug::BadRequest);
    }
    let root = crate::merkle::root_from_leaves(leaves);
    if root.as_slice() != expected.as_slice() {
        // Integrity violation — shred and reject per spec. Skip when the
        // blob was already sealed: chunks are immutable post-seal, so a
        // differing digest on replay is a client bug, not corruption —
        // surface it as a conflict and keep the blob alive.
        if meta.sealed {
            return err_response(ErrorSlug::Conflict);
        }
        let _ = state.storage.delete_blob(&blob_id);
        return err_response(ErrorSlug::Integrity);
    }

    if meta.sealed {
        // Idempotent replay: digest matches on-disk bytes, return OK.
        return (StatusCode::OK, "ok").into_response();
    }

    if state.storage.seal(&blob_id).is_err() {
        return err_response(ErrorSlug::ServerError);
    }
    (StatusCode::OK, "ok").into_response()
}
