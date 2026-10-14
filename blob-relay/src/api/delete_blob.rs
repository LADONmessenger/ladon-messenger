use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::capability::{verify, OP_DELETE};
use crate::errors::{err_response, ErrorSlug};
use crate::util::{now_secs, parse_blob_id};
use crate::AppState;

pub async fn handle(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(id_hex): Path<String>,
    headers: HeaderMap,
) -> Response {
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
        OP_DELETE,
        &blob_id,
        None,
        now_secs(),
    )
    .is_err()
    {
        return err_response(ErrorSlug::AuthFailed);
    }

    // Always return 204 to prevent existence probing (spec §6.3).
    let _ = state.storage.delete_blob(&blob_id);
    (StatusCode::NO_CONTENT, "").into_response()
}
