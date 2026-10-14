use std::sync::Arc;

use axum::extract::State;
use axum::http::{header::CONTENT_TYPE, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

use ladon_relay_core_v2::constants::RELAY_PROTOCOL_VERSION;

use crate::error::EntryError;
use crate::state::EntryState;

/// Read an upstream response body, rejecting once it exceeds `max` bytes.
///
/// `reqwest::Response::bytes()` buffers the whole body with no ceiling. Exit
/// URLs are pinned to the operator-configured registry, so only a compromised
/// or misbehaving fleet upstream can trigger this — but to keep the Entry's
/// memory bounded regardless, we fast-reject on an oversized declared
/// Content-Length, then stream chunks with a running cap so a lying or absent
/// Content-Length cannot bypass the limit.
pub(crate) async fn read_body_capped(resp: reqwest::Response, max: usize) -> Result<Vec<u8>, EntryError> {
    if let Some(len) = resp.content_length() {
        if len > max as u64 {
            return Err(EntryError::Upstream);
        }
    }
    let mut resp = resp;
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|_| EntryError::Upstream)? {
        if buf.len() + chunk.len() > max {
            return Err(EntryError::Upstream);
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

#[derive(Serialize)]
pub struct HealthBody {
    pub status: &'static str,
    pub hop: String,
    pub exits: usize,
    pub version: u8,
}

pub async fn health(State(s): State<Arc<EntryState>>) -> Json<HealthBody> {
    Json(HealthBody {
        status: "ok",
        hop: s.hop_id.clone(),
        exits: s.registry.len(),
        version: RELAY_PROTOCOL_VERSION,
    })
}

pub async fn canary(State(s): State<Arc<EntryState>>) -> Response {
    // P7-RELAY-21: async fs read so the worker thread isn't blocked on disk I/O.
    match tokio::fs::read(&s.canary_path).await {
        Ok(b) => {
            let mut r = (StatusCode::OK, b).into_response();
            r.headers_mut().insert(CONTENT_TYPE, "application/json".parse().unwrap());
            r
        }
        Err(_) => (StatusCode::NOT_FOUND, "canary file missing").into_response(),
    }
}
