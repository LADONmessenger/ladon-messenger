//! Blob-relay library entry point.
//!
//! Exposed as a library so integration tests and future tooling can embed
//! the router without running the binary. The binary `main.rs` is a thin
//! wrapper that parses the environment, builds the router via
//! [`build_app`], and starts the server.

// The other four crates have carried this since the initial import; blob-relay
// was the only one without it. It has no `unsafe` today, so this changes
// nothing at present — it is the guard against a future block slipping in.
#![forbid(unsafe_code)]

pub mod capability;
pub mod config;
pub mod errors;
pub mod gc;
pub mod merkle;
pub mod rate_limit;
pub mod storage;
pub mod util;

pub mod api;

use std::sync::Arc;

use axum::{
    extract::DefaultBodyLimit,
    routing::{delete, get, post, put},
    Router,
};

/// Build the Axum router with the given application state.
///
/// Separated from `main.rs` so that integration tests can construct
/// a full-fidelity instance backed by a temp directory.
pub fn build_app(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/blob/init", post(api::init::handle))
        .route("/v1/blob/:id/finalize", post(api::finalize::handle))
        .route("/v1/blob/:id/:index", put(api::put_chunk::handle))
        .route("/v1/blob/:id/:index", get(api::get_chunk::handle))
        .route("/v1/blob/:id", delete(api::delete_blob::handle))
        .route("/v1/blob/pubkey", get(api::pubkey::handle))
        .route("/v1/blob/health", get(api::health::handle))
        // #18: explicit router-wide body cap (defense-in-depth). put_chunk also
        // enforces its own MAX_CHUNK_BODY_BYTES; this makes the bound intentional
        // rather than relying on axum's implicit 2 MiB default. The chunk PUT is
        // the largest body any endpoint legitimately accepts.
        .layer(DefaultBodyLimit::max(api::put_chunk::MAX_CHUNK_BODY_BYTES))
        .with_state(state)
}

/// Shared state threaded through every handler.
pub struct AppState {
    pub config: config::Config,
    pub storage: storage::BlobStorage,
    pub capability_signer: capability::Signer,
    /// 600 req/min per IP — all endpoints.
    pub ip_limiter: rate_limit::IpLimiter,
    /// 1200 req/min per IP for GET chunk (higher ceiling for downloads).
    pub ip_limiter_read: rate_limit::IpLimiter,
    /// Concurrency gate for PUT chunk (8/IP, 256 global).
    pub put_gate: rate_limit::ConcurrencyGate,
}
