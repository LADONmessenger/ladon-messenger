//! Exit-Relay v2 (`L1`) — serves sealed requests (Addendum A2, relay protocol
//! 0x06): delivery checks (A1 §8), acknowledged fetch (A1 §13), recipient
//! directory (A1 §4), replay (A1 §8), push decision (A2 §7).

#![forbid(unsafe_code)]

pub mod config;
pub mod constant_time;
pub mod entry_keys;
pub mod error;
pub mod handlers;
pub mod online;
pub mod push_client;
pub mod s2s;
pub mod sealed;
pub mod state;
pub mod verify;

pub use config::ExitConfig;
pub use error::{ApiError, ApiResult};
pub use push_client::{PushClient, RecordingPushClient, ReqwestPushClient};
pub use state::ExitState;

use std::sync::Arc;

/// Construct the axum router. Exposed for integration tests.
///
/// Addendum A2 stage 2, phase B: the exit has one working route,
/// `POST /v2/sealed`, S2S-authenticated from the entry (per-client limits
/// are the entry's; the expensive kinds are limited in `sealed.rs`). The
/// former client-facing routes `/v2/forward`, `/v2/fetch` and
/// `/v2/directory/:rid` are gone, and with them the per-IP middleware and its
/// `LADON_ALLOW_NO_XFF` switch.
pub fn router(state: Arc<ExitState>) -> axum::Router {
    use axum::extract::DefaultBodyLimit;
    use axum::routing::{get, post};

    // The larger lane request (16,384 B); every body is exactly one lane size.
    const SEALED_BODY_LIMIT: usize = ladon_relay_core_v2::wire::sealed::LANE_S_REQUEST_LEN;

    let s2s = axum::Router::new()
        .route("/v2/sealed", post(sealed::sealed))
        .layer(DefaultBodyLimit::max(SEALED_BODY_LIMIT));

    // Health/canary: never limited.
    let unmetered = axum::Router::new()
        .route("/v2/health", get(handlers::health))
        .route("/canary.json", get(handlers::canary));

    s2s.merge(unmetered).with_state(state)
}
