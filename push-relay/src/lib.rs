//! Push-Relay v2 (`push-relay`) — V2.1 sealed-sender push notification
//! service.
//!
//! Runs on a dedicated host (`push.ladon.app`) separate from entry/exit
//! relays so that:
//!   * APNs credentials (.p8 key, key id, team id) are not co-located with
//!     message-routing state.
//!   * A compromise of an exit-relay does not leak the device-token
//!     database.
//!   * The push-relay can be in a different jurisdiction from the
//!     exit-relays without exposing recipient mailbox data.
//!
//! Endpoints (Spec §4.9 — Phase 3a):
//!   * `GET  /v2/health`                       — liveness, no auth.
//!   * `PUT  /v2/directory/replicate`          — exit→push, S2S HMAC over a
//!     sealed PUSH_REPLICATE (lane F, F43): `rid || hsig_pk` inside the
//!     AEAD. Replicates rid→hsig_pk so the push relay can verify hsig-signed
//!     registrations.
//!   * `POST /v2/sealed`                       — client→entry→push, sealed
//!     PUSH_REGISTER (Addendum A2 §4.4): `rid || apns_token(32) ||
//!     sandbox(1) || ts_be(8) || hsig_sig(3373)` sealed to this relay's key.
//!   * `POST /v2/push/notify`                  — exit→push, S2S HMAC over a
//!     sealed PUSH_NOTIFY (lane F, F43): `recipient_id(32)` inside the AEAD.
//!     Triggers a debounced APNs alert push.
//!
//! Out of scope for Phase 3a:
//!   * Wiring the exit-relay to call `replicate` and `notify`. That is
//!     Phase 3b — see `feat/v2.1-uak-push` branch.
//!   * On-disk persistence. Push tokens live in RAM (Spec G1); restarts
//!     drop tokens, clients re-register on next launch.

#![forbid(unsafe_code)]

pub mod apns;
pub mod constant_time;
pub mod error;
pub mod exit_keys;
pub mod handlers;
pub mod s2s;
pub mod state;

pub use error::{ApiError, ApiResult};
pub use state::{PushState, SealedIdentity};

/// Construct the axum router. Exposed for integration tests.
pub fn router(state: std::sync::Arc<PushState>) -> axum::Router {
    use axum::extract::DefaultBodyLimit;
    use axum::routing::{get, post, put};

    // P7-PUSH-09 (verified Low): per-route body limit below axum's 2 MiB
    // default. Every request on these routes is a sealed lane-F request
    // (client PUSH_REGISTER, and since F43 the exit's PUSH_REPLICATE and
    // PUSH_NOTIFY), exactly LANE_F_REQUEST_LEN bytes.
    const SEALED_BODY_LIMIT: usize = ladon_relay_core_v2::wire::sealed::LANE_F_REQUEST_LEN;

    // F43: no rid in the path any more; `/v2/directory/replicate/:rid` is
    // gone (404), so the plaintext form cannot be accepted.
    let replicate_r = axum::Router::new()
        .route("/v2/directory/replicate", put(handlers::directory_replicate))
        .layer(DefaultBodyLimit::max(SEALED_BODY_LIMIT));

    let notify_r = axum::Router::new()
        .route("/v2/push/notify", post(handlers::push_notify))
        .layer(DefaultBodyLimit::max(SEALED_BODY_LIMIT));

    // A2 stage 2: sealed PUSH_REGISTER, lane F request (8,192 B) — the only
    // client path since phase B (`PUT /v2/push/register/:rid` is gone).
    let sealed_r = axum::Router::new()
        .route("/v2/sealed", post(handlers::push_sealed))
        .layer(DefaultBodyLimit::max(SEALED_BODY_LIMIT));

    let health_r = axum::Router::new()
        .route("/v2/health", get(handlers::health));

    health_r
        .merge(replicate_r)
        .merge(notify_r)
        .merge(sealed_r)
        .with_state(state)
}
