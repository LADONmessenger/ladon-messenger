//! Entry-Relay v2 (`L1`) — opaque forwarder.
//!
//! Spec §4.7.1, §4.7.2, §5.4. The Entry holds NO secrets about messages: it
//! only HMACs S2S calls to Exits using a shared per-Exit key (or one global
//! key for the Pilot). Bodies are forwarded byte-for-byte.

#![forbid(unsafe_code)]

pub mod config;
pub mod error;
pub mod forward;
pub mod handlers;
pub mod registry;
pub mod relay;
pub mod state;

pub use error::{EntryError, EntryResult};
pub use registry::ExitRegistry;
pub use state::EntryState;

use std::sync::Arc;

/// FIX SRV-1 (2026-05-06): Per-IP rate limit middleware.
///
/// Keys on the **rightmost** `X-Forwarded-For` value (what trusted Caddy saw).
/// Applied to user-facing routes only — see `router()` for the layered set.
/// Health and canary routes are exempt to keep monitoring functional under load.
async fn rate_limit_mw(
    axum::extract::State(state): axum::extract::State<Arc<EntryState>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, EntryError> {
    let xff = req.headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok());
    match ladon_relay_core_v2::ratelimit::extract_client_ip(xff) {
        Some(ip) => {
            if state.rate_limiter.check(ip).is_err() {
                // FIX M-10: do NOT log the IP. Generic warn only.
                tracing::warn!("entry rate limit hit");
                return Err(EntryError::TooManyRequests);
            }
        }
        None => {
            // P7-RELAY-07: without an X-Forwarded-For we cannot identify the
            // client and therefore cannot rate-limit them. Caddy is supposed
            // to set XFF on every forward; if it's missing the request either
            // bypassed Caddy or Caddy is misconfigured. Fail closed by
            // default. Set `LADON_ALLOW_NO_XFF=1` if you genuinely operate
            // direct-loopback (e.g. cargo-run integration tests).
            let allow = std::env::var("LADON_ALLOW_NO_XFF")
                .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
                .unwrap_or(false);
            if !allow {
                tracing::warn!("entry rate-limit: refusing request without X-Forwarded-For");
                return Err(EntryError::TooManyRequests);
            }
        }
    }
    Ok(next.run(req).await)
}

pub fn router(state: Arc<EntryState>) -> axum::Router {
    use axum::extract::DefaultBodyLimit;
    use axum::routing::{get, post};

    // Addendum A2 stage 2, phase B: one client route. Every sealed request is
    // exactly one of the two lane sizes, the larger being 16 KiB. The former
    // routes (enqueue, proxy-directory[-put], proxy-push-register,
    // fetch-proxy) are gone.
    let limited = axum::Router::new()
        .route("/v2/relay", post(relay::relay))
        .layer(DefaultBodyLimit::max(ladon_relay_core_v2::wire::sealed::LANE_S_REQUEST_LEN))
        .layer(axum::middleware::from_fn_with_state(state.clone(), rate_limit_mw));

    // Unlimited: health/canary for monitoring.
    let unlimited = axum::Router::new()
        .route("/v2/health", get(handlers::health))
        .route("/canary.json", get(handlers::canary));

    limited.merge(unlimited).with_state(state)
}

