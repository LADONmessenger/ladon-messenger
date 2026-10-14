use std::sync::Arc;

use ladon_relay_core_v2::ratelimit::RateLimiter;

use crate::registry::ExitRegistry;

pub struct EntryState {
    pub hop_id: String,
    pub s2s_key: [u8; 32],
    pub registry: ExitRegistry,
    pub http: reqwest::Client,
    pub canary_path: std::path::PathBuf,
    /// Base URL of the push-relay used by `PUT /v2/proxy-push-register/:rid`.
    /// `None` disables the proxy endpoint (returns 503 E-PUSH-DISABLED).
    /// Privacy-by-design: clients never reach the push-relay directly,
    /// mirroring the proxy-directory[-put] pattern.
    pub push_relay_url: Option<String>,
    /// A2 stage 2: target id of the push relay's HKEM key. A sealed request
    /// for this id goes to `push_relay_url`; `None` = such requests are
    /// refused as an unknown target.
    pub push_target_id: Option<[u8; 16]>,
    /// FIX SRV-1 (2026-05-06): Per-IP sliding-window rate limiter (600 req/min).
    /// Keyed by the rightmost X-Forwarded-For value (Caddy's view of the client).
    /// Applied to user-facing routes only (NOT /v2/health, NOT /canary.json).
    pub rate_limiter: Arc<RateLimiter>,
}

impl EntryState {
    pub fn arc(self) -> Arc<Self> { Arc::new(self) }
}
