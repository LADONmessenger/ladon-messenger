//! Push-Relay shared state.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use ladon_relay_core_v2::ratelimit::IdentityRateLimiter;
use ladon_relay_core_v2::store::{DirectoryReplica, PushTokenStore};

use crate::apns::ApnsSender;
use crate::s2s::S2sNonceStore;

/// Shared state injected into every handler. All fields are cheap to clone
/// (Arc/atomic) so we can wrap the whole thing in a single `Arc<PushState>`.
/// A2 §7 rule 4: upper bound of the random delay before an APNs send.
pub const PUSH_DELAY_MAX_MS: u64 = 3_000;

/// Allowed clock skew for inbound S2S timestamps (exit → push).
pub const S2S_SKEW_SEC: u64 = 60;

/// F44: authenticated S2S requests admitted per exit hop and second; above
/// it the request is shed with 503 (replicate and notify are best-effort on
/// the exit side). An exit calls the push relay at most once per sealed
/// request it accepted (replicate after a DIR_PUT, notify after an
/// ENQUEUE), and admits at most 2,000 sealed requests a second (exit
/// `sealed::SEALED_ADMIT_PER_SEC`, P8-AUDIT8-SRV-07). A deferred notify
/// (`DEFERRED_PUSH_CHECK_SEC` later) can share a second with fresh calls,
/// hence twice that.
///
/// The nonce store holds `4,000 × (2 × 60 + 1) = 484,000` entries per hop;
/// at roughly 200 B each (hop string and nonce, kept in the set and in the
/// FIFO) that is about 0.1 GB per exit hop, at full rate only.
pub const S2S_ADMIT_PER_HOP_PER_SEC: u32 = 4_000;

pub struct PushState {
    /// Recipient → APNs device token registry.
    pub push_tokens: PushTokenStore,
    /// Replica of `(rid → hsig_pk)` from the exit-relay; read-only here.
    pub directory_replica: DirectoryReplica,
    /// B2.2 (2026-05-12): Per-exit HMAC key map for inbound S2S verify.
    /// Lookup by `X-Relay-Hop` header. Loaded at startup from
    /// `LADON_EXIT_KEYS_FILE`; immutable thereafter.
    pub exit_keys: Arc<HashMap<String, [u8; 32]>>,
    /// Allowed clock skew for inbound S2S timestamps.
    pub s2s_skew_sec: u64,
    /// Allowed clock skew for the signed timestamp of a push registration.
    pub push_register_skew_sec: u64,
    /// Minimum interval between two successive APNs pushes for the same
    /// recipient (`PUSH_DEBOUNCE_SEC`).
    pub push_debounce_sec: u64,
    /// A2 §7 rule 4: each push leaves after a uniformly random delay in
    /// `0..=push_delay_max_ms`, so its time says less about the arrival.
    /// `PUSH_DELAY_MAX_MS` in production; tests set 0.
    pub push_delay_max_ms: u64,
    /// APNs sender (real in production, recording mock in tests).
    pub apns: Arc<dyn ApnsSender>,
    /// This relay's hop id, e.g. `"push1"`. Echoed in headers + logs.
    pub hop_id: String,
    /// P7-PUSH-04: anti-replay store for S2S nonces.
    pub s2s_nonce_store: S2sNonceStore,
    /// P7-PUSH-04: when true, accept legacy (no-nonce) S2S signatures.
    /// Default true for zero-downtime rollout; flip to false once all
    /// upstream exit-relays sign with the tagged + nonce form.
    pub s2s_accept_legacy: bool,
    /// F9: verify budget and per-recipient limit of `POST /v2/sealed`.
    pub sealed_limits: SealedLimits,
    /// P7-PUSH-09: bound on concurrent APNs send tasks.
    ///
    /// `push_notify` previously did `tokio::spawn(send_alert(...))`
    /// unconditionally per accepted request. Apple's HTTP/2 stack can
    /// stall on backpressure for tens of seconds, so an attacker spraying
    /// notifies (with valid S2S sigs from a compromised exit-hop key)
    /// could pin an unbounded number of futures in the runtime and OOM
    /// the relay. Acquiring a permit before spawn (or dropping the send)
    /// bounds the in-flight set at `APNS_MAX_CONCURRENT` (default 256).
    pub apns_concurrency: Arc<tokio::sync::Semaphore>,
    /// P7-PUSH-08 / Addendum A1 §14: allow-list of hop ids permitted to
    /// call `PUT /v2/directory/replicate`. Mandatory: `main` refuses to
    /// start without `LADON_PUSH_DIRECTORY_OWNERS` (comma-separated). Empty
    /// (the `new` default) means no hop may replicate — fail-closed.
    pub directory_owner_hops: HashSet<String>,
    /// A2 stage 2: this relay's HKEM key pair and target id for sealed
    /// requests (`POST /v2/sealed`, kind PUSH_REGISTER). `main` loads it from
    /// `LADON_PUSH_HKEM_KEYFILE` (fail-closed in release builds); `None` makes
    /// the sealed route answer 503.
    pub sealed: Option<SealedIdentity>,
}

/// F9: limits on the sealed route (`POST /v2/sealed`), modelled on the
/// exit's `SealedLimits`. The route has no per-IP limit any more: the Entry
/// forwards every sealed request, so behind Caddy each one carries the
/// Entry's address and a per-IP bucket was one bucket for all clients. The
/// Entry already limits per client IP (`entry-relay-v2/src/lib.rs`
/// `rate_limit_mw`, 600/min).
///
/// - `MAX_SIG_VERIFIES_PER_SEC`: hybrid-signature verifications per second
///   for the whole relay, taken right before `hsig::verify_tagged`; above
///   it the sealed status is UNAVAILABLE (the client retries later). Same
///   value as the exit's cap.
/// - `REGISTER_PER_RID_PER_MIN`: registrations per recipient, counted only
///   after the signature held (a forged request must not spend the
///   victim's budget); above it the sealed status is RATE. A device
///   registers on launch and on token rotation, far below 10 a minute.
pub const MAX_SIG_VERIFIES_PER_SEC: u32 = 2_000;
pub const REGISTER_PER_RID_PER_MIN: u32 = 10;

pub struct SealedLimits {
    verifies: std::sync::Mutex<(u64, u32)>,
    max_verifies_per_sec: u32,
    pub register_per_rid: IdentityRateLimiter,
}

impl Default for SealedLimits {
    fn default() -> Self {
        Self::with_verify_cap(MAX_SIG_VERIFIES_PER_SEC)
    }
}

impl SealedLimits {
    pub fn with_verify_cap(max_verifies_per_sec: u32) -> Self {
        Self {
            verifies: std::sync::Mutex::new((0, 0)),
            max_verifies_per_sec,
            register_per_rid: IdentityRateLimiter::new_with_budget(REGISTER_PER_RID_PER_MIN),
        }
    }

    /// Take one verification from this second's budget (`now` in seconds).
    pub fn take_verify(&self, now: u64) -> Result<(), crate::error::ApiError> {
        let mut g = self.verifies.lock().unwrap_or_else(|e| e.into_inner());
        if g.0 != now {
            *g = (now, 0);
        }
        if g.1 >= self.max_verifies_per_sec {
            tracing::warn!("sealed: signature-verify cap reached");
            return Err(crate::error::ApiError::Unavailable);
        }
        g.1 += 1;
        Ok(())
    }
}

/// HKEM key pair and the derived target id (`BLAKE3(pk)[..16]`, as for an
/// exit) the client seals PUSH_REGISTER to.
pub struct SealedIdentity {
    pub keys: ladon_relay_core_v2::hkem::HkemKeyPair,
    pub target_id: [u8; 16],
}

impl PushState {
    pub fn new(
        exit_keys: Arc<HashMap<String, [u8; 32]>>,
        hop_id: String,
        apns: Arc<dyn ApnsSender>,
    ) -> Self {
        use ladon_relay_core_v2::constants::{PUSH_DEBOUNCE_SEC, PUSH_REGISTER_SKEW_SEC};
        // F44: a nonce stays valid while |ts - now| <= skew on this clock,
        // i.e. for up to 2 × skew after the first time it is seen (sender
        // clock ahead by `skew`, replay at `ts + skew`). So TTL = 2 × skew;
        // longer only costs memory. Capacity follows from the admission cap.
        let s2s_nonce_store = S2sNonceStore::new(
            Duration::from_secs(2 * S2S_SKEW_SEC),
            S2S_ADMIT_PER_HOP_PER_SEC,
            exit_keys.keys().map(String::as_str),
        );
        Self {
            push_tokens: PushTokenStore::new(),
            directory_replica: DirectoryReplica::new(),
            exit_keys,
            s2s_skew_sec: S2S_SKEW_SEC,
            push_register_skew_sec: PUSH_REGISTER_SKEW_SEC,
            push_debounce_sec: PUSH_DEBOUNCE_SEC,
            push_delay_max_ms: PUSH_DELAY_MAX_MS,
            apns,
            hop_id,
            s2s_nonce_store,
            s2s_accept_legacy: true,
            sealed_limits: SealedLimits::default(),
            apns_concurrency: Arc::new(tokio::sync::Semaphore::new(256)),
            directory_owner_hops: HashSet::new(),
            sealed: None,
        }
    }
}
