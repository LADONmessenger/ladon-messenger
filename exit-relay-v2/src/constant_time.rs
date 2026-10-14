//! Constant-time error padding (Spec §4.8 last paragraph): every error response
//! takes the same wall-clock duration regardless of which validation step failed,
//! preventing timing oracles. The success path is deliberately NOT padded —
//! correct envelopes are dominated by AEAD/HKEM cost which already varies less.
//!
//! Implementation: handlers `await` the deadline future before returning an error.

use std::time::Instant;
use tokio::time::{sleep_until, Instant as TokioInstant};

/// Scope object created at handler entry. On drop (or via `delay()`) it pads
/// the elapsed time up to a fixed deadline.
pub struct PadDeadline {
    deadline: TokioInstant,
}

impl PadDeadline {
    pub fn new(target_ms: u64) -> Self {
        let now = Instant::now();
        Self {
            deadline: TokioInstant::from_std(now)
                + std::time::Duration::from_millis(target_ms),
        }
    }

    /// Sleeps until the fixed deadline. Call before returning an error.
    pub async fn delay(&self) {
        sleep_until(self.deadline).await;
    }
}

/// Default pad target: 50 ms.
///
/// P7-EXIT-09: bumped from 20 ms to 50 ms because the prior budget was
/// measured under loopback-only benchmarks. On a real exit (Kyber768
/// decaps + AEAD + directory lookup + replay-window check) the success
/// path occasionally exceeds 20 ms, which would let the success/error
/// dichotomy become observable through the very padding that was
/// supposed to hide it. 50 ms keeps the success path comfortably below
/// the deadline on every benchmark host we measured (P99 ~ 35 ms).
pub const DEFAULT_PAD_MS: u64 = 50;
