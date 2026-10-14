//! Constant-time error padding — copy of `exit-relay-v2::constant_time` so
//! the push-relay can reuse the same pattern without depending on the exit
//! crate.

use std::time::Instant;
use tokio::time::{sleep_until, Instant as TokioInstant};

/// Scope object created at handler entry. Call `delay()` before returning
/// an error to pad the wall-clock time to a fixed deadline.
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

    pub async fn delay(&self) {
        sleep_until(self.deadline).await;
    }
}

pub const DEFAULT_PAD_MS: u64 = 20;
