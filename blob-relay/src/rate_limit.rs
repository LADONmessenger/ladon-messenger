//! Sliding-window rate limiters (per-IP and per-identity) and concurrency
//! semaphores. Mirrors exit-relay patterns.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tokio::sync::Semaphore;

const IP_CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

/// Sliding-window limiter keyed by some string key.
pub struct SlidingLimiter {
    inner: Mutex<SlidingInner>,
    window: Duration,
    limit: usize,
}

struct SlidingInner {
    windows: HashMap<String, VecDeque<Instant>>,
    last_cleanup: Instant,
}

impl SlidingLimiter {
    pub fn new(window: Duration, limit: usize) -> Self {
        Self {
            inner: Mutex::new(SlidingInner {
                windows: HashMap::new(),
                last_cleanup: Instant::now(),
            }),
            window,
            limit,
        }
    }

    /// Returns true if the request is allowed.
    pub fn check(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut g = self.inner.lock().unwrap();

        if now.duration_since(g.last_cleanup) >= IP_CLEANUP_INTERVAL {
            let window = self.window;
            g.windows.retain(|_, entries| {
                entries.retain(|t| now.duration_since(*t) <= window);
                !entries.is_empty()
            });
            g.last_cleanup = now;
        }

        let window = self.window;
        let limit = self.limit;
        let entries = g.windows.entry(key.to_string()).or_default();
        while let Some(front) = entries.front() {
            if now.duration_since(*front) > window {
                entries.pop_front();
            } else {
                break;
            }
        }
        if entries.len() >= limit {
            return false;
        }
        entries.push_back(now);
        true
    }
}

/// Per-IP limiter convenience wrapper.
pub struct IpLimiter {
    limiter: SlidingLimiter,
}

impl IpLimiter {
    pub fn new(window: Duration, limit: usize) -> Self {
        Self {
            limiter: SlidingLimiter::new(window, limit),
        }
    }
    pub fn check(&self, ip: IpAddr) -> bool {
        self.limiter.check(&ip.to_string())
    }
}

/// Tight semaphore wrapping concurrency limits. Acquire-try pattern.
///
/// P7-BLOB-06 fix (2026-05-12): the `per_ip` HashMap previously grew without
/// bound — one entry per distinct client IP for the process lifetime. Behind
/// a botnet that's hundreds of MB of leaked memory plus unbounded lock-
/// contention on the table itself. We now cap the map at `MAX_PER_IP_KEYS`
/// and, when at cap and inserting a new IP, evict any entries whose semaphore
/// is fully released (i.e. no in-flight request). If none can be released
/// (everyone is actively in-flight) the new IP is rejected — fail-closed.
pub struct ConcurrencyGate {
    global: std::sync::Arc<Semaphore>,
    per_ip: Mutex<HashMap<String, std::sync::Arc<Semaphore>>>,
    per_ip_limit: usize,
}

/// Hard upper bound on distinct IPs tracked at once. Sized for typical
/// pilot fleet (5k–50k DAU per Exit) with comfortable headroom.
const MAX_PER_IP_KEYS: usize = 65_536;

impl ConcurrencyGate {
    pub fn new(global_limit: usize, per_ip_limit: usize) -> Self {
        Self {
            global: std::sync::Arc::new(Semaphore::new(global_limit)),
            per_ip: Mutex::new(HashMap::new()),
            per_ip_limit,
        }
    }

    /// Try to acquire one global + one per-IP permit. Returns both permits
    /// on success, dropping will release them.
    pub fn try_acquire(&self, ip: IpAddr) -> Option<GatePermits> {
        let ip_key = ip.to_string();
        let ip_sem = {
            let mut g = self.per_ip.lock().unwrap();
            if !g.contains_key(&ip_key) && g.len() >= MAX_PER_IP_KEYS {
                // Evict any IP with no current in-flight request (semaphore
                // fully released). Bounded by MAX_PER_IP_KEYS so still O(N)
                // in absolute terms but only on insert-after-cap, never in
                // the hot path.
                let idle: Vec<String> = g
                    .iter()
                    .filter(|(_, s)| s.available_permits() >= self.per_ip_limit)
                    .map(|(k, _)| k.clone())
                    .collect();
                if idle.is_empty() {
                    // All tracked IPs are actively in-flight: refuse the new
                    // IP rather than blow the bound. Fail-closed.
                    return None;
                }
                for k in idle {
                    g.remove(&k);
                }
            }
            g.entry(ip_key)
                .or_insert_with(|| std::sync::Arc::new(Semaphore::new(self.per_ip_limit)))
                .clone()
        };

        let global_permit = self.global.clone().try_acquire_owned().ok()?;
        let ip_permit = ip_sem.try_acquire_owned().ok()?;
        Some(GatePermits {
            _global: global_permit,
            _ip: ip_permit,
        })
    }
}

pub struct GatePermits {
    _global: tokio::sync::OwnedSemaphorePermit,
    _ip: tokio::sync::OwnedSemaphorePermit,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sliding_limiter_blocks_at_limit() {
        let l = SlidingLimiter::new(Duration::from_secs(60), 3);
        assert!(l.check("x"));
        assert!(l.check("x"));
        assert!(l.check("x"));
        assert!(!l.check("x"));
    }

    #[test]
    fn distinct_keys_independent() {
        let l = SlidingLimiter::new(Duration::from_secs(60), 1);
        assert!(l.check("a"));
        assert!(l.check("b"));
        assert!(!l.check("a"));
    }
}
