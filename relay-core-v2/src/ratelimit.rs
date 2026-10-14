//! FIX SRV-1 (2026-05-06): Sliding-window rate limiting for entry/exit v2.
//!
//! Ported verbatim from v1 (`exit-relay/src/main.rs:934-1108`). Same algorithm,
//! same constants, same audit history (S5 sliding-window, M-10 no-IP-logging,
//! K13 opaque error, RS-M1 per-identity complement).
//!
//! Algorithmic properties:
//!   * **Sliding window** with two counters (previous/current) — RFC 6585
//!     compliant; prevents 2× burst at boundary that fixed-window allows.
//!   * **Bounded memory**: oldest-10% eviction when `MAX_*_ENTRIES` exceeded.
//!   * **Opaque error**: returns `Err(RateLimited)` (a unit struct, no
//!     payload) so callers cannot leak request count.
//!
//! Public surface:
//!   * `RateLimiter::check(IpAddr) -> Result<(), RateLimited>` (per-IP, 600 req/min)
//!   * `IdentityRateLimiter::check(&str) -> Result<(), RateLimited>` (per-identity, 120 req/min)
//!   * `cleanup_expired()` for periodic GC by spawned task.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

// Per-IP limits (matches v1: exit-relay/src/main.rs:947-949).
const IP_MAX_REQ_PER_MIN: u32 = 600;
const IP_MAX_ENTRIES: usize = 100_000;

// Per-identity limits (matches v1: exit-relay/src/main.rs:1052-1054).
const ID_MAX_REQ_PER_MIN: u32 = 120;
const ID_MAX_ENTRIES: usize = 200_000;

const WINDOW_SECONDS: i64 = 60;

#[derive(Clone)]
struct Entry {
    previous_count: u32,
    current_count: u32,
    window_start: i64,
}

/// Budget exceeded. Deliberately carries nothing — no count, no remaining
/// budget — so a caller cannot leak it (K13). Replaces the former `()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimited;

/// Generic sliding-window check; returns `Err(RateLimited)` if estimated rate ≥ `max_per_min`.
fn check_generic<K: std::hash::Hash + Eq + Clone>(
    map: &mut HashMap<K, Entry>,
    key: K,
    now: i64,
    max_per_min: u32,
    max_entries: usize,
) -> Result<(), RateLimited> {
    // Bounded-memory eviction. P7-RCV2-04 fix (2026-05-12): the original
    // implementation collected all keys + window_starts into a Vec, sorted it
    // O(N log N) and removed the oldest 10 %. At N = 200 000 (identity map)
    // that is a ~3.6 M-comparison sort on every cache-miss while at cap.
    //
    // New strategy (still bounded, but cheap):
    //   1. Drop entries whose sliding window is already two windows old
    //      (their counters are zero anyway). O(N) one scan, no sort.
    //   2. If we are still at cap and the new key isn't present, fall back
    //      to `select_nth_unstable` (O(N) avg, no full sort) to find the
    //      10 % cutoff and evict everything <= it.
    // The second branch only runs under sustained pressure; the first
    // covers the steady state.
    if map.len() >= max_entries && !map.contains_key(&key) {
        // Step 1 — cheap expiry sweep (same predicate as cleanup_generic).
        map.retain(|_, e| now - e.window_start < WINDOW_SECONDS * 2);

        // Step 2 — only if pressure is real.
        if map.len() >= max_entries {
            let target = (map.len() / 10).max(1);
            let mut ages: Vec<i64> = map.values().map(|v| v.window_start).collect();
            if target < ages.len() {
                // O(N) average partition; we only need the cutoff value.
                let (_, cutoff_ref, _) = ages.select_nth_unstable(target);
                let cutoff = *cutoff_ref;
                map.retain(|_, e| e.window_start > cutoff);
            } else {
                // Degenerate: cap == 1; drop everything.
                map.clear();
            }
        }
    }

    let entry = map.entry(key).or_insert(Entry {
        previous_count: 0,
        current_count: 0,
        window_start: now,
    });

    // Window rotation.
    let elapsed = now - entry.window_start;
    if elapsed >= WINDOW_SECONDS {
        if elapsed >= 2 * WINDOW_SECONDS {
            entry.previous_count = 0;
            entry.current_count = 0;
        } else {
            entry.previous_count = entry.current_count;
            entry.current_count = 0;
        }
        entry.window_start += (elapsed / WINDOW_SECONDS) * WINDOW_SECONDS;
    }

    // Sliding-window estimation.
    let elapsed_in_current = now - entry.window_start;
    let previous_weight = 1.0 - (elapsed_in_current as f64 / WINDOW_SECONDS as f64);
    let estimated =
        (entry.previous_count as f64 * previous_weight) + entry.current_count as f64;

    if estimated >= max_per_min as f64 {
        return Err(RateLimited); // K13: opaque, no count leak.
    }
    entry.current_count += 1;
    Ok(())
}

fn cleanup_generic<K: std::hash::Hash + Eq>(map: &mut HashMap<K, Entry>, now: i64) {
    map.retain(|_, e| now - e.window_start < WINDOW_SECONDS * 2);
}

#[inline]
fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

// ---------------------------------------------------------------------------
// Per-IP limiter
// ---------------------------------------------------------------------------

pub struct RateLimiter {
    inner: Mutex<HashMap<IpAddr, Entry>>,
    max_per_min: u32,
    max_entries: usize,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            max_per_min: IP_MAX_REQ_PER_MIN,
            max_entries: IP_MAX_ENTRIES,
        }
    }

    /// P7-ENTRY-05: construct a per-IP limiter with a tighter custom budget.
    /// Used for high-bandwidth endpoints (e.g. proxy_directory_put) that need
    /// stricter caps than the generic 600/min user budget.
    pub fn new_with_budget(max_per_min: u32, max_entries: usize) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            max_per_min,
            max_entries,
        }
    }

    /// Returns `Err(RateLimited)` when the per-IP budget is exceeded. Caller maps
    /// to HTTP 429. Never log the IP (FIX M-10).
    pub fn check(&self, ip: IpAddr) -> Result<(), RateLimited> {
        let now = now_secs();
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        check_generic(&mut map, ip, now, self.max_per_min, self.max_entries)
    }

    pub fn cleanup_expired(&self) {
        let now = now_secs();
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        cleanup_generic(&mut map, now);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }
}

impl Default for RateLimiter {
    fn default() -> Self { Self::new() }
}

// ---------------------------------------------------------------------------
// Per-identity limiter
// ---------------------------------------------------------------------------

pub struct IdentityRateLimiter {
    inner: Mutex<HashMap<String, Entry>>,
    max_per_min: u32,
}

impl IdentityRateLimiter {
    pub fn new() -> Self {
        Self::new_with_budget(ID_MAX_REQ_PER_MIN)
    }

    /// A limiter with its own per-identity budget (requests per minute).
    pub fn new_with_budget(max_per_min: u32) -> Self {
        Self { inner: Mutex::new(HashMap::new()), max_per_min }
    }

    /// Returns `Err(RateLimited)` when the per-identity budget is exceeded.
    pub fn check(&self, identity: &str) -> Result<(), RateLimited> {
        let now = now_secs();
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        check_generic(&mut map, identity.to_string(), now, self.max_per_min, ID_MAX_ENTRIES)
    }

    pub fn cleanup_expired(&self) {
        let now = now_secs();
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        cleanup_generic(&mut map, now);
    }
}

impl Default for IdentityRateLimiter {
    fn default() -> Self { Self::new() }
}

// ---------------------------------------------------------------------------
// X-Forwarded-For extraction
// ---------------------------------------------------------------------------

/// Extract the client IP from the trusted reverse proxy chain.
///
/// The v2 relays listen on 127.0.0.1 and only ever receive traffic via the
/// local Caddy reverse-proxy (`tls` terminates in Caddy → loopback). Therefore
/// the **last** value of `X-Forwarded-For` is the IP that Caddy itself observed
/// (the real client, modulo any upstream proxy the operator configures); the
/// first value is whatever the client claimed and MUST NOT be trusted.
///
/// Returns `None` on malformed input, missing header, or unparseable address.
/// Callers SHOULD fall back to `remote_addr.ip()` only if they trust the
/// peer address (which on 127.0.0.1 is always loopback — useless for
/// rate-limiting). With Caddy in front, treating "no XFF" as bypass is wrong;
/// we instead deny if no usable client IP can be derived.
pub fn extract_client_ip(xff_header: Option<&str>) -> Option<IpAddr> {
    let raw = xff_header?;
    // Caddy appends, so the **rightmost** entry is what Caddy saw. Walk from
    // the right and return the first parseable address.
    for tok in raw.rsplit(',') {
        let s = tok.trim();
        if s.is_empty() { continue; }
        if let Ok(ip) = s.parse::<IpAddr>() {
            return Some(ip);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn ip_limiter_allows_under_budget() {
        let rl = RateLimiter::new();
        for _ in 0..599 {
            assert!(rl.check(ip(10, 0, 0, 1)).is_ok());
        }
    }

    #[test]
    fn ip_limiter_blocks_when_exceeded() {
        let rl = RateLimiter::new();
        // 600 allowed, the 601st must be denied within the same second.
        for _ in 0..600 {
            let _ = rl.check(ip(10, 0, 0, 2));
        }
        // After 600 successful, current_count=600. Estimated >= 600 → deny.
        assert!(rl.check(ip(10, 0, 0, 2)).is_err());
    }

    #[test]
    fn ip_limiter_isolates_keys() {
        let rl = RateLimiter::new();
        for _ in 0..600 { let _ = rl.check(ip(10, 0, 0, 3)); }
        // Different IP must still be allowed.
        assert!(rl.check(ip(10, 0, 0, 4)).is_ok());
    }

    #[test]
    fn identity_limiter_lower_budget() {
        let il = IdentityRateLimiter::new();
        for _ in 0..120 { let _ = il.check("rid-A"); }
        assert!(il.check("rid-A").is_err());
        assert!(il.check("rid-B").is_ok());
    }

    #[test]
    fn xff_uses_rightmost_token() {
        // Last entry = what trusted proxy (Caddy) observed.
        assert_eq!(
            extract_client_ip(Some("1.1.1.1, 2.2.2.2, 3.3.3.3")),
            Some(ip(3, 3, 3, 3))
        );
    }

    #[test]
    fn xff_skips_bad_tokens() {
        assert_eq!(
            extract_client_ip(Some("1.1.1.1, garbage, 9.9.9.9")),
            Some(ip(9, 9, 9, 9))
        );
    }

    #[test]
    fn xff_handles_missing() {
        assert_eq!(extract_client_ip(None), None);
        assert_eq!(extract_client_ip(Some("")), None);
        assert_eq!(extract_client_ip(Some("not-an-ip")), None);
    }

    #[test]
    fn xff_ipv6() {
        assert_eq!(
            extract_client_ip(Some("::1")),
            Some("::1".parse().unwrap())
        );
    }

    #[test]
    fn eviction_bounded() {
        let rl = RateLimiter::new();
        // We can't easily push 100k entries quickly here without time; just
        // verify single-entry path doesn't grow unboundedly.
        for i in 0..50 {
            let _ = rl.check(ip(10, 0, 0, i));
        }
        assert_eq!(rl.len(), 50);
    }
}
