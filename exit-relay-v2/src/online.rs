//! A2 §7: who fetched recently. The push decision for sealed envelopes
//! depends on this alone, never on envelope content: a recipient that
//! fetched within `ONLINE_WINDOW_SEC` is online and gets no push.
//!
//! RAM only, one timestamp per recipient. An entry older than the window
//! means the same as no entry (offline), so the map is pruned of those
//! whenever it grows past `PRUNE_AT` — its size is bounded by the number of
//! recipients that fetched within one window.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use ladon_relay_core_v2::constants::PUSH_DEBOUNCE_SEC;
use ladon_relay_core_v2::ids::RecipientId;
use ladon_relay_core_v2::wire::sealed::ONLINE_WINDOW_SEC;

const PRUNE_AT: usize = 10_000;

/// Per recipient: time of the last fetch (unix s) and a fetch sequence
/// number from one counter for the whole exit, so "fetched since" never
/// depends on clock resolution.
#[derive(Default)]
pub struct OnlineTracker {
    last_fetch: Mutex<HashMap<RecipientId, (u64, u64)>>,
    seq: AtomicU64,
}

impl OnlineTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a successful fetch by `rid` at `now`.
    pub fn record_fetch(&self, rid: &RecipientId, now: u64) {
        let mut g = self.last_fetch.lock().unwrap_or_else(|e| e.into_inner());
        if g.len() >= PRUNE_AT {
            g.retain(|_, (t, _)| now.saturating_sub(*t) <= ONLINE_WINDOW_SEC);
        }
        let seq = self.seq.fetch_add(1, Ordering::Relaxed) + 1;
        g.insert(*rid, (now, seq));
    }

    /// True iff `rid` fetched within `ONLINE_WINDOW_SEC` before `now`.
    pub fn is_online(&self, rid: &RecipientId, now: u64) -> bool {
        let g = self.last_fetch.lock().unwrap_or_else(|e| e.into_inner());
        g.get(rid).is_some_and(|(t, _)| now.saturating_sub(*t) <= ONLINE_WINDOW_SEC)
    }

    /// A mark for `fetched_since`: the recipient's latest fetch so far.
    pub fn fetch_mark(&self, rid: &RecipientId) -> u64 {
        let g = self.last_fetch.lock().unwrap_or_else(|e| e.into_inner());
        g.get(rid).map_or(0, |(_, seq)| *seq)
    }

    /// True iff `rid` fetched after `mark` was taken. A pruned entry counts
    /// as no fetch (it is pruned only once it is older than the window).
    pub fn fetched_since(&self, rid: &RecipientId, mark: u64) -> bool {
        let g = self.last_fetch.lock().unwrap_or_else(|e| e.into_inner());
        g.get(rid).is_some_and(|(_, seq)| *seq > mark)
    }
}

/// F44: at most one notify per recipient per `PUSH_DEBOUNCE_SEC` leaves this
/// exit. The push relay debounces with the same window, so a second notify
/// inside it never reached APNs; sending it only spent the push relay's S2S
/// admissions and nonce slots. Bounded like `OnlineTracker`: an entry older
/// than the window means the same as no entry, so the map is pruned of
/// those whenever it grows past `PRUNE_AT`. Local clock only.
#[derive(Default)]
pub struct NotifyDebounce {
    last: Mutex<HashMap<RecipientId, u64>>,
}

impl NotifyDebounce {
    pub fn new() -> Self {
        Self::default()
    }

    /// `true` (and records `now`) iff no notify for `rid` was allowed within
    /// the last `PUSH_DEBOUNCE_SEC` seconds.
    pub fn allow(&self, rid: &RecipientId, now: u64) -> bool {
        let mut g = self.last.lock().unwrap_or_else(|e| e.into_inner());
        if g.len() >= PRUNE_AT {
            g.retain(|_, t| now.saturating_sub(*t) < PUSH_DEBOUNCE_SEC);
        }
        if g.get(rid).is_some_and(|t| now.saturating_sub(*t) < PUSH_DEBOUNCE_SEC) {
            return false;
        }
        g.insert(*rid, now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notify_debounce_window_and_pruning() {
        let d = NotifyDebounce::new();
        let rid = RecipientId([4; 32]);
        assert!(d.allow(&rid, 1_000));
        assert!(!d.allow(&rid, 1_000 + PUSH_DEBOUNCE_SEC - 1));
        assert!(d.allow(&rid, 1_000 + PUSH_DEBOUNCE_SEC), "window over");
        assert!(d.allow(&RecipientId([5; 32]), 1_000), "per recipient");
        for i in 0..PRUNE_AT {
            let mut b = [0u8; 32];
            b[..8].copy_from_slice(&(i as u64).to_be_bytes());
            d.allow(&RecipientId(b), 2_000);
        }
        assert!(d.allow(&RecipientId([6; 32]), 2_000 + PUSH_DEBOUNCE_SEC));
        assert_eq!(d.last.lock().unwrap().len(), 1, "expired entries pruned");
    }

    #[test]
    fn online_only_within_the_window() {
        let t = OnlineTracker::new();
        let rid = RecipientId([1; 32]);
        assert!(!t.is_online(&rid, 1_000), "never fetched = offline");
        t.record_fetch(&rid, 1_000);
        assert!(t.is_online(&rid, 1_000));
        assert!(t.is_online(&rid, 1_000 + ONLINE_WINDOW_SEC));
        assert!(!t.is_online(&rid, 1_000 + ONLINE_WINDOW_SEC + 1));
    }

    #[test]
    fn fetched_since_follows_the_fetch_sequence() {
        let t = OnlineTracker::new();
        let rid = RecipientId([2; 32]);
        let other = RecipientId([3; 32]);
        let m0 = t.fetch_mark(&rid);
        assert!(!t.fetched_since(&rid, m0), "no fetch yet");
        t.record_fetch(&rid, 100);
        assert!(t.fetched_since(&rid, m0));
        let m1 = t.fetch_mark(&rid);
        t.record_fetch(&other, 100);
        assert!(!t.fetched_since(&rid, m1), "another recipient's fetch does not count");
        t.record_fetch(&rid, 100);
        assert!(t.fetched_since(&rid, m1), "same second, still a later fetch");
    }

    #[test]
    fn pruning_keeps_recent_and_drops_stale() {
        let t = OnlineTracker::new();
        for i in 0..PRUNE_AT {
            let mut b = [0u8; 32];
            b[..8].copy_from_slice(&(i as u64).to_be_bytes());
            t.record_fetch(&RecipientId(b), 100);
        }
        let recent = RecipientId([9; 32]);
        t.record_fetch(&recent, 100 + ONLINE_WINDOW_SEC + 5);
        assert!(t.last_fetch.lock().unwrap().len() == 1, "stale entries pruned");
        assert!(t.is_online(&recent, 100 + ONLINE_WINDOW_SEC + 5));
    }
}
