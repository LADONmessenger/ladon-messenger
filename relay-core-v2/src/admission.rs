//! Admission caps and replay sets that are sized to each other (audit 8:
//! F8, F44).
//!
//! A bounded replay set fails closed when full: it refuses everything new,
//! so a full set is a denial of service on the path it guards. It must
//! therefore never fill at the rate the relay admits. These two types make
//! that a checkable property instead of a guessed constant:
//!
//! - [`PerSecondCap`] admits at most `per_sec` requests per calendar second
//!   of the caller's clock (the same fixed-window pattern as the exit's
//!   verify budget).
//! - [`SeenFifo`] remembers keys for `ttl` seconds with insertion-ordered
//!   expiry (O(1) amortised, no full scan per insert), and
//!   [`SeenFifo::capacity_for`] is the size a given admission rate needs.
//!
//! Neither depends on clocks agreeing between hosts: both only compare
//! values of the local clock passed in by the caller.

use std::collections::{HashSet, VecDeque};
use std::hash::Hash;
use std::sync::Mutex;

/// At most `per_sec` admissions per calendar second.
pub struct PerSecondCap {
    window: Mutex<(u64, u32)>,
    per_sec: u32,
}

impl PerSecondCap {
    pub fn new(per_sec: u32) -> Self {
        Self { window: Mutex::new((0, 0)), per_sec }
    }

    /// Take one admission in second `now`; `false` once this second's
    /// budget is spent.
    pub fn try_take(&self, now: u64) -> bool {
        let mut g = self.window.lock().unwrap_or_else(|e| e.into_inner());
        if g.0 != now {
            *g = (now, 0);
        }
        if g.1 >= self.per_sec {
            return false;
        }
        g.1 += 1;
        true
    }

    pub fn per_sec(&self) -> u32 {
        self.per_sec
    }
}

/// Outcome of [`SeenFifo::insert_if_new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeenInsert {
    /// Not seen within the TTL; now recorded.
    Fresh,
    /// Seen within the TTL.
    Replay,
    /// At capacity; nothing recorded. Callers refuse (fail-closed). With a
    /// capacity from `capacity_for` this happens only above the admitted
    /// rate or after the local clock stepped backwards.
    Full,
}

/// Keys seen within the last `ttl_sec` seconds. A key recorded at second
/// `t` is remembered while `now - t <= ttl_sec`.
pub struct SeenFifo<K> {
    seen: HashSet<K>,
    /// Insertion order with the recording second, non-decreasing: a clock
    /// that steps back records at the newest second already present, so
    /// such keys are remembered longer, never shorter.
    order: VecDeque<(u64, K)>,
    ttl_sec: u64,
    capacity: usize,
}

impl<K: Hash + Eq + Clone> SeenFifo<K> {
    pub fn new(ttl_sec: u64, capacity: usize) -> Self {
        Self { seen: HashSet::new(), order: VecDeque::new(), ttl_sec, capacity }
    }

    /// Entries needed so that `per_sec` admissions per calendar second never
    /// fill a set with this TTL: a key recorded in second `t` is held
    /// through second `t + ttl`, so `ttl + 1` seconds of admissions are
    /// held at once.
    pub fn capacity_for(per_sec: u32, ttl_sec: u64) -> usize {
        (per_sec as u64).saturating_mul(ttl_sec.saturating_add(1)) as usize
    }

    pub fn insert_if_new(&mut self, key: K, now: u64) -> SeenInsert {
        while let Some((t, _)) = self.order.front() {
            if now.saturating_sub(*t) <= self.ttl_sec {
                break;
            }
            let (_, old) = self.order.pop_front().expect("front exists");
            self.seen.remove(&old);
        }
        if self.seen.contains(&key) {
            return SeenInsert::Replay;
        }
        if self.seen.len() >= self.capacity {
            return SeenInsert::Full;
        }
        let at = self.order.back().map_or(now, |(t, _)| (*t).max(now));
        self.seen.insert(key.clone());
        self.order.push_back((at, key));
        SeenInsert::Fresh
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_is_per_second() {
        let c = PerSecondCap::new(2);
        assert!(c.try_take(10));
        assert!(c.try_take(10));
        assert!(!c.try_take(10));
        assert!(c.try_take(11), "next second has a fresh budget");
    }

    #[test]
    fn seen_fifo_refuses_replays_and_forgets_after_ttl() {
        let mut s = SeenFifo::new(120, 16);
        assert_eq!(s.insert_if_new(1u32, 1_000), SeenInsert::Fresh);
        assert_eq!(s.insert_if_new(1u32, 1_120), SeenInsert::Replay, "still within the TTL");
        assert_eq!(s.insert_if_new(1u32, 1_121), SeenInsert::Fresh, "forgotten after the TTL");
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn seen_fifo_is_fail_closed_when_full() {
        let mut s = SeenFifo::new(120, 2);
        assert_eq!(s.insert_if_new(1u32, 10), SeenInsert::Fresh);
        assert_eq!(s.insert_if_new(2u32, 10), SeenInsert::Fresh);
        assert_eq!(s.insert_if_new(3u32, 10), SeenInsert::Full);
        assert_eq!(s.insert_if_new(1u32, 10), SeenInsert::Replay);
    }

    #[test]
    fn clock_stepping_back_never_shortens_memory() {
        let mut s = SeenFifo::new(10, 16);
        assert_eq!(s.insert_if_new(1u32, 100), SeenInsert::Fresh);
        // Clock steps back 50 s: the key is recorded at 100, not 50.
        assert_eq!(s.insert_if_new(2u32, 50), SeenInsert::Fresh);
        assert_eq!(s.insert_if_new(2u32, 109), SeenInsert::Replay);
    }

    /// The property both F8 and F44 rely on: at `per_sec` admissions per
    /// second, every one of them a fresh key, a set of `capacity_for`
    /// entries never reports Full — over many TTLs, for several rates/TTLs.
    #[test]
    fn admitted_rate_times_ttl_never_fills() {
        for (per_sec, ttl) in [(1u32, 0u64), (3, 5), (50, 120), (7, 240)] {
            let cap = PerSecondCap::new(per_sec);
            let mut s = SeenFifo::new(ttl, SeenFifo::<u64>::capacity_for(per_sec, ttl));
            let mut next = 0u64;
            for sec in 1_000..1_000 + 4 * (ttl + 1) + 3 {
                // Offer twice the cap; only admitted ones reach the set.
                for _ in 0..2 * per_sec {
                    if cap.try_take(sec) {
                        assert_eq!(s.insert_if_new(next, sec), SeenInsert::Fresh, "rate {per_sec}, ttl {ttl}");
                        next += 1;
                    }
                }
                assert!(s.len() <= s.capacity());
            }
        }
    }
}
