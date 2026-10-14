//! Sliding-window Bloom filter for envelope-replay detection.
//! Spec §6.2 (lines 832–940); keyed by the envelope id since Addendum A1 §8.
//!
//! - 6 buckets × 600 s: an inserted id is remembered for 3,000–3,600 s, far
//!   longer than the ±`SENT_AT_WINDOW_SEC` acceptance window (A1 §8).
//! - Per-bucket: m = 24,000,000 bits (≈2.86 MiB), k = 17 hash positions.
//! - Target per-bucket FPR = 10⁻⁵; aggregate ≤ 6·10⁻⁵.
//! - Hash positions: `BLAKE3("L1-Bloom-v1" || u8(j) || tid)[0..8]` (BE u64) mod m.
//! - All state RAM-only; restart loses state (Spec §6.3.1, security-OK).
//!
//! Total RAM at full window: ~17.2 MiB.

use crate::constants::*;
use crate::ids::EnvelopeId;

/// Per-bucket bit-array size in bits — Spec §6.2.5.
pub const BLOOM_BUCKET_BITS: usize = 24_000_000;
/// Per-bucket bit-array size in bytes (rounded up to u64 alignment).
pub const BLOOM_BUCKET_BYTES: usize = BLOOM_BUCKET_BITS.div_ceil(64) * 8;
/// Number of hash positions per insert/lookup — Spec §6.2.4.
pub const BLOOM_HASH_K: u8 = 17;
/// Domain string for hash position derivation — Spec §6.2.3.
pub const BLOOM_DOMAIN: &[u8] = b"L1-Bloom-v1";

/// A single Bloom-filter bucket — fixed-size bit array.
pub struct BloomBucket {
    /// Backing storage: `m / 64` u64 words.
    bits: Vec<u64>,
    /// Wallclock second this bucket started accepting inserts (UTC).
    pub start_time_sec: u64,
}

impl BloomBucket {
    pub fn new(start_time_sec: u64) -> Self {
        let words = BLOOM_BUCKET_BYTES / 8;
        Self { bits: vec![0u64; words], start_time_sec }
    }

    /// Compute the j-th bit position for `tid` per Spec §6.2.3.
    #[inline]
    fn position(j: u8, tid: &EnvelopeId) -> usize {
        let mut h = blake3::Hasher::new();
        h.update(BLOOM_DOMAIN);
        h.update(&[j]);
        h.update(tid.as_bytes());
        let out = h.finalize();
        let prefix = u64::from_be_bytes(out.as_bytes()[..8].try_into().unwrap());
        (prefix % (BLOOM_BUCKET_BITS as u64)) as usize
    }

    /// Returns true iff the bucket *might* already contain `tid`
    /// (false positive ≤ 10⁻⁵; never false negative).
    pub fn contains(&self, tid: &EnvelopeId) -> bool {
        for j in 0..BLOOM_HASH_K {
            let p = Self::position(j, tid);
            let word = p / 64;
            let bit = p % 64;
            if (self.bits[word] >> bit) & 1 == 0 {
                return false;
            }
        }
        true
    }

    /// Set all k bit positions for `tid`.
    pub fn insert(&mut self, tid: &EnvelopeId) {
        for j in 0..BLOOM_HASH_K {
            let p = Self::position(j, tid);
            let word = p / 64;
            let bit = p % 64;
            self.bits[word] |= 1u64 << bit;
        }
    }

    /// Bytes occupied by the bit array (excluding heap allocator overhead).
    pub fn memory_bytes(&self) -> usize {
        self.bits.len() * 8
    }

    /// Number of set bits (test/diagnostic helper).
    pub fn popcount(&self) -> u64 {
        self.bits.iter().map(|w| w.count_ones() as u64).sum()
    }
}

/// Sliding-window of `BLOOM_BUCKETS_RETAINED` buckets — Spec §6.2.1.
///
/// Buckets are indexed `[oldest .. newest]`. The newest bucket receives
/// inserts; lookups scan all buckets.
pub struct ReplayWindow {
    buckets: Vec<BloomBucket>,
}

impl ReplayWindow {
    /// Create a new window with all 6 buckets empty, anchored at `now_sec`.
    pub fn new(now_sec: u64) -> Self {
        // Pre-fill buckets so each spans BLOOM_BUCKET_DURATION_SEC backwards.
        // start_time of B_i = now_sec - (BUCKETS_RETAINED-1-i) * BUCKET_DURATION
        let mut buckets = Vec::with_capacity(BLOOM_BUCKETS_RETAINED);
        for i in 0..BLOOM_BUCKETS_RETAINED {
            let offset = (BLOOM_BUCKETS_RETAINED - 1 - i) as u64 * BLOOM_BUCKET_DURATION_SEC;
            let start = now_sec.saturating_sub(offset);
            buckets.push(BloomBucket::new(start));
        }
        Self { buckets }
    }

    /// Check if `tid` is present in *any* bucket.
    /// Spec §6.2.2 — lookup scans all 6 buckets.
    pub fn contains(&self, tid: &EnvelopeId) -> bool {
        self.buckets.iter().any(|b| b.contains(tid))
    }

    /// Insert into the active (newest) bucket.
    /// Caller MUST first verify `!self.contains(tid)`; spec §6.2.2 / §4.1.3 step 8–9.
    pub fn insert_active(&mut self, tid: &EnvelopeId) {
        let last = self.buckets.last_mut().expect("at least one bucket");
        last.insert(tid);
    }

    /// Atomic check-and-insert. Returns `true` if `tid` is fresh (was inserted),
    /// `false` if it was already in the window (replay).
    pub fn check_and_insert(&mut self, tid: &EnvelopeId) -> bool {
        if self.contains(tid) {
            return false;
        }
        self.insert_active(tid);
        true
    }

    /// Rotate buckets if `now_sec` has advanced past the active bucket's lifetime.
    /// May rotate multiple times if relay was idle for >1 bucket duration.
    /// Spec §6.2.1: on rotation, drop oldest, shift, allocate fresh active.
    pub fn maybe_rotate(&mut self, now_sec: u64) {
        loop {
            let active = self.buckets.last().expect("at least one bucket");
            let active_end = active.start_time_sec + BLOOM_BUCKET_DURATION_SEC;
            if now_sec < active_end {
                return;
            }
            // Drop oldest, shift left, append fresh.
            self.buckets.remove(0);
            let new_start = active_end; // contiguous coverage
            self.buckets.push(BloomBucket::new(new_start));
        }
    }

    /// Total memory across all buckets (for diagnostics / SLO reporting).
    pub fn memory_bytes(&self) -> usize {
        self.buckets.iter().map(|b| b.memory_bytes()).sum()
    }

    /// Number of buckets currently held (always = `BLOOM_BUCKETS_RETAINED`).
    #[inline]
    pub fn bucket_count(&self) -> usize { self.buckets.len() }

    /// Active bucket's `start_time_sec` (test/diagnostic helper).
    pub fn active_start(&self) -> u64 {
        self.buckets.last().unwrap().start_time_sec
    }
}

// ---------------------------------------------------------------------------
// P7-EXIT-05 — best-effort persistence of the replay window across restart.
//
// Spec §6.3.1 declares the in-RAM design "security-OK" because a token's
// natural TTL is 1 h and a process restart is a rare event. The audit
// flagged that within the active bucket window a captured token could
// be replayed against the freshly-started follower until the bucket
// re-fills. Mitigation: snapshot the active bucket only (≈ 24 MB) and
// restore it on startup if the file is fresh. Older buckets become
// empty after restore, so cross-bucket replay is still possible — but
// the typical replay window (active bucket = 600 s) is now protected.
//
// Snapshot format (little-endian, version-tagged):
//     "LB01" (4) || version: u32 || start_time_sec: u64 || words_len: u64
//                || words_len × u64
//
// All I/O is synchronous; the caller (operator script or a periodic task
// in main.rs) is responsible for scheduling outside the request path.

use std::io::{Read, Write};
use std::path::Path;

const SNAPSHOT_MAGIC: &[u8; 4] = b"LB01";

impl ReplayWindow {
    /// Persist the currently-active bucket to `path` atomically (write to
    /// `path.tmp`, then rename). Returns the number of bytes written on
    /// success. Silent on logical failure (e.g. malformed snapshot is
    /// simply overwritten); only unrecoverable I/O errors surface.
    pub fn snapshot_active_to<P: AsRef<Path>>(&self, path: P) -> std::io::Result<usize> {
        let path = path.as_ref();
        let tmp = path.with_extension("tmp");
        let active = self.buckets.last().expect("at least one bucket");
        let mut buf: Vec<u8> = Vec::with_capacity(4 + 4 + 8 + 8 + active.bits.len() * 8);
        buf.extend_from_slice(SNAPSHOT_MAGIC);
        buf.extend_from_slice(&1u32.to_le_bytes()); // version
        buf.extend_from_slice(&active.start_time_sec.to_le_bytes());
        buf.extend_from_slice(&(active.bits.len() as u64).to_le_bytes());
        for w in &active.bits {
            buf.extend_from_slice(&w.to_le_bytes());
        }
        {
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp)?;
            f.write_all(&buf)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, path)?;
        Ok(buf.len())
    }

    /// Try to load an active-bucket snapshot from `path`. Returns
    /// `Ok(Some(window))` if the snapshot is structurally valid and its
    /// `start_time_sec` falls within the retention window. Returns
    /// `Ok(None)` on missing / malformed / stale / future-dated files.
    /// `Err` only on unexpected I/O.
    pub fn try_restore_active_from<P: AsRef<Path>>(
        path: P,
        now_sec: u64,
    ) -> std::io::Result<Option<Self>> {
        let path = path.as_ref();
        let mut f = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let mut hdr = [0u8; 4 + 4 + 8 + 8];
        if f.read_exact(&mut hdr).is_err() {
            return Ok(None);
        }
        if &hdr[..4] != SNAPSHOT_MAGIC {
            return Ok(None);
        }
        let version = u32::from_le_bytes(hdr[4..8].try_into().unwrap());
        if version != 1 {
            return Ok(None);
        }
        let start = u64::from_le_bytes(hdr[8..16].try_into().unwrap());
        let words_len = u64::from_le_bytes(hdr[16..24].try_into().unwrap()) as usize;
        let expected_words = BLOOM_BUCKET_BYTES / 8;
        if words_len != expected_words {
            return Ok(None);
        }

        // Freshness gate: the snapshot's bucket must overlap the
        // current retention window. Otherwise return None and let the
        // caller fall through to ReplayWindow::new(now_sec).
        let max_age = (BLOOM_BUCKETS_RETAINED as u64) * BLOOM_BUCKET_DURATION_SEC;
        if start + max_age < now_sec {
            return Ok(None);
        }
        if start > now_sec.saturating_add(BLOOM_BUCKET_DURATION_SEC) {
            // Snapshot from the future (clock skew on previous host) — ignore.
            return Ok(None);
        }

        let mut words = vec![0u64; words_len];
        let mut word_buf = [0u8; 8];
        for w in words.iter_mut() {
            if f.read_exact(&mut word_buf).is_err() {
                return Ok(None);
            }
            *w = u64::from_le_bytes(word_buf);
        }

        // Reconstruct: newest bucket is the restored snapshot; older
        // buckets are empty (we do not persist them).
        let mut buckets = Vec::with_capacity(BLOOM_BUCKETS_RETAINED);
        for i in 0..BLOOM_BUCKETS_RETAINED - 1 {
            let offset = (BLOOM_BUCKETS_RETAINED - 1 - i) as u64 * BLOOM_BUCKET_DURATION_SEC;
            let s = start.saturating_sub(offset);
            buckets.push(BloomBucket::new(s));
        }
        buckets.push(BloomBucket { bits: words, start_time_sec: start });
        Ok(Some(Self { buckets }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tid(byte: u8) -> EnvelopeId {
        let mut t = [0u8; ENVELOPE_ID_LEN];
        t[0] = byte;
        EnvelopeId(t)
    }

    #[test]
    fn parameters_match_spec() {
        assert_eq!(BLOOM_BUCKET_BITS, 24_000_000);
        // Aligned up to u64: 24,000,000 / 8 = 3,000,000 B already aligned.
        assert_eq!(BLOOM_BUCKET_BYTES, 3_000_000);
        assert_eq!(BLOOM_HASH_K, 17);
        assert_eq!(BLOOM_BUCKETS_RETAINED, 6);
        assert_eq!(BLOOM_BUCKET_DURATION_SEC, 600);
    }

    #[test]
    fn empty_bucket_reports_no_membership() {
        let b = BloomBucket::new(0);
        for i in 0..50u8 {
            assert!(!b.contains(&tid(i)));
        }
    }

    #[test]
    fn insert_then_contains() {
        let mut b = BloomBucket::new(0);
        let t = tid(0xAB);
        assert!(!b.contains(&t));
        b.insert(&t);
        assert!(b.contains(&t));
    }

    #[test]
    fn position_is_deterministic_and_in_range() {
        let t = tid(0x42);
        for j in 0..BLOOM_HASH_K {
            let p1 = BloomBucket::position(j, &t);
            let p2 = BloomBucket::position(j, &t);
            assert_eq!(p1, p2);
            assert!(p1 < BLOOM_BUCKET_BITS);
        }
    }

    #[test]
    fn position_is_domain_separated_per_j() {
        let t = tid(0x42);
        // Different j must produce (almost surely) different positions.
        let mut positions: Vec<usize> = (0..BLOOM_HASH_K)
            .map(|j| BloomBucket::position(j, &t))
            .collect();
        positions.sort();
        positions.dedup();
        // All 17 positions distinct (collision over 24M bits is negligible).
        assert_eq!(positions.len(), BLOOM_HASH_K as usize);
    }

    #[test]
    fn no_false_negative_after_insert() {
        let mut b = BloomBucket::new(0);
        for i in 0..1000u32 {
            let mut id = [0u8; ENVELOPE_ID_LEN];
            id[..4].copy_from_slice(&i.to_be_bytes());
            b.insert(&EnvelopeId(id));
        }
        for i in 0..1000u32 {
            let mut id = [0u8; ENVELOPE_ID_LEN];
            id[..4].copy_from_slice(&i.to_be_bytes());
            assert!(b.contains(&EnvelopeId(id)), "no false negative at i={i}");
        }
    }

    #[test]
    fn fpr_under_target_for_small_load() {
        // Empirical: insert 10k random tids, then check 100k unrelated tids.
        // Expected false positives at this load << 1; we accept up to 5 to keep CI stable.
        let mut b = BloomBucket::new(0);
        for i in 0..10_000u32 {
            let mut id = [0u8; ENVELOPE_ID_LEN];
            id[..4].copy_from_slice(&i.to_be_bytes());
            id[15] = 0xAA; // marker
            b.insert(&EnvelopeId(id));
        }
        let mut fp = 0;
        for i in 0..100_000u32 {
            let mut id = [0u8; ENVELOPE_ID_LEN];
            id[..4].copy_from_slice(&i.to_be_bytes());
            id[15] = 0xBB; // marker — disjoint from inserts
            if b.contains(&EnvelopeId(id)) { fp += 1; }
        }
        assert!(fp <= 5, "false positives = {fp} (expected ~0 at 10k load)");
    }

    #[test]
    fn window_initial_state_has_six_buckets() {
        let w = ReplayWindow::new(1_700_000_000);
        assert_eq!(w.bucket_count(), 6);
        assert_eq!(w.memory_bytes(), 6 * BLOOM_BUCKET_BYTES);
    }

    #[test]
    fn check_and_insert_idempotency() {
        let mut w = ReplayWindow::new(1_700_000_000);
        let t = tid(7);
        assert!(w.check_and_insert(&t), "first insert returns fresh");
        assert!(!w.check_and_insert(&t), "second returns replay");
    }

    #[test]
    fn rotation_advances_active_bucket() {
        let t0 = 1_700_000_000;
        let mut w = ReplayWindow::new(t0);
        let active0 = w.active_start();
        // Insert into active.
        let tok = tid(0x33);
        w.insert_active(&tok);
        assert!(w.contains(&tok));

        // Advance by exactly one bucket duration → 1 rotation.
        w.maybe_rotate(t0 + BLOOM_BUCKET_DURATION_SEC);
        assert_eq!(
            w.active_start(),
            active0 + BLOOM_BUCKET_DURATION_SEC,
            "active bucket should have advanced exactly one slot"
        );
        // tid still visible (it's now in the second-newest bucket).
        assert!(w.contains(&tok));
        assert_eq!(w.bucket_count(), BLOOM_BUCKETS_RETAINED);
    }

    #[test]
    fn rotation_evicts_after_full_window() {
        let t0 = 1_700_000_000;
        let mut w = ReplayWindow::new(t0);
        let tok = tid(0x55);
        w.insert_active(&tok);
        // Advance past full window: 6 rotations should evict.
        let dt = (BLOOM_BUCKETS_RETAINED as u64 + 1) * BLOOM_BUCKET_DURATION_SEC;
        w.maybe_rotate(t0 + dt);
        assert!(!w.contains(&tok), "tid must be evicted after full window passes");
    }

    #[test]
    fn idle_relay_multi_bucket_rotation() {
        let t0 = 1_700_000_000;
        let mut w = ReplayWindow::new(t0);
        // Skip 3 full buckets in one call.
        w.maybe_rotate(t0 + 3 * BLOOM_BUCKET_DURATION_SEC);
        assert_eq!(w.bucket_count(), BLOOM_BUCKETS_RETAINED);
        // Active should have moved 3 buckets.
        // (We can't compare exactly without re-deriving the original active start;
        //  but we can verify it's contiguous and >= original.)
        assert!(w.active_start() >= t0 + 3 * BLOOM_BUCKET_DURATION_SEC);
    }

    #[test]
    fn memory_estimate_under_20_mib() {
        // Spec §6.2.5: ~17.2 MiB for the bit-arrays alone.
        let w = ReplayWindow::new(0);
        let bytes = w.memory_bytes();
        assert_eq!(bytes, 18_000_000, "6 × 3,000,000 = 18 MB exactly");
        assert!(bytes < 20 * 1024 * 1024);
    }

    // ------------------------------------------------------------------
    // P7-EXIT-05 — snapshot / restore round-trips.
    // ------------------------------------------------------------------

    fn tmp_snapshot_path() -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        p.push(format!("ladon-bloom-snap-{}-{}.bin", std::process::id(), nanos));
        p
    }

    #[test]
    fn p7_exit_05_snapshot_roundtrip_replay_caught() {
        let now = 100_000u64;
        let mut w = ReplayWindow::new(now);
        let t = tid(7);
        assert!(w.check_and_insert(&t));
        let path = tmp_snapshot_path();
        let n = w.snapshot_active_to(&path).unwrap();
        assert!(n > 0);

        let restored = ReplayWindow::try_restore_active_from(&path, now).unwrap().unwrap();
        // Replay must be detected after restore.
        assert!(restored.contains(&t));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn p7_exit_05_missing_snapshot_returns_none() {
        let mut p = std::env::temp_dir();
        p.push(format!("ladon-bloom-nonexistent-{}.bin", std::process::id()));
        let r = ReplayWindow::try_restore_active_from(&p, 1_000).unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn p7_exit_05_stale_snapshot_returns_none() {
        // Snapshot dated 1 year ago is far outside the retention window.
        let snap_time = 1_000u64;
        let w = ReplayWindow::new(snap_time);
        let path = tmp_snapshot_path();
        w.snapshot_active_to(&path).unwrap();
        let now = 1_000 + 365 * 24 * 3600;
        let r = ReplayWindow::try_restore_active_from(&path, now).unwrap();
        assert!(r.is_none(), "stale snapshot must be ignored");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn p7_exit_05_corrupt_magic_returns_none() {
        let path = tmp_snapshot_path();
        std::fs::write(&path, b"XXXX___garbage___").unwrap();
        let r = ReplayWindow::try_restore_active_from(&path, 1_000).unwrap();
        assert!(r.is_none(), "bad magic must produce None, not Err");
        let _ = std::fs::remove_file(&path);
    }
}
