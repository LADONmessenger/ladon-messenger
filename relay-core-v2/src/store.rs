//! In-RAM Recipient Directory + Mailbox Queue.
//! Spec §5.2 line 609 (LRU 200k bundles) and §5.5 line 707 (mailbox drain, 1 MiB cap).
//!
//! All state is RAM-only (Spec G1, §6.3.1). Restart loses state without security
//! consequences: clients re-upload bundles on next refresh; mailbox messages are
//! lost (acceptable per spec). A sender-side resubmit on absent ACK was
//! specified but never implemented; delivery to the *recipient* is protected by
//! the acknowledged fetch (`MailboxStore::fetch_unacked`): items stay queued
//! until the recipient confirms it stored them.
//!
//! Concurrency: each public type wraps the inner state in `Mutex` to keep the
//! handler-side simple. For the Pilot deployment (5k–50k DAU per Exit) a single
//! mutex is acceptable; we re-evaluate sharding when measured contention warrants it.

use crate::constants::*;
use crate::ids::{BundleId, RecipientId};

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[inline]
fn now_sec() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ============================================================================
// Recipient Directory
// ============================================================================

/// Outcome of `RecipientDirectory::put`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectoryPutError {
    /// The submitted bundle is not newer than the stored one and differs from
    /// it. Refusing this is what prevents a captured bundle from being replayed
    /// after the recipient rotated.
    NotMonotonic,
    /// No bundle is stored for this recipient and the submitted one was
    /// published more than `DIRECTORY_FIRST_PUT_MAX_AGE_SECS` ago. Without a
    /// stored predecessor (exit restart, LRU eviction) the monotonic check
    /// has nothing to compare against, so an old bundle captured from the
    /// public GET — e.g. one from before a block rotated the delivery key —
    /// could be put back. A client always publishes a fresh one.
    Stale,
    /// F19: a new recipient at capacity, and every stored one had
    /// authenticated activity within `MAILBOX_TTL_SEC`. Nothing is evicted;
    /// the caller answers UNAVAILABLE (retryable).
    Full,
}

/// Outcome of `RecipientDirectory::check_put` when the put would succeed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectoryPutCheck {
    /// Byte-identical to the stored bundle and not newer: `put` is a no-op.
    Identical,
    /// `put` would store it.
    Fresh,
}

/// Maximum age of a bundle accepted when no bundle is stored for that
/// recipient (A1 §4 rule 4a). Clients stamp `published_at` with the
/// relay-anchored clock at publication time, so a legitimate publication is
/// seconds old; ten minutes leaves room for slow paths.
pub const DIRECTORY_FIRST_PUT_MAX_AGE_SECS: u64 = 600;

/// One entry in the directory: the published bundle bytes + metadata.
#[derive(Clone)]
pub struct DirectoryEntry {
    pub bundle_bytes: Vec<u8>,
    pub bundle_id: BundleId,
    pub published_at: u64,
    /// Monotonic counter set on authenticated activity; orders the LRU.
    /// Strictly increasing across the process; no wallclock dependency.
    last_access_seq: u64,
    /// F19: local clock (s) of the last authenticated activity — a stored
    /// bundle (put) or a verified fetch (`touch`). Decides whether the entry
    /// may be evicted for a newcomer.
    last_auth_at: u64,
}

/// In-memory recipient directory with LRU eviction at `DIRECTORY_LRU_CAPACITY`.
///
/// P7-RCV2-05 fix (2026-05-12): previously the LRU was a plain `HashMap` and
/// every eviction scanned all entries via `min_by_key` (O(N), ~200 000 work
/// per overflow insert). We now keep a secondary `BTreeMap<seq, rid>` index
/// so eviction is O(log N) and insert/get are O(log N) instead of O(1) but
/// with bounded worst-case (~17 cmp at 200 000). Net: every public op stays
/// well under 1 µs even at cap.
///
/// F19: the LRU order follows authenticated activity only — a stored bundle
/// (`put`, signature checked by the caller) and a verified fetch (`touch`).
/// Reads (DIR_GET, the delivery lookup) are open to anyone, so they no
/// longer renew an entry: otherwise a flood of reads plus new rids decided
/// who stays. At capacity the least recently active entry is evicted only
/// if that activity is more than `MAILBOX_TTL_SEC` (7 days) old; otherwise
/// the newcomer is refused (`DirectoryPutError::Full`, the exit answers
/// UNAVAILABLE). An entry inside the window keeps its bundle, so mail for
/// it can still be delivered and fetched.
pub struct RecipientDirectory {
    inner: Mutex<DirectoryInner>,
    capacity: usize,
    access_counter: AtomicU64,
}

struct DirectoryInner {
    entries: HashMap<RecipientId, DirectoryEntry>,
    /// Secondary index: ascending `last_access_seq` -> rid.
    /// Smallest entry is the LRU victim. Invariant: `lru.len() == entries.len()`.
    lru: BTreeMap<u64, RecipientId>,
}

impl RecipientDirectory {
    pub fn new() -> Self {
        Self::with_capacity(DIRECTORY_LRU_CAPACITY)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(DirectoryInner {
                entries: HashMap::with_capacity(capacity.min(64 * 1024)),
                lru: BTreeMap::new(),
            }),
            capacity: capacity.max(1),
            access_counter: AtomicU64::new(0),
        }
    }

    #[inline]
    fn next_seq(&self) -> u64 {
        self.access_counter.fetch_add(1, Ordering::Relaxed)
    }

    /// The decision `put` makes, without storing anything (F4/N4). Lets the
    /// caller tell an idempotent republish (`Identical`: no rate budget, no
    /// push replication) from a real update (`Fresh`) before it spends a
    /// recipient's budget. `put` re-runs the same decision under its lock.
    pub fn check_put(
        &self,
        rid: &RecipientId,
        published_at: u64,
        now_sec: u64,
        bundle_bytes: &[u8],
    ) -> std::result::Result<DirectoryPutCheck, DirectoryPutError> {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        self.decide(&g, rid, published_at, now_sec, bundle_bytes)
    }

    fn decide(
        &self,
        g: &DirectoryInner,
        rid: &RecipientId,
        published_at: u64,
        now_sec: u64,
        bundle_bytes: &[u8],
    ) -> std::result::Result<DirectoryPutCheck, DirectoryPutError> {
        // Anti-rollback. `published_at` was stored but never evaluated, so a
        // bundle captured from the public GET /v2/directory/:rid could be
        // re-PUT after the recipient rotated: the hsig still verifies (the
        // identity key is stable) and the older bundle won. That resets
        // `recipient_hkem_pk` to a superseded key and reinstates expired
        // tokens, giving any observer a repeatable, targeted delivery block
        // against a named recipient.
        //
        // Includes the `.min(now_sec)`
        // cap: a stored future timestamp must not be able to lock out later
        // legitimate publications.
        if let Some(existing) = g.entries.get(rid) {
            let effective_prev = existing.published_at.min(now_sec);
            if published_at <= effective_prev {
                // A byte-identical republish is idempotent, not an attack —
                // clients retry, and a retry must not fail.
                if existing.bundle_bytes == bundle_bytes {
                    return Ok(DirectoryPutCheck::Identical);
                }
                return Err(DirectoryPutError::NotMonotonic);
            }
        } else {
            if now_sec.saturating_sub(published_at) > DIRECTORY_FIRST_PUT_MAX_AGE_SECS {
                return Err(DirectoryPutError::Stale);
            }
            // F19: a newcomer at capacity only displaces an entry whose last
            // authenticated activity is older than MAILBOX_TTL_SEC.
            if g.entries.len() >= self.capacity && Self::lru_victim(g, now_sec).is_none() {
                return Err(DirectoryPutError::Full);
            }
        }
        Ok(DirectoryPutCheck::Fresh)
    }

    /// The least recently active entry, if it may be evicted at `now_sec`.
    fn lru_victim(g: &DirectoryInner, now_sec: u64) -> Option<(u64, RecipientId)> {
        let (&seq, &rid) = g.lru.iter().next()?;
        let last = g.entries.get(&rid)?.last_auth_at;
        (now_sec.saturating_sub(last) > MAILBOX_TTL_SEC).then_some((seq, rid))
    }

    /// Store/replace the bundle for `rid` (an authenticated activity: the
    /// caller checked the signature). At capacity a newcomer evicts the
    /// least recently active entry if that is older than `MAILBOX_TTL_SEC`,
    /// and is refused with `Full` otherwise (F19).
    /// `bundle_bytes` MUST already be structurally validated by the caller.
    pub fn put(
        &self,
        rid: RecipientId,
        bundle_id: BundleId,
        published_at: u64,
        now_sec: u64,
        bundle_bytes: Vec<u8>,
    ) -> std::result::Result<(), DirectoryPutError> {
        let seq = self.next_seq();
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        // An identical republish can be anyone's replay of the public
        // bundle: no-op, and no renewal of the entry.
        if self.decide(&g, &rid, published_at, now_sec, &bundle_bytes)?
            == DirectoryPutCheck::Identical
        {
            return Ok(());
        }

        // Remove the stale LRU index entry if this rid already exists.
        let old_seq = g.entries.get(&rid).map(|e| e.last_access_seq);
        if let Some(s) = old_seq {
            g.lru.remove(&s);
        } else if g.entries.len() >= self.capacity {
            // `decide` refused unless a victim is evictable. O(log N).
            let (victim_seq, victim_rid) =
                Self::lru_victim(&g, now_sec).ok_or(DirectoryPutError::Full)?;
            g.lru.remove(&victim_seq);
            g.entries.remove(&victim_rid);
        }
        let entry = DirectoryEntry {
            bundle_bytes, bundle_id, published_at,
            last_access_seq: seq,
            last_auth_at: now_sec,
        };
        g.entries.insert(rid, entry);
        g.lru.insert(seq, rid);
        debug_assert_eq!(g.entries.len(), g.lru.len());
        Ok(())
    }

    /// F19: record an authenticated activity of `rid` other than a put — a
    /// fetch whose signature verified. Renews its LRU position and its
    /// activity time. No-op for an unknown rid.
    pub fn touch(&self, rid: &RecipientId, now_sec: u64) {
        let seq = self.next_seq();
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(old_seq) = g.entries.get(rid).map(|e| e.last_access_seq) else {
            return;
        };
        g.lru.remove(&old_seq);
        g.lru.insert(seq, *rid);
        let e = g.entries.get_mut(rid).expect("present by lookup above");
        e.last_access_seq = seq;
        e.last_auth_at = e.last_auth_at.max(now_sec);
    }

    /// Fetch bundle bytes for `rid`. A read only: anyone can read any rid,
    /// so it does not renew the entry (F19).
    pub fn get(&self, rid: &RecipientId) -> Option<Vec<u8>> {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.entries.get(rid).map(|e| e.bundle_bytes.clone())
    }

    /// Test/diagnostic helper.
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).entries.len()
    }

    /// Test/diagnostic helper.
    pub fn is_empty(&self) -> bool {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).entries.is_empty()
    }

    /// Maximum number of entries (F1 audit 14.10.: the exit logs the fill
    /// level against it so monitoring can alarm on a flood of identities).
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Test/diagnostic helper.
    pub fn contains(&self, rid: &RecipientId) -> bool {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).entries.contains_key(rid)
    }
}

impl Default for RecipientDirectory {
    fn default() -> Self { Self::new() }
}

// ============================================================================
// Mailbox Queue
// ============================================================================

/// One queued message waiting to be fetched.
#[derive(Clone, Debug)]
pub struct MailboxItem {
    pub inner_envelope: Vec<u8>,
    pub enqueued_at_sec: u64,
    /// Position in the store-wide enqueue order, strictly increasing. An
    /// acknowledgement deletes by sequence number, not by count, so items that
    /// TTL eviction or a legacy drain removed in between can never shift what
    /// an ack covers onto items the client has not received.
    pub seq: u64,
}

/// The batch an acknowledged fetch last handed out for one recipient.
struct PendingBatch {
    id: [u8; FETCH_BATCH_ID_LEN],
    /// Highest `MailboxItem::seq` in the batch; an ack deletes up to here.
    last_seq: u64,
}

/// Per-recipient FIFO queue + global TTL eviction.
///
/// Spec §5.5: drain on fetch (cap 1 MiB), preserve until MAILBOX_TTL.
/// Spec §5.5: messages dropped on client decryption-failure are lost by design.
pub struct MailboxStore {
    inner: Mutex<MailboxInner>,
    ttl_sec: u64,
    fetch_cap_bytes: usize,
    /// P7-RELAY-12: maximum queued envelopes per recipient. Prevents a single
    /// offline recipient (or attacker spamming a specific rid) from growing
    /// the mailbox heap without bound. ~1024 inner envelopes ≈ 16 MiB worst
    /// case for a 16 KiB envelope (much smaller in practice since inner
    /// envelopes are typically ~5 KiB once the outer 16 KiB padding is gone).
    per_queue_cap: usize,
    /// F3/F5: maximum envelope bytes queued across all recipients. The
    /// per-recipient cap alone bounds one queue, not their number, so many
    /// recipients together could still exhaust the exit's memory.
    global_cap_bytes: u64,
}

struct MailboxInner {
    queues: HashMap<RecipientId, VecDeque<MailboxItem>>,
    /// At most one outstanding batch per recipient (`fetch_unacked`). Only
    /// present while that recipient's queue is non-empty.
    pending: HashMap<RecipientId, PendingBatch>,
    next_seq: u64,
    /// F3/F5: Σ `inner_envelope.len()` over every queued item. Every push and
    /// every pop goes through `push_counted` / `pop_counted`.
    total_bytes: u64,
}

/// Append `item` to `q` and add its bytes to `total`.
fn push_counted(q: &mut VecDeque<MailboxItem>, total: &mut u64, item: MailboxItem) {
    *total += item.inner_envelope.len() as u64;
    q.push_back(item);
}

/// Pop the front of `q` and take its bytes off `total`.
fn pop_counted(q: &mut VecDeque<MailboxItem>, total: &mut u64) -> Option<MailboxItem> {
    let it = q.pop_front()?;
    *total -= it.inner_envelope.len() as u64;
    Some(it)
}

/// Pop every item at the front of `q` older than `ttl_sec`; returns how many.
fn expire_front(q: &mut VecDeque<MailboxItem>, total: &mut u64, now: u64, ttl_sec: u64) -> usize {
    let mut n = 0;
    while q.front().is_some_and(|f| now.saturating_sub(f.enqueued_at_sec) > ttl_sec) {
        pop_counted(q, total);
        n += 1;
    }
    n
}

/// P7-RELAY-12: enqueue outcome. `Full` indicates the per-recipient queue is
/// at capacity; callers should surface a retryable error (HTTP 503 / "later")
/// rather than silently dropping the envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailboxEnqueueError {
    /// The recipient's queue is at `per_queue_cap`, or (F3/F5) the store is
    /// at `global_cap_bytes`. The envelope was NOT stored. The sender's
    /// retry policy decides whether to back off.
    Full,
}

/// Default cap on per-recipient queued envelopes (P7-RELAY-12).
pub const DEFAULT_MAILBOX_PER_QUEUE_CAP: usize = 1024;

/// F3/F5: default cap on envelope bytes queued across all recipients:
/// 4 GiB, half of the 8 GiB the exit container (CT 105) has. The exit
/// overrides it with `LADON_MAILBOX_CAP_BYTES`. Counted are the envelope
/// bytes; per-item bookkeeping (Vec header, timestamps, sequence number,
/// queue slack) adds well under 1 % at the fixed sealed envelope size.
pub const DEFAULT_MAILBOX_GLOBAL_CAP_BYTES: u64 = 4 * 1024 * 1024 * 1024;

impl MailboxStore {
    pub fn new() -> Self {
        Self::with_params(MAILBOX_TTL_SEC, FETCH_RESPONSE_MAX_BYTES)
    }

    pub fn with_params(ttl_sec: u64, fetch_cap_bytes: usize) -> Self {
        Self {
            inner: Mutex::new(MailboxInner {
                queues: HashMap::new(),
                pending: HashMap::new(),
                next_seq: 0,
                total_bytes: 0,
            }),
            ttl_sec, fetch_cap_bytes,
            per_queue_cap: DEFAULT_MAILBOX_PER_QUEUE_CAP,
            global_cap_bytes: DEFAULT_MAILBOX_GLOBAL_CAP_BYTES,
        }
    }

    /// Override the per-recipient queue cap. Mostly useful for tests that
    /// exercise the saturate-and-shed path.
    pub fn with_per_queue_cap(mut self, cap: usize) -> Self {
        self.per_queue_cap = cap.max(1);
        self
    }

    /// F3/F5: override the cap on envelope bytes across all recipients.
    pub fn with_global_cap_bytes(mut self, cap: u64) -> Self {
        self.global_cap_bytes = cap;
        self
    }

    /// Envelope bytes currently queued across all recipients.
    pub fn total_bytes(&self) -> u64 {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).total_bytes
    }

    /// Append `inner_envelope` to recipient's queue.
    ///
    /// Returns `Err(MailboxEnqueueError::Full)` if the recipient is already at
    /// `per_queue_cap`, or if the envelope would take the store past
    /// `global_cap_bytes` (F3/F5). P7-RELAY-12: prefers shed-to-error over
    /// unbounded growth so neither one offline (or attacker-targeted)
    /// recipient nor many of them together can exhaust process memory.
    pub fn enqueue(&self, rid: RecipientId, inner_envelope: Vec<u8>) -> Result<(), MailboxEnqueueError> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let MailboxInner { queues, next_seq, total_bytes, .. } = &mut *g;
        // Checked before `entry`, so a refusal leaves no empty queue behind.
        if total_bytes.saturating_add(inner_envelope.len() as u64) > self.global_cap_bytes {
            return Err(MailboxEnqueueError::Full);
        }
        let seq = *next_seq;
        let q = queues.entry(rid).or_default();
        if q.len() >= self.per_queue_cap {
            return Err(MailboxEnqueueError::Full);
        }
        let item = MailboxItem { inner_envelope, enqueued_at_sec: now_sec(), seq };
        push_counted(q, total_bytes, item);
        *next_seq = seq + 1;
        Ok(())
    }

    /// Fetch and remove up to `fetch_cap_bytes` worth of envelopes for `rid`.
    /// Spec §5.5 line 726: deletion happens *after* the response is built; here
    /// we model that by removing from the queue when items are returned. The
    /// HTTP-FIN-after-deletion semantic is the caller's concern.
    /// Returns the drained items and a `has_more` flag for cursor pagination.
    pub fn drain(&self, rid: &RecipientId) -> DrainResult {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let now = now_sec();
        let MailboxInner { queues, pending, total_bytes, .. } = &mut *g;
        let q = match queues.get_mut(rid) {
            Some(q) => q,
            None => return DrainResult { items: Vec::new(), has_more: false },
        };
        // Apply TTL eviction first.
        expire_front(q, total_bytes, now, self.ttl_sec);
        let mut delivered = Vec::new();
        let mut out_bytes: usize = 0;
        // Each record is 4-byte length prefix + envelope (Spec §4.6 line 527).
        while let Some(front) = q.front() {
            let entry_size = 4 + front.inner_envelope.len();
            if out_bytes + entry_size > self.fetch_cap_bytes {
                break;
            }
            out_bytes += entry_size;
            delivered.push(pop_counted(q, total_bytes).expect("front exists"));
        }
        let has_more = !q.is_empty();
        // Clean up empty queue.
        if q.is_empty() {
            queues.remove(rid);
        }
        // A legacy drain removes items outright; an outstanding batch of an
        // acknowledged fetch no longer describes the queue. (Its ack would be
        // harmless — it deletes by sequence — but must not linger.)
        pending.remove(rid);
        DrainResult { items: delivered, has_more }
    }

    /// Acknowledged fetch: hand out up to `fetch_cap_bytes` of envelopes for
    /// `rid` WITHOUT deleting them, and delete only what the client confirms.
    ///
    /// `ack` is the batch id the client received last time and has stored
    /// (`None` = nothing to acknowledge). If it matches the outstanding batch,
    /// those items — and only those — are deleted first. Anything not
    /// acknowledged is handed out again: a response lost on the way (Tor
    /// circuit drop, cancelled request, killed app) loses no message. The
    /// client's ratchet rejects a second copy of a message it already opened,
    /// so a re-delivery never shows twice.
    ///
    /// `new_batch_id` must be fresh randomness from the caller (the exit). It
    /// becomes the outstanding batch if anything is handed out; with an empty
    /// queue there is no batch and nothing to acknowledge.
    ///
    /// A mismatching ack (stale, from a racing fetch, or forged) deletes
    /// nothing. The comparison is constant-time.
    pub fn fetch_unacked(
        &self,
        rid: &RecipientId,
        ack: Option<&[u8; FETCH_BATCH_ID_LEN]>,
        new_batch_id: [u8; FETCH_BATCH_ID_LEN],
    ) -> UnackedFetch {
        self.fetch_unacked_limited(rid, ack, new_batch_id, usize::MAX)
    }

    /// `fetch_unacked` handing out at most `max_items` (A2 §5: the sealed
    /// lane-F response carries one inner envelope, so a fetch never reveals
    /// how many are waiting).
    pub fn fetch_unacked_limited(
        &self,
        rid: &RecipientId,
        ack: Option<&[u8; FETCH_BATCH_ID_LEN]>,
        new_batch_id: [u8; FETCH_BATCH_ID_LEN],
        max_items: usize,
    ) -> UnackedFetch {
        use subtle::ConstantTimeEq;

        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let now = now_sec();
        let MailboxInner { queues, pending, total_bytes, .. } = &mut *g;

        // 1. Acknowledgement: delete exactly the confirmed batch.
        if let Some(ack) = ack {
            let confirmed = pending.get(rid)
                .filter(|p| bool::from(p.id.ct_eq(ack)))
                .map(|p| p.last_seq);
            if let Some(last_seq) = confirmed {
                pending.remove(rid);
                if let Some(q) = queues.get_mut(rid) {
                    while q.front().is_some_and(|f| f.seq <= last_seq) {
                        pop_counted(q, total_bytes);
                    }
                }
            }
        }

        let Some(q) = queues.get_mut(rid) else {
            pending.remove(rid);
            return UnackedFetch { items: Vec::new(), batch_id: None, has_more: false };
        };

        // 2. TTL eviction, as in `drain`.
        expire_front(q, total_bytes, now, self.ttl_sec);

        // 3. Hand out from the front without removing.
        let mut items = Vec::new();
        let mut out_bytes: usize = 0;
        // Each record is 4-byte length prefix + envelope (Spec §4.6 line 527).
        for it in q.iter().take(max_items) {
            let entry_size = 4 + it.inner_envelope.len();
            if out_bytes + entry_size > self.fetch_cap_bytes {
                break;
            }
            out_bytes += entry_size;
            items.push(it.clone());
        }
        let has_more = q.len() > items.len();
        let queue_empty = q.is_empty();

        let batch_id = match items.last() {
            Some(last) => {
                pending.insert(*rid, PendingBatch { id: new_batch_id, last_seq: last.seq });
                Some(new_batch_id)
            }
            None => {
                pending.remove(rid);
                None
            }
        };
        if queue_empty {
            queues.remove(rid);
        }
        UnackedFetch { items, batch_id, has_more }
    }

    /// Test/diagnostic helper: queue depth for `rid`.
    pub fn depth(&self, rid: &RecipientId) -> usize {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.queues.get(rid).map(|q| q.len()).unwrap_or(0)
    }

    /// Sweep expired items across all queues. Call periodically (e.g. every minute).
    /// Returns the number of items evicted.
    ///
    /// P7-RCV2-06: this method holds the global `MailboxStore` mutex for the
    /// entire duration of the sweep. With current capacity (≤ 64 K queues) a
    /// full sweep is microseconds and acceptable. Operators with much larger
    /// fleets should call [`Self::sweep_expired_chunked`] instead, which
    /// yields the lock every `max_rids` queues so that concurrent
    /// enqueue/drain operations can interleave.
    pub fn sweep_expired(&self) -> usize {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let now = now_sec();
        let MailboxInner { queues, pending, total_bytes, .. } = &mut *g;
        let mut evicted = 0usize;
        let empty: Vec<RecipientId> = queues.iter_mut()
            .filter_map(|(rid, q)| {
                evicted += expire_front(q, total_bytes, now, self.ttl_sec);
                if q.is_empty() { Some(*rid) } else { None }
            })
            .collect();
        for rid in empty {
            queues.remove(&rid);
            pending.remove(&rid);
        }
        evicted
    }

    /// P7-RCV2-06: chunked variant of [`Self::sweep_expired`].
    ///
    /// Snapshots the current rid set under a brief lock, then processes the
    /// snapshot in chunks of `max_rids` queues per locked critical section,
    /// dropping the mutex between chunks so other callers can make progress.
    /// Returns the total number of items evicted. A `max_rids` of 0 falls
    /// back to a single-shot sweep (same semantics as `sweep_expired`).
    ///
    /// Queues created *after* the snapshot are not visited this round — they
    /// have not yet had time to accumulate expired items and will be picked
    /// up on the next periodic call.
    pub fn sweep_expired_chunked(&self, max_rids: usize) -> usize {
        if max_rids == 0 {
            return self.sweep_expired();
        }
        // Snapshot rid set under a brief lock.
        let rids: Vec<RecipientId> = {
            let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            g.queues.keys().copied().collect()
        };
        let mut total = 0usize;
        for chunk in rids.chunks(max_rids) {
            let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            let now = now_sec();
            let MailboxInner { queues, pending, total_bytes, .. } = &mut *g;
            let mut empty: Vec<RecipientId> = Vec::new();
            for rid in chunk {
                if let Some(q) = queues.get_mut(rid) {
                    total += expire_front(q, total_bytes, now, self.ttl_sec);
                    if q.is_empty() { empty.push(*rid); }
                }
            }
            for rid in &empty {
                queues.remove(rid);
                pending.remove(rid);
            }
            drop(g);
            std::thread::yield_now();
        }
        total
    }
}

impl Default for MailboxStore {
    fn default() -> Self { Self::new() }
}

/// Result of [`MailboxStore::fetch_unacked`].
#[derive(Debug)]
pub struct UnackedFetch {
    /// Copies of the handed-out items; they stay queued until acknowledged.
    pub items: Vec<MailboxItem>,
    /// Id the client must echo as its ack once it has stored `items`.
    /// `None` iff `items` is empty.
    pub batch_id: Option<[u8; FETCH_BATCH_ID_LEN]>,
    /// True iff the queue holds more than this batch.
    pub has_more: bool,
}

#[derive(Debug)]
pub struct DrainResult {
    pub items: Vec<MailboxItem>,
    /// True iff the queue still holds items the caller did not receive
    /// (cap exceeded). Client should re-fetch with cursor.
    pub has_more: bool,
}

#[cfg(test)]
mod tests {
    /// Wallclock stand-in for the anti-rollback check: larger than every
    /// `published_at` used below, so `.min(now_sec)` never masks a case.
    const NOW: u64 = 1_000_000;
    /// A publication time `t` seconds into a window ending shortly before
    /// NOW: keeps the tests' relative order while every first PUT stays
    /// inside DIRECTORY_FIRST_PUT_MAX_AGE_SECS.
    fn at(t: u64) -> u64 { NOW - 300 + t }

    use super::*;

    fn rid(b: u8) -> RecipientId {
        let mut a = [0u8; 32]; a[0] = b; RecipientId(a)
    }
    fn bid(b: u8) -> BundleId {
        let mut a = [0u8; 16]; a[0] = b; BundleId(a)
    }

    // ---- Directory tests ---------------------------------------------------

    #[test]
    fn directory_put_and_get() {
        let d = RecipientDirectory::new();
        let r = rid(1);
        assert!(d.get(&r).is_none());
        d.put(r, bid(1), at(100), NOW, vec![1, 2, 3]).unwrap();
        assert_eq!(d.get(&r), Some(vec![1, 2, 3]));
    }

    #[test]
    fn directory_rejects_rollback_to_older_bundle() {
        // The attack: capture a bundle from the public GET, wait for the
        // recipient to rotate, then re-PUT the captured one. The hsig still
        // verifies because the identity key is stable, so only freshness can
        // stop it.
        let d = RecipientDirectory::new();
        let r = rid(7);
        d.put(r, bid(1), at(100), NOW, vec![b'o', b'l', b'd']).unwrap();
        d.put(r, bid(2), at(200), NOW, vec![b'n', b'e', b'w']).unwrap();

        assert_eq!(
            d.put(r, bid(1), at(100), NOW, vec![b'o', b'l', b'd']),
            Err(DirectoryPutError::NotMonotonic),
            "replaying the captured older bundle must be refused"
        );
        assert_eq!(d.get(&r), Some(b"new".to_vec()), "stored bundle unchanged");

        // Equal timestamp with different bytes is also a rollback attempt.
        assert_eq!(
            d.put(r, bid(3), at(200), NOW, vec![b'x']),
            Err(DirectoryPutError::NotMonotonic)
        );
        assert_eq!(d.get(&r), Some(b"new".to_vec()));
    }

    #[test]
    fn directory_identical_republish_is_idempotent() {
        // Clients retry. A byte-identical republish is not an attack and must
        // not fail, even though it is not strictly newer.
        let d = RecipientDirectory::new();
        let r = rid(8);
        d.put(r, bid(1), at(100), NOW, vec![1, 2, 3]).unwrap();
        d.put(r, bid(1), at(100), NOW, vec![1, 2, 3])
            .expect("identical republish must succeed");
        assert_eq!(d.get(&r), Some(vec![1, 2, 3]));
    }

    /// F4/N4: check_put makes exactly put's decision and stores nothing.
    #[test]
    fn directory_check_put_matches_put_and_stores_nothing() {
        let d = RecipientDirectory::new();
        let r = rid(12);
        assert_eq!(d.check_put(&r, at(100), NOW, &[1]), Ok(DirectoryPutCheck::Fresh));
        assert_eq!(d.get(&r), None, "check_put stores nothing");
        assert_eq!(
            d.check_put(&r, NOW - DIRECTORY_FIRST_PUT_MAX_AGE_SECS - 1, NOW, &[1]),
            Err(DirectoryPutError::Stale)
        );
        d.put(r, bid(1), at(100), NOW, vec![1]).unwrap();
        assert_eq!(d.check_put(&r, at(100), NOW, &[1]), Ok(DirectoryPutCheck::Identical));
        assert_eq!(d.check_put(&r, at(100), NOW, &[2]), Err(DirectoryPutError::NotMonotonic));
        assert_eq!(d.check_put(&r, at(99), NOW, &[1]), Ok(DirectoryPutCheck::Identical), "older, same bytes");
        assert_eq!(d.check_put(&r, at(101), NOW, &[1]), Ok(DirectoryPutCheck::Fresh));
    }

    #[test]
    fn directory_refuses_old_bundle_without_stored_predecessor() {
        // After an exit restart (or LRU eviction) nothing is stored for the
        // recipient. A bundle captured from the public GET long ago — e.g.
        // before a block rotated the delivery key — must not be accepted.
        let d = RecipientDirectory::new();
        let r = rid(9);
        assert_eq!(
            d.put(r, bid(1), NOW - DIRECTORY_FIRST_PUT_MAX_AGE_SECS - 1, NOW, vec![b'o', b'l', b'd']),
            Err(DirectoryPutError::Stale)
        );
        assert_eq!(d.get(&r), None, "nothing stored");
        // Exactly at the limit, and a fresh one, are accepted.
        d.put(r, bid(2), NOW - DIRECTORY_FIRST_PUT_MAX_AGE_SECS, NOW, vec![b'e', b'd', b'g', b'e'])
            .expect("a bundle exactly at the limit is accepted");
        let r2 = rid(10);
        d.put(r2, bid(3), NOW, NOW, vec![b'n', b'e', b'w'])
            .expect("a fresh bundle is accepted");
    }

    #[test]
    fn directory_age_limit_applies_only_without_predecessor() {
        // With a stored bundle the monotonic rule decides, not the age: a
        // recipient whose last publication is old can still be superseded by
        // a newer one that is itself older than the first-PUT window.
        let d = RecipientDirectory::new();
        let r = rid(11);
        d.put(r, bid(1), NOW, NOW, vec![1]).unwrap();
        let later = NOW + 10_000;
        d.put(r, bid(2), NOW + 1, later, vec![2])
            .expect("newer than stored is accepted regardless of age");
        assert_eq!(d.get(&r), Some(vec![2]));
    }

    #[test]
    fn directory_future_timestamp_cannot_lock_out_later_publications() {
        // Without the `.min(now_sec)` cap a bundle dated far in the future
        // would block every later legitimate publication for as long as that
        // date stands. now_sec caps what the stored value can veto.
        let d = RecipientDirectory::new();
        let r = rid(9);
        let now = 1_000u64;
        d.put(r, bid(1), 999_999, now, vec![b'f', b'u', b't']).unwrap();
        d.put(r, bid(2), now + 1, now, vec![b'o', b'k'])
            .expect("a present-dated bundle must still be accepted");
        assert_eq!(d.get(&r), Some(b"ok".to_vec()));
    }

    #[test]
    fn directory_overwrite_replaces_bundle() {
        let d = RecipientDirectory::new();
        let r = rid(2);
        d.put(r, bid(1), at(100), NOW, vec![1, 1, 1]).unwrap();
        d.put(r, bid(2), at(200), NOW, vec![2, 2, 2]).unwrap();
        assert_eq!(d.get(&r), Some(vec![2, 2, 2]));
        assert_eq!(d.len(), 1);
    }

    /// F19: the LRU follows authenticated activity (a verified fetch =
    /// `touch`), and a newcomer evicts only once the least recently active
    /// entry is older than MAILBOX_TTL_SEC. (Before F19 a plain `get` renewed
    /// and eviction happened at any age.)
    #[test]
    fn directory_lru_eviction_at_capacity() {
        let d = RecipientDirectory::with_capacity(3);
        d.put(rid(1), bid(1), at(1), NOW, vec![1]).unwrap();
        d.put(rid(2), bid(2), at(2), NOW, vec![2]).unwrap();
        d.put(rid(3), bid(3), at(3), NOW, vec![3]).unwrap();
        let later = NOW + MAILBOX_TTL_SEC + 1;
        // rid(1) fetched (verified) just now: most recently active.
        d.touch(&rid(1), later);
        // Insert 4th — evicts rid(2) (oldest activity, older than the TTL).
        d.put(rid(4), bid(4), later, later, vec![4]).unwrap();
        assert_eq!(d.len(), 3);
        assert!(d.contains(&rid(1)), "rid(1) was just touched");
        assert!(d.contains(&rid(3)));
        assert!(d.contains(&rid(4)));
        assert!(!d.contains(&rid(2)), "rid(2) was oldest, must be evicted");
    }

    /// F19: reads (DIR_GET, deliver lookups) are unauthenticated — anyone
    /// can read any rid — so they must not decide who stays. A flood of new
    /// recipients cannot push out one that was active within
    /// MAILBOX_TTL_SEC; the newcomer is refused instead.
    #[test]
    fn directory_active_entry_survives_a_flood() {
        let d = RecipientDirectory::with_capacity(2);
        d.put(rid(1), bid(1), at(1), NOW, vec![1]).unwrap();
        d.put(rid(2), bid(2), at(2), NOW, vec![2]).unwrap();
        for i in 3..50u8 {
            assert!(d.put(rid(i), bid(i), at(3), NOW + 60, vec![i]).is_err(), "newcomer {i} refused");
        }
        assert!(d.contains(&rid(1)) && d.contains(&rid(2)), "active entries stay");
        assert_eq!(d.len(), 2);
    }

    /// F19: a read does not count as activity. After the inactivity limit
    /// the entry that was only read is the one evicted.
    #[test]
    fn directory_reads_do_not_renew() {
        let d = RecipientDirectory::with_capacity(2);
        d.put(rid(1), bid(1), at(1), NOW, vec![1]).unwrap();
        d.put(rid(2), bid(2), at(2), NOW, vec![2]).unwrap();
        for _ in 0..10 {
            let _ = d.get(&rid(1));
        }
        let later = NOW + MAILBOX_TTL_SEC + 1;
        d.put(rid(3), bid(3), later, later, vec![3]).unwrap();
        assert!(!d.contains(&rid(1)), "only read, so the oldest activity: evicted");
        assert!(d.contains(&rid(2)));
        assert!(d.contains(&rid(3)));
    }

    /// F19: a verified fetch (`touch`) keeps an entry whose bundle is old:
    /// a recipient that only fetches and never republishes stays.
    #[test]
    fn directory_verified_fetch_keeps_the_entry() {
        let d = RecipientDirectory::with_capacity(1);
        d.put(rid(1), bid(1), at(1), NOW, vec![1]).unwrap();
        let later = NOW + MAILBOX_TTL_SEC + 1;
        d.touch(&rid(1), later - 60);
        assert_eq!(d.put(rid(2), bid(2), later, later, vec![2]), Err(DirectoryPutError::Full));
        assert!(d.contains(&rid(1)));
        d.touch(&rid(9), later); // unknown rid: no-op
        assert_eq!(d.len(), 1);
    }

    #[test]
    fn directory_below_capacity_no_eviction() {
        let d = RecipientDirectory::with_capacity(10);
        for i in 0..5u8 {
            d.put(rid(i), bid(i), at(i as u64), NOW, vec![i]).unwrap();
        }
        assert_eq!(d.len(), 5);
    }

    // ---- Mailbox tests -----------------------------------------------------

    #[test]
    fn mailbox_enqueue_drain_fifo() {
        let m = MailboxStore::new();
        let r = rid(7);
        m.enqueue(r, vec![1; 100]).unwrap();
        m.enqueue(r, vec![2; 100]).unwrap();
        m.enqueue(r, vec![3; 100]).unwrap();
        let res = m.drain(&r);
        assert_eq!(res.items.len(), 3);
        assert_eq!(res.items[0].inner_envelope[0], 1);
        assert_eq!(res.items[1].inner_envelope[0], 2);
        assert_eq!(res.items[2].inner_envelope[0], 3);
        assert!(!res.has_more);
        assert_eq!(m.depth(&r), 0);
    }

    #[test]
    fn mailbox_drain_respects_byte_cap() {
        // Cap 1000 B, each envelope = 400 B + 4 prefix → 2 fit, third overflows.
        let m = MailboxStore::with_params(MAILBOX_TTL_SEC, 1000);
        let r = rid(8);
        m.enqueue(r, vec![0u8; 400]).unwrap();
        m.enqueue(r, vec![0u8; 400]).unwrap();
        m.enqueue(r, vec![0u8; 400]).unwrap();
        let res = m.drain(&r);
        assert_eq!(res.items.len(), 2, "404+404=808 fits, +404=1212 exceeds");
        assert!(res.has_more);
        assert_eq!(m.depth(&r), 1);
        // Next drain takes the third.
        let res2 = m.drain(&r);
        assert_eq!(res2.items.len(), 1);
        assert!(!res2.has_more);
    }

    #[test]
    fn mailbox_isolated_per_recipient() {
        let m = MailboxStore::new();
        m.enqueue(rid(1), vec![0xAA]).unwrap();
        m.enqueue(rid(2), vec![0xBB]).unwrap();
        let r1 = m.drain(&rid(1));
        assert_eq!(r1.items.len(), 1);
        assert_eq!(r1.items[0].inner_envelope, vec![0xAA]);
        // rid(2)'s queue untouched.
        assert_eq!(m.depth(&rid(2)), 1);
    }

    #[test]
    fn mailbox_drain_empty_returns_empty() {
        let m = MailboxStore::new();
        let res = m.drain(&rid(99));
        assert_eq!(res.items.len(), 0);
        assert!(!res.has_more);
    }

    #[test]
    fn mailbox_ttl_expiry_removes_old_items() {
        // ttl = 0 s → every enqueued item is "expired" on next drain.
        let m = MailboxStore::with_params(0, FETCH_RESPONSE_MAX_BYTES);
        m.enqueue(rid(1), vec![1, 2, 3]).unwrap();
        // Force timestamp into past.
        {
            let mut g = m.inner.lock().unwrap();
            for q in g.queues.values_mut() {
                for it in q.iter_mut() { it.enqueued_at_sec = 0; }
            }
        }
        let res = m.drain(&rid(1));
        assert_eq!(res.items.len(), 0, "TTL=0 must drop all aged items");
    }

    #[test]
    fn mailbox_sweep_evicts_expired() {
        let m = MailboxStore::with_params(0, FETCH_RESPONSE_MAX_BYTES);
        m.enqueue(rid(1), vec![1]).unwrap();
        m.enqueue(rid(2), vec![2]).unwrap();
        // Backdate.
        {
            let mut g = m.inner.lock().unwrap();
            for q in g.queues.values_mut() {
                for it in q.iter_mut() { it.enqueued_at_sec = 0; }
            }
        }
        let evicted = m.sweep_expired();
        assert_eq!(evicted, 2);
        assert_eq!(m.depth(&rid(1)), 0);
        assert_eq!(m.depth(&rid(2)), 0);
    }

    // ---- Acknowledged fetch (fetch_unacked) --------------------------------

    fn batch(b: u8) -> [u8; FETCH_BATCH_ID_LEN] {
        [b; FETCH_BATCH_ID_LEN]
    }

    fn envelopes(f: &UnackedFetch) -> Vec<u8> {
        f.items.iter().map(|it| it.inner_envelope[0]).collect()
    }

    fn backdate_all(m: &MailboxStore) {
        let mut g = m.inner.lock().unwrap();
        for q in g.queues.values_mut() {
            for it in q.iter_mut() { it.enqueued_at_sec = 0; }
        }
    }

    #[test]
    fn limited_fetch_hands_out_one_at_a_time() {
        // A2 §5: the sealed fetch carries one inner envelope per response.
        let m = MailboxStore::new();
        let r = rid(7);
        for v in 1..=3u8 {
            m.enqueue(r, vec![v; 10]).unwrap();
        }
        let f1 = m.fetch_unacked_limited(&r, None, batch(0xD1), 1);
        assert_eq!(envelopes(&f1), vec![1]);
        assert!(f1.has_more);
        // Unacknowledged: the same item again under a new batch id.
        let f2 = m.fetch_unacked_limited(&r, None, batch(0xD2), 1);
        assert_eq!(envelopes(&f2), vec![1]);
        // Acknowledging the current batch moves on to the next item.
        let f3 = m.fetch_unacked_limited(&r, Some(&batch(0xD2)), batch(0xD3), 1);
        assert_eq!(envelopes(&f3), vec![2]);
        let f4 = m.fetch_unacked_limited(&r, Some(&batch(0xD3)), batch(0xD4), 1);
        assert_eq!(envelopes(&f4), vec![3]);
        assert!(!f4.has_more);
        let f5 = m.fetch_unacked_limited(&r, Some(&batch(0xD4)), batch(0xD5), 1);
        assert!(f5.items.is_empty());
        assert_eq!(f5.batch_id, None);
    }

    #[test]
    fn unacked_fetch_keeps_items_until_acknowledged() {
        let m = MailboxStore::new();
        let r = rid(1);
        m.enqueue(r, vec![1; 10]).unwrap();
        m.enqueue(r, vec![2; 10]).unwrap();
        // First fetch: handed out, still queued.
        let f1 = m.fetch_unacked(&r, None, batch(0xA1));
        assert_eq!(envelopes(&f1), vec![1, 2]);
        assert_eq!(f1.batch_id, Some(batch(0xA1)));
        assert!(!f1.has_more);
        assert_eq!(m.depth(&r), 2, "nothing deleted without an ack");
        // Response lost: the client fetches again without an ack → same items.
        let f2 = m.fetch_unacked(&r, None, batch(0xA2));
        assert_eq!(envelopes(&f2), vec![1, 2], "unacknowledged items are re-delivered");
        assert_eq!(f2.batch_id, Some(batch(0xA2)));
        // Ack the batch the client actually stored → deleted, nothing left.
        let f3 = m.fetch_unacked(&r, Some(&batch(0xA2)), batch(0xA3));
        assert!(f3.items.is_empty());
        assert_eq!(f3.batch_id, None, "empty response carries no batch");
        assert_eq!(m.depth(&r), 0);
    }

    #[test]
    fn ack_deletes_exactly_the_batch_not_later_arrivals() {
        let m = MailboxStore::new();
        let r = rid(2);
        m.enqueue(r, vec![1; 10]).unwrap();
        let f1 = m.fetch_unacked(&r, None, batch(0xB1));
        assert_eq!(envelopes(&f1), vec![1]);
        // A message arrives after the batch was handed out.
        m.enqueue(r, vec![2; 10]).unwrap();
        let f2 = m.fetch_unacked(&r, Some(&batch(0xB1)), batch(0xB2));
        assert_eq!(envelopes(&f2), vec![2], "the later arrival must survive the ack of the earlier batch");
        assert_eq!(m.depth(&r), 1);
    }

    #[test]
    fn wrong_or_stale_ack_deletes_nothing() {
        let m = MailboxStore::new();
        let r = rid(3);
        m.enqueue(r, vec![1; 10]).unwrap();
        let _ = m.fetch_unacked(&r, None, batch(0xC1));
        // Unknown id.
        let f = m.fetch_unacked(&r, Some(&batch(0xEE)), batch(0xC2));
        assert_eq!(envelopes(&f), vec![1]);
        // Stale id: C1 was superseded by C2 (e.g. two racing fetches).
        let f = m.fetch_unacked(&r, Some(&batch(0xC1)), batch(0xC3));
        assert_eq!(envelopes(&f), vec![1], "a superseded batch id must not delete");
        assert_eq!(m.depth(&r), 1);
        // The current one does.
        let f = m.fetch_unacked(&r, Some(&batch(0xC3)), batch(0xC4));
        assert!(f.items.is_empty());
        assert_eq!(m.depth(&r), 0);
    }

    #[test]
    fn ack_for_another_recipient_has_no_effect() {
        let m = MailboxStore::new();
        m.enqueue(rid(4), vec![1; 10]).unwrap();
        m.enqueue(rid(5), vec![2; 10]).unwrap();
        let f4 = m.fetch_unacked(&rid(4), None, batch(0xD1));
        let _ = m.fetch_unacked(&rid(5), None, batch(0xD2));
        // rid(5) presents rid(4)'s batch id.
        let _ = m.fetch_unacked(&rid(5), f4.batch_id.as_ref(), batch(0xD3));
        assert_eq!(m.depth(&rid(4)), 1);
        assert_eq!(m.depth(&rid(5)), 1);
    }

    #[test]
    fn unacked_fetch_pages_by_byte_cap() {
        // Cap 1000 B, each envelope = 400 B + 4 → two per batch.
        let m = MailboxStore::with_params(MAILBOX_TTL_SEC, 1000);
        let r = rid(6);
        for b in 1..=3u8 { m.enqueue(r, vec![b; 400]).unwrap(); }
        let f1 = m.fetch_unacked(&r, None, batch(0xE1));
        assert_eq!(envelopes(&f1), vec![1, 2]);
        assert!(f1.has_more);
        let f2 = m.fetch_unacked(&r, f1.batch_id.as_ref(), batch(0xE2));
        assert_eq!(envelopes(&f2), vec![3]);
        assert!(!f2.has_more);
        let f3 = m.fetch_unacked(&r, f2.batch_id.as_ref(), batch(0xE3));
        assert!(f3.items.is_empty());
        assert_eq!(m.depth(&r), 0);
    }

    #[test]
    fn ttl_eviction_between_fetch_and_ack_never_over_deletes() {
        let m = MailboxStore::with_params(1_000, FETCH_RESPONSE_MAX_BYTES);
        let r = rid(7);
        m.enqueue(r, vec![1; 10]).unwrap();
        m.enqueue(r, vec![2; 10]).unwrap();
        let f1 = m.fetch_unacked(&r, None, batch(0xF1));
        assert_eq!(envelopes(&f1), vec![1, 2]);
        // Both expire, a new one arrives, a sweep runs before the ack.
        backdate_all(&m);
        m.enqueue(r, vec![3; 10]).unwrap();
        assert_eq!(m.sweep_expired(), 2);
        // The ack covers seq of items 1–2 only; item 3 must survive. (A
        // count-based ack would have deleted it.)
        let f2 = m.fetch_unacked(&r, f1.batch_id.as_ref(), batch(0xF2));
        assert_eq!(envelopes(&f2), vec![3]);
        assert_eq!(m.depth(&r), 1);
    }

    #[test]
    fn expired_items_are_not_handed_out() {
        let m = MailboxStore::with_params(0, FETCH_RESPONSE_MAX_BYTES);
        let r = rid(8);
        m.enqueue(r, vec![1; 10]).unwrap();
        backdate_all(&m);
        let f = m.fetch_unacked(&r, None, batch(0x11));
        assert!(f.items.is_empty());
        assert_eq!(f.batch_id, None);
        assert_eq!(m.depth(&r), 0);
    }

    #[test]
    fn legacy_drain_clears_the_outstanding_batch() {
        let m = MailboxStore::new();
        let r = rid(9);
        m.enqueue(r, vec![1; 10]).unwrap();
        let f1 = m.fetch_unacked(&r, None, batch(0x21));
        let d = m.drain(&r);
        assert_eq!(d.items.len(), 1);
        assert!(!m.inner.lock().unwrap().pending.contains_key(&r));
        // A later message is not touched by the old batch id.
        m.enqueue(r, vec![2; 10]).unwrap();
        let f2 = m.fetch_unacked(&r, f1.batch_id.as_ref(), batch(0x22));
        assert_eq!(envelopes(&f2), vec![2]);
    }

    #[test]
    fn pending_state_is_dropped_with_the_queue() {
        let m = MailboxStore::with_params(1_000, FETCH_RESPONSE_MAX_BYTES);
        let r = rid(10);
        m.enqueue(r, vec![1; 10]).unwrap();
        let _ = m.fetch_unacked(&r, None, batch(0x31));
        backdate_all(&m);
        assert_eq!(m.sweep_expired(), 1);
        let g = m.inner.lock().unwrap();
        assert!(!g.queues.contains_key(&r));
        assert!(!g.pending.contains_key(&r), "no pending batch may outlive its queue");
        drop(g);
        // Same via the chunked sweep.
        m.enqueue(r, vec![2; 10]).unwrap();
        let _ = m.fetch_unacked(&r, None, batch(0x32));
        backdate_all(&m);
        assert_eq!(m.sweep_expired_chunked(1), 1);
        assert!(!m.inner.lock().unwrap().pending.contains_key(&r));
    }

    #[test]
    fn empty_mailbox_returns_no_batch() {
        let m = MailboxStore::new();
        let f = m.fetch_unacked(&rid(12), Some(&batch(0x41)), batch(0x42));
        assert!(f.items.is_empty());
        assert_eq!(f.batch_id, None);
        assert!(!f.has_more);
        assert!(m.inner.lock().unwrap().pending.is_empty());
    }

    #[test]
    fn sequence_numbers_increase_across_recipients() {
        let m = MailboxStore::new();
        m.enqueue(rid(13), vec![1]).unwrap();
        m.enqueue(rid(14), vec![2]).unwrap();
        m.enqueue(rid(13), vec![3]).unwrap();
        let g = m.inner.lock().unwrap();
        let s13: Vec<u64> = g.queues[&rid(13)].iter().map(|i| i.seq).collect();
        let s14: Vec<u64> = g.queues[&rid(14)].iter().map(|i| i.seq).collect();
        assert_eq!(s13, vec![0, 2]);
        assert_eq!(s14, vec![1]);
    }

    fn assert_byte_invariant(m: &MailboxStore) {
        let g = m.inner.lock().unwrap();
        let sum: u64 = g.queues.values().flatten().map(|it| it.inner_envelope.len() as u64).sum();
        assert_eq!(g.total_bytes, sum, "total_bytes == Σ len");
    }

    /// F3/F5: the per-recipient cap alone let many recipients together
    /// grow the mailbox until the exit ran out of memory. Filling across
    /// many rids reaches the global cap and is refused (Full, the exit
    /// answers UNAVAILABLE); acknowledged fetches and the TTL sweep give
    /// the room back.
    #[test]
    fn global_byte_cap_refuses_across_rids_and_recovers() {
        let m = MailboxStore::with_params(1_000, FETCH_RESPONSE_MAX_BYTES).with_global_cap_bytes(1_000);
        for i in 0..10u8 {
            m.enqueue(rid(100 + i), vec![i; 100]).unwrap();
        }
        assert_eq!(m.enqueue(rid(200), vec![0; 1]), Err(MailboxEnqueueError::Full), "cap reached across rids");
        assert_eq!(m.depth(&rid(200)), 0, "a refused enqueue leaves no queue behind");
        assert_byte_invariant(&m);

        // Ack frees room.
        let f = m.fetch_unacked(&rid(100), None, batch(0x51));
        let _ = m.fetch_unacked(&rid(100), f.batch_id.as_ref(), batch(0x52));
        m.enqueue(rid(200), vec![9; 100]).unwrap();
        assert_eq!(m.enqueue(rid(201), vec![9; 1]), Err(MailboxEnqueueError::Full));
        assert_byte_invariant(&m);

        // TTL sweep frees room.
        backdate_all(&m);
        assert_eq!(m.sweep_expired(), 10);
        assert_eq!(m.total_bytes(), 0);
        m.enqueue(rid(201), vec![9; 1_000]).unwrap();
        assert_byte_invariant(&m);
    }

    /// F3/F5: total_bytes stays the exact sum over every path that adds or
    /// removes items (enqueue, refused enqueue, drain with TTL and byte cap,
    /// unacked fetch, ack, TTL inside fetch, both sweeps).
    #[test]
    fn total_bytes_matches_the_queues_after_mixed_operations() {
        let m = MailboxStore::with_params(1_000, 900).with_per_queue_cap(4).with_global_cap_bytes(100_000);
        for round in 0..6u8 {
            for r in 0..5u8 {
                let _ = m.enqueue(rid(r), vec![round; 100 + 50 * r as usize]);
                assert_byte_invariant(&m);
            }
            let _ = m.drain(&rid(0));
            assert_byte_invariant(&m);
            let f = m.fetch_unacked(&rid(1), None, batch(round));
            assert_byte_invariant(&m);
            let _ = m.fetch_unacked_limited(&rid(1), f.batch_id.as_ref(), batch(round ^ 0x80), 1);
            assert_byte_invariant(&m);
            if round % 2 == 1 {
                backdate_all(&m);
                if round == 3 { m.sweep_expired_chunked(2); } else { m.sweep_expired(); }
                assert_byte_invariant(&m);
            }
            let _ = m.fetch_unacked(&rid(2), None, batch(0x70)); // TTL path inside fetch
            assert_byte_invariant(&m);
        }
    }

    #[test]
    fn rejected_enqueue_consumes_no_sequence_number() {
        let m = MailboxStore::new().with_per_queue_cap(1);
        let r = rid(15);
        m.enqueue(r, vec![1]).unwrap();
        assert_eq!(m.enqueue(r, vec![2]), Err(MailboxEnqueueError::Full));
        m.enqueue(rid(16), vec![3]).unwrap();
        let g = m.inner.lock().unwrap();
        assert_eq!(g.queues[&rid(16)][0].seq, 1);
    }
}

// ============================================================================
// V2.1 — Push-Relay state (Phase 3a, 2026-05-04)
// ============================================================================
//
// Both stores below live in the **push-relay** process, never on the
// exit-relay. The exit-relay replicates `(rid, hsig_pk)` to the push-relay
// after a successful `PUT /v2/directory/:rid`; the push-relay uses that
// replica to authenticate `PUT /v2/push/register/:rid` (hsig-signed).
//
// In-RAM only (Spec G1). Restart loses all push tokens; clients re-register
// on next app launch (the iOS Silent-Push handler will reschedule).

/// One push-token entry: 32-byte APNs device token + production/sandbox flag
/// + registration timestamp (for diagnostics + future TTL cleanup).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PushEntry {
    pub apns_token: [u8; APNS_TOKEN_LEN],
    pub sandbox: bool,
    /// Server wallclock at acceptance. Diagnostics + future TTL cleanup only —
    /// it is set by us, so it says nothing about the freshness of the request.
    pub registered_at: u64,
    /// The client-signed timestamp from the register body. This is the only
    /// field a replay cannot advance, so it is what monotonicity is judged on.
    pub signed_at: u64,
}

/// Outcome of `PushTokenStore::register`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushRegisterError {
    /// The signed timestamp is not newer than the stored one. Refusing this is
    /// what stops a captured register body from reinstating an old APNs token.
    NotMonotonic,
}

/// In-RAM push-token registry.
///
/// Keyed by `RecipientId` (not by APNs token) so that push triggers from
/// the exit-relay, which only know the rid, can locate the device token in
/// O(1). Capacity-bounded via `MAX_PUSH_ENTRIES`.
///
/// N5: at capacity a new recipient displaces the entry with the oldest
/// `registered_at` instead of being refused. Refusing locked every device
/// that registered after the store filled out of push until a restart; a
/// displaced device gets its push back on its next registration (clients
/// re-register on launch). Every registration is hsig-verified against the
/// replicated directory, so displacing needs that many valid identities.
pub struct PushTokenStore {
    inner: Mutex<PushInner>,
    /// Last push timestamp per rid, used to enforce `PUSH_DEBOUNCE_SEC`.
    debounce: Mutex<HashMap<RecipientId, u64>>,
    capacity: usize,
}

struct PushInner {
    /// Entry plus its tie-breaking insertion number in `order`.
    entries: HashMap<RecipientId, (PushEntry, u64)>,
    /// Ascending `(registered_at, insertion)` -> rid; the first key is the
    /// eviction victim. Invariant: `order.len() == entries.len()`.
    order: BTreeMap<(u64, u64), RecipientId>,
    next_insertion: u64,
}

impl PushTokenStore {
    pub fn new() -> Self {
        Self::with_capacity(MAX_PUSH_ENTRIES)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(PushInner {
                entries: HashMap::with_capacity(capacity.min(64 * 1024)),
                order: BTreeMap::new(),
                next_insertion: 0,
            }),
            debounce: Mutex::new(HashMap::new()),
            capacity: capacity.max(1),
        }
    }

    /// Register or replace the push token for `rid`. At capacity a new
    /// recipient displaces the entry with the oldest `registered_at` (N5).
    pub fn register(
        &self,
        rid: RecipientId,
        entry: PushEntry,
        now_sec: u64,
    ) -> std::result::Result<(), PushRegisterError> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        // Anti-rollback. The register body is signed but carried no freshness
        // beyond a skew check, so a captured body could be resent inside the
        // window and replace a newer registration with an older APNs token —
        // after which the recipient stops receiving pushes entirely.
        //
        // Judged on the client-signed timestamp, not `registered_at`: the
        // latter is server wallclock, so a replay would always look fresh.
        match g.entries.get(&rid) {
            Some(&(prev, prev_insertion)) => {
                let effective_prev = prev.signed_at.min(now_sec);
                if entry.signed_at <= effective_prev {
                    // Re-registering the identical token is idempotent, not an
                    // attack — clients retry.
                    if prev.apns_token == entry.apns_token && prev.sandbox == entry.sandbox {
                        return Ok(());
                    }
                    return Err(PushRegisterError::NotMonotonic);
                }
                g.order.remove(&(prev.registered_at, prev_insertion));
            }
            None => {
                if g.entries.len() >= self.capacity {
                    let victim = g.order.iter().next().map(|(&k, &r)| (k, r));
                    if let Some((key, victim_rid)) = victim {
                        g.order.remove(&key);
                        g.entries.remove(&victim_rid);
                        // Lock order inner -> debounce; nothing takes them
                        // the other way round.
                        self.debounce.lock().unwrap().remove(&victim_rid);
                    }
                }
            }
        }
        let insertion = g.next_insertion;
        g.next_insertion += 1;
        g.order.insert((entry.registered_at, insertion), rid);
        g.entries.insert(rid, (entry, insertion));
        debug_assert_eq!(g.entries.len(), g.order.len());
        Ok(())
    }

    pub fn get(&self, rid: &RecipientId) -> Option<PushEntry> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).entries.get(rid).map(|&(e, _)| e)
    }

    /// Remove the entry (rotation-to-empty / device unregister). Returns
    /// `true` iff an entry was present.
    pub fn remove(&self, rid: &RecipientId) -> bool {
        let removed = {
            let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            match g.entries.remove(rid) {
                Some((e, insertion)) => {
                    g.order.remove(&(e.registered_at, insertion));
                    true
                }
                None => false,
            }
        };
        // Also clear debounce so a re-registration is not artificially throttled.
        self.debounce.lock().unwrap().remove(rid);
        removed
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).entries.is_empty()
    }

    pub fn contains(&self, rid: &RecipientId) -> bool {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).entries.contains_key(rid)
    }

    /// Debounced "should I push?" check. Returns `true` iff `now_sec` is at
    /// least `min_interval_sec` seconds after the last allowed push for
    /// `rid` (and updates the last-push timestamp atomically).
    ///
    /// Mirrors V1's `should_send_push` semantics
    /// (`exit-relay/src/main.rs` L2291-L2317).
    pub fn allow_push(&self, rid: &RecipientId, now_sec: u64, min_interval_sec: u64) -> bool {
        let mut g = self.debounce.lock().unwrap();
        // Periodic cleanup so the debounce map cannot grow unbounded under
        // a stream of unique rids that never repeat.
        if g.len() > 10_000 {
            let cutoff = now_sec.saturating_sub(2 * min_interval_sec);
            g.retain(|_, ts| *ts >= cutoff);
        }
        if let Some(&last) = g.get(rid) {
            if now_sec.saturating_sub(last) < min_interval_sec {
                return false;
            }
        }
        g.insert(*rid, now_sec);
        true
    }
}

impl Default for PushTokenStore {
    fn default() -> Self { Self::new() }
}

// ----------------------------------------------------------------------------
// Directory replica (rid → hsig_pk)
// ----------------------------------------------------------------------------
//
// The push-relay's **read-only** view of the recipient directory, used to
// verify hsig-signed `PUT /v2/push/register/:rid` requests. Populated by
// `PUT /v2/directory/replicate` from the exit-relay (S2S HMAC + sealed, F43).

/// F10: LRU by last `put`, capacity `MAX_DIRECTORY_REPLICA_ENTRIES`.
///
/// It used to refuse new recipients once full, so every recipient that
/// published after that point could never register for push until the
/// push relay restarted. Now the entry least recently put (= replicated by
/// an exit, i.e. least recently re-published) is dropped. A `get` is not
/// use: registrations must not keep an entry alive that its exit no longer
/// replicates. A dropped recipient comes back with its next directory PUT.
///
/// Memory at capacity: hsig_pk 1,984 B + Vec header 24 B + rid 32 B + the
/// LRU index (seq 8 B + rid 32 B) + hash/tree overhead ≈ 2.1 KB per entry,
/// so 200,000 entries ≈ 420 MB on the push relay.
pub struct DirectoryReplica {
    inner: Mutex<ReplicaInner>,
    capacity: usize,
}

struct ReplicaInner {
    /// hsig_pk plus the sequence number of its last put.
    entries: HashMap<RecipientId, (Vec<u8>, u64)>,
    /// Ascending last-put sequence -> rid; the first key is the LRU victim.
    /// Invariant: `lru.len() == entries.len()`.
    lru: BTreeMap<u64, RecipientId>,
    next_seq: u64,
}

impl DirectoryReplica {
    pub fn new() -> Self {
        Self::with_capacity(MAX_DIRECTORY_REPLICA_ENTRIES)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(ReplicaInner {
                entries: HashMap::with_capacity(capacity.min(64 * 1024)),
                lru: BTreeMap::new(),
                next_seq: 0,
            }),
            capacity: capacity.max(1),
        }
    }

    /// Insert or replace the hsig public key for `rid`, evicting the entry
    /// least recently put when a new rid arrives at capacity. Caller is
    /// responsible for validating `hsig_pk.len() == HSIG_PK_LEN` (and the
    /// rid binding) before calling; this method intentionally accepts any
    /// length so the wire validation lives at one well-defined boundary
    /// (the handler).
    pub fn put(&self, rid: RecipientId, hsig_pk: Vec<u8>) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let seq = g.next_seq;
        g.next_seq += 1;
        if let Some(&(_, old_seq)) = g.entries.get(&rid) {
            g.lru.remove(&old_seq);
        } else if g.entries.len() >= self.capacity {
            if let Some((&victim_seq, &victim_rid)) = g.lru.iter().next() {
                g.lru.remove(&victim_seq);
                g.entries.remove(&victim_rid);
            }
        }
        g.lru.insert(seq, rid);
        g.entries.insert(rid, (hsig_pk, seq));
        debug_assert_eq!(g.entries.len(), g.lru.len());
    }

    pub fn get(&self, rid: &RecipientId) -> Option<Vec<u8>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).entries.get(rid).map(|(pk, _)| pk.clone())
    }

    pub fn remove(&self, rid: &RecipientId) -> bool {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        match g.entries.remove(rid) {
            Some((_, seq)) => {
                g.lru.remove(&seq);
                true
            }
            None => false,
        }
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).entries.is_empty()
    }

    pub fn contains(&self, rid: &RecipientId) -> bool {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).entries.contains_key(rid)
    }
}

impl Default for DirectoryReplica {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod push_store_tests {
    use super::*;

    fn rid(b: u8) -> RecipientId {
        let mut a = [0u8; 32]; a[0] = b; RecipientId(a)
    }

    /// Server wallclock stand-in, larger than every `signed_at` below so the
    /// `.min(now_sec)` cap never masks a case.
    const NOW: u64 = 1_700_001_000;

    fn entry(byte: u8) -> PushEntry {
        entry_at(byte, 1_700_000_000)
    }

    fn entry_at(byte: u8, signed_at: u64) -> PushEntry {
        PushEntry {
            apns_token: [byte; APNS_TOKEN_LEN],
            sandbox: false,
            registered_at: 1_700_000_000,
            signed_at,
        }
    }

    #[test]
    fn register_and_get_roundtrip() {
        let s = PushTokenStore::new();
        let r = rid(1);
        assert!(s.get(&r).is_none());
        s.register(r, entry(0x42), NOW).unwrap();
        let got = s.get(&r).expect("entry present");
        assert_eq!(got.apns_token, [0x42; APNS_TOKEN_LEN]);
        assert!(!got.sandbox);
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn overwrite_replaces_token() {
        let s = PushTokenStore::new();
        let r = rid(2);
        s.register(r, entry_at(0x11, 1_700_000_000), NOW).unwrap();
        // A real rotation carries a newer signed timestamp; that is what makes
        // it distinguishable from a replay of the previous registration.
        s.register(r, PushEntry { sandbox: true, ..entry_at(0x22, 1_700_000_060) }, NOW).unwrap();
        let got = s.get(&r).unwrap();
        assert_eq!(got.apns_token, [0x22; APNS_TOKEN_LEN]);
        assert!(got.sandbox);
        assert_eq!(s.len(), 1);
    }

    /// N5: a full store no longer refuses new recipients (that locked every
    /// later device out of push until a restart). It drops the entry with
    /// the oldest `registered_at`; a re-registration refreshes that time.
    #[test]
    fn capacity_evicts_oldest_registration() {
        let s = PushTokenStore::with_capacity(2);
        let reg = |byte, registered_at| PushEntry { registered_at, ..entry(byte) };
        s.register(rid(1), reg(0x01, 100), NOW).unwrap();
        s.register(rid(2), reg(0x02, 200), NOW).unwrap();
        // rid(1) re-registers later: now rid(2) holds the oldest registration.
        s.register(rid(1), PushEntry { signed_at: 1_700_000_060, ..reg(0xAA, 300) }, NOW)
            .expect("a newer registration must still overwrite at capacity");
        assert_eq!(s.register(rid(3), reg(0x03, 400), NOW), Ok(()));
        assert_eq!(s.len(), 2);
        assert!(s.contains(&rid(1)), "re-registered entry survives");
        assert!(!s.contains(&rid(2)), "oldest registration is evicted");
        assert!(s.contains(&rid(3)));
    }

    #[test]
    fn push_register_refuses_rollback_to_older_token() {
        // The attack: capture a signed register body, resend it inside the
        // 120 s skew window after the device registered a new APNs token. The
        // signature still verifies, so only freshness can stop it — and the
        // consequence is silent: the recipient simply stops getting pushes.
        let s = PushTokenStore::new();
        let r = rid(3);
        let old = entry_at(0xAA, 1_700_000_000);
        s.register(r, old, NOW).unwrap();
        s.register(r, entry_at(0xBB, 1_700_000_060), NOW).unwrap();

        assert_eq!(
            s.register(r, old, NOW),
            Err(PushRegisterError::NotMonotonic),
            "replaying the captured older registration must be refused"
        );
        assert_eq!(s.get(&r).unwrap().apns_token, [0xBB; APNS_TOKEN_LEN]);
    }

    #[test]
    fn push_register_same_token_is_idempotent() {
        // Clients retry. Re-sending the identical registration must not fail.
        let s = PushTokenStore::new();
        let r = rid(4);
        let e = entry_at(0xCC, 1_700_000_000);
        s.register(r, e, NOW).unwrap();
        s.register(r, e, NOW).expect("identical re-registration must succeed");
        assert_eq!(s.get(&r).unwrap().apns_token, [0xCC; APNS_TOKEN_LEN]);
    }

    #[test]
    fn push_register_future_timestamp_cannot_lock_out_later_registrations() {
        // Without the `.min(now_sec)` cap a body dated far ahead would block
        // every later legitimate registration for as long as that date stands.
        let s = PushTokenStore::new();
        let r = rid(5);
        let now = 1_700_000_000u64;
        s.register(r, entry_at(0xDD, now + 999_999), now).unwrap();
        s.register(r, entry_at(0xEE, now + 1), now)
            .expect("a present-dated registration must still be accepted");
        assert_eq!(s.get(&r).unwrap().apns_token, [0xEE; APNS_TOKEN_LEN]);
    }

    #[test]
    fn remove_clears_debounce_too() {
        let s = PushTokenStore::new();
        let r = rid(7);
        s.register(r, entry(0x77), NOW).unwrap();
        // First push allowed; second within window blocked.
        assert!(s.allow_push(&r, 1000, 30));
        assert!(!s.allow_push(&r, 1010, 30));
        // After remove + re-register, debounce is reset.
        s.remove(&r);
        s.register(r, entry(0x77), NOW).unwrap();
        assert!(s.allow_push(&r, 1015, 30));
    }

    #[test]
    fn allow_push_debounce_window() {
        let s = PushTokenStore::new();
        let r = rid(9);
        assert!(s.allow_push(&r, 100, 30));
        assert!(!s.allow_push(&r, 105, 30));
        assert!(!s.allow_push(&r, 129, 30));
        assert!(s.allow_push(&r, 130, 30));
    }

    #[test]
    fn directory_replica_roundtrip() {
        let r = DirectoryReplica::new();
        let id = rid(5);
        assert!(r.get(&id).is_none());
        r.put(id, vec![0xAB; HSIG_PK_LEN]);
        assert_eq!(r.get(&id), Some(vec![0xAB; HSIG_PK_LEN]));
        assert!(r.contains(&id));
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn directory_replica_overwrite() {
        let r = DirectoryReplica::new();
        let id = rid(6);
        r.put(id, vec![0x00; HSIG_PK_LEN]);
        r.put(id, vec![0xFF; HSIG_PK_LEN]);
        assert_eq!(r.get(&id), Some(vec![0xFF; HSIG_PK_LEN]));
        assert_eq!(r.len(), 1);
    }

    /// F10: a full replica no longer refuses new recipients; it drops the
    /// entry least recently put. A `get` does not count as use.
    #[test]
    fn directory_replica_evicts_least_recently_put() {
        let r = DirectoryReplica::with_capacity(2);
        r.put(rid(1), vec![1; HSIG_PK_LEN]);
        r.put(rid(2), vec![2; HSIG_PK_LEN]);
        // rid(1) is put again (re-replicated): rid(2) is now the oldest put.
        r.put(rid(1), vec![0x11; HSIG_PK_LEN]);
        // Reading rid(2) must not protect it.
        assert!(r.get(&rid(2)).is_some());
        r.put(rid(3), vec![3; HSIG_PK_LEN]);
        assert_eq!(r.len(), 2);
        assert_eq!(r.get(&rid(1)), Some(vec![0x11; HSIG_PK_LEN]));
        assert!(!r.contains(&rid(2)), "least recently put is evicted");
        assert!(r.contains(&rid(3)));
    }

    /// F10: the replica holds at least as many recipients as one exit's
    /// directory, so a recipient the exit stores is never refused here.
    #[test]
    fn directory_replica_capacity_matches_directory() {
        assert_eq!(MAX_DIRECTORY_REPLICA_ENTRIES, DIRECTORY_LRU_CAPACITY);
    }
}
