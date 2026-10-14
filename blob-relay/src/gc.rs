//! Background garbage collector. Runs every 5 minutes (spec §9).
//!
//!   - Expiration: blobs whose `expires_at < now` are deleted, bounded to
//!     1000 per cycle.
//!   - Abandoned inits: blobs created but never sealed and older than 1h
//!     are deleted (prevents disk leak from buggy clients).
//!   - Orphan directories: blob directories without an index entry whose
//!     mtime is older than 1h are shredded (F16/F17 leftovers, failed inits,
//!     metas that no longer decrypt at reindex).
//!   - Per-blob write locks nobody holds are dropped (F22).

use std::sync::Arc;
use std::time::Duration;

use tracing::{error, info};

use crate::storage::BlobStorage;
use crate::util::now_secs;

const GC_INTERVAL: Duration = Duration::from_secs(5 * 60);
/// P7-BLOB-17: default GC batch ceiling. Operators with burst backlog (large
/// expiration waves, e.g. after a daily reset window) can raise this via
/// `LADON_BLOB_GC_MAX_PER_CYCLE`. The default 1000/cycle * 5min cycle =
/// 12 000/hour drain rate is adequate for steady-state but inadequate for
/// recovery from a multi-hour stall.
const DEFAULT_MAX_PER_CYCLE: usize = 1000;
const ABANDONED_INIT_AGE_SECS: u64 = 3600;

/// Read the per-cycle drain cap from env (P7-BLOB-17). Clamped to a sane
/// range [100, 100_000] so a typo can't lock the GC or saturate the disk
/// scanner.
fn max_per_cycle() -> usize {
    let raw = std::env::var("LADON_BLOB_GC_MAX_PER_CYCLE")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(DEFAULT_MAX_PER_CYCLE);
    raw.clamp(100, 100_000)
}

pub fn spawn_gc(storage: Arc<BlobStorage>, shutdown: Arc<tokio::sync::Notify>) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown.notified() => {
                    info!("gc: shutdown received, exiting");
                    return;
                }
                _ = tokio::time::sleep(GC_INTERVAL) => {
                    if let Err(e) = run_once(&storage) {
                        error!(?e, "gc: cycle failed");
                    }
                }
            }
        }
    });
}

pub fn run_once(storage: &BlobStorage) -> Result<(), crate::storage::StorageError> {
    run_once_at(storage, now_secs())
}

/// One GC cycle against an explicit clock (tests drive the orphan age).
pub fn run_once_at(storage: &BlobStorage, now: u64) -> Result<(), crate::storage::StorageError> {
    let cap = max_per_cycle();
    let expired = storage.expired_blobs(now, cap);
    let mut expired_count = 0usize;
    for id in &expired {
        storage.delete_blob(id)?;
        expired_count += 1;
    }

    let abandoned = storage.abandoned_blobs(ABANDONED_INIT_AGE_SECS, cap);
    let mut abandoned_count = 0usize;
    for id in &abandoned {
        storage.delete_blob(id)?;
        abandoned_count += 1;
    }

    let orphans = storage.orphan_dirs(now, ABANDONED_INIT_AGE_SECS, cap);
    let mut orphan_count = 0usize;
    for id in &orphans {
        if storage.remove_orphan_dir(id)? {
            orphan_count += 1;
        }
    }

    // F22: the deletes above were the last users of most per-blob locks.
    storage.prune_write_locks();

    if expired_count > 0 || abandoned_count > 0 || orphan_count > 0 {
        info!(%expired_count, %abandoned_count, %orphan_count, "gc: cycle completed");
    }
    Ok(())
}
