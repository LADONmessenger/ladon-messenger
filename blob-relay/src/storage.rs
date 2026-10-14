//! Per-blob on-disk storage with atomic writes.
//!
//! Layout (spec §3.3):
//!
//!   data/{id[0..2]}/{id}/
//!     ├─ meta.bin          # AES-GCM wrapped meta (see [`Meta`])
//!     ├─ chunk_00000
//!     ├─ chunk_00001
//!     └─ …
//!
//! All writes go through `tempfile + fsync + rename`, followed by a directory
//! fsync. Readers assume that any visible file is complete.
//!
//! Thread-safety: the [`BlobStorage::index`] is a single `RwLock<HashMap>`;
//! per-blob write operations additionally acquire a `Mutex` from
//! [`BlobStorage::write_locks`]. Reads go lock-free through the filesystem.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use thiserror::Error;

use crate::util::{now_secs, Bucket, FULL_CHUNK_WIRE_BYTES, PLAINTEXT_CHUNK_BYTES};

const META_FILENAME: &str = "meta.bin";
const META_MAGIC: &[u8; 8] = b"LBMETA01";
const META_PLAINTEXT_BYTES: usize = 16 + 2 + 1 + 8 + 8 + 1 + 32;
const SHRED_BLOCK_BYTES: usize = 64 * 1024;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("blob already exists")]
    AlreadyExists,
    #[error("blob not found")]
    NotFound,
    #[error("chunk index out of range")]
    ChunkOutOfRange,
    #[error("blob is sealed")]
    Sealed,
    #[error("chunk already uploaded with different bytes")]
    ChunkConflict,
    #[error("meta decode failure")]
    MetaCorrupt,
    #[error("global disk quota exhausted")]
    DiskFull,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("crypto error: {0}")]
    Crypto(String),
}

/// On-disk metadata for one blob.
#[derive(Debug, Clone)]
pub struct Meta {
    pub blob_id: [u8; 16],
    pub chunk_count: u16,
    pub bucket: Bucket,
    pub created_at: u64,
    pub expires_at: u64,
    pub sealed: bool,
    /// Always zero. Until Addendum A2 stage 1 this held
    /// SHA-256("uploader-v1" || identity || blob_id), a reversible link from
    /// every blob to its uploader's long-term key (scan F29/F37). Uploads no
    /// longer carry an identity; the 32 bytes stay in the format so existing
    /// meta files still parse, and `reindex_from_disk` zeroes old values.
    pub reserved: [u8; 32],
}

impl Meta {
    fn encode_plaintext(&self) -> [u8; META_PLAINTEXT_BYTES] {
        let mut buf = [0u8; META_PLAINTEXT_BYTES];
        buf[..16].copy_from_slice(&self.blob_id);
        buf[16..18].copy_from_slice(&self.chunk_count.to_be_bytes());
        buf[18] = self.bucket.raw();
        buf[19..27].copy_from_slice(&self.created_at.to_be_bytes());
        buf[27..35].copy_from_slice(&self.expires_at.to_be_bytes());
        buf[35] = self.sealed as u8;
        buf[36..68].copy_from_slice(&self.reserved);
        buf
    }

    fn decode_plaintext(buf: &[u8]) -> Result<Self, StorageError> {
        if buf.len() != META_PLAINTEXT_BYTES {
            return Err(StorageError::MetaCorrupt);
        }
        let mut blob_id = [0u8; 16];
        blob_id.copy_from_slice(&buf[..16]);
        let chunk_count = u16::from_be_bytes([buf[16], buf[17]]);
        let bucket = Bucket::from_u8(buf[18]).ok_or(StorageError::MetaCorrupt)?;
        let created_at = u64::from_be_bytes(buf[19..27].try_into().unwrap());
        let expires_at = u64::from_be_bytes(buf[27..35].try_into().unwrap());
        let sealed = buf[35] != 0;
        let mut reserved = [0u8; 32];
        reserved.copy_from_slice(&buf[36..68]);
        Ok(Self {
            blob_id,
            chunk_count,
            bucket,
            created_at,
            expires_at,
            sealed,
            reserved,
        })
    }
}

/// Primary storage entry point. Clone-friendly (internally `Arc`).
#[derive(Clone)]
pub struct BlobStorage {
    inner: Arc<Inner>,
}

struct Inner {
    root: PathBuf,
    meta_key: [u8; 32],
    index: RwLock<HashMap<[u8; 16], Meta>>,
    write_locks: Mutex<HashMap<[u8; 16], Arc<Mutex<()>>>>,
    /// Sum of bucket byte sizes of currently-active blobs. Updated on
    /// `create_blob` / `delete_blob` / GC.
    disk_bytes_used: RwLock<u64>,
}

impl BlobStorage {
    /// Open (or create) a storage root directory.
    pub fn open(root: PathBuf, master_key: &[u8; 32]) -> Result<Self, StorageError> {
        std::fs::create_dir_all(&root)?;
        // P7-BLOB-03: set 0700 explicitly on the root so the storage tree
        // is owner-only regardless of process umask. create_dir_all does
        // not let us pass a mode and would otherwise rely on inherited
        // umask (typically 0022 → world-readable 0755).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700));
        }
        let meta_key = derive_meta_key(master_key);

        let inner = Inner {
            root,
            meta_key,
            index: RwLock::new(HashMap::new()),
            write_locks: Mutex::new(HashMap::new()),
            disk_bytes_used: RwLock::new(0),
        };
        let storage = Self {
            inner: Arc::new(inner),
        };
        storage.reindex_from_disk()?;
        Ok(storage)
    }

    fn reindex_from_disk(&self) -> Result<(), StorageError> {
        let root = &self.inner.root;
        if !root.exists() {
            return Ok(());
        }
        let mut idx = self.inner.index.write().unwrap();
        let mut bytes = self.inner.disk_bytes_used.write().unwrap();
        for shard in std::fs::read_dir(root)? {
            let shard = shard?;
            if !shard.file_type()?.is_dir() {
                continue;
            }
            for blob_dir in std::fs::read_dir(shard.path())? {
                let blob_dir = blob_dir?;
                if !blob_dir.file_type()?.is_dir() {
                    continue;
                }
                let meta_path = blob_dir.path().join(META_FILENAME);
                match self.read_meta(&meta_path) {
                    Ok(mut meta) => {
                        // A2 stage 1: a meta written before the upload
                        // identity was removed still carries the uploader
                        // hash. Rewrite it with zeros (fresh nonce, atomic
                        // replace). A failure leaves that one file as it was;
                        // it expires with its blob (at most MAX_TTL_SECS).
                        if meta.reserved != [0u8; 32] {
                            meta.reserved = [0u8; 32];
                            if self.write_meta(&meta).is_err() {
                                tracing::warn!("could not zero the uploader hash of one stored blob");
                            }
                        }
                        *bytes += meta.bucket.byte_size();
                        idx.insert(meta.blob_id, meta);
                    }
                    Err(_) => {
                        // Abandoned init or undecryptable meta: not indexed.
                        // The GC orphan sweep (`orphan_dirs`) shreds it once
                        // its directory is older than the abandoned-init age.
                    }
                }
            }
        }
        Ok(())
    }

    fn blob_dir(&self, blob_id: &[u8; 16]) -> PathBuf {
        let hex_id = hex::encode(blob_id);
        let shard = &hex_id[..2];
        self.inner.root.join(shard).join(hex_id)
    }

    fn chunk_path(&self, blob_id: &[u8; 16], index: u32) -> PathBuf {
        self.blob_dir(blob_id).join(format!("chunk_{:05}", index))
    }

    fn meta_path(&self, blob_id: &[u8; 16]) -> PathBuf {
        self.blob_dir(blob_id).join(META_FILENAME)
    }

    fn write_lock_for(&self, blob_id: &[u8; 16]) -> Arc<Mutex<()>> {
        let mut map = self.inner.write_locks.lock().unwrap();
        map.entry(*blob_id)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    #[cfg(test)]
    fn write_lock_count(&self) -> usize {
        self.inner.write_locks.lock().unwrap().len()
    }

    /// F22: drop per-blob locks nobody holds, so the map does not keep one
    /// entry per blob id ever seen. Correct because a lock is cloned out of
    /// the map only in `write_lock_for`, under this same map mutex: with the
    /// mutex held, a strong count of 1 means no caller holds or waits on
    /// that lock and none can obtain it before it is gone. The next
    /// `write_lock_for` for that id creates a fresh one.
    pub fn prune_write_locks(&self) {
        self.inner
            .write_locks
            .lock()
            .unwrap()
            .retain(|_, l| Arc::strong_count(l) > 1);
    }

    /// First-wins insertion. Returns [`StorageError::AlreadyExists`] on
    /// second insertion of the same blob_id (after crash the prior blob is
    /// still in the index from reindex).
    pub fn create_blob(&self, meta: Meta, disk_quota_bytes: u64) -> Result<(), StorageError> {
        // P7-BLOB-03: serialise all create_blob calls for the same blob_id
        // through the per-blob write lock BEFORE touching the on-disk state.
        // The earlier ordering (disk-write -> index-lock) allowed two parallel
        // creators with the same blob_id to both write meta.bin / create the
        // directory; only one of them registered in the index, leaving the
        // loser's partial on-disk state orphaned.
        let lock = self.write_lock_for(&meta.blob_id);
        let _guard = lock.lock().unwrap();

        {
            let idx = self.inner.index.read().unwrap();
            if idx.contains_key(&meta.blob_id) {
                return Err(StorageError::AlreadyExists);
            }
        }
        {
            let used = *self.inner.disk_bytes_used.read().unwrap();
            if used + meta.bucket.byte_size() > disk_quota_bytes {
                return Err(StorageError::DiskFull);
            }
        }

        let dir = self.blob_dir(&meta.blob_id);
        std::fs::create_dir_all(&dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        }

        self.write_meta(&meta)?;

        let bucket_bytes = meta.bucket.byte_size();
        let mut idx = self.inner.index.write().unwrap();
        // The per-blob lock guarantees no concurrent create_blob for this id,
        // but a reindex on startup may have inserted the same id; keep the
        // check as a safety net.
        if idx.contains_key(&meta.blob_id) {
            return Err(StorageError::AlreadyExists);
        }
        idx.insert(meta.blob_id, meta);
        drop(idx);
        *self.inner.disk_bytes_used.write().unwrap() += bucket_bytes;
        Ok(())
    }

    pub fn get_meta(&self, blob_id: &[u8; 16]) -> Option<Meta> {
        self.inner.index.read().unwrap().get(blob_id).cloned()
    }

    pub fn disk_bytes_used(&self) -> u64 {
        *self.inner.disk_bytes_used.read().unwrap()
    }

    /// Write a single chunk.
    ///
    /// Idempotency: if the chunk file already exists with identical bytes,
    /// returns `Ok(())`. If it exists with different bytes, returns
    /// [`StorageError::ChunkConflict`] (spec §6.2).
    pub fn put_chunk(
        &self,
        blob_id: &[u8; 16],
        index: u32,
        bytes: &[u8],
    ) -> Result<(), StorageError> {
        // F16/F17: every check runs under the per-blob lock on a meta read
        // under that lock. A meta read before the lock could belong to a blob
        // that `delete_blob` removed (or that was deleted and re-created with
        // a different shape) while this call waited; writing then would
        // resurrect the shredded directory outside the index, where no
        // quota and no expiry ever reach it.
        let lock = self.write_lock_for(blob_id);
        let _guard = lock.lock().unwrap();

        let meta = self.get_meta(blob_id).ok_or(StorageError::NotFound)?;
        if meta.sealed {
            return Err(StorageError::Sealed);
        }
        if index as u16 >= meta.chunk_count {
            return Err(StorageError::ChunkOutOfRange);
        }
        // Size validation: non-final chunks must be exactly FULL_CHUNK_WIRE_BYTES.
        // Final chunk size is derived from bucket+chunk_count.
        let is_last = (index as u16) + 1 == meta.chunk_count;
        let expected_size = expected_chunk_size(&meta, is_last);
        if bytes.len() != expected_size {
            return Err(StorageError::ChunkOutOfRange);
        }

        let path = self.chunk_path(blob_id, index);
        if path.exists() {
            let existing = std::fs::read(&path)?;
            if existing.len() != bytes.len() {
                return Err(StorageError::ChunkConflict);
            }
            // P7-BLOB-10: constant-time equality on the idempotency compare.
            // Chunk payloads are ciphertext (server-side meaningless) so
            // timing-leak of which prefix matched does not reveal plaintext,
            // but defence-in-depth keeps the door closed if a future change
            // ever puts client-controlled material through this path.
            use subtle::ConstantTimeEq;
            if bool::from(existing.as_slice().ct_eq(bytes)) {
                return Ok(());
            } else {
                return Err(StorageError::ChunkConflict);
            }
        }
        atomic_write(&path, bytes)?;
        Ok(())
    }

    pub fn get_chunk(&self, blob_id: &[u8; 16], index: u32) -> Result<Vec<u8>, StorageError> {
        let meta = self.get_meta(blob_id).ok_or(StorageError::NotFound)?;
        if index as u16 >= meta.chunk_count {
            return Err(StorageError::ChunkOutOfRange);
        }
        let path = self.chunk_path(blob_id, index);
        if !path.exists() {
            return Err(StorageError::NotFound);
        }
        Ok(std::fs::read(path)?)
    }

    /// Seal a blob after digest verification.
    pub fn seal(&self, blob_id: &[u8; 16]) -> Result<(), StorageError> {
        let lock = self.write_lock_for(blob_id);
        let _guard = lock.lock().unwrap();
        let mut idx = self.inner.index.write().unwrap();
        let meta = idx.get_mut(blob_id).ok_or(StorageError::NotFound)?;
        if meta.sealed {
            return Ok(());
        }
        meta.sealed = true;
        let to_write = meta.clone();
        drop(idx);
        self.write_meta(&to_write)?;
        Ok(())
    }

    /// Return every frame currently stored, in chunk-index order. Errors if
    /// any chunk is missing or if the blob is not known.
    pub fn load_all_frames(&self, blob_id: &[u8; 16]) -> Result<Vec<Vec<u8>>, StorageError> {
        let meta = self.get_meta(blob_id).ok_or(StorageError::NotFound)?;
        let mut frames = Vec::with_capacity(meta.chunk_count as usize);
        for i in 0..meta.chunk_count {
            let path = self.chunk_path(blob_id, i as u32);
            if !path.exists() {
                return Err(StorageError::NotFound);
            }
            frames.push(std::fs::read(&path)?);
        }
        Ok(frames)
    }

    /// P7-BLOB-09 fix (2026-05-12): streaming variant used by `/finalize`.
    /// Reads each chunk file in index order, hashes it into a leaf with
    /// `hash_one`, drops the bytes, and returns the leaf vector. Peak RAM
    /// is therefore 32 B/chunk + one chunk's bytes, not the full blob.
    /// At 1024 chunks × 256 KiB blobs this drops peak from ~256 MiB to ~256 KiB.
    pub fn fold_frames_to_leaves<F>(
        &self,
        blob_id: &[u8; 16],
        mut hash_one: F,
    ) -> Result<Vec<[u8; 32]>, StorageError>
    where
        F: FnMut(u32, &[u8]) -> [u8; 32],
    {
        let meta = self.get_meta(blob_id).ok_or(StorageError::NotFound)?;
        let mut leaves = Vec::with_capacity(meta.chunk_count as usize);
        for i in 0..meta.chunk_count {
            let path = self.chunk_path(blob_id, i as u32);
            if !path.exists() {
                return Err(StorageError::NotFound);
            }
            let frame = std::fs::read(&path)?;
            leaves.push(hash_one(i as u32, &frame));
            // `frame` drops here; only the 32-byte digest is retained.
        }
        Ok(leaves)
    }

    /// Shred-and-unlink every chunk plus the meta file, then drop from index.
    /// Intended for finalize-failure, DELETE, GC, or panic-wipe.
    pub fn delete_blob(&self, blob_id: &[u8; 16]) -> Result<(), StorageError> {
        let lock = self.write_lock_for(blob_id);
        let _guard = lock.lock().unwrap();

        let removed_meta = self.inner.index.write().unwrap().remove(blob_id);
        let dir = self.blob_dir(blob_id);
        if dir.exists() {
            shred_directory(&dir)?;
        }
        if let Some(m) = removed_meta {
            let mut used = self.inner.disk_bytes_used.write().unwrap();
            *used = used.saturating_sub(m.bucket.byte_size());
        }
        Ok(())
    }

    /// Return every blob currently past its expiry. Cheap; caller iterates
    /// and calls `delete_blob` per entry.
    pub fn expired_blobs(&self, now: u64, max: usize) -> Vec<[u8; 16]> {
        let idx = self.inner.index.read().unwrap();
        idx.values()
            .filter(|m| m.expires_at < now)
            .take(max)
            .map(|m| m.blob_id)
            .collect()
    }

    /// Return every blob that was created but never sealed and has lingered
    /// for longer than the given cutoff. Used on startup sweep.
    pub fn abandoned_blobs(&self, older_than_secs: u64, max: usize) -> Vec<[u8; 16]> {
        let now = now_secs();
        let idx = self.inner.index.read().unwrap();
        idx.values()
            .filter(|m| !m.sealed && now.saturating_sub(m.created_at) >= older_than_secs)
            .take(max)
            .map(|m| m.blob_id)
            .collect()
    }

    /// Blob directories on disk without an index entry whose mtime lies at
    /// least `older_than_secs` before `now`. Such a directory is invisible
    /// to `expired_blobs` / `abandoned_blobs` and would otherwise stay
    /// forever: an init whose meta write failed, a meta that no longer
    /// decrypts at reindex, or a directory resurrected by a chunk write
    /// before F16/F17. A fresh directory of a `create_blob` in progress is
    /// young, so the age bound keeps it out; `remove_orphan_dir` re-checks
    /// the index under the per-blob lock regardless.
    pub fn orphan_dirs(&self, now: u64, older_than_secs: u64, max: usize) -> Vec<[u8; 16]> {
        let mut out = Vec::new();
        let Ok(shards) = std::fs::read_dir(&self.inner.root) else {
            return out;
        };
        let idx = self.inner.index.read().unwrap();
        for shard in shards.flatten() {
            if !shard.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            let Ok(dirs) = std::fs::read_dir(shard.path()) else {
                continue;
            };
            for dir in dirs.flatten() {
                if out.len() >= max {
                    return out;
                }
                let Some(id) = dir.file_name().to_str().and_then(crate::util::parse_blob_id)
                else {
                    continue;
                };
                // Only the canonical location of `id`; anything else is not ours.
                if self.blob_dir(&id) != dir.path() || idx.contains_key(&id) {
                    continue;
                }
                let Ok(md) = dir.metadata() else { continue };
                if !md.is_dir() {
                    continue;
                }
                let mtime = md
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(now);
                if now.saturating_sub(mtime) >= older_than_secs {
                    out.push(id);
                }
            }
        }
        out
    }

    /// Shred one directory found by `orphan_dirs`. Returns `false` without
    /// touching the disk when the blob is (again) in the index.
    pub fn remove_orphan_dir(&self, blob_id: &[u8; 16]) -> Result<bool, StorageError> {
        let lock = self.write_lock_for(blob_id);
        let _guard = lock.lock().unwrap();
        if self.inner.index.read().unwrap().contains_key(blob_id) {
            return Ok(false);
        }
        shred_directory(&self.blob_dir(blob_id))?;
        Ok(true)
    }

    /// Used by panic-wipe: wipe everything. Ignores locks; caller must
    /// guarantee no concurrent requests.
    pub fn wipe_everything(&self) -> Result<(), StorageError> {
        let root = self.inner.root.clone();
        if root.exists() {
            shred_directory(&root)?;
            std::fs::create_dir_all(&root)?;
        }
        self.inner.index.write().unwrap().clear();
        *self.inner.disk_bytes_used.write().unwrap() = 0;
        Ok(())
    }

    // --- Meta encryption helpers ---

    fn write_meta(&self, meta: &Meta) -> Result<(), StorageError> {
        let plaintext = meta.encode_plaintext();
        let mut nonce_bytes = [0u8; 12];
        getrandom::getrandom(&mut nonce_bytes)
            .map_err(|e| StorageError::Crypto(format!("getrandom: {e}")))?;
        let cipher = Aes256Gcm::new_from_slice(&self.inner.meta_key)
            .map_err(|e| StorageError::Crypto(format!("aes-gcm key: {e}")))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        // P7-BLOB-08 fix (2026-05-12): bind blob_id as Additional Authenticated
        // Data so a disk-tamper swap (rename one blob's meta.bin to another's
        // dir) yields a decrypt failure rather than a silent semantic mismatch.
        let ciphertext = cipher
            .encrypt(
                nonce,
                aes_gcm::aead::Payload { msg: plaintext.as_ref(), aad: &meta.blob_id },
            )
            .map_err(|e| StorageError::Crypto(format!("aes-gcm seal: {e}")))?;

        let mut buf = Vec::with_capacity(META_MAGIC.len() + 12 + ciphertext.len());
        buf.extend_from_slice(META_MAGIC);
        buf.extend_from_slice(&nonce_bytes);
        buf.extend_from_slice(&ciphertext);

        atomic_write(&self.meta_path(&meta.blob_id), &buf)?;
        Ok(())
    }

    fn read_meta(&self, path: &Path) -> Result<Meta, StorageError> {
        let mut f = std::fs::File::open(path)?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;
        if buf.len() < META_MAGIC.len() + 12 + 16 {
            return Err(StorageError::MetaCorrupt);
        }
        if &buf[..META_MAGIC.len()] != META_MAGIC {
            return Err(StorageError::MetaCorrupt);
        }
        // P7-BLOB-08 fix: derive expected blob_id from the on-disk path
        // (parent directory name is the hex blob_id) and feed it as AAD.
        // Any mismatch between file location and ciphertext yields MetaCorrupt.
        let blob_id_from_path = path
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .and_then(crate::util::parse_blob_id)
            .ok_or(StorageError::MetaCorrupt)?;

        let nonce = Nonce::from_slice(&buf[META_MAGIC.len()..META_MAGIC.len() + 12]);
        let ciphertext = &buf[META_MAGIC.len() + 12..];
        let cipher = Aes256Gcm::new_from_slice(&self.inner.meta_key)
            .map_err(|e| StorageError::Crypto(format!("aes-gcm key: {e}")))?;
        let plaintext = cipher
            .decrypt(
                nonce,
                aes_gcm::aead::Payload { msg: ciphertext, aad: &blob_id_from_path },
            )
            .map_err(|_| StorageError::MetaCorrupt)?;
        let meta = Meta::decode_plaintext(&plaintext)?;
        // Defence-in-depth: blob_id encoded in plaintext must also match.
        if meta.blob_id != blob_id_from_path {
            return Err(StorageError::MetaCorrupt);
        }
        Ok(meta)
    }
}

/// Size in bytes the server expects on the wire for chunk `is_last`.
fn expected_chunk_size(meta: &Meta, is_last: bool) -> usize {
    if !is_last {
        return FULL_CHUNK_WIRE_BYTES;
    }
    // Chunk 0's plaintext includes a 32-byte header (§5.4). Total plaintext
    // bytes across all chunks == 32 + bucket.byte_size() (the sealer builds
    // `header || padded_plaintext`). Non-final chunks carry exactly 256 KB
    // of plaintext each; the final chunk carries the remainder.
    let total_plain = meta.bucket.byte_size() as usize + crate::util::CHUNK0_HEADER_BYTES;
    let full_count = total_plain / PLAINTEXT_CHUNK_BYTES;
    let last_plain = total_plain - full_count * PLAINTEXT_CHUNK_BYTES;
    if last_plain == 0 {
        // Exact fit — the "last" chunk is a full chunk.
        FULL_CHUNK_WIRE_BYTES
    } else {
        last_plain + crate::util::AEAD_FRAME_OVERHEAD
    }
}

fn derive_meta_key(master_key: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(b"LadonBlobKeyDerivation-v1"), master_key);
    let mut out = [0u8; 32];
    hk.expand(b"blob-meta-v1", &mut out).expect("32 bytes");
    out
}

/// The parent directory must already exist. F17: this path used to create
/// it, which let a late chunk write recreate a deleted blob's directory.
/// Blob directories come into being only in `create_blob`. Chunk writes and
/// `write_meta` from create/seal run under the per-blob lock for a blob whose
/// directory exists (create makes it first, delete removes the index entry
/// before shredding); reindex writes into a directory it is iterating, at
/// open, before the storage is shared.
fn atomic_write(target: &Path, data: &[u8]) -> Result<(), StorageError> {
    let parent = target
        .parent()
        .ok_or_else(|| StorageError::Io(std::io::Error::other("no parent")))?;

    let mut tmp = parent.to_path_buf();
    let mut random_suffix = [0u8; 8];
    getrandom::getrandom(&mut random_suffix)
        .map_err(|e| StorageError::Crypto(format!("getrandom: {e}")))?;
    let suffix = hex::encode(random_suffix);
    tmp.push(format!(
        ".{}.{}.tmp",
        target.file_name().unwrap().to_string_lossy(),
        suffix
    ));

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let mut f = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }

    std::fs::rename(&tmp, target)?;

    #[cfg(unix)]
    {
        // Best-effort directory fsync. Not all platforms allow opening a dir
        // for fsync (macOS is fine; Linux is fine). Ignore errors.
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }

    Ok(())
}

/// Overwrite every regular file within `dir` with zero bytes, fsync, then
/// unlink. Finally remove the directory tree.
fn shred_directory(dir: &Path) -> Result<(), StorageError> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in walk(dir)? {
        if entry.is_file() {
            shred_file(&entry)?;
        }
    }
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

fn shred_file(path: &Path) -> Result<(), StorageError> {
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return Ok(()),
    };
    let len = meta.len();
    if len > 0 {
        let mut f = std::fs::OpenOptions::new().write(true).open(path)?;
        let zero = vec![0u8; SHRED_BLOCK_BYTES];
        let mut remaining = len as usize;
        while remaining > 0 {
            let n = remaining.min(zero.len());
            f.write_all(&zero[..n])?;
            remaining -= n;
        }
        f.sync_all()?;
    }
    std::fs::remove_file(path)?;
    Ok(())
}

fn walk(dir: &Path) -> Result<Vec<PathBuf>, StorageError> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(p) = stack.pop() {
        let md = std::fs::metadata(&p)?;
        if md.is_dir() {
            for e in std::fs::read_dir(&p)? {
                stack.push(e?.path());
            }
        } else {
            out.push(p);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn fresh_storage() -> (BlobStorage, TempDir) {
        let tmp = TempDir::new().unwrap();
        let mk = [0x33; 32];
        let storage = BlobStorage::open(tmp.path().join("data"), &mk).unwrap();
        (storage, tmp)
    }

    fn make_meta(id: [u8; 16], chunk_count: u16, bucket: Bucket) -> Meta {
        Meta {
            blob_id: id,
            chunk_count,
            bucket,
            created_at: now_secs(),
            expires_at: now_secs() + 3600,
            sealed: false,
            reserved: [0u8; 32],
        }
    }

    #[test]
    fn create_and_read_meta() {
        let (storage, _tmp) = fresh_storage();
        let meta = make_meta([0xa1; 16], 1, Bucket::B1KB);
        storage.create_blob(meta.clone(), u64::MAX).unwrap();
        let got = storage.get_meta(&[0xa1; 16]).unwrap();
        assert_eq!(got.blob_id, meta.blob_id);
        assert_eq!(got.chunk_count, meta.chunk_count);
        assert!(!got.sealed);
    }

    #[test]
    fn reopen_zeroes_a_legacy_uploader_hash() {
        // A2 stage 1: a meta file written before the upload identity was
        // removed carries a non-zero uploader hash. Reopening the storage
        // must rewrite it on disk, not only in the in-memory index.
        let tmp = TempDir::new().unwrap();
        let mk = [0x33; 32];
        let root = tmp.path().join("data");
        let mut legacy = make_meta([0xa9; 16], 1, Bucket::B1KB);
        legacy.reserved = [0x5c; 32];
        {
            let storage = BlobStorage::open(root.clone(), &mk).unwrap();
            storage.create_blob(legacy, u64::MAX).unwrap();
            let path = storage.meta_path(&[0xa9; 16]);
            assert_eq!(storage.read_meta(&path).unwrap().reserved, [0x5c; 32]);
        }
        let reopened = BlobStorage::open(root, &mk).unwrap();
        assert_eq!(reopened.get_meta(&[0xa9; 16]).unwrap().reserved, [0u8; 32]);
        let path = reopened.meta_path(&[0xa9; 16]);
        assert_eq!(reopened.read_meta(&path).unwrap().reserved, [0u8; 32], "rewritten on disk");
    }

    #[test]
    fn create_duplicate_rejected() {
        let (storage, _tmp) = fresh_storage();
        let meta = make_meta([0xa2; 16], 1, Bucket::B1KB);
        storage.create_blob(meta.clone(), u64::MAX).unwrap();
        let err = storage.create_blob(meta, u64::MAX).unwrap_err();
        assert!(matches!(err, StorageError::AlreadyExists));
    }

    fn bucket_single_chunk_frame(bucket: Bucket) -> Vec<u8> {
        // Single-chunk bucket: plaintext = 32-byte header + bucket bytes.
        // Non-final chunks would be FULL_CHUNK_WIRE_BYTES; here the only
        // chunk *is* the last and holds `32 + bucket.byte_size()` plaintext.
        let plain = 32 + bucket.byte_size() as usize;
        vec![0u8; plain + crate::util::AEAD_FRAME_OVERHEAD]
    }

    #[test]
    fn put_and_get_chunk_roundtrip() {
        let (storage, _tmp) = fresh_storage();
        let id = [0xa3; 16];
        let bucket = Bucket::B1KB;
        let meta = make_meta(id, 1, bucket);
        storage.create_blob(meta, u64::MAX).unwrap();
        let frame = bucket_single_chunk_frame(bucket);
        storage.put_chunk(&id, 0, &frame).unwrap();
        let got = storage.get_chunk(&id, 0).unwrap();
        assert_eq!(got, frame);
    }

    #[test]
    fn put_with_wrong_size_rejected() {
        let (storage, _tmp) = fresh_storage();
        let id = [0xa4; 16];
        let meta = make_meta(id, 1, Bucket::B1KB);
        storage.create_blob(meta, u64::MAX).unwrap();
        let err = storage.put_chunk(&id, 0, &[0u8; 10]).unwrap_err();
        assert!(matches!(err, StorageError::ChunkOutOfRange));
    }

    #[test]
    fn put_conflict_detected() {
        let (storage, _tmp) = fresh_storage();
        let id = [0xa5; 16];
        let bucket = Bucket::B1KB;
        let meta = make_meta(id, 1, bucket);
        storage.create_blob(meta, u64::MAX).unwrap();
        let mut frame = bucket_single_chunk_frame(bucket);
        storage.put_chunk(&id, 0, &frame).unwrap();
        frame[0] ^= 0x01;
        let err = storage.put_chunk(&id, 0, &frame).unwrap_err();
        assert!(matches!(err, StorageError::ChunkConflict));
    }

    #[test]
    fn seal_blocks_further_writes() {
        let (storage, _tmp) = fresh_storage();
        let id = [0xa6; 16];
        let bucket = Bucket::B1KB;
        let meta = make_meta(id, 1, bucket);
        storage.create_blob(meta, u64::MAX).unwrap();
        let frame = bucket_single_chunk_frame(bucket);
        storage.put_chunk(&id, 0, &frame).unwrap();
        storage.seal(&id).unwrap();
        let err = storage.put_chunk(&id, 0, &frame).unwrap_err();
        assert!(matches!(err, StorageError::Sealed));
    }

    #[test]
    fn delete_removes_everything() {
        let (storage, _tmp) = fresh_storage();
        let id = [0xa7; 16];
        let bucket = Bucket::B1KB;
        let meta = make_meta(id, 1, bucket);
        storage.create_blob(meta, u64::MAX).unwrap();
        let frame = bucket_single_chunk_frame(bucket);
        storage.put_chunk(&id, 0, &frame).unwrap();
        storage.delete_blob(&id).unwrap();
        assert!(storage.get_meta(&id).is_none());
        let err = storage.get_chunk(&id, 0).unwrap_err();
        assert!(matches!(err, StorageError::NotFound));
    }

    #[test]
    fn disk_quota_enforced() {
        let (storage, _tmp) = fresh_storage();
        let meta = make_meta([0xa8; 16], 1, Bucket::B1KB);
        let err = storage.create_blob(meta, 100).unwrap_err();
        assert!(matches!(err, StorageError::DiskFull));
    }

    /// P7-BLOB-03: parallel create_blob with the same id must not produce
    /// orphaned on-disk state. Exactly one creator wins, all others see
    /// AlreadyExists, and the index/disk accounting must be consistent.
    #[test]
    fn parallel_create_same_id_no_orphan() {
        use std::sync::Arc;
        use std::sync::Barrier;
        use std::thread;

        let (storage, _tmp) = fresh_storage();
        let storage = Arc::new(storage);
        let id = [0xab; 16];
        let bucket = Bucket::B1KB;
        let threads = 8usize;
        let barrier = Arc::new(Barrier::new(threads));

        let handles: Vec<_> = (0..threads)
            .map(|_| {
                let s = storage.clone();
                let b = barrier.clone();
                thread::spawn(move || {
                    b.wait();
                    s.create_blob(make_meta(id, 1, bucket), u64::MAX)
                })
            })
            .collect();

        let mut ok = 0;
        let mut already = 0;
        let mut other = 0;
        for h in handles {
            match h.join().unwrap() {
                Ok(()) => ok += 1,
                Err(StorageError::AlreadyExists) => already += 1,
                Err(_) => other += 1,
            }
        }

        assert_eq!(ok, 1, "exactly one creator must win");
        assert_eq!(already, threads - 1, "all others must see AlreadyExists");
        assert_eq!(other, 0, "no other error class allowed");

        // disk accounting must equal exactly one blob's bucket size
        assert_eq!(storage.disk_bytes_used(), bucket.byte_size());
        assert!(storage.get_meta(&id).is_some());
    }

    /// F16/F17: a chunk upload that races a delete of the same blob must not
    /// resurrect the blob directory. The test holds the per-blob lock, lets
    /// the uploader thread take its handle on that lock (strong count 3:
    /// map + test + uploader), removes the blob exactly like `delete_blob`,
    /// then releases the lock. The upload must fail with NotFound and leave
    /// no directory behind.
    #[test]
    fn put_chunk_racing_delete_does_not_resurrect_dir() {
        let (storage, _tmp) = fresh_storage();
        let id = [0xac; 16];
        let bucket = Bucket::B1KB;
        storage.create_blob(make_meta(id, 1, bucket), u64::MAX).unwrap();
        let frame = bucket_single_chunk_frame(bucket);

        let lock = storage.write_lock_for(&id);
        let guard = lock.lock().unwrap();

        let uploader = {
            let s = storage.clone();
            let f = frame.clone();
            std::thread::spawn(move || s.put_chunk(&id, 0, &f))
        };
        while Arc::strong_count(&lock) < 3 {
            std::thread::yield_now();
        }

        // Body of delete_blob, executed while the lock is held.
        storage.inner.index.write().unwrap().remove(&id);
        shred_directory(&storage.blob_dir(&id)).unwrap();
        drop(guard);

        let res = uploader.join().unwrap();
        assert!(matches!(res, Err(StorageError::NotFound)), "got {res:?}");
        assert!(!storage.blob_dir(&id).exists(), "deleted blob dir must stay gone");
    }

    /// F16/F17 leftovers: a blob directory without an index entry is
    /// shredded by GC once it is older than one hour, a young one is kept,
    /// and an indexed blob is never touched by the orphan sweep.
    #[test]
    fn gc_shreds_old_unindexed_dirs_only() {
        let (storage, _tmp) = fresh_storage();
        let live = [0xad; 16];
        let mut meta = make_meta(live, 1, Bucket::B1KB);
        meta.expires_at = now_secs() + 10 * 24 * 3600;
        storage.create_blob(meta, u64::MAX).unwrap();
        storage.seal(&live).unwrap();

        let orphan = [0xae; 16];
        let dir = storage.blob_dir(&orphan);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("chunk_00000"), [7u8; 64]).unwrap();

        let now = now_secs();
        crate::gc::run_once_at(&storage, now).unwrap();
        assert!(dir.exists(), "young orphan is kept (create may be in flight)");

        crate::gc::run_once_at(&storage, now + 3600 + 1).unwrap();
        assert!(!dir.exists(), "old orphan is shredded");
        assert!(storage.blob_dir(&live).exists(), "indexed blob untouched");
        assert!(storage.get_meta(&live).is_some());
    }

    /// F22: per-blob write locks must not accumulate one entry per blob id
    /// ever seen. After a GC cycle no lock of a finished operation remains.
    #[test]
    fn gc_prunes_unused_write_locks() {
        let (storage, _tmp) = fresh_storage();
        for i in 0..1000u32 {
            let mut id = [0u8; 16];
            id[..4].copy_from_slice(&i.to_be_bytes());
            storage.create_blob(make_meta(id, 1, Bucket::B1KB), u64::MAX).unwrap();
            storage.delete_blob(&id).unwrap();
        }
        crate::gc::run_once(&storage).unwrap();
        assert_eq!(storage.write_lock_count(), 0);
    }

    /// F22: a lock somebody still holds survives the prune, so a waiter
    /// and a later caller keep serialising on the same mutex.
    #[test]
    fn prune_keeps_held_write_lock() {
        let (storage, _tmp) = fresh_storage();
        let id = [0xaf; 16];
        let held = storage.write_lock_for(&id);
        storage.prune_write_locks();
        assert_eq!(storage.write_lock_count(), 1);
        assert!(Arc::ptr_eq(&held, &storage.write_lock_for(&id)));
        drop(held);
        storage.prune_write_locks();
        assert_eq!(storage.write_lock_count(), 0);
    }

    #[test]
    fn reindex_round_trip() {
        let tmp = TempDir::new().unwrap();
        let mk = [0x44; 32];
        let root = tmp.path().join("data");
        {
            let storage = BlobStorage::open(root.clone(), &mk).unwrap();
            let meta = make_meta([0xa9; 16], 1, Bucket::B1KB);
            storage.create_blob(meta, u64::MAX).unwrap();
            let frame = bucket_single_chunk_frame(Bucket::B1KB);
            storage.put_chunk(&[0xa9; 16], 0, &frame).unwrap();
            storage.seal(&[0xa9; 16]).unwrap();
        }
        let storage = BlobStorage::open(root, &mk).unwrap();
        let meta = storage.get_meta(&[0xa9; 16]).unwrap();
        assert!(meta.sealed);
        assert_eq!(meta.chunk_count, 1);
    }
}
