use std::sync::Arc;

use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::response::Response;
use axum::Json;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use crate::capability::{Capability, OP_DELETE, OP_READ, OP_UPLOAD};
use crate::errors::{err_response, ErrorSlug};
use crate::storage::Meta;
use crate::util::{
    expected_chunk_count, now_secs, parse_blob_id, Bucket, MAX_CHUNK_COUNT, MAX_TTL_SECS,
    MIN_TTL_SECS,
};
use crate::AppState;

const CAP_LIFETIME_SECS: u64 = 15 * 60;

/// P7-BLOB-02: hard ceiling on READ and DELETE capability lifetimes.
/// Previously the read/delete cap inherited the full blob retention TTL
/// (`req.expires_at`, up to MAX_TTL_SECS=48h). A leaked cap was thus
/// usable for the entire retention window with no identity binding.
/// 24 h covers the realistic offline-recipient pickup case while
/// shrinking the leak-exposure window 2x; clients that need to read
/// or delete after 24 h must request a fresh cap.
///
/// (Identity binding — making the cap a function of the recipient's
/// UAK — is the cleaner long-term fix but is wire-breaking; tracked
/// for a future cap-v3 format. This TTL ceiling reduces the
/// exposure window in the meantime.)
const READ_DELETE_CAP_MAX_LIFETIME_SECS: u64 = 24 * 3600;

#[derive(Deserialize)]
pub struct InitRequest {
    pub blob_id: String,
    pub chunk_count: u16,
    pub bucket: u8,
    pub expires_at: u64,
}

#[derive(Serialize)]
pub struct InitResponse {
    pub upload_cap: String,
    pub read_cap: String,
    pub delete_cap: String,
    pub chunk_size: u32,
}

pub async fn handle(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    // P7-BLOB-13: respect X-Forwarded-For when behind trusted proxy.
    let client = crate::util::client_ip(&headers, peer.ip());
    // 1. Per-IP rate limit.
    if !state.ip_limiter.check(client) {
        return err_response(ErrorSlug::RateLimit);
    }

    // 2. No identity (Addendum A2 stage 1). Until then every init carried
    //    the uploader's long-term Ed25519 key in `x-ladon-identity` with an
    //    HMAC under a per-identity secret, and per-identity limits keyed on
    //    it. Provisioning was open — any freshly generated key got a
    //    secret — so those limits never bound an abuser, while the header
    //    gave the operator a stable pseudonym for every upload (scan F9).
    //    Headers an older client still sends are ignored. The limits that
    //    bind are the per-IP limit above, the 80 % disk guard (step 4), the
    //    bucket-bound chunk count and the 48 h maximum TTL.

    // 3. Parse body.
    let req: InitRequest = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return err_response(ErrorSlug::BadRequest),
    };
    let blob_id = match parse_blob_id(&req.blob_id) {
        Some(v) => v,
        None => return err_response(ErrorSlug::BadRequest),
    };
    if req.chunk_count == 0 || req.chunk_count > MAX_CHUNK_COUNT {
        return err_response(ErrorSlug::BadRequest);
    }
    let bucket = match Bucket::from_u8(req.bucket) {
        Some(v) => v,
        None => return err_response(ErrorSlug::BadRequest),
    };
    // #12: bind chunk_count to the declared bucket. The sealer always chunks
    // `header || plaintext-padded-to-bucket`, so chunk_count is a deterministic
    // function of the bucket (see `util::expected_chunk_count`). Without this an
    // authenticated client could declare a tiny bucket — which is all that quota
    // and disk accounting charge — while uploading up to MAX_CHUNK_COUNT full
    // chunks (put_chunk forces each non-final chunk to FULL_CHUNK_WIRE_BYTES),
    // a ~34,000x disk/quota amplification that also defeats the 80% disk guard.
    if req.chunk_count as usize != expected_chunk_count(bucket) {
        return err_response(ErrorSlug::BadRequest);
    }
    let now = now_secs();
    let ttl = req.expires_at.saturating_sub(now);
    if !(MIN_TTL_SECS..=MAX_TTL_SECS).contains(&ttl) {
        return err_response(ErrorSlug::BadRequest);
    }

    // 4. Disk quota: reject at ≥80% projected utilisation (spec §8.3).
    let used = state.storage.disk_bytes_used();
    let limit = state.config.disk_quota_bytes;
    let projected = used.saturating_add(bucket.byte_size());
    // projected > 0.8 * limit  ⇔  projected * 10 > limit * 8  (overflow-safe
    // because projected and limit are both bounded u64 disk-size figures).
    if projected.saturating_mul(10) > limit.saturating_mul(8) {
        return err_response(ErrorSlug::StorageFull);
    }

    // 5. Create on disk.
    let meta = Meta {
        blob_id,
        chunk_count: req.chunk_count,
        bucket,
        created_at: now,
        expires_at: req.expires_at,
        sealed: false,
        reserved: [0u8; 32],
    };
    if let Err(e) = state.storage.create_blob(meta, limit) {
        return match e {
            crate::storage::StorageError::AlreadyExists => err_response(ErrorSlug::Conflict),
            crate::storage::StorageError::DiskFull => err_response(ErrorSlug::StorageFull),
            _ => err_response(ErrorSlug::ServerError),
        };
    }

    // 6. Issue capabilities. Upload mask covers all requested chunks.
    let cap_expires = now + CAP_LIFETIME_SECS;
    let upload_mask = build_upload_mask(req.chunk_count);
    let upload_cap_tok = state.capability_signer.issue(&Capability::new(
        blob_id,
        OP_UPLOAD,
        upload_mask,
        cap_expires,
        random_nonce(),
    ));
    // P7-BLOB-02: cap read/delete TTLs to a hard 24h ceiling. The blob
    // itself may live longer (up to req.expires_at = 48h); clients
    // needing read/delete past 24h must request a fresh cap.
    let rd_cap_expires = req.expires_at.min(now + READ_DELETE_CAP_MAX_LIFETIME_SECS);
    let read_cap_tok = state.capability_signer.issue(&Capability::new(
        blob_id,
        OP_READ,
        [0u8; 16],  // V2: 128-bit chunk_mask
        rd_cap_expires,
        random_nonce(),
    ));
    let delete_cap_tok = state.capability_signer.issue(&Capability::new(
        blob_id,
        OP_DELETE,
        [0u8; 16],  // V2: 128-bit chunk_mask
        rd_cap_expires,
        random_nonce(),
    ));

    let resp = InitResponse {
        upload_cap: upload_cap_tok,
        read_cap: read_cap_tok,
        delete_cap: delete_cap_tok,
        chunk_size: crate::util::FULL_CHUNK_WIRE_BYTES as u32,
    };
    (axum::http::StatusCode::OK, Json(resp)).into_response()
}

fn build_upload_mask(chunk_count: u16) -> [u8; 16] {
    // P7-BLOB-04: chunk_count is bounded to MAX_CHUNK_COUNT (=128) at the
    // request validator above, so all requested chunks fit in the 128-bit
    // mask. The `min(128)` below is a defence-in-depth clamp against any
    // future change to MAX_CHUNK_COUNT without also widening the mask.
    let mut mask = [0u8; 16];
    let upto = chunk_count.min(128) as usize;
    for i in 0..upto {
        mask[i / 8] |= 1 << (i % 8);
    }
    mask
}

fn random_nonce() -> [u8; 16] {
    let mut out = [0u8; 16];
    getrandom::getrandom(&mut out).expect("getrandom");
    out
}

use axum::response::IntoResponse;

#[cfg(test)]
mod tests {
    use super::build_upload_mask;
    use crate::util::MAX_CHUNK_COUNT;

    #[test]
    fn p7_blob_04_max_chunk_count_fits_in_mask() {
        // The capability chunk_mask is 16 bytes = 128 bits. The ceiling
        // must never exceed this width or higher-indexed chunks could not
        // be authorised. Checked at compile time.
        const _: () = assert!(MAX_CHUNK_COUNT <= 128);
    }

    #[test]
    fn p7_blob_04_upload_mask_full_at_ceiling() {
        let mask = build_upload_mask(MAX_CHUNK_COUNT);
        // All bits up to MAX_CHUNK_COUNT must be set.
        for i in 0..MAX_CHUNK_COUNT {
            let byte = mask[(i / 8) as usize];
            let bit = byte & (1 << (i % 8));
            assert!(bit != 0, "bit {i} must be set");
        }
        // Bits past MAX_CHUNK_COUNT (if any) must be zero. Empty while the
        // ceiling is exactly 128; written so it still bites if it shrinks.
        for i in (0..128).filter(|&i| i >= MAX_CHUNK_COUNT) {
            let byte = mask[(i / 8) as usize];
            let bit = byte & (1 << (i % 8));
            assert!(bit == 0, "bit {i} must be unset");
        }
    }

    #[test]
    fn p7_blob_04_upload_mask_partial() {
        let mask = build_upload_mask(5);
        assert_eq!(mask[0], 0b0001_1111);
        for &b in &mask[1..] {
            assert_eq!(b, 0);
        }
    }
}
