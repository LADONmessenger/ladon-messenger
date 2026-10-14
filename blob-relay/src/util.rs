//! Miscellaneous shared helpers.

use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

/// UNIX epoch seconds, saturating to 0 if the system clock is before epoch.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// P7-BLOB-13: client-IP extraction with optional XFF support.
///
/// blob-relay binds loopback by default and sits behind Caddy. If Caddy is
/// running with a `trusted_proxies` directive (or equivalent) AND
/// `LADON_BLOB_BEHIND_PROXY=1` is set, the rightmost `X-Forwarded-For`
/// entry is the authoritative client IP and we should rate-limit on that
/// rather than the loopback `peer.ip()` (which degenerates to a single
/// global bucket). Without the env flag we fall back to `peer.ip()` so
/// development and direct-bind deployments still work.
///
/// Caller is responsible for confirming the deployment really has a
/// trusted proxy in front: enabling this flag without Caddy stripping
/// inbound XFF headers allows a remote client to forge their source IP.
pub fn client_ip(
    headers: &axum::http::HeaderMap,
    peer: IpAddr,
) -> IpAddr {
    let behind_proxy = std::env::var("LADON_BLOB_BEHIND_PROXY")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if !behind_proxy {
        return peer;
    }
    // P7-BLOB-04: only honour X-Forwarded-For when the TCP peer is the
    // trusted loopback proxy (Caddy listening on 127.0.0.1 in front of
    // blob-relay). If the immediate peer is anything else, the request
    // bypassed Caddy and the XFF header is attacker-controlled - ignore
    // it and fall back to the actual peer IP. This prevents IP spoofing
    // by a client who connects directly to a misconfigured blob-relay
    // and forges XFF.
    if !peer.is_loopback() {
        return peer;
    }
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        // Rightmost entry = what trusted Caddy saw as the immediate client.
        if let Some(last) = xff.split(',').next_back() {
            if let Ok(ip) = last.trim().parse::<IpAddr>() {
                return ip;
            }
        }
    }
    peer
}

/// Hex-decode a 16-byte blob id. Returns `None` on any failure.
pub fn parse_blob_id(hex_str: &str) -> Option<[u8; 16]> {
    if hex_str.len() != 32 {
        return None;
    }
    let bytes = hex::decode(hex_str).ok()?;
    if bytes.len() != 16 {
        return None;
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes);
    Some(out)
}

/// Bucket metadata mirrored from `LadonApp/Attachments/AttachmentTypes.swift`.
///
/// Must stay in lockstep with the Swift enum; adding a bucket on either side
/// without the other is a protocol break.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bucket {
    B1KB = 0x01,
    B16KB = 0x02,
    B128KB = 0x03,
    B512KB = 0x04,
    B1MB = 0x05,
    B4MB = 0x06,
    B16MB = 0x07,
    B50MB = 0x08,
}

impl Bucket {
    pub fn from_u8(v: u8) -> Option<Self> {
        use Bucket::*;
        Some(match v {
            0x01 => B1KB,
            0x02 => B16KB,
            0x03 => B128KB,
            0x04 => B512KB,
            0x05 => B1MB,
            0x06 => B4MB,
            0x07 => B16MB,
            0x08 => B50MB,
            _ => return None,
        })
    }

    pub fn byte_size(&self) -> u64 {
        use Bucket::*;
        match self {
            B1KB => 1_024,
            B16KB => 16_384,
            B128KB => 131_072,
            B512KB => 524_288,
            B1MB => 1_048_576,
            B4MB => 4_194_304,
            B16MB => 16_777_216,
            B50MB => 52_428_800,
        }
    }

    pub fn raw(&self) -> u8 {
        *self as u8
    }
}

/// Plaintext chunk size fixed by the spec.
pub const PLAINTEXT_CHUNK_BYTES: usize = 256 * 1024;

/// AEAD overhead per chunk (nonce + tag).
pub const AEAD_FRAME_OVERHEAD: usize = 12 + 16;

/// Full wire size of a non-final 256 KB chunk: nonce + ciphertext + tag.
pub const FULL_CHUNK_WIRE_BYTES: usize = PLAINTEXT_CHUNK_BYTES + AEAD_FRAME_OVERHEAD;

/// Bytes of the chunk-0 plaintext header (§5.4). The sealer builds
/// `header || plaintext-padded-to-bucket` and then splits the result into
/// `PLAINTEXT_CHUNK_BYTES`-sized plaintext chunks. Must match the iOS sealer
/// (`AttachmentSealer`) and the server reconstruction in
/// `storage::expected_chunk_size`.
pub const CHUNK0_HEADER_BYTES: usize = 32;

/// The exact number of chunks a blob of `bucket` must declare.
///
/// Because the sealer always pads to the full bucket size and prepends a
/// fixed [`CHUNK0_HEADER_BYTES`] header, `chunk_count` is a deterministic
/// function of the bucket — never a free parameter. `init` binds the
/// client-supplied `chunk_count` to this value so a tiny bucket (which is
/// what quota/disk accounting charges) cannot be paired with many full-size
/// chunks. Single source of truth for that relationship.
pub fn expected_chunk_count(bucket: Bucket) -> usize {
    let total_plain = bucket.byte_size() as usize + CHUNK0_HEADER_BYTES;
    total_plain.div_ceil(PLAINTEXT_CHUNK_BYTES)
}

/// Hard ceiling on chunk count.
///
/// P7-BLOB-04: must stay ≤ the capability `chunk_mask` width (128 bits).
/// A higher ceiling would let init succeed for blobs whose later chunks
/// cannot be authorised by the upload capability, causing silent upload
/// failures past index 127. Bucket sizes that require more than 128
/// chunks (B50MB needs ~200) are therefore rejected at init time.
pub const MAX_CHUNK_COUNT: u16 = 128;

/// Minimum / maximum TTL the client may request.
pub const MIN_TTL_SECS: u64 = 60;
pub const MAX_TTL_SECS: u64 = 48 * 3600;

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_BUCKETS: [Bucket; 8] = [
        Bucket::B1KB,
        Bucket::B16KB,
        Bucket::B128KB,
        Bucket::B512KB,
        Bucket::B1MB,
        Bucket::B4MB,
        Bucket::B16MB,
        Bucket::B50MB,
    ];

    #[test]
    fn expected_chunk_count_matches_sealer_formula() {
        // ceil((bucket + 32) / 256 KiB). Mirrors AttachmentSealer / the iOS
        // padding to the full bucket plus the 32-byte chunk-0 header.
        assert_eq!(expected_chunk_count(Bucket::B1KB), 1);
        assert_eq!(expected_chunk_count(Bucket::B128KB), 1);
        // 512 KiB + 32 spills the header into a 3rd chunk.
        assert_eq!(expected_chunk_count(Bucket::B512KB), 3);
        assert_eq!(expected_chunk_count(Bucket::B1MB), 5);
        // 16 MiB is exactly 64 full chunks; the +32 header forces a 65th.
        assert_eq!(expected_chunk_count(Bucket::B16MB), 65);
    }

    #[test]
    fn sendable_buckets_fit_chunk_mask_but_b50mb_does_not() {
        // Every bucket the client can actually seal must fit within
        // MAX_CHUNK_COUNT; B50MB intentionally overflows it (see #16 / W3).
        for b in ALL_BUCKETS {
            let needs = expected_chunk_count(b);
            if b == Bucket::B50MB {
                assert!(needs > MAX_CHUNK_COUNT as usize, "B50MB must overflow the 128 mask");
            } else {
                assert!(
                    needs <= MAX_CHUNK_COUNT as usize,
                    "{b:?} needs {needs} chunks > MAX_CHUNK_COUNT"
                );
            }
        }
    }
}
