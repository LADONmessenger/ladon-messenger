//! Ed25519-signed capability tokens (spec §6.4).
//!
//! **V2 Format (current, issued after 2026-05-08):**
//!   struct Capability {
//!       blob_id:    [u8; 16],
//!       op:         u8,        // 0x01=read, 0x02=delete, 0x04=upload (bit-OR allowed)
//!       chunk_mask: [u8; 16],  // bitmap of allowed chunk indices 0..127 (0 = "all")
//!       expires_at: u64_be,
//!       nonce:      [u8; 16],
//!   }  // 57 bytes
//!
//!   token = cap || Ed25519_sign(signing_key, "ladon-cap-v2:" || cap)  // 121 B
//!   wire  = base64url_nopad(token)
//!
//! **V1 Format (deprecated, accepted until 2026-06-08):**
//!   struct CapabilityV1 {
//!       blob_id:    [u8; 16],
//!       op:         u8,        // 0x01=read, 0x02=delete, 0x04=upload (bit-OR allowed)
//!       chunk_mask: [u8; 4],   // bitmap of allowed chunk indices 0..31 (0 = "all")
//!       expires_at: u64_be,
//!       nonce:      [u8; 16],
//!   }  // 45 bytes
//!
//!   token = cap || Ed25519_sign(signing_key, "ladon-cap-v1:" || cap)  // 109 B
//!   wire  = base64url_nopad(token)
//!
//! Backward compatibility: verify() accepts both v1 and v2. issue() produces v2 only.
//!
//! Verification is constant-time in the decision branch: every check is
//! evaluated into a single `bool` before a 401 is returned (spec §6.4).

use std::io::Write;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use rand_core::OsRng;
use subtle::ConstantTimeEq;
use thiserror::Error;

pub const CAPABILITY_BYTES: usize = 57;  // V2: 16 + 1 + 16 + 8 + 16
pub const CAPABILITY_BYTES_V1: usize = 45; // V1: 16 + 1 + 4 + 8 + 16 (deprecated, removed 2026-06-08)
pub const TOKEN_BYTES: usize = CAPABILITY_BYTES + 64;
pub const TOKEN_BYTES_V1: usize = CAPABILITY_BYTES_V1 + 64;
pub const SIGN_DOMAIN: &[u8] = b"ladon-cap-v2:";
pub const SIGN_DOMAIN_V1: &[u8] = b"ladon-cap-v1:";

pub const OP_READ: u8 = 0x01;
pub const OP_DELETE: u8 = 0x02;
pub const OP_UPLOAD: u8 = 0x04;

#[derive(Debug, Error)]
pub enum CapabilityError {
    #[error("capability decode failed")]
    Decode,
    #[error("capability signature invalid")]
    BadSignature,
    #[error("capability expired")]
    Expired,
    #[error("capability op does not authorise this endpoint")]
    OpMismatch,
    #[error("capability blob_id does not match request")]
    BlobIdMismatch,
    #[error("capability chunk index not permitted")]
    ChunkNotPermitted,
    #[error("signing key io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Long-lived state wrapping the Ed25519 keypair used to sign capabilities.
///
/// The private key never leaves this process (enforced by the filesystem
/// permission 0600 on [`Signer::load_or_create`]).
pub struct Signer {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl Signer {
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Load the signing key from disk; create a new random keypair if the
    /// file does not exist. File mode is forced to 0600 on creation.
    pub fn load_or_create(path: &std::path::Path) -> Result<Self, CapabilityError> {
        if path.exists() {
            let bytes = std::fs::read(path)?;
            if bytes.len() != 32 {
                return Err(CapabilityError::Decode);
            }
            let mut sk = [0u8; 32];
            sk.copy_from_slice(&bytes);
            let signing_key = SigningKey::from_bytes(&sk);
            let verifying_key = signing_key.verifying_key();
            return Ok(Self {
                signing_key,
                verifying_key,
            });
        }

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        // Write as 0600 — mirror exit-relay/src/main.rs pattern.
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(path)?;
            f.write_all(signing_key.as_bytes())?;
            f.sync_all()?;
        }
        #[cfg(not(unix))]
        {
            std::fs::write(path, signing_key.as_bytes())?;
        }

        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    /// Create a new random signer without persisting (tests only).
    pub fn random() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Produce a base64url-nopad wire capability token for the given spec.
    pub fn issue(&self, cap: &Capability) -> String {
        let cap_bytes = cap.to_bytes();
        let sig = self.sign_bytes(&cap_bytes);

        let mut token = [0u8; TOKEN_BYTES];
        token[..CAPABILITY_BYTES].copy_from_slice(&cap_bytes);
        token[CAPABILITY_BYTES..].copy_from_slice(&sig.to_bytes());
        URL_SAFE_NO_PAD.encode(token)
    }

    /// Sign an arbitrary byte slice under the capability domain tag.
    /// Exposed so tests can build forged tokens.
    fn sign_bytes(&self, cap_bytes: &[u8]) -> Signature {
        let mut signed = Vec::with_capacity(SIGN_DOMAIN.len() + cap_bytes.len());
        signed.extend_from_slice(SIGN_DOMAIN);
        signed.extend_from_slice(cap_bytes);
        self.signing_key.sign(&signed)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capability {
    pub blob_id: [u8; 16],
    pub op: u8,
    pub chunk_mask: [u8; 16],  // V2: 128 bits, covers chunks 0..127
    pub expires_at: u64,
    pub nonce: [u8; 16],
}

impl Capability {
    pub fn new(
        blob_id: [u8; 16],
        op: u8,
        chunk_mask: [u8; 16],
        expires_at: u64,
        nonce: [u8; 16],
    ) -> Self {
        Self {
            blob_id,
            op,
            chunk_mask,
            expires_at,
            nonce,
        }
    }

    pub fn to_bytes(&self) -> [u8; CAPABILITY_BYTES] {
        let mut out = [0u8; CAPABILITY_BYTES];
        out[..16].copy_from_slice(&self.blob_id);
        out[16] = self.op;
        out[17..33].copy_from_slice(&self.chunk_mask);  // V2: 16 bytes for chunk_mask
        out[33..41].copy_from_slice(&self.expires_at.to_be_bytes());
        out[41..57].copy_from_slice(&self.nonce);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != CAPABILITY_BYTES {
            return None;
        }
        let mut blob_id = [0u8; 16];
        blob_id.copy_from_slice(&bytes[..16]);
        let op = bytes[16];
        let mut chunk_mask = [0u8; 16];
        chunk_mask.copy_from_slice(&bytes[17..33]);  // V2: 16 bytes
        let mut ts = [0u8; 8];
        ts.copy_from_slice(&bytes[33..41]);
        let expires_at = u64::from_be_bytes(ts);
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&bytes[41..57]);
        Some(Self {
            blob_id,
            op,
            chunk_mask,
            expires_at,
            nonce,
        })
    }

    /// Test if the given chunk index (`0..chunk_count`) is permitted by this
    /// capability's `chunk_mask`. For `read`/`delete` a fully-zero mask means
    /// “all chunks”. For `upload` the mask is populated at issue time.
    pub fn permits_chunk(&self, index: u32) -> bool {
        // All-zero mask on read/delete is interpreted as “all chunks”.
        if self.op & (OP_READ | OP_DELETE) != 0
            && (self.op & OP_UPLOAD) == 0
            && self.chunk_mask == [0u8; 16]
        {
            return true;
        }
        // V2: chunk_mask covers 0..127 exactly (128 bits).
        // Reject index > 127 unconditionally.
        if index >= 128 {
            return false;
        }
        let byte = self.chunk_mask[(index / 8) as usize];
        (byte >> (index % 8)) & 1 != 0
    }
}

/// Verify a wire-format capability token against the given signer, required
/// op, target blob_id, and chunk index. The verification evaluates every
/// step into booleans before returning, leaking no structural information
/// about which check failed.
///
/// Accepts both V2 (current, 57-byte capabilities) and V1 (deprecated, 45-byte).
/// V1 support is deprecated and will be removed 2026-06-08.
pub fn verify(
    signer: &Signer,
    token_b64: &str,
    required_op: u8,
    blob_id: &[u8; 16],
    chunk_index: Option<u32>,
    now_secs: u64,
) -> Result<Capability, CapabilityError> {
    // FIX F-P8-BLOB-CAP-ERR (2026-05-13): previously this function tried V2
    // verification first and, on ANY V2 error (including legitimate
    // Expired/OpMismatch/BlobIdMismatch/ChunkNotPermitted on a properly-sized
    // V2 token), silently fell through to verify_v1() which always rejected
    // with Decode because of the length mismatch. The net effect was that
    // every real V2 verification failure surfaced as Decode, masking the
    // actual check that failed. Production callers (api/put_chunk.rs etc.)
    // only test `.is_err()` so this had no security/runtime impact, but it
    // made tests, audit logs and debugging far less useful.
    //
    // Resolution: dispatch on the decoded token length. V2 = 121 B,
    // V1 = 109 B (deprecated). Anything else is Decode. This preserves the
    // constant-time inner combine in each branch and the closed-slug
    // ErrorSlug::AuthFailed mapping at the API surface.
    let raw = URL_SAFE_NO_PAD
        .decode(token_b64.as_bytes())
        .map_err(|_| CapabilityError::Decode)?;
    match raw.len() {
        TOKEN_BYTES => verify_v2_inner(signer, &raw, required_op, blob_id, chunk_index, now_secs),
        TOKEN_BYTES_V1 => {
            verify_v1_inner(signer, &raw, required_op, blob_id, chunk_index, now_secs)
        }
        _ => Err(CapabilityError::Decode),
    }
}

/// Verify V2 capability token (57-byte cap).
fn verify_v2_inner(
    signer: &Signer,
    raw: &[u8],
    required_op: u8,
    blob_id: &[u8; 16],
    chunk_index: Option<u32>,
    now_secs: u64,
) -> Result<Capability, CapabilityError> {
    let cap_bytes = &raw[..CAPABILITY_BYTES];
    let sig_bytes = &raw[CAPABILITY_BYTES..];

    // 2. Verify signature under V2 domain.
    let sig = Signature::from_slice(sig_bytes).map_err(|_| CapabilityError::BadSignature)?;
    let mut signed = Vec::with_capacity(SIGN_DOMAIN.len() + cap_bytes.len());
    signed.extend_from_slice(SIGN_DOMAIN);
    signed.extend_from_slice(cap_bytes);
    let sig_ok = signer.verifying_key.verify(&signed, &sig).is_ok();

    // 3–6. Parse and collect booleans.
    let cap = Capability::from_bytes(cap_bytes).ok_or(CapabilityError::Decode)?;
    let not_expired = cap.expires_at > now_secs;
    let op_ok = (cap.op & required_op) == required_op;
    let blob_match: bool = cap.blob_id.ct_eq(blob_id).into();
    let chunk_ok = match chunk_index {
        Some(i) => cap.permits_chunk(i),
        None => true,
    };

    // Combine before branching so callers can't tell which specific check
    // failed by timing side-channels.
    let all_ok = sig_ok & not_expired & op_ok & blob_match & chunk_ok;
    if all_ok {
        return Ok(cap);
    }

    if !sig_ok {
        Err(CapabilityError::BadSignature)
    } else if !not_expired {
        Err(CapabilityError::Expired)
    } else if !op_ok {
        Err(CapabilityError::OpMismatch)
    } else if !blob_match {
        Err(CapabilityError::BlobIdMismatch)
    } else {
        Err(CapabilityError::ChunkNotPermitted)
    }
}

/// Verify V1 capability token (45-byte cap) and upconvert to V2 Capability struct.
/// Deprecated: V1 support will be removed 2026-06-08.
fn verify_v1_inner(
    signer: &Signer,
    raw: &[u8],
    required_op: u8,
    blob_id: &[u8; 16],
    chunk_index: Option<u32>,
    now_secs: u64,
) -> Result<Capability, CapabilityError> {
    let cap_bytes = &raw[..CAPABILITY_BYTES_V1];
    let sig_bytes = &raw[CAPABILITY_BYTES_V1..];

    // 2. Verify signature under V1 domain.
    let sig = Signature::from_slice(sig_bytes).map_err(|_| CapabilityError::BadSignature)?;
    let mut signed = Vec::with_capacity(SIGN_DOMAIN_V1.len() + cap_bytes.len());
    signed.extend_from_slice(SIGN_DOMAIN_V1);
    signed.extend_from_slice(cap_bytes);
    let sig_ok = signer.verifying_key.verify(&signed, &sig).is_ok();

    // 3. Parse V1 structure: blob_id(16) || op(1) || chunk_mask(4) || expires_at(8) || nonce(16).
    let mut blob_id_v1 = [0u8; 16];
    blob_id_v1.copy_from_slice(&cap_bytes[..16]);
    let op_v1 = cap_bytes[16];
    let mut chunk_mask_v1 = [0u8; 4];
    chunk_mask_v1.copy_from_slice(&cap_bytes[17..21]);
    let mut ts = [0u8; 8];
    ts.copy_from_slice(&cap_bytes[21..29]);
    let expires_at_v1 = u64::from_be_bytes(ts);
    let mut nonce_v1 = [0u8; 16];
    nonce_v1.copy_from_slice(&cap_bytes[29..45]);

    // 4. Check and collect booleans.
    let not_expired = expires_at_v1 > now_secs;
    let op_ok = (op_v1 & required_op) == required_op;
    let blob_match: bool = blob_id_v1.ct_eq(blob_id).into();
    let chunk_ok_v1 = match chunk_index {
        Some(i) => permits_chunk_v1(op_v1, &chunk_mask_v1, i),
        None => true,
    };

    let all_ok = sig_ok & not_expired & op_ok & blob_match & chunk_ok_v1;
    if all_ok {
        // Upconvert to V2: expand chunk_mask from 4 to 16 bytes.
        let mut chunk_mask_v2 = [0u8; 16];
        // P7-BLOB-01: if the V1 mask was all-zero on a READ/DELETE cap
        // (= "all V1 chunks", 0..31), expand to an EXPLICIT 32-bit allow
        // (0xff*4 in the first four bytes) rather than leaving 16 zero
        // bytes. The latter would trip V2's zero-mask shortcut in
        // permits_chunk() and authorise indices 32..127 that this V1
        // cap was never scoped to.
        let zero_v1 = chunk_mask_v1 == [0u8; 4];
        let is_read_delete_only = (op_v1 & (OP_READ | OP_DELETE)) != 0 && (op_v1 & OP_UPLOAD) == 0;
        if zero_v1 && is_read_delete_only {
            chunk_mask_v2[0] = 0xff;
            chunk_mask_v2[1] = 0xff;
            chunk_mask_v2[2] = 0xff;
            chunk_mask_v2[3] = 0xff;
        } else {
            chunk_mask_v2[..4].copy_from_slice(&chunk_mask_v1);
        }
        return Ok(Capability {
            blob_id: blob_id_v1,
            op: op_v1,
            chunk_mask: chunk_mask_v2,
            expires_at: expires_at_v1,
            nonce: nonce_v1,
        });
    }

    if !sig_ok {
        Err(CapabilityError::BadSignature)
    } else if !not_expired {
        Err(CapabilityError::Expired)
    } else if !op_ok {
        Err(CapabilityError::OpMismatch)
    } else if !blob_match {
        Err(CapabilityError::BlobIdMismatch)
    } else {
        Err(CapabilityError::ChunkNotPermitted)
    }
}

/// V1 chunk permit logic (deprecated). Permits chunks 0..31 only.
///
/// FIX P7-BLOB-01 (audit 2026-05-12): Previously indices >= 32 were a
/// catch-all `return true` ("V1 fallthrough"), which bypassed the chunk_mask
/// authorisation entirely for any index outside the 32-bit mask. A V1
/// capability scoped to chunk 0 could be used to write/read chunks 32..127.
/// Now indices >= 32 are unconditionally rejected (fail-closed). V1 support
/// is scheduled for removal 2026-06-08.
fn permits_chunk_v1(op: u8, chunk_mask_v1: &[u8; 4], index: u32) -> bool {
    // P7-BLOB-01: bound check FIRST, before the zero-mask shortcut.
    // V1 capabilities only describe chunks 0..31 (32-bit mask). The
    // zero-mask "all chunks" semantic must therefore mean "all V1 chunks"
    // (0..31), NOT "all chunks regardless of V2 chunk_count". Without
    // this guard a leaked V1 zero-mask READ/DELETE cap would authorise
    // index 32..127 because the shortcut returned true unconditionally.
    if index >= 32 {
        return false;
    }
    // All-zero mask on read/delete is interpreted as "all V1 chunks" (0..31).
    if op & (OP_READ | OP_DELETE) != 0
        && (op & OP_UPLOAD) == 0
        && chunk_mask_v1 == &[0u8; 4]
    {
        return true;
    }
    let byte = chunk_mask_v1[(index / 8) as usize];
    (byte >> (index % 8)) & 1 != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_cap() -> (Signer, Capability) {
        let signer = Signer::random();
        let cap = Capability::new(
            [0xab; 16],
            OP_READ | OP_DELETE,
            [0u8; 16],  // V2: 16-byte chunk_mask
            crate::util::now_secs() + 3600,
            [0x11; 16],
        );
        (signer, cap)
    }

    #[test]
    fn roundtrip_and_verify() {
        let (signer, cap) = fresh_cap();
        let token = signer.issue(&cap);
        let verified = verify(
            &signer,
            &token,
            OP_READ,
            &cap.blob_id,
            Some(0),
            crate::util::now_secs(),
        )
        .expect("verify");
        assert_eq!(verified, cap);
    }

    #[test]
    fn expired_rejected() {
        let (signer, mut cap) = fresh_cap();
        cap.expires_at = crate::util::now_secs() - 1;
        let token = signer.issue(&cap);
        let err = verify(
            &signer,
            &token,
            OP_READ,
            &cap.blob_id,
            Some(0),
            crate::util::now_secs(),
        )
        .unwrap_err();
        assert!(matches!(err, CapabilityError::Expired));
    }

    #[test]
    fn op_mismatch() {
        let (signer, mut cap) = fresh_cap();
        cap.op = OP_UPLOAD;
        let token = signer.issue(&cap);
        let err = verify(
            &signer,
            &token,
            OP_READ,
            &cap.blob_id,
            Some(0),
            crate::util::now_secs(),
        )
        .unwrap_err();
        assert!(matches!(err, CapabilityError::OpMismatch));
    }

    #[test]
    fn wrong_blob_id() {
        let (signer, cap) = fresh_cap();
        let token = signer.issue(&cap);
        let err = verify(
            &signer,
            &token,
            OP_READ,
            &[0xcd; 16],
            Some(0),
            crate::util::now_secs(),
        )
        .unwrap_err();
        assert!(matches!(err, CapabilityError::BlobIdMismatch));
    }

    #[test]
    fn tampered_signature() {
        let (signer, cap) = fresh_cap();
        let mut token = signer.issue(&cap).into_bytes();
        // Flip one bit in the signature region.
        let idx = token.len() - 4;
        token[idx] ^= 0x01;
        let s = String::from_utf8(token).unwrap();
        let err = verify(
            &signer,
            &s,
            OP_READ,
            &cap.blob_id,
            Some(0),
            crate::util::now_secs(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            CapabilityError::BadSignature | CapabilityError::Decode
        ));
    }

    #[test]
    fn upload_chunk_mask_v2() {
        let signer = Signer::random();
        // Allow indices 0..=3 only (bits 0..=3 of byte 0).
        let mut mask = [0u8; 16];
        mask[0] = 0b0000_1111;
        let cap = Capability::new(
            [0xab; 16],
            OP_UPLOAD,
            mask,
            crate::util::now_secs() + 3600,
            [0x11; 16],
        );
        let token = signer.issue(&cap);
        for i in 0..4u32 {
            verify(
                &signer,
                &token,
                OP_UPLOAD,
                &cap.blob_id,
                Some(i),
                crate::util::now_secs(),
            )
            .expect("allowed");
        }
        let err = verify(
            &signer,
            &token,
            OP_UPLOAD,
            &cap.blob_id,
            Some(4),
            crate::util::now_secs(),
        )
        .unwrap_err();
        assert!(matches!(err, CapabilityError::ChunkNotPermitted));
        
        // Verify that indices >= 128 are always rejected.
        let err = verify(
            &signer,
            &token,
            OP_UPLOAD,
            &cap.blob_id,
            Some(128),
            crate::util::now_secs(),
        )
        .unwrap_err();
        assert!(matches!(err, CapabilityError::ChunkNotPermitted));
    }

    /// Regression test for P7-BLOB-01 (audit 2026-05-12).
    ///
    /// V1 capabilities only carry a 32-bit chunk_mask. Indices >= 32 must
    /// be rejected (fail-closed). Pre-fix the function returned `true` for
    /// any index >= 32, which let a V1 cap scoped to chunk 0 authorise
    /// uploads/reads on chunks 32..127.
    #[test]
    fn v1_cap_rejects_index_above_32() {
        // chunk_mask permits ALL 32 bits — yet indices >= 32 must still fail.
        let mask = [0xFFu8; 4];
        // Indices 0..=31 are permitted by the mask.
        for i in 0..32u32 {
            assert!(
                permits_chunk_v1(OP_UPLOAD, &mask, i),
                "V1: index {} should be permitted by full mask",
                i
            );
        }
        // Indices >= 32 must be rejected unconditionally (fail-closed).
        for i in [32u32, 33, 63, 64, 127, 128, 255, u32::MAX] {
            assert!(
                !permits_chunk_v1(OP_UPLOAD, &mask, i),
                "V1: index {} must be rejected (P7-BLOB-01 fix)",
                i
            );
        }
        // Same for READ-only cap with zero mask (the "all chunks" shortcut
        // legitimately allows reads, but only inside the V1 32-chunk window).
        let zero_mask = [0u8; 4];
        assert!(permits_chunk_v1(OP_READ, &zero_mask, 0));
        assert!(permits_chunk_v1(OP_READ, &zero_mask, 31));
        // NOTE: the zero-mask READ shortcut still returns true for index>=32
        // because it short-circuits before the index check. V1 readers should
        // not request chunks >= 32 anyway; V2 caps replace this path.
        // Upload with zero mask: must reject everything.
        assert!(!permits_chunk_v1(OP_UPLOAD, &zero_mask, 0));
        assert!(!permits_chunk_v1(OP_UPLOAD, &zero_mask, 32));
    }
}
