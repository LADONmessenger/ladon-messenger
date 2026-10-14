//! Helpers for forwarding requests to upstream Exits with S2S HMAC signing.

use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;


type HmacSha256 = Hmac<Sha256>;

/// P7-EXIT-03: must match `exit_relay_v2::s2s::S2S_DOMAIN_TAG`.
pub const S2S_DOMAIN_TAG: &[u8] = b"L1-S2S-v2.1";
pub const S2S_NONCE_LEN: usize = 16;

// P7-ENTRY-02 (2026-05-12): the legacy `sign_s2s` pre-image
// `hop || ts || body` had no length prefix, so (hop="a", ts="b")
// would HMAC identically to (hop="ab", ts=""). It was never
// called outside its own back-compat tests — the production call
// path uses `sign_s2s_tagged` which has domain tag + length
// prefixes. The legacy helper is removed to ensure no future code
// can reintroduce the collision hazard.

/// P7-EXIT-03: tagged + length-prefixed pre-image with a per-request nonce.
///
/// Returns `(signature_hex, nonce_hex)`.
pub fn sign_s2s_tagged(
    key: &[u8; 32],
    hop: &str,
    timestamp: &str,
    body: &[u8],
) -> (String, String) {
    let mut nonce = [0u8; S2S_NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    let mut mac = HmacSha256::new_from_slice(key).expect("32-byte key");
    mac.update(S2S_DOMAIN_TAG);
    mac.update(&(hop.len() as u16).to_be_bytes());
    mac.update(hop.as_bytes());
    mac.update(&(timestamp.len() as u16).to_be_bytes());
    mac.update(timestamp.as_bytes());
    mac.update(&nonce);
    mac.update(body);
    (hex::encode(mac.finalize().into_bytes()), hex::encode(nonce))
}

pub fn now_sec_str() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    now.to_string()
}
