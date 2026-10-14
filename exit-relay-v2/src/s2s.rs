//! S2S HMAC-SHA256 verification for `POST /v2/forward` (Spec §4.7.2).
//!
//! Legacy header: `X-Relay-Signature = hex(HMAC(K, hop || ts || body))`.
//!
//! P7-EXIT-03 introduces an optional `X-Relay-Nonce` header (32 hex chars =
//! 16 random bytes). When present, the HMAC pre-image switches to the
//! tagged, length-prefixed form
//!   `"L1-S2S-v2.1" || u16_be(hop_len) || hop
//!                  || u16_be(ts_len)  || ts
//!                  || nonce_bytes      || body`
//! and the receiver tracks the (hop, nonce) pair to reject replays beyond
//! what timestamp-skew alone can catch.

use std::sync::Mutex;
use std::time::Duration;

use hmac::{Hmac, Mac};
use ladon_relay_core_v2::admission::{PerSecondCap, SeenFifo, SeenInsert};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::error::ApiError;

type HmacSha256 = Hmac<Sha256>;

pub const S2S_DOMAIN_TAG: &[u8] = b"L1-S2S-v2.1";
pub const S2S_NONCE_LEN: usize = 16;

pub struct S2sHeaders<'a> {
    pub hop: &'a str,
    pub timestamp: &'a str,
    pub signature_hex: &'a str,
    /// P7-EXIT-03: optional 16-byte nonce (hex). When `Some`, the receiver
    /// requires uniqueness over (hop, nonce) within the skew window.
    pub nonce_hex: Option<&'a str>,
}

/// Per-hop seen-nonce tracker with bounded TTL, plus the admission cap of
/// `POST /v2/sealed` that sizes it (F8).
///
/// The store used to hold 65,536 entries for 2 × skew = 240 s and prune
/// with an O(n) scan on every insert, so ~273 authenticated requests a
/// second filled it and every later request was refused. Now every request
/// whose HMAC verified takes one admission from a global
/// [`PerSecondCap`] (`SEALED_ADMIT_PER_SEC`) before its nonce is recorded;
/// above it the request is shed with 503. The set holds
/// `SeenFifo::capacity_for(SEALED_ADMIT_PER_SEC, 2 × skew)` entries, what
/// that rate needs, so at an admitted rate it never fills. Full stays a
/// fail-closed refusal as the last safeguard. The skew is not changed.
pub struct S2sNonceStore {
    seen: Mutex<SeenFifo<(String, [u8; S2S_NONCE_LEN])>>,
    admission: PerSecondCap,
}

impl S2sNonceStore {
    pub fn new(ttl: Duration, admit_per_sec: u32) -> Self {
        let ttl_secs = ttl.as_secs();
        Self {
            seen: Mutex::new(SeenFifo::new(
                ttl_secs,
                SeenFifo::<()>::capacity_for(admit_per_sec, ttl_secs),
            )),
            admission: PerSecondCap::new(admit_per_sec),
        }
    }

    /// The store `main` runs: TTL 2 × skew (a nonce stays acceptable for up
    /// to two skews after first use), admission `SEALED_ADMIT_PER_SEC`.
    ///
    /// Memory at the default 120 s skew and full rate: 2,000 × 241 =
    /// 482,000 entries; at roughly 200 B each (hop string and nonce, kept in
    /// the set and in the FIFO) about 0.1 GB of the exit's 8 GiB.
    pub fn for_skew(skew_sec: u64) -> Self {
        Self::new(
            Duration::from_secs(skew_sec.saturating_mul(2)),
            crate::sealed::SEALED_ADMIT_PER_SEC,
        )
    }

    /// Take one admission in second `now_sec`; `false` above the cap.
    pub fn admit(&self, now_sec: u64) -> bool {
        self.admission.try_take(now_sec)
    }

    /// Returns `true` iff the (hop, nonce) pair was not seen before. On
    /// `true`, the pair is recorded. On `false`, this is a replay (or the
    /// store is at capacity).
    pub fn insert_if_new(&self, hop: &str, nonce: &[u8; S2S_NONCE_LEN], now_sec: u64) -> bool {
        let mut g = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        g.insert_if_new((hop.to_owned(), *nonce), now_sec) == SeenInsert::Fresh
    }

    pub fn capacity(&self) -> usize { self.seen.lock().unwrap_or_else(|e| e.into_inner()).capacity() }
    pub fn len(&self) -> usize { self.seen.lock().unwrap_or_else(|e| e.into_inner()).len() }
    pub fn is_empty(&self) -> bool { self.seen.lock().unwrap_or_else(|e| e.into_inner()).is_empty() }
}

pub fn verify_s2s(
    key: &[u8; 32],
    headers: &S2sHeaders<'_>,
    body: &[u8],
    now_sec: u64,
    skew_sec: u64,
    nonce_store: &S2sNonceStore,
    accept_legacy: bool,
) -> Result<(), ApiError> {
    // Parse and validate timestamp.
    let ts: u64 = headers.timestamp.parse().map_err(|_| ApiError::S2sAuth)?;
    let drift = ts.abs_diff(now_sec);
    if drift > skew_sec {
        return Err(ApiError::S2sAuth);
    }
    // Decode signature.
    let provided = hex::decode(headers.signature_hex).map_err(|_| ApiError::S2sAuth)?;
    if provided.len() != 32 {
        return Err(ApiError::S2sAuth);
    }

    // Compute expected over the appropriate pre-image.
    //
    // FIX F-P8-S2S-NONCE-POLLUTION (2026-05-13): the nonce-store
    // `insert_if_new` MUST run AFTER the HMAC verify. Inserting
    // unauthenticated (hop, nonce) tuples lets any caller that can hit
    // the internet-facing `POST /v2/forward` saturate the bounded
    // 16,384-entry store with random nonces (rejected at HMAC, but the
    // nonce stays for the full TTL), causing legitimate S2S traffic to
    // be rejected with E-S2S-AUTH ("store full"). Blob-relay's
    // `api/init.rs` uses the same hardening pattern with an explicit
    // comment.
    let (expected, parsed_nonce) = if let Some(nonce_hex) = headers.nonce_hex {
        // Tagged + nonce form.
        let nonce_raw = hex::decode(nonce_hex).map_err(|_| ApiError::S2sAuth)?;
        if nonce_raw.len() != S2S_NONCE_LEN {
            return Err(ApiError::S2sAuth);
        }
        let mut nonce = [0u8; S2S_NONCE_LEN];
        nonce.copy_from_slice(&nonce_raw);

        let hop_bytes = headers.hop.as_bytes();
        let ts_bytes = headers.timestamp.as_bytes();
        if hop_bytes.len() > u16::MAX as usize || ts_bytes.len() > u16::MAX as usize {
            return Err(ApiError::S2sAuth);
        }
        let mut mac = HmacSha256::new_from_slice(key).map_err(|_| ApiError::Internal)?;
        mac.update(S2S_DOMAIN_TAG);
        mac.update(&(hop_bytes.len() as u16).to_be_bytes());
        mac.update(hop_bytes);
        mac.update(&(ts_bytes.len() as u16).to_be_bytes());
        mac.update(ts_bytes);
        mac.update(&nonce);
        mac.update(body);
        (mac.finalize().into_bytes(), Some(nonce))
    } else {
        // Legacy form, gated by accept_legacy.
        if !accept_legacy {
            return Err(ApiError::S2sAuth);
        }
        let mut mac = HmacSha256::new_from_slice(key).map_err(|_| ApiError::Internal)?;
        mac.update(headers.hop.as_bytes());
        mac.update(headers.timestamp.as_bytes());
        mac.update(body);
        (mac.finalize().into_bytes(), None)
    };

    if !bool::from(expected.as_slice().ct_eq(&provided)) {
        return Err(ApiError::S2sAuth);
    }

    // F8: authenticated — take one admission before recording anything.
    // Above the cap the request is shed (503); that is what keeps the nonce
    // store below its capacity. Unauthenticated requests never get here.
    if !nonce_store.admit(now_sec) {
        tracing::warn!(stage = "s2s-admit", "S2S admission cap reached");
        return Err(ApiError::Unavailable);
    }

    // HMAC is valid — NOW record the nonce. A replayed (hop, nonce) pair
    // from a previously-valid signature is rejected here; an unauthenticated
    // caller never reaches this point and cannot pollute the store.
    if let Some(nonce) = parsed_nonce {
        if !nonce_store.insert_if_new(headers.hop, &nonce, now_sec) {
            tracing::warn!(
                stage = "s2s-nonce",
                hop = headers.hop,
                "S2S nonce replay or store full (post-HMAC)"
            );
            return Err(ApiError::S2sAuth);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> S2sNonceStore {
        S2sNonceStore::new(Duration::from_secs(120), 100)
    }

    #[test]
    fn s2s_roundtrip_legacy() {
        let key = [0xABu8; 32];
        let body = b"hello";
        let hop = "entry-ch1";
        let ts = "1000";
        let mut mac = HmacSha256::new_from_slice(&key).unwrap();
        mac.update(hop.as_bytes());
        mac.update(ts.as_bytes());
        mac.update(body);
        let sig = hex::encode(mac.finalize().into_bytes());
        let h = S2sHeaders { hop, timestamp: ts, signature_hex: &sig, nonce_hex: None };
        assert!(verify_s2s(&key, &h, body, 1000, 60, &store(), true).is_ok());
    }

    #[test]
    fn s2s_legacy_rejected_when_flag_off() {
        let key = [0xABu8; 32];
        let body = b"hello";
        let hop = "e";
        let ts = "1000";
        let mut mac = HmacSha256::new_from_slice(&key).unwrap();
        mac.update(hop.as_bytes()); mac.update(ts.as_bytes()); mac.update(body);
        let sig = hex::encode(mac.finalize().into_bytes());
        let h = S2sHeaders { hop, timestamp: ts, signature_hex: &sig, nonce_hex: None };
        assert!(verify_s2s(&key, &h, body, 1000, 60, &store(), false).is_err());
    }

    fn sign_tagged(key: &[u8; 32], hop: &str, ts: &str, nonce: &[u8; 16], body: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(key).unwrap();
        mac.update(S2S_DOMAIN_TAG);
        mac.update(&(hop.len() as u16).to_be_bytes());
        mac.update(hop.as_bytes());
        mac.update(&(ts.len() as u16).to_be_bytes());
        mac.update(ts.as_bytes());
        mac.update(nonce);
        mac.update(body);
        hex::encode(mac.finalize().into_bytes())
    }

    #[test]
    fn s2s_tagged_roundtrip() {
        let key = [3u8; 32];
        let body = b"hello";
        let hop = "e1";
        let ts = "1000";
        let nonce = [9u8; 16];
        let sig = sign_tagged(&key, hop, ts, &nonce, body);
        let nh = hex::encode(nonce);
        let h = S2sHeaders { hop, timestamp: ts, signature_hex: &sig, nonce_hex: Some(&nh) };
        let s = store();
        assert!(verify_s2s(&key, &h, body, 1000, 60, &s, false).is_ok());
    }

    #[test]
    fn s2s_tagged_nonce_replay_rejected() {
        let key = [3u8; 32];
        let body = b"hello";
        let hop = "e1";
        let ts = "1000";
        let nonce = [9u8; 16];
        let sig = sign_tagged(&key, hop, ts, &nonce, body);
        let nh = hex::encode(nonce);
        let h = S2sHeaders { hop, timestamp: ts, signature_hex: &sig, nonce_hex: Some(&nh) };
        let s = store();
        assert!(verify_s2s(&key, &h, body, 1000, 60, &s, false).is_ok());
        // second time → replay
        assert!(verify_s2s(&key, &h, body, 1000, 60, &s, false).is_err());
    }

    /// FIX F-P8-S2S-NONCE-POLLUTION (2026-05-13): an unauthenticated caller
    /// (wrong HMAC) MUST NOT pollute the nonce store. After a forged-sig
    /// request, the same (hop, nonce) tuple must remain usable by a
    /// legitimate signer.
    #[test]
    fn s2s_bad_hmac_does_not_pollute_nonce_store() {
        let key = [3u8; 32];
        let body = b"hello";
        let hop = "e1";
        let ts = "1000";
        let nonce = [9u8; 16];
        let nh = hex::encode(nonce);
        let store = store();

        // 1. Forged request: same nonce, GARBAGE signature.
        let bogus_sig = hex::encode([0xAAu8; 32]);
        let bad = S2sHeaders {
            hop,
            timestamp: ts,
            signature_hex: &bogus_sig,
            nonce_hex: Some(&nh),
        };
        assert!(verify_s2s(&key, &bad, body, 1000, 60, &store, false).is_err());
        assert_eq!(store.len(), 0, "nonce store must NOT contain forged-sig nonce");

        // 2. Legitimate request with the SAME nonce must still succeed.
        let good_sig = sign_tagged(&key, hop, ts, &nonce, body);
        let good = S2sHeaders {
            hop,
            timestamp: ts,
            signature_hex: &good_sig,
            nonce_hex: Some(&nh),
        };
        assert!(verify_s2s(&key, &good, body, 1000, 60, &store, false).is_ok());
        assert_eq!(store.len(), 1, "nonce store must record only the verified nonce");
    }

    /// F8: the store as `main` builds it never fills while the Entry stays
    /// at the admitted rate (2,000 distinct authenticated nonces a second,
    /// for two TTLs). Before, it held 65,536 entries for 240 s, so ~273
    /// requests/s filled it and every later request was refused.
    #[test]
    fn nonce_store_never_fills_at_the_admitted_rate() {
        let skew = 120u64;
        let st = S2sNonceStore::for_skew(skew);
        let rate = crate::sealed::SEALED_ADMIT_PER_SEC as u64;
        let t0 = 1_000_000u64;
        for sec in 0..2 * (2 * skew + 1) {
            for i in 0..rate {
                let mut n = [0u8; S2S_NONCE_LEN];
                n[..8].copy_from_slice(&sec.to_be_bytes());
                n[8..].copy_from_slice(&i.to_be_bytes());
                assert!(st.insert_if_new("entry1", &n, t0 + sec), "fresh nonce refused at second {sec}, #{i}");
            }
        }
    }

    /// F8 / N3: admitted rate × (TTL + 1) ≤ capacity, for any configured
    /// skew (LADON_S2S_SKEW_SEC / LADON_FETCH_SKEW_SEC are env-settable).
    #[test]
    fn capacity_covers_the_admitted_rate_for_any_skew() {
        use crate::sealed::{MAX_SIG_VERIFIES_PER_SEC, SEALED_ADMIT_PER_SEC};
        for skew in [1u64, 30, 60, 120, 600, 3_600] {
            let s2s = S2sNonceStore::for_skew(skew);
            assert!(s2s.capacity() as u64 >= SEALED_ADMIT_PER_SEC as u64 * (2 * skew + 1), "s2s, skew {skew}");
            let fetch = crate::verify::FetchReplayStore::for_skew(skew);
            assert!(fetch.capacity() as u64 >= MAX_SIG_VERIFIES_PER_SEC as u64 * (2 * skew + 1), "fetch, skew {skew}");
        }
    }

    /// F8: authenticated requests beyond the cap in one second are shed with
    /// Unavailable and record no nonce; forged ones never spend admissions;
    /// the next second has a fresh budget.
    #[test]
    fn admission_cap_sheds_above_the_rate_and_ignores_forgeries() {
        let key = [3u8; 32];
        let s = store(); // 100 per second
        let call = |i: u32, now: u64, forged: bool| {
            let mut nonce = [0u8; 16];
            nonce[..4].copy_from_slice(&i.to_be_bytes());
            let nh = hex::encode(nonce);
            let ts = now.to_string();
            let sig = if forged { hex::encode([0xAA; 32]) } else { sign_tagged(&key, "e1", &ts, &nonce, b"b") };
            let h = S2sHeaders { hop: "e1", timestamp: &ts, signature_hex: &sig, nonce_hex: Some(&nh) };
            verify_s2s(&key, &h, b"b", now, 60, &s, false)
        };
        for i in 0..500 {
            assert!(matches!(call(i, 1_000, true), Err(ApiError::S2sAuth)));
        }
        for i in 0..100 {
            assert!(call(i, 1_000, false).is_ok(), "forgeries did not spend the budget");
        }
        assert!(matches!(call(100, 1_000, false), Err(ApiError::Unavailable)));
        assert_eq!(s.len(), 100, "a shed request records no nonce");
        assert!(call(101, 1_001, false).is_ok(), "next second");
    }

    #[test]
    fn s2s_skew_rejected() {
        let key = [1u8; 32];
        let body = b"x";
        let mut mac = HmacSha256::new_from_slice(&key).unwrap();
        mac.update(b"e"); mac.update(b"100"); mac.update(body);
        let sig = hex::encode(mac.finalize().into_bytes());
        let h = S2sHeaders { hop: "e", timestamp: "100", signature_hex: &sig, nonce_hex: None };
        assert!(verify_s2s(&key, &h, body, 10_000, 60, &store(), true).is_err());
    }

    #[test]
    fn s2s_wrong_key() {
        let key = [1u8; 32];
        let body = b"x";
        let mut mac = HmacSha256::new_from_slice(&[2u8; 32]).unwrap();
        mac.update(b"e"); mac.update(b"100"); mac.update(body);
        let sig = hex::encode(mac.finalize().into_bytes());
        let h = S2sHeaders { hop: "e", timestamp: "100", signature_hex: &sig, nonce_hex: None };
        assert!(verify_s2s(&key, &h, body, 100, 60, &store(), true).is_err());
    }
}
