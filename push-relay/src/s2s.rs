//! S2S HMAC verification — identical scheme to `exit-relay-v2::s2s` so that
//! exit-relays can re-use a single hop-id/HMAC pattern when calling out to
//! either the next exit-relay or the push-relay. Spec §4.7.2 line 444.
//!
//! Legacy wire format:
//!   `X-Relay-Signature = hex(HMAC-SHA256(K, hop || ts || body))`.
//!
//! P7-PUSH-04 fix (2026-05-12): mirror P7-EXIT-03 — introduce an optional
//! `X-Relay-Nonce` header (32 hex = 16 random bytes). When present, the
//! HMAC pre-image switches to the tagged + length-prefixed form
//!   `"L1-S2S-v2.1" || u16_be(hop_len) || hop
//!                  || u16_be(ts_len)  || ts
//!                  || nonce_bytes      || body`
//! and the receiver tracks the `(hop, nonce)` pair to reject replays beyond
//! what timestamp-skew alone can catch. Legacy form is still accepted when
//! `accept_legacy=true` (controlled by `LADON_PUSH_S2S_ACCEPT_LEGACY`,
//! default true) to allow zero-downtime rollout with older exit-relays.

use std::collections::HashMap;
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
    /// P7-PUSH-04: optional 16-byte nonce (hex). When `Some`, receiver
    /// requires uniqueness over (hop, nonce) within the skew window.
    pub nonce_hex: Option<&'a str>,
}

/// Per-hop seen-nonce tracker with bounded TTL, plus the per-hop admission
/// cap that sizes it (F44).
///
/// The store used to hold 65,536 entries for 300 s and prune with an O(n)
/// scan on every insert: one exit at ~220 authenticated calls a second
/// filled it, after which every call was refused. Now every authenticated
/// request first takes one admission from its hop's [`PerSecondCap`]; the
/// set holds `hops × SeenFifo::capacity_for(per_hop_per_sec, ttl)` entries,
/// exactly what that rate needs, so at an admitted rate it never fills.
/// Full remains a fail-closed refusal (clock stepped back, or a bug).
pub struct S2sNonceStore {
    seen: Mutex<SeenFifo<(String, [u8; S2S_NONCE_LEN])>>,
    /// One cap per hop that holds an S2S key; fixed at construction.
    admission: HashMap<String, PerSecondCap>,
}

impl S2sNonceStore {
    pub fn new<'a>(
        ttl: Duration,
        per_hop_per_sec: u32,
        hops: impl IntoIterator<Item = &'a str>,
    ) -> Self {
        let admission: HashMap<String, PerSecondCap> = hops
            .into_iter()
            .map(|h| (h.to_owned(), PerSecondCap::new(per_hop_per_sec)))
            .collect();
        let ttl_secs = ttl.as_secs();
        let capacity = SeenFifo::<()>::capacity_for(per_hop_per_sec, ttl_secs)
            .saturating_mul(admission.len());
        Self {
            seen: Mutex::new(SeenFifo::new(ttl_secs, capacity)),
            admission,
        }
    }

    /// Take one admission for `hop` in second `now_sec`. `false` above the
    /// per-hop rate or for a hop without a cap (fail-closed).
    pub fn admit(&self, hop: &str, now_sec: u64) -> bool {
        self.admission.get(hop).is_some_and(|c| c.try_take(now_sec))
    }

    /// Returns `true` iff the (hop, nonce) pair was not seen before. On
    /// `true`, the pair is recorded. On `false`, this is a replay (or the
    /// store is at capacity — fail-closed).
    pub fn insert_if_new(
        &self,
        hop: &str,
        nonce: &[u8; S2S_NONCE_LEN],
        now_sec: u64,
    ) -> bool {
        let mut g = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        g.insert_if_new((hop.to_owned(), *nonce), now_sec) == SeenInsert::Fresh
    }

    pub fn capacity(&self) -> usize {
        self.seen.lock().unwrap_or_else(|e| e.into_inner()).capacity()
    }

    pub fn len(&self) -> usize {
        self.seen.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
    pub fn is_empty(&self) -> bool {
        self.seen.lock().unwrap_or_else(|e| e.into_inner()).is_empty()
    }
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
    let ts: u64 = headers.timestamp.parse().map_err(|_| ApiError::S2sAuth)?;
    let drift = ts.abs_diff(now_sec);
    if drift > skew_sec {
        return Err(ApiError::S2sAuth);
    }
    let provided = hex::decode(headers.signature_hex).map_err(|_| ApiError::S2sAuth)?;
    if provided.len() != 32 {
        return Err(ApiError::S2sAuth);
    }

    let expected;
    let parsed_nonce: Option<[u8; S2S_NONCE_LEN]>;
    // FIX F-P8-S2S-NONCE-POLLUTION (2026-05-13): the nonce-store
    // `insert_if_new` MUST run AFTER the HMAC verify. Inserting
    // unauthenticated (hop, nonce) tuples lets any caller that can reach
    // the internet-facing push-relay S2S endpoints saturate the bounded
    // nonce store with random nonces (rejected at HMAC but cached until
    // TTL), causing legitimate exit→push traffic to be rejected with
    // E-S2S-AUTH ("store full"). Blob-relay's `api/init.rs` uses the
    // same hardening pattern with an explicit comment.
    if let Some(nonce_hex) = headers.nonce_hex {
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
        expected = mac.finalize().into_bytes();
        parsed_nonce = Some(nonce);
    } else {
        if !accept_legacy {
            return Err(ApiError::S2sAuth);
        }
        let mut mac = HmacSha256::new_from_slice(key).map_err(|_| ApiError::Internal)?;
        mac.update(headers.hop.as_bytes());
        mac.update(headers.timestamp.as_bytes());
        mac.update(body);
        expected = mac.finalize().into_bytes();
        parsed_nonce = None;
    }

    if !bool::from(expected.as_slice().ct_eq(&provided)) {
        return Err(ApiError::S2sAuth);
    }

    // F44: authenticated — take one admission from this hop's per-second
    // cap before recording anything. Above it the call is shed (503); that
    // is what keeps the nonce store below its capacity.
    if !nonce_store.admit(headers.hop, now_sec) {
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
        S2sNonceStore::new(Duration::from_secs(120), 100, ["ch1", "e", "h"])
    }

    fn legacy_sign(key: &[u8; 32], hop: &str, ts: &str, body: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(key).unwrap();
        mac.update(hop.as_bytes());
        mac.update(ts.as_bytes());
        mac.update(body);
        hex::encode(mac.finalize().into_bytes())
    }

    fn tagged_sign(
        key: &[u8; 32],
        hop: &str,
        ts: &str,
        nonce: &[u8; S2S_NONCE_LEN],
        body: &[u8],
    ) -> String {
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
    fn legacy_roundtrip_when_accepted() {
        let key = [0xABu8; 32];
        let body = b"abc";
        let sig = legacy_sign(&key, "ch1", "1000", body);
        let h = S2sHeaders {
            hop: "ch1",
            timestamp: "1000",
            signature_hex: &sig,
            nonce_hex: None,
        };
        assert!(verify_s2s(&key, &h, body, 1000, 60, &store(), true).is_ok());
    }

    #[test]
    fn legacy_rejected_when_disabled() {
        let key = [1u8; 32];
        let sig = legacy_sign(&key, "e", "1000", b"x");
        let h = S2sHeaders {
            hop: "e",
            timestamp: "1000",
            signature_hex: &sig,
            nonce_hex: None,
        };
        assert!(verify_s2s(&key, &h, b"x", 1000, 60, &store(), false).is_err());
    }

    #[test]
    fn tagged_roundtrip_records_nonce() {
        let key = [9u8; 32];
        let nonce = [7u8; S2S_NONCE_LEN];
        let nh = hex::encode(nonce);
        let sig = tagged_sign(&key, "ch1", "1000", &nonce, b"abc");
        let s = store();
        let h = S2sHeaders {
            hop: "ch1",
            timestamp: "1000",
            signature_hex: &sig,
            nonce_hex: Some(&nh),
        };
        assert!(verify_s2s(&key, &h, b"abc", 1000, 60, &s, false).is_ok());
        // Second call with same nonce must be rejected.
        let h2 = S2sHeaders {
            hop: "ch1",
            timestamp: "1000",
            signature_hex: &sig,
            nonce_hex: Some(&nh),
        };
        assert!(verify_s2s(&key, &h2, b"abc", 1000, 60, &s, false).is_err());
    }

    #[test]
    fn tagged_skew_rejected() {
        let key = [3u8; 32];
        let nonce = [0u8; S2S_NONCE_LEN];
        let nh = hex::encode(nonce);
        let sig = tagged_sign(&key, "e", "100", &nonce, b"x");
        let h = S2sHeaders {
            hop: "e",
            timestamp: "100",
            signature_hex: &sig,
            nonce_hex: Some(&nh),
        };
        assert!(verify_s2s(&key, &h, b"x", 10_000, 60, &store(), false).is_err());
    }

    #[test]
    fn tagged_body_tamper_rejected() {
        let key = [9u8; 32];
        let nonce = [1u8; S2S_NONCE_LEN];
        let nh = hex::encode(nonce);
        let sig = tagged_sign(&key, "h", "100", &nonce, b"original");
        let h = S2sHeaders {
            hop: "h",
            timestamp: "100",
            signature_hex: &sig,
            nonce_hex: Some(&nh),
        };
        assert!(verify_s2s(&key, &h, b"tampered", 100, 60, &store(), false).is_err());
    }

    /// F44: the store of a running push relay never fills while one exit
    /// stays at the admitted rate (here 4,000 distinct authenticated nonces
    /// a second, for two TTLs). Before, it held 65,536 entries for 300 s, so
    /// ~220 calls/s from one exit filled it and every later call was
    /// refused as "replay or store full".
    #[test]
    fn nonce_store_never_fills_at_the_admitted_rate() {
        use std::sync::Arc;
        let mut keys = HashMap::new();
        keys.insert("exit1".to_string(), [0u8; 32]);
        let st = crate::state::PushState::new(
            Arc::new(keys),
            "push1".to_string(),
            Arc::new(crate::apns::RecordingApnsSender::new()),
        );
        let rate = crate::state::S2S_ADMIT_PER_HOP_PER_SEC as u64;
        let ttl = 2 * st.s2s_skew_sec;
        assert_eq!(st.s2s_nonce_store.capacity() as u64, rate * (ttl + 1), "one hop");
        let t0 = 1_000_000u64;
        for sec in 0..2 * (ttl + 1) {
            for i in 0..rate {
                let mut n = [0u8; S2S_NONCE_LEN];
                n[..8].copy_from_slice(&sec.to_be_bytes());
                n[8..].copy_from_slice(&i.to_be_bytes());
                assert!(
                    st.s2s_nonce_store.insert_if_new("exit1", &n, t0 + sec),
                    "fresh nonce refused at second {sec}, #{i}"
                );
            }
        }
    }

    /// F44: authenticated calls beyond the per-hop cap in one second are
    /// shed with Unavailable and record no nonce; another hop is unaffected,
    /// and the next second has a fresh budget.
    #[test]
    fn admission_cap_is_per_hop_and_per_second() {
        let key = [5u8; 32];
        let s = store(); // 100 per hop and second
        let call = |hop: &str, i: u32, now: u64| {
            let mut nonce = [0u8; S2S_NONCE_LEN];
            nonce[..4].copy_from_slice(&i.to_be_bytes());
            nonce[4] = hop.len() as u8;
            let nh = hex::encode(nonce);
            let ts = now.to_string();
            let sig = tagged_sign(&key, hop, &ts, &nonce, b"x");
            let h = S2sHeaders { hop, timestamp: &ts, signature_hex: &sig, nonce_hex: Some(&nh) };
            verify_s2s(&key, &h, b"x", now, 60, &s, false)
        };
        for i in 0..100 {
            assert!(call("ch1", i, 1_000).is_ok());
        }
        assert!(matches!(call("ch1", 100, 1_000), Err(ApiError::Unavailable)));
        assert_eq!(s.len(), 100, "a shed call records no nonce");
        assert!(call("e", 0, 1_000).is_ok(), "other hop has its own budget");
        assert!(call("ch1", 101, 1_001).is_ok(), "next second");
        assert!(matches!(call("unknown", 0, 1_001), Err(ApiError::Unavailable)), "no cap, no admission");
    }

    /// FIX F-P8-S2S-NONCE-POLLUTION (2026-05-13): an unauthenticated caller
    /// (wrong HMAC) MUST NOT pollute the nonce store. After a forged-sig
    /// request, the same (hop, nonce) tuple must remain usable by a
    /// legitimate signer.
    #[test]
    fn bad_hmac_does_not_pollute_nonce_store() {
        let key = [9u8; 32];
        let body = b"hello";
        let hop = "h";
        let ts = "1000";
        let nonce = [7u8; S2S_NONCE_LEN];
        let nh = hex::encode(nonce);
        let store = store();

        let bogus_sig = hex::encode([0xAAu8; 32]);
        let bad = S2sHeaders {
            hop,
            timestamp: ts,
            signature_hex: &bogus_sig,
            nonce_hex: Some(&nh),
        };
        assert!(verify_s2s(&key, &bad, body, 1000, 60, &store, false).is_err());
        assert_eq!(store.len(), 0, "forged-sig nonce must NOT be recorded");

        let good_sig = tagged_sign(&key, hop, ts, &nonce, body);
        let good = S2sHeaders {
            hop,
            timestamp: ts,
            signature_hex: &good_sig,
            nonce_hex: Some(&nh),
        };
        assert!(verify_s2s(&key, &good, body, 1000, 60, &store, false).is_ok());
        assert_eq!(store.len(), 1, "only the verified nonce must be recorded");
    }
}
