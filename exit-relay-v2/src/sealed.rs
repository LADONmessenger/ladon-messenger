//! `POST /v2/sealed` — Addendum A2 stage 2 (relay protocol 0x06).
//!
//! The Entry forwards a client's sealed request unchanged (S2S-authenticated
//! as `/v2/forward`). Only this Exit can open it. The kind, the recipient id
//! and every refusal travel inside the AEAD; the HTTP status is 200 whenever
//! the request opened, so the Entry learns nothing from the response either.
//! Every response is the lane's fixed size and is timing-padded.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header::CONTENT_TYPE, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use zeroize::Zeroizing;

use ladon_relay_core_v2::constants::*;
use ladon_relay_core_v2::ids::RecipientId;
use ladon_relay_core_v2::ratelimit::IdentityRateLimiter;
use ladon_relay_core_v2::wire::sealed::{self, status, Kind, SEALED_INNER_ENVELOPE_LEN};
use ladon_relay_core_v2::wire::{Bundle, OuterPlaintext};

use crate::constant_time::{PadDeadline, DEFAULT_PAD_MS};
use crate::error::ApiError;
use crate::handlers::{deliver, put_directory_inner, verify_entry_s2s};
use crate::state::ExitState;
use crate::verify::verify_fetch_ack_sig;

/// FETCH body: rid 32 || ts u64 BE || ack 16 || HSig over the ack pre-image.
const FETCH_BODY_LEN: usize = RECIPIENT_ID_LEN + 8 + FETCH_BATCH_ID_LEN + HSIG_SIG_LEN;

/// A2 §8 [D]: the Entry cannot tell the kinds apart any more, so the Exit
/// limits the expensive ones itself.
///
/// - `MAX_SIG_VERIFIES_PER_SEC`: hybrid-signature verifications (FETCH,
///   DIR_PUT) per second, for the whole exit. Above it the request gets
///   UNAVAILABLE before any verify. A legitimate client causes one verify
///   per lane-F tick (3 s), so the cap covers ~6,000 clients in the
///   foreground at once.
/// - Per recipient, counted only after the signature held (a forged
///   request must not spend the victim's budget): FETCH 120/min (lane F
///   needs 20/min plus catch-up bursts), DIR_PUT 20/min (the former
///   Entry limit for publishing).
pub const MAX_SIG_VERIFIES_PER_SEC: u32 = 2_000;

/// F8: requests per second `/v2/sealed` admits after the Entry's S2S HMAC
/// verified, before the S2S nonce is recorded; above it 503. Every kind
/// counts (the Entry cannot tell them apart, A2 §8). Same value as the
/// verify cap; it sizes the S2S nonce store (`S2sNonceStore::for_skew`).
pub const SEALED_ADMIT_PER_SEC: u32 = MAX_SIG_VERIFIES_PER_SEC;
pub const FETCH_PER_RID_PER_MIN: u32 = 120;
pub const DIR_PUT_PER_RID_PER_MIN: u32 = 20;

pub struct SealedLimits {
    verifies: std::sync::Mutex<(u64, u32)>,
    max_verifies_per_sec: u32,
    pub fetch_per_rid: IdentityRateLimiter,
    pub dir_put_per_rid: IdentityRateLimiter,
}

impl Default for SealedLimits {
    fn default() -> Self {
        Self::with_verify_cap(MAX_SIG_VERIFIES_PER_SEC)
    }
}

impl SealedLimits {
    pub fn with_verify_cap(max_verifies_per_sec: u32) -> Self {
        Self {
            verifies: std::sync::Mutex::new((0, 0)),
            max_verifies_per_sec,
            fetch_per_rid: IdentityRateLimiter::new_with_budget(FETCH_PER_RID_PER_MIN),
            dir_put_per_rid: IdentityRateLimiter::new_with_budget(DIR_PUT_PER_RID_PER_MIN),
        }
    }

    /// Take one verification from this second's budget.
    fn take_verify(&self, now: u64) -> Result<(), ApiError> {
        let mut g = self.verifies.lock().unwrap_or_else(|e| e.into_inner());
        if g.0 != now {
            *g = (now, 0);
        }
        if g.1 >= self.max_verifies_per_sec {
            tracing::warn!("sealed: signature-verify cap reached");
            return Err(ApiError::Unavailable);
        }
        g.1 += 1;
        Ok(())
    }

    #[doc(hidden)]
    pub fn take_verify_for_test(&self, now: u64) -> Result<(), ApiError> {
        self.take_verify(now)
    }

    pub fn cleanup_expired(&self) {
        self.fetch_per_rid.cleanup_expired();
        self.dir_put_per_rid.cleanup_expired();
    }
}

fn now_sec() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub async fn sealed(
    State(s): State<Arc<ExitState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let pad = PadDeadline::new(DEFAULT_PAD_MS);
    let result = sealed_inner(&s, &headers, &body).await;
    pad.delay().await;
    match result {
        Ok(bytes) => {
            let mut r = (StatusCode::OK, bytes).into_response();
            r.headers_mut().insert(CONTENT_TYPE, "application/octet-stream".parse().unwrap());
            r
        }
        Err(e) => e.into_response(),
    }
}

/// Errors here are the only ones the Entry can see: the request did not
/// authenticate or open. Everything after opening becomes a sealed status.
async fn sealed_inner(s: &ExitState, headers: &HeaderMap, body: &[u8]) -> Result<Vec<u8>, ApiError> {
    if sealed::Lane::from_request_len(body.len()).is_none() {
        tracing::warn!(stage = "sealed-size", "sealed Malformed: not a lane size");
        return Err(ApiError::Malformed);
    }
    verify_entry_s2s(s, headers, body)?;
    let opened = sealed::open_request(&s.hkem_keys, s.exit_id.as_bytes(), body).map_err(|e| {
        tracing::warn!(stage = "sealed-open", err = %e, "sealed request did not open");
        match e {
            ladon_relay_core_v2::Error::WrongTarget => ApiError::WrongExit,
            ladon_relay_core_v2::Error::UnsupportedVersion(_) => ApiError::Version,
            _ => ApiError::Malformed,
        }
    })?;
    let now = now_sec();
    let (code, out) = match opened.kind {
        Kind::Cover => (status::OK, Vec::new()),
        Kind::Enqueue => (code_of(enqueue(s, &opened.body).await), Vec::new()),
        Kind::Fetch => match fetch(s, &opened.body, now) {
            Ok(b) => (status::OK, b),
            Err(e) => (code_of(Err(e)), Vec::new()),
        },
        Kind::DirGet => match dir_get(s, &opened.body) {
            Ok(b) => (status::OK, b),
            Err(e) => (code_of(Err(e)), Vec::new()),
        },
        Kind::DirPut => (code_of(dir_put(s, &opened.body, now).await), Vec::new()),
        // The push relay's kind; an Exit never serves it.
        Kind::PushRegister => (status::MALFORMED, Vec::new()),
        // F43: exit -> push kinds; an exit never serves them either.
        Kind::PushNotify | Kind::PushReplicate => (status::MALFORMED, Vec::new()),
    };
    sealed::seal_response(&opened.response_key, s.exit_id.as_bytes(), opened.lane, code, now, &out)
        .map_err(|_| ApiError::Internal)
}

/// Map an outcome to the sealed status byte (A2 §4.2).
fn code_of(r: Result<(), ApiError>) -> u8 {
    match r {
        Ok(()) => status::OK,
        Err(ApiError::Stale) => status::STALE,
        Err(ApiError::Replay) => status::REPLAY,
        Err(ApiError::Rate) => status::RATE,
        Err(ApiError::DeliveryKey) => status::DELIVERY_KEY,
        Err(ApiError::UnknownRecipient) => status::UNKNOWN_RECIPIENT,
        Err(ApiError::FetchSig) => status::FETCH_SIG,
        Err(ApiError::Signature) => status::SIGNATURE,
        Err(ApiError::Unavailable) => status::UNAVAILABLE,
        Err(ApiError::Internal) => status::INTERNAL,
        Err(_) => status::MALFORMED,
    }
}

/// ENQUEUE body = A1 outer plaintext without its flags byte. The inner
/// envelope must be exactly `SEALED_INNER_ENVELOPE_LEN`, so every mailbox
/// item and every fetch response looks the same. Push: A2 §7 rule.
async fn enqueue(s: &ExitState, body: &[u8]) -> Result<(), ApiError> {
    if body.len() != OUTER_PT_HEADER_LEN - 1 + SEALED_INNER_ENVELOPE_LEN {
        tracing::warn!(stage = "sealed-enqueue", "sealed ENQUEUE: wrong body length");
        return Err(ApiError::Malformed);
    }
    // Rebuild the A1 layout (flags byte 0) so the A1 §8 checks run in one place.
    let mut pt = Zeroizing::new(Vec::with_capacity(1 + body.len()));
    pt.push(0);
    pt.extend_from_slice(body);
    let parsed = OuterPlaintext::parse(&pt).map_err(|_| ApiError::Malformed)?;
    deliver(s, parsed).await
}

/// FETCH: the acknowledged fetch of A1 §14 with one envelope per response.
/// Response body = has_more (1) || batch_id (16, zero if none) || count (1)
/// || [len u32 BE || inner envelope].
fn fetch(s: &ExitState, body: &[u8], now: u64) -> Result<Vec<u8>, ApiError> {
    if body.len() != FETCH_BODY_LEN {
        return Err(ApiError::FetchSig);
    }
    let rid = RecipientId::from_bytes(&body[..RECIPIENT_ID_LEN]).expect("32 bytes");
    let ts = u64::from_be_bytes(body[32..40].try_into().expect("8 bytes"));
    let ack: [u8; FETCH_BATCH_ID_LEN] = body[40..56].try_into().expect("16 bytes");
    let sig = &body[56..];

    let bundle_bytes = s.directory.get(&rid).ok_or(ApiError::UnknownRecipient)?;
    let bundle = Bundle::parse(&bundle_bytes).map_err(|_| ApiError::Internal)?;
    s.sealed_limits.take_verify(now)?;
    verify_fetch_ack_sig(&bundle.recipient_hsig_pk, &s.exit_id, &rid, ts, &ack, sig, now, s.fetch_skew_sec)?;
    if s.sealed_limits.fetch_per_rid.check(&hex::encode(rid.as_bytes())).is_err() {
        tracing::warn!("sealed FETCH: per-recipient limit");
        return Err(ApiError::Rate);
    }
    if !s.fetch_replay.insert_if_new(sig, now) {
        return Err(ApiError::Replay);
    }
    let mut next = [0u8; FETCH_BATCH_ID_LEN];
    loop {
        rand_core::RngCore::try_fill_bytes(&mut rand_core::OsRng, &mut next)
            .map_err(|_| ApiError::Internal)?;
        if next != [0u8; FETCH_BATCH_ID_LEN] {
            break;
        }
    }
    let confirmed = if ack == [0u8; FETCH_BATCH_ID_LEN] { None } else { Some(&ack) };
    let f = s.mailbox.fetch_unacked_limited(&rid, confirmed, next, 1);
    // A2 §7: an authenticated fetch is what makes a recipient "online".
    s.online.record_fetch(&rid, now);
    // F19: and it is authenticated activity that keeps the directory entry.
    s.directory.touch(&rid, now);

    let mut out = Vec::with_capacity(1 + FETCH_BATCH_ID_LEN + 1 + 4 + SEALED_INNER_ENVELOPE_LEN);
    out.push(f.has_more as u8);
    out.extend_from_slice(&f.batch_id.unwrap_or([0u8; FETCH_BATCH_ID_LEN]));
    out.push(f.items.len() as u8);
    for it in &f.items {
        out.extend_from_slice(&(it.inner_envelope.len() as u32).to_be_bytes());
        out.extend_from_slice(&it.inner_envelope);
    }
    Ok(out)
}

/// DIR_GET: a contact's signed bundle (the client verifies it).
fn dir_get(s: &ExitState, body: &[u8]) -> Result<Vec<u8>, ApiError> {
    let rid = RecipientId::from_bytes(body).ok_or(ApiError::Malformed)?;
    s.directory.get(&rid).ok_or(ApiError::UnknownRecipient)
}

/// DIR_PUT: the client's own bundle; the A1 §4 checks of the PUT route.
async fn dir_put(s: &ExitState, body: &[u8], now: u64) -> Result<(), ApiError> {
    let bundle = Bundle::parse(body).map_err(|_| ApiError::Malformed)?;
    let rid_hex = hex::encode(bundle.recipient_id.as_bytes());
    // F4: the exact bytes already stored were verified when they were
    // stored, so a byte-identical republish (anyone can replay the public
    // bundle) is answered without spending the global verify budget. Same
    // outcome as the full path: OK, nothing stored, nothing replicated.
    match s.directory.check_put(&bundle.recipient_id, bundle.published_at, now, body) {
        Ok(ladon_relay_core_v2::store::DirectoryPutCheck::Identical) => return Ok(()),
        Ok(ladon_relay_core_v2::store::DirectoryPutCheck::Fresh) => {}
        // F1 step A: a refusal (full directory, stale or older bundle) is
        // decided before the signature check, so a flood against a full
        // directory no longer spends the global verify budget. Nothing is
        // stored either way; bundles are public via DIR_GET, so answering
        // before verification reveals nothing new.
        Err(e) => return Err(crate::handlers::map_put_err(e)),
    }
    s.sealed_limits.take_verify(now)?;
    put_directory_inner(s, &rid_hex, body, &s.sealed_limits.dir_put_per_rid).await
}
