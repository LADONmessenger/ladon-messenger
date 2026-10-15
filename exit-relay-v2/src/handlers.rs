//! Axum HTTP handlers for the Exit-Relay v2.
//!
//! All endpoints are version-2 only; legacy `/v1/*` endpoints live in the old
//! exit-relay binary and are NOT served by this implementation.

use std::sync::Arc;

use axum::{
    extract::State,
    http::{header::CONTENT_TYPE, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

use ladon_relay_core_v2::constants::*;
use ladon_relay_core_v2::hsig;
use ladon_relay_core_v2::ids::RecipientId;
use ladon_relay_core_v2::store::{DirectoryPutCheck, DirectoryPutError};
use ladon_relay_core_v2::wire::{Bundle, OuterPlaintext};

use crate::error::ApiError;
use crate::s2s::{verify_s2s, S2sHeaders};
use crate::state::ExitState;

#[inline]
fn now_sec() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------- /v2/health ------------------------------------------------------

#[derive(Serialize)]
pub struct HealthBody {
    pub status: &'static str,
    pub exit_id: String,
    pub version: u8,
}

pub async fn health(State(s): State<Arc<ExitState>>) -> Json<HealthBody> {
    Json(HealthBody {
        status: "ok",
        exit_id: hex::encode(s.exit_id.as_bytes()),
        version: RELAY_PROTOCOL_VERSION,
    })
}

// ---------- /canary.json ----------------------------------------------------

pub async fn canary(State(s): State<Arc<ExitState>>) -> Response {
    // P7-EXIT-08: use async tokio::fs::read so the tokio worker thread is
    // not blocked on disk I/O. canary.json is small (<4 KB) but stat+read
    // still goes to the kernel; on a contended filesystem this can stall
    // an entire worker for tens of ms, head-of-line-blocking forward/
    // fetch on the same thread.
    match tokio::fs::read(&s.canary_path).await {
        Ok(b) => {
            let mut r = (StatusCode::OK, b).into_response();
            r.headers_mut().insert(CONTENT_TYPE, "application/json".parse().unwrap());
            r
        }
        Err(_) => (StatusCode::NOT_FOUND, "canary file missing").into_response(),
    }
}

/// S2S authentication of a request from an Entry (Spec §4.7.2, B2.2): the
/// per-entry HMAC over the body. Shared by `/v2/forward` and `/v2/sealed`.
pub(crate) fn verify_entry_s2s(
    s: &ExitState,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(), ApiError> {
    let hop = headers.get("x-relay-hop").and_then(|v| v.to_str().ok()).ok_or_else(|| {
        tracing::warn!(stage = "hdr-hop", "forward S2sAuth: missing x-relay-hop");
        ApiError::S2sAuth
    })?;
    let ts  = headers.get("x-relay-timestamp").and_then(|v| v.to_str().ok()).ok_or_else(|| {
        tracing::warn!(stage = "hdr-ts", "forward S2sAuth: missing x-relay-timestamp");
        ApiError::S2sAuth
    })?;
    let sig = headers.get("x-relay-signature").and_then(|v| v.to_str().ok()).ok_or_else(|| {
        tracing::warn!(stage = "hdr-sig", "forward S2sAuth: missing x-relay-signature");
        ApiError::S2sAuth
    })?;
    let nonce_hdr = headers.get("x-relay-nonce").and_then(|v| v.to_str().ok());
    verify_s2s(
        {
            // B2.2: per-entry HMAC key lookup by hop.
            // Unknown hop must return the same S2sAuth error as a wrong
            // signature (no existence oracle).
            let Some(k) = s.entry_keys.get(hop) else {
                let hop_short = hop.get(..hop.len().min(32)).unwrap_or("");
                tracing::warn!(stage = "s2s-hop-unknown", hop = hop_short, "forward S2sAuth: unknown hop");
                return Err(ApiError::S2sAuth);
            };
            k
        },
        &S2sHeaders { hop, timestamp: ts, signature_hex: sig, nonce_hex: nonce_hdr },
        body,
        now_sec(),
        s.s2s_skew_sec,
        &s.s2s_nonce_store,
        s.s2s_accept_legacy,
    ).inspect_err(|&e| {
        let hop_short = hop.get(..hop.len().min(32)).unwrap_or("");
        let ts_short = ts.get(..ts.len().min(16)).unwrap_or("");
        tracing::warn!(stage = "s2s", err = ?e, hop = hop_short, ts = ts_short, "forward S2S verify failed");
    })?;
    Ok(())
}

/// A1 §8 steps 4–10 plus the push decision for a sealed ENQUEUE.
///
/// Push (A2 §7, no per-envelope bit): notify at once if the recipient has not
/// fetched within `ONLINE_WINDOW_SEC`. Otherwise check again after
/// `DEFERRED_PUSH_CHECK_SEC` and notify if it has not fetched since the
/// envelope arrived — a device frozen by iOS right after a fetch still looks
/// online, and would otherwise never be told (12 Pro, 13.10.2026: messages
/// after a push wake waited 3 min).
pub(crate) async fn deliver(s: &ExitState, mut parsed: OuterPlaintext) -> Result<(), ApiError> {
    // P7-EXIT-10: the inner envelope must hold at least its HKEM ciphertext,
    // nonce and AEAD tag; anything smaller cannot parse on the client and
    // would only waste mailbox space.
    const MIN_INNER_BYTES: usize = INNER_ENVELOPE_HEADER_LEN + AEAD_TAG_LEN;
    if parsed.inner_envelope.len() < MIN_INNER_BYTES {
        tracing::warn!(stage = "pt-size", "forward Malformed: inner_envelope too small");
        return Err(ApiError::Malformed);
    }
    // A1 §8 step 4: freshness. Together with the envelope-id filter below
    // this bounds every possible replay to the Bloom memory (A1 §8 argument).
    let now = now_sec();
    if now.abs_diff(parsed.sent_at) > SENT_AT_WINDOW_SEC {
        tracing::warn!(stage = "stale", "forward Stale: sent_at outside the window");
        return Err(ApiError::Stale);
    }
    // A1 §8 steps 5–6: the presented exit delivery key must match the
    // verifier in the recipient's signed bundle (constant-time compare).
    let bundle_bytes = s.directory.get(&parsed.recipient_id).ok_or_else(|| {
        tracing::warn!(stage = "directory", "forward UnknownRecipient");
        ApiError::UnknownRecipient
    })?;
    let bundle = Bundle::parse(&bundle_bytes).map_err(|_| ApiError::Internal)?;
    {
        use subtle::ConstantTimeEq;
        let presented = ladon_relay_core_v2::hash::delivery_verifier(&parsed.delivery_key);
        if !bool::from(presented.ct_eq(&bundle.verifier)) {
            tracing::warn!(stage = "delivery-key", "forward DeliveryKey: verifier mismatch");
            return Err(ApiError::DeliveryKey);
        }
    }
    // A1 §8 step 7: replay. Check-and-insert in one step under the lock, so
    // two copies arriving together cannot both pass. Done before the rate
    // limit so replays cannot spend a recipient's budget. A later refusal
    // (rate, mailbox full) does not un-insert: a sender retries with a newly
    // sealed envelope and a fresh id.
    {
        let mut g = s.replay.lock().unwrap_or_else(|e| e.into_inner());
        g.maybe_rotate(now);
        if !g.check_and_insert(&parsed.envelope_id) {
            tracing::warn!(stage = "replay", "forward Replay: envelope id already seen");
            return Err(ApiError::Replay);
        }
    }
    // A1 §8 step 8 (P7-EXIT-06): per-recipient rate limit.
    let rid_hex = hex::encode(parsed.recipient_id.as_bytes());
    if s.forward_recipient_limiter.check(&rid_hex).is_err() {
        tracing::warn!(stage = "fwd-rl", "forward Rate: per-recipient quota exceeded");
        return Err(ApiError::Rate);
    }
    let recipient_id = parsed.recipient_id;
    // None = notify now; Some(mark) = after the deferred check, unless the
    // recipient fetched after `mark`.
    let deferred: Option<u64> = s
        .online
        .is_online(&recipient_id, now)
        .then(|| s.online.fetch_mark(&recipient_id));
    // A1 §8 steps 9–10 (P7-RELAY-12): enqueue, or 503 when the per-recipient
    // queue or (F3/F5) the store-wide byte cap is reached.
    let inner_envelope = std::mem::take(&mut parsed.inner_envelope);
    drop(parsed);
    if let Err(ladon_relay_core_v2::store::MailboxEnqueueError::Full) =
        s.mailbox.enqueue(recipient_id, inner_envelope)
    {
        tracing::warn!(stage = "enqueue", "mailbox full (recipient queue or global cap) - shedding");
        return Err(ApiError::Unavailable);
    }
    // V2.1 Phase 3b: best-effort APNs alert via push-relay. Fire-and-forget
    // \u2014 a push-relay outage must not stall the forward response. The
    // push-relay enforces its own debounce window, so calling on every
    // enqueue is safe (and required for first-message latency).
    //
    // P7-RELAY-13: cap outstanding spawned notifications via a shared
    // semaphore in ExitState. If the cap is reached, drop the notify (best-
    // effort semantics already) rather than spawning unbounded tasks that
    // could fork-bomb the outbound HTTP/2 pool.
    {
        if let Some(push) = s.push.clone() {
            let rid = recipient_id;
            let sema = s.push_notify_sema.clone();
            let online = s.online.clone();
            let debounce = s.notify_debounce.clone();
            // Try to acquire a permit; if we can't, drop this notify. A
            // deferred check holds its permit while it waits, so the waits
            // are bounded by the same cap.
            if let Ok(permit) = sema.try_acquire_owned() {
                tokio::spawn(async move {
                    if let Some(mark) = deferred {
                        tokio::time::sleep(std::time::Duration::from_secs(
                            ladon_relay_core_v2::wire::sealed::DEFERRED_PUSH_CHECK_SEC,
                        ))
                        .await;
                        if online.fetched_since(&rid, mark) {
                            return;
                        }
                    }
                    // F44: decided at send time, so a deferred notify that
                    // was cancelled by a fetch does not suppress a later one.
                    if !debounce.allow(&rid, now_sec()) {
                        return;
                    }
                    push.notify(&rid).await;
                    drop(permit);
                });
            } else {
                // P8-AUDIT5-EXIT-MED-1 (2026-05-22): elevate from debug to warn.
                // Sema saturation means push fan-out is being shed. Operator
                // needs to see this so they can scale the cap or investigate
                // a stuck push-relay (HTTP/2 GOAWAY backpressure pulling the
                // exit's notify spawns to the cap).
                tracing::warn!(stage = "push", "notify semaphore exhausted - dropping");
            }
        }
    }
    Ok(())
}

/// One mapping (and log line) for every directory PUT refusal, shared by the
/// pre-verify check in `sealed::dir_put` and the verified path below. The
/// "directory full" text is what the F1 monitoring counts.
pub(crate) fn map_put_err(e: DirectoryPutError) -> ApiError {
    match e {
        DirectoryPutError::NotMonotonic => {
            tracing::warn!("directory PUT rejected: bundle not newer than stored");
            ApiError::Replay
        }
        DirectoryPutError::Stale => {
            tracing::warn!("directory PUT rejected: no stored bundle and this one is too old");
            ApiError::Replay
        }
        // F19: full, and every stored recipient was active within the
        // mailbox TTL. Retryable for the client.
        DirectoryPutError::Full => {
            tracing::warn!("directory PUT rejected: directory full of active recipients");
            ApiError::Unavailable
        }
    }
}

/// `rid_limiter`: A2 per-recipient DIR_PUT limit, checked after the signature
/// and the rid binding held — never before, or anyone could spend a
/// victim's budget with forged bundles and keep it from republishing.
pub(crate) async fn put_directory_inner(
    s: &ExitState,
    rid_hex: &str,
    body: &[u8],
    rid_limiter: &ladon_relay_core_v2::ratelimit::IdentityRateLimiter,
) -> Result<(), ApiError> {
    let rid_bytes = hex::decode(rid_hex).map_err(|_| ApiError::Malformed)?;
    if rid_bytes.len() != RECIPIENT_ID_LEN { return Err(ApiError::Malformed); }
    let mut a = [0u8; RECIPIENT_ID_LEN]; a.copy_from_slice(&rid_bytes);
    let path_rid = RecipientId(a);
    // Parse + structural validation.
    let bundle = Bundle::parse(body).map_err(|e| {
        tracing::warn!(err = ?e, "bundle parse failed");
        ApiError::Malformed
    })?;
    bundle.validate_structure().map_err(|_| ApiError::Malformed)?;
    if bundle.recipient_id != path_rid {
        return Err(ApiError::Malformed);
    }
    // A1 §4 rule 2: a bundle carries the verifier for exactly one Exit.
    if bundle.exit_id != s.exit_id {
        tracing::warn!("directory PUT rejected: bundle is for another exit");
        return Err(ApiError::WrongExit);
    }
    // Bundle signature (A1 §10 — tag "L1-Bundle-v3", no untagged fallback).
    let signing_input = bundle.signing_input();
    hsig::verify_tagged(
        hsig::HSIG_USECASE_BUNDLE,
        &bundle.recipient_hsig_pk,
        &signing_input,
        &bundle.bundle_hsig,
    ).map_err(|e| {
        tracing::warn!(err = ?e, "bundle hsig verify failed");
        ApiError::Signature
    })?;
    // FIX P7-EXIT-01 (B1.3): cryptographically bind path `rid` to the bundle's
    // `recipient_hsig_pk`. Without this check a client could publish a bundle
    // signed by IK_X under any chosen `rid`, even one already taken by another
    // recipient (path_rid == bundle.recipient_id covers only client-supplied
    // self-consistency, not the actual key↔id binding required by Spec §3/§4.1
    // `rid_R = SHA-256(IK_R)`). Mismatch ⇒ Malformed.
    let derived_rid = ladon_relay_core_v2::hash::recipient_id_from_hsig_pk(&bundle.recipient_hsig_pk);
    if derived_rid != path_rid {
        tracing::warn!("rid/hsig_pk binding mismatch on PUT /v2/directory");
        return Err(ApiError::Malformed);
    }
    // F4/N4: decide before spending the recipient's budget. The stored
    // bundle is public (DIR_GET), so anyone can replay it: a byte-identical
    // republish is answered OK without budget and without replication;
    // a rollback/stale one is refused as before, also without budget. Only
    // a real update (`Fresh`) spends the budget.
    let now = now_sec();
    match s.directory.check_put(&path_rid, bundle.published_at, now, body).map_err(map_put_err)? {
        DirectoryPutCheck::Identical => return Ok(()),
        DirectoryPutCheck::Fresh => {}
    }
    if rid_limiter.check(rid_hex).is_err() {
        tracing::warn!("directory PUT rejected: per-recipient limit");
        return Err(ApiError::Rate);
    }
    // Store. Rejects a bundle that is not newer than the stored one: the
    // signature stays valid forever because the identity key is stable, so
    // without this check a bundle captured from the public GET could be
    // replayed after rotation and win. Rejected before the push replication
    // below, so a rolled-back hsig_pk never reaches the push-relay either.
    // `put` re-runs the decision under its lock (another PUT may have
    // landed since `check_put`).
    s.directory
        .put(path_rid, bundle.bundle_id, bundle.published_at, now, body.to_vec())
        .map_err(map_put_err)?;
    // V2.1 Phase 3b: replicate (rid, hsig_pk) to the push-relay so it can
    // verify hsig-signed `PUT /v2/push/register/:rid`. Best-effort: a
    // replication failure must not surface to the client \u2014 the directory
    // PUT itself succeeded and clients can register again later.
    if let Some(push) = s.push.clone() {
        let rid = path_rid;
        let hsig_pk = bundle.recipient_hsig_pk.to_vec();
        tokio::spawn(async move {
            push.replicate(&rid, &hsig_pk).await;
        });
    }
    Ok(())
}
