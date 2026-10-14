//! HTTP request handlers for push-relay v2.1.
//!
//! Handler responsibility split:
//!   * `health`               — GET /v2/health, no auth.
//!   * `directory_replicate`  — exit→push, S2S HMAC + sealed PUSH_REPLICATE
//!     (F43). Stores `(rid → hsig_pk)` so subsequent register requests can
//!     be verified.
//!   * `push_sealed`          — client→entry→push, sealed PUSH_REGISTER
//!     (A2 §4.4). Opens the request, looks up the replicated `hsig_pk`,
//!     verifies the signature over a domain-separated pre-image, and keeps
//!     the APNs token in the in-RAM store.
//!   * `push_notify`          — exit→push, S2S HMAC + sealed PUSH_NOTIFY
//!     (F43). Triggers a debounced APNs alert if the recipient has a
//!     registered token.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use ladon_relay_core_v2::{
    constants::{
        APNS_TOKEN_LEN, DIRECTORY_REPLICATE_BODY_LEN, DOMAIN_PUSH_REGISTER, HSIG_SIG_LEN,
        PUSH_NOTIFY_BODY_LEN, PUSH_REGISTER_BODY_LEN, RECIPIENT_ID_LEN,
    },
    hsig,
    ids::RecipientId,
    store::{PushEntry, PushRegisterError},
};
use serde::Serialize;
use tracing::{debug, info, warn};

use crate::{
    constant_time::{PadDeadline, DEFAULT_PAD_MS},
    error::{ApiError, ApiResult},
    s2s::{verify_s2s, S2sHeaders},
    state::PushState,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> ApiResult<&'a str> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .ok_or(ApiError::S2sAuth)
}

fn extract_s2s<'a>(headers: &'a HeaderMap) -> ApiResult<S2sHeaders<'a>> {
    Ok(S2sHeaders {
        hop: header_str(headers, "X-Relay-Hop")?,
        timestamp: header_str(headers, "X-Relay-Timestamp")?,
        signature_hex: header_str(headers, "X-Relay-Signature")?,
        // P7-PUSH-04: nonce is OPTIONAL on the wire; absence falls through
        // to the legacy path gated by `s2s_accept_legacy`.
        nonce_hex: headers
            .get("X-Relay-Nonce")
            .and_then(|v| v.to_str().ok()),
    })
}

// ---------------------------------------------------------------------------
// GET /v2/health
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct HealthResp {
    status: &'static str,
    hop: String,
    version: u32,
}

pub async fn health(State(state): State<Arc<PushState>>) -> impl IntoResponse {
    // P7-PUSH-10: do NOT publish push_token_count / directory_replica_count.
    // These are unauthenticated and would let any internet host poll the
    // active-user trajectory of the relay (and indirectly the messenger).
    // The remaining fields are public-by-design (hop id is the relay's
    // routing handle; version is a protocol constant).
    Json(HealthResp {
        status: "ok",
        hop: state.hop_id.clone(),
        version: 2,
    })
}

// ---------------------------------------------------------------------------
// Exit -> push requests (S2S HMAC + sealed, F43)
// ---------------------------------------------------------------------------

/// F43: an exit -> push request is a sealed request (lane F, `wire::sealed`)
/// to this relay's HKEM key, carried on an S2S-authenticated route. The rid
/// travels only inside the AEAD — never in the URL or in a plaintext body —
/// so the exit -> push hop (plain HTTP in the host network) shows no rid.
/// The S2S HMAC covers the sealed bytes and is checked first, so an
/// unauthenticated caller never makes this relay decapsulate.
///
/// Errors before the request opened are HTTP errors (as before); once it
/// opened, the outcome is a sealed status in an HTTP 200 response.
fn open_s2s_sealed(
    state: &PushState,
    headers: &HeaderMap,
    body: &[u8],
    owners_only: bool,
) -> ApiResult<ladon_relay_core_v2::wire::sealed::OpenedRequest> {
    use ladon_relay_core_v2::wire::sealed::{self, LANE_F_REQUEST_LEN};
    if body.len() != LANE_F_REQUEST_LEN {
        return Err(ApiError::Malformed);
    }
    let s2s = extract_s2s(headers)?;
    // B2.2: per-exit HMAC key lookup by hop. Unknown hop -> S2sAuth
    // (same as wrong-signature; no existence oracle).
    let key = state.exit_keys.get(s2s.hop).ok_or(ApiError::S2sAuth)?;
    // P7-PUSH-08 / A1 §14: only hops in the mandatory directory-owner
    // allow-list may replicate. Without this, any compromised exit
    // S2S-key would let the attacker overwrite ANY recipient's
    // hsig_pk in the replica, defeating the architectural
    // separation push-relay is meant to provide. Same opaque
    // S2sAuth response so we don't leak which hops are permitted.
    if owners_only && !state.directory_owner_hops.contains(s2s.hop) {
        tracing::warn!(stage = "dir-replicate", "hop not in directory-owner allow-list");
        return Err(ApiError::S2sAuth);
    }
    verify_s2s(
        key,
        &s2s,
        body,
        now_secs(),
        state.s2s_skew_sec,
        &state.s2s_nonce_store,
        state.s2s_accept_legacy,
    )?;
    let Some(id) = state.sealed.as_ref() else {
        tracing::error!("exit request but no HKEM key loaded");
        return Err(ApiError::Unavailable);
    };
    sealed::open_request(&id.keys, &id.target_id, body).map_err(|e| {
        tracing::warn!(err = %e, "exit request did not open");
        ApiError::Malformed
    })
}

/// Seal `code` as the response to `opened` and wrap it in HTTP 200.
fn sealed_reply(
    state: &PushState,
    opened: &ladon_relay_core_v2::wire::sealed::OpenedRequest,
    code: u8,
) -> ApiResult<axum::response::Response> {
    let id = state.sealed.as_ref().ok_or(ApiError::Unavailable)?;
    let bytes = ladon_relay_core_v2::wire::sealed::seal_response(
        &opened.response_key,
        &id.target_id,
        opened.lane,
        code,
        now_secs(),
        &[],
    )
    .map_err(|_| ApiError::Internal)?;
    let mut r = (StatusCode::OK, bytes).into_response();
    r.headers_mut()
        .insert(axum::http::header::CONTENT_TYPE, "application/octet-stream".parse().unwrap());
    Ok(r)
}

// ---------------------------------------------------------------------------
// PUT /v2/directory/replicate  (S2S HMAC, sealed PUSH_REPLICATE)
// ---------------------------------------------------------------------------

/// Sealed body: rid (32) || hsig_pk (`DIRECTORY_REPLICATE_BODY_LEN`).
pub async fn directory_replicate(
    State(state): State<Arc<PushState>>,
    headers: HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    use ladon_relay_core_v2::wire::sealed::{status, Kind};
    let pad = PadDeadline::new(DEFAULT_PAD_MS);
    let result: ApiResult<axum::response::Response> = (|| {
        let opened = open_s2s_sealed(&state, &headers, &body, true)?;
        let code = if opened.kind != Kind::PushReplicate
            || opened.body.len() != RECIPIENT_ID_LEN + DIRECTORY_REPLICATE_BODY_LEN
        {
            status::MALFORMED
        } else {
            let rid = RecipientId::from_bytes(&opened.body[..RECIPIENT_ID_LEN]).expect("32 bytes");
            let hsig_pk = &opened.body[RECIPIENT_ID_LEN..];
            // F38: a recipient id is SHA-256 of its hsig public key; the exit
            // enforces this on directory PUT before it replicates. Enforce it
            // here too, so a leaked owner-hop S2S key cannot bind a victim's
            // rid to an attacker key and register the attacker's APNs token
            // for the victim.
            let derived = ladon_relay_core_v2::hash::recipient_id_from_hsig_pk(hsig_pk);
            if !bool::from(subtle::ConstantTimeEq::ct_eq(&derived.0[..], &rid.0[..])) {
                tracing::warn!(stage = "dir-replicate", "rid does not match hsig_pk");
                status::MALFORMED
            } else {
                // F10: the replica is an LRU; a full one drops its least
                // recently put entry instead of refusing this recipient.
                state.directory_replica.put(rid, hsig_pk.to_vec());
                debug!("directory replica updated");
                status::OK
            }
        };
        sealed_reply(&state, &opened, code)
    })();
    // P7-PUSH-05: pad success and error alike.
    pad.delay().await;
    match result {
        Ok(r) => r,
        Err(e) => e.into_response(),
    }
}

// ---------------------------------------------------------------------------
// Push registration body (hsig-signed; carried by the sealed PUSH_REGISTER)
// ---------------------------------------------------------------------------

/// Parsed registration body.
struct RegisterBody<'a> {
    apns_token: [u8; APNS_TOKEN_LEN],
    sandbox: bool,
    timestamp: u64,
    signature: &'a [u8],
    /// The bytes that were signed: `apns_token || sandbox_byte || ts_be`.
    signed_payload: Vec<u8>,
}

fn parse_register_body(body: &[u8]) -> ApiResult<RegisterBody<'_>> {
    if body.len() != PUSH_REGISTER_BODY_LEN {
        return Err(ApiError::Malformed);
    }
    let mut apns_token = [0u8; APNS_TOKEN_LEN];
    apns_token.copy_from_slice(&body[..APNS_TOKEN_LEN]);
    let sandbox_byte = body[APNS_TOKEN_LEN];
    if sandbox_byte > 1 {
        return Err(ApiError::Malformed);
    }
    let sandbox = sandbox_byte == 1;
    let mut ts_bytes = [0u8; 8];
    ts_bytes.copy_from_slice(&body[APNS_TOKEN_LEN + 1..APNS_TOKEN_LEN + 1 + 8]);
    let timestamp = u64::from_be_bytes(ts_bytes);
    let signature = &body[APNS_TOKEN_LEN + 1 + 8..];
    debug_assert_eq!(signature.len(), HSIG_SIG_LEN);
    let signed_payload = body[..APNS_TOKEN_LEN + 1 + 8].to_vec();
    Ok(RegisterBody {
        apns_token,
        sandbox,
        timestamp,
        signature,
        signed_payload,
    })
}

/// Verify and store a signed push-token registration (body layout
/// `PUSH_REGISTER_BODY_LEN`), as carried by the sealed PUSH_REGISTER (A2 §4.4).
fn register_token(state: &PushState, rid: RecipientId, body: &[u8]) -> ApiResult<()> {
    let parsed = parse_register_body(body)?;

    // Skew check (timestamp validity).
    let now = now_secs();
    let drift = parsed.timestamp.abs_diff(now);
    if drift > state.push_register_skew_sec {
        return Err(ApiError::FetchSig);
    }

    // Resolve recipient's hsig public key from replicated directory.
    let pk = state
        .directory_replica
        .get(&rid)
        .ok_or(ApiError::UnknownRecipient)?;

    // Verify signature over: DOMAIN || rid.0 || apns_token || sandbox || ts_be,
    // under tag "L1-PushRegister-v3" — no untagged fallback (A1 §10).
    let mut pre = Vec::with_capacity(
        DOMAIN_PUSH_REGISTER.len() + 32 + parsed.signed_payload.len(),
    );
    pre.extend_from_slice(DOMAIN_PUSH_REGISTER);
    pre.extend_from_slice(&rid.0);
    pre.extend_from_slice(&parsed.signed_payload);
    // F9 (a): global verify budget, spent only on a request that reached
    // the hybrid verify (opened, fresh, known recipient).
    state.sealed_limits.take_verify(now)?;
    hsig::verify_tagged(hsig::HSIG_USECASE_PUSH_REGISTER, &pk, &pre, parsed.signature)
        .map_err(|_| ApiError::FetchSig)?;
    // F9 (b): per recipient, after the signature held, so forged requests
    // cannot spend a victim's budget.
    if state.sealed_limits.register_per_rid.check(&hex::encode(rid.0)).is_err() {
        warn!("push register rejected: per-recipient limit");
        return Err(ApiError::RateLimited);
    }

    let entry = PushEntry {
        apns_token: parsed.apns_token,
        sandbox: parsed.sandbox,
        registered_at: now,
        signed_at: parsed.timestamp,
    };
    match state.push_tokens.register(rid, entry, now) {
        Ok(()) => {
            // No rid in the log line. A 32-bit prefix is short but it is
            // still a stable per-recipient identifier, and a log that
            // records who registered when is exactly the correlation the
            // relay separation exists to prevent (project rule: no RIDs in
            // logs). The sandbox flag carries no recipient information.
            info!(sandbox = parsed.sandbox, "push token registered");
            Ok(())
        }
        Err(PushRegisterError::NotMonotonic) => {
            // Deliberately the same error the skew check returns. A
            // distinct code would be an oracle: it would tell an attacker
            // that a newer registration exists for this rid, which is
            // exactly the kind of per-recipient fact the push-relay must
            // not answer questions about.
            warn!("push register rejected: signed timestamp not newer than stored");
            Err(ApiError::FetchSig)
        }
    }
}

// ---------------------------------------------------------------------------
// POST /v2/sealed  (A2 stage 2: sealed PUSH_REGISTER via the Entry)
// ---------------------------------------------------------------------------

/// The client's push registration sealed to this relay's HKEM key, so the
/// Entry no longer sees the rid or the APNs token. Lane F; body = rid (32)
/// || the `PUSH_REGISTER_BODY_LEN` registration. HTTP 200 whenever the
/// request opened; the outcome is the sealed status.
pub async fn push_sealed(
    State(state): State<Arc<PushState>>,
    body: Bytes,
) -> axum::response::Response {
    use ladon_relay_core_v2::wire::sealed::{self, status, Kind};
    let pad = PadDeadline::new(DEFAULT_PAD_MS);
    let result: ApiResult<Vec<u8>> = (|| {
        // F9: no per-IP limit here. Every sealed request comes from the
        // Entry (which limits per client IP), so behind Caddy they all
        // carried one address and shared one bucket. The limits are the
        // verify budget and the per-recipient budget in `register_token`.
        let Some(id) = state.sealed.as_ref() else {
            tracing::error!("sealed request but no HKEM key loaded");
            return Err(ApiError::Unavailable);
        };
        let opened = sealed::open_request(&id.keys, &id.target_id, &body).map_err(|e| {
            tracing::warn!(err = %e, "sealed request did not open");
            ApiError::Malformed
        })?;
        let code = if opened.kind != Kind::PushRegister
            || opened.body.len() != RECIPIENT_ID_LEN + PUSH_REGISTER_BODY_LEN
        {
            status::MALFORMED
        } else {
            let rid = RecipientId::from_bytes(&opened.body[..RECIPIENT_ID_LEN]).expect("32 bytes");
            match register_token(&state, rid, &opened.body[RECIPIENT_ID_LEN..]) {
                Ok(()) => status::OK,
                Err(ApiError::FetchSig) => status::SIGNATURE,
                Err(ApiError::UnknownRecipient) => status::UNKNOWN_RECIPIENT,
                Err(ApiError::Unavailable) => status::UNAVAILABLE,
                Err(ApiError::RateLimited) => status::RATE,
                Err(_) => status::MALFORMED,
            }
        };
        sealed::seal_response(&opened.response_key, &id.target_id, opened.lane, code, now_secs(), &[])
            .map_err(|_| ApiError::Internal)
    })();
    match result {
        Ok(bytes) => {
            pad.delay().await;
            let mut r = (StatusCode::OK, bytes).into_response();
            r.headers_mut().insert(axum::http::header::CONTENT_TYPE, "application/octet-stream".parse().unwrap());
            r
        }
        Err(e) => {
            pad.delay().await;
            e.into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// POST /v2/push/notify  (S2S HMAC, sealed PUSH_NOTIFY)
// ---------------------------------------------------------------------------

/// Sealed body: rid (`PUSH_NOTIFY_BODY_LEN`). Sealed status OK whenever the
/// sender's notification intent was honoured — an APNs send, a debounce
/// (the recipient already has a pending push) or no registration at all —
/// so the caller cannot tell "no push registration" from "active user"
/// (P7-PUSH-05). UNAVAILABLE only when the APNs send was shed (P7-PUSH-14).
pub async fn push_notify(
    State(state): State<Arc<PushState>>,
    headers: HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    use ladon_relay_core_v2::wire::sealed::{status, Kind};
    let pad = PadDeadline::new(DEFAULT_PAD_MS);
    let result: ApiResult<axum::response::Response> = (|| {
        let opened = open_s2s_sealed(&state, &headers, &body, false)?;
        if opened.kind != Kind::PushNotify || opened.body.len() != PUSH_NOTIFY_BODY_LEN {
            return sealed_reply(&state, &opened, status::MALFORMED);
        }
        let rid = RecipientId::from_bytes(&opened.body[..]).expect("32 bytes");

        // No registered token → OK, not "unknown" (no recipient-existence
        // oracle towards the exit).
        let Some(entry) = state.push_tokens.get(&rid) else {
            return sealed_reply(&state, &opened, status::OK);
        };

        let now = now_secs();
        if !state
            .push_tokens
            .allow_push(&rid, now, state.push_debounce_sec)
        {
            debug!("push debounced");
            return sealed_reply(&state, &opened, status::OK);
        }

        let token_hex = hex::encode(entry.apns_token);
        let sandbox = entry.sandbox;
        let apns = state.apns.clone();
        // A2 §7 rule 4: drawn here, slept off the request path below.
        let delay_ms = if state.push_delay_max_ms == 0 {
            0
        } else {
            rand::Rng::gen_range(&mut rand::rngs::OsRng, 0..=state.push_delay_max_ms)
        };
        // P7-PUSH-09: bound in-flight APNs sends to avoid runaway memory
        // when Apple's HTTP/2 stack stalls. try_acquire_owned returns
        // immediately; without a permit the send is shed.
        let Ok(permit) = state.apns_concurrency.clone().try_acquire_owned() else {
            // P7-PUSH-14: an honest "shed", so the exit can see the load.
            warn!("apns send shed: concurrency cap reached");
            return sealed_reply(&state, &opened, status::UNAVAILABLE);
        };
        // Fire-and-forget: APNs send happens off the request path so the
        // exit-relay's notify call is not blocked by Apple's HTTP/2 RTT.
        tokio::spawn(async move {
            let _permit = permit; // released on task exit
            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
            let outcome = apns.send_alert(&token_hex, sandbox).await;
            if !matches!(outcome, crate::apns::ApnsOutcome::Sent) {
                warn!(?outcome, "apns delivery non-success");
            }
        });
        sealed_reply(&state, &opened, status::OK)
    })();
    // P7-PUSH-05: pad success and error alike.
    pad.delay().await;
    match result {
        Ok(r) => r,
        Err(e) => e.into_response(),
    }
}
