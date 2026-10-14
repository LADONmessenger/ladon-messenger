//! `POST /v2/relay` — Addendum A2 stage 2 (relay protocol 0x06).
//!
//! The single client route for sealed requests. The Entry cannot open them:
//! it checks the lane size and the version byte, looks the target id up and
//! forwards the body byte for byte — to an Exit with the S2S HMAC, to the
//! push relay without one (as `proxy-push-register`). The sealed response
//! goes back byte for byte and must be exactly the lane's response size.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header::CONTENT_TYPE, StatusCode};
use axum::response::{IntoResponse, Response};

use ladon_relay_core_v2::constants::EXIT_ID_LEN;
use ladon_relay_core_v2::ids::ExitId;
use ladon_relay_core_v2::wire::sealed::{Lane, SEALED_OFF_TARGET_ID, SEALED_VERSION};

use crate::error::EntryError;
use crate::forward::{now_sec_str, sign_s2s_tagged};
use crate::handlers::read_body_capped;
use crate::state::EntryState;

pub async fn relay(State(s): State<Arc<EntryState>>, body: Bytes) -> Result<Response, EntryError> {
    let lane = Lane::from_request_len(body.len()).ok_or(EntryError::Malformed)?;
    if body[0] != SEALED_VERSION {
        return Err(EntryError::Version);
    }
    let target: [u8; EXIT_ID_LEN] = body[SEALED_OFF_TARGET_ID..SEALED_OFF_TARGET_ID + EXIT_ID_LEN]
        .try_into()
        .expect("16 bytes");

    let req = if let Some(exit_url) = s.registry.lookup(&ExitId(target)) {
        let ts = now_sec_str();
        let (sig, nonce_hex) = sign_s2s_tagged(&s.s2s_key, &s.hop_id, &ts, &body);
        s.http
            .post(format!("{exit_url}/v2/sealed"))
            .header("X-Relay-Hop", &s.hop_id)
            .header("X-Relay-Timestamp", &ts)
            .header("X-Relay-Signature", &sig)
            .header("X-Relay-Nonce", &nonce_hex)
    } else if s.push_target_id == Some(target) {
        let push_url = s.push_relay_url.as_deref().ok_or(EntryError::PushDisabled)?;
        s.http.post(format!("{}/v2/sealed", push_url.trim_end_matches('/')))
    } else {
        return Err(EntryError::UnknownExit);
    };

    let resp = req
        .header(CONTENT_TYPE, "application/octet-stream")
        .body(body.to_vec())
        .send()
        .await
        .map_err(|e| {
            tracing::warn!(err = %e, is_timeout = e.is_timeout(), "relay upstream send failed");
            EntryError::Upstream
        })?;
    let status = resp.status();
    if !status.is_success() {
        // The upstream refused before it could open the request. Only the
        // verdicts about the request itself reach the client (400 malformed
        // or wrong version, 401 wrong target); S2S auth, rate and every 5xx
        // stay a neutral 502, as in `enqueue`.
        tracing::warn!(status = %status, "relay upstream returned non-2xx");
        return Err(match status.as_u16() {
            code @ (400 | 401) => EntryError::UpstreamRejected(code),
            _ => EntryError::Upstream,
        });
    }
    let out = read_body_capped(resp, lane.response_len()).await?;
    if out.len() != lane.response_len() {
        tracing::warn!("relay upstream answered with a non-lane size");
        return Err(EntryError::Upstream);
    }
    let mut r = (StatusCode::OK, out).into_response();
    r.headers_mut().insert(CONTENT_TYPE, "application/octet-stream".parse().unwrap());
    Ok(r)
}
