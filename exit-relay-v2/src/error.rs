//! Symbolic API errors. Mapping to HTTP status codes per Spec §4.8 table.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiError {
    Version,
    Malformed,
    WrongExit,
    /// A recipient signature (bundle) did not verify under its usecase tag.
    Signature,
    FetchSig,
    UnknownRecipient,
    Replay,
    /// A1 §8 step 4: `sent_at` outside ±`SENT_AT_WINDOW_SEC`.
    Stale,
    TooLarge,
    Upgrade,
    Rate,
    Internal,
    Unavailable,
    /// S2S authentication failed (Spec §4.7.2). Mapped to 403; not in the
    /// public client-facing table because clients never see this error.
    S2sAuth,
    /// A1 §8 step 6: the presented exit delivery key does not match the
    /// recipient's published verifier. Mapped to 403 (the Entry collapses
    /// 403 into 502, so a sender cannot tell this apart from other refusals).
    DeliveryKey,
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
    message: &'static str,
    retry_after_sec: Option<u64>,
}

impl ApiError {
    pub fn code(&self) -> &'static str {
        use ApiError::*;
        match self {
            Version => "E-VERSION",
            Malformed => "E-MALFORMED",
            WrongExit => "E-WRONG-EXIT",
            Signature => "E-SIGNATURE",
            FetchSig => "E-FETCH-SIG",
            UnknownRecipient => "E-UNKNOWN-RECIPIENT",
            Replay => "E-REPLAY",
            Stale => "E-STALE",
            TooLarge => "E-TOO-LARGE",
            Upgrade => "E-UPGRADE",
            Rate => "E-RATE",
            Internal => "E-INTERNAL",
            Unavailable => "E-UNAVAILABLE",
            S2sAuth => "E-S2S-AUTH",
            DeliveryKey => "E-DELIVERY-KEY",
        }
    }

    pub fn status(&self) -> StatusCode {
        use ApiError::*;
        match self {
            Version | Malformed | Stale => StatusCode::BAD_REQUEST,
            WrongExit | Signature | FetchSig => StatusCode::UNAUTHORIZED,
            UnknownRecipient | S2sAuth | DeliveryKey => StatusCode::FORBIDDEN,
            Replay => StatusCode::CONFLICT,
            TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Upgrade => StatusCode::UPGRADE_REQUIRED,
            Rate => StatusCode::TOO_MANY_REQUESTS,
            Internal => StatusCode::INTERNAL_SERVER_ERROR,
            Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    pub fn message(&self) -> &'static str {
        use ApiError::*;
        match self {
            Version => "unsupported version",
            Malformed => "malformed envelope",
            WrongExit => "wrong target exit",
            Signature => "signature invalid",
            FetchSig => "fetch signature invalid",
            UnknownRecipient => "recipient not in directory",
            Replay => "already received",
            Stale => "envelope outside the time window",
            TooLarge => "envelope too large",
            Upgrade => "upgrade required",
            Rate => "rate limit exceeded",
            Internal => "internal error",
            Unavailable => "service unavailable",
            S2sAuth => "S2S authentication failed",
            DeliveryKey => "delivery key not accepted",
        }
    }
}

pub type ApiResult<T> = Result<T, ApiError>;

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = ErrorBody { error: self.code(), message: self.message(), retry_after_sec: None };
        let mut resp = (self.status(), Json(body)).into_response();
        resp.headers_mut().insert(
            "X-Ladon-Error-Code",
            self.code().parse().unwrap(),
        );
        resp
    }
}

#[allow(dead_code)]
pub const FIXED_ERROR_DELAY: Duration = Duration::from_millis(20);
