//! Symbolic API errors for push-relay. Subset of exit-relay-v2 error codes
//! plus push-specific variants. Mapping mirrors Spec §4.8.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiError {
    /// Body length / parsing wrong.
    Malformed,
    /// hsig-signature verification failed (push-register signature does not
    /// match the replicated hsig_pk).
    FetchSig,
    /// Recipient is not present in the replicated directory yet (so we
    /// cannot verify their hsig-signed registration). Mapped to 403.
    UnknownRecipient,
    /// S2S HMAC authentication failed (replicate or notify). Mapped to 403.
    S2sAuth,
    /// Capacity reached.
    Unavailable,
    /// P7-PUSH-06: per-IP sliding-window rate limit exceeded.
    RateLimited,
    /// Internal error (should be unreachable in production).
    Internal,
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
            Malformed => "E-MALFORMED",
            FetchSig => "E-FETCH-SIG",
            UnknownRecipient => "E-UNKNOWN-RECIPIENT",
            S2sAuth => "E-S2S-AUTH",
            Unavailable => "E-UNAVAILABLE",
            RateLimited => "E-RATE-LIMITED",
            Internal => "E-INTERNAL",
        }
    }

    pub fn status(&self) -> StatusCode {
        use ApiError::*;
        match self {
            Malformed => StatusCode::BAD_REQUEST,
            FetchSig => StatusCode::UNAUTHORIZED,
            UnknownRecipient | S2sAuth => StatusCode::FORBIDDEN,
            Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn message(&self) -> &'static str {
        use ApiError::*;
        match self {
            Malformed => "malformed body",
            FetchSig => "signature invalid",
            UnknownRecipient => "recipient not in directory replica",
            S2sAuth => "S2S authentication failed",
            Unavailable => "service unavailable",
            RateLimited => "too many requests",
            Internal => "internal error",
        }
    }
}

pub type ApiResult<T> = Result<T, ApiError>;

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = ErrorBody {
            error: self.code(),
            message: self.message(),
            retry_after_sec: None,
        };
        let mut resp = (self.status(), Json(body)).into_response();
        resp.headers_mut()
            .insert("X-Ladon-Error-Code", self.code().parse().unwrap());
        resp
    }
}

#[allow(dead_code)]
pub const FIXED_ERROR_DELAY: Duration = Duration::from_millis(20);
