use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryError {
    Version,
    Malformed,
    UnknownExit,
    TooLarge,
    Upstream,
    /// The exit answered the forward with a request-level verdict
    /// the sender can act on (see `handlers::enqueue`). Carries that status.
    UpstreamRejected(u16),
    Internal,
    /// `PUT /v2/proxy-push-register/:rid` arrived but the entry has no
    /// push-relay configured. 503 — operational, not client error.
    PushDisabled,
    /// FIX SRV-1: Sliding-window rate limit exceeded (per-IP). 429.
    TooManyRequests,
}

#[derive(Serialize)]
struct Body { error: &'static str, message: &'static str }

impl EntryError {
    pub fn code(&self) -> &'static str {
        use EntryError::*;
        match self {
            Version => "E-VERSION",
            Malformed => "E-MALFORMED",
            UnknownExit => "E-UNKNOWN-EXIT",
            TooLarge => "E-TOO-LARGE",
            Upstream => "E-UPSTREAM",
            UpstreamRejected(_) => "E-UPSTREAM-REJECTED",
            Internal => "E-INTERNAL",
            PushDisabled => "E-PUSH-DISABLED",
            TooManyRequests => "E-RATE-LIMIT",
        }
    }
    pub fn status(&self) -> StatusCode {
        use EntryError::*;
        match self {
            Version | Malformed => StatusCode::BAD_REQUEST,
            UnknownExit => StatusCode::NOT_FOUND,
            TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Upstream => StatusCode::BAD_GATEWAY,
            UpstreamRejected(code) => StatusCode::from_u16(*code).unwrap_or(StatusCode::BAD_GATEWAY),
            Internal => StatusCode::INTERNAL_SERVER_ERROR,
            PushDisabled => StatusCode::SERVICE_UNAVAILABLE,
            TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
        }
    }
    pub fn message(&self) -> &'static str {
        use EntryError::*;
        match self {
            Version => "unsupported version",
            Malformed => "malformed request",
            UnknownExit => "target exit unknown to this entry",
            TooLarge => "envelope too large",
            Upstream => "exit-relay rejected or unreachable",
            UpstreamRejected(_) => "exit-relay rejected the request",
            Internal => "internal error",
            PushDisabled => "push-relay not configured on this entry",
            TooManyRequests => "rate limit exceeded",
        }
    }
}

pub type EntryResult<T> = Result<T, EntryError>;

impl IntoResponse for EntryError {
    fn into_response(self) -> Response {
        let body = Body { error: self.code(), message: self.message() };
        let mut r = (self.status(), Json(body)).into_response();
        r.headers_mut().insert("X-Ladon-Error-Code", self.code().parse().unwrap());
        r
    }
}
