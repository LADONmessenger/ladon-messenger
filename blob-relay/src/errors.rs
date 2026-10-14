//! HTTP error response helpers.
//!
//! Every error on the data path maps to the closed slug set defined in
//! PHASE3_SERVER_SPEC.md §10. Callers never build ad-hoc JSON bodies.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorSlug {
    BadRequest,
    AuthFailed,
    NotFound,
    Conflict,
    Gone,
    Quota,
    Integrity,
    RateLimit,
    ServerError,
    Unavailable,
    StorageFull,
}

impl ErrorSlug {
    pub fn as_str(&self) -> &'static str {
        match self {
            ErrorSlug::BadRequest => "bad_request",
            ErrorSlug::AuthFailed => "auth_failed",
            ErrorSlug::NotFound => "not_found",
            ErrorSlug::Conflict => "conflict",
            ErrorSlug::Gone => "gone",
            ErrorSlug::Quota => "quota",
            ErrorSlug::Integrity => "integrity",
            ErrorSlug::RateLimit => "rate_limit",
            ErrorSlug::ServerError => "server_error",
            ErrorSlug::Unavailable => "unavailable",
            ErrorSlug::StorageFull => "storage_full",
        }
    }

    pub fn status(&self) -> StatusCode {
        match self {
            ErrorSlug::BadRequest => StatusCode::BAD_REQUEST,
            ErrorSlug::AuthFailed => StatusCode::UNAUTHORIZED,
            ErrorSlug::NotFound => StatusCode::NOT_FOUND,
            ErrorSlug::Conflict => StatusCode::CONFLICT,
            ErrorSlug::Gone => StatusCode::GONE,
            ErrorSlug::Quota => StatusCode::PAYLOAD_TOO_LARGE,
            ErrorSlug::Integrity => StatusCode::UNPROCESSABLE_ENTITY,
            ErrorSlug::RateLimit => StatusCode::TOO_MANY_REQUESTS,
            ErrorSlug::ServerError => StatusCode::INTERNAL_SERVER_ERROR,
            ErrorSlug::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            ErrorSlug::StorageFull => StatusCode::INSUFFICIENT_STORAGE,
        }
    }
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
}

pub fn err_response(slug: ErrorSlug) -> Response {
    let body = ErrorBody {
        error: slug.as_str(),
    };
    (slug.status(), Json(body)).into_response()
}
