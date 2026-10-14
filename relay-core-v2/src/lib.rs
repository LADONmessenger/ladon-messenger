//! Ladon Relay Core v2 — Wire Formats & Crypto Primitives
//!
//! Implements §3-§6 of `docs/specs/VARIANTE_1_PROTOCOL_SPEC.md` (v0.10) as
//! amended by Addendum A1 (delivery keys, relay protocol 0x05).
//!
//! This crate is shared by `entry-relay-v2` and `exit-relay-v2` and contains:
//!   - Wire format parsers/serializers (Bundle, OuterPlaintext, sealed requests)
//!   - Identifier types (ExitId, RecipientId, EnvelopeId, BundleId)
//!   - Protocol constants from Appendix A
//!   - BLAKE3 domain-separated helpers
//!
//! No HTTP, no I/O. Pure data + crypto.

#![forbid(unsafe_code)]
#![deny(unused_must_use)]

pub mod constants;
pub mod ids;
pub mod wire;
pub mod hash;
pub mod hkem;
pub mod hsig;
pub mod bloom;
pub mod store;
pub mod error;
pub mod ratelimit;
pub mod admission;

pub use constants::*;
pub use ids::{ExitId, RecipientId, EnvelopeId, BundleId};
pub use error::{Error, Result};
