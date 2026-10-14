//! Wire format parsers/serializers — Spec §4 as amended by Addendum A1 §3.

pub mod bundle;
pub mod outer_plaintext;
pub mod sealed;

pub use bundle::Bundle;
pub use outer_plaintext::OuterPlaintext;

#[inline]
pub(crate) fn read_u64_be(b: &[u8]) -> u64 {
    u64::from_be_bytes(b.try_into().expect("8 bytes"))
}
