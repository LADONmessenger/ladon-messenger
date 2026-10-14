//! Identifier types — fixed-size byte arrays with strict typing.
//!
//! All identifiers in v0.2 are short, opaque byte strings derived from
//! cryptographic hashes. Wrapping them in newtype structs prevents
//! accidental swap (e.g. passing a RecipientId where ExitId is expected).

use crate::constants::*;
use std::fmt;

macro_rules! id_type {
    ($name:ident, $len:expr, $doc:expr) => {
        #[doc = $doc]
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name(pub [u8; $len]);

        impl $name {
            pub const LEN: usize = $len;

            #[inline]
            pub fn from_bytes(b: &[u8]) -> Option<Self> {
                if b.len() == $len {
                    let mut a = [0u8; $len];
                    a.copy_from_slice(b);
                    Some(Self(a))
                } else {
                    None
                }
            }
            #[inline]
            pub fn as_bytes(&self) -> &[u8; $len] { &self.0 }
            #[inline]
            pub fn into_bytes(self) -> [u8; $len] { self.0 }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), hex::encode(&self.0))
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&hex::encode(&self.0))
            }
        }
    };
}

id_type!(ExitId, EXIT_ID_LEN,
    "Exit-Relay 16-byte identifier — `BLAKE3(hkem_pk)[..16]` per Spec §3.5 line 233.");
id_type!(RecipientId, RECIPIENT_ID_LEN,
    "Recipient 32-byte identifier — `SHA-256(IK_R)`.");
id_type!(EnvelopeId, ENVELOPE_ID_LEN,
    "Envelope 16-byte identifier — random per envelope, chosen by the sender; replay-filter key (Addendum A1 §3.4).");
id_type!(BundleId, BUNDLE_ID_LEN,
    "Bundle 16-byte identifier — generator-chosen unique value.");
