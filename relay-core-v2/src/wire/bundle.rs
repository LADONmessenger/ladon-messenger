//! Delivery bundle — Addendum A1 §3.2. One bundle per Exit, 6,678 B.
//!
//! Layout:
//! ```text
//!   off=0      1 B     version              = 0x05
//!   off=1      32 B    recipient_id         = SHA-256(recipient_hsig_pk)
//!   off=33     1,984 B recipient_hsig_pk    (Ed25519_PK || ML-DSA-65_PK)
//!   off=2,017  1,216 B recipient_hkem_pk    (X25519_PK || ML-KEM-768_PK)
//!   off=3,233  16 B    bundle_id
//!   off=3,249  8 B     published_at         (unix seconds, BE)
//!   off=3,257  16 B    exit_id              (the Exit this bundle is for)
//!   off=3,273  32 B    verifier             = SHA-256("L1-DeliverVerify-v1" || K_X)
//!   off=3,305  3,373 B bundle_hsig          = HSig.Sign["L1-Bundle-v3"](IK_R, bytes[0..3,305))
//! ```

use crate::constants::*;
use crate::error::{Error, Result};
use crate::ids::{BundleId, ExitId, RecipientId};
use crate::wire::read_u64_be;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bundle {
    pub version: u8,
    pub recipient_id: RecipientId,
    pub recipient_hsig_pk: Vec<u8>, // 1,984 B
    pub recipient_hkem_pk: Vec<u8>, // 1,216 B
    pub bundle_id: BundleId,
    pub published_at: u64,
    pub exit_id: ExitId,
    pub verifier: [u8; DELIVERY_VERIFIER_LEN],
    pub bundle_hsig: Vec<u8>, // 3,373 B
}

impl Bundle {
    /// Parse exactly `BUNDLE_LEN` bytes. Any other length, or a version other
    /// than `RELAY_PROTOCOL_VERSION`, is rejected.
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < BUNDLE_LEN {
            return Err(Error::Short { expected: BUNDLE_LEN, got: buf.len() });
        }
        if buf.len() > BUNDLE_LEN {
            return Err(Error::Trailing(buf.len() - BUNDLE_LEN));
        }
        let version = buf[BUNDLE_OFF_VERSION];
        if version != RELAY_PROTOCOL_VERSION {
            return Err(Error::UnsupportedVersion(version));
        }
        let recipient_id = RecipientId::from_bytes(&buf[BUNDLE_OFF_RECIPIENT_ID..BUNDLE_OFF_HSIG_PK])
            .expect("32 bytes");
        let recipient_hsig_pk = buf[BUNDLE_OFF_HSIG_PK..BUNDLE_OFF_HKEM_PK].to_vec();
        let recipient_hkem_pk = buf[BUNDLE_OFF_HKEM_PK..BUNDLE_OFF_BUNDLE_ID].to_vec();
        let bundle_id = BundleId::from_bytes(&buf[BUNDLE_OFF_BUNDLE_ID..BUNDLE_OFF_PUBLISHED_AT])
            .expect("16 bytes");
        let published_at = read_u64_be(&buf[BUNDLE_OFF_PUBLISHED_AT..BUNDLE_OFF_EXIT_ID]);
        let exit_id = ExitId::from_bytes(&buf[BUNDLE_OFF_EXIT_ID..BUNDLE_OFF_VERIFIER])
            .expect("16 bytes");
        let mut verifier = [0u8; DELIVERY_VERIFIER_LEN];
        verifier.copy_from_slice(&buf[BUNDLE_OFF_VERIFIER..BUNDLE_OFF_SIG]);
        let bundle_hsig = buf[BUNDLE_OFF_SIG..BUNDLE_LEN].to_vec();
        Ok(Bundle {
            version, recipient_id, recipient_hsig_pk, recipient_hkem_pk,
            bundle_id, published_at, exit_id, verifier, bundle_hsig,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.signing_input();
        out.extend_from_slice(&self.bundle_hsig);
        debug_assert_eq!(out.len(), BUNDLE_LEN);
        out
    }

    /// The bytes covered by `bundle_hsig`: everything before it.
    pub fn signing_input(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(BUNDLE_LEN);
        out.push(self.version);
        out.extend_from_slice(self.recipient_id.as_bytes());
        out.extend_from_slice(&self.recipient_hsig_pk);
        out.extend_from_slice(&self.recipient_hkem_pk);
        out.extend_from_slice(self.bundle_id.as_bytes());
        out.extend_from_slice(&self.published_at.to_be_bytes());
        out.extend_from_slice(self.exit_id.as_bytes());
        out.extend_from_slice(&self.verifier);
        debug_assert_eq!(out.len(), BUNDLE_BODY_LEN);
        out
    }

    /// Structural invariants that need no signature check.
    pub fn validate_structure(&self) -> Result<()> {
        if self.version != RELAY_PROTOCOL_VERSION {
            return Err(Error::UnsupportedVersion(self.version));
        }
        if self.recipient_hsig_pk.len() != HSIG_PK_LEN {
            return Err(Error::Internal("hsig_pk length"));
        }
        if self.recipient_hkem_pk.len() != HKEM_PK_LEN {
            return Err(Error::Internal("hkem_pk length"));
        }
        // P7-RELAY-19: the Kyber768 half must be a well-formed public key; a
        // length-only check would let a publisher upload a bundle that
        // silently degrades hybrid HKEM to X25519-only at encapsulation time.
        {
            use pqcrypto_traits::kem::PublicKey;
            let kyber_pk = &self.recipient_hkem_pk[X25519_PK_LEN..];
            if pqcrypto_kyber::kyber768::PublicKey::from_bytes(kyber_pk).is_err() {
                return Err(Error::Internal("hkem_pk: kyber768 half invalid"));
            }
        }
        if self.bundle_hsig.len() != HSIG_SIG_LEN {
            return Err(Error::Internal("bundle_hsig length"));
        }
        // rid binding (P7-EXIT-01): the bundle's own rid must be the hash of
        // its own identity key.
        if crate::hash::recipient_id_from_hsig_pk(&self.recipient_hsig_pk) != self.recipient_id {
            return Err(Error::Internal("recipient_id != SHA-256(recipient_hsig_pk)"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::recipient_id_from_hsig_pk;

    fn valid_hkem_pk() -> Vec<u8> {
        use pqcrypto_traits::kem::PublicKey;
        let (pk, _) = pqcrypto_kyber::kyber768::keypair();
        let mut v = vec![0x33u8; X25519_PK_LEN];
        v.extend_from_slice(pk.as_bytes());
        v
    }

    fn dummy_bundle() -> Bundle {
        let hsig_pk = vec![0x22u8; HSIG_PK_LEN];
        Bundle {
            version: RELAY_PROTOCOL_VERSION,
            recipient_id: recipient_id_from_hsig_pk(&hsig_pk),
            recipient_hsig_pk: hsig_pk,
            recipient_hkem_pk: valid_hkem_pk(),
            bundle_id: BundleId([0x44; 16]),
            published_at: 1_700_000_000,
            exit_id: ExitId([0xBB; 16]),
            verifier: [0x66; DELIVERY_VERIFIER_LEN],
            bundle_hsig: vec![0x55; HSIG_SIG_LEN],
        }
    }

    #[test]
    fn encode_parse_roundtrip() {
        let b = dummy_bundle();
        let enc = b.encode();
        assert_eq!(enc.len(), BUNDLE_LEN);
        assert_eq!(Bundle::parse(&enc).unwrap(), b);
        b.validate_structure().unwrap();
    }

    #[test]
    fn rejects_wrong_length_and_version() {
        let enc = dummy_bundle().encode();
        assert!(Bundle::parse(&enc[..BUNDLE_LEN - 1]).is_err());
        let mut longer = enc.clone();
        longer.push(0);
        assert!(Bundle::parse(&longer).is_err());
        let mut old = enc.clone();
        old[0] = 0x02;
        assert!(matches!(Bundle::parse(&old), Err(Error::UnsupportedVersion(0x02))));
    }

    #[test]
    fn validate_structure_enforces_rid_binding() {
        let mut b = dummy_bundle();
        b.recipient_id = RecipientId([0x99; 32]);
        assert!(b.validate_structure().is_err());
    }

    #[test]
    fn signing_input_is_everything_before_the_signature() {
        let b = dummy_bundle();
        let si = b.signing_input();
        assert_eq!(si.len(), BUNDLE_BODY_LEN);
        assert_eq!(&b.encode()[..BUNDLE_BODY_LEN], si.as_slice());
    }
}
