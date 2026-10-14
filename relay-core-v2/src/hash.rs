//! Domain-separated hash helpers — Spec §3.6, Addendum A1 §2.

use crate::constants::{
    DELIVERY_KEY_LEN, DELIVERY_VERIFIER_LEN, DOMAIN_DELIVER_INFO, DOMAIN_DELIVER_SALT,
    DOMAIN_DELIVER_VERIFY,
};
use crate::ids::{ExitId, RecipientId};

/// Derive the 32-byte Recipient identifier from the recipient's HSig public key.
/// Spec §3 / §4.1: `rid_R = SHA-256(ID_R)` where `ID_R == recipient_hsig_pk`
/// (HSIG_PK_LEN = 1984 B: Ed25519_PK(32) || Dilithium3_PK(1952)).
///
/// FIX P7-EXIT-01 (B1.3): used by the exit-relay to enforce that the path
/// `rid` matches `SHA-256(bundle.recipient_hsig_pk)` on `PUT /v2/directory/{rid}`,
/// closing the rid↔hsig_pk binding loophole that would otherwise allow a
/// client to publish a bundle signed by IK_X under a path rid != SHA-256(IK_X).
pub fn recipient_id_from_hsig_pk(hsig_pk: &[u8]) -> RecipientId {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(hsig_pk);
    let mut id = [0u8; RecipientId::LEN];
    id.copy_from_slice(&digest);
    RecipientId(id)
}

/// A1 §2.2: the key a sender presents to Exit `exit_id`,
/// `K_X = HKDF-SHA256(salt = "L1-DeliverSalt-v1", ikm = K, info = "L1-Deliver-v1" || exit_id)`.
/// The relays only ever see `K_X`; this function exists for clients, tests
/// and the cross-language vectors.
pub fn exit_delivery_key(delivery_key: &[u8; DELIVERY_KEY_LEN], exit_id: &ExitId) -> [u8; DELIVERY_KEY_LEN] {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(DOMAIN_DELIVER_SALT), delivery_key);
    let mut info = Vec::with_capacity(DOMAIN_DELIVER_INFO.len() + ExitId::LEN);
    info.extend_from_slice(DOMAIN_DELIVER_INFO);
    info.extend_from_slice(exit_id.as_bytes());
    let mut out = [0u8; DELIVERY_KEY_LEN];
    hk.expand(&info, &mut out).expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

/// A1 §2.3: `V_X = SHA-256("L1-DeliverVerify-v1" || K_X)` — published in the
/// recipient's signed delivery bundle, compared (constant-time) by the Exit.
pub fn delivery_verifier(exit_delivery_key: &[u8; DELIVERY_KEY_LEN]) -> [u8; DELIVERY_VERIFIER_LEN] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(DOMAIN_DELIVER_VERIFY);
    h.update(exit_delivery_key);
    h.finalize().into()
}

/// Derive the 16-byte Exit-Relay identifier from its HKEM public key.
/// Spec §3.5 line 233: `id = BLAKE3(hkem_pk)[..16]`.
pub fn exit_id_from_hkem_pk(hkem_pk: &[u8]) -> crate::ids::ExitId {
    let h = blake3::hash(hkem_pk);
    let mut id = [0u8; 16];
    id.copy_from_slice(&h.as_bytes()[..16]);
    crate::ids::ExitId(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_delivery_key_is_exit_bound() {
        let k = [0x11u8; DELIVERY_KEY_LEN];
        let a = exit_delivery_key(&k, &ExitId([0xA0; 16]));
        let b = exit_delivery_key(&k, &ExitId([0xB0; 16]));
        assert_ne!(a, b, "a key presented to one Exit must not work at another");
        assert_eq!(a, exit_delivery_key(&k, &ExitId([0xA0; 16])), "deterministic");
        assert_ne!(a, k, "the master key never appears on the wire");
    }

    #[test]
    fn delivery_verifier_is_domain_separated() {
        use sha2::{Digest, Sha256};
        let kx = [0x22u8; DELIVERY_KEY_LEN];
        let v = delivery_verifier(&kx);
        let plain: [u8; 32] = Sha256::digest(kx).into();
        assert_ne!(v, plain);
        assert_ne!(delivery_verifier(&[0x23u8; DELIVERY_KEY_LEN]), v);
    }

    #[test]
    fn exit_id_from_hkem_is_16b() {
        let pk = [0x55u8; 1_216];
        let id = exit_id_from_hkem_pk(&pk);
        assert_eq!(id.as_bytes().len(), 16);
    }

    #[test]
    fn recipient_id_from_hsig_pk_is_32b_and_deterministic() {
        let pk = [0x42u8; 1984];
        let a = recipient_id_from_hsig_pk(&pk);
        let b = recipient_id_from_hsig_pk(&pk);
        assert_eq!(a, b);
        assert_eq!(a.as_bytes().len(), 32);
    }

    #[test]
    fn recipient_id_changes_on_input_change() {
        let mut pk = [0x42u8; 1984];
        let a = recipient_id_from_hsig_pk(&pk);
        pk[7] ^= 1;
        let b = recipient_id_from_hsig_pk(&pk);
        assert_ne!(a, b);
    }

    #[test]
    fn recipient_id_matches_sha256_spec() {
        // Spec §3 / §4.1: rid = SHA-256(IK_R). Verify against raw sha2 digest.
        use sha2::{Digest, Sha256};
        let pk = [0xA5u8; 1984];
        let expected = Sha256::digest(pk);
        let got = recipient_id_from_hsig_pk(&pk);
        assert_eq!(&expected[..], got.as_bytes());
    }
}
