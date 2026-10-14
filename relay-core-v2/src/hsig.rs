//! Hybrid signature (HSig): Ed25519 + Dilithium3 — Spec §3.2 (lines 174–187).
//!
//! Construction:
//! ```text
//!   pre = BLAKE3("L1-Sig-v1" || m)            (32 B)
//!   σ_ed  = Ed25519.Sign(sk_ed, pre)          (64 B)
//!   σ_dil = Dilithium3.Sign(sk_dil, pre)      (3,309 B detached, ML-DSA-65)
//!   σ     = σ_ed || σ_dil                     (3,373 B)
//! ```
//!
//! Verify accepts iff BOTH classical and PQ verifies succeed.
//! EUF-CMA-secure if *either* component is EUF-CMA-secure.
//!
//! Addendum A1 §10: every signature carries a usecase tag
//! (`pre = BLAKE3("L1-Sig-v1" || u8(len) || tag || m)`). The untagged form and
//! the legacy-accept switch are gone from the public API; untagged
//! signatures verify nowhere.

use crate::constants::*;
use crate::error::{Error, Result};

use ed25519_dalek::{
    Signature as EdSig, Signer, SigningKey as EdSigningKey, Verifier, VerifyingKey as EdVerifyingKey,
};
use oqs::sig::{Algorithm as OqsSigAlgorithm, Sig as OqsSig};
use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{
    DetachedSignature as DilDetachedSigTrait, PublicKey as DilPk, SecretKey as DilSk,
};
use rand_core::{OsRng, RngCore};
use std::sync::OnceLock;

const HSIG_DOMAIN: &[u8] = b"L1-Sig-v1";

/// HOTFIX 2026-05-13: iOS-Clients signieren mit liboqs ml_dsa_65 (FIPS-204).
/// Der Server signiert/verifiziert mit pqcrypto-dilithium 0.5 (NIST Round 3),
/// das ist mit FIPS-204 nicht bit-kompatibel. Bis iOS auf pqcrypto migriert ist
/// muss der Server beide Verifier akzeptieren (Pre-cd71489-Verhalten).
///
/// Env-Flag `LADON_RCV2_HSIG_ACCEPT_OQS` (Default: "1"/true) erlaubt Operatoren
/// den OQS-Fallback wieder zu schliessen sobald alle Clients migriert sind —
/// genau wie es `LADON_RCV2_ACCEPT_LEGACY_HSIG` für tagged sigs macht.
fn oqs_fallback_enabled() -> bool {
    static FLAG: OnceLock<bool> = OnceLock::new();
    *FLAG.get_or_init(|| {
        match std::env::var("LADON_RCV2_HSIG_ACCEPT_OQS") {
            Ok(v) => {
                let v = v.trim().to_ascii_lowercase();
                !matches!(v.as_str(), "0" | "false" | "no" | "off")
            }
            Err(_) => true,
        }
    })
}

fn verify_dilithium_with_oqs(pre: &[u8], pk_bytes: &[u8], sig_bytes: &[u8]) -> Result<()> {
    let scheme = OqsSig::new(OqsSigAlgorithm::MlDsa65)
        .map_err(|_| Error::Internal("oqs ml_dsa_65 unavailable"))?;
    let pk = scheme
        .public_key_from_bytes(pk_bytes)
        .ok_or(Error::Internal("invalid ml_dsa_65 public key"))?;
    let sig = scheme
        .signature_from_bytes(sig_bytes)
        .ok_or(Error::Internal("invalid ml_dsa_65 signature"))?;
    scheme
        .verify(pre, sig, pk)
        .map_err(|_| Error::Internal("ml_dsa_65 verify failed"))
}

/// P7-RCV2-03 / A1 §10: per-usecase domain tags. Without these, bundle,
/// fetch, push-register and inner-sender signatures made with the same
/// identity key would share one BLAKE3 input space, and a signature from
/// one context could be offered in another. The tag is length-prefixed
/// (1-byte length) before being folded into the prehash, so two tags can
/// never collide even if one is a prefix of the other.
pub const HSIG_USECASE_BUNDLE: &[u8] = b"L1-Bundle-v3";
pub const HSIG_USECASE_FETCH: &[u8] = b"L1-Fetch-v2.1";
pub const HSIG_USECASE_PUSH_REGISTER: &[u8] = b"L1-PushRegister-v3";
/// Verified by the recipient app only (relays never see the inner layer);
/// defined here so the cross-language vectors cover it.
pub const HSIG_USECASE_INNER_SENDER: &[u8] = b"L1-InnerSender-v3";
/// SRV-14: pairing codes signed by the app. Relays never verify it; it is
/// mirrored here so the disjointness tests and the cross-language vectors
/// cover every tag the identity key signs under.
pub const HSIG_USECASE_PAIRING: &[u8] = b"L1-Pairing-v1";

/// Untagged pre-hash per spec §3.2 line 181/182: `BLAKE3("L1-Sig-v1" || m)`.
/// Test-only since A1: nothing in production signs or verifies untagged.
#[cfg(test)]
fn prehash(m: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(HSIG_DOMAIN);
    h.update(m);
    *h.finalize().as_bytes()
}

/// Per-usecase prehash (P7-RCV2-03).
/// `BLAKE3("L1-Sig-v1" || u8(usecase.len()) || usecase || m)` — 32 B.
/// Panics if `usecase.len() > 255`; the four exported constants are all far below that bound.
pub fn prehash_tagged(usecase: &[u8], m: &[u8]) -> [u8; 32] {
    assert!(usecase.len() <= u8::MAX as usize, "usecase tag too long");
    let mut h = blake3::Hasher::new();
    h.update(HSIG_DOMAIN);
    h.update(&[usecase.len() as u8]);
    h.update(usecase);
    h.update(m);
    *h.finalize().as_bytes()
}

/// Combined HSig keypair (long-term identity).
pub struct HsigKeyPair {
    pub ed_sk: EdSigningKey,
    pub ed_pk: EdVerifyingKey,
    pub dil_sk: dilithium3::SecretKey,
    pub dil_pk: dilithium3::PublicKey,
}

/// P7-RCV2-08: best-effort wipe of the long-term HSig keypair on drop.
/// `ed25519_dalek::SigningKey` already implements `ZeroizeOnDrop` upstream, so
/// `ed_sk` is wiped automatically. `pqcrypto-dilithium 0.5`'s `SecretKey` is an
/// opaque type with no public byte-mut accessor or Zeroize impl; we cannot
/// safely wipe it from outside the crate without `unsafe`-transmute. This is
/// tracked as an upstream gap (parallel to RCV2-09 / RCV2-15 MLKEM migration).
impl Drop for HsigKeyPair {
    fn drop(&mut self) {
        // `ed_sk` zeroizes itself via ed25519_dalek's ZeroizeOnDrop.
        // `dil_sk` cannot be wiped from outside the crate (upstream gap).
        // `ed_pk` and `dil_pk` are public material.
    }
}

impl HsigKeyPair {
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let ed_sk = EdSigningKey::from_bytes(&seed);
        let ed_pk = ed_sk.verifying_key();
        let (dil_pk, dil_sk) = dilithium3::keypair();
        Self { ed_sk, ed_pk, dil_sk, dil_pk }
    }

    /// Public key wire layout: `Ed25519_PK (32) || Dilithium3_PK (1,952)` = 1,984 B.
    pub fn public_key_bytes(&self) -> [u8; HSIG_PK_LEN] {
        let mut out = [0u8; HSIG_PK_LEN];
        out[..ED25519_PK_LEN].copy_from_slice(self.ed_pk.as_bytes());
        out[ED25519_PK_LEN..].copy_from_slice(self.dil_pk.as_bytes());
        out
    }

    /// Reconstruct a keypair from raw secret-key components.
    pub fn from_components(
        ed_sk_bytes: &[u8; 32],
        dil_sk_bytes: &[u8],
        dil_pk_bytes: &[u8],
    ) -> Result<Self> {
        let ed_sk = EdSigningKey::from_bytes(ed_sk_bytes);
        let ed_pk = ed_sk.verifying_key();
        let dil_sk = dilithium3::SecretKey::from_bytes(dil_sk_bytes)
            .map_err(|_| Error::Internal("invalid dilithium3 secret key"))?;
        let dil_pk = dilithium3::PublicKey::from_bytes(dil_pk_bytes)
            .map_err(|_| Error::Internal("invalid dilithium3 public key"))?;
        Ok(Self { ed_sk, ed_pk, dil_sk, dil_pk })
    }

    /// Untagged sign — test-only since A1 (used to prove that untagged
    /// signatures are rejected).
    #[cfg(test)]
    pub(crate) fn sign(&self, m: &[u8]) -> [u8; HSIG_SIG_LEN] {
        let pre = prehash(m);
        self.sign_pre(&pre)
    }

    /// Sign with a per-usecase domain tag. Callers must use one of the
    /// `HSIG_USECASE_*` constants so that signatures of different contexts
    /// live in disjoint hash domains and cannot be replayed cross-context.
    pub fn sign_tagged(&self, usecase: &[u8], m: &[u8]) -> [u8; HSIG_SIG_LEN] {
        let pre = prehash_tagged(usecase, m);
        self.sign_pre(&pre)
    }

    fn sign_pre(&self, pre: &[u8; 32]) -> [u8; HSIG_SIG_LEN] {
        let ed_sig: EdSig = self.ed_sk.sign(pre);
        let dil_sig = dilithium3::detached_sign(pre, &self.dil_sk);

        let mut out = [0u8; HSIG_SIG_LEN];
        out[..ED25519_SIG_LEN].copy_from_slice(&ed_sig.to_bytes());

        let dil_bytes = dil_sig.as_bytes();
        debug_assert_eq!(dil_bytes.len(), DILITHIUM3_SIG_LEN);
        out[ED25519_SIG_LEN..].copy_from_slice(dil_bytes);
        out
    }
}

/// Untagged verify — test-only since A1.
#[cfg(test)]
pub(crate) fn verify(pk_bytes: &[u8], m: &[u8], sig_bytes: &[u8]) -> Result<()> {
    let pre = prehash(m);
    verify_pre(pk_bytes, &pre, sig_bytes)
}

/// Verify a hybrid signature over `m` under usecase tag `usecase` against
/// the wire-format public key (1,984 B). `Ok(())` iff BOTH the classical and
/// the PQ half verify.
pub fn verify_tagged(usecase: &[u8], pk_bytes: &[u8], m: &[u8], sig_bytes: &[u8]) -> Result<()> {
    let pre = prehash_tagged(usecase, m);
    verify_pre(pk_bytes, &pre, sig_bytes)
}

fn verify_pre(pk_bytes: &[u8], pre: &[u8; 32], sig_bytes: &[u8]) -> Result<()> {
    if pk_bytes.len() != HSIG_PK_LEN {
        return Err(Error::Short { expected: HSIG_PK_LEN, got: pk_bytes.len() });
    }
    if sig_bytes.len() != HSIG_SIG_LEN {
        return Err(Error::Short { expected: HSIG_SIG_LEN, got: sig_bytes.len() });
    }

    let mut ed_pk_bytes = [0u8; ED25519_PK_LEN];
    ed_pk_bytes.copy_from_slice(&pk_bytes[..ED25519_PK_LEN]);
    let ed_pk = EdVerifyingKey::from_bytes(&ed_pk_bytes)
        .map_err(|_| Error::Internal("invalid ed25519 public key"))?;
    let dil_pk = dilithium3::PublicKey::from_bytes(&pk_bytes[ED25519_PK_LEN..])
        .map_err(|_| Error::Internal("invalid dilithium3 public key"))?;

    let mut ed_sig_bytes = [0u8; ED25519_SIG_LEN];
    ed_sig_bytes.copy_from_slice(&sig_bytes[..ED25519_SIG_LEN]);
    let ed_sig = EdSig::from_bytes(&ed_sig_bytes);
    let dil_sig_bytes = &sig_bytes[ED25519_SIG_LEN..];

    // Verify both halves; accept only if Ed25519 and PQ verification pass.
    ed_pk
        .verify(pre, &ed_sig)
        .map_err(|_| Error::Internal("ed25519 verify failed"))?;

    // FIX P7-RCV2-01 (audit 2026-05-12): primary verifier ist strict pqcrypto-dilithium.
    // HOTFIX 2026-05-13: zusätzlicher OQS-Fallback (FIPS-204 ml_dsa_65) für iOS-Clients,
    // die liboqs signieren. pqcrypto-dilithium 0.5 = NIST Round 3, oqs ml_dsa_65 = FIPS-204
    // final, beide Formate sind nicht bit-kompatibel. Gated hinter LADON_RCV2_HSIG_ACCEPT_OQS
    // (Default an). Wird vom OQS-Pfad bestätigt → Ok. Anti-Confusion: der Ed25519-Teil
    // wurde oben bereits strict verifiziert, der OQS-Fallback betrifft NUR die PQ-Hälfte.
    let pq_strict = dilithium3::DetachedSignature::from_bytes(dil_sig_bytes)
        .ok()
        .and_then(|s| dilithium3::verify_detached_signature(&s, pre, &dil_pk).ok());
    if pq_strict.is_some() {
        return Ok(());
    }
    if oqs_fallback_enabled() {
        return verify_dilithium_with_oqs(pre, &pk_bytes[ED25519_PK_LEN..], dil_sig_bytes);
    }
    Err(Error::Internal("dilithium3 verify failed"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dilithium_signature_length_matches_constant() {
        // Catches silent dependency drift.
        let (_, sk) = dilithium3::keypair();
        let sig = dilithium3::detached_sign(&[0u8; 32], &sk);
        assert_eq!(sig.as_bytes().len(), DILITHIUM3_SIG_LEN);
    }

    #[test]
    fn sign_verify_roundtrip() {
        let kp = HsigKeyPair::generate();
        let pk = kp.public_key_bytes();
        let m = b"the quick brown fox jumps over the lazy dog";
        let sig = kp.sign(m);
        assert_eq!(sig.len(), HSIG_SIG_LEN);
        verify(&pk, m, &sig).expect("verify should succeed");
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let kp = HsigKeyPair::generate();
        let pk = kp.public_key_bytes();
        let sig = kp.sign(b"original");
        assert!(verify(&pk, b"tampered", &sig).is_err());
    }

    #[test]
    fn verify_rejects_wrong_pk() {
        let kp_a = HsigKeyPair::generate();
        let kp_b = HsigKeyPair::generate();
        let sig = kp_a.sign(b"hello");
        assert!(verify(&kp_b.public_key_bytes(), b"hello", &sig).is_err());
    }

    #[test]
    fn verify_rejects_flipped_classical_half() {
        // Flip a byte in σ_ed → ed verify fails → overall fails.
        let kp = HsigKeyPair::generate();
        let pk = kp.public_key_bytes();
        let mut sig = kp.sign(b"msg");
        sig[0] ^= 0x01;
        assert!(verify(&pk, b"msg", &sig).is_err());
    }

    #[test]
    fn verify_rejects_flipped_pq_half() {
        // Flip a byte in σ_dil → dilithium verify fails → overall fails.
        let kp = HsigKeyPair::generate();
        let pk = kp.public_key_bytes();
        let mut sig = kp.sign(b"msg");
        sig[ED25519_SIG_LEN + 5] ^= 0x01;
        // May be Internal (parse) or TokenSig (verify) — either rejects.
        assert!(verify(&pk, b"msg", &sig).is_err());
    }

    #[test]
    fn verify_rejects_wrong_lengths() {
        let bad_pk = [0u8; HSIG_PK_LEN - 1];
        let bad_sig = [0u8; HSIG_SIG_LEN - 1];
        assert!(verify(&bad_pk, b"m", &[0u8; HSIG_SIG_LEN]).is_err());
        assert!(verify(&[0u8; HSIG_PK_LEN], b"m", &bad_sig).is_err());
    }

    #[test]
    fn from_components_reconstructs_signing_capability() {
        use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _};
        let kp = HsigKeyPair::generate();
        let ed_sk_bytes: [u8; 32] = kp.ed_sk.to_bytes();
        let dil_sk_bytes = kp.dil_sk.as_bytes().to_vec();
        let dil_pk_bytes = kp.dil_pk.as_bytes().to_vec();
        let restored = HsigKeyPair::from_components(&ed_sk_bytes, &dil_sk_bytes, &dil_pk_bytes)
            .expect("reconstruct");

        let m = b"reconstructed signs";
        let sig = restored.sign(m);
        // Verify with original PK: must succeed.
        verify(&kp.public_key_bytes(), m, &sig).expect("restored kp → original pk verifies");
    }

    #[test]
    fn prehash_is_domain_separated() {
        let direct = blake3::hash(b"hello");
        let domain = prehash(b"hello");
        assert_ne!(direct.as_bytes(), &domain);
    }

    #[test]
    fn pk_layout_classical_then_pq() {
        let kp = HsigKeyPair::generate();
        let pk = kp.public_key_bytes();
        assert_eq!(&pk[..ED25519_PK_LEN], kp.ed_pk.as_bytes());
        use pqcrypto_traits::sign::PublicKey;
        assert_eq!(&pk[ED25519_PK_LEN..], kp.dil_pk.as_bytes());
    }

    #[test]
    fn p7_rcv2_03_tagged_roundtrip() {
        let kp = HsigKeyPair::generate();
        let pk = kp.public_key_bytes();
        let m = b"payload";
        let sig = kp.sign_tagged(HSIG_USECASE_BUNDLE, m);
        verify_tagged(HSIG_USECASE_BUNDLE, &pk, m, &sig).expect("tagged verify");
    }

    #[test]
    fn p7_rcv2_03_cross_usecase_rejected() {
        // A signature minted for the token usecase MUST NOT verify under
        // the bundle (or any other) usecase — this is the entire point of
        // RCV2-03.
        let kp = HsigKeyPair::generate();
        let pk = kp.public_key_bytes();
        let m = b"payload";
        let sig = kp.sign_tagged(HSIG_USECASE_BUNDLE, m);
        assert!(verify_tagged(HSIG_USECASE_FETCH, &pk, m, &sig).is_err());
        assert!(verify_tagged(HSIG_USECASE_PUSH_REGISTER, &pk, m, &sig).is_err());
        assert!(verify_tagged(HSIG_USECASE_INNER_SENDER, &pk, m, &sig).is_err());
        assert!(verify_tagged(HSIG_USECASE_PAIRING, &pk, m, &sig).is_err());
    }

    /// SRV-14: every usecase tag, the app-only pairing tag included, gives a
    /// distinct prehash for the same message, and a signature under one tag
    /// verifies under no other.
    #[test]
    fn usecase_tags_are_pairwise_disjoint() {
        let tags = [
            HSIG_USECASE_BUNDLE,
            HSIG_USECASE_FETCH,
            HSIG_USECASE_PUSH_REGISTER,
            HSIG_USECASE_INNER_SENDER,
            HSIG_USECASE_PAIRING,
        ];
        let m = b"payload";
        let kp = HsigKeyPair::generate();
        let pk = kp.public_key_bytes();
        for (i, a) in tags.iter().enumerate() {
            let sig = kp.sign_tagged(a, m);
            for (j, b) in tags.iter().enumerate() {
                if i == j {
                    verify_tagged(b, &pk, m, &sig).expect("own tag verifies");
                } else {
                    assert_ne!(prehash_tagged(a, m), prehash_tagged(b, m));
                    assert!(verify_tagged(b, &pk, m, &sig).is_err());
                }
            }
        }
    }

    #[test]
    fn p7_rcv2_03_tagged_not_accepted_as_legacy() {
        // A tagged sig must NOT verify under the legacy (untagged) verify.
        let kp = HsigKeyPair::generate();
        let pk = kp.public_key_bytes();
        let m = b"payload";
        let sig = kp.sign_tagged(HSIG_USECASE_BUNDLE, m);
        assert!(verify(&pk, m, &sig).is_err());
    }

    #[test]
    fn a1_untagged_signature_is_rejected_under_every_tag() {
        // A1 §10: there is no legacy path. An untagged signature verifies
        // under no usecase.
        let kp = HsigKeyPair::generate();
        let pk = kp.public_key_bytes();
        let m = b"payload";
        let untagged = kp.sign(m);
        for tag in [HSIG_USECASE_BUNDLE, HSIG_USECASE_FETCH, HSIG_USECASE_PUSH_REGISTER, HSIG_USECASE_INNER_SENDER, HSIG_USECASE_PAIRING] {
            assert!(verify_tagged(tag, &pk, m, &untagged).is_err());
        }
    }
}
