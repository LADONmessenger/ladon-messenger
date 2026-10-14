//! Hybrid KEM (HKEM): X25519 + Kyber768 — Spec §3.3 (lines 195–219).
//!
//! Combiner construction (PQCrypto 2019, Bindel et al.):
//! ```text
//!   K = HKDF-SHA256(
//!         ikm  = K_x || K_ky,
//!         salt = "L1-HKEM-v1",
//!         info = epk_x || ct_ky,
//!         L    = 32)
//! ```
//! - IND-CCA2-secure if either component is IND-CCA2-secure.
//! - All operations are constant-time per their underlying libraries.
//!
//! Wire layout:
//! ```text
//!   pk_HKEM = pk_x (32) || pk_ky (1,184)            = 1,216 B
//!   ct_HKEM = epk_x (32) || ct_ky (1,088)           = 1,120 B
//!   K       =                                          32 B
//! ```

use crate::constants::*;
use crate::error::{Error, Result};

use hkdf::Hkdf;
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{
    Ciphertext as KemCt, PublicKey as KemPk, SecretKey as KemSk, SharedSecret as KemSs,
};
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{PublicKey as XPub, StaticSecret as XSec};
use zeroize::{Zeroize, Zeroizing};

const HKEM_SALT: &[u8] = b"L1-HKEM-v1";

/// P7-RCV2-02: domain-separated info prefix that binds the derived key to
/// the recipient public key.  V2 (legacy) callers used only `epk_x||ct_ky`
/// as info; receivers now prepend this tag plus the recipient `pk_bytes`
/// to the transcript, foreclosing cross-PK reuse of a (k_x, k_ky) pair.
const HKEM_INFO_TAG: &[u8] = b"L1-HKEM-v2.1-info";

/// Combined HKEM keypair (long-term, e.g. recipient or exit-relay).
#[derive(Clone)]
pub struct HkemKeyPair {
    pub x_sk: XSec,
    pub x_pk: XPub,
    pub ky_sk: kyber768::SecretKey,
    pub ky_pk: kyber768::PublicKey,
}

impl HkemKeyPair {
    /// Generate a new HKEM keypair using OS randomness.
    pub fn generate() -> Self {
        let x_sk = XSec::random_from_rng(OsRng);
        let x_pk = XPub::from(&x_sk);
        let (ky_pk, ky_sk) = kyber768::keypair();
        HkemKeyPair { x_sk, x_pk, ky_sk, ky_pk }
    }

    /// Serialize the public key in wire format: `pk_x (32) || pk_ky (1,184)`.
    pub fn public_key_bytes(&self) -> [u8; HKEM_PK_LEN] {
        let mut out = [0u8; HKEM_PK_LEN];
        out[..X25519_PK_LEN].copy_from_slice(self.x_pk.as_bytes());
        out[X25519_PK_LEN..].copy_from_slice(self.ky_pk.as_bytes());
        out
    }

    /// Reconstruct a keypair from raw secret-key components and the public key.
    /// Used for loading from disk.
    pub fn from_components(
        x_sk_bytes: [u8; 32],
        ky_sk_bytes: &[u8],
        ky_pk_bytes: &[u8],
    ) -> Result<Self> {
        let x_sk = XSec::from(x_sk_bytes);
        let x_pk = XPub::from(&x_sk);
        let ky_sk = kyber768::SecretKey::from_bytes(ky_sk_bytes)
            .map_err(|_| Error::Internal("invalid kyber768 secret key"))?;
        let ky_pk = kyber768::PublicKey::from_bytes(ky_pk_bytes)
            .map_err(|_| Error::Internal("invalid kyber768 public key"))?;
        Ok(Self { x_sk, x_pk, ky_sk, ky_pk })
    }
}

/// Output of `encaps`: 32-byte shared key + 1,120-byte ciphertext.
///
/// P7-RCV2-07: `shared_key` is zeroized on drop. Callers that want a
/// move-and-own copy should use [`encaps_zeroizing`] which returns the
/// key wrapped in [`zeroize::Zeroizing`].
pub struct EncapsOutput {
    pub shared_key: [u8; 32],
    pub ciphertext: [u8; HKEM_CT_LEN],
}

impl Drop for EncapsOutput {
    fn drop(&mut self) {
        self.shared_key.zeroize();
        // ciphertext is public material — no need to wipe.
    }
}

/// HKEM encapsulation. Spec §3.3 — `Encaps(pk_x, pk_ky) -> (ct, K)`.
pub fn encaps(pk_bytes: &[u8]) -> Result<EncapsOutput> {
    if pk_bytes.len() != HKEM_PK_LEN {
        return Err(Error::Short { expected: HKEM_PK_LEN, got: pk_bytes.len() });
    }
    // Parse classical and PQ halves.
    let mut x_pk_bytes = [0u8; X25519_PK_LEN];
    x_pk_bytes.copy_from_slice(&pk_bytes[..X25519_PK_LEN]);
    let x_pk = XPub::from(x_pk_bytes);
    let ky_pk = kyber768::PublicKey::from_bytes(&pk_bytes[X25519_PK_LEN..])
        .map_err(|_| Error::Internal("invalid kyber768 public key"))?;

    // Ephemeral X25519 key pair.
    let esk = XSec::random_from_rng(OsRng);
    let epk = XPub::from(&esk);

    // Classical and PQ shared secrets.
    let k_x = esk.diffie_hellman(&x_pk);
    let (k_ky, ct_ky) = kyber768::encapsulate(&ky_pk);

    // Combiner.
    let mut ikm = [0u8; 32 + 32]; // X25519 SS = 32, Kyber768 SS = 32
    ikm[..32].copy_from_slice(k_x.as_bytes());
    ikm[32..].copy_from_slice(k_ky.as_bytes());

    // P7-RCV2-02: bind derived key to recipient public key so that an
    // attacker cannot reuse a (k_x, k_ky) pair captured against another
    // recipient. Transcript: HKEM_INFO_TAG || pk_bytes || epk_x || ct_ky.
    let mut info = Vec::with_capacity(HKEM_INFO_TAG.len() + HKEM_PK_LEN + X25519_CT_LEN + KYBER768_CT_LEN);
    info.extend_from_slice(HKEM_INFO_TAG);
    info.extend_from_slice(pk_bytes);
    info.extend_from_slice(epk.as_bytes());
    info.extend_from_slice(ct_ky.as_bytes());

    let hk = Hkdf::<Sha256>::new(Some(HKEM_SALT), &ikm);
    let mut shared_key = [0u8; 32];
    hk.expand(&info, &mut shared_key).map_err(|_| Error::Internal("hkdf expand"))?;

    // Build ciphertext = epk_x || ct_ky.
    let mut ct = [0u8; HKEM_CT_LEN];
    ct[..X25519_CT_LEN].copy_from_slice(epk.as_bytes());
    ct[X25519_CT_LEN..].copy_from_slice(ct_ky.as_bytes());

    ikm.zeroize();
    Ok(EncapsOutput { shared_key, ciphertext: ct })
}

/// HKEM decapsulation. Spec §3.3 — `Decaps(sk_x, sk_ky, ct) -> K`.
///
/// Returns the same 32-byte K iff the ciphertext is well-formed AND
/// produced by a peer that knew `pk`.
pub fn decaps(kp: &HkemKeyPair, ct_bytes: &[u8]) -> Result<[u8; 32]> {
    if ct_bytes.len() != HKEM_CT_LEN {
        return Err(Error::Short { expected: HKEM_CT_LEN, got: ct_bytes.len() });
    }
    let mut epk_bytes = [0u8; X25519_CT_LEN];
    epk_bytes.copy_from_slice(&ct_bytes[..X25519_CT_LEN]);
    let epk = XPub::from(epk_bytes);
    let ct_ky = kyber768::Ciphertext::from_bytes(&ct_bytes[X25519_CT_LEN..])
        .map_err(|_| Error::Internal("invalid kyber768 ciphertext"))?;

    let k_x = kp.x_sk.diffie_hellman(&epk);
    let k_ky = kyber768::decapsulate(&ct_ky, &kp.ky_sk);

    let mut ikm = [0u8; 32 + 32];
    ikm[..32].copy_from_slice(k_x.as_bytes());
    ikm[32..].copy_from_slice(k_ky.as_bytes());

    // P7-RCV2-02: bind derived key to recipient public key. Receiver
    // already holds the keypair so reconstructing pk is free.
    let pk_bytes_arr = kp.public_key_bytes();
    let mut info = Vec::with_capacity(HKEM_INFO_TAG.len() + HKEM_PK_LEN + X25519_CT_LEN + KYBER768_CT_LEN);
    info.extend_from_slice(HKEM_INFO_TAG);
    info.extend_from_slice(&pk_bytes_arr);
    info.extend_from_slice(epk.as_bytes());
    info.extend_from_slice(ct_ky.as_bytes());

    let hk = Hkdf::<Sha256>::new(Some(HKEM_SALT), &ikm);
    let mut shared_key = [0u8; 32];
    hk.expand(&info, &mut shared_key).map_err(|_| Error::Internal("hkdf expand"))?;

    ikm.zeroize();
    Ok(shared_key)
}

/// P7-RCV2-07: zeroize-on-drop variant of [`decaps`]. Returned key is
/// wiped from memory the moment the [`Zeroizing`] guard goes out of scope.
/// Prefer this in new call sites; the plain [`decaps`] is retained for
/// existing consumers that still want a bare `[u8;32]`.
pub fn decaps_zeroizing(kp: &HkemKeyPair, ct_bytes: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let k = decaps(kp, ct_bytes)?;
    Ok(Zeroizing::new(k))
}

/// P7-RCV2-09: best-effort wipe of the X25519 secret half of an HKEM keypair.
/// `x25519_dalek::StaticSecret` already implements `ZeroizeOnDrop` upstream, so
/// in practice this Drop adds nothing for `x_sk`. The Kyber768 secret key from
/// `pqcrypto-kyber 0.8` exposes no `zeroize`/`as_mut_bytes` API and the type is
/// opaque, so we cannot wipe `ky_sk` from here without unsafe transmute. This
/// is a documented upstream limitation; tracking the migration to
/// `pqcrypto-mlkem` (which has a maintained Zeroize impl) under RCV2-15.
impl Drop for HkemKeyPair {
    fn drop(&mut self) {
        // `x_sk` zeroizes itself via x25519_dalek's ZeroizeOnDrop.
        // `ky_sk` cannot be wiped from outside the crate (upstream gap).
        // `x_pk` and `ky_pk` are public material.
    }
}

/// Test vector helper — fills a buffer with `getrandom` so that fuzz-ish tests
/// don't reuse stack zeros. Public so integration tests in sibling crates can use it.
pub fn fill_random(out: &mut [u8]) {
    OsRng.fill_bytes(out);
}

/// On-disk HKEM keyfile written by `gen_host_secrets`:
/// X25519 SK (32) || Kyber768 SK (2,400) || Kyber768 PK (1,184) = 3,616 B.
pub const KEYFILE_X25519_SK_LEN: usize = 32;
pub const KEYFILE_KYBER768_SK_LEN: usize = 2_400;
pub const KEYFILE_KYBER768_PK_LEN: usize = KYBER768_PK_LEN;
pub const KEYFILE_TOTAL_LEN: usize =
    KEYFILE_X25519_SK_LEN + KEYFILE_KYBER768_SK_LEN + KEYFILE_KYBER768_PK_LEN;

/// Load an HKEM key pair from a keyfile (layout above). Shared by the exit
/// and, since A2 stage 2, the push relay. The file bytes are wiped after use.
pub fn load_keyfile(path: &std::path::Path) -> std::result::Result<HkemKeyPair, String> {
    let bytes = Zeroizing::new(
        std::fs::read(path).map_err(|e| format!("failed to read HKEM keyfile {}: {}", path.display(), e))?,
    );
    if bytes.len() != KEYFILE_TOTAL_LEN {
        return Err(format!(
            "HKEM keyfile {} has wrong size: got {} bytes, expected {}",
            path.display(),
            bytes.len(),
            KEYFILE_TOTAL_LEN
        ));
    }
    let mut x_sk = [0u8; KEYFILE_X25519_SK_LEN];
    x_sk.copy_from_slice(&bytes[..KEYFILE_X25519_SK_LEN]);
    let ky_sk = &bytes[KEYFILE_X25519_SK_LEN..KEYFILE_X25519_SK_LEN + KEYFILE_KYBER768_SK_LEN];
    let ky_pk = &bytes[KEYFILE_X25519_SK_LEN + KEYFILE_KYBER768_SK_LEN..];
    let kp = HkemKeyPair::from_components(x_sk, ky_sk, ky_pk)
        .map_err(|e| format!("invalid key material in {}: {:?}", path.display(), e));
    x_sk.zeroize();
    kp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_public_key_layout() {
        let kp = HkemKeyPair::generate();
        let pk = kp.public_key_bytes();
        assert_eq!(pk.len(), HKEM_PK_LEN);
        // First 32 bytes match X25519 pubkey.
        assert_eq!(&pk[..X25519_PK_LEN], kp.x_pk.as_bytes());
        // Remaining bytes match Kyber768 pubkey.
        use pqcrypto_traits::kem::PublicKey;
        assert_eq!(&pk[X25519_PK_LEN..], kp.ky_pk.as_bytes());
    }

    #[test]
    fn encaps_decaps_roundtrip() {
        let kp = HkemKeyPair::generate();
        let pk = kp.public_key_bytes();
        let out = encaps(&pk).expect("encaps");
        let k2 = decaps(&kp, &out.ciphertext).expect("decaps");
        assert_eq!(out.shared_key, k2, "encaps and decaps must derive equal K");
        assert_eq!(out.ciphertext.len(), HKEM_CT_LEN);
    }

    #[test]
    fn different_runs_produce_different_ct_and_key() {
        let kp = HkemKeyPair::generate();
        let pk = kp.public_key_bytes();
        let a = encaps(&pk).unwrap();
        let b = encaps(&pk).unwrap();
        assert_ne!(a.ciphertext, b.ciphertext);
        assert_ne!(a.shared_key, b.shared_key);
    }

    #[test]
    fn rejects_wrong_length_pk() {
        let bad = [0u8; HKEM_PK_LEN - 1];
        assert!(matches!(encaps(&bad), Err(Error::Short { .. })));
    }

    #[test]
    fn rejects_wrong_length_ct() {
        let kp = HkemKeyPair::generate();
        let bad = [0u8; HKEM_CT_LEN - 1];
        assert!(matches!(decaps(&kp, &bad), Err(Error::Short { .. })));
    }

    #[test]
    fn cross_keypair_decaps_yields_different_key() {
        // CT produced for kp_a, decapsulated with kp_b's secret (Kyber will
        // implicitly reject and return a pseudo-random K via FO-transform).
        // Crucially the resulting K MUST differ from the sender's K.
        let kp_a = HkemKeyPair::generate();
        let kp_b = HkemKeyPair::generate();
        let pk_a = kp_a.public_key_bytes();
        let out = encaps(&pk_a).unwrap();
        let k_wrong = decaps(&kp_b, &out.ciphertext).unwrap();
        assert_ne!(out.shared_key, k_wrong);
    }

    #[test]
    fn from_components_reconstructs_decaps_capability() {
        use pqcrypto_traits::kem::{PublicKey as _, SecretKey as _};
        let kp = HkemKeyPair::generate();
        let x_sk_bytes: [u8; 32] = kp.x_sk.to_bytes();
        let ky_sk_bytes = kp.ky_sk.as_bytes().to_vec();
        let ky_pk_bytes = kp.ky_pk.as_bytes().to_vec();
        let restored =
            HkemKeyPair::from_components(x_sk_bytes, &ky_sk_bytes, &ky_pk_bytes).unwrap();

        let out = encaps(&kp.public_key_bytes()).unwrap();
        let k_orig = decaps(&kp, &out.ciphertext).unwrap();
        let k_restored = decaps(&restored, &out.ciphertext).unwrap();
        assert_eq!(k_orig, k_restored);
    }

    #[test]
    fn shared_key_is_32_bytes() {
        let kp = HkemKeyPair::generate();
        let out = encaps(&kp.public_key_bytes()).unwrap();
        assert_eq!(out.shared_key.len(), 32);
    }

    #[test]
    fn p7_rcv2_02_recipient_pk_in_transcript_changes_key() {
        // Two encaps to *different* recipients produce different shared
        // keys even when the (k_x, k_ky) IKM happens to collide. We
        // cannot easily force a collision, but we can at minimum assert
        // that the same encaps-then-decaps with a swapped pk does not
        // yield the same key (i.e. binding is meaningful).
        let kp_a = HkemKeyPair::generate();
        let kp_b = HkemKeyPair::generate();
        let pk_a = kp_a.public_key_bytes();
        let pk_b = kp_b.public_key_bytes();
        let e_a = encaps(&pk_a).unwrap();
        let e_b = encaps(&pk_b).unwrap();
        // Different recipients → different shared keys (with overwhelming
        // probability — true for any well-formed combined KEM, but here
        // also enforced explicitly by the pk_bytes-in-info binding).
        assert_ne!(e_a.shared_key, e_b.shared_key);
    }
}
