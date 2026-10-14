//! Sealed requests and responses — Addendum A2 §4 (relay protocol 0x06).
//!
//! Every client request is sealed to the HKEM key of its target (an Exit or
//! the push relay). The Entry routes it by `target_id` and sees nothing else;
//! sizes are fixed per lane, so it cannot tell request kinds apart either.
//!
//! ```text
//! request  (lane size, exactly):
//!   off=0      1 B      version   = 0x06
//!   off=1      16 B     target_id
//!   off=17     1,120 B  hkem_ct   HKEM.Encaps(target pk)
//!   off=1,137  12 B     nonce
//!   off=1,149  …        ChaCha20-Poly1305(k_req, nonce, plaintext, aad_req) incl. 16 B tag
//!   plaintext = kind (1) || body_len (u16 BE) || body || zeros
//!
//! response (lane size, exactly):
//!   off=0      12 B     nonce
//!   off=12     …        ChaCha20-Poly1305(k_resp, nonce, plaintext, aad_resp) incl. 16 B tag
//!   plaintext = status (1) || target_time (u64 BE) || body_len (u16 BE) || body || zeros
//!
//! ss     = HKEM shared secret (32 B, as for the outer envelope)
//! k_req  = HKDF-SHA256(ikm = ss, salt = none, info = "L1-SealedReq-v1")
//! k_resp = HKDF-SHA256(ikm = ss, salt = none, info = "L1-SealedResp-v1")
//! aad_*  = info label || version || target_id
//! ```
//!
//! The padding is inside the AEAD, so it is authenticated, and it must be
//! zero: a parser that ignored it would give a sender a covert channel.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::constants::{AEAD_NONCE_LEN, AEAD_TAG_LEN, EXIT_ID_LEN, HKEM_CT_LEN};
use crate::error::{Error, Result};
use crate::hkem::{self, HkemKeyPair};

/// Relay protocol version of sealed requests (A2 stage 2).
pub const SEALED_VERSION: u8 = 0x06;

pub const SEALED_OFF_TARGET_ID: usize = 1;
pub const SEALED_OFF_HKEM_CT: usize = SEALED_OFF_TARGET_ID + EXIT_ID_LEN; // 17
pub const SEALED_OFF_NONCE: usize = SEALED_OFF_HKEM_CT + HKEM_CT_LEN; // 1,137
pub const SEALED_REQ_HEADER_LEN: usize = SEALED_OFF_NONCE + AEAD_NONCE_LEN; // 1,149

/// Lane S (send): request and response size (A2 §5).
pub const LANE_S_REQUEST_LEN: usize = 16_384;
pub const LANE_S_RESPONSE_LEN: usize = 8_192;
/// Lane F (fetch / own identity): request and response size (A2 §5).
pub const LANE_F_REQUEST_LEN: usize = 8_192;
pub const LANE_F_RESPONSE_LEN: usize = 16_384;

/// Fixed inner-envelope length under relay protocol 0x06: the ENQUEUE body
/// (rid 32, K_X 32, sent_at 8, envelope id 16, inner envelope) fills lane S
/// exactly. A1 had 15,130 B; the 2-byte body length costs two of them.
pub const SEALED_INNER_ENVELOPE_LEN: usize = LANE_S_REQUEST_LEN
    - SEALED_REQ_HEADER_LEN
    - AEAD_TAG_LEN
    - REQ_PT_PREFIX
    - (32 + 32 + 8 + 16);

/// A2 §5 / decision D1: the lane tick.
pub const TICK_SEC: u64 = 3;
/// A2 §7: a recipient that fetched within this window counts as online and
/// gets no push (five ticks: lane F fetches once per tick).
pub const ONLINE_WINDOW_SEC: u64 = 5 * TICK_SEC;
/// A2 §7: an envelope for a recipient that counted as online is checked
/// again after this long; if the recipient has not fetched since it
/// arrived, it is notified then. Three ticks cover two missed fetches. This
/// closes the gap after a suspension: a device that fetched just before
/// iOS froze it still counts as online for `ONLINE_WINDOW_SEC`.
pub const DEFERRED_PUSH_CHECK_SEC: u64 = 3 * TICK_SEC;

const INFO_REQ: &[u8] = b"L1-SealedReq-v1";
const INFO_RESP: &[u8] = b"L1-SealedResp-v1";

/// kind || body_len
const REQ_PT_PREFIX: usize = 1 + 2;
/// status || target_time || body_len
const RESP_PT_PREFIX: usize = 1 + 8 + 2;

/// The two fixed-rate lanes (A2 §5). Lane S runs on the send connection,
/// lane F on the identity connection (A2 §2a): every kind that names the
/// client's own rid is a lane-F kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lane {
    Send,
    Fetch,
}

impl Lane {
    pub const fn request_len(self) -> usize {
        match self {
            Lane::Send => LANE_S_REQUEST_LEN,
            Lane::Fetch => LANE_F_REQUEST_LEN,
        }
    }

    pub const fn response_len(self) -> usize {
        match self {
            Lane::Send => LANE_S_RESPONSE_LEN,
            Lane::Fetch => LANE_F_RESPONSE_LEN,
        }
    }

    /// The lane a request of exactly `len` bytes belongs to.
    pub fn from_request_len(len: usize) -> Option<Lane> {
        match len {
            LANE_S_REQUEST_LEN => Some(Lane::Send),
            LANE_F_REQUEST_LEN => Some(Lane::Fetch),
            _ => None,
        }
    }

    /// Largest request body that fits this lane.
    pub const fn max_request_body(self) -> usize {
        self.request_len() - SEALED_REQ_HEADER_LEN - AEAD_TAG_LEN - REQ_PT_PREFIX
    }

    /// Largest response body that fits this lane.
    pub const fn max_response_body(self) -> usize {
        self.response_len() - AEAD_NONCE_LEN - AEAD_TAG_LEN - RESP_PT_PREFIX
    }
}

/// Request kinds (A2 §4.1). Values start at 0x10 so they never coincide with
/// the inner version (0x02/0x03), the ratchet frame versions or the relay
/// protocol version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Enqueue = 0x11,
    Fetch = 0x12,
    DirGet = 0x13,
    DirPut = 0x14,
    PushRegister = 0x15,
    Cover = 0x16,
    /// F43: exit -> push relay, body = rid (32). Sent on the S2S route
    /// `POST /v2/push/notify` (HMAC-authenticated), never by a client;
    /// the push relay refuses it on its client route.
    PushNotify = 0x17,
    /// F43: exit -> push relay, body = rid (32) || hsig_pk (1,984). Sent on
    /// the S2S route `PUT /v2/directory/replicate`, never by a client.
    PushReplicate = 0x18,
}

impl Kind {
    pub fn from_u8(b: u8) -> Option<Kind> {
        Some(match b {
            0x11 => Kind::Enqueue,
            0x12 => Kind::Fetch,
            0x13 => Kind::DirGet,
            0x14 => Kind::DirPut,
            0x15 => Kind::PushRegister,
            0x16 => Kind::Cover,
            0x17 => Kind::PushNotify,
            0x18 => Kind::PushReplicate,
            _ => return None,
        })
    }

    /// The only lane this kind may travel in (A2 §5).
    pub const fn lane(self) -> Lane {
        match self {
            Kind::Enqueue | Kind::DirGet | Kind::Cover => Lane::Send,
            Kind::Fetch
            | Kind::DirPut
            | Kind::PushRegister
            | Kind::PushNotify
            | Kind::PushReplicate => Lane::Fetch,
        }
    }
}

/// Response status values carried inside the sealed response (A2 §4.2). The
/// outer HTTP status is 200 whenever the target could open the request.
pub mod status {
    pub const OK: u8 = 0x00;
    pub const MALFORMED: u8 = 0x01;
    pub const STALE: u8 = 0x02;
    pub const REPLAY: u8 = 0x03;
    pub const RATE: u8 = 0x04;
    pub const DELIVERY_KEY: u8 = 0x05;
    pub const UNKNOWN_RECIPIENT: u8 = 0x06;
    pub const FETCH_SIG: u8 = 0x07;
    pub const SIGNATURE: u8 = 0x08;
    pub const UNAVAILABLE: u8 = 0x09;
    pub const INTERNAL: u8 = 0x0A;
}

/// `k_resp` for one request. Wiped on drop; never logged (no `Debug`).
pub struct ResponseKey(Zeroizing<[u8; 32]>);

/// A request the target opened.
pub struct OpenedRequest {
    pub kind: Kind,
    pub lane: Lane,
    /// Wiped on drop: may carry K_X, a bundle or a push token.
    pub body: Zeroizing<Vec<u8>>,
    pub response_key: ResponseKey,
}

/// A response the client opened.
pub struct OpenedResponse {
    pub status: u8,
    pub target_time: u64,
    pub body: Zeroizing<Vec<u8>>,
}

fn derive(ss: &[u8; 32], info: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let hk = Hkdf::<Sha256>::new(None, ss);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(info, &mut out[..]).map_err(|_| Error::Internal("hkdf expand"))?;
    Ok(out)
}

fn aad(label: &[u8], target_id: &[u8; EXIT_ID_LEN]) -> Vec<u8> {
    let mut a = Vec::with_capacity(label.len() + 1 + EXIT_ID_LEN);
    a.extend_from_slice(label);
    a.push(SEALED_VERSION);
    a.extend_from_slice(target_id);
    a
}

fn random_nonce() -> Result<[u8; AEAD_NONCE_LEN]> {
    let mut n = [0u8; AEAD_NONCE_LEN];
    // Fail closed: no request or response without fresh randomness.
    OsRng.try_fill_bytes(&mut n).map_err(|_| Error::Internal("csprng"))?;
    Ok(n)
}

fn padding_is_zero(b: &[u8]) -> bool {
    b.iter().fold(0u8, |acc, x| acc | x) == 0
}

/// Client side: seal `body` as a `kind` request to the target with HKEM
/// public key `target_hkem_pk` and id `target_id`. Returns the request bytes
/// (exactly the lane's request size) and the key that opens the response.
pub fn seal_request(
    target_hkem_pk: &[u8],
    target_id: &[u8; EXIT_ID_LEN],
    kind: Kind,
    body: &[u8],
) -> Result<(Vec<u8>, ResponseKey)> {
    if body.len() > kind.lane().max_request_body() {
        return Err(Error::TooLarge(body.len()));
    }
    let enc = hkem::encaps(target_hkem_pk)?;
    let nonce = random_nonce()?;
    seal_request_with(&enc.shared_key, &enc.ciphertext, &nonce, target_id, kind, body)
}

/// The deterministic part of `seal_request`: everything after HKEM and the
/// nonce. Private, so production code can only seal with a fresh HKEM secret
/// and a fresh nonce.
fn seal_request_with(
    ss: &[u8; 32],
    hkem_ct: &[u8; HKEM_CT_LEN],
    nonce: &[u8; AEAD_NONCE_LEN],
    target_id: &[u8; EXIT_ID_LEN],
    kind: Kind,
    body: &[u8],
) -> Result<(Vec<u8>, ResponseKey)> {
    let lane = kind.lane();
    if body.len() > lane.max_request_body() {
        return Err(Error::TooLarge(body.len()));
    }
    let k_req = derive(ss, INFO_REQ)?;
    let k_resp = derive(ss, INFO_RESP)?;

    let pt_len = lane.request_len() - SEALED_REQ_HEADER_LEN - AEAD_TAG_LEN;
    let mut pt = Zeroizing::new(vec![0u8; pt_len]);
    pt[0] = kind as u8;
    pt[1..3].copy_from_slice(&(body.len() as u16).to_be_bytes());
    pt[REQ_PT_PREFIX..REQ_PT_PREFIX + body.len()].copy_from_slice(body);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&k_req[..]));
    let ct = cipher
        .encrypt(Nonce::from_slice(nonce), Payload { msg: &pt[..], aad: &aad(INFO_REQ, target_id) })
        .map_err(|_| Error::Internal("aead seal"))?;

    let mut out = Vec::with_capacity(lane.request_len());
    out.push(SEALED_VERSION);
    out.extend_from_slice(target_id);
    out.extend_from_slice(hkem_ct);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ct);
    if out.len() != lane.request_len() {
        return Err(Error::Internal("sealed request size"));
    }
    Ok((out, ResponseKey(k_resp)))
}

/// Target side: open a request addressed to `my_target_id` with key pair
/// `kp`. Refuses a wrong size, version or target, a failed AEAD, an unknown
/// kind, a kind in the wrong lane, a length past the plaintext and non-zero
/// padding.
pub fn open_request(
    kp: &HkemKeyPair,
    my_target_id: &[u8; EXIT_ID_LEN],
    buf: &[u8],
) -> Result<OpenedRequest> {
    let lane = Lane::from_request_len(buf.len()).ok_or(Error::Malformed("sealed request size"))?;
    if buf[0] != SEALED_VERSION {
        return Err(Error::UnsupportedVersion(buf[0]));
    }
    let target_id: [u8; EXIT_ID_LEN] = buf[SEALED_OFF_TARGET_ID..SEALED_OFF_HKEM_CT]
        .try_into()
        .expect("16 bytes");
    if &target_id != my_target_id {
        return Err(Error::WrongTarget);
    }
    let ss = hkem::decaps_zeroizing(kp, &buf[SEALED_OFF_HKEM_CT..SEALED_OFF_NONCE])
        .map_err(|_| Error::Malformed("hkem"))?;
    let k_req = derive(&ss, INFO_REQ)?;
    let k_resp = derive(&ss, INFO_RESP)?;

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&k_req[..]));
    let pt = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&buf[SEALED_OFF_NONCE..SEALED_REQ_HEADER_LEN]),
                Payload { msg: &buf[SEALED_REQ_HEADER_LEN..], aad: &aad(INFO_REQ, &target_id) },
            )
            .map_err(|_| Error::Malformed("aead"))?,
    );
    let kind = Kind::from_u8(pt[0]).ok_or(Error::Malformed("unknown kind"))?;
    if kind.lane() != lane {
        return Err(Error::Malformed("kind in wrong lane"));
    }
    let len = u16::from_be_bytes([pt[1], pt[2]]) as usize;
    let end = REQ_PT_PREFIX + len;
    if end > pt.len() {
        return Err(Error::Malformed("body length"));
    }
    if !padding_is_zero(&pt[end..]) {
        return Err(Error::Malformed("padding"));
    }
    Ok(OpenedRequest {
        kind,
        lane,
        body: Zeroizing::new(pt[REQ_PT_PREFIX..end].to_vec()),
        response_key: ResponseKey(k_resp),
    })
}

/// Target side: seal the response to a request opened with `key`.
pub fn seal_response(
    key: &ResponseKey,
    target_id: &[u8; EXIT_ID_LEN],
    lane: Lane,
    status: u8,
    target_time: u64,
    body: &[u8],
) -> Result<Vec<u8>> {
    let nonce = random_nonce()?;
    seal_response_with(key, &nonce, target_id, lane, status, target_time, body)
}

/// The deterministic part of `seal_response` (private, see `seal_request_with`).
fn seal_response_with(
    key: &ResponseKey,
    nonce: &[u8; AEAD_NONCE_LEN],
    target_id: &[u8; EXIT_ID_LEN],
    lane: Lane,
    status: u8,
    target_time: u64,
    body: &[u8],
) -> Result<Vec<u8>> {
    if body.len() > lane.max_response_body() {
        return Err(Error::TooLarge(body.len()));
    }
    let pt_len = lane.response_len() - AEAD_NONCE_LEN - AEAD_TAG_LEN;
    let mut pt = Zeroizing::new(vec![0u8; pt_len]);
    pt[0] = status;
    pt[1..9].copy_from_slice(&target_time.to_be_bytes());
    pt[9..11].copy_from_slice(&(body.len() as u16).to_be_bytes());
    pt[RESP_PT_PREFIX..RESP_PT_PREFIX + body.len()].copy_from_slice(body);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key.0[..]));
    let ct = cipher
        .encrypt(Nonce::from_slice(nonce), Payload { msg: &pt[..], aad: &aad(INFO_RESP, target_id) })
        .map_err(|_| Error::Internal("aead seal"))?;
    let mut out = Vec::with_capacity(lane.response_len());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ct);
    if out.len() != lane.response_len() {
        return Err(Error::Internal("sealed response size"));
    }
    Ok(out)
}

/// Client side: open the response to a request sealed with `key`.
pub fn open_response(
    key: &ResponseKey,
    target_id: &[u8; EXIT_ID_LEN],
    lane: Lane,
    buf: &[u8],
) -> Result<OpenedResponse> {
    if buf.len() != lane.response_len() {
        return Err(Error::Malformed("sealed response size"));
    }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key.0[..]));
    let pt = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&buf[..AEAD_NONCE_LEN]),
                Payload { msg: &buf[AEAD_NONCE_LEN..], aad: &aad(INFO_RESP, target_id) },
            )
            .map_err(|_| Error::Malformed("aead"))?,
    );
    let status = pt[0];
    let target_time = u64::from_be_bytes(pt[1..9].try_into().expect("8 bytes"));
    let len = u16::from_be_bytes([pt[9], pt[10]]) as usize;
    let end = RESP_PT_PREFIX + len;
    if end > pt.len() {
        return Err(Error::Malformed("body length"));
    }
    if !padding_is_zero(&pt[end..]) {
        return Err(Error::Malformed("padding"));
    }
    Ok(OpenedResponse { status, target_time, body: Zeroizing::new(pt[RESP_PT_PREFIX..end].to_vec()) })
}

/// Cross-language test vectors only (`emit_test_vectors`, feature
/// `test-vectors`; never enabled by a relay): seal with a caller-chosen HKEM
/// secret, HKEM ciphertext and nonces, so Swift can reproduce the bytes.
#[cfg(any(test, feature = "test-vectors"))]
pub struct TestVectorSeal {
    pub k_req: [u8; 32],
    pub k_resp: [u8; 32],
    pub request: Vec<u8>,
    pub response: Vec<u8>,
}

#[cfg(any(test, feature = "test-vectors"))]
#[allow(clippy::too_many_arguments)]
pub fn seal_for_test_vectors(
    ss: &[u8; 32],
    hkem_ct: &[u8; HKEM_CT_LEN],
    request_nonce: &[u8; AEAD_NONCE_LEN],
    response_nonce: &[u8; AEAD_NONCE_LEN],
    target_id: &[u8; EXIT_ID_LEN],
    kind: Kind,
    body: &[u8],
    status: u8,
    target_time: u64,
    response_body: &[u8],
) -> Result<TestVectorSeal> {
    let (request, key) = seal_request_with(ss, hkem_ct, request_nonce, target_id, kind, body)?;
    let response =
        seal_response_with(&key, response_nonce, target_id, kind.lane(), status, target_time, response_body)?;
    Ok(TestVectorSeal { k_req: *derive(ss, INFO_REQ)?, k_resp: *key.0, request, response })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_KINDS: [Kind; 8] = [
        Kind::Enqueue,
        Kind::Fetch,
        Kind::DirGet,
        Kind::DirPut,
        Kind::PushRegister,
        Kind::Cover,
        Kind::PushNotify,
        Kind::PushReplicate,
    ];

    /// F43: the exit -> push kinds fit lane F with their bodies (replicate:
    /// rid 32 + hsig_pk 1,984) and round-trip through from_u8.
    #[test]
    fn exit_to_push_kinds_fit_lane_f() {
        use crate::constants::{DIRECTORY_REPLICATE_BODY_LEN, RECIPIENT_ID_LEN};
        assert!(Lane::Fetch.max_request_body() >= RECIPIENT_ID_LEN + DIRECTORY_REPLICATE_BODY_LEN);
        for k in [Kind::PushNotify, Kind::PushReplicate] {
            assert_eq!(k.lane(), Lane::Fetch);
            assert_eq!(Kind::from_u8(k as u8), Some(k));
        }
    }

    fn target() -> (HkemKeyPair, [u8; 16]) {
        (HkemKeyPair::generate(), [0x42; 16])
    }

    #[test]
    fn sizes_match_the_spec() {
        assert_eq!(SEALED_REQ_HEADER_LEN, 1_149);
        // A2 §5. ENQUEUE body = rid 32 + K_X 32 + sent_at 8 + id 16 + inner
        // envelope. The 2-byte body length costs two bytes against A1's
        // single flags byte, so the fixed inner envelope is 15,128 B under
        // relay protocol 0x06 (A1: 15,130 B) and fills lane S exactly.
        assert_eq!(Lane::Send.max_request_body(), 16_384 - 1_149 - 16 - 3);
        assert_eq!(Lane::Send.max_request_body(), 32 + 32 + 8 + 16 + SEALED_INNER_ENVELOPE_LEN);
        assert_eq!(SEALED_INNER_ENVELOPE_LEN, 15_128);
        assert!(Lane::Fetch.max_request_body() >= crate::constants::BUNDLE_LEN);
        assert!(Lane::Send.max_response_body() >= crate::constants::BUNDLE_LEN);
        // has_more 1 + batch id 16 + item length 4 + one inner envelope.
        assert!(Lane::Fetch.max_response_body() >= 1 + 16 + 4 + SEALED_INNER_ENVELOPE_LEN);
    }

    #[test]
    fn every_kind_round_trips_at_the_lane_size() {
        let (kp, id) = target();
        let pk = kp.public_key_bytes();
        for kind in ALL_KINDS {
            let body = vec![0xA5; 100];
            let (req, ck) = seal_request(&pk, &id, kind, &body).unwrap();
            assert_eq!(req.len(), kind.lane().request_len(), "{kind:?}");
            let opened = open_request(&kp, &id, &req).unwrap();
            assert_eq!(opened.kind, kind);
            assert_eq!(opened.lane, kind.lane());
            assert_eq!(&opened.body[..], &body[..]);

            let resp = seal_response(&opened.response_key, &id, opened.lane, status::OK, 1_791_000_000, b"r")
                .unwrap();
            assert_eq!(resp.len(), kind.lane().response_len());
            let r = open_response(&ck, &id, kind.lane(), &resp).unwrap();
            assert_eq!((r.status, r.target_time, &r.body[..]), (status::OK, 1_791_000_000, &b"r"[..]));
        }
    }

    #[test]
    fn largest_bodies_fit_and_one_more_byte_does_not() {
        let (kp, id) = target();
        let pk = kp.public_key_bytes();
        for kind in [Kind::Enqueue, Kind::DirPut] {
            let max = kind.lane().max_request_body();
            let (req, _) = seal_request(&pk, &id, kind, &vec![1u8; max]).unwrap();
            assert_eq!(&open_request(&kp, &id, &req).unwrap().body[..], &vec![1u8; max][..]);
            assert!(seal_request(&pk, &id, kind, &vec![1u8; max + 1]).is_err());
        }
    }

    #[test]
    fn wrong_target_wrong_key_and_tampering_are_refused() {
        let (kp, id) = target();
        let (req, _) = seal_request(&kp.public_key_bytes(), &id, Kind::Fetch, b"x").unwrap();
        assert!(matches!(open_request(&kp, &[0x43; 16], &req), Err(Error::WrongTarget)));
        assert!(open_request(&HkemKeyPair::generate(), &id, &req).is_err());
        for off in [0usize, 5, SEALED_OFF_HKEM_CT + 7, SEALED_OFF_NONCE + 1, req.len() - 1] {
            let mut t = req.clone();
            t[off] ^= 0x01;
            assert!(open_request(&kp, &id, &t).is_err(), "byte {off} flipped");
        }
        // A request rewritten to name another target fails the AAD.
        let mut t = req.clone();
        t[SEALED_OFF_TARGET_ID..SEALED_OFF_HKEM_CT].copy_from_slice(&[0x43; 16]);
        assert!(open_request(&kp, &[0x43; 16], &t).is_err());
    }

    #[test]
    fn wrong_sizes_and_versions_are_refused() {
        let (kp, id) = target();
        let (req, _) = seal_request(&kp.public_key_bytes(), &id, Kind::Cover, b"").unwrap();
        assert!(open_request(&kp, &id, &req[..req.len() - 1]).is_err());
        let mut longer = req.clone();
        longer.push(0);
        assert!(open_request(&kp, &id, &longer).is_err());
        let mut v = req.clone();
        v[0] = 0x05;
        assert!(matches!(open_request(&kp, &id, &v), Err(Error::UnsupportedVersion(0x05))));
    }

    /// Build a request with a chosen plaintext, bypassing seal_request's
    /// checks, to test what the opener refuses.
    fn raw_request(kp: &HkemKeyPair, id: &[u8; 16], lane: Lane, pt: &[u8]) -> Vec<u8> {
        let enc = hkem::encaps(&kp.public_key_bytes()).unwrap();
        let k_req = derive(&enc.shared_key, INFO_REQ).unwrap();
        let nonce = [7u8; 12];
        let ct = ChaCha20Poly1305::new(Key::from_slice(&k_req[..]))
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: pt, aad: &aad(INFO_REQ, id) })
            .unwrap();
        let mut out = vec![SEALED_VERSION];
        out.extend_from_slice(id);
        out.extend_from_slice(&enc.ciphertext);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        assert_eq!(out.len(), lane.request_len());
        out
    }

    #[test]
    fn opener_refuses_bad_plaintexts() {
        let (kp, id) = target();
        let pt_len = Lane::Fetch.request_len() - SEALED_REQ_HEADER_LEN - AEAD_TAG_LEN;
        let good = |k: u8, len: u16| {
            let mut p = vec![0u8; pt_len];
            p[0] = k;
            p[1..3].copy_from_slice(&len.to_be_bytes());
            p
        };
        // Sanity: the hand-built form opens.
        assert!(open_request(&kp, &id, &raw_request(&kp, &id, Lane::Fetch, &good(0x12, 4))).is_ok());
        // Unknown kind.
        assert!(open_request(&kp, &id, &raw_request(&kp, &id, Lane::Fetch, &good(0x10, 4))).is_err());
        // A lane-S kind in lane F (own-rid kinds must not cross lanes either).
        assert!(open_request(&kp, &id, &raw_request(&kp, &id, Lane::Fetch, &good(0x11, 4))).is_err());
        // Length past the plaintext.
        assert!(open_request(&kp, &id, &raw_request(&kp, &id, Lane::Fetch, &good(0x12, u16::MAX))).is_err());
        // Non-zero padding.
        let mut p = good(0x12, 4);
        *p.last_mut().unwrap() = 1;
        assert!(open_request(&kp, &id, &raw_request(&kp, &id, Lane::Fetch, &p)).is_err());
    }

    #[test]
    fn response_is_bound_to_its_request_and_target() {
        let (kp, id) = target();
        let pk = kp.public_key_bytes();
        let (req_a, key_a) = seal_request(&pk, &id, Kind::Fetch, b"a").unwrap();
        let (_req_b, key_b) = seal_request(&pk, &id, Kind::Fetch, b"b").unwrap();
        let opened = open_request(&kp, &id, &req_a).unwrap();
        let resp = seal_response(&opened.response_key, &id, Lane::Fetch, status::OK, 1, b"x").unwrap();
        assert!(open_response(&key_a, &id, Lane::Fetch, &resp).is_ok());
        assert!(open_response(&key_b, &id, Lane::Fetch, &resp).is_err(), "other request's key");
        assert!(open_response(&key_a, &[0x43; 16], Lane::Fetch, &resp).is_err(), "other target");
        assert!(open_response(&key_a, &id, Lane::Send, &resp).is_err(), "wrong lane size");
        let mut t = resp.clone();
        t[40] ^= 1;
        assert!(open_response(&key_a, &id, Lane::Fetch, &t).is_err());
    }

    #[test]
    fn request_and_response_keys_differ() {
        let ss = [9u8; 32];
        assert_ne!(*derive(&ss, INFO_REQ).unwrap(), *derive(&ss, INFO_RESP).unwrap());
    }
}
