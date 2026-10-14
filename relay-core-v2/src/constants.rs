//! Protocol constants — Spec Appendix A, as amended by Addendum A1
//! (`docs/specs/VARIANTE_1_ADDENDUM_A1_DELIVERY_KEYS.md` §12).

/// Relay protocol version byte (A1 §3.1): outer envelope byte 0 and delivery
/// bundle byte 0. `0x03`/`0x04` are skipped on purpose — they already name the
/// inner cover-traffic version and the ratchet frame version.
pub const RELAY_PROTOCOL_VERSION: u8 = 0x05;

/// Fixed envelope size on the wire — profile=maximum (Appendix A).
pub const ENVELOPE_FIXED_SIZE: usize = 16_384;

/// Permitted clock skew between sender and exit (Appendix A).
pub const CLOCK_SKEW_TOLERANCE_SEC: u64 = 120;

/// A1 §8 step 4: an envelope is accepted only while `|now - sent_at|` is at
/// most this. Twice this (600 s) is far below the Bloom filter's minimum
/// memory of 3,000 s, so a replay inside the window is always detected.
pub const SENT_AT_WINDOW_SEC: u64 = 300;

/// Bloom filter bucket duration (Appendix A).
pub const BLOOM_BUCKET_DURATION_SEC: u64 = 600;

/// Number of Bloom buckets retained in sliding window (Appendix A).
pub const BLOOM_BUCKETS_RETAINED: usize = 6;

/// Target Bloom false-positive rate (Appendix A).
pub const BLOOM_TARGET_FPR: f64 = 1e-5;

/// Mailbox TTL in seconds — Spec §5.5 line 724 ("7 days").
/// Note: §11 mentions 48 h as a future-revision option; operational baseline is 7 days.
pub const MAILBOX_TTL_SEC: u64 = 7 * 24 * 3_600;

/// Maximum bytes of inner-envelope data delivered in a single fetch response.
/// Spec §4.6 / §5.5 line 707 / line 527: "Total size capped at 1 MiB".
pub const FETCH_RESPONSE_MAX_BYTES: usize = 1_048_576;

/// Length of the batch id an acknowledged fetch returns (`X-Ladon-Batch`)
/// and the client echoes as its ack (`X-Ladon-Ack`). Random per batch,
/// drawn by the exit; all-zero means "nothing to acknowledge".
pub const FETCH_BATCH_ID_LEN: usize = 16;

/// LRU capacity for the in-RAM recipient directory — Spec §5.2 line 609.
pub const DIRECTORY_LRU_CAPACITY: usize = 200_000;

// ----------------------------------------------------------------------------
// Wire-format byte sizes (§4) — derived from primitives, fixed at compile time.
// ----------------------------------------------------------------------------

/// Recipient ID = SHA-256(IK_R) — 32 bytes.
pub const RECIPIENT_ID_LEN: usize = 32;

/// Exit-Relay ID = BLAKE3(hkem_pk)[..16] — 16 bytes (§3.5, line 233).
pub const EXIT_ID_LEN: usize = 16;

/// Envelope id — 16 random bytes chosen by the sender, fresh per envelope;
/// the replay-filter key (A1 §3.4, §8).
pub const ENVELOPE_ID_LEN: usize = 16;

/// Delivery key `K`, exit delivery key `K_X` and verifier `V_X` (A1 §2) — 32 bytes each.
pub const DELIVERY_KEY_LEN: usize = 32;
pub const DELIVERY_VERIFIER_LEN: usize = 32;

/// Bundle-ID — 16 bytes (§4.2 wire layout, offset 3233).
pub const BUNDLE_ID_LEN: usize = 16;

/// ML-DSA-65 (FIPS 204) signature length — 3,309 bytes (final standardized).
///
/// NB: Earlier draft of `VARIANTE_1_PROTOCOL_SPEC.md` quotes 3,357 B for HSig
/// (= 64 + 3,293), which corresponds to **Round-3 Dilithium3** before FIPS 204
/// finalization (Aug 2024). We adopt the standardized ML-DSA-65 size; this
/// crate is the source of truth and the spec will be updated to match.
pub const DILITHIUM3_SIG_LEN: usize = 3_309;

/// Dilithium3 public key length — 1,952 bytes.
pub const DILITHIUM3_PK_LEN: usize = 1_952;

/// Ed25519 signature length — 64 bytes.
pub const ED25519_SIG_LEN: usize = 64;

/// Ed25519 public key length — 32 bytes.
pub const ED25519_PK_LEN: usize = 32;

/// Kyber768 ciphertext length — 1,088 bytes.
pub const KYBER768_CT_LEN: usize = 1_088;

/// Kyber768 public key length — 1,184 bytes.
pub const KYBER768_PK_LEN: usize = 1_184;

/// X25519 public key length — 32 bytes.
pub const X25519_PK_LEN: usize = 32;

/// X25519 ciphertext (sender ephemeral pubkey) length — 32 bytes.
pub const X25519_CT_LEN: usize = 32;

/// HKEM ciphertext = X25519_CT || Kyber768_CT — 32 + 1,088 = 1,120 bytes (§3.3, §4.4).
pub const HKEM_CT_LEN: usize = X25519_CT_LEN + KYBER768_CT_LEN;

/// HKEM public key = X25519_PK || Kyber768_PK — 32 + 1,184 = 1,216 bytes (§3.3).
pub const HKEM_PK_LEN: usize = X25519_PK_LEN + KYBER768_PK_LEN;

/// HSig public key = Ed25519_PK || Dilithium3_PK — 32 + 1,952 = 1,984 bytes (§3.4).
pub const HSIG_PK_LEN: usize = ED25519_PK_LEN + DILITHIUM3_PK_LEN;

/// HSig signature = Ed25519_SIG || Dilithium3_SIG — 64 + 3,309 = 3,373 bytes (§3.2 — ML-DSA-65 sizes).
pub const HSIG_SIG_LEN: usize = ED25519_SIG_LEN + DILITHIUM3_SIG_LEN;

/// AEAD nonce length — 12 bytes (ChaCha20-Poly1305).
pub const AEAD_NONCE_LEN: usize = 12;

/// AEAD tag length — 16 bytes (ChaCha20-Poly1305).
pub const AEAD_TAG_LEN: usize = 16;

// ----------------------------------------------------------------------------
// Delivery bundle layout (A1 §3.2) — 6,678 B, one bundle per Exit
// ----------------------------------------------------------------------------

pub const BUNDLE_OFF_VERSION: usize = 0;
pub const BUNDLE_OFF_RECIPIENT_ID: usize = 1;
pub const BUNDLE_OFF_HSIG_PK: usize = 33;
pub const BUNDLE_OFF_HKEM_PK: usize = BUNDLE_OFF_HSIG_PK + HSIG_PK_LEN; // 2,017
pub const BUNDLE_OFF_BUNDLE_ID: usize = BUNDLE_OFF_HKEM_PK + HKEM_PK_LEN; // 3,233
pub const BUNDLE_OFF_PUBLISHED_AT: usize = BUNDLE_OFF_BUNDLE_ID + BUNDLE_ID_LEN; // 3,249
pub const BUNDLE_OFF_EXIT_ID: usize = BUNDLE_OFF_PUBLISHED_AT + 8; // 3,257
pub const BUNDLE_OFF_VERIFIER: usize = BUNDLE_OFF_EXIT_ID + EXIT_ID_LEN; // 3,273
pub const BUNDLE_OFF_SIG: usize = BUNDLE_OFF_VERIFIER + DELIVERY_VERIFIER_LEN; // 3,305

/// Signed body = every byte before `bundle_hsig`.
pub const BUNDLE_BODY_LEN: usize = BUNDLE_OFF_SIG; // 3,305
/// Total wire length of a delivery bundle.
pub const BUNDLE_LEN: usize = BUNDLE_BODY_LEN + HSIG_SIG_LEN; // 6,678

// ----------------------------------------------------------------------------
// Outer plaintext layout (A1 §3.4) — 89-byte header, then the inner envelope.
// Since relay protocol 0x06 it is the sealed ENQUEUE body behind a flags byte
// that must be 0: the A1 outer envelope container, its AAD and the
// SUPPRESS_PUSH / DROP bits are gone (A2 stage 2, phase B).
// ----------------------------------------------------------------------------

pub const OUTER_PT_OFF_FLAGS: usize = 0;
pub const OUTER_PT_OFF_RECIPIENT_ID: usize = 1;
pub const OUTER_PT_OFF_DELIVERY_KEY: usize = OUTER_PT_OFF_RECIPIENT_ID + RECIPIENT_ID_LEN; // 33
pub const OUTER_PT_OFF_SENT_AT: usize = OUTER_PT_OFF_DELIVERY_KEY + DELIVERY_KEY_LEN; // 65
pub const OUTER_PT_OFF_ENVELOPE_ID: usize = OUTER_PT_OFF_SENT_AT + 8; // 73
pub const OUTER_PT_HEADER_LEN: usize = OUTER_PT_OFF_ENVELOPE_ID + ENVELOPE_ID_LEN; // 89

// ----------------------------------------------------------------------------
// Inner envelope layout (§4.3)
// ----------------------------------------------------------------------------

/// Inner envelope cryptographic baseline (without AEAD ct + padding):
/// hkem_ct_R(1,120) + aead_nonce(12) = 1,132 B (AEAD tag is counted separately at each use site).
pub const INNER_ENVELOPE_HEADER_LEN: usize = HKEM_CT_LEN + AEAD_NONCE_LEN;

// ----------------------------------------------------------------------------
// AAD domain separation strings (Spec §3.6)
// ----------------------------------------------------------------------------

pub const AAD_INNER_V1: &[u8] = b"L1-Inner-v1";
/// Version byte inside the inner-envelope AAD (`"L1-Inner-v1" || 0x02 || rid`).
/// Unchanged by Addendum A1 — the inner layer is not part of the relay protocol.
pub const INNER_AAD_VERSION: u8 = 0x02;
/// A1 §2.2 / §2.3: `K_X = HKDF-SHA256(salt, K, info || exit_id)`,
/// `V_X = SHA-256(verify-domain || K_X)`.
pub const DOMAIN_DELIVER_SALT: &[u8] = b"L1-DeliverSalt-v1";
pub const DOMAIN_DELIVER_INFO: &[u8] = b"L1-Deliver-v1";
pub const DOMAIN_DELIVER_VERIFY: &[u8] = b"L1-DeliverVerify-v1";
/// Acknowledged fetch:
/// `"L1-FetchAck-v2" || exit_id (16) || rid (32) || ts_be (8) || ack (16)`.
/// The ack names the batch the client has stored; only then does the exit
/// delete it. The only fetch pre-image: the destructive "L1-Fetch-v1" drain
/// was removed with relay protocol 0x05 (A1 §13).
///
/// SRV-13 (F12): v2 binds the signature to the exit it is sent to. A v1
/// signature (no exit_id) was valid at every exit holding the recipient's
/// bundle, so a fetch captured for one exit could be replayed at another
/// within the skew window. v1 is not accepted any more (coordinated break,
/// no fallback); the FETCH body layout is unchanged — the exit inserts its
/// own exit_id when it rebuilds the pre-image.
pub const DOMAIN_FETCH_ACK_AUTH: &[u8] = b"L1-FetchAck-v2";

// ----------------------------------------------------------------------------
// V2.1 — Push-Relay (PutRegister, Notify, DirectoryReplicate)
// ----------------------------------------------------------------------------
//
// Phase 3a (2026-05-04): the push-relay is a separate process running on a
// dedicated host (`push.ladon.app`), not co-located with the exit-relay. It
// holds APNs device tokens and signs/sends APNs HTTP/2 requests on the
// exit-relay's behalf, isolating APNs credentials and the device-token DB
// from the message-routing path.
//
// Authentication model:
//   * PUT /v2/push/register/:rid — client → push (hsig-signed, asymmetric;
//     domain `L1-PushRegister-v2.1`). The push-relay verifies the signature
//     against the recipient's hsig public key, which it learns from a
//     directory-replication push by the exit-relay (variant B).
//   * PUT /v2/directory/replicate — exit → push (S2S HMAC over a sealed
//     PUSH_REPLICATE, F43). Sealed body: rid || hsig public key.
//     Authenticated via the same X-Relay-{Hop,Timestamp,Signature,Nonce}
//     pattern as the entry → exit hop.
//   * POST /v2/push/notify — exit → push (S2S HMAC over a sealed
//     PUSH_NOTIFY, F43). Sealed body: the recipient id (32 B). The
//     push-relay debounces and fires an APNs alert push.

/// APNs device token length on the wire — 32 bytes (matches V1's 64-hex-char
/// validation in `exit-relay/src/main.rs::is_valid_device_token`).
pub const APNS_TOKEN_LEN: usize = 32;

/// Domain separator for the hsig pre-image of `PUT /v2/push/register/:rid`.
/// Distinct from every other v2/v2.1 domain so a leaked signature in one
/// protocol cannot be replayed in another.
pub const DOMAIN_PUSH_REGISTER: &[u8] = b"L1-PushRegister-v2.1";

/// Wire body length for `PUT /v2/push/register/:rid`:
///   apns_token(32) || sandbox(1) || timestamp_be(8) || hsig(3,373) = 3,414 B
pub const PUSH_REGISTER_BODY_LEN: usize =
    APNS_TOKEN_LEN + 1 + 8 + HSIG_SIG_LEN;

/// Default skew window for push-register timestamps (seconds).
pub const PUSH_REGISTER_SKEW_SEC: u64 = 120;

/// Length of the hsig_pk that follows the rid in a sealed PUSH_REPLICATE
/// body (exit→push, F43): hsig_pk(1,984) = 1,984 B.
pub const DIRECTORY_REPLICATE_BODY_LEN: usize = HSIG_PK_LEN;

/// Sealed PUSH_NOTIFY body length (exit→push, F43):
///   recipient_id(32) = 32 B.
///
/// P8-PUSH-NSE-01 (2026-05-21): Phase-1 keeps this constant at exactly
/// the legacy RID-only length so the handler MUST still reject anything
/// else strictly. Phase-3 will replace this single-length check with a
/// `(MIN, MAX)` pair allowing an optional length-prefixed push-blob to
/// follow the rid (`rid || u16-be(blob_len) || blob_bytes`). The new
/// constants below are defined now so all crates can compile against
/// them, but the handler in Phase 1 still uses `PUSH_NOTIFY_BODY_LEN`.
pub const PUSH_NOTIFY_BODY_LEN: usize = RECIPIENT_ID_LEN;

/// P8-PUSH-NSE-01 Phase-3 (2026-05-21): minimum accepted body length for
/// `POST /v2/push/notify`. Equal to legacy RID-only length for backwards
/// compatibility with older exit-relays that have not been upgraded yet.
pub const PUSH_NOTIFY_BODY_MIN: usize = RECIPIENT_ID_LEN;

/// P8-PUSH-NSE-01 Phase-3 (2026-05-21): maximum accepted body length for
/// `POST /v2/push/notify`.
///   rid(32) + u16-be blob_len(2) + blob(<=2048).
/// 2 KiB is generous for an HKEM ciphertext over a Blake3 fingerprint
/// (~1,180 B raw, ~1,620 B base64); leaves headroom for protocol
/// growth without exposing a DoS amplification vector.
pub const PUSH_NOTIFY_BODY_MAX: usize = RECIPIENT_ID_LEN + 2 + 2048;

/// P8-PUSH-NSE-01 Phase-3 (2026-05-21): hard cap on the push blob the
/// exit-relay is willing to forward. Validated again at the push-relay
/// to guard against a malicious exit sending oversized junk that gets
/// embedded into APNs payloads (APNs has its own 4 KiB / 5 KiB caps but
/// we want to fail closed earlier).
pub const PUSH_BLOB_MAX_LEN: usize = 2048;

/// Maximum entries kept in the in-RAM push-token store. Mirrors V1's
/// `MAX_PUSH_ENTRIES` (`exit-relay/src/main.rs` L1264). N5: at capacity the
/// oldest registration is displaced, never a new one refused.
pub const MAX_PUSH_ENTRIES: usize = 100_000;

/// Maximum entries kept in the in-RAM hsig-pk replica (LRU by last put).
/// F10: as large as one exit's directory, so a recipient the exit stores is
/// never refused by the replica. ≈ 2.1 KB per entry, ≈ 420 MB at capacity
/// (see `store::DirectoryReplica`).
pub const MAX_DIRECTORY_REPLICA_ENTRIES: usize = DIRECTORY_LRU_CAPACITY;

/// APNs push debounce — minimum seconds between two alert pushes for the
/// same recipient.
///
/// P8-AUDIT5-PUSH-DEBOUNCE (2026-05-22): reduced from 30s to 10s. The 30s
/// window (inherited from V1) meant a second message arriving within 30s
/// of the first got no push at all — visible to the user as "message 2
/// silently dropped, message 3 pushed". With content-available the woken
/// app fetches ALL pending messages so a single push covers a burst, but
/// 10s tightens the worst-case "next push" latency for an active
/// back-and-forth while still capping APNs fan-out / battery from a true
/// flood. Still well above any abusive rate.
pub const PUSH_DEBOUNCE_SEC: u64 = 10;

#[cfg(test)]
mod test_constants {
    use super::*;

    #[test]
    fn delivery_bundle_layout_matches_addendum_a1() {
        // A1 §3.2 table.
        assert_eq!(BUNDLE_OFF_RECIPIENT_ID, 1);
        assert_eq!(BUNDLE_OFF_HSIG_PK, 33);
        assert_eq!(BUNDLE_OFF_HKEM_PK, 2_017);
        assert_eq!(BUNDLE_OFF_BUNDLE_ID, 3_233);
        assert_eq!(BUNDLE_OFF_PUBLISHED_AT, 3_249);
        assert_eq!(BUNDLE_OFF_EXIT_ID, 3_257);
        assert_eq!(BUNDLE_OFF_VERIFIER, 3_273);
        assert_eq!(BUNDLE_OFF_SIG, 3_305);
        assert_eq!(BUNDLE_LEN, 6_678);
    }

    #[test]
    fn outer_plaintext_layout_matches_addendum_a1() {
        // A1 §3.4 table.
        assert_eq!(OUTER_PT_OFF_RECIPIENT_ID, 1);
        assert_eq!(OUTER_PT_OFF_DELIVERY_KEY, 33);
        assert_eq!(OUTER_PT_OFF_SENT_AT, 65);
        assert_eq!(OUTER_PT_OFF_ENVELOPE_ID, 73);
        assert_eq!(OUTER_PT_HEADER_LEN, 89);
    }

    #[test]
    fn replay_window_is_covered_by_bloom_memory() {
        // A1 §8: two acceptances of one envelope id are at most 2 × window
        // apart; the filter remembers an id for at least (buckets − 1) ×
        // bucket duration.
        let min_memory = (BLOOM_BUCKETS_RETAINED as u64 - 1) * BLOOM_BUCKET_DURATION_SEC;
        assert!(2 * SENT_AT_WINDOW_SEC < min_memory);
    }

    #[test]
    fn primitive_lengths_match_dependencies() {
        use pqcrypto_traits::kem::Ciphertext;
        // Length check that catches silent dependency-version drift.
        let ct = pqcrypto_kyber::kyber768::Ciphertext::from_bytes(&[0u8; KYBER768_CT_LEN])
            .expect("kyber768 ct length matches constant");
        assert_eq!(ct.as_bytes().len(), KYBER768_CT_LEN);
    }
}
