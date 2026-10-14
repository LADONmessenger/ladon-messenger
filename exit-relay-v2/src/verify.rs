//! Signed fetch authorization (Spec §4.7.3, acknowledged fetch per
//! P8-RCV2-SRV-02, usecase tags mandatory per Addendum A1 §10).
//!
//! Delivery authorization (formerly the token pipeline of Spec §4.1.3) lives
//! in `handlers::forward_inner` since Addendum A1 §8: delivery key against
//! the recipient's verifier, freshness window, envelope-id replay filter.

use ladon_relay_core_v2::admission::{SeenFifo, SeenInsert};
use ladon_relay_core_v2::constants::*;
use ladon_relay_core_v2::hsig;

use crate::error::ApiError;

/// Verify an acknowledged-fetch signature.
/// Pre-image: `"L1-FetchAck-v2" || exit_id (16) || recipient_id (32) ||
/// timestamp_be (8) || ack (16)`, signed under usecase tag `"L1-Fetch-v2.1"`.
///
/// The ack is signed because it authorises deletion: unsigned, anyone on the
/// entry↔exit hop could swap it for the outstanding batch id they saw in the
/// previous response and delete mail the client never stored.
///
/// SRV-13 (F12): `exit_id` is always this exit's own id, never taken from
/// the request, so a signature made for another exit does not verify here.
/// The v1 pre-image (without exit_id) is not accepted.
#[allow(clippy::too_many_arguments)]
pub fn verify_fetch_ack_sig(
    recipient_hsig_pk: &[u8],
    exit_id: &ladon_relay_core_v2::ids::ExitId,
    rid: &ladon_relay_core_v2::ids::RecipientId,
    ts: u64,
    ack: &[u8; FETCH_BATCH_ID_LEN],
    sig: &[u8],
    now_sec: u64,
    skew_sec: u64,
) -> Result<(), ApiError> {
    if ts.abs_diff(now_sec) > skew_sec {
        return Err(ApiError::FetchSig);
    }
    let mut m = Vec::with_capacity(
        DOMAIN_FETCH_ACK_AUTH.len() + EXIT_ID_LEN + RECIPIENT_ID_LEN + 8 + FETCH_BATCH_ID_LEN,
    );
    m.extend_from_slice(DOMAIN_FETCH_ACK_AUTH);
    m.extend_from_slice(exit_id.as_bytes());
    m.extend_from_slice(rid.as_bytes());
    m.extend_from_slice(&ts.to_be_bytes());
    m.extend_from_slice(ack);
    hsig::verify_tagged(hsig::HSIG_USECASE_FETCH, recipient_hsig_pk, &m, sig)
        .map_err(|_| ApiError::FetchSig)
}

/// Replay guard for `GET /v2/fetch`.
///
/// The fetch authorisation is `sign("L1-Fetch-v1" || rid || ts)` and carries no
/// nonce, while the handler's effect is destructive — `mailbox.drain` removes
/// the messages with no acknowledgement. Anyone who sees the three headers can
/// therefore replay them inside `fetch_skew_sec` and destroy a recipient's
/// mail. On the entry↔exit hop that is plain HTTP inside the host network, so
/// "anyone" includes every process on the machine. The S2S path has had exactly
/// this protection since 2026-05; the fetch path never got it.
///
/// Closing it needs no protocol change and no client release: a replay must
/// present the identical signature bytes, so remembering the signatures seen
/// inside the window turns "valid signature" into "valid signature, not seen
/// before". Keyed by SHA-256 of the signature so an entry costs 32 B instead of
/// the 3,373 B of a hybrid signature.
///
/// Fail-closed at capacity, like `S2sNonceStore`. Refusing a fetch costs
/// nothing — the mailbox is not drained and the next poll collects the mail —
/// whereas admitting an unchecked one destroys it.
///
/// N3: the capacity used to be a fixed 65,536 for a 120 s window with an
/// O(n) prune per insert, so ~546 verified fetches a second filled it. Every
/// insert follows a `SealedLimits::take_verify`, so at most
/// `MAX_SIG_VERIFIES_PER_SEC` arrive per second; `for_skew` sizes the store
/// for exactly that (`SeenFifo::capacity_for`), so it never fills. Expiry is
/// insertion-ordered (O(1) amortised). A signature is remembered while
/// `now - seen <= ttl` (one second longer than the former `< ttl`).
pub struct FetchReplayStore {
    inner: std::sync::Mutex<SeenFifo<[u8; 32]>>,
}

impl FetchReplayStore {
    pub fn new(ttl_sec: u64, max_entries: usize) -> Self {
        Self { inner: std::sync::Mutex::new(SeenFifo::new(ttl_sec, max_entries)) }
    }

    /// The store `main` runs: TTL = 2 × fetch skew, capacity for
    /// `MAX_SIG_VERIFIES_PER_SEC` inserts a second.
    ///
    /// SRV-11: a signature with timestamp T is accepted while
    /// |T - now| <= skew, so from T - skew to T + skew — up to 2 × skew after
    /// its first use. With a TTL of one skew a replay between skew and
    /// 2 × skew after first use was accepted again.
    ///
    /// At the default 120 s: 2,000 × 241 = 482,000 entries of a 32-byte key
    /// (set + FIFO, roughly 100 B each), about 50 MB at full rate.
    pub fn for_skew(fetch_skew_sec: u64) -> Self {
        let ttl = fetch_skew_sec.saturating_mul(2);
        Self::new(
            ttl,
            SeenFifo::<[u8; 32]>::capacity_for(crate::sealed::MAX_SIG_VERIFIES_PER_SEC, ttl),
        )
    }

    /// Returns `true` iff this signature has not been seen within the TTL
    /// window; on `true` it is recorded. `false` means replay — or capacity,
    /// which is refused for the same reason.
    pub fn insert_if_new(&self, sig: &[u8], now_sec: u64) -> bool {
        use sha2::{Digest, Sha256};
        let key: [u8; 32] = Sha256::digest(sig).into();
        // Poison-tolerant: a panic elsewhere must not turn every later fetch
        // into a hard failure (relay-core uses this form throughout).
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.insert_if_new(key, now_sec) == SeenInsert::Fresh
    }

    pub fn capacity(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).capacity()
    }

    /// Number of remembered signatures. Not named `len` on purpose — a public
    /// `len` without `is_empty` is a clippy finding, and `is_empty` would be
    /// meaningless here.
    #[cfg(test)]
    pub fn entry_count(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ladon_relay_core_v2::hsig::HsigKeyPair;
    use ladon_relay_core_v2::ids::{ExitId, RecipientId};

    // ---- FetchReplayStore --------------------------------------------------

    #[test]
    fn fetch_replay_refuses_the_same_signature_twice() {
        // The attack: capture the three fetch headers off the entry-exit hop
        // and resend them inside the skew window. The signature verifies again
        // — only "seen before" can stop it.
        let st = FetchReplayStore::new(120, 1024);
        let sig = vec![0xAB; 3373];
        assert!(st.insert_if_new(&sig, 1_000), "first use must pass");
        assert!(!st.insert_if_new(&sig, 1_000), "replay must be refused");
        assert!(!st.insert_if_new(&sig, 1_060), "still inside the window");
    }

    #[test]
    fn fetch_replay_allows_distinct_signatures() {
        let st = FetchReplayStore::new(120, 1024);
        assert!(st.insert_if_new(&[1u8; 64], 1_000));
        assert!(st.insert_if_new(&[2u8; 64], 1_000));
        assert_eq!(st.entry_count(), 2);
    }

    #[test]
    fn fetch_replay_forgets_after_the_skew_window() {
        // Outside the window verify_fetch_sig rejects on drift anyway, so
        // holding the entry longer buys nothing and would only grow RAM.
        let st = FetchReplayStore::new(120, 1024);
        let sig = vec![0xCD; 64];
        assert!(st.insert_if_new(&sig, 1_000));
        assert!(st.insert_if_new(&sig, 1_121), "expired entry must be pruned");
    }

    #[test]
    fn fetch_replay_is_fail_closed_at_capacity() {
        // Refusing a fetch costs nothing: the mailbox is not drained and the
        // next poll collects the mail. Admitting an unchecked one destroys it.
        let st = FetchReplayStore::new(120, 2);
        assert!(st.insert_if_new(&[1u8; 8], 10));
        assert!(st.insert_if_new(&[2u8; 8], 10));
        assert!(!st.insert_if_new(&[3u8; 8], 10), "must refuse, not admit");
    }

    /// N3: the store as `main` builds it never fills at the verify rate
    /// (every insert follows a `take_verify`). Before, it held 65,536
    /// entries for 120 s, so ~546 fetches/s filled it and every later fetch
    /// was refused as a replay.
    #[test]
    fn fetch_replay_never_fills_at_the_verify_rate() {
        let skew = 120u64;
        let st = FetchReplayStore::for_skew(skew);
        let rate = crate::sealed::MAX_SIG_VERIFIES_PER_SEC as u64;
        let t0 = 1_000_000u64;
        for sec in 0..2 * (2 * skew + 1) {
            for i in 0..rate {
                let mut sig = [0u8; 16];
                sig[..8].copy_from_slice(&sec.to_be_bytes());
                sig[8..].copy_from_slice(&i.to_be_bytes());
                assert!(st.insert_if_new(&sig, t0 + sec), "fresh signature refused at second {sec}, #{i}");
            }
        }
    }

    /// SRV-11: a fetch signature with ts = T is accepted while
    /// |T - now| <= skew, i.e. from T - skew to T + skew: up to 2 × skew
    /// after its first use. A replay at 1.5 × skew after first use must be
    /// refused (with a TTL of one skew it was accepted).
    #[test]
    fn fetch_replay_is_remembered_for_two_skews() {
        let skew = 120u64;
        let st = FetchReplayStore::for_skew(skew);
        let sig = vec![0x5E; 64];
        assert!(st.insert_if_new(&sig, 1_000));
        assert!(!st.insert_if_new(&sig, 1_000 + skew * 3 / 2), "replay at 1.5 × skew");
        assert!(!st.insert_if_new(&sig, 1_000 + 2 * skew), "replay at 2 × skew");
        assert!(st.insert_if_new(&sig, 1_000 + 2 * skew + 1), "outside every acceptance window");
    }

    const EXIT: ExitId = ExitId([0xBB; EXIT_ID_LEN]);

    fn ack_preimage(rid: &RecipientId, ts: u64, ack: &[u8; FETCH_BATCH_ID_LEN]) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(b"L1-FetchAck-v2");
        m.extend_from_slice(EXIT.as_bytes());
        m.extend_from_slice(rid.as_bytes());
        m.extend_from_slice(&ts.to_be_bytes());
        m.extend_from_slice(ack);
        m
    }

    #[test]
    fn fetch_ack_sig_roundtrip_and_ack_binding() {
        let ikp = HsigKeyPair::generate();
        let pk = ikp.public_key_bytes();
        let rid = RecipientId([5u8; 32]);
        let ts = 1234u64;
        let ack = [0xABu8; FETCH_BATCH_ID_LEN];
        let sig = ikp.sign_tagged(hsig::HSIG_USECASE_FETCH, &ack_preimage(&rid, ts, &ack)).to_vec();
        verify_fetch_ack_sig(&pk, &EXIT, &rid, ts, &ack, &sig, ts, 60).unwrap();
        // The ack is covered: swapping it invalidates the request.
        let mut other_ack = ack;
        other_ack[0] ^= 1;
        assert!(verify_fetch_ack_sig(&pk, &EXIT, &rid, ts, &other_ack, &sig, ts, 60).is_err());
        assert!(verify_fetch_ack_sig(&pk, &EXIT, &RecipientId([6u8; 32]), ts, &ack, &sig, ts, 60).is_err());
        assert!(verify_fetch_ack_sig(&pk, &EXIT, &rid, ts, &ack, &sig, ts + 9999, 60).is_err());
        // SRV-13: the signature is bound to the exit it was made for.
        assert!(verify_fetch_ack_sig(&pk, &ExitId([0xCC; EXIT_ID_LEN]), &rid, ts, &ack, &sig, ts, 60).is_err());
    }

    #[test]
    fn fetch_ack_sig_rejects_other_tags_and_the_legacy_preimage() {
        let ikp = HsigKeyPair::generate();
        let pk = ikp.public_key_bytes();
        let rid = RecipientId([7u8; 32]);
        let ts = 4321u64;
        let ack = [0u8; FETCH_BATCH_ID_LEN];
        let pre = ack_preimage(&rid, ts, &ack);
        // Right bytes, wrong usecase tag.
        let sig = ikp.sign_tagged(hsig::HSIG_USECASE_BUNDLE, &pre).to_vec();
        assert!(verify_fetch_ack_sig(&pk, &EXIT, &rid, ts, &ack, &sig, ts, 60).is_err());
        // The pre-A1 legacy fetch pre-image under the fetch tag.
        let mut legacy = b"L1-Fetch-v1".to_vec();
        legacy.extend_from_slice(rid.as_bytes());
        legacy.extend_from_slice(&ts.to_be_bytes());
        let sig = ikp.sign_tagged(hsig::HSIG_USECASE_FETCH, &legacy).to_vec();
        assert!(verify_fetch_ack_sig(&pk, &EXIT, &rid, ts, &ack, &sig, ts, 60).is_err());
        // SRV-13: the v1 ack pre-image (no exit_id) is refused, no fallback.
        let mut v1 = b"L1-FetchAck-v1".to_vec();
        v1.extend_from_slice(rid.as_bytes());
        v1.extend_from_slice(&ts.to_be_bytes());
        v1.extend_from_slice(&ack);
        let sig = ikp.sign_tagged(hsig::HSIG_USECASE_FETCH, &v1).to_vec();
        assert!(verify_fetch_ack_sig(&pk, &EXIT, &rid, ts, &ack, &sig, ts, 60).is_err());
    }
}
