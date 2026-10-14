//! Shared setup for the integration tests.
//!
//! Why this file exists: both test files used to build a 20-line `ExitState`
//! literal each, three times in total. Every field added to `ExitState` broke
//! all three, and because `cargo test --lib` does not compile integration
//! tests, nothing surfaced it — `push_notify_sema` was added in the initial
//! import and the tests had not compiled since. They were repaired on
//! 2026-08-23 together with this module.
//!
//! Rule: a new `ExitState` field is added here, once. If you find yourself
//! writing an `ExitState { .. }` literal in a test file again, add a parameter
//! to `test_state` instead.
//!
//! Deliberately not a constructor on `ExitState` itself: that would put a
//! function producing test defaults (`s2s_accept_legacy: true`) into the
//! production library, where it could be called by mistake.
//!
//! Also home of the delivery-bundle builder (Addendum A1 §3.2) shared by the
//! test files.

use std::collections::HashMap;
use std::sync::Arc;

use exit_relay_v2 as exit;
use ladon_relay_core_v2::bloom::ReplayWindow;
use ladon_relay_core_v2::constants::*;
use ladon_relay_core_v2::hash::{delivery_verifier, exit_delivery_key};
use ladon_relay_core_v2::hkem::HkemKeyPair;
use ladon_relay_core_v2::hsig::{HsigKeyPair, HSIG_USECASE_BUNDLE};
use ladon_relay_core_v2::ids::{BundleId, ExitId, RecipientId};
use ladon_relay_core_v2::ratelimit::IdentityRateLimiter;
use ladon_relay_core_v2::store::{MailboxStore, RecipientDirectory};
use ladon_relay_core_v2::wire::Bundle;

/// The parts the individual tests actually vary. Everything else is a shared
/// default and lives in `test_state`.
pub struct TestStateOpts {
    /// Hop name the entry-keys map is keyed by (`"test"` or `"entry1"`).
    pub entry_hop: &'static str,
    pub s2s_key: [u8; 32],
    /// `None` disables the push integration, mirroring an exit without
    /// `LADON_PUSH_RELAY_URL`.
    pub push: Option<Arc<dyn exit::PushClient>>,
}

/// Build an `ExitState` with the defaults every integration test shares.
///
/// The values here match what the tests asserted against before they stopped
/// compiling — migration-era permissive flags, 120 s skew everywhere — so a
/// repaired test exercises the same behaviour it was written for.
pub fn test_state(
    exit_id: ExitId,
    hkem_keys: HkemKeyPair,
    canary_path: std::path::PathBuf,
    now: u64,
    opts: TestStateOpts,
) -> exit::ExitState {
    let mut entry_keys = HashMap::new();
    entry_keys.insert(opts.entry_hop.to_string(), opts.s2s_key);

    exit::ExitState {
        exit_id,
        hkem_keys,
        directory: RecipientDirectory::new(),
        mailbox: MailboxStore::new(),
        replay: std::sync::Mutex::new(ReplayWindow::new(now)),
        entry_keys: Arc::new(entry_keys),
        s2s_skew_sec: 120,
        fetch_skew_sec: 120,
        canary_path,
        push: opts.push,
        // F8/N3: the stores `main` builds for the skews above.
        s2s_nonce_store: exit::s2s::S2sNonceStore::for_skew(120),
        // Added 2026-08-23 (P8-EXIT-SRV-02). TTL 2 × `fetch_skew_sec` above
        // (SRV-11): a signature stays acceptable that long after first use.
        fetch_replay: exit::verify::FetchReplayStore::for_skew(120),
        s2s_accept_legacy: true,
        forward_recipient_limiter: Arc::new(IdentityRateLimiter::new()),
        // Present since the initial import; its absence here is what kept the
        // integration tests from compiling.
        push_notify_sema: Arc::new(tokio::sync::Semaphore::new(256)),
        online: std::sync::Arc::new(exit_relay_v2::online::OnlineTracker::new()),
        notify_debounce: std::sync::Arc::new(exit_relay_v2::online::NotifyDebounce::new()),
        sealed_limits: exit_relay_v2::sealed::SealedLimits::default(),
    }
}

/// HTTP client for client-facing routes, carrying `X-Forwarded-For` the way
/// Caddy sets it in production.
///
/// Without the header the exit refuses the request: the rate-limit middleware
/// fails closed on a missing XFF (P7-RELAY-07, `lib.rs`), because it cannot
/// limit per IP otherwise. These tests were written before that control
/// existed, so the moment they compiled again every client-facing call came
/// back 429. Setting the header is the honest repair — the alternative,
/// `LADON_ALLOW_NO_XFF=1`, would test a configuration we do not ship.
///
/// `/v2/forward` is S2S and not behind this middleware, but sending the header
/// there too is harmless and keeps one client for all calls.
pub fn client() -> reqwest::Client {
    let mut headers = reqwest::header::HeaderMap::new();
    // TEST-NET-3 (RFC 5737) — never a real client.
    headers.insert("x-forwarded-for", "203.0.113.7".parse().unwrap());
    reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .expect("test client builds")
}

// =============================================================================
// Addendum A1 builders
// =============================================================================

#[allow(dead_code)]
pub fn now_sec() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

/// A recipient as the tests need it: identity, inner HKEM key, delivery key.
#[allow(dead_code)]
pub struct Recipient {
    pub hsig: HsigKeyPair,
    pub hkem_pk: Vec<u8>,
    pub rid: RecipientId,
    pub delivery_key: [u8; DELIVERY_KEY_LEN],
}

#[allow(dead_code)]
pub fn new_recipient() -> Recipient {
    use rand::RngCore;
    let hsig = HsigKeyPair::generate();
    let hkem_pk = HkemKeyPair::generate().public_key_bytes().to_vec();
    let rid = ladon_relay_core_v2::hash::recipient_id_from_hsig_pk(&hsig.public_key_bytes());
    let mut delivery_key = [0u8; DELIVERY_KEY_LEN];
    rand::thread_rng().fill_bytes(&mut delivery_key);
    Recipient { hsig, hkem_pk, rid, delivery_key }
}

/// A1 §3.2 delivery bundle for `exit_id`, signed under "L1-Bundle-v3".
#[allow(dead_code)]
pub fn make_bundle(r: &Recipient, exit_id: ExitId, published_at: u64) -> Vec<u8> {
    let k_x = exit_delivery_key(&r.delivery_key, &exit_id);
    let mut b = Bundle {
        version: RELAY_PROTOCOL_VERSION,
        recipient_id: r.rid,
        recipient_hsig_pk: r.hsig.public_key_bytes().to_vec(),
        recipient_hkem_pk: r.hkem_pk.clone(),
        bundle_id: BundleId([0xAB; 16]),
        published_at,
        exit_id,
        verifier: delivery_verifier(&k_x),
        bundle_hsig: vec![0u8; HSIG_SIG_LEN],
    };
    b.bundle_hsig = r.hsig.sign_tagged(HSIG_USECASE_BUNDLE, &b.signing_input()).to_vec();
    b.encode()
}

/// An inner envelope of the minimum size the exit accepts, tagged with `b`.
#[allow(dead_code)]
pub fn inner(b: u8) -> Vec<u8> {
    vec![b; INNER_ENVELOPE_HEADER_LEN + AEAD_TAG_LEN + 12]
}

/// Fresh random envelope id.
#[allow(dead_code)]
pub fn envelope_id() -> [u8; ENVELOPE_ID_LEN] {
    use rand::RngCore;
    let mut id = [0u8; ENVELOPE_ID_LEN];
    rand::thread_rng().fill_bytes(&mut id);
    id
}
