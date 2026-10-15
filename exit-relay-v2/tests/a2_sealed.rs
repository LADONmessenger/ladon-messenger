//! Addendum A2 stage 2 — `POST /v2/sealed` over real HTTP.
//!
//! Requests are sealed with `relay-core-v2::wire::sealed` exactly as the
//! client will seal them; every response is opened and checked for its lane
//! size, its status and its body. The Entry sees only the outer HTTP status,
//! so the tests also assert that a refusal after opening is still HTTP 200.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::serve;
use rand::RngCore;
use sha2::Sha256;
use tokio::net::TcpListener;

use ladon_relay_core_v2::constants::*;
use ladon_relay_core_v2::hash::{exit_delivery_key, exit_id_from_hkem_pk};
use ladon_relay_core_v2::hkem::HkemKeyPair;
use ladon_relay_core_v2::hsig::{HSIG_USECASE_BUNDLE, HSIG_USECASE_FETCH, HSIG_USECASE_PUSH_REGISTER};
use ladon_relay_core_v2::ids::ExitId;
use ladon_relay_core_v2::wire::Bundle;
use ladon_relay_core_v2::wire::sealed::{
    self, status, Kind, Lane, OpenedResponse, ONLINE_WINDOW_SEC, SEALED_INNER_ENVELOPE_LEN,
};

use exit_relay_v2 as exit;
use exit::push_client::RecordingPushClient;

struct Running {
    addr: SocketAddr,
    hkem_pk: Vec<u8>,
    exit_id: ExitId,
    s2s_key: [u8; 32],
    push: Arc<RecordingPushClient>,
}

async fn spawn() -> Running {
    spawn_with(|_| {}).await
}

/// `spawn` with a hook to adjust the state before it is served (capacity,
/// verify budget).
async fn spawn_with(adjust: impl FnOnce(&mut exit::ExitState)) -> Running {
    let kp = HkemKeyPair::generate();
    let hkem_pk = kp.public_key_bytes().to_vec();
    let exit_id = exit_id_from_hkem_pk(&hkem_pk);
    let mut s2s_key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut s2s_key);
    let canary = std::env::temp_dir().join("ladon-test-a2-canary.json");
    let _ = std::fs::write(&canary, br#"{"ok":true}"#);
    let push = Arc::new(RecordingPushClient::new());
    let mut state = common::test_state(
        exit_id,
        kp,
        canary,
        common::now_sec(),
        common::TestStateOpts {
            entry_hop: "entry1",
            s2s_key,
            push: Some(push.clone() as Arc<dyn exit::PushClient>),
        },
    );
    adjust(&mut state);
    let app = exit::router(Arc::new(state));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = serve(listener, app).await;
    });
    Running { addr, hkem_pk, exit_id, s2s_key, push }
}

/// POST a sealed request as the Entry does (S2S HMAC over the body).
async fn post_sealed(running: &Running, body: Vec<u8>) -> reqwest::Response {
    use hmac::{Hmac, Mac};
    let ts = common::now_sec().to_string();
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&running.s2s_key).unwrap();
    mac.update(b"entry1");
    mac.update(ts.as_bytes());
    mac.update(&body);
    let sig = hex::encode(mac.finalize().into_bytes());
    common::client()
        .post(format!("http://{}/v2/sealed", running.addr))
        .header("x-relay-hop", "entry1")
        .header("x-relay-timestamp", ts)
        .header("x-relay-signature", sig)
        .body(body)
        .send()
        .await
        .unwrap()
}

/// Seal, send, require HTTP 200 and open the sealed response.
async fn call(running: &Running, kind: Kind, body: &[u8]) -> OpenedResponse {
    let (req, key) = sealed::seal_request(&running.hkem_pk, running.exit_id.as_bytes(), kind, body).unwrap();
    let resp = post_sealed(running, req).await;
    assert_eq!(resp.status(), 200, "{kind:?}: the outer status is 200 once the request opened");
    let bytes = resp.bytes().await.unwrap();
    assert_eq!(bytes.len(), kind.lane().response_len(), "{kind:?}: response is the lane size");
    sealed::open_response(&key, running.exit_id.as_bytes(), kind.lane(), &bytes).unwrap()
}

fn enqueue_body(running: &Running, r: &common::Recipient, sent_at: u64, fill: u8) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&r.rid.0);
    b.extend_from_slice(&exit_delivery_key(&r.delivery_key, &running.exit_id));
    b.extend_from_slice(&sent_at.to_be_bytes());
    b.extend_from_slice(&common::envelope_id());
    b.extend_from_slice(&vec![fill; SEALED_INNER_ENVELOPE_LEN]);
    b
}

/// FETCH body signed over the v2 pre-image for `running`'s exit (SRV-13).
fn fetch_body(running: &Running, r: &common::Recipient, ack: [u8; FETCH_BATCH_ID_LEN]) -> Vec<u8> {
    let ts = common::now_sec();
    let mut m = DOMAIN_FETCH_ACK_AUTH.to_vec();
    m.extend_from_slice(running.exit_id.as_bytes());
    m.extend_from_slice(&r.rid.0);
    m.extend_from_slice(&ts.to_be_bytes());
    m.extend_from_slice(&ack);
    let sig = r.hsig.sign_tagged(HSIG_USECASE_FETCH, &m);
    let mut b = Vec::new();
    b.extend_from_slice(&r.rid.0);
    b.extend_from_slice(&ts.to_be_bytes());
    b.extend_from_slice(&ack);
    b.extend_from_slice(&sig);
    b
}

/// Parsed sealed fetch body: (has_more, batch id, envelopes).
fn parse_fetch(body: &[u8]) -> (bool, [u8; FETCH_BATCH_ID_LEN], Vec<Vec<u8>>) {
    let has_more = body[0] == 1;
    let batch: [u8; FETCH_BATCH_ID_LEN] = body[1..17].try_into().unwrap();
    let count = body[17] as usize;
    let mut items = Vec::new();
    let mut i = 18;
    for _ in 0..count {
        let n = u32::from_be_bytes(body[i..i + 4].try_into().unwrap()) as usize;
        items.push(body[i + 4..i + 4 + n].to_vec());
        i += 4 + n;
    }
    assert_eq!(i, body.len(), "no trailing bytes in the fetch body");
    (has_more, batch, items)
}

/// Publish `r`'s bundle with a sealed DIR_PUT.
async fn registered(running: &Running) -> common::Recipient {
    let r = common::new_recipient();
    let bundle = common::make_bundle(&r, running.exit_id, common::now_sec());
    let resp = call(running, Kind::DirPut, &bundle).await;
    assert_eq!(resp.status, status::OK, "baseline sealed DIR_PUT");
    r
}

#[tokio::test]
async fn enqueue_then_fetch_hands_out_one_envelope_per_response() {
    let running = spawn().await;
    let r = registered(&running).await;
    for fill in [0x11u8, 0x22] {
        let resp = call(&running, Kind::Enqueue, &enqueue_body(&running, &r, common::now_sec(), fill)).await;
        assert_eq!(resp.status, status::OK);
    }
    let first = call(&running, Kind::Fetch, &fetch_body(&running, &r, [0u8; FETCH_BATCH_ID_LEN])).await;
    assert_eq!(first.status, status::OK);
    let (more, batch, items) = parse_fetch(&first.body);
    assert!(more, "a second envelope is waiting");
    assert_eq!(items, vec![vec![0x11; SEALED_INNER_ENVELOPE_LEN]]);

    let second = call(&running, Kind::Fetch, &fetch_body(&running, &r, batch)).await;
    let (more, batch, items) = parse_fetch(&second.body);
    assert!(!more);
    assert_eq!(items, vec![vec![0x22; SEALED_INNER_ENVELOPE_LEN]]);

    let empty = call(&running, Kind::Fetch, &fetch_body(&running, &r, batch)).await;
    let (more, batch, items) = parse_fetch(&empty.body);
    assert!(!more && items.is_empty() && batch == [0u8; FETCH_BATCH_ID_LEN]);
}

#[tokio::test]
async fn refusals_after_opening_are_sealed_statuses() {
    let running = spawn().await;
    let r = registered(&running).await;
    // Stale sent_at.
    let resp = call(&running, Kind::Enqueue, &enqueue_body(&running, &r, common::now_sec() - SENT_AT_WINDOW_SEC - 5, 1)).await;
    assert_eq!(resp.status, status::STALE);
    // Wrong delivery key.
    let mut b = enqueue_body(&running, &r, common::now_sec(), 1);
    b[RECIPIENT_ID_LEN] ^= 1;
    assert_eq!(call(&running, Kind::Enqueue, &b).await.status, status::DELIVERY_KEY);
    // Inner envelope not exactly the fixed length.
    let mut b = enqueue_body(&running, &r, common::now_sec(), 1);
    b.pop();
    assert_eq!(call(&running, Kind::Enqueue, &b).await.status, status::MALFORMED);
    // Unknown recipient for a lookup.
    assert_eq!(call(&running, Kind::DirGet, &[0x99u8; RECIPIENT_ID_LEN]).await.status, status::UNKNOWN_RECIPIENT);
    // Fetch with a signature over another ack.
    let mut f = fetch_body(&running, &r, [0u8; FETCH_BATCH_ID_LEN]);
    f[40] ^= 1;
    assert_eq!(call(&running, Kind::Fetch, &f).await.status, status::FETCH_SIG);
    // The push relay's kind is never served by an exit.
    assert_eq!(call(&running, Kind::PushRegister, b"x").await.status, status::MALFORMED);
}

#[tokio::test]
async fn cover_is_accepted_and_stores_nothing() {
    let running = spawn().await;
    let r = registered(&running).await;
    assert_eq!(call(&running, Kind::Cover, &[]).await.status, status::OK);
    let (_, _, items) = parse_fetch(&call(&running, Kind::Fetch, &fetch_body(&running, &r, [0u8; 16])).await.body);
    assert!(items.is_empty());
}

#[tokio::test]
async fn directory_lookup_returns_the_published_bundle() {
    let running = spawn().await;
    let r = common::new_recipient();
    let bundle = common::make_bundle(&r, running.exit_id, common::now_sec());
    assert_eq!(call(&running, Kind::DirPut, &bundle).await.status, status::OK);
    let got = call(&running, Kind::DirGet, &r.rid.0).await;
    assert_eq!(got.status, status::OK);
    assert_eq!(&got.body[..], &bundle[..]);
    // A byte-identical republish is idempotent (store.rs: retries must not
    // fail); an older bundle is a rollback (A1 §4) and is refused.
    assert_eq!(call(&running, Kind::DirPut, &bundle).await.status, status::OK);
    let older = common::make_bundle(&r, running.exit_id, common::now_sec() - 10);
    assert_eq!(call(&running, Kind::DirPut, &older).await.status, status::REPLAY);
}

#[tokio::test]
async fn push_follows_the_online_rule_not_the_envelope() {
    let running = spawn().await;
    let r = registered(&running).await;
    // Never fetched: offline, so an accepted envelope notifies.
    call(&running, Kind::Enqueue, &enqueue_body(&running, &r, common::now_sec(), 1)).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(running.push.notify_snapshot(), vec![r.rid]);
    // After an authenticated fetch it is online for ONLINE_WINDOW_SEC: no push.
    call(&running, Kind::Fetch, &fetch_body(&running, &r, [0u8; 16])).await;
    call(&running, Kind::Enqueue, &enqueue_body(&running, &r, common::now_sec(), 2)).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(running.push.notify_snapshot(), vec![r.rid], "online recipient: no second notify");
    const { assert!(ONLINE_WINDOW_SEC >= 2 * sealed::TICK_SEC) };
}

#[tokio::test]
async fn unopenable_requests_are_refused_before_anything_else() {
    let running = spawn().await;
    // Wrong target: sealed to another exit id.
    let (req, _) = sealed::seal_request(&running.hkem_pk, &[0x55; 16], Kind::Cover, &[]).unwrap();
    assert_eq!(post_sealed(&running, req).await.status(), 401);
    // Not a lane size.
    assert_eq!(post_sealed(&running, vec![0u8; 10_000]).await.status(), 400);
    // A tampered request does not open.
    let (mut req, _) = sealed::seal_request(&running.hkem_pk, running.exit_id.as_bytes(), Kind::Cover, &[]).unwrap();
    let n = req.len();
    req[n - 1] ^= 1;
    assert_eq!(post_sealed(&running, req).await.status(), 400);
    // Without S2S authentication the exit does not even try.
    let (req, _) = sealed::seal_request(&running.hkem_pk, running.exit_id.as_bytes(), Kind::Cover, &[]).unwrap();
    let resp = common::client()
        .post(format!("http://{}/v2/sealed", running.addr))
        .body(req)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn both_lanes_answer_with_their_fixed_sizes() {
    // Asserted inside `call` for every kind; here the two sizes side by side.
    assert_eq!((Lane::Send.request_len(), Lane::Send.response_len()), (16_384, 8_192));
    assert_eq!((Lane::Fetch.request_len(), Lane::Fetch.response_len()), (8_192, 16_384));
}

#[test]
fn a2_verify_cap_refuses_above_the_budget() {
    // Unit-level: the cap is per second and resets with the next second.
    let l = exit::sealed::SealedLimits::with_verify_cap(2);
    assert!(l.take_verify_for_test(100).is_ok());
    assert!(l.take_verify_for_test(100).is_ok());
    assert!(l.take_verify_for_test(100).is_err(), "third verify in the same second refused");
    assert!(l.take_verify_for_test(101).is_ok(), "next second has a fresh budget");
}

#[tokio::test]
async fn a2_forged_fetches_do_not_spend_the_victims_budget() {
    let running = spawn().await;
    let r = registered(&running).await;
    // Far more forged fetches for r's rid than the per-recipient budget.
    for _ in 0..(exit::sealed::FETCH_PER_RID_PER_MIN + 5) {
        let mut f = fetch_body(&running, &r, [0u8; FETCH_BATCH_ID_LEN]);
        f[40] ^= 1;
        assert_eq!(call(&running, Kind::Fetch, &f).await.status, status::FETCH_SIG);
    }
    let ok = call(&running, Kind::Fetch, &fetch_body(&running, &r, [0u8; FETCH_BATCH_ID_LEN])).await;
    assert_eq!(ok.status, status::OK, "the owner still fetches");
}

/// A device that fetched and was then frozen by iOS still counts as online;
/// an envelope for it is notified after the deferred check (12 Pro,
/// 13.10.2026). One that keeps fetching is not.
#[tokio::test]
async fn deferred_check_notifies_a_recipient_that_stopped_fetching() {
    let running = spawn().await;
    let r = registered(&running).await;
    call(&running, Kind::Fetch, &fetch_body(&running, &r, [0u8; 16])).await;
    call(&running, Kind::Enqueue, &enqueue_body(&running, &r, common::now_sec(), 1)).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(running.push.notify_snapshot().is_empty(), "online at arrival: no push yet");
    tokio::time::sleep(Duration::from_secs(sealed::DEFERRED_PUSH_CHECK_SEC) + Duration::from_millis(500)).await;
    assert_eq!(running.push.notify_snapshot(), vec![r.rid], "no fetch since arrival: notified");
}

#[tokio::test]
async fn deferred_check_stays_silent_when_the_recipient_fetched() {
    let running = spawn().await;
    let r = registered(&running).await;
    let first = call(&running, Kind::Fetch, &fetch_body(&running, &r, [0u8; 16])).await;
    let (_, batch, _) = parse_fetch(&first.body);
    call(&running, Kind::Enqueue, &enqueue_body(&running, &r, common::now_sec(), 1)).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    call(&running, Kind::Fetch, &fetch_body(&running, &r, batch)).await;
    tokio::time::sleep(Duration::from_secs(sealed::DEFERRED_PUSH_CHECK_SEC)).await;
    assert!(running.push.notify_snapshot().is_empty(), "fetched after arrival: no push");
}

// ---------- A1 checks through the sealed path (phase B: /v2/forward,
// /v2/fetch and /v2/directory/:rid are gone, so these replace their tests) ---

/// ENQUEUE body with an explicit K_X and envelope id.
fn enqueue_with(r: &common::Recipient, k_x: [u8; 32], sent_at: u64, id: [u8; ENVELOPE_ID_LEN], fill: u8) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&r.rid.0);
    b.extend_from_slice(&k_x);
    b.extend_from_slice(&sent_at.to_be_bytes());
    b.extend_from_slice(&id);
    b.extend_from_slice(&vec![fill; SEALED_INNER_ENVELOPE_LEN]);
    b
}

fn kx(running: &Running, r: &common::Recipient) -> [u8; 32] {
    exit_delivery_key(&r.delivery_key, &running.exit_id)
}

#[tokio::test]
async fn a1_delivery_key_for_another_exit_is_refused() {
    let running = spawn().await;
    let r = registered(&running).await;
    let other = exit_delivery_key(&r.delivery_key, &ExitId([0xBB; EXIT_ID_LEN]));
    let resp = call(&running, Kind::Enqueue, &enqueue_with(&r, other, common::now_sec(), common::envelope_id(), 1)).await;
    assert_eq!(resp.status, status::DELIVERY_KEY);
}

#[tokio::test]
async fn a1_future_sent_at_is_refused() {
    let running = spawn().await;
    let r = registered(&running).await;
    let b = enqueue_with(&r, kx(&running, &r), common::now_sec() + SENT_AT_WINDOW_SEC + 5, common::envelope_id(), 1);
    assert_eq!(call(&running, Kind::Enqueue, &b).await.status, status::STALE);
}

#[tokio::test]
async fn a1_replay_is_keyed_on_the_envelope_id() {
    let running = spawn().await;
    let r = registered(&running).await;
    let id = common::envelope_id();
    let b = enqueue_with(&r, kx(&running, &r), common::now_sec(), id, 1);
    assert_eq!(call(&running, Kind::Enqueue, &b).await.status, status::OK);
    // Same body again (fresh HKEM seal) and another body with the same id.
    assert_eq!(call(&running, Kind::Enqueue, &b).await.status, status::REPLAY);
    let other = enqueue_with(&r, kx(&running, &r), common::now_sec(), id, 2);
    assert_eq!(call(&running, Kind::Enqueue, &other).await.status, status::REPLAY);
}

#[tokio::test]
async fn a1_refused_envelope_does_not_burn_its_id() {
    let running = spawn().await;
    let r = registered(&running).await;
    let id = common::envelope_id();
    let mut bad_k = kx(&running, &r);
    bad_k[31] ^= 0x80;
    assert_eq!(call(&running, Kind::Enqueue, &enqueue_with(&r, bad_k, common::now_sec(), id, 1)).await.status, status::DELIVERY_KEY);
    assert_eq!(call(&running, Kind::Enqueue, &enqueue_with(&r, kx(&running, &r), common::now_sec(), id, 1)).await.status, status::OK);
}

#[tokio::test]
async fn a1_enqueue_for_unknown_recipient_is_refused() {
    let running = spawn().await;
    let r = common::new_recipient(); // never published
    let b = enqueue_with(&r, kx(&running, &r), common::now_sec(), common::envelope_id(), 1);
    assert_eq!(call(&running, Kind::Enqueue, &b).await.status, status::UNKNOWN_RECIPIENT);
}

#[tokio::test]
async fn a1_rotation_cuts_off_the_old_key_and_rollback_is_refused() {
    let running = spawn().await;
    let mut r = common::new_recipient();
    let old_k = r.delivery_key;
    let old_bundle = common::make_bundle(&r, running.exit_id, common::now_sec() - 10);
    assert_eq!(call(&running, Kind::DirPut, &old_bundle).await.status, status::OK);
    rand::thread_rng().fill_bytes(&mut r.delivery_key);
    let new_bundle = common::make_bundle(&r, running.exit_id, common::now_sec());
    assert_eq!(call(&running, Kind::DirPut, &new_bundle).await.status, status::OK);

    let old_kx = exit_delivery_key(&old_k, &running.exit_id);
    let with_old = |id| enqueue_with(&r, old_kx, common::now_sec(), id, 1);
    assert_eq!(call(&running, Kind::Enqueue, &with_old(common::envelope_id())).await.status, status::DELIVERY_KEY);
    assert_eq!(call(&running, Kind::Enqueue, &enqueue_with(&r, kx(&running, &r), common::now_sec(), common::envelope_id(), 1)).await.status, status::OK);
    assert_eq!(call(&running, Kind::DirPut, &old_bundle).await.status, status::REPLAY, "rolled-back bundle refused");
    assert_eq!(call(&running, Kind::Enqueue, &with_old(common::envelope_id())).await.status, status::DELIVERY_KEY);
}

#[tokio::test]
async fn a1_bundle_for_another_exit_is_refused() {
    let running = spawn().await;
    let r = common::new_recipient();
    let body = common::make_bundle(&r, ExitId([0xBB; EXIT_ID_LEN]), common::now_sec());
    assert_eq!(call(&running, Kind::DirPut, &body).await.status, status::MALFORMED);
}

#[tokio::test]
async fn a1_bundle_signed_under_another_tag_or_altered_is_refused() {
    let running = spawn().await;
    let r = common::new_recipient();
    let good = common::make_bundle(&r, running.exit_id, common::now_sec());
    for tag in [HSIG_USECASE_FETCH, HSIG_USECASE_PUSH_REGISTER] {
        let mut b = Bundle::parse(&good).unwrap();
        b.bundle_hsig = r.hsig.sign_tagged(tag, &b.signing_input()).to_vec();
        assert_eq!(call(&running, Kind::DirPut, &b.encode()).await.status, status::SIGNATURE);
    }
    let mut b = Bundle::parse(&good).unwrap();
    b.verifier[0] ^= 0x01;
    assert_eq!(call(&running, Kind::DirPut, &b.encode()).await.status, status::SIGNATURE, "verifier is signed");
    assert_eq!(call(&running, Kind::DirPut, &good).await.status, status::OK, "baseline");
}

#[tokio::test]
async fn a1_fetch_signed_under_another_tag_is_refused() {
    let running = spawn().await;
    let r = registered(&running).await;
    let ts = common::now_sec();
    let ack = [0u8; FETCH_BATCH_ID_LEN];
    let mut m = DOMAIN_FETCH_ACK_AUTH.to_vec();
    m.extend_from_slice(running.exit_id.as_bytes());
    m.extend_from_slice(&r.rid.0);
    m.extend_from_slice(&ts.to_be_bytes());
    m.extend_from_slice(&ack);
    let sig = r.hsig.sign_tagged(HSIG_USECASE_BUNDLE, &m);
    let mut b = r.rid.0.to_vec();
    b.extend_from_slice(&ts.to_be_bytes());
    b.extend_from_slice(&ack);
    b.extend_from_slice(&sig);
    assert_eq!(call(&running, Kind::Fetch, &b).await.status, status::FETCH_SIG);
}

// ---------- push wiring (formerly phase3b over /v2/forward) -----------------

#[tokio::test]
async fn dir_put_replicates_and_a_refused_one_does_not() {
    let running = spawn().await;
    let r = common::new_recipient();
    let bad = common::make_bundle(&r, ExitId([0xBB; EXIT_ID_LEN]), common::now_sec());
    call(&running, Kind::DirPut, &bad).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(running.push.replicate_snapshot().is_empty(), "refused bundle: no replication");
    call(&running, Kind::DirPut, &common::make_bundle(&r, running.exit_id, common::now_sec())).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let reps = running.push.replicate_snapshot();
    assert_eq!(reps.len(), 1);
    assert_eq!(reps[0].0, r.rid);
    assert_eq!(reps[0].1, r.hsig.public_key_bytes().to_vec(), "replicates the bundle's hsig pk");
}

/// F44: within `PUSH_DEBOUNCE_SEC` the exit sends one notify per recipient.
/// The push relay debounces with the same window, so the others never
/// reached APNs; they only spent the push relay's S2S admissions and nonce
/// slots. Another recipient is not affected.
#[tokio::test]
async fn notify_is_debounced_per_recipient_on_the_exit() {
    let running = spawn().await;
    let r = registered(&running).await;
    let other = registered(&running).await;
    for fill in 1..=3u8 {
        let resp = call(&running, Kind::Enqueue, &enqueue_body(&running, &r, common::now_sec(), fill)).await;
        assert_eq!(resp.status, status::OK);
    }
    call(&running, Kind::Enqueue, &enqueue_body(&running, &other, common::now_sec(), 9)).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let calls = running.push.notify_snapshot();
    assert_eq!(calls.iter().filter(|c| **c == r.rid).count(), 1, "one notify per window");
    assert_eq!(calls.iter().filter(|c| **c == other.rid).count(), 1);
    const { assert!(PUSH_DEBOUNCE_SEC >= 1) };
}

/// F4 + N4: the published bundle is public (DIR_GET), so anyone can replay
/// it. A byte-identical republish is idempotent; it must not spend the
/// recipient's DIR_PUT budget (20/min) nor replicate again. Before, 20
/// replays locked the owner out of publishing a newer bundle (RATE) and
/// each replay re-replicated to the push relay.
#[tokio::test]
async fn identical_republish_spends_no_budget_and_does_not_replicate() {
    let running = spawn().await;
    let r = common::new_recipient();
    let bundle = common::make_bundle(&r, running.exit_id, common::now_sec() - 5);
    assert_eq!(call(&running, Kind::DirPut, &bundle).await.status, status::OK);
    for _ in 0..25 {
        assert_eq!(call(&running, Kind::DirPut, &bundle).await.status, status::OK);
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(running.push.replicate_snapshot().len(), 1, "replays do not replicate");

    let newer = common::make_bundle(&r, running.exit_id, common::now_sec());
    assert_eq!(call(&running, Kind::DirPut, &newer).await.status, status::OK, "owner can still publish");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(running.push.replicate_snapshot().len(), 2);
    let got = call(&running, Kind::DirGet, &r.rid.0).await;
    assert_eq!(&got.body[..], &newer[..]);
}

/// F1 step A: a DIR_PUT refused because the directory is full (every entry
/// active) is answered before the signature check, so it does not spend the
/// global verify budget. With a budget of one verify per second, a refused
/// newcomer is followed in the same second by the owner's verified republish,
/// which only succeeds if the refusal left the budget untouched.
#[tokio::test]
async fn full_directory_refusal_spends_no_verify_budget() {
    let running = spawn_with(|s| {
        s.directory = ladon_relay_core_v2::store::RecipientDirectory::with_capacity(1);
        s.sealed_limits = exit::sealed::SealedLimits::with_verify_cap(1);
    })
    .await;
    let owner = common::new_recipient();
    let first = common::make_bundle(&owner, running.exit_id, common::now_sec() - 5);
    assert_eq!(call(&running, Kind::DirPut, &first).await.status, status::OK);

    // Start of a fresh one-second budget window, with room for two calls.
    loop {
        let ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_millis();
        if ms < 100 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let newcomer = common::new_recipient();
    let refused = common::make_bundle(&newcomer, running.exit_id, common::now_sec());
    assert_eq!(call(&running, Kind::DirPut, &refused).await.status, status::UNAVAILABLE, "directory is full");
    let newer = common::make_bundle(&owner, running.exit_id, common::now_sec());
    assert_eq!(
        call(&running, Kind::DirPut, &newer).await.status,
        status::OK,
        "the refusal left the one verify of this second unspent"
    );
}

/// SRV-13 (F12): the fetch signature names the exit it is meant for:
/// `"L1-FetchAck-v2" || exit_id (16) || rid || ts_be || ack`. A fetch signed
/// for this exit is served; the same request signed for another exit, or
/// over the former v1 pre-image without exit_id, is FETCH_SIG.
#[tokio::test]
async fn fetch_signature_is_bound_to_the_exit() {
    let running = spawn().await;
    let r = registered(&running).await;
    let signed_for = |exit_id: &[u8; EXIT_ID_LEN], domain: &[u8], with_exit: bool| {
        let ts = common::now_sec();
        let ack = [0u8; FETCH_BATCH_ID_LEN];
        let mut m = domain.to_vec();
        if with_exit {
            m.extend_from_slice(exit_id);
        }
        m.extend_from_slice(&r.rid.0);
        m.extend_from_slice(&ts.to_be_bytes());
        m.extend_from_slice(&ack);
        let sig = r.hsig.sign_tagged(HSIG_USECASE_FETCH, &m);
        let mut b = r.rid.0.to_vec();
        b.extend_from_slice(&ts.to_be_bytes());
        b.extend_from_slice(&ack);
        b.extend_from_slice(&sig);
        b
    };
    let own = *running.exit_id.as_bytes();
    let ok = call(&running, Kind::Fetch, &signed_for(&own, b"L1-FetchAck-v2", true)).await;
    assert_eq!(ok.status, status::OK, "signed for this exit");
    let other = call(&running, Kind::Fetch, &signed_for(&[0xBB; EXIT_ID_LEN], b"L1-FetchAck-v2", true)).await;
    assert_eq!(other.status, status::FETCH_SIG, "signed for another exit");
    let v1 = call(&running, Kind::Fetch, &signed_for(&own, b"L1-FetchAck-v1", false)).await;
    assert_eq!(v1.status, status::FETCH_SIG, "v1 pre-image no longer accepted");
}

#[tokio::test]
async fn refused_enqueue_does_not_notify() {
    let running = spawn().await;
    let r = registered(&running).await;
    let mut bad_k = kx(&running, &r);
    bad_k[0] ^= 1;
    call(&running, Kind::Enqueue, &enqueue_with(&r, bad_k, common::now_sec(), common::envelope_id(), 1)).await;
    call(&running, Kind::Cover, b"").await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(running.push.notify_snapshot().is_empty());
}
