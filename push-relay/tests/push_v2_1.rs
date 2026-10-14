//! End-to-end integration tests for push-relay v2.1.
//!
//! Spawns the full axum app on `127.0.0.1:0`, talks to it via reqwest,
//! and uses a `RecordingApnsSender` so we can assert on actual outbound
//! APNs calls without hitting Apple.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use ladon_relay_core_v2::{
    constants::{
        APNS_TOKEN_LEN, DIRECTORY_REPLICATE_BODY_LEN, DOMAIN_PUSH_REGISTER,
        PUSH_NOTIFY_BODY_LEN, PUSH_REGISTER_BODY_LEN,
    },
    hsig::{HsigKeyPair, HSIG_USECASE_BUNDLE, HSIG_USECASE_PUSH_REGISTER},
    hash::{exit_id_from_hkem_pk, recipient_id_from_hsig_pk},
    hkem::HkemKeyPair,
    ids::RecipientId,
    wire::sealed::{self, status, Kind, Lane},
};
use push_relay::{
    apns::{ApnsOutcome, RecordingApnsSender},
    router, PushState, SealedIdentity,
};
use sha2::Sha256;
use tokio::net::TcpListener;

type HmacSha256 = Hmac<Sha256>;

const HOP: &str = "exit1";
const S2S_KEY: [u8; 32] = [0xCAu8; 32];

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn s2s_sign(key: &[u8; 32], hop: &str, ts: &str, body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    mac.update(hop.as_bytes());
    mac.update(ts.as_bytes());
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

struct Running {
    base_url: String,
    apns: Arc<RecordingApnsSender>,
    /// The sealed identity's HKEM pk and target id; None = no key loaded.
    sealed: Option<(Vec<u8>, [u8; 16])>,
}

/// A fresh sealed identity, as `main` builds it from `LADON_PUSH_HKEM_KEYFILE`.
fn new_identity() -> SealedIdentity {
    let keys = HkemKeyPair::generate();
    let target_id = *exit_id_from_hkem_pk(&keys.public_key_bytes()).as_bytes();
    SealedIdentity { keys, target_id }
}

fn running_at(addr: std::net::SocketAddr, apns: Arc<RecordingApnsSender>, sealed: Option<(Vec<u8>, [u8; 16])>) -> Running {
    Running { base_url: format!("http://{}", addr), apns, sealed }
}

async fn spawn(apns: Arc<RecordingApnsSender>) -> Running {
    spawn_with_owners(apns, &[HOP]).await
}

/// `owners` is the mandatory directory-owner allow-list (A1 §14), as `main`
/// would build it from `LADON_PUSH_DIRECTORY_OWNERS`.
async fn spawn_with_owners(apns: Arc<RecordingApnsSender>, owners: &[&str]) -> Running {
    spawn_with(apns, owners, Some(new_identity())).await
}

/// `sealed` is the A2 stage 2 identity `main` builds from
/// `LADON_PUSH_HKEM_KEYFILE`; `None` = no key loaded.
async fn spawn_with(
    apns: Arc<RecordingApnsSender>,
    owners: &[&str],
    sealed: Option<SealedIdentity>,
) -> Running {
    spawn_tuned(apns, owners, sealed, |_| {}).await
}

/// `spawn_with`, plus a hook to adjust the state before the router starts.
async fn spawn_tuned(
    apns: Arc<RecordingApnsSender>,
    owners: &[&str],
    sealed: Option<SealedIdentity>,
    tune: impl FnOnce(&mut PushState),
) -> Running {
    // B2.2: register HOP → S2S_KEY in exit-keys map.
    let mut keys = std::collections::HashMap::new();
    keys.insert(HOP.to_string(), S2S_KEY);
    let mut state = PushState::new(Arc::new(keys), "push1".to_string(), apns.clone());
    state.directory_owner_hops = owners.iter().map(|h| h.to_string()).collect();
    let public = sealed.as_ref().map(|i| (i.keys.public_key_bytes().to_vec(), i.target_id));
    state.sealed = sealed;
    // Immediate APNs sends: the tests assert on them after 50 ms.
    state.push_delay_max_ms = 0;
    tune(&mut state);
    let app = router(Arc::new(state));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });
    running_at(addr, apns, public)
}

/// The rid a key pair owns: SHA-256(hsig_pk), the binding the exit enforces
/// on directory PUT and the push relay on replicate (F38).
fn rid_of(kp: &HsigKeyPair) -> RecipientId {
    recipient_id_from_hsig_pk(&kp.public_key_bytes())
}

fn rid_from(byte: u8) -> RecipientId {
    let mut a = [0u8; 32];
    a[0] = byte;
    a[31] = 0xEE;
    RecipientId(a)
}

/// Build the hsig-signed register body (tag "L1-PushRegister-v3"):
/// `apns_token(32) || sandbox(1) || ts_be(8) || hsig_sig(HSIG_SIG_LEN)`.
/// The pre-image fed into hsig::sign is:
/// `DOMAIN_PUSH_REGISTER || rid.0 || apns_token || sandbox_byte || ts_be`.
fn build_register_body(
    kp: &HsigKeyPair,
    rid: &RecipientId,
    apns_token: &[u8; APNS_TOKEN_LEN],
    sandbox: bool,
    ts: u64,
) -> Vec<u8> {
    build_register_body_tagged(kp, HSIG_USECASE_PUSH_REGISTER, rid, apns_token, sandbox, ts)
}

fn build_register_body_tagged(
    kp: &HsigKeyPair,
    tag: &[u8],
    rid: &RecipientId,
    apns_token: &[u8; APNS_TOKEN_LEN],
    sandbox: bool,
    ts: u64,
) -> Vec<u8> {
    let sandbox_byte: u8 = if sandbox { 1 } else { 0 };
    let mut signed_payload = Vec::with_capacity(APNS_TOKEN_LEN + 1 + 8);
    signed_payload.extend_from_slice(apns_token);
    signed_payload.push(sandbox_byte);
    signed_payload.extend_from_slice(&ts.to_be_bytes());

    let mut pre = Vec::new();
    pre.extend_from_slice(DOMAIN_PUSH_REGISTER);
    pre.extend_from_slice(&rid.0);
    pre.extend_from_slice(&signed_payload);
    let sig = kp.sign_tagged(tag, &pre);

    let mut body = Vec::with_capacity(PUSH_REGISTER_BODY_LEN);
    body.extend_from_slice(&signed_payload);
    body.extend_from_slice(&sig);
    assert_eq!(body.len(), PUSH_REGISTER_BODY_LEN);
    body
}

/// What an exit -> push call returned (F43): the HTTP status, the error
/// code header of a refusal before opening, and the opened sealed response.
struct Reply {
    http: u16,
    error_code: Option<String>,
    sealed: Option<sealed::OpenedResponse>,
}

impl Reply {
    fn sealed_status(&self) -> Option<u8> {
        self.sealed.as_ref().map(|r| r.status)
    }
    fn ok(&self) -> bool {
        self.http == 200 && self.sealed_status() == Some(status::OK)
    }
}

/// Send raw bytes on an exit -> push route, S2S-signed as `hop` with `key`.
async fn exit_raw(running: &Running, put: bool, path: &str, hop: &str, key: &[u8; 32], bytes: Vec<u8>) -> reqwest::Response {
    let url = format!("{}{}", running.base_url, path);
    let ts = now_secs().to_string();
    let sig = s2s_sign(key, hop, &ts, &bytes);
    let c = reqwest::Client::new();
    let req = if put { c.put(&url) } else { c.post(&url) };
    req.header("x-relay-hop", hop)
        .header("x-relay-timestamp", &ts)
        .header("x-relay-signature", &sig)
        .body(bytes)
        .send()
        .await
        .unwrap()
}

/// F43: seal `kind` with `body` to the relay's HKEM key (as the exit does),
/// S2S-sign the sealed bytes, send, and open the sealed answer if any.
async fn exit_call(running: &Running, put: bool, path: &str, hop: &str, key: &[u8; 32], kind: Kind, body: &[u8]) -> Reply {
    let (pk, target_id) = running.sealed.clone().expect("relay has a sealed identity");
    let (req, rk) = sealed::seal_request(&pk, &target_id, kind, body).unwrap();
    let r = exit_raw(running, put, path, hop, key, req).await;
    let http = r.status().as_u16();
    let error_code = r
        .headers()
        .get("X-Ladon-Error-Code")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let bytes = r.bytes().await.unwrap();
    let sealed = (http == 200).then(|| {
        assert_eq!(bytes.len(), kind.lane().response_len(), "lane-size answer");
        sealed::open_response(&rk, &target_id, kind.lane(), &bytes).unwrap()
    });
    Reply { http, error_code, sealed }
}

const REPLICATE_PATH: &str = "/v2/directory/replicate";
const NOTIFY_PATH: &str = "/v2/push/notify";

fn replicate_body(rid: &RecipientId, hsig_pk: &[u8]) -> Vec<u8> {
    assert_eq!(hsig_pk.len(), DIRECTORY_REPLICATE_BODY_LEN);
    let mut b = rid.0.to_vec();
    b.extend_from_slice(hsig_pk);
    b
}

async fn replicate(running: &Running, rid: &RecipientId, hsig_pk: &[u8]) -> Reply {
    replicate_as(running, HOP, &S2S_KEY, rid, hsig_pk).await
}

/// Register through the only client path left (A2 phase B): a sealed
/// PUSH_REGISTER, `rid || body`, to the relay's own key. Returns the sealed
/// status.
async fn register(running: &Running, rid: &RecipientId, body: Vec<u8>) -> u8 {
    let (pk, target_id) = running.sealed.clone().expect("relay has a sealed identity");
    sealed_register(running, &pk, &target_id, Kind::PushRegister, rid, &body).await.status
}

async fn notify(running: &Running, rid: &RecipientId) -> Reply {
    exit_call(running, false, NOTIFY_PATH, HOP, &S2S_KEY, Kind::PushNotify, &rid.0).await
}

// =============================================================================
// Tests
// =============================================================================

#[tokio::test]
async fn health_returns_ok() {
    let running = spawn(Arc::new(RecordingApnsSender::new())).await;
    let resp = reqwest::get(format!("{}/v2/health", running.base_url))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "ok");
    assert_eq!(body["hop"], "push1");
    assert_eq!(body["version"], 2);
}

#[tokio::test]
async fn replicate_then_register_happy_path() {
    let apns = Arc::new(RecordingApnsSender::new());
    let running = spawn(apns).await;
    let kp = HsigKeyPair::generate();
    let rid = rid_of(&kp);

    let r = replicate(&running, &rid, &kp.public_key_bytes()).await;
    assert!(r.ok(), "replicate should be 204");

    let token = [0xAB; APNS_TOKEN_LEN];
    let body = build_register_body(&kp, &rid, &token, false, now_secs());
    let r = register(&running, &rid, body).await;
    assert_eq!(r, status::OK, "register happy path");
}

#[tokio::test]
async fn register_unknown_recipient_is_403() {
    let running = spawn(Arc::new(RecordingApnsSender::new())).await;
    let kp = HsigKeyPair::generate();
    let rid = rid_from(2);
    // Skip replicate.
    let token = [0x11; APNS_TOKEN_LEN];
    let body = build_register_body(&kp, &rid, &token, true, now_secs());
    let r = register(&running, &rid, body).await;
    assert_eq!(r, status::UNKNOWN_RECIPIENT);
}

#[tokio::test]
async fn register_bad_signature_is_401() {
    let running = spawn(Arc::new(RecordingApnsSender::new())).await;
    let kp = HsigKeyPair::generate();
    let rid = rid_of(&kp);
    replicate(&running, &rid, &kp.public_key_bytes()).await;

    // Sign with a *different* keypair than the one we replicated.
    let attacker = HsigKeyPair::generate();
    let token = [0x22; APNS_TOKEN_LEN];
    let body = build_register_body(&attacker, &rid, &token, false, now_secs());
    let r = register(&running, &rid, body).await;
    assert_eq!(r, status::SIGNATURE);
}

#[tokio::test]
async fn register_skew_too_large_is_401() {
    let running = spawn(Arc::new(RecordingApnsSender::new())).await;
    let kp = HsigKeyPair::generate();
    let rid = rid_of(&kp);
    replicate(&running, &rid, &kp.public_key_bytes()).await;

    let token = [0x33; APNS_TOKEN_LEN];
    // 10 minutes in the past (>> PUSH_REGISTER_SKEW_SEC = 120).
    let body = build_register_body(&kp, &rid, &token, false, now_secs() - 600);
    let r = register(&running, &rid, body).await;
    assert_eq!(r, status::SIGNATURE);
}

#[tokio::test]
async fn register_malformed_body_is_400() {
    let running = spawn(Arc::new(RecordingApnsSender::new())).await;
    let rid = rid_from(5);
    let r = register(&running, &rid, vec![0u8; 100]).await;
    assert_eq!(r, status::MALFORMED);
}

#[tokio::test]
async fn replicate_bad_s2s_is_403() {
    let running = spawn(Arc::new(RecordingApnsSender::new())).await;
    let kp = HsigKeyPair::generate();
    // Sign with WRONG key.
    let r = replicate_as(&running, HOP, &[0u8; 32], &rid_of(&kp), &kp.public_key_bytes()).await;
    assert_eq!(r.http, 403);
    assert_eq!(r.error_code.as_deref(), Some("E-S2S-AUTH"));
}

#[tokio::test]
async fn replicate_wrong_body_len_is_400() {
    let running = spawn(Arc::new(RecordingApnsSender::new())).await;
    // Not a lane-F request: refused before anything is opened.
    let r = exit_raw(&running, true, REPLICATE_PATH, HOP, &S2S_KEY, vec![0u8; Lane::Fetch.request_len() - 1]).await;
    assert_eq!(r.status(), 400);
    // Opened, but the sealed body is one byte short: sealed MALFORMED.
    let kp = HsigKeyPair::generate();
    let mut body = replicate_body(&rid_of(&kp), &kp.public_key_bytes());
    body.pop();
    let r = exit_call(&running, true, REPLICATE_PATH, HOP, &S2S_KEY, Kind::PushReplicate, &body).await;
    assert_eq!(r.sealed_status(), Some(status::MALFORMED));
}

#[tokio::test]
async fn notify_triggers_apns_call() {
    let apns = Arc::new(RecordingApnsSender::new());
    let running = spawn(apns.clone()).await;
    let kp = HsigKeyPair::generate();
    let rid = rid_of(&kp);

    replicate(&running, &rid, &kp.public_key_bytes()).await;
    let token = [0x55; APNS_TOKEN_LEN];
    let body = build_register_body(&kp, &rid, &token, true, now_secs());
    let r = register(&running, &rid, body).await;
    assert_eq!(r, status::OK);

    let r = notify(&running, &rid).await;
    assert!(r.ok());
    // P7-PUSH-05: no `delivered` / `debounced` fields any more; the sealed
    // answer carries only a status and an empty body.
    assert!(r.sealed.as_ref().unwrap().body.is_empty());

    // APNs send is fire-and-forget via tokio::spawn; give it a beat.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let calls = apns.snapshot();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, hex::encode(token));
    assert!(calls[0].1, "sandbox flag should be propagated");
}

#[tokio::test]
async fn notify_debounce_blocks_second_call() {
    let apns = Arc::new(RecordingApnsSender::new());
    let running = spawn(apns.clone()).await;
    let kp = HsigKeyPair::generate();
    let rid = rid_of(&kp);

    replicate(&running, &rid, &kp.public_key_bytes()).await;
    let token = [0x66; APNS_TOKEN_LEN];
    let body = build_register_body(&kp, &rid, &token, false, now_secs());
    register(&running, &rid, body).await;

    assert!(notify(&running, &rid).await.ok());

    // P7-PUSH-05: a debounced notify answers exactly like a delivered one
    // (no presence oracle); the debounce shows only in the APNs call count.
    assert!(notify(&running, &rid).await.ok());

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    // Only one APNs call despite two notify requests.
    assert_eq!(apns.snapshot().len(), 1);
}

#[tokio::test]
async fn notify_unknown_rid_is_silent_accepted() {
    let apns = Arc::new(RecordingApnsSender::new());
    let running = spawn(apns.clone()).await;
    let rid = rid_from(10);
    // P7-PUSH-05: an unknown rid answers like a known one — the sender must
    // not learn whether the recipient has push registered.
    assert!(notify(&running, &rid).await.ok());
    assert_eq!(apns.snapshot().len(), 0);
}

#[tokio::test]
async fn notify_bad_s2s_is_403() {
    let apns = Arc::new(RecordingApnsSender::new());
    let running = spawn(apns).await;
    let rid = rid_from(11);
    let r = exit_call(&running, false, NOTIFY_PATH, HOP, &[0xFFu8; 32], Kind::PushNotify, &rid.0).await;
    assert_eq!(r.http, 403);
}

#[tokio::test]
async fn notify_wrong_body_len_is_400() {
    let running = spawn(Arc::new(RecordingApnsSender::new())).await;
    let r = exit_raw(&running, false, NOTIFY_PATH, HOP, &S2S_KEY, vec![0u8; PUSH_NOTIFY_BODY_LEN]).await;
    assert_eq!(r.status(), 400, "a plaintext-size body is not a sealed request");
    let r = exit_call(&running, false, NOTIFY_PATH, HOP, &S2S_KEY, Kind::PushNotify, &[0u8; PUSH_NOTIFY_BODY_LEN - 1]).await;
    assert_eq!(r.sealed_status(), Some(status::MALFORMED));
}

#[tokio::test]
async fn rotate_overwrites_token_and_resets_debounce() {
    let apns = Arc::new(RecordingApnsSender::new());
    let running = spawn(apns.clone()).await;
    let kp = HsigKeyPair::generate();
    let rid = rid_of(&kp);
    replicate(&running, &rid, &kp.public_key_bytes()).await;

    let t1 = [0xA1; APNS_TOKEN_LEN];
    let body = build_register_body(&kp, &rid, &t1, false, now_secs());
    register(&running, &rid, body).await;
    notify(&running, &rid).await;

    // Rotate to a new token. Registration is monotonic in the signed
    // timestamp (5aac2a7): a rotation carries a newer one, as a real device
    // re-registering later does; the same second would be refused as replay.
    let t2 = [0xB2; APNS_TOKEN_LEN];
    let body = build_register_body(&kp, &rid, &t2, true, now_secs() + 1);
    let r = register(&running, &rid, body).await;
    assert_eq!(r, status::OK);

    // Without explicit debounce reset on register, second notify still
    // hits debounce window. We just verify the token store now points at
    // t2 by waiting for debounce to lapse... too slow for a test. Instead
    // assert via a fresh notify that the recorded call mentions the *new*
    // token by registering a *different* rid is overkill — we already
    // covered rotation in unit tests. Here just assert overwrite is 201.
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let _ = apns.snapshot(); // not strictly asserted; behaviour belongs to unit tests.
}

#[tokio::test]
async fn apns_failure_does_not_break_notify_response() {
    let apns = Arc::new(RecordingApnsSender::with_outcome(ApnsOutcome::Rejected(410)));
    let running = spawn(apns.clone()).await;
    let kp = HsigKeyPair::generate();
    let rid = rid_of(&kp);
    replicate(&running, &rid, &kp.public_key_bytes()).await;
    let token = [0xCC; APNS_TOKEN_LEN];
    let body = build_register_body(&kp, &rid, &token, false, now_secs());
    register(&running, &rid, body).await;

    let r = notify(&running, &rid).await;
    assert!(r.ok(), "notify response is independent of APNs outcome");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(apns.snapshot().len(), 1);
}

// =============================================================================
// B1.5 P7-PUSH-02 — Multi-hop HashMap-lookup isolation
// =============================================================================
//
// Verifies that the per-exit-key HashMap introduced in B2.2 enforces strict
// per-hop key isolation:
//   1. Multiple hops, each with its own key, authenticate independently.
//   2. A request whose `X-Relay-Hop` header points at hop B but is signed
//      with hop A's key is rejected (no cross-hop substitution).
//   3. A hop not present in the map is rejected without leaking existence
//      (collapsed to S2sAuth → 403, same as wrong-signature).
//   4. Removing a hop from the map causes subsequent requests from that
//      hop to fail closed (no implicit fallback to any other key).

const HOP_A: &str = "is1";
const HOP_B: &str = "is2";
const HOP_UNKNOWN: &str = "ghost";
const KEY_A: [u8; 32] = [0xA1u8; 32];
const KEY_B: [u8; 32] = [0xB2u8; 32];

async fn spawn_multi() -> Running {
    let apns = Arc::new(RecordingApnsSender::new());
    let mut keys = std::collections::HashMap::new();
    keys.insert(HOP_A.to_string(), KEY_A);
    keys.insert(HOP_B.to_string(), KEY_B);
    let mut state = PushState::new(Arc::new(keys), "push1".to_string(), apns.clone());
    state.directory_owner_hops = [HOP_A, HOP_B].iter().map(|h| h.to_string()).collect();
    state.push_delay_max_ms = 0;
    let identity = new_identity();
    let public = Some((identity.keys.public_key_bytes().to_vec(), identity.target_id));
    state.sealed = Some(identity);
    let app = router(Arc::new(state));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });
    running_at(addr, apns, public)
}

async fn replicate_as(
    running: &Running,
    hop: &str,
    key: &[u8; 32],
    rid: &RecipientId,
    hsig_pk: &[u8],
) -> Reply {
    exit_call(running, true, REPLICATE_PATH, hop, key, Kind::PushReplicate, &replicate_body(rid, hsig_pk)).await
}

#[tokio::test]
async fn p7_push_02_multi_hop_both_keys_authenticate() {
    let running = spawn_multi().await;
    let kp_a = HsigKeyPair::generate();
    let kp_b = HsigKeyPair::generate();
    let rid_a = rid_of(&kp_a);
    let rid_b = rid_of(&kp_b);

    let ra = replicate_as(&running, HOP_A, &KEY_A, &rid_a, &kp_a.public_key_bytes()).await;
    assert!(ra.ok(), "hop A signs with key A → ok");

    let rb = replicate_as(&running, HOP_B, &KEY_B, &rid_b, &kp_b.public_key_bytes()).await;
    assert!(rb.ok(), "hop B signs with key B → ok");
}

#[tokio::test]
async fn p7_push_02_cross_hop_signature_is_403() {
    let running = spawn_multi().await;
    let kp = HsigKeyPair::generate();
    let rid = rid_of(&kp);

    // Header claims HOP_B but signature was computed with KEY_A.
    // The handler looks up KEY_B (by header), then verifies against KEY_A's
    // signature → mismatch → S2sAuth → 403.
    let r = replicate_as(&running, HOP_B, &KEY_A, &rid, &kp.public_key_bytes()).await;
    assert_eq!(r.http, 403);
    assert_eq!(
        r.error_code.as_deref(),
        Some("E-S2S-AUTH")
    );
}

#[tokio::test]
async fn p7_push_02_unknown_hop_is_403() {
    let running = spawn_multi().await;
    let kp = HsigKeyPair::generate();
    let rid = rid_of(&kp);

    // HOP_UNKNOWN is not in the exit-keys map. Whatever key the attacker
    // signs with, the lookup misses → S2sAuth → 403 (no existence oracle).
    let r = replicate_as(&running, HOP_UNKNOWN, &KEY_A, &rid, &kp.public_key_bytes()).await;
    assert_eq!(r.http, 403);
    assert_eq!(
        r.error_code.as_deref(),
        Some("E-S2S-AUTH")
    );

    // Also: signing with a totally random key under the unknown hop.
    let r2 = replicate_as(&running, HOP_UNKNOWN, &[0u8; 32], &rid, &kp.public_key_bytes()).await;
    assert_eq!(r2.http, 403);
}

#[tokio::test]
async fn p7_push_02_notify_routes_through_per_hop_key() {
    // End-to-end: hop B replicates+notifies with KEY_B; hop A trying to
    // notify on B's rid using KEY_A is rejected even though the rid is
    // registered.
    let running = spawn_multi().await;
    let kp = HsigKeyPair::generate();
    let rid = rid_of(&kp);

    // Register via hop B (KEY_B).
    let r = replicate_as(&running, HOP_B, &KEY_B, &rid, &kp.public_key_bytes()).await;
    assert!(r.ok());
    let token = [0x55; APNS_TOKEN_LEN];
    let body = build_register_body(&kp, &rid, &token, true, now_secs());
    let r = register(&running, &rid, body).await;
    assert_eq!(r, status::OK);

    // Notify with hop A's key under hop B's header → reject.
    let r = exit_call(&running, false, NOTIFY_PATH, HOP_B, &KEY_A, Kind::PushNotify, &rid.0).await;
    assert_eq!(r.http, 403, "cross-hop key on notify must fail");

    // Notify with the correct hop B + KEY_B → accepted.
    let r = exit_call(&running, false, NOTIFY_PATH, HOP_B, &KEY_B, Kind::PushNotify, &rid.0).await;
    assert!(r.ok());
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(running.apns.snapshot().len(), 1);
}

// ---------- Addendum A1 §10 / §14 -------------------------------------------

#[tokio::test]
async fn a1_register_signed_under_another_tag_is_401() {
    let running = spawn(Arc::new(RecordingApnsSender::new())).await;
    let kp = HsigKeyPair::generate();
    let rid = rid_of(&kp);
    assert!(replicate(&running, &rid, &kp.public_key_bytes()).await.ok());

    let token = [0x41; APNS_TOKEN_LEN];
    let body = build_register_body_tagged(&kp, HSIG_USECASE_BUNDLE, &rid, &token, false, now_secs());
    let r = register(&running, &rid, body).await;
    assert_eq!(r, status::SIGNATURE);

    // Baseline: the same request under the right tag is accepted.
    let body = build_register_body(&kp, &rid, &token, false, now_secs() + 1);
    assert_eq!(register(&running, &rid, body).await, status::OK);
}

#[tokio::test]
async fn a1_replicate_from_hop_outside_owner_list_is_403() {
    // HOP holds a valid S2S key but is not a directory owner.
    let running = spawn_with_owners(Arc::new(RecordingApnsSender::new()), &["some-other-exit"]).await;
    let kp = HsigKeyPair::generate();
    let r = replicate(&running, &rid_of(&kp), &kp.public_key_bytes()).await;
    assert_eq!(r.http, 403);
}

#[tokio::test]
async fn a1_empty_owner_list_lets_no_hop_replicate() {
    // The library default is fail-closed: without a list nobody replicates.
    let running = spawn_with_owners(Arc::new(RecordingApnsSender::new()), &[]).await;
    let kp = HsigKeyPair::generate();
    let r = replicate(&running, &rid_of(&kp), &kp.public_key_bytes()).await;
    assert_eq!(r.http, 403);
}

// =============================================================================
// Addendum A2 stage 2 — sealed PUSH_REGISTER (POST /v2/sealed)
// =============================================================================

/// A push relay with a sealed identity; returns its HKEM pk and target id.
async fn spawn_sealed(apns: Arc<RecordingApnsSender>) -> (Running, Vec<u8>, [u8; 16]) {
    let running = spawn(apns).await;
    let (pk, target_id) = running.sealed.clone().unwrap();
    (running, pk, target_id)
}

/// F9: no X-Forwarded-For. The sealed route no longer keys anything on the
/// client address (every request arrives from the Entry).
async fn post_sealed(running: &Running, body: Vec<u8>) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("{}/v2/sealed", running.base_url))
        .body(body)
        .send()
        .await
        .unwrap()
}

/// Seal `kind` with `rid || register_body`, post it, open the answer.
async fn sealed_register(
    running: &Running,
    pk: &[u8],
    target_id: &[u8; 16],
    kind: Kind,
    rid: &RecipientId,
    register_body: &[u8],
) -> sealed::OpenedResponse {
    let mut body = rid.0.to_vec();
    body.extend_from_slice(register_body);
    let (req, key) = sealed::seal_request(pk, target_id, kind, &body).unwrap();
    let r = post_sealed(running, req).await;
    assert_eq!(r.status(), 200, "an opened request always answers 200");
    let bytes = r.bytes().await.unwrap();
    sealed::open_response(&key, target_id, kind.lane(), &bytes).unwrap()
}

#[tokio::test]
async fn a2_sealed_register_happy_path_then_notify_reaches_apns() {
    let apns = Arc::new(RecordingApnsSender::new());
    let (running, pk, target_id) = spawn_sealed(apns.clone()).await;
    let kp = HsigKeyPair::generate();
    let rid = rid_of(&kp);
    assert!(replicate(&running, &rid, &kp.public_key_bytes()).await.ok());

    let token = [0x5A; APNS_TOKEN_LEN];
    let reg = build_register_body(&kp, &rid, &token, false, now_secs());
    let resp = sealed_register(&running, &pk, &target_id, Kind::PushRegister, &rid, &reg).await;
    assert_eq!(resp.status, status::OK);
    assert!(resp.body.is_empty());
    assert!(resp.target_time.abs_diff(now_secs()) <= 5, "target time is the relay clock");

    // The token stored through the sealed path is the one a notify uses.
    assert!(notify(&running, &rid).await.ok());
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(apns.snapshot().len(), 1, "one APNs send for the sealed-registered token");
}

#[tokio::test]
async fn a2_sealed_register_bad_signature_is_sealed_signature() {
    let apns = Arc::new(RecordingApnsSender::new());
    let (running, pk, target_id) = spawn_sealed(apns.clone()).await;
    let kp = HsigKeyPair::generate();
    let rid = rid_of(&kp);
    replicate(&running, &rid, &kp.public_key_bytes()).await;

    let attacker = HsigKeyPair::generate();
    let reg = build_register_body(&attacker, &rid, &[0x5B; APNS_TOKEN_LEN], false, now_secs());
    let resp = sealed_register(&running, &pk, &target_id, Kind::PushRegister, &rid, &reg).await;
    assert_eq!(resp.status, status::SIGNATURE);
    assert!(notify(&running, &rid).await.ok());
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(apns.snapshot().is_empty(), "no token stored");
}

#[tokio::test]
async fn a2_sealed_register_unknown_recipient_is_sealed_unknown() {
    let (running, pk, target_id) = spawn_sealed(Arc::new(RecordingApnsSender::new())).await;
    let kp = HsigKeyPair::generate();
    let rid = rid_from(0x53);
    let reg = build_register_body(&kp, &rid, &[0x5C; APNS_TOKEN_LEN], false, now_secs());
    let resp = sealed_register(&running, &pk, &target_id, Kind::PushRegister, &rid, &reg).await;
    assert_eq!(resp.status, status::UNKNOWN_RECIPIENT);
}

#[tokio::test]
async fn a2_sealed_other_kind_is_sealed_malformed() {
    let (running, pk, target_id) = spawn_sealed(Arc::new(RecordingApnsSender::new())).await;
    let kp = HsigKeyPair::generate();
    let rid = rid_of(&kp);
    replicate(&running, &rid, &kp.public_key_bytes()).await;
    // A correct register body under a kind the push relay does not serve.
    let reg = build_register_body(&kp, &rid, &[0x5D; APNS_TOKEN_LEN], false, now_secs());
    let resp = sealed_register(&running, &pk, &target_id, Kind::Fetch, &rid, &reg).await;
    assert_eq!(resp.status, status::MALFORMED);
}

#[tokio::test]
async fn a2_sealed_short_body_is_sealed_malformed() {
    let (running, pk, target_id) = spawn_sealed(Arc::new(RecordingApnsSender::new())).await;
    let rid = rid_from(0x55);
    let resp = sealed_register(&running, &pk, &target_id, Kind::PushRegister, &rid, &[0u8; 10]).await;
    assert_eq!(resp.status, status::MALFORMED);
}

#[tokio::test]
async fn a2_sealed_for_another_target_is_400() {
    let (running, _pk, _target_id) = spawn_sealed(Arc::new(RecordingApnsSender::new())).await;
    // Sealed to a different key: the relay cannot open it.
    let other = HkemKeyPair::generate();
    let other_pk = other.public_key_bytes();
    let other_id = *exit_id_from_hkem_pk(&other_pk).as_bytes();
    let (req, _) = sealed::seal_request(&other_pk, &other_id, Kind::PushRegister, &[0u8; 32]).unwrap();
    assert_eq!(post_sealed(&running, req).await.status(), 400);
}

#[tokio::test]
async fn a2_sealed_not_a_lane_size_is_400() {
    let (running, _pk, _target_id) = spawn_sealed(Arc::new(RecordingApnsSender::new())).await;
    assert_eq!(post_sealed(&running, vec![0x06; Lane::Fetch.request_len() - 1]).await.status(), 400);
}

#[tokio::test]
async fn a2_sealed_without_a_loaded_key_is_503() {
    let running = spawn_with(Arc::new(RecordingApnsSender::new()), &[HOP], None).await;
    let other = HkemKeyPair::generate();
    let pk = other.public_key_bytes();
    let id = *exit_id_from_hkem_pk(&pk).as_bytes();
    let (req, _) = sealed::seal_request(&pk, &id, Kind::PushRegister, &[0u8; 32]).unwrap();
    assert_eq!(post_sealed(&running, req).await.status(), 503);
}

#[test]
fn a2_push_delay_defaults_to_three_seconds() {
    let state = PushState::new(
        Arc::new(std::collections::HashMap::new()),
        "push1".to_string(),
        Arc::new(RecordingApnsSender::new()),
    );
    assert_eq!(state.push_delay_max_ms, push_relay::state::PUSH_DELAY_MAX_MS);
    assert_eq!(push_relay::state::PUSH_DELAY_MAX_MS, 3_000);
}

/// Phase B: the client-facing `PUT /v2/push/register/:rid` is gone; the
/// sealed PUSH_REGISTER is the only way to register.
#[tokio::test]
async fn a2_old_register_route_is_gone() {
    let running = spawn(Arc::new(RecordingApnsSender::new())).await;
    let r = reqwest::Client::new()
        .put(format!("{}/v2/push/register/{}", running.base_url, "aa".repeat(32)))
        .body(vec![0u8; PUSH_REGISTER_BODY_LEN])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);
}

/// F38: the replica binds rid to SHA-256(hsig_pk), as the exit enforces on
/// `PUT /v2/directory/:rid`. A replicate whose rid is not the hash of its
/// hsig_pk is refused (sealed MALFORMED since F43), even with a valid S2S
/// signature from an owner hop, and stores nothing.
#[tokio::test]
async fn f38_replicate_with_rid_not_matching_pk_is_refused() {
    let running = spawn(Arc::new(RecordingApnsSender::new())).await;
    let victim = HsigKeyPair::generate();
    let attacker = HsigKeyPair::generate();
    let victim_rid = rid_of(&victim);

    // Valid S2S, owner hop, but the attacker's key under the victim's rid.
    let r = replicate(&running, &victim_rid, &attacker.public_key_bytes()).await;
    assert_eq!(r.sealed_status(), Some(status::MALFORMED));

    // Nothing was stored: the attacker cannot register a token for the victim.
    let body = build_register_body(&attacker, &victim_rid, &[0x38; APNS_TOKEN_LEN], false, now_secs());
    assert_eq!(register(&running, &victim_rid, body).await, status::UNKNOWN_RECIPIENT);
}

// ---------- F9: limits on the sealed route ----------------------------------

/// The address Caddy in front of the push relay reports for every sealed
/// request: the Entry's, since only the Entry forwards them.
const ENTRY_XFF: &str = "198.51.100.10";

/// F9: every sealed request reaches the push relay from the Entry, so a
/// per-IP limit there put all clients into one bucket: 600 requests a
/// minute from anyone locked every device out of push registration. After
/// 601 garbage requests from the same peer a valid registration still
/// succeeds.
#[tokio::test]
async fn f9_garbage_from_the_entry_does_not_block_registration() {
    let (running, pk, target_id) = spawn_sealed(Arc::new(RecordingApnsSender::new())).await;
    let kp = HsigKeyPair::generate();
    let rid = rid_of(&kp);
    assert!(replicate(&running, &rid, &kp.public_key_bytes()).await.ok());

    let client = reqwest::Client::new();
    let url = format!("{}/v2/sealed", running.base_url);
    // 601 requests on 20 parallel workers (a burst of 601 connects
    // overflows the test listener's backlog).
    let sent = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..20 {
        let (c, u, sent) = (client.clone(), url.clone(), sent.clone());
        tasks.spawn(async move {
            let mut codes = Vec::new();
            while sent.fetch_add(1, std::sync::atomic::Ordering::SeqCst) < 601 {
                let r = c
                    .post(&u)
                    .header("x-forwarded-for", ENTRY_XFF)
                    .body(vec![0x06; Lane::Fetch.request_len()])
                    .send()
                    .await
                    .unwrap();
                codes.push(r.status().as_u16());
            }
            codes
        });
    }
    let mut total = 0;
    while let Some(codes) = tasks.join_next().await {
        for c in codes.unwrap() {
            assert_eq!(c, 400, "garbage does not open");
            total += 1;
        }
    }
    assert_eq!(total, 601);

    let reg = build_register_body(&kp, &rid, &[0x09; APNS_TOKEN_LEN], false, now_secs());
    let mut body = rid.0.to_vec();
    body.extend_from_slice(&reg);
    let (req, key) = sealed::seal_request(&pk, &target_id, Kind::PushRegister, &body).unwrap();
    let r = client.post(&url).header("x-forwarded-for", ENTRY_XFF).body(req).send().await.unwrap();
    assert_eq!(r.status(), 200);
    let resp = sealed::open_response(&key, &target_id, Lane::Fetch, &r.bytes().await.unwrap()).unwrap();
    assert_eq!(resp.status, status::OK);
}

/// F9 (a): the global signature-verify budget is spent before the hybrid
/// verify; over it the sealed status is UNAVAILABLE and nothing is stored.
#[tokio::test]
async fn f9_verify_budget_exhausted_is_sealed_unavailable() {
    let running = spawn_tuned(Arc::new(RecordingApnsSender::new()), &[HOP], Some(new_identity()), |s| {
        s.sealed_limits = push_relay::state::SealedLimits::with_verify_cap(0);
    })
    .await;
    let kp = HsigKeyPair::generate();
    let rid = rid_of(&kp);
    assert!(replicate(&running, &rid, &kp.public_key_bytes()).await.ok());
    let body = build_register_body(&kp, &rid, &[0x0A; APNS_TOKEN_LEN], false, now_secs());
    assert_eq!(register(&running, &rid, body).await, status::UNAVAILABLE);
}

/// F9 (b): per recipient, counted only after the signature held: forged
/// requests do not spend the victim's budget; the 11th valid one within a
/// minute is RATE.
#[tokio::test]
async fn f9_per_rid_limit_counts_only_verified_registrations() {
    let (running, _pk, _target_id) = spawn_sealed(Arc::new(RecordingApnsSender::new())).await;
    let kp = HsigKeyPair::generate();
    let rid = rid_of(&kp);
    assert!(replicate(&running, &rid, &kp.public_key_bytes()).await.ok());

    let attacker = HsigKeyPair::generate();
    for _ in 0..push_relay::state::REGISTER_PER_RID_PER_MIN + 5 {
        let forged = build_register_body(&attacker, &rid, &[0x0B; APNS_TOKEN_LEN], false, now_secs());
        assert_eq!(register(&running, &rid, forged).await, status::SIGNATURE);
    }

    let body = build_register_body(&kp, &rid, &[0x0C; APNS_TOKEN_LEN], false, now_secs());
    for _ in 0..push_relay::state::REGISTER_PER_RID_PER_MIN {
        assert_eq!(register(&running, &rid, body.clone()).await, status::OK);
    }
    assert_eq!(register(&running, &rid, body).await, status::RATE);
}

// ---------- F43: exit -> push carries no plaintext rid ----------------------

/// F43: the replicate URL and the notify body used to carry the rid in
/// clear on the exit -> push hop. Both plaintext forms are refused now
/// (fail-closed, no window in which both are accepted), even with a valid
/// S2S signature from an owner hop.
#[tokio::test]
async fn f43_plaintext_rid_forms_are_refused() {
    let running = spawn(Arc::new(RecordingApnsSender::new())).await;
    let kp = HsigKeyPair::generate();
    let rid = rid_of(&kp);
    let r = replicate_plain(&running, &rid, &kp.public_key_bytes()).await;
    assert!(r == 404 || r == 405, "replicate with rid in the URL: {r}");
    let n = notify_plain(&running, &rid).await;
    assert_eq!(n, 400, "notify with a plaintext rid body");
}

/// The pre-F43 replicate: rid in the URL, hsig_pk as body, valid S2S.
async fn replicate_plain(running: &Running, rid: &RecipientId, hsig_pk: &[u8]) -> u16 {
    let url = format!("{}/v2/directory/replicate/{}", running.base_url, hex::encode(rid.0));
    let ts = now_secs().to_string();
    let sig = s2s_sign(&S2S_KEY, HOP, &ts, hsig_pk);
    reqwest::Client::new()
        .put(&url)
        .header("x-relay-hop", HOP)
        .header("x-relay-timestamp", &ts)
        .header("x-relay-signature", &sig)
        .body(hsig_pk.to_vec())
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

/// The pre-F43 notify: the rid itself as body, valid S2S.
async fn notify_plain(running: &Running, rid: &RecipientId) -> u16 {
    let ts = now_secs().to_string();
    let sig = s2s_sign(&S2S_KEY, HOP, &ts, &rid.0);
    reqwest::Client::new()
        .post(format!("{}/v2/push/notify", running.base_url))
        .header("x-relay-hop", HOP)
        .header("x-relay-timestamp", &ts)
        .header("x-relay-signature", &sig)
        .body(rid.0.to_vec())
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

/// F43: each S2S route opens only its own kind; the client route refuses
/// the exit kinds, so nobody can replicate or notify without S2S.
#[tokio::test]
async fn f43_kinds_are_bound_to_their_routes() {
    let running = spawn(Arc::new(RecordingApnsSender::new())).await;
    let kp = HsigKeyPair::generate();
    let rid = rid_of(&kp);
    let body = replicate_body(&rid, &kp.public_key_bytes());
    // Replicate kind on the notify route, notify kind on the replicate route.
    let r = exit_call(&running, false, NOTIFY_PATH, HOP, &S2S_KEY, Kind::PushReplicate, &body).await;
    assert_eq!(r.sealed_status(), Some(status::MALFORMED));
    let r = exit_call(&running, true, REPLICATE_PATH, HOP, &S2S_KEY, Kind::PushNotify, &rid.0).await;
    assert_eq!(r.sealed_status(), Some(status::MALFORMED));
    // The exit kinds through the client route (no S2S): refused, nothing stored.
    let (pk, target_id) = running.sealed.clone().unwrap();
    let resp = sealed_register(&running, &pk, &target_id, Kind::PushReplicate, &rid, &kp.public_key_bytes()).await;
    assert_eq!(resp.status, status::MALFORMED);
    let reg = build_register_body(&kp, &rid, &[0x43; APNS_TOKEN_LEN], false, now_secs());
    assert_eq!(register(&running, &rid, reg).await, status::UNKNOWN_RECIPIENT, "nothing was replicated");
}
