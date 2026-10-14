//! Entry integration tests: 1 Entry + exits (and a mock push relay), over
//! real HTTP.
//!
//! Addendum A2 stage 2, phase B: the entry has one client route,
//! `POST /v2/relay`. A sealed request (relay protocol 0x06) is routed by its
//! target id — to an exit with the S2S HMAC (`/v2/sealed`), or to the push
//! relay without it — and the lane-size answer comes back byte for byte.
//! The former A1 routes (`/v2/enqueue`, `/v2/proxy-directory[-put]`,
//! `/v2/proxy-push-register`, `/v2/fetch-proxy`) must answer 404.
//!
//! The exit test state comes from the exit crate's test module.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::serve;
use tokio::net::TcpListener;

use ladon_relay_core_v2::constants::*;
use ladon_relay_core_v2::hash::{exit_delivery_key, exit_id_from_hkem_pk};
use ladon_relay_core_v2::hkem::HkemKeyPair;
use ladon_relay_core_v2::hsig::HSIG_USECASE_FETCH;
use ladon_relay_core_v2::ids::ExitId;


use exit_relay_v2 as exit;
use entry_relay_v2 as entry;

#[allow(dead_code)]
#[path = "../../exit-relay-v2/tests/common/mod.rs"]
mod exit_common;
use exit_common::Recipient;

// ---------- Test scaffolding ------------------------------------------------

struct RunningExit {
    addr: SocketAddr,
    hkem_pk: Vec<u8>,
    exit_id: ExitId,
}

async fn spawn_exit(s2s_key: [u8; 32]) -> RunningExit {
    let kp = HkemKeyPair::generate();
    let pk = kp.public_key_bytes().to_vec();
    let exit_id = exit_id_from_hkem_pk(&pk);

    let canary = std::env::temp_dir().join("ladon-test-canary.json");
    let _ = std::fs::write(&canary, br#"{"ok":true}"#);

    // The entry under test signs with hop "entry-test" (see spawn_entry below).
    let state = exit_common::test_state(
        exit_id,
        kp,
        canary,
        exit_common::now_sec(),
        exit_common::TestStateOpts { entry_hop: "entry-test", s2s_key, push: None },
    );
    let app = exit::router(Arc::new(state));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { let _ = serve(listener, app).await; });
    RunningExit { addr, hkem_pk: pk, exit_id }
}

async fn spawn_entry(
    s2s_key: [u8; 32],
    exits: &[(ladon_relay_core_v2::ids::ExitId, SocketAddr)],
) -> SocketAddr {
    spawn_entry_with_push(s2s_key, exits, None).await
}

/// `push` = the push relay's address and sealed-request target id (A2).
async fn spawn_entry_with_push(
    s2s_key: [u8; 32],
    exits: &[(ladon_relay_core_v2::ids::ExitId, SocketAddr)],
    push: Option<(SocketAddr, [u8; 16])>,
) -> SocketAddr {
    let mut hex_map: HashMap<String, String> = HashMap::new();
    for (id, addr) in exits {
        hex_map.insert(hex::encode(id.as_bytes()), format!("http://{}", addr));
    }
    let registry = entry::ExitRegistry::from_hex_map(&hex_map).unwrap();
    let canary = std::env::temp_dir().join("ladon-entry-test-canary.json");
    let _ = std::fs::write(&canary, br#"{"ok":true}"#);
    let http = reqwest::Client::builder()
        .pool_max_idle_per_host(8)
        .timeout(std::time::Duration::from_secs(5))
        .build().unwrap();
    let state = entry::EntryState {
        hop_id: "entry-test".to_string(),
        s2s_key, registry, http, canary_path: canary,
        push_relay_url: push.map(|(a, _)| format!("http://{}", a)),
        push_target_id: push.map(|(_, id)| id),
        rate_limiter: Arc::new(ladon_relay_core_v2::ratelimit::RateLimiter::new()),
    };
    let app = entry::router(Arc::new(state));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { let _ = serve(listener, app).await; });
    addr
}

// ---------- Client helpers ---------------------------------------------------

/// Client for the client-facing routes, carrying `X-Forwarded-For` the way
/// Caddy sets it in production. The relays' rate-limit middleware fails
/// closed on a missing XFF (P7-RELAY-07), so without it every call is 429 —
/// same repair as `exit-relay-v2/tests/common/mod.rs`.
fn test_client() -> reqwest::Client {
    let mut headers = reqwest::header::HeaderMap::new();
    // TEST-NET-3 (RFC 5737) — never a real client.
    headers.insert("x-forwarded-for", "203.0.113.7".parse().unwrap());
    reqwest::Client::builder()
        .default_headers(headers)
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .expect("test client builds")
}

// ---------- Addendum A2 stage 2: POST /v2/relay -----------------------------

use ladon_relay_core_v2::wire::sealed::{self, status, Kind, Lane, OpenedResponse, SEALED_INNER_ENVELOPE_LEN};

/// Seal `body` for `exit`, send it through the Entry's `/v2/relay`, require
/// HTTP 200 and a lane-size answer, and open it.
async fn relay_call(client: &reqwest::Client, entry: SocketAddr, exit: &RunningExit, kind: Kind, body: &[u8]) -> OpenedResponse {
    let (req, key) = sealed::seal_request(&exit.hkem_pk, exit.exit_id.as_bytes(), kind, body).unwrap();
    assert_eq!(req.len(), kind.lane().request_len());
    let resp = client.post(format!("http://{}/v2/relay", entry)).body(req).send().await.unwrap();
    assert_eq!(resp.status(), 200, "{kind:?} through the entry");
    let bytes = resp.bytes().await.unwrap();
    assert_eq!(bytes.len(), kind.lane().response_len(), "{kind:?}: lane-size response");
    sealed::open_response(&key, exit.exit_id.as_bytes(), kind.lane(), &bytes).unwrap()
}

/// FETCH body signed over the v2 pre-image for `exit` (SRV-13).
fn sealed_fetch_body(exit: &RunningExit, r: &Recipient, ack: [u8; FETCH_BATCH_ID_LEN]) -> Vec<u8> {
    let ts = exit_common::now_sec();
    let mut m = DOMAIN_FETCH_ACK_AUTH.to_vec();
    m.extend_from_slice(exit.exit_id.as_bytes());
    m.extend_from_slice(r.rid.as_bytes());
    m.extend_from_slice(&ts.to_be_bytes());
    m.extend_from_slice(&ack);
    let sig = r.hsig.sign_tagged(HSIG_USECASE_FETCH, &m);
    let mut b = r.rid.as_bytes().to_vec();
    b.extend_from_slice(&ts.to_be_bytes());
    b.extend_from_slice(&ack);
    b.extend_from_slice(&sig);
    b
}

/// Publish, send and fetch with sealed requests only, through the Entry, with
/// a second exit configured so routing by target id is exercised too.
#[tokio::test]
async fn a2_relay_sealed_roundtrip_through_entry() {
    let s2s_key = [0xA2u8; 32];
    let exit_a = spawn_exit(s2s_key).await;
    let exit_b = spawn_exit(s2s_key).await;
    let entry_addr = spawn_entry(s2s_key, &[(exit_a.exit_id, exit_a.addr), (exit_b.exit_id, exit_b.addr)]).await;
    let client = test_client();

    let r = exit_common::new_recipient();
    let bundle = exit_common::make_bundle(&r, exit_a.exit_id, exit_common::now_sec());
    assert_eq!(relay_call(&client, entry_addr, &exit_a, Kind::DirPut, &bundle).await.status, status::OK);

    let inner = vec![0x5Eu8; SEALED_INNER_ENVELOPE_LEN];
    let mut enq = r.rid.as_bytes().to_vec();
    enq.extend_from_slice(&exit_delivery_key(&r.delivery_key, &exit_a.exit_id));
    enq.extend_from_slice(&exit_common::now_sec().to_be_bytes());
    enq.extend_from_slice(&exit_common::envelope_id());
    enq.extend_from_slice(&inner);
    assert_eq!(relay_call(&client, entry_addr, &exit_a, Kind::Enqueue, &enq).await.status, status::OK);

    // Exit B never saw the recipient.
    let rid = r.rid.as_bytes().to_vec();
    assert_eq!(relay_call(&client, entry_addr, &exit_b, Kind::DirGet, &rid).await.status, status::UNKNOWN_RECIPIENT);

    let got = relay_call(&client, entry_addr, &exit_a, Kind::Fetch, &sealed_fetch_body(&exit_a, &r, [0u8; FETCH_BATCH_ID_LEN])).await;
    assert_eq!(got.status, status::OK);
    // has_more 0 || batch id || count 1 || len u32 || inner
    assert_eq!(got.body[0], 0);
    assert_eq!(got.body[17], 1);
    assert_eq!(u32::from_be_bytes(got.body[18..22].try_into().unwrap()) as usize, SEALED_INNER_ENVELOPE_LEN);
    assert_eq!(&got.body[22..], &inner[..]);
}

/// Mock push relay: records what reached `POST /v2/sealed` and answers with
/// a fixed body.
/// (body, carried an S2S signature header)
type SeenRequest = (Vec<u8>, bool);

#[derive(Clone, Default)]
struct MockSealedPush {
    bodies: Arc<std::sync::Mutex<Vec<SeenRequest>>>,
    answer: Arc<Vec<u8>>,
}

async fn spawn_mock_sealed_push(answer: Vec<u8>) -> (SocketAddr, MockSealedPush) {
    use axum::{body::Bytes, extract::State, http::HeaderMap, routing::post};
    let mock = MockSealedPush { bodies: Default::default(), answer: Arc::new(answer) };
    async fn h(State(m): State<MockSealedPush>, headers: HeaderMap, body: Bytes) -> Vec<u8> {
        let has_s2s = headers.contains_key("x-relay-signature");
        m.bodies.lock().unwrap().push((body.to_vec(), has_s2s));
        m.answer.as_ref().clone()
    }
    let app = axum::Router::new().route("/v2/sealed", post(h)).with_state(mock.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { let _ = serve(listener, app).await; });
    (addr, mock)
}

/// A request for the push relay's target id: forwarded verbatim, without the
/// exits' S2S HMAC, and the answer comes back verbatim.
#[tokio::test]
async fn a2_relay_routes_push_target_to_push_relay() {
    let push_keys = HkemKeyPair::generate();
    let push_pk = push_keys.public_key_bytes();
    let push_id = *exit_id_from_hkem_pk(&push_pk).as_bytes();
    let answer = vec![0xABu8; Lane::Fetch.response_len()];
    let (push_addr, mock) = spawn_mock_sealed_push(answer.clone()).await;
    let entry_addr = spawn_entry_with_push([0x11; 32], &[], Some((push_addr, push_id))).await;

    let (req, _) = sealed::seal_request(&push_pk, &push_id, Kind::PushRegister, &[7u8; 64]).unwrap();
    let resp = test_client().post(format!("http://{}/v2/relay", entry_addr)).body(req.clone()).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.bytes().await.unwrap().to_vec(), answer);
    let seen = mock.bodies.lock().unwrap().clone();
    assert_eq!(seen, vec![(req, false)], "body verbatim, no S2S header to the push relay");
}

#[tokio::test]
async fn a2_relay_upstream_answer_of_wrong_size_is_502() {
    let push_keys = HkemKeyPair::generate();
    let push_pk = push_keys.public_key_bytes();
    let push_id = *exit_id_from_hkem_pk(&push_pk).as_bytes();
    let (push_addr, _mock) = spawn_mock_sealed_push(vec![0u8; Lane::Fetch.response_len() - 1]).await;
    let entry_addr = spawn_entry_with_push([0x11; 32], &[], Some((push_addr, push_id))).await;
    let (req, _) = sealed::seal_request(&push_pk, &push_id, Kind::PushRegister, &[7u8; 64]).unwrap();
    let resp = test_client().post(format!("http://{}/v2/relay", entry_addr)).body(req).send().await.unwrap();
    assert_eq!(resp.status(), 502);
}

#[tokio::test]
async fn a2_relay_refuses_what_it_can_check() {
    let s2s_key = [0xA3u8; 32];
    let exit_a = spawn_exit(s2s_key).await;
    let entry_addr = spawn_entry(s2s_key, &[(exit_a.exit_id, exit_a.addr)]).await;
    let client = test_client();
    let post = |body: Vec<u8>| client.post(format!("http://{}/v2/relay", entry_addr)).body(body).send();

    // Not one of the two lane sizes.
    let r = post(vec![sealed::SEALED_VERSION; Lane::Fetch.request_len() + 1]).await.unwrap();
    assert_eq!(r.status(), 400);
    // Lane size, but not protocol 0x06.
    let (mut req, _) = sealed::seal_request(&exit_a.hkem_pk, exit_a.exit_id.as_bytes(), Kind::Fetch, b"x").unwrap();
    req[0] = 0x05;
    let r = post(req).await.unwrap();
    assert_eq!(r.status(), 400);
    assert_eq!(r.headers().get("X-Ladon-Error-Code").unwrap(), "E-VERSION");
    // Unknown target id (no push relay configured either).
    let other = HkemKeyPair::generate();
    let other_pk = other.public_key_bytes();
    let other_id = *exit_id_from_hkem_pk(&other_pk).as_bytes();
    let (req, _) = sealed::seal_request(&other_pk, &other_id, Kind::PushRegister, b"x").unwrap();
    assert_eq!(post(req).await.unwrap().status(), 404);
    // A request the exit cannot open (target id of exit A, sealed to another
    // key) is the exit's 400, passed through.
    let (mut req, _) = sealed::seal_request(&other_pk, exit_a.exit_id.as_bytes(), Kind::Fetch, b"x").unwrap();
    req[sealed::SEALED_OFF_NONCE] ^= 1;
    assert_eq!(post(req).await.unwrap().status(), 400);
}

/// A wrong S2S key between entry and exit is the operator's problem: the
/// client sees a neutral 502, never the exit's 403.
#[tokio::test]
async fn a2_relay_s2s_failure_is_a_neutral_502() {
    let exit_a = spawn_exit([0x01; 32]).await;
    let entry_addr = spawn_entry([0x02; 32], &[(exit_a.exit_id, exit_a.addr)]).await;
    let (req, _) = sealed::seal_request(&exit_a.hkem_pk, exit_a.exit_id.as_bytes(), Kind::Cover, b"").unwrap();
    let r = test_client().post(format!("http://{}/v2/relay", entry_addr)).body(req).send().await.unwrap();
    assert_eq!(r.status(), 502);
}

/// Phase B: the A1 client routes are gone; only `/v2/relay`, health and
/// canary answer.
#[tokio::test]
async fn a2_old_routes_are_gone() {
    let s2s_key = [0xA4u8; 32];
    let exit_a = spawn_exit(s2s_key).await;
    let entry_addr = spawn_entry(s2s_key, &[(exit_a.exit_id, exit_a.addr)]).await;
    let client = test_client();
    let base = format!("http://{}", entry_addr);
    let rid = "aa".repeat(32);
    let exit_hex = hex::encode(exit_a.exit_id.as_bytes());
    let checks = [
        client.post(format!("{base}/v2/enqueue")).body(vec![0u8; 16]),
        client.put(format!("{base}/v2/proxy-directory-put/{rid}")).body(vec![0u8; 16]),
        client.put(format!("{base}/v2/proxy-push-register/{rid}")).body(vec![0u8; 16]),
        client.get(format!("{base}/v2/proxy-directory?recipient={rid}&exit={exit_hex}")),
        client.get(format!("{base}/v2/fetch-proxy")),
    ];
    for req in checks {
        assert_eq!(req.send().await.unwrap().status(), 404);
    }
    assert_eq!(client.get(format!("{base}/v2/health")).send().await.unwrap().status(), 200);
}
