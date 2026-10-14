//! End-to-end integration test: init → put → finalize → get → delete.
//!
//! Uses `Router::oneshot` directly; fakes the `ConnectInfo` extension.

use std::sync::Arc;
use std::time::Duration;

use ladon_blob_relay::{
    build_app,
    capability::Signer,
    config::Config,
    rate_limit::{ConcurrencyGate, IpLimiter},
    storage::BlobStorage,
    AppState,
};
use sha2::{Digest, Sha256};

use axum::body::{to_bytes, Body};
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use axum::Router;
use tower::ServiceExt;

fn peer() -> ConnectInfo<std::net::SocketAddr> {
    ConnectInfo("127.0.0.1:9000".parse().unwrap())
}

fn req_with_peer(builder: axum::http::request::Builder, body: Body) -> Request<Body> {
    let mut req = builder.body(body).unwrap();
    req.extensions_mut().insert(peer());
    req
}

const LEAF_TAG: &[u8] = b"ladon-attach-v1/leaf";
const NODE_TAG: &[u8] = b"ladon-attach-v1/node";
const EMPTY_TAG: &[u8] = b"ladon-attach-v1/empty";

fn leaf_hash(i: u32, f: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(LEAF_TAG);
    h.update(i.to_be_bytes());
    h.update(f);
    h.finalize().into()
}
fn node_hash(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(NODE_TAG);
    h.update(a);
    h.update(b);
    h.finalize().into()
}
fn empty_hash() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(EMPTY_TAG);
    h.finalize().into()
}
fn merkle_root(frames: &[Vec<u8>]) -> [u8; 32] {
    if frames.is_empty() {
        return empty_hash();
    }
    let mut layer: Vec<[u8; 32]> = frames
        .iter()
        .enumerate()
        .map(|(i, f)| leaf_hash(i as u32, f))
        .collect();
    let target = layer.len().next_power_of_two().max(1);
    let empty = empty_hash();
    while layer.len() < target {
        layer.push(empty);
    }
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len() / 2);
        for pair in layer.chunks_exact(2) {
            next.push(node_hash(&pair[0], &pair[1]));
        }
        layer = next;
    }
    layer[0]
}

fn make_app() -> (Router, BlobStorage, tempfile::TempDir) {
    let tmp = tempfile::TempDir::new().unwrap();
    let cfg = Config::for_tests(tmp.path().to_path_buf());
    let storage = BlobStorage::open(cfg.data_dir.clone(), &cfg.master_key).unwrap();
    let signer = Signer::random();
    let state = Arc::new(AppState {
        storage: storage.clone(),
        capability_signer: signer,
        ip_limiter: IpLimiter::new(Duration::from_secs(60), 600),
        ip_limiter_read: IpLimiter::new(Duration::from_secs(60), 1200),
        put_gate: ConcurrencyGate::new(16, 4),
        config: cfg,
    });
    (build_app(state), storage, tmp)
}

/// `POST /v1/blob/init` without any identity (Addendum A2 stage 1).
fn init_request(blob_id_hex: &str) -> Request<Body> {
    let body_json = serde_json::json!({
        "blob_id": blob_id_hex,
        "chunk_count": 1u16,
        "bucket": 0x01u8,
        "expires_at": ladon_blob_relay::util::now_secs() + 3600,
    });
    req_with_peer(
        Request::builder()
            .method("POST")
            .uri("/v1/blob/init")
            .header("content-type", "application/json"),
        Body::from(serde_json::to_vec(&body_json).unwrap()),
    )
}

#[tokio::test]
async fn full_blob_lifecycle() {
    let (app, storage, _tmp) = make_app();

    let blob_id = [0x11u8; 16];
    let blob_id_hex = hex::encode(blob_id);
    let resp = app.clone().oneshot(init_request(&blob_id_hex)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "init failed");
    // Nothing about the uploader is stored with the blob.
    assert_eq!(storage.get_meta(&blob_id).unwrap().reserved, [0u8; 32]);
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let init_resp: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let upload_cap = init_resp["upload_cap"].as_str().unwrap().to_string();
    let read_cap = init_resp["read_cap"].as_str().unwrap().to_string();
    let delete_cap = init_resp["delete_cap"].as_str().unwrap().to_string();

    let chunk = vec![0x42u8; 32 + 1024 + 28];
    let req = req_with_peer(
        Request::builder()
            .method("PUT")
            .uri(format!("/v1/blob/{}/{}", blob_id_hex, 0))
            .header("x-ladon-blob-capability", &upload_cap)
            .header("content-type", "application/octet-stream"),
        Body::from(chunk.clone()),
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "put failed");

    let root = merkle_root(std::slice::from_ref(&chunk));
    let body = serde_json::json!({ "digest": hex::encode(root) });
    let req = req_with_peer(
        Request::builder()
            .method("POST")
            .uri(format!("/v1/blob/{}/finalize", blob_id_hex))
            .header("x-ladon-blob-capability", &upload_cap)
            .header("content-type", "application/json"),
        Body::from(serde_json::to_vec(&body).unwrap()),
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "finalize failed");

    let req = req_with_peer(
        Request::builder()
            .method("GET")
            .uri(format!("/v1/blob/{}/{}", blob_id_hex, 0))
            .header("x-ladon-blob-capability", &read_cap),
        Body::empty(),
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "get failed");
    let got = to_bytes(resp.into_body(), 10 * 1024 * 1024).await.unwrap();
    assert_eq!(got.as_ref(), chunk.as_slice());

    let req = req_with_peer(
        Request::builder()
            .method("DELETE")
            .uri(format!("/v1/blob/{}", blob_id_hex))
            .header("x-ladon-blob-capability", &delete_cap),
        Body::empty(),
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let req = req_with_peer(
        Request::builder()
            .method("GET")
            .uri(format!("/v1/blob/{}/{}", blob_id_hex, 0))
            .header("x-ladon-blob-capability", &read_cap),
        Body::empty(),
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn tampered_digest_triggers_integrity_error() {
    let (app, _storage, _tmp) = make_app();
    let blob_id = [0x22u8; 16];
    let blob_id_hex = hex::encode(blob_id);
    let resp = app.clone().oneshot(init_request(&blob_id_hex)).await.unwrap();
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let init_resp: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let upload_cap = init_resp["upload_cap"].as_str().unwrap().to_string();

    let chunk = vec![0xAAu8; 32 + 1024 + 28];
    let req = req_with_peer(
        Request::builder()
            .method("PUT")
            .uri(format!("/v1/blob/{}/{}", blob_id_hex, 0))
            .header("x-ladon-blob-capability", &upload_cap)
            .header("content-type", "application/octet-stream"),
        Body::from(chunk.clone()),
    );
    let _ = app.clone().oneshot(req).await.unwrap();

    let bogus = [0u8; 32];
    let body = serde_json::json!({ "digest": hex::encode(bogus) });
    let req = req_with_peer(
        Request::builder()
            .method("POST")
            .uri(format!("/v1/blob/{}/finalize", blob_id_hex))
            .header("x-ladon-blob-capability", &upload_cap)
            .header("content-type", "application/json"),
        Body::from(serde_json::to_vec(&body).unwrap()),
    );
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn health_and_pubkey_public() {
    let (app, _storage, _tmp) = make_app();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/blob/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/v1/blob/pubkey")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn identity_headers_of_an_older_client_are_ignored() {
    // An app from before A2 stage 1 still sends its identity and an HMAC.
    // The relay must neither need nor read them, and must store nothing of
    // them.
    let (app, storage, _tmp) = make_app();
    let blob_id = [0x33u8; 16];
    let mut req = init_request(&hex::encode(blob_id));
    let h = req.headers_mut();
    h.insert("x-ladon-identity", "bb".repeat(32).parse().unwrap());
    h.insert("x-ladon-timestamp", "1".parse().unwrap());
    h.insert("x-ladon-nonce", "n".parse().unwrap());
    h.insert("x-ladon-signature", "00".repeat(32).parse().unwrap());
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(storage.get_meta(&blob_id).unwrap().reserved, [0u8; 32]);
}

#[tokio::test]
async fn provisioning_is_gone() {
    // The identity enrolment endpoints are removed: neither answers with a
    // challenge or a secret any more.
    let (app, _storage, _tmp) = make_app();
    let resp = app
        .clone()
        .oneshot(req_with_peer(
            Request::builder().uri("/v1/blob/provision/challenge"),
            Body::empty(),
        ))
        .await
        .unwrap();
    assert_ne!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    assert!(json_field(&body, "challenge").is_none());

    let resp = app
        .oneshot(req_with_peer(
            Request::builder()
                .method("POST")
                .uri("/v1/blob/provision_auth_secret")
                .header("content-type", "application/json"),
            Body::from(r#"{"identity_pk":"","challenge":"","signature":""}"#),
        ))
        .await
        .unwrap();
    assert_ne!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    assert!(json_field(&body, "auth_secret").is_none());
}

/// The value of `key` if `body` is a JSON object that has it.
fn json_field(body: &[u8], key: &str) -> Option<serde_json::Value> {
    serde_json::from_slice::<serde_json::Value>(body).ok()?.get(key).cloned()
}
