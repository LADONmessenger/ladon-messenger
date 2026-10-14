//! F43: the real exit -> push client against a capturing stand-in for the
//! push relay. The rid must not appear in the URL or in the bytes on the
//! wire; the request must be a sealed lane-F request to the push relay's
//! HKEM key that opens to the right kind and body.

use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Uri};
use axum::routing::{post, put};
use tokio::net::TcpListener;

use exit_relay_v2::{PushClient, ReqwestPushClient};
use ladon_relay_core_v2::constants::HSIG_PK_LEN;
use ladon_relay_core_v2::hash::exit_id_from_hkem_pk;
use ladon_relay_core_v2::hkem::HkemKeyPair;
use ladon_relay_core_v2::ids::RecipientId;
use ladon_relay_core_v2::wire::sealed::{self, status, Kind, LANE_F_REQUEST_LEN};

struct Seen {
    path: String,
    has_s2s: bool,
    body: Vec<u8>,
}

struct Push {
    keys: HkemKeyPair,
    target_id: [u8; 16],
    seen: Mutex<Vec<Seen>>,
}

async fn capture(State(p): State<Arc<Push>>, uri: Uri, headers: HeaderMap, body: Bytes) -> Vec<u8> {
    let has_s2s = ["x-relay-hop", "x-relay-timestamp", "x-relay-signature", "x-relay-nonce"]
        .iter()
        .all(|h| headers.contains_key(*h));
    p.seen.lock().unwrap().push(Seen { path: uri.path().to_string(), has_s2s, body: body.to_vec() });
    let opened = sealed::open_request(&p.keys, &p.target_id, &body).unwrap();
    sealed::seal_response(&opened.response_key, &p.target_id, opened.lane, status::OK, 1, &[]).unwrap()
}

#[tokio::test]
async fn f43_replicate_and_notify_are_sealed_without_plaintext_rid() {
    let keys = HkemKeyPair::generate();
    let pk = keys.public_key_bytes().to_vec();
    let target_id = *exit_id_from_hkem_pk(&pk).as_bytes();
    let push = Arc::new(Push { keys, target_id, seen: Mutex::new(Vec::new()) });
    let app = axum::Router::new()
        .route("/v2/directory/replicate", put(capture))
        .route("/v2/push/notify", post(capture))
        .with_state(push.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let client = ReqwestPushClient::new(format!("http://{addr}"), [0x5C; 32], "exit1".into(), pk, target_id);
    let rid = RecipientId([0xA7; 32]);
    let hsig_pk = vec![0x3D; HSIG_PK_LEN];
    client.replicate(&rid, &hsig_pk).await;
    client.notify(&rid).await;

    let seen = push.seen.lock().unwrap();
    assert_eq!(seen.len(), 2, "both calls reached the push relay");
    let rid_hex = hex::encode(rid.0);
    for (s, (path, kind)) in seen.iter().zip([
        ("/v2/directory/replicate", Kind::PushReplicate),
        ("/v2/push/notify", Kind::PushNotify),
    ]) {
        assert_eq!(s.path, path);
        assert!(!s.path.contains(&rid_hex), "no rid in the URL");
        assert!(s.has_s2s, "S2S HMAC headers stay");
        assert_eq!(s.body.len(), LANE_F_REQUEST_LEN, "a sealed lane-F request");
        assert!(!s.body.windows(32).any(|w| w == rid.0), "no plaintext rid on the wire");
        let opened = sealed::open_request(&push.keys, &target_id, &s.body).unwrap();
        assert_eq!(opened.kind, kind);
        let mut want = rid.0.to_vec();
        if kind == Kind::PushReplicate {
            want.extend_from_slice(&hsig_pk);
        }
        assert_eq!(&opened.body[..], &want[..]);
    }
}
