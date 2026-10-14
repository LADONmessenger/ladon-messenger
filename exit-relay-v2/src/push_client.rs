//! Outbound HTTP client to the push-relay (Phase 3b, V2.1).
//!
//! The exit-relay calls into the push-relay at two points:
//!   * After a stored DIR_PUT we replicate the rid → hsig_pk mapping so the
//!     push-relay can verify hsig-signed registrations
//!     (`PUT /v2/directory/replicate`, sealed PUSH_REPLICATE).
//!   * After an accepted ENQUEUE we trigger a debounced APNs alert push
//!     (`POST /v2/push/notify`, sealed PUSH_NOTIFY).
//!
//! F43: both requests are sealed (`wire::sealed`, lane F) to the push
//! relay's HKEM key, so the rid appears neither in the URL nor in a
//! plaintext body on the exit → push hop. The S2S HMAC below covers the
//! sealed bytes.
//!
//! Both calls are **best-effort, fire-and-forget**: handlers `tokio::spawn`
//! the request and immediately return their normal response. A push-relay
//! outage must NEVER stall delivery or surface as an error to the caller —
//! envelopes still land in the mailbox and the iOS client's constant-rate
//! fetch loop will pick them up at the next tick.
//!
//! Authentication: every request carries the standard S2S quartet
//! `X-Relay-Hop`, `X-Relay-Timestamp`, `X-Relay-Signature`,
//! `X-Relay-Nonce`. P7-RELAY-08 (2026-05-20): we now sign with the
//! length-prefixed, domain-tagged pre-image
//!     DOMAIN_TAG || u16(|hop|) || hop || u16(|ts|) || ts || nonce || body
//! identical to the entry→exit `sign_s2s_tagged` form. The previous
//! untagged form `hop || ts || body` had a length-collision hazard
//! (hop="a"+ts="b" hashed the same as hop="ab"+ts="") and is removed.
//! The push-relay's verify_s2s already accepts both forms during the
//! migration window (`s2s_accept_legacy=true`); once all exits are on
//! the tagged form, `LADON_PUSH_S2S_ACCEPT_LEGACY=false` closes the
//! migration (PUSH-07).

use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use hmac::{Hmac, Mac};
use ladon_relay_core_v2::ids::RecipientId;
use ladon_relay_core_v2::wire::sealed::{self, status, Kind};
use rand::RngCore;
use sha2::Sha256;
use tracing::{debug, warn};
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

// P7-RELAY-08: must match push-relay's S2S_DOMAIN_TAG constant
// (push-relay/src/s2s.rs) and entry-relay's forward::S2S_DOMAIN_TAG.
const S2S_DOMAIN_TAG: &[u8] = b"L1-S2S-v2.1";
const S2S_NONCE_LEN: usize = 16;

/// Outbound push-relay client. Two operations, both best-effort.
///
/// Implementations are expected to log transport errors internally and
/// **never** propagate them — this is a notification side-channel, not a
/// critical path. The trait returns `()` to make that contract structural.
#[async_trait]
pub trait PushClient: Send + Sync {
    /// `PUT /v2/directory/replicate`, sealed PUSH_REPLICATE with
    /// body = `rid || hsig_pk` (32 + 1,984 B).
    async fn replicate(&self, rid: &RecipientId, hsig_pk: &[u8]);
    /// `POST /v2/push/notify`, sealed PUSH_NOTIFY with body = `rid` (32 B).
    async fn notify(&self, rid: &RecipientId);
}

// ============================================================================
// Real client (reqwest HTTP/2)
// ============================================================================

pub struct ReqwestPushClient {
    /// Base URL of the push-relay, e.g. `https://push.ladon.app`.
    /// No trailing slash.
    base_url: String,
    /// Shared HMAC key with the push-relay (32 bytes).
    s2s_key: [u8; 32],
    /// This exit's hop id, e.g. `exit1`.
    hop_id: String,
    /// F43: the push relay's HKEM public key and target id
    /// (`BLAKE3(pk)[..16]`); every request is sealed to them.
    push_hkem_pk: Vec<u8>,
    push_target_id: [u8; 16],
    http: reqwest::Client,
}

impl ReqwestPushClient {
    pub fn new(
        base_url: String,
        s2s_key: [u8; 32],
        hop_id: String,
        push_hkem_pk: Vec<u8>,
        push_target_id: [u8; 16],
    ) -> Self {
        let http = reqwest::Client::builder()
            .pool_idle_timeout(Duration::from_secs(60))
            .timeout(Duration::from_secs(5))
            .build()
            .expect("build reqwest http client");
        // Strip trailing slash so we can always concatenate `/v2/...`.
        let base_url = base_url.trim_end_matches('/').to_string();
        Self { base_url, s2s_key, hop_id, push_hkem_pk, push_target_id, http }
    }

    /// P7-RELAY-08: tagged + length-prefixed pre-image, identical to
    /// `entry_relay_v2::forward::sign_s2s_tagged`. Returns
    /// `(signature_hex, nonce_hex)` — both go on the wire as separate
    /// headers (`X-Relay-Signature`, `X-Relay-Nonce`).
    fn sign_tagged(&self, body: &[u8], ts_str: &str) -> (String, String) {
        let mut nonce = [0u8; S2S_NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce);
        let mut mac = HmacSha256::new_from_slice(&self.s2s_key)
            .expect("hmac key length is constant 32");
        mac.update(S2S_DOMAIN_TAG);
        mac.update(&(self.hop_id.len() as u16).to_be_bytes());
        mac.update(self.hop_id.as_bytes());
        mac.update(&(ts_str.len() as u16).to_be_bytes());
        mac.update(ts_str.as_bytes());
        mac.update(&nonce);
        mac.update(body);
        (hex::encode(mac.finalize().into_bytes()), hex::encode(nonce))
    }

    fn now_ts() -> String {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
            .to_string()
    }

    /// F43: seal `body` as `kind` to the push relay, S2S-sign the sealed
    /// bytes, send, and open the sealed answer. Best-effort: every failure
    /// is logged (without rid) and swallowed. `what` names the call in logs.
    async fn send_sealed(&self, put: bool, path: &str, kind: Kind, body: &[u8], what: &'static str) {
        let (req, response_key) =
            match sealed::seal_request(&self.push_hkem_pk, &self.push_target_id, kind, body) {
                Ok(v) => v,
                Err(e) => {
                    warn!(call = what, err = %e, "push request could not be sealed");
                    return;
                }
            };
        let url = format!("{}{}", self.base_url, path);
        let ts = Self::now_ts();
        let (sig, nonce_hex) = self.sign_tagged(&req, &ts);
        let builder = if put { self.http.put(&url) } else { self.http.post(&url) };
        let res = builder
            .header("x-relay-hop", &self.hop_id)
            .header("x-relay-timestamp", &ts)
            .header("x-relay-signature", sig)
            .header("x-relay-nonce", nonce_hex)
            .header("content-type", "application/octet-stream")
            .body(req)
            .send()
            .await;
        let r = match res {
            Ok(r) => r,
            Err(e) => {
                warn!(call = what, error = %e.without_url(), "push transport error");
                return;
            }
        };
        if !r.status().is_success() {
            warn!(call = what, status = %r.status(), "push request refused before opening");
            return;
        }
        let lane = kind.lane();
        let bytes = match r.bytes().await {
            Ok(b) if b.len() == lane.response_len() => b,
            Ok(_) => {
                warn!(call = what, "push answered with a non-lane size");
                return;
            }
            Err(e) => {
                warn!(call = what, error = %e.without_url(), "push response read error");
                return;
            }
        };
        match sealed::open_response(&response_key, &self.push_target_id, lane, &bytes) {
            Ok(o) if o.status == status::OK => debug!(call = what, "push ok"),
            Ok(o) => warn!(call = what, status = o.status, "push sealed status non-OK"),
            Err(e) => warn!(call = what, err = %e, "push response did not open"),
        }
    }
}

#[async_trait]
impl PushClient for ReqwestPushClient {
    async fn replicate(&self, rid: &RecipientId, hsig_pk: &[u8]) {
        // No rid, prefix or derived value in any log line, at any level
        // (scan F27/F36): with at most ~200 000 recipients an 8-hex prefix is
        // practically unique, and these lines fire per delivery — a log
        // anyone obtains later would record who received what, when. Only the
        // outcome is logged. F43: and none on the wire either — the rid
        // travels only inside the sealed request.
        let mut body = Zeroizing::new(Vec::with_capacity(rid.0.len() + hsig_pk.len()));
        body.extend_from_slice(&rid.0);
        body.extend_from_slice(hsig_pk);
        self.send_sealed(true, "/v2/directory/replicate", Kind::PushReplicate, &body, "replicate")
            .await;
    }

    async fn notify(&self, rid: &RecipientId) {
        self.send_sealed(false, "/v2/push/notify", Kind::PushNotify, &rid.0, "notify").await;
    }
}

// ============================================================================
// Recording mock (tests + dev mode)
// ============================================================================

/// In-memory recorder. Used by integration tests to assert that handlers
/// dispatch the expected push-relay calls. Also used as a stub in dev mode
/// when no `LADON_PUSH_RELAY_URL` is configured.
pub struct RecordingPushClient {
    pub replicate_calls: Mutex<Vec<(RecipientId, Vec<u8>)>>,
    pub notify_calls: Mutex<Vec<RecipientId>>,
}

impl RecordingPushClient {
    pub fn new() -> Self {
        Self {
            replicate_calls: Mutex::new(Vec::new()),
            notify_calls: Mutex::new(Vec::new()),
        }
    }

    pub fn replicate_snapshot(&self) -> Vec<(RecipientId, Vec<u8>)> {
        self.replicate_calls.lock().unwrap().clone()
    }

    pub fn notify_snapshot(&self) -> Vec<RecipientId> {
        self.notify_calls.lock().unwrap().clone()
    }
}

impl Default for RecordingPushClient {
    fn default() -> Self { Self::new() }
}

#[async_trait]
impl PushClient for RecordingPushClient {
    async fn replicate(&self, rid: &RecipientId, hsig_pk: &[u8]) {
        self.replicate_calls
            .lock()
            .unwrap()
            .push((*rid, hsig_pk.to_vec()));
    }
    async fn notify(&self, rid: &RecipientId) {
        self.notify_calls.lock().unwrap().push(*rid);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn recording_client_records_both() {
        let c = RecordingPushClient::new();
        let mut id = [0u8; 32]; id[0] = 7;
        let rid = RecipientId(id);
        c.replicate(&rid, &[0xAB; 1984]).await;
        c.notify(&rid).await;
        assert_eq!(c.replicate_snapshot().len(), 1);
        assert_eq!(c.notify_snapshot(), vec![rid]);
    }

    #[test]
    fn reqwest_client_strips_trailing_slash() {
        let c = ReqwestPushClient::new(
            "https://push.example.com/".to_string(),
            [0u8; 32],
            "exit1".to_string(),
            vec![0u8; ladon_relay_core_v2::constants::HKEM_PK_LEN],
            [0u8; 16],
        );
        assert_eq!(c.base_url, "https://push.example.com");
    }
}
