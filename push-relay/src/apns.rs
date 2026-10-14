//! APNs HTTP/2 push sender.
//!
//! Models the push-relay's outbound side. We isolate the actual HTTP/2 +
//! ES256 JWT path behind the `ApnsSender` trait so integration tests can
//! substitute a mock that records calls without hitting Apple's
//! `api.push.apple.com`. Production uses `RealApnsSender`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use once_cell::sync::Lazy;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::DecodePrivateKey;
use tracing::{debug, error, warn};

/// Outcome of a push delivery attempt. The push-relay treats every variant
/// as terminal for the current notify request — APNs handles its own
/// retries via the device's connection state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApnsOutcome {
    /// 2xx from APNs (or mock success).
    Sent,
    /// APNs returned a hard error (4xx). The token may be invalid.
    Rejected(u16),
    /// Network / TLS / serialization error before APNs responded.
    TransportError(String),
}

/// Trait for sending APNs alert pushes. Trait-object friendly so the
/// implementation can be swapped at runtime (real vs. mock).
#[async_trait]
pub trait ApnsSender: Send + Sync {
    /// Send an alert push to a single device. The push-relay never sends
    /// per-message content (Spec §4.9 / privacy goal SG-Notify-1) — the
    /// payload is a constant "New Message" alert.
    async fn send_alert(&self, device_token_hex: &str, sandbox: bool) -> ApnsOutcome;
}

// ----------------------------------------------------------------------------
// Real APNs sender (HTTP/2 + ES256 JWT)
// ----------------------------------------------------------------------------

/// Apple's bundle id; sent as the `apns-topic` header. Public identifier,
/// not a secret.
pub const APNS_BUNDLE_ID: &str = "app.ladon.messenger";

/// JWT TTL: regenerate every 50 minutes (APNs allows up to 60 min).
const JWT_TTL_SECS: u64 = 50 * 60;

/// P8-PUSH-NSE-REMOVE (2026-05-21): alert push, minimal payload, no NSE.
///
/// Iteration history for context:
///
/// * PUSH-03 (silent-only `content-available:1`):
///   reliable on the first attempt, then aggressively throttled by iOS
///   in low-power / background-app-refresh-restricted state. Apple's
///   "best-effort" silent class is incompatible with messenger-grade
///   real-time delivery. Dropped.
///
/// * PUSH-NSE-01 Phase 1+2 (alert + mutable-content + Notification
///   Service Extension on the iOS side):
///   reliable delivery. NSE scaffolded as pass-through (no crypto, no
///   keychain reads in code) and provisioned with shared App-Group +
///   shared Keychain-Access-Group entitlements in case a future Phase 3
///   wanted sender-personalisation. But Phase 3 would have leaked an
///   8-hex sender fingerprint onto the lockscreen, contradicting the
///   "nothing readable" privacy commitment. Phase 3 is now permanently
///   out of scope, which makes the NSE attack surface (a second process
///   with shared-keychain entitlements) pure dead weight. NSE removed.
///
/// * PUSH-NSE-REMOVE (this commit):
///   keep alert + priority 10 for guaranteed real-time delivery. Drop
///   `mutable-content: 1` because there is no NSE left to wake. Keep
///   sound + badge as pure on-device UX hints — they do not change the
///   bytes-on-the-wire pattern and Apple's APNs already knew the device
///   was an iOS endpoint that supports sound/badge.
///
/// Payload after this iteration is BYTE-IDENTICAL for every Ladon push,
/// regardless of sender, recipient, or message content. Apple's APNs
/// server cannot infer per-message data from the payload alone — only
/// timing + recipient device-token remain (unavoidable for any APNs-based
/// messenger including Signal/Wire). Banner stays generic with no
/// per-message variation: the alert carries only `loc-key`, which iOS
/// resolves on the device from the app's Localizable.strings
/// ("New encrypted message" / "Neue verschlüsselte Nachricht"), so the
/// device language applies and no text is fixed here (01.10.2026; was a
/// hard-coded German title + body).
///
/// P8-AUDIT5-PUSH-WAKE (2026-05-22): added `content-available: 1`.
///
/// Symptom: with a pure alert push (no content-available), iOS shows the
/// banner but does NOT wake the suspended app to fetch. The user only got
/// the actual message after manually opening the app, at which point Tor
/// had to rebuild a circuit (~5-15s) before the fetch could run — the
/// "messages arrive only after I open the app, and fetching takes long"
/// complaint.
///
/// With `content-available: 1` alongside the alert, iOS delivers the
/// banner AND wakes the app in the background via
/// application(_:didReceiveRemoteNotification:fetchCompletionHandler:)
/// (SilentPushHandler.handleSilentPush, which already accepts
/// `content-available == 1 || hasAlert`). The app fetches over Tor while
/// backgrounded, so the message is present the moment the user taps in.
///
/// NOTE the earlier lesson (PUSH-NSE-01) was specifically about the
/// HYBRID alert + mutable-content + content-available being throttled on
/// iOS 18+. mutable-content is gone now; alert + content-available (no
/// mutable-content) is the standard Signal/WhatsApp shape and is NOT
/// subject to that throttle. apns-push-type stays `alert` + priority 10
/// so the banner delivery remains guaranteed; the background wake is a
/// best-effort bonus on top.
///
/// Privacy unchanged: payload is still byte-identical for every push.
const ALERT_PAYLOAD: &str = r#"{"aps":{"alert":{"loc-key":"PUSH_NEW_ENCRYPTED_MESSAGE"},"sound":"default","badge":1,"content-available":1}}"#;

/// Cached HTTP/2 client; created once per process (HTTP/2 multiplexing).
static APNS_CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
    reqwest::Client::builder()
        .http2_prior_knowledge()
        .pool_idle_timeout(Duration::from_secs(300))
        .build()
        .expect("build reqwest http2 client")
});

/// Production APNs sender. Holds the ES256 signing key + key id + team id;
/// caches the JWT and reuses the HTTP/2 client.
pub struct RealApnsSender {
    signing_key: SigningKey,
    key_id: String,
    team_id: String,
    jwt_cache: Mutex<(String, u64)>,
    /// Optional override for `api.push.apple.com` / `api.sandbox.push.apple.com`.
    /// Used by integration tests that point at a local mock; `None` in
    /// production.
    endpoint_override: Option<String>,
    /// Successful sends counter (for `/v2/health` diagnostics).
    pub sent: AtomicU64,
    pub failed: AtomicU64,
}

impl RealApnsSender {
    /// Construct from a parsed PKCS#8 DER key body (the binary payload of
    /// the `.p8` file with the BEGIN/END lines stripped + base64-decoded).
    pub fn from_pkcs8_der(
        der: &[u8],
        key_id: String,
        team_id: String,
    ) -> Result<Self, &'static str> {
        // P7-PUSH-07: the JWT header/claims are built via format!(),
        // which would interpolate raw bytes of key_id / team_id into the
        // JSON payload. If either is contaminated (e.g. parsed from a
        // misconfigured env-var that contains a quote or a backslash),
        // the resulting JWT becomes malformed JSON and at worst smuggles
        // attacker-controlled claims into the APNs auth header. Apple
        // documents both as alphanumeric (key_id is 10 chars, team_id is
        // 10 chars, both case-insensitive A-Z0-9), so we enforce that
        // narrow shape at construction time.
        fn valid_apple_id(s: &str) -> bool {
            !s.is_empty()
                && s.len() <= 32
                && s.chars().all(|c| c.is_ascii_alphanumeric())
        }
        if !valid_apple_id(&key_id) {
            return Err("invalid APNs key_id (must be A-Z0-9, <= 32 chars)");
        }
        if !valid_apple_id(&team_id) {
            return Err("invalid APNs team_id (must be A-Z0-9, <= 32 chars)");
        }
        let signing_key =
            SigningKey::from_pkcs8_der(der).map_err(|_| "invalid PKCS#8 ES256 key")?;
        Ok(Self {
            signing_key,
            key_id,
            team_id,
            jwt_cache: Mutex::new((String::new(), 0)),
            endpoint_override: None,
            sent: AtomicU64::new(0),
            failed: AtomicU64::new(0),
        })
    }

    /// Convenience constructor: parse the standard `.p8` PEM (BEGIN PRIVATE
    /// KEY ... END PRIVATE KEY) format.
    pub fn from_p8_pem(
        pem: &str,
        key_id: String,
        team_id: String,
    ) -> Result<Self, &'static str> {
        let body: String = pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect::<Vec<&str>>()
            .join("");
        let der = base64::engine::general_purpose::STANDARD
            .decode(body.as_bytes())
            .map_err(|_| "invalid base64 in .p8")?;
        Self::from_pkcs8_der(&der, key_id, team_id)
    }

    /// Test/diagnostic: redirect APNs requests to a custom base URL (e.g.
    /// `http://127.0.0.1:PORT`). The `:PORT/3/device/<token>` path layout
    /// is preserved so tests can mount their own handler.
    pub fn with_endpoint_override(mut self, base: String) -> Self {
        self.endpoint_override = Some(base);
        self
    }

    fn current_jwt(&self) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // P7-PUSH-11: keep the lock-hold time to a cache-hit clone (most
        // paths) so we don't block the tokio runtime worker on JWT
        // generation. Cache-miss path computes the JWT WITHOUT holding the
        // lock, then re-acquires briefly to publish. Defensive
        // `unwrap_or_else(|e| e.into_inner())` consistent with the rest of
        // the codebase: a previous-holder panic shouldn't kill the relay.
        {
            let cache = self.jwt_cache.lock().unwrap_or_else(|e| e.into_inner());
            if !cache.0.is_empty() && now.saturating_sub(cache.1) < JWT_TTL_SECS {
                return cache.0.clone();
            }
        }
        // Cache miss: compute JWT outside the lock (~100 us for ES256 sign +
        // base64).
        let header = format!(r#"{{"alg":"ES256","kid":"{}"}}"#, self.key_id);
        let claims = format!(r#"{{"iss":"{}","iat":{}}}"#, self.team_id, now);
        let h_b64 = URL_SAFE_NO_PAD.encode(header.as_bytes());
        let c_b64 = URL_SAFE_NO_PAD.encode(claims.as_bytes());
        let signing_input = format!("{}.{}", h_b64, c_b64);
        let sig: Signature = self.signing_key.sign(signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        let jwt = format!("{}.{}", signing_input, sig_b64);
        // Publish (double-checked: a concurrent caller may have raced us;
        // either value is valid - we keep whichever was published last).
        {
            let mut cache = self.jwt_cache.lock().unwrap_or_else(|e| e.into_inner());
            *cache = (jwt.clone(), now);
        }
        jwt
    }
}

#[async_trait]
impl ApnsSender for RealApnsSender {
    async fn send_alert(&self, device_token_hex: &str, sandbox: bool) -> ApnsOutcome {
        if !is_valid_device_token(device_token_hex) {
            warn!("invalid device token format");
            self.failed.fetch_add(1, Ordering::Relaxed);
            return ApnsOutcome::Rejected(400);
        }
        let base = self.endpoint_override.clone().unwrap_or_else(|| {
            if sandbox {
                "https://api.sandbox.push.apple.com:443".to_string()
            } else {
                "https://api.push.apple.com:443".to_string()
            }
        });
        let url = format!("{}/3/device/{}", base, device_token_hex);
        let jwt = self.current_jwt();
        // P7-PUSH-12: per-Apple recommendations, set apns-id (a request-
        // unique UUID for log correlation if Apple's side rejects) and
        // apns-expiration: 0 so APNs discards the notification rather
        // than queueing it when the device is offline. The notification
        // content is the same every time ("Message"/"New Message"), so
        // queueing stale copies would never deliver new information.
        // P7-PUSH-12: opaque per-request apns-id (Apple just wants any
        // unique 36-char identifier; format follows RFC 4122 UUID v4
        // shape so Apple's logs render it nicely). Source from a fresh
        // OS-RNG read.
        // P7-PUSH-12: opaque per-request apns-id (Apple needs a unique
        // identifier for log correlation; it does NOT need to be
        // cryptographically random). Composed from epoch-ns + a per-
        // process atomic counter so collisions need both a clock-jump and
        // a counter wrap (~2^64 sends).
        let apns_id = {
            static APNS_ID_CTR: AtomicU64 = AtomicU64::new(0);
            let ctr = APNS_ID_CTR.fetch_add(1, Ordering::Relaxed);
            let now_ns = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
            // RFC 4122-shaped formatting (Apple just expects 36-char id).
            format!(
                "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
                (now_ns >> 32) as u32,
                ((now_ns >> 16) & 0xffff) as u16,
                (now_ns & 0xffff) as u16,
                ((ctr >> 48) & 0xffff) as u16,
                ctr & 0xffff_ffff_ffff,
            )
        };
        let resp = APNS_CLIENT
            .post(&url)
            .header("authorization", format!("bearer {}", jwt))
            .header("apns-topic", APNS_BUNDLE_ID)
            // P8-PUSH-NSE-01 (2026-05-21): alert push-type with priority 10
            // for real-time delivery. PUSH-03's `background` + priority 5
            // path was throttled by iOS (best-effort silent), so we swap
            // to `alert` (guaranteed delivery) and rely on the NSE to keep
            // banner content privacy-preserving. priority 10 is what Apple
            // requires for `alert`-class pushes that should bypass
            // background-refresh budget gating.
            .header("apns-push-type", "alert")
            .header("apns-priority", "10")
            .header("apns-id", apns_id)
            .header("apns-expiration", "0")
            .body(ALERT_PAYLOAD)
            .send()
            .await;
        match resp {
            Ok(r) => {
                let status = r.status().as_u16();
                let body = r.text().await.unwrap_or_default();
                if (200..300).contains(&status) {
                    debug!(status, %body, "APNs success");
                    self.sent.fetch_add(1, Ordering::Relaxed);
                    ApnsOutcome::Sent
                } else {
                    warn!(status, %body, "APNs rejected");
                    self.failed.fetch_add(1, Ordering::Relaxed);
                    ApnsOutcome::Rejected(status)
                }
            }
            Err(e) => {
                // reqwest's error text carries the request URL, which for
                // APNs is /3/device/<device token> — drop it before the error
                // reaches the journal or the outcome string logged by the
                // notify handler.
                let e = e.without_url();
                error!(error = %e, "APNs transport error");
                self.failed.fetch_add(1, Ordering::Relaxed);
                ApnsOutcome::TransportError(e.to_string())
            }
        }
    }
}

/// Validate APNs device token format: 64 hex chars (= 32 bytes). Mirrors
/// V1's `is_valid_device_token` (`exit-relay/src/main.rs` L869).
pub fn is_valid_device_token(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

// ----------------------------------------------------------------------------
// Test sender (records calls; never hits the network)
// ----------------------------------------------------------------------------

/// A mock APNs sender that records every `send_alert` call into a Mutex'd
/// vector. Used by integration tests to assert that the push-relay called
/// APNs with the expected token + sandbox flag.
pub struct RecordingApnsSender {
    pub calls: Mutex<Vec<(String, bool)>>,
    /// If `Some(s)`, every call returns the given outcome; otherwise `Sent`.
    pub fixed_outcome: Option<ApnsOutcome>,
}

impl RecordingApnsSender {
    pub fn new() -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            fixed_outcome: None,
        }
    }

    pub fn with_outcome(outcome: ApnsOutcome) -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            fixed_outcome: Some(outcome),
        }
    }

    pub fn snapshot(&self) -> Vec<(String, bool)> {
        self.calls.lock().unwrap().clone()
    }
}

impl Default for RecordingApnsSender {
    fn default() -> Self { Self::new() }
}

#[async_trait]
impl ApnsSender for RecordingApnsSender {
    async fn send_alert(&self, device_token_hex: &str, sandbox: bool) -> ApnsOutcome {
        self.calls
            .lock()
            .unwrap()
            .push((device_token_hex.to_string(), sandbox));
        self.fixed_outcome.clone().unwrap_or(ApnsOutcome::Sent)
    }
}

#[cfg(test)]
mod tests {

    /// The alert carries only a localisation key: no title, no body text,
    /// nothing per message. The key must match the app's Localizable.strings.
    #[test]
    fn alert_payload_is_key_only_and_constant() {
        let v: serde_json::Value = serde_json::from_str(ALERT_PAYLOAD).unwrap();
        let alert = v["aps"]["alert"].as_object().unwrap();
        assert_eq!(alert.len(), 1, "alert must hold only loc-key");
        assert_eq!(alert["loc-key"], "PUSH_NEW_ENCRYPTED_MESSAGE");
        assert_eq!(v["aps"]["content-available"], 1);
        assert_eq!(v["aps"]["sound"], "default");
        assert_eq!(v["aps"]["badge"], 1);
    }

    use super::*;

    #[tokio::test]
    async fn recording_sender_records_calls() {
        let s = RecordingApnsSender::new();
        let outcome = s.send_alert(&"a".repeat(64), true).await;
        assert_eq!(outcome, ApnsOutcome::Sent);
        let calls = s.snapshot();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "a".repeat(64));
        assert!(calls[0].1);
    }

    #[test]
    fn token_validator_accepts_64_hex() {
        assert!(is_valid_device_token(&"0".repeat(64)));
        assert!(is_valid_device_token("ABcdef0123456789".repeat(4).as_str()));
    }

    #[test]
    fn token_validator_rejects_wrong_len_and_non_hex() {
        assert!(!is_valid_device_token(&"a".repeat(63)));
        assert!(!is_valid_device_token(&"a".repeat(65)));
        assert!(!is_valid_device_token(&"g".repeat(64)));
        assert!(!is_valid_device_token(""));
    }
}
