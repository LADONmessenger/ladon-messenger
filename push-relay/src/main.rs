//! Push-relay v2.1 binary entrypoint.
//!
//! Environment variables:
//!   * `LADON_PUSH_BIND`           — bind address (default `0.0.0.0:8083`).
//!   * `LADON_PUSH_HOP`            — hop id (default `push1`).
//!   * `LADON_EXIT_KEYS_FILE`      — required: path to JSON map
//!     `{hop_id: hex32}` of allowed exit-relay HMAC keys (B2.2). Replaces
//!     the previous single `LADON_PUSH_S2S_KEY`.
//!   * `LADON_APNS_KEY_ID`         — required for production APNs.
//!   * `LADON_APNS_TEAM_ID`        — required for production APNs.
//!   * `LADON_APNS_KEY_PATH`       — path to the .p8 PEM file. If unset
//!     AND `LADON_APNS_KEY_PEM` unset, the relay starts with a *stub*
//!     APNs sender that logs but never delivers (development mode).
//!   * `LADON_APNS_KEY_PEM`        — alternative: full PEM body inline.
//!   * `LADON_PUSH_HKEM_KEYFILE`   — HKEM key file for sealed requests
//!     (Addendum A2 stage 2). Required in release builds; debug builds
//!     generate an ephemeral key pair instead.
//!
//! The push-relay does not store any persistent state on disk (Spec G1).

use std::sync::Arc;

use async_trait::async_trait;
use ladon_relay_core_v2::{hash::exit_id_from_hkem_pk, hkem::HkemKeyPair};
use push_relay::{
    apns::{ApnsOutcome, ApnsSender, RealApnsSender},
    exit_keys::load_exit_keys,
    router, PushState, SealedIdentity,
};
use tracing::{info, warn};

struct StubApnsSender;

#[async_trait]
impl ApnsSender for StubApnsSender {
    async fn send_alert(&self, token: &str, sandbox: bool) -> ApnsOutcome {
        // No token or token prefix in the log (scan F7/F12 family).
        let _ = token;
        info!(sandbox, "stub APNs send (no delivery)");
        ApnsOutcome::Sent
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,push_relay=info")),
        )
        .json()
        .init();

    let bind = std::env::var("LADON_PUSH_BIND").unwrap_or_else(|_| "0.0.0.0:8083".into());
    let hop = std::env::var("LADON_PUSH_HOP").unwrap_or_else(|_| "push1".into());

    // B2.2 (2026-05-12): per-exit HMAC key map loaded from JSON file.
    // Fail-closed if unset/empty. Hardened loader (mode 0640, hex32 validate).
    let exit_keys_path = std::env::var("LADON_EXIT_KEYS_FILE")
        .map_err(|_| "LADON_EXIT_KEYS_FILE required (path to JSON map of per-exit keys)")?;
    if exit_keys_path.is_empty() {
        return Err("LADON_EXIT_KEYS_FILE is empty — fail-closed (B2.2)".into());
    }
    let exit_keys = load_exit_keys(std::path::Path::new(&exit_keys_path))?;
    info!(
        path = %exit_keys_path,
        entries = exit_keys.len(),
        "exit-keys map loaded"
    );
    let exit_keys = Arc::new(exit_keys);

    let apns: Arc<dyn ApnsSender> = match (
        std::env::var("LADON_APNS_KEY_ID").ok(),
        std::env::var("LADON_APNS_TEAM_ID").ok(),
        std::env::var("LADON_APNS_KEY_PATH").ok(),
        std::env::var("LADON_APNS_KEY_PEM").ok(),
    ) {
        (Some(kid), Some(team), Some(path), _) => {
            // P7-PUSH-02: refuse to load the APNs signing key if its file
            // mode is world- or group-readable. On Unix the .p8 is a long-
            // lived ES256 private key; a 0644 file under /etc would let any
            // local process forge JWTs against api.push.apple.com. Caller
            // must `chmod 600 path` (or 0400) before launch.
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                let md = std::fs::metadata(&path)?;
                let mode = md.mode() & 0o777;
                if mode & 0o077 != 0 {
                    return Err(format!(
                        "refusing to load APNs key {} with mode {:o} - require 0600/0400",
                        path, mode
                    ).into());
                }
            }
            let pem = std::fs::read_to_string(&path)?;
            Arc::new(RealApnsSender::from_p8_pem(&pem, kid, team)?)
        }
        (Some(kid), Some(team), None, Some(pem)) => {
            Arc::new(RealApnsSender::from_p8_pem(&pem, kid, team)?)
        }
        _ => {
            warn!("APNs credentials missing — running with stub sender (no real pushes)");
            Arc::new(StubApnsSender)
        }
    };

    let mut state = PushState::new(exit_keys, hop, apns);
    // P7-PUSH-04: legacy-S2S accept flag.
    // #28a: default fail-closed. All upstream exit-relays already sign the
    // tagged + nonce pre-image and production env sets this =false explicitly;
    // the migration window is closed, so a deploy omitting the var must not
    // silently re-open the legacy (length-unprefixed) S2S path.
    let accept_legacy = std::env::var("LADON_PUSH_S2S_ACCEPT_LEGACY")
        .map(|v| !matches!(v.trim().to_ascii_lowercase().as_str(), "0" | "false" | "no"))
        .unwrap_or(false);
    state.s2s_accept_legacy = accept_legacy;
    info!(s2s_accept_legacy = accept_legacy, "S2S legacy (no-nonce) accept policy");

    // P7-PUSH-08 / Addendum A1 §14 (F-2605-02): comma-separated allow-list
    // of hops permitted to call PUT /v2/directory/replicate. Mandatory:
    // without it any exit_keys-authenticated hop could overwrite any
    // recipient's hsig_pk in the replica and then re-register that
    // recipient's push token. No list, no start.
    let directory_owners = std::env::var("LADON_PUSH_DIRECTORY_OWNERS").ok();
    let directory_set: std::collections::HashSet<String> = directory_owners
        .as_deref()
        .map(|raw| {
            raw.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();
    if directory_set.is_empty() {
        return Err("LADON_PUSH_DIRECTORY_OWNERS is unset or empty — fail-closed (A1 §14)".into());
    }
    info!(count = directory_set.len(), "directory-owner allow-list configured");
    state.directory_owner_hops = directory_set;

    // A2 stage 2: the HKEM key that sealed PUSH_REGISTER requests are
    // addressed to. Fail-closed in release, like the exit's key.
    let hkem_keys: HkemKeyPair = match std::env::var("LADON_PUSH_HKEM_KEYFILE") {
        Ok(p) if !p.is_empty() => {
            let path = std::path::PathBuf::from(&p);
            let kp = ladon_relay_core_v2::hkem::load_keyfile(&path)?;
            info!(keyfile = %path.display(), "HKEM keypair loaded from disk");
            kp
        }
        _ => {
            #[cfg(not(debug_assertions))]
            {
                return Err("LADON_PUSH_HKEM_KEYFILE is unset or empty — fail-closed (A2 stage 2)".into());
            }
            #[cfg(debug_assertions)]
            {
                warn!("no LADON_PUSH_HKEM_KEYFILE — generating ephemeral HKEM keypair (dev only)");
                HkemKeyPair::generate()
            }
        }
    };
    let target_id = *exit_id_from_hkem_pk(&hkem_keys.public_key_bytes()).as_bytes();
    info!(target_id = %hex::encode(target_id), "sealed-request target id");
    state.sealed = Some(SealedIdentity { keys: hkem_keys, target_id });
    let state = Arc::new(state);
    let app = router(state);

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    info!(addr = %bind, "push-relay v2.1 listening");
    // F9: no route keys on the peer address any more (the sealed route lost
    // its per-IP limit); the connect info stays available to handlers.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}
