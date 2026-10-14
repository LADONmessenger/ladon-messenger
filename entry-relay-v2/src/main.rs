//! Entry-Relay v2 binary.
//!
//! Configuration via env vars (alternative to TOML for the Pilot):
//!   LADON_LISTEN              bind addr (default 127.0.0.1:8080)
//!   LADON_HOP_ID              hop label (default "entry-dev")
//!   LADON_S2S_HMAC_KEY_HEX    32-byte hex S2S key
//!   LADON_EXIT_<HEX_ID>=URL   one variable per known exit (HEX_ID = 32 hex chars)
//!   LADON_CANARY_FILE         canary path (default ./canary.json)
//!   LADON_PUSH_RELAY_URL      push relay base URL (optional)
//!   LADON_PUSH_TARGET_ID      32 hex chars: the push relay's sealed-request
//!                             target id (A2 stage 2, optional)

use std::collections::HashMap;

use entry_relay_v2::{router, EntryState, ExitRegistry};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let listen = std::env::var("LADON_LISTEN").unwrap_or_else(|_| "127.0.0.1:8080".into());
    let hop_id = std::env::var("LADON_HOP_ID").unwrap_or_else(|_| "entry-dev".into());
    let canary_path = std::env::var("LADON_CANARY_FILE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("./canary.json"));

    let s2s_hex = std::env::var("LADON_S2S_HMAC_KEY_HEX").unwrap_or_default();
    let s2s_key: [u8; 32] = if !s2s_hex.is_empty() {
        let v = hex::decode(&s2s_hex)?;
        if v.len() != 32 { return Err("S2S key must be 32 bytes".into()); }
        let mut a = [0u8; 32]; a.copy_from_slice(&v); a
    } else {
        // FIX F-RUST-ENTRY-001: fail-closed in production, dev-only fallback in debug.
        #[cfg(not(debug_assertions))]
        {
            panic!("LADON_S2S_HMAC_KEY_HEX not set — production fail-closed. Set this environment variable.");
        }
        #[cfg(debug_assertions)]
        {
            tracing::warn!("no LADON_S2S_HMAC_KEY_HEX — using zero key (dev only)");
            [0u8; 32]
        }
    };

    let mut exit_map: HashMap<String, String> = HashMap::new();
    for (k, v) in std::env::vars() {
        if let Some(rest) = k.strip_prefix("LADON_EXIT_") {
            // Expect 32-hex-char id. Lower-case it for the registry.
            let id = rest.to_ascii_lowercase();
            if id.len() == 32 && id.chars().all(|c| c.is_ascii_hexdigit()) {
                exit_map.insert(id, v);
            }
        }
    }
    if exit_map.is_empty() {
        tracing::warn!("no LADON_EXIT_<id> entries configured — entry has no upstream targets");
    }
    let registry = ExitRegistry::from_hex_map(&exit_map)
        .map_err(|e| format!("registry: {:?}", e))?;
    tracing::info!(exits = registry.len(), hop = %hop_id, "entry-relay-v2 starting");

    // FIX UPSTREAM-TIMEOUT-30S: 10s was too tight when the client reaches the
    // entry over Tor and the entry then forwards to a geographically distant
    // exit (e.g. ch1 -> pa1, ~180ms RTT + TLS). Realistic forward end-to-end
    // can spike to 5-15s under Tor congestion, producing spurious 502
    // (E-UPSTREAM) responses to the client. 30s aligns with Caddy's
    // read/write_timeout in front of the exits.
    //
    // FIX POOL-STALE-2026-05: Empirical 13% burst-failure rate ch1→pa1 with
    // bursts of 3-8 simultaneous 502s, all under 1s, traced to reqwest's
    // 90s default pool_idle_timeout keeping half-broken HTTP/2 connections
    // alive. Tighten pool reuse + add TCP keep-alive so dead connections are
    // dropped before they accept new requests.
    //   - pool_idle_timeout(20s): replace idle conns ~4× more often
    //   - tcp_keepalive(15s): detect half-closed sockets faster
    //   - connect_timeout(8s): hard ceiling for new TLS handshake
    let http = reqwest::Client::builder()
        .pool_max_idle_per_host(32)
        .pool_idle_timeout(std::time::Duration::from_secs(20))
        .tcp_keepalive(std::time::Duration::from_secs(15))
        .connect_timeout(std::time::Duration::from_secs(8))
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let push_relay_url = std::env::var("LADON_PUSH_RELAY_URL").ok().filter(|s| !s.is_empty());
    if push_relay_url.is_none() {
        tracing::warn!("LADON_PUSH_RELAY_URL not set \u{2014} /v2/proxy-push-register disabled");
    } else {
        tracing::info!(url = %push_relay_url.as_deref().unwrap_or(""), "push-relay proxy enabled");
    }

    // A2 stage 2: the push relay's target id. A malformed value is a
    // configuration error, not "push off".
    let push_target_id: Option<[u8; 16]> = match std::env::var("LADON_PUSH_TARGET_ID") {
        Ok(h) if !h.is_empty() => {
            let v = hex::decode(h.trim()).map_err(|_| "LADON_PUSH_TARGET_ID is not hex")?;
            let a: [u8; 16] = v.try_into().map_err(|_| "LADON_PUSH_TARGET_ID must be 16 bytes")?;
            if push_relay_url.is_none() {
                return Err("LADON_PUSH_TARGET_ID set without LADON_PUSH_RELAY_URL".into());
            }
            if registry.lookup(&ladon_relay_core_v2::ids::ExitId(a)).is_some() {
                return Err("LADON_PUSH_TARGET_ID equals a configured exit id".into());
            }
            tracing::info!(target_id = %hex::encode(a), "sealed push target configured");
            Some(a)
        }
        _ => {
            tracing::warn!("LADON_PUSH_TARGET_ID not set \u{2014} sealed push requests refused");
            None
        }
    };

    let rate_limiter = std::sync::Arc::new(ladon_relay_core_v2::ratelimit::RateLimiter::new());
    // FIX SRV-1: spawn periodic GC for the per-IP table (every 60 s).
    {
        let rl = rate_limiter.clone();
        tokio::spawn(async move {
            let mut t = tokio::time::interval(std::time::Duration::from_secs(60));
            t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                t.tick().await;
                rl.cleanup_expired();
            }
        });
    }

    let state = EntryState { hop_id, s2s_key, registry, http, canary_path, push_relay_url, push_target_id, rate_limiter }.arc();

    let app = router(state);
    let listener = tokio::net::TcpListener::bind(&listen).await?;
    tracing::info!(addr = %listen, "listening");
    axum::serve(listener, app).await?;
    Ok(())
}
