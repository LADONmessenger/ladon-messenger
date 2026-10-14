//! Shared application state for axum handlers.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ladon_relay_core_v2::bloom::ReplayWindow;
use ladon_relay_core_v2::hkem::HkemKeyPair;
use ladon_relay_core_v2::ids::ExitId;
use ladon_relay_core_v2::store::{MailboxStore, RecipientDirectory};

use crate::push_client::PushClient;

pub struct ExitState {
    pub exit_id: ExitId,
    pub hkem_keys: HkemKeyPair,
    pub directory: RecipientDirectory,
    pub mailbox: MailboxStore,
    /// Envelope-id replay filter (Addendum A1 §8).
    pub replay: Mutex<ReplayWindow>,
    /// B2.2 (2026-05-12): Per-entry HMAC key map for inbound S2S verify.
    /// Lookup by `X-Relay-Hop` header. Loaded at startup from
    /// `LADON_ENTRY_KEYS_FILE`; immutable thereafter.
    pub entry_keys: Arc<HashMap<String, [u8; 32]>>,
    pub s2s_skew_sec: u64,
    pub fetch_skew_sec: u64,
    pub canary_path: std::path::PathBuf,
    /// Optional outbound push-relay client (Phase 3b). When `None`, push
    /// integration is disabled — handlers operate exactly as before.
    /// Configured via `LADON_PUSH_RELAY_URL` + `LADON_PUSH_S2S_KEY` in `main`.
    pub push: Option<Arc<dyn PushClient>>,
    /// P7-EXIT-03: per-hop nonce store for S2S anti-replay. Active when
    /// the inbound forward carries an `X-Relay-Nonce` header.
    pub s2s_nonce_store: crate::s2s::S2sNonceStore,
    /// Replay guard for `GET /v2/fetch`. The fetch signature carries no
    /// nonce and stays valid for the whole skew window, while the fetch
    /// itself drains the mailbox — see `verify::FetchReplayStore`.
    pub fetch_replay: crate::verify::FetchReplayStore,
    /// P7-EXIT-03: when true, accept legacy (no-nonce) S2S signatures.
    /// Default true for the migration window. Flip to false via
    /// `LADON_S2S_ACCEPT_LEGACY=false` once all entries ship the nonce.
    pub s2s_accept_legacy: bool,
    /// P7-EXIT-06: per-recipient sliding-window limiter applied inside
    /// `forward_inner` after the delivery key matched (Addendum A1 §8 step 8).
    /// Prevents one recipient from monopolising the bounded mailbox
    /// queue when behind shared NAT/CGNAT.
    pub forward_recipient_limiter: std::sync::Arc<ladon_relay_core_v2::ratelimit::IdentityRateLimiter>,
    /// P7-RELAY-13: bounds the number of in-flight `push.notify` spawns.
    /// `forward` uses `try_acquire_owned` so when the cap is reached the
    /// notify is dropped (push is best-effort) rather than spawning
    /// unbounded tasks that could fork-bomb the outbound HTTP/2 pool.
    pub push_notify_sema: Arc<tokio::sync::Semaphore>,
    /// A2 §7: last authenticated fetch per recipient (push decision).
    pub online: Arc<crate::online::OnlineTracker>,
    /// F44: one notify per recipient per `PUSH_DEBOUNCE_SEC`.
    pub notify_debounce: Arc<crate::online::NotifyDebounce>,
    /// A2 §8 [D]: verify cap and per-recipient limits of `/v2/sealed`.
    pub sealed_limits: crate::sealed::SealedLimits,
}

impl ExitState {
    pub fn arc(self) -> Arc<Self> {
        Arc::new(self)
    }
}
