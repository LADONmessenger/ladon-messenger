use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize)]
pub struct EntryConfig {
    pub listen: String,
    pub hop_id: String,
    /// Hex-encoded 32-byte S2S HMAC key shared with all configured exits.
    /// (Per-exit keys may be added later; the Pilot uses a single shared key.)
    pub s2s_hmac_key_hex: String,
    /// Map: hex(exit_id, 16 B → 32 hex chars) → base URL ("https://exit.ch1.ladon.app").
    pub exits: HashMap<String, String>,
    pub canary_file: PathBuf,
}
