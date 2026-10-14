//! Service configuration parsed from environment variables, fail-closed.
//!
//! Mirrors the fail-closed convention used in `exit-relay/src/main.rs:38` —
//! critical secrets must be present and correctly sized at startup, otherwise
//! the process exits instead of running in a degraded mode.

use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("{0} must be set")]
    MissingVar(&'static str),
    #[error("{var} must be at least {min} bytes (got {got})")]
    TooShort {
        var: &'static str,
        min: usize,
        got: usize,
    },
    #[error("{0} could not be parsed: {1}")]
    BadValue(&'static str, String),
}

/// Resolved, validated configuration.
#[derive(Clone, Debug)]
pub struct Config {
    /// Per-process secret distinct from `LADON_RELAY_SECRET`. Used when a
    /// second hop is inserted in front of blob-relay; reserved in v1.
    pub blob_relay_secret: String,
    /// Master key for the on-disk meta-file AES-GCM wrapper.
    /// 32 bytes exactly (hex-encoded in env).
    pub master_key: [u8; 32],
    /// Directory holding `data/`, `logs/`, `secrets.key`.
    pub data_dir: PathBuf,
    /// Ed25519 signing key path (created on first boot if missing).
    pub signing_key_path: PathBuf,
    /// Where the per-identity upload secrets used to be stored. Retired with
    /// the upload identity (Addendum A2 stage 1): the file listed every
    /// uploader's long-term key, so `main` overwrites and removes it at start.
    pub retired_auth_secrets_path: PathBuf,
    /// TCP bind address.
    pub bind_addr: String,
    /// Maximum bytes retained on disk before 507 is returned on init.
    pub disk_quota_bytes: u64,
    /// If set at startup, the service shreds `data/` before binding.
    pub panic_wipe: bool,
}

impl Config {
    /// Build from `std::env`, with fail-closed validation.
    pub fn from_env() -> Result<Self, ConfigError> {
        let blob_relay_secret = require_min_len("LADON_BLOB_RELAY_SECRET", 32)?;

        let master_key_hex = std::env::var("LADON_BLOB_MASTER_KEY")
            .map_err(|_| ConfigError::MissingVar("LADON_BLOB_MASTER_KEY"))?;
        let master_key_bytes = hex::decode(master_key_hex.trim())
            .map_err(|e| ConfigError::BadValue("LADON_BLOB_MASTER_KEY", e.to_string()))?;
        if master_key_bytes.len() != 32 {
            return Err(ConfigError::TooShort {
                var: "LADON_BLOB_MASTER_KEY",
                min: 32,
                got: master_key_bytes.len(),
            });
        }
        let mut master_key = [0u8; 32];
        master_key.copy_from_slice(&master_key_bytes);

        let data_dir: PathBuf = std::env::var("LADON_BLOB_DATA_DIR")
            .unwrap_or_else(|_| "/opt/ladon-blob/data".to_string())
            .into();
        let signing_key_path: PathBuf = std::env::var("LADON_BLOB_SIGNING_KEY_PATH")
            .unwrap_or_else(|_| "/opt/ladon-blob/secrets.key".to_string())
            .into();
        let retired_auth_secrets_path: PathBuf = std::env::var("LADON_BLOB_AUTH_SECRETS_PATH")
            .unwrap_or_else(|_| "/opt/ladon-blob/auth-secrets.bin".to_string())
            .into();

        let bind_addr = std::env::var("LADON_BLOB_BIND_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:8090".to_string());

        let disk_quota_bytes = parse_u64_env("LADON_BLOB_DISK_QUOTA_BYTES", 32 * 1024 * 1024 * 1024)?;
        let panic_wipe = std::env::var("LADON_BLOB_PANIC")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        Ok(Self {
            blob_relay_secret,
            master_key,
            data_dir,
            signing_key_path,
            retired_auth_secrets_path,
            bind_addr,
            disk_quota_bytes,
            panic_wipe,
        })
    }

    /// Test-only config backed by a temp directory. Not exposed via env.
    pub fn for_tests(data_dir: PathBuf) -> Self {
        let mut mk = [0u8; 32];
        mk.copy_from_slice(&[
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
            0x0d, 0x0e, 0x0f, 0x10,
        ]);
        Self {
            blob_relay_secret: "x".repeat(32),
            master_key: mk,
            signing_key_path: data_dir.join("signing.key"),
            retired_auth_secrets_path: data_dir.join("auth-secrets.bin"),
            data_dir: data_dir.join("data"),
            bind_addr: "127.0.0.1:0".to_string(),
            disk_quota_bytes: 32 * 1024 * 1024 * 1024,
            panic_wipe: false,
        }
    }
}

fn require_min_len(var: &'static str, min: usize) -> Result<String, ConfigError> {
    let v = std::env::var(var).map_err(|_| ConfigError::MissingVar(var))?;
    if v.len() < min {
        return Err(ConfigError::TooShort {
            var,
            min,
            got: v.len(),
        });
    }
    Ok(v)
}

fn parse_u64_env(var: &'static str, default: u64) -> Result<u64, ConfigError> {
    match std::env::var(var) {
        Ok(v) => v.parse().map_err(|e: std::num::ParseIntError| ConfigError::BadValue(var, e.to_string())),
        Err(_) => Ok(default),
    }
}
