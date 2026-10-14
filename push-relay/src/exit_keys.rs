//! Per-exit HMAC key map (B2.2, 2026-05-12).
//!
//! Push-relay verifies inbound `PUT /v2/directory/replicate` and
//! `POST /v2/push/notify` requests by looking up the sender's hop id
//! (`X-Relay-Hop`) in this map. Each exit-relay has a distinct 32-byte
//! HMAC key. The map is loaded ONCE at startup from a JSON file
//! (`LADON_EXIT_KEYS_FILE`); immutable thereafter.
//!
//! File format:
//! ```json
//! { "is1": "<64 hex>", "is2": "<64 hex>", "pa1": "<64 hex>" }
//! ```
//!
//! File MUST be mode 0640 or stricter on Unix.
//!
//! Unknown-hop lookups return the same `S2sAuth` error as wrong-signature
//! — no existence oracle.

use std::collections::HashMap;
use std::path::Path;

#[derive(Debug)]
pub enum ExitKeysError {
    Io(String),
    Json(String),
    Mode(String),
    InvalidKey(String),
    Empty,
}

impl std::fmt::Display for ExitKeysError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(s) => write!(f, "I/O error reading exit-keys file: {s}"),
            Self::Json(s) => write!(f, "JSON parse error in exit-keys file: {s}"),
            Self::Mode(s) => write!(f, "exit-keys file has unsafe permissions: {s}"),
            Self::InvalidKey(s) => write!(f, "invalid key in exit-keys file: {s}"),
            Self::Empty => write!(f, "exit-keys file contains no entries"),
        }
    }
}
impl std::error::Error for ExitKeysError {}

/// Load and validate the exit-keys JSON map.
///
/// Same hardening as `entry-keys` loader in the exit-relay:
/// * Rejects mode bits `0o007` (world) and `0o020` (group-write).
/// * Rejects empty maps, non-hex values, and non-32-byte keys.
/// * Hop ids are bounded to 32 ASCII chars.
pub fn load_exit_keys(path: &Path) -> Result<HashMap<String, [u8; 32]>, ExitKeysError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let md = std::fs::metadata(path)
            .map_err(|e| ExitKeysError::Io(format!("{}: {e}", path.display())))?;
        let mode = md.mode() & 0o777;
        if mode & 0o007 != 0 || mode & 0o020 != 0 {
            return Err(ExitKeysError::Mode(format!(
                "{}: mode {:o} permits world or group-write access",
                path.display(),
                mode
            )));
        }
    }

    let bytes = std::fs::read(path)
        .map_err(|e| ExitKeysError::Io(format!("{}: {e}", path.display())))?;
    let raw: HashMap<String, String> =
        serde_json::from_slice(&bytes).map_err(|e| ExitKeysError::Json(e.to_string()))?;
    if raw.is_empty() {
        return Err(ExitKeysError::Empty);
    }

    let mut out: HashMap<String, [u8; 32]> = HashMap::with_capacity(raw.len());
    for (hop, hex_val) in raw {
        if hop.is_empty() || hop.len() > 32 || !hop.chars().all(|c| c.is_ascii_graphic()) {
            return Err(ExitKeysError::InvalidKey(format!("invalid hop id: {hop:?}")));
        }
        let dec = hex::decode(&hex_val)
            .map_err(|e| ExitKeysError::InvalidKey(format!("hop {hop}: hex decode: {e}")))?;
        if dec.len() != 32 {
            return Err(ExitKeysError::InvalidKey(format!(
                "hop {hop}: key must be 32 bytes, got {}",
                dec.len()
            )));
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(&dec);
        out.insert(hop, k);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tmpdir() -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        let n: u64 = rand::random();
        p.push(format!("ladon-exit-keys-{n:016x}"));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn write_mode(path: &Path, body: &[u8], mode: u32) {
        let mut f = std::fs::File::create(path).unwrap();
        f.write_all(body).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        let _ = mode;
    }

    #[test]
    fn loads_valid_map() {
        let d = tmpdir();
        let p = d.join("k.json");
        let body = br#"{"is1":"ead197038146d9625fcef597330cb15e8c6a54c64ff82ac1be0cf21b380930f7","is2":"711a49fd313c116908fb8c90287e9cce7e0795015b05096a20181eb223831025"}"#;
        write_mode(&p, body, 0o640);
        let m = load_exit_keys(&p).unwrap();
        assert_eq!(m.len(), 2);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_world_readable() {
        let d = tmpdir();
        let p = d.join("k.json");
        let body = br#"{"is1":"ead197038146d9625fcef597330cb15e8c6a54c64ff82ac1be0cf21b380930f7"}"#;
        write_mode(&p, body, 0o644);
        let e = load_exit_keys(&p).unwrap_err();
        assert!(matches!(e, ExitKeysError::Mode(_)), "got {e:?}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn rejects_empty_map() {
        let d = tmpdir();
        let p = d.join("k.json");
        write_mode(&p, b"{}", 0o640);
        let e = load_exit_keys(&p).unwrap_err();
        assert!(matches!(e, ExitKeysError::Empty), "got {e:?}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn rejects_short_key() {
        let d = tmpdir();
        let p = d.join("k.json");
        write_mode(&p, br#"{"is1":"abcd"}"#, 0o640);
        let e = load_exit_keys(&p).unwrap_err();
        assert!(matches!(e, ExitKeysError::InvalidKey(_)), "got {e:?}");
        let _ = std::fs::remove_dir_all(&d);
    }
}
