//! Per-entry HMAC key map (B2.2, 2026-05-12).
//!
//! Exit-relay verifies inbound `POST /v2/forward` requests by looking up
//! the sender's hop id (`X-Relay-Hop`) in this map. Each entry has a
//! distinct 32-byte HMAC key. The map is loaded ONCE at startup from a
//! JSON file (`LADON_ENTRY_KEYS_FILE`) and is immutable thereafter; no
//! hot-reload, no signal-based refresh.
//!
//! File format (strict JSON, exactly):
//! ```json
//! {
//!   "ch1": "<64 hex>",
//!   "fi1": "<64 hex>"
//! }
//! ```
//!
//! File MUST be mode 0640 or stricter (no world bits) on Unix.
//!
//! On lookup failure (unknown hop), the verify path returns `ApiError::S2sAuth`
//! — identical to the wrong-signature path — so an unknown hop does not act
//! as an existence oracle.

use std::collections::HashMap;
use std::path::Path;

#[derive(Debug)]
pub enum EntryKeysError {
    Io(String),
    Json(String),
    Mode(String),
    InvalidKey(String),
    Empty,
}

impl std::fmt::Display for EntryKeysError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(s) => write!(f, "I/O error reading entry-keys file: {s}"),
            Self::Json(s) => write!(f, "JSON parse error in entry-keys file: {s}"),
            Self::Mode(s) => write!(f, "entry-keys file has unsafe permissions: {s}"),
            Self::InvalidKey(s) => write!(f, "invalid key in entry-keys file: {s}"),
            Self::Empty => write!(f, "entry-keys file contains no entries"),
        }
    }
}
impl std::error::Error for EntryKeysError {}

/// Load and validate the entry-keys JSON map.
///
/// * Rejects world-readable or world-writable files (mode bits `0o007` set).
/// * Rejects group-writable files (mode bit `0o020` set). Group-readable is OK
///   so the `ladon` service group can read the file installed by ansible.
/// * Rejects empty maps, non-hex values, and values that aren't 32 bytes.
/// * Hop ids are bounded to 32 ASCII chars to limit log/parse surface.
pub fn load_entry_keys(path: &Path) -> Result<HashMap<String, [u8; 32]>, EntryKeysError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let md = std::fs::metadata(path)
            .map_err(|e| EntryKeysError::Io(format!("{}: {e}", path.display())))?;
        let mode = md.mode() & 0o777;
        // Reject world bits and group-write.
        if mode & 0o007 != 0 || mode & 0o020 != 0 {
            return Err(EntryKeysError::Mode(format!(
                "{}: mode {:o} permits world or group-write access",
                path.display(),
                mode
            )));
        }
    }

    let bytes = std::fs::read(path)
        .map_err(|e| EntryKeysError::Io(format!("{}: {e}", path.display())))?;
    let raw: HashMap<String, String> =
        serde_json::from_slice(&bytes).map_err(|e| EntryKeysError::Json(e.to_string()))?;
    if raw.is_empty() {
        return Err(EntryKeysError::Empty);
    }

    let mut out: HashMap<String, [u8; 32]> = HashMap::with_capacity(raw.len());
    for (hop, hex_val) in raw {
        if hop.is_empty() || hop.len() > 32 || !hop.chars().all(|c| c.is_ascii_graphic()) {
            return Err(EntryKeysError::InvalidKey(format!("invalid hop id: {hop:?}")));
        }
        let dec = hex::decode(&hex_val)
            .map_err(|e| EntryKeysError::InvalidKey(format!("hop {hop}: hex decode: {e}")))?;
        if dec.len() != 32 {
            return Err(EntryKeysError::InvalidKey(format!(
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
        let n: u64 = rand_core::RngCore::next_u64(&mut rand_core::OsRng);
        p.push(format!("ladon-entry-keys-{n:016x}"));
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
        let body = br#"{"ch1":"83f847a668ea5bad4957f95d224863c332572312ffaa041d073120c90c64986b","fi1":"f9f69971d33d5724c05af5f9515b04b60183a6b6ce488982859e4046e5248f9d"}"#;
        write_mode(&p, body, 0o640);
        let m = load_entry_keys(&p).unwrap();
        assert_eq!(m.len(), 2);
        assert!(m.contains_key("ch1") && m.contains_key("fi1"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_world_readable() {
        let d = tmpdir();
        let p = d.join("k.json");
        let body = br#"{"ch1":"83f847a668ea5bad4957f95d224863c332572312ffaa041d073120c90c64986b"}"#;
        write_mode(&p, body, 0o644);
        let e = load_entry_keys(&p).unwrap_err();
        assert!(matches!(e, EntryKeysError::Mode(_)), "got {e:?}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn rejects_short_key() {
        let d = tmpdir();
        let p = d.join("k.json");
        let body = br#"{"ch1":"deadbeef"}"#;
        write_mode(&p, body, 0o640);
        let e = load_entry_keys(&p).unwrap_err();
        assert!(matches!(e, EntryKeysError::InvalidKey(_)), "got {e:?}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn rejects_empty_map() {
        let d = tmpdir();
        let p = d.join("k.json");
        write_mode(&p, b"{}", 0o640);
        let e = load_entry_keys(&p).unwrap_err();
        assert!(matches!(e, EntryKeysError::Empty), "got {e:?}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn rejects_non_hex() {
        let d = tmpdir();
        let p = d.join("k.json");
        let body = br#"{"ch1":"NOTHEX!"}"#;
        write_mode(&p, body, 0o640);
        let e = load_entry_keys(&p).unwrap_err();
        assert!(matches!(e, EntryKeysError::InvalidKey(_)), "got {e:?}");
        let _ = std::fs::remove_dir_all(&d);
    }
}
