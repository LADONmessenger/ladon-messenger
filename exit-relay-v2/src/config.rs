use std::path::PathBuf;
use serde::Deserialize;

/// Operator-facing configuration for an Exit-Relay instance.
/// Loaded from a TOML file via `ExitConfig::load`.
#[derive(Debug, Clone, Deserialize)]
pub struct ExitConfig {
    /// Bind address, e.g. "127.0.0.1:8443" (TLS terminated by reverse-proxy in front).
    pub listen: String,

    /// Path to long-term HKEM secret-key file (raw bytes:
    /// X25519_SK (32) || Kyber768_SK (var) || Kyber768_PK (1184)).
    pub hkem_keyfile: PathBuf,

    /// 32-byte hex-encoded S2S HMAC key shared with the entry-relays
    /// allowed to forward to us.
    pub s2s_hmac_key_hex: String,

    /// Maximum allowed S2S timestamp skew in seconds.
    #[serde(default = "default_s2s_skew")]
    pub s2s_skew_sec: u64,

    /// Path to the canary file served on `/canary.json`.
    pub canary_file: PathBuf,

    /// Optional override for replay-bloom window start (test only).
    #[serde(default)]
    pub now_override_sec: Option<u64>,
}

fn default_s2s_skew() -> u64 { 120 }

/// F3/F5: `LADON_MAILBOX_CAP_BYTES`, the cap on envelope bytes queued across
/// all recipients. Unset: `DEFAULT_MAILBOX_GLOBAL_CAP_BYTES` (4 GiB, half of
/// the exit's 8 GiB). Set: a positive integer number of bytes; anything else
/// is an error and `main` refuses to start, like a bad `LADON_PUSH_S2S_KEY`
/// (fail-closed: a typo must not silently mean "default" or "no cap").
pub fn mailbox_cap_bytes(raw: Option<&str>) -> Result<u64, String> {
    let Some(raw) = raw else {
        return Ok(ladon_relay_core_v2::store::DEFAULT_MAILBOX_GLOBAL_CAP_BYTES);
    };
    match raw.trim().parse::<u64>() {
        Ok(n) if n > 0 => Ok(n),
        _ => Err("LADON_MAILBOX_CAP_BYTES must be a positive integer (bytes)".into()),
    }
}

/// F43: `LADON_PUSH_HKEM_PK` (hex, `HKEM_PK_LEN` bytes) and
/// `LADON_PUSH_TARGET_ID` (hex, 16 bytes) — the push relay's public HKEM key
/// and its id, the same public values the app has in `exits-bootstrap.json`
/// (`push.hkemPkHex`, `push.targetIdHex`). Every exit -> push request is
/// sealed to them. Both are required when a push URL is configured; the id
/// must equal `BLAKE3(pk)[..16]`, so a pk/id mix-up stops the start instead
/// of producing requests the push relay cannot open.
pub fn push_target(pk_hex: Option<&str>, target_hex: Option<&str>) -> Result<(Vec<u8>, [u8; 16]), String> {
    use ladon_relay_core_v2::constants::HKEM_PK_LEN;
    let pk = pk_hex
        .map(str::trim)
        .and_then(|h| hex::decode(h).ok())
        .filter(|v| v.len() == HKEM_PK_LEN)
        .ok_or("LADON_PUSH_HKEM_PK must be the push relay's HKEM public key (hex)")?;
    let id: [u8; 16] = target_hex
        .map(str::trim)
        .and_then(|h| hex::decode(h).ok())
        .and_then(|v| v.try_into().ok())
        .ok_or("LADON_PUSH_TARGET_ID must be 16 bytes (32 hex)")?;
    if *ladon_relay_core_v2::hash::exit_id_from_hkem_pk(&pk).as_bytes() != id {
        return Err("LADON_PUSH_TARGET_ID is not BLAKE3(LADON_PUSH_HKEM_PK)[..16]".into());
    }
    Ok((pk, id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ladon_relay_core_v2::store::DEFAULT_MAILBOX_GLOBAL_CAP_BYTES;

    /// F3/F5: unset means the 4 GiB default; a set value must be a positive
    /// integer, anything else stops the start (fail-closed).
    #[test]
    fn mailbox_cap_env_is_fail_closed() {
        assert_eq!(mailbox_cap_bytes(None), Ok(DEFAULT_MAILBOX_GLOBAL_CAP_BYTES));
        assert_eq!(mailbox_cap_bytes(Some("1073741824")), Ok(1 << 30));
        assert_eq!(mailbox_cap_bytes(Some(" 2048 ")), Ok(2048));
        for bad in ["", "0", "-1", "4GiB", "1e9", "18446744073709551616"] {
            assert!(mailbox_cap_bytes(Some(bad)).is_err(), "{bad:?} must be refused");
        }
    }

    /// F43: with a push URL the exit needs the push relay's HKEM pk and
    /// target id, and the id must be BLAKE3(pk)[..16]. Anything missing or
    /// inconsistent stops the start.
    #[test]
    fn push_target_is_fail_closed() {
        use ladon_relay_core_v2::hash::exit_id_from_hkem_pk;
        use ladon_relay_core_v2::hkem::HkemKeyPair;
        let pk = HkemKeyPair::generate().public_key_bytes().to_vec();
        let id = *exit_id_from_hkem_pk(&pk).as_bytes();
        let (pk_hex, id_hex) = (hex::encode(&pk), hex::encode(id));
        assert_eq!(push_target(Some(&pk_hex), Some(&id_hex)), Ok((pk.clone(), id)));
        assert_eq!(push_target(Some(&format!(" {pk_hex}\n")), Some(&id_hex)), Ok((pk.clone(), id)));
        let mut other = id;
        other[0] ^= 1;
        for (p, t) in [
            (None, Some(id_hex.as_str())),
            (Some(pk_hex.as_str()), None),
            (Some(""), Some(id_hex.as_str())),
            (Some(&pk_hex[2..]), Some(id_hex.as_str())),
            (Some("zz"), Some(id_hex.as_str())),
            (Some(pk_hex.as_str()), Some(&id_hex[2..])),
            (Some(pk_hex.as_str()), Some(hex::encode(other).as_str())),
        ] {
            assert!(push_target(p, t).is_err(), "{:?} / {:?}", p.map(str::len), t);
        }
    }
}

