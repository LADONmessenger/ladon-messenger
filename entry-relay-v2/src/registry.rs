use std::collections::HashMap;

use ladon_relay_core_v2::ids::ExitId;

use crate::error::EntryError;

/// Maps `target_exit_id` (16 B) to the upstream Exit-Relay base URL
/// (e.g. `https://exit.ch1.ladon.app`). Constructed once at start-up from
/// `EntryConfig::exits` (keys are hex-encoded). Lookups are O(1).
#[derive(Debug, Clone)]
pub struct ExitRegistry {
    by_id: HashMap<ExitId, String>,
}

impl ExitRegistry {
    pub fn from_hex_map(m: &HashMap<String, String>) -> Result<Self, EntryError> {
        let mut by_id = HashMap::with_capacity(m.len());
        for (hex_id, url) in m {
            let bytes = hex::decode(hex_id).map_err(|_| EntryError::Internal)?;
            if bytes.len() != 16 { return Err(EntryError::Internal); }
            let mut a = [0u8; 16]; a.copy_from_slice(&bytes);
            by_id.insert(ExitId(a), url.trim_end_matches('/').to_string());
        }
        Ok(Self { by_id })
    }

    pub fn lookup(&self, id: &ExitId) -> Option<&str> {
        self.by_id.get(id).map(|s| s.as_str())
    }

    pub fn lookup_hex(&self, hex_id: &str) -> Result<&str, EntryError> {
        let bytes = hex::decode(hex_id).map_err(|_| EntryError::Malformed)?;
        if bytes.len() != 16 { return Err(EntryError::Malformed); }
        let mut a = [0u8; 16]; a.copy_from_slice(&bytes);
        self.lookup(&ExitId(a)).ok_or(EntryError::UnknownExit)
    }

    pub fn len(&self) -> usize { self.by_id.len() }
    pub fn is_empty(&self) -> bool { self.by_id.is_empty() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_by_hex() {
        let mut m = HashMap::new();
        m.insert("00".repeat(16), "https://x.example".into());
        let r = ExitRegistry::from_hex_map(&m).unwrap();
        assert_eq!(r.lookup_hex(&"00".repeat(16)).unwrap(), "https://x.example");
        assert!(r.lookup_hex(&"11".repeat(16)).is_err());
    }

    #[test]
    fn rejects_wrong_length() {
        let mut m = HashMap::new();
        m.insert("00".to_string(), "https://x".into());
        assert!(ExitRegistry::from_hex_map(&m).is_err());
    }
}
