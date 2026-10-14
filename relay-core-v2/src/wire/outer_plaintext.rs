//! Outer plaintext — Addendum A1 §3.4 layout. Since relay protocol 0x06 it
//! carries the sealed ENQUEUE (A2 §4.1): the Exit rebuilds it from the body
//! (`rid ‖ K_X ‖ sent_at ‖ envelope_id ‖ inner`) behind a zero flags byte,
//! so the A1 checks run in one place. Never visible to the Entry.
//!
//! ```text
//!   off=0    1 B   flags         MUST be 0 (no per-envelope push bit, A2 §7)
//!   off=1    32 B  recipient_id
//!   off=33   32 B  delivery_key  K_X for this Exit
//!   off=65   8 B   sent_at       unix seconds (BE), sender's relay-anchored clock
//!   off=73   16 B  envelope_id   random per envelope
//!   off=89   rest  inner_envelope
//! ```

use crate::constants::*;
use crate::error::{Error, Result};
use crate::ids::{EnvelopeId, RecipientId};
use crate::wire::read_u64_be;
use zeroize::Zeroize;

pub struct OuterPlaintext {
    pub flags: u8,
    pub recipient_id: RecipientId,
    /// `K_X` — a credential. Wiped on drop; never logged (no `Debug`).
    pub delivery_key: [u8; DELIVERY_KEY_LEN],
    pub sent_at: u64,
    pub envelope_id: EnvelopeId,
    pub inner_envelope: Vec<u8>,
}

impl Drop for OuterPlaintext {
    fn drop(&mut self) {
        self.delivery_key.zeroize();
    }
}

impl OuterPlaintext {
    /// Parse the outer plaintext. Rejects a buffer shorter than the 89-byte
    /// header and any flag bit (no silent forward-compat).
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < OUTER_PT_HEADER_LEN {
            return Err(Error::Short { expected: OUTER_PT_HEADER_LEN, got: buf.len() });
        }
        let flags = buf[OUTER_PT_OFF_FLAGS];
        if flags != 0 {
            return Err(Error::Internal("outer plaintext: flag bit set"));
        }
        let recipient_id = RecipientId::from_bytes(&buf[OUTER_PT_OFF_RECIPIENT_ID..OUTER_PT_OFF_DELIVERY_KEY])
            .expect("32 bytes");
        let mut delivery_key = [0u8; DELIVERY_KEY_LEN];
        delivery_key.copy_from_slice(&buf[OUTER_PT_OFF_DELIVERY_KEY..OUTER_PT_OFF_SENT_AT]);
        let sent_at = read_u64_be(&buf[OUTER_PT_OFF_SENT_AT..OUTER_PT_OFF_ENVELOPE_ID]);
        let envelope_id = EnvelopeId::from_bytes(&buf[OUTER_PT_OFF_ENVELOPE_ID..OUTER_PT_HEADER_LEN])
            .expect("16 bytes");
        let inner_envelope = buf[OUTER_PT_HEADER_LEN..].to_vec();
        Ok(Self { flags, recipient_id, delivery_key, sent_at, envelope_id, inner_envelope })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(OUTER_PT_HEADER_LEN + self.inner_envelope.len());
        out.push(self.flags);
        out.extend_from_slice(self.recipient_id.as_bytes());
        out.extend_from_slice(&self.delivery_key);
        out.extend_from_slice(&self.sent_at.to_be_bytes());
        out.extend_from_slice(self.envelope_id.as_bytes());
        debug_assert_eq!(out.len(), OUTER_PT_HEADER_LEN);
        out.extend_from_slice(&self.inner_envelope);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> OuterPlaintext {
        OuterPlaintext {
            flags: 0,
            recipient_id: RecipientId([0xAA; 32]),
            delivery_key: [0x5A; DELIVERY_KEY_LEN],
            sent_at: 1_700_000_000,
            envelope_id: EnvelopeId([0xE1; 16]),
            inner_envelope: vec![1, 2, 3, 4],
        }
    }

    #[test]
    fn roundtrip() {
        let p = sample();
        let enc = p.encode();
        assert_eq!(enc.len(), OUTER_PT_HEADER_LEN + 4);
        let q = OuterPlaintext::parse(&enc).unwrap();
        assert_eq!(q.flags, p.flags);
        assert_eq!(q.recipient_id, p.recipient_id);
        assert_eq!(q.delivery_key, p.delivery_key);
        assert_eq!(q.sent_at, p.sent_at);
        assert_eq!(q.envelope_id, p.envelope_id);
        assert_eq!(q.inner_envelope, p.inner_envelope);
    }

    #[test]
    fn rejects_short_buffer() {
        let enc = sample().encode();
        assert!(OuterPlaintext::parse(&enc[..OUTER_PT_HEADER_LEN - 1]).is_err());
        // Exactly the header (empty inner) parses; the Exit rejects a short
        // inner envelope separately.
        assert!(OuterPlaintext::parse(&enc[..OUTER_PT_HEADER_LEN]).is_ok());
    }

    #[test]
    fn rejects_every_flag_bit() {
        // The A1 SUPPRESS_PUSH (bit 0) and DROP (bit 1) included.
        for bit in 0..8u8 {
            let mut enc = sample().encode();
            enc[0] = 1 << bit;
            assert!(OuterPlaintext::parse(&enc).is_err(), "bit {bit} must be rejected");
        }
    }
}
