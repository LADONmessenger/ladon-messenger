//! SHA-256 Merkle tree matching `LadonApp/Attachments/AttachmentMerkle.swift`
//! and PHASE3_SERVER_SPEC.md §5.6.
//!
//!   leaf_i     = SHA-256("ladon-attach-v1/leaf" || BE32(i) || frame_i)
//!   node(a, b) = SHA-256("ladon-attach-v1/node" || a || b)
//!   empty      = SHA-256("ladon-attach-v1/empty")
//!   root       = reduce, padding each layer to next power of 2 with empty.
//!
//! Interop requirement: byte-for-byte equality with the Swift implementation.

use sha2::{Digest, Sha256};

const LEAF_TAG: &[u8] = b"ladon-attach-v1/leaf";
const NODE_TAG: &[u8] = b"ladon-attach-v1/node";
const EMPTY_TAG: &[u8] = b"ladon-attach-v1/empty";

pub fn empty_hash() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(EMPTY_TAG);
    h.finalize().into()
}

pub fn leaf_hash(index: u32, frame: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(LEAF_TAG);
    h.update(index.to_be_bytes());
    h.update(frame);
    h.finalize().into()
}

fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(NODE_TAG);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Compute the Merkle root of the given frames. An empty list returns the
/// empty-tag hash, matching the Swift reference.
pub fn root(frames: &[&[u8]]) -> [u8; 32] {
    if frames.is_empty() {
        return empty_hash();
    }

    // Seed leaf layer.
    let mut layer: Vec<[u8; 32]> = frames
        .iter()
        .enumerate()
        .map(|(i, f)| leaf_hash(i as u32, f))
        .collect();

    // Pad to next power of two with empty hashes.
    let target = layer.len().next_power_of_two().max(1);
    let empty = empty_hash();
    while layer.len() < target {
        layer.push(empty);
    }

    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len() / 2);
        for pair in layer.chunks_exact(2) {
            next.push(node_hash(&pair[0], &pair[1]));
        }
        layer = next;
    }

    layer[0]
}

/// P7-BLOB-09 helper: compute the root from a pre-hashed leaf layer. This is
/// what callers should use when they want to stream frames through `leaf_hash`
/// without keeping each frame's bytes resident. Identical output to `root`.
pub fn root_from_leaves(mut layer: Vec<[u8; 32]>) -> [u8; 32] {
    if layer.is_empty() {
        return empty_hash();
    }
    let target = layer.len().next_power_of_two().max(1);
    let empty = empty_hash();
    while layer.len() < target {
        layer.push(empty);
    }
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len() / 2);
        for pair in layer.chunks_exact(2) {
            next.push(node_hash(&pair[0], &pair[1]));
        }
        layer = next;
    }
    layer[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_deterministic() {
        let a = root(&[]);
        let b = root(&[]);
        assert_eq!(a, b);
    }

    #[test]
    fn single_frame() {
        let data = b"one frame";
        let r1 = root(&[data]);
        let r2 = root(&[data]);
        assert_eq!(r1, r2);
        // Single-frame root should pad to next_power_of_two=1 → r1 == leaf(0, data).
        assert_eq!(r1, leaf_hash(0, data));
    }

    #[test]
    fn flip_changes_root() {
        let a = b"aaaa".to_vec();
        let mut b = a.clone();
        b[0] ^= 1;
        let ra = root(&[&a[..]]);
        let rb = root(&[&b[..]]);
        assert_ne!(ra, rb);
    }

    #[test]
    fn odd_count_pads_with_empty() {
        // With 3 leaves we pad to 4 with empty.
        let f0 = b"zero";
        let f1 = b"one!";
        let f2 = b"two!";
        let root_3 = root(&[f0, f1, f2]);

        // Recompute manually.
        let l0 = leaf_hash(0, f0);
        let l1 = leaf_hash(1, f1);
        let l2 = leaf_hash(2, f2);
        let l3 = empty_hash();
        let n01 = node_hash(&l0, &l1);
        let n23 = node_hash(&l2, &l3);
        let r = node_hash(&n01, &n23);
        assert_eq!(root_3, r);
    }
}
