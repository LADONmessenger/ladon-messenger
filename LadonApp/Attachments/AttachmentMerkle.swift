// AttachmentMerkle.swift — Phase 2
//
// SHA-256 Merkle tree over ciphertext frames, per PHASE3_SERVER_SPEC.md §5.6.
// The root (32 bytes) is carried in ``AttachmentDescriptor.digest`` and, in
// Phase 3, is sent to the server at /v1/blob/{id}/finalize for integrity
// verification.
//
// Domain-separated tags prevent length-extension and node/leaf confusion:
//   * leaf   :  SHA-256("ladon-attach-v1/leaf"  || BE32(i) || frame_i)
//   * node   :  SHA-256("ladon-attach-v1/node"  || a || b)
//   * empty  :  SHA-256("ladon-attach-v1/empty")
//
// The tree is a balanced binary tree. If the number of leaves is not a power
// of two, the level is padded with ``empty`` nodes until it is. This matches
// the RFC 6962-style construction used throughout industry.

import Foundation
import CryptoKit

public enum AttachmentMerkle {

    private static let domain = AttachmentKeyDerivation.domainPrefix

    /// Compute the 32-byte Merkle root over a sequence of ciphertext frames.
    /// Input order is preserved (chunk 0 first, chunk N−1 last).
    public static func root(of frames: [Data]) -> Data {
        if frames.isEmpty {
            return emptyHash()
        }

        // Leaf layer.
        var layer: [Data] = frames.enumerated().map { idx, frame in
            leafHash(index: UInt32(idx), frame: frame)
        }

        // Pad to next power of two with the domain-separated empty hash.
        let target = nextPowerOfTwo(layer.count)
        if layer.count < target {
            let pad = emptyHash()
            while layer.count < target {
                layer.append(pad)
            }
        }

        // Iteratively fold.
        while layer.count > 1 {
            var next: [Data] = []
            next.reserveCapacity(layer.count / 2)
            var i = 0
            while i < layer.count {
                next.append(nodeHash(left: layer[i], right: layer[i + 1]))
                i += 2
            }
            layer = next
        }
        return layer[0]
    }

    // MARK: - Internal hash helpers (internal so the self-test can reach them)

    static func leafHash(index: UInt32, frame: Data) -> Data {
        var input = Data()
        input.append(Data("\(domain)leaf".utf8))
        var be = index.bigEndian
        withUnsafeBytes(of: &be) { input.append(contentsOf: $0) }
        input.append(frame)
        return Data(SHA256.hash(data: input))
    }

    static func nodeHash(left: Data, right: Data) -> Data {
        precondition(left.count == 32 && right.count == 32)
        var input = Data(capacity: 2 * 32 + 32)
        input.append(Data("\(domain)node".utf8))
        input.append(left)
        input.append(right)
        return Data(SHA256.hash(data: input))
    }

    static func emptyHash() -> Data {
        let input = Data("\(domain)empty".utf8)
        return Data(SHA256.hash(data: input))
    }

    private static func nextPowerOfTwo(_ n: Int) -> Int {
        precondition(n > 0)
        if n == 1 { return 1 }
        var v = n - 1
        v |= v >> 1
        v |= v >> 2
        v |= v >> 4
        v |= v >> 8
        v |= v >> 16
        v |= v >> 32
        return v + 1
    }
}
