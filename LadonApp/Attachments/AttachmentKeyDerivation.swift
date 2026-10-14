// AttachmentKeyDerivation.swift — Phase 2
//
// Implements the key-derivation schedule from PHASE3_SERVER_SPEC.md §5.2 and
// §5.3. All HKDF outputs are 32-byte SymmetricKey values.
//
// Domain-separation strategy:
//   * salt  = blob_id (16 bytes, unique per attachment)
//   * info  = "ladon-attach-v1/<purpose>" — namespace is reserved; no other
//             Ladon subsystem uses the "ladon-attach-v1/" prefix.
//
// Inert while ``FeatureFlags.attachmentsEnabled`` is false. The functions do
// not check the flag — they are pure mathematical operations; the caller
// (AttachmentSealer / AttachmentUnsealer) performs the gating. This avoids
// having to feature-flag-guard helper primitives.

import Foundation
import CryptoKit

public enum AttachmentKeyDerivation {

    /// The domain prefix reserved for attachment v1 key derivation. No other
    /// subsystem is allowed to reuse this prefix.
    static let domainPrefix = "ladon-attach-v1/"

    // MARK: Top-level subkeys derived from the master seed

    /// Base key for chunk-key derivation. Feeds ``deriveChunkKey(base:blobID:chunkIndex:)``.
    public static func deriveContentKeyBase(
        seed: Data,
        blobID: Data
    ) -> SymmetricKey {
        precondition(seed.count == 32, "seed must be 32 bytes")
        precondition(blobID.count == AttachmentDescriptor.blobIDByteCount, "blob_id must be 16 bytes")
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: seed),
            salt: blobID,
            info: Data("\(domainPrefix)content".utf8),
            outputByteCount: 32
        )
    }

    public static func deriveThumbnailKey(
        seed: Data,
        blobID: Data
    ) -> SymmetricKey {
        precondition(seed.count == 32)
        precondition(blobID.count == AttachmentDescriptor.blobIDByteCount)
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: seed),
            salt: blobID,
            info: Data("\(domainPrefix)thumb".utf8),
            outputByteCount: 32
        )
    }

    public static func deriveCaptionKey(
        seed: Data,
        blobID: Data
    ) -> SymmetricKey {
        precondition(seed.count == 32)
        precondition(blobID.count == AttachmentDescriptor.blobIDByteCount)
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: seed),
            salt: blobID,
            info: Data("\(domainPrefix)caption".utf8),
            outputByteCount: 32
        )
    }

    /// V2 Option-C: derive a 32-byte sub-seed for the *separate* thumbnail
    /// blob from the master seed of the main attachment.
    ///
    /// The sub-seed plays the role of an independent blob seed — i.e. it is
    /// fed into ``deriveContentKeyBase(seed:blobID:)`` together with the
    /// thumbnail's own (distinct) blob_id. This means the thumbnail blob is
    /// cryptographically separated from the main blob (different content
    /// keys, different chunk keys), while still being recoverable from the
    /// single PQ-hybrid seed wrap that protects the master seed.
    ///
    /// Domain string: "ladon-attach-v1/thumb-blob-seed". Reserved here.
    /// The salt is the *main* blob's id, so the same master seed never
    /// produces the same sub-seed across two main blobs.
    public static func deriveThumbnailBlobSeed(
        masterSeed: Data,
        mainBlobID: Data
    ) -> Data {
        precondition(masterSeed.count == 32, "seed must be 32 bytes")
        precondition(
            mainBlobID.count == AttachmentDescriptor.blobIDByteCount,
            "main blob_id must be 16 bytes"
        )
        let key = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: masterSeed),
            salt: mainBlobID,
            info: Data("\(domainPrefix)thumb-blob-seed".utf8),
            outputByteCount: 32
        )
        return key.withUnsafeBytes { Data($0) }
    }

    /// Reserved for future use — currently unused (spec §5.4 defers it).
    /// Not removed, to keep the derivation schedule immutable across v1.
    public static func deriveHeaderKey(
        seed: Data,
        blobID: Data
    ) -> SymmetricKey {
        precondition(seed.count == 32)
        precondition(blobID.count == AttachmentDescriptor.blobIDByteCount)
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: seed),
            salt: blobID,
            info: Data("\(domainPrefix)header".utf8),
            outputByteCount: 32
        )
    }

    // MARK: Per-chunk derivation

    /// Derive the AEAD key for chunk ``chunkIndex``. The info string encodes
    /// the index in network byte order so the derivation is deterministic
    /// and collision-free across chunk counts.
    public static func deriveChunkKey(
        base: SymmetricKey,
        blobID: Data,
        chunkIndex: UInt32
    ) -> SymmetricKey {
        precondition(blobID.count == AttachmentDescriptor.blobIDByteCount)
        var info = Data()
        info.append(Data("\(domainPrefix)chunk/".utf8))
        var idxBE = chunkIndex.bigEndian
        withUnsafeBytes(of: &idxBE) { info.append(contentsOf: $0) }
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: base,
            salt: blobID,
            info: info,
            outputByteCount: 32
        )
    }

    // MARK: PQ-Hybrid seed wrap key

    /// Combine classical X25519 shared secret with Kyber-768 shared secret
    /// into a single 32-byte AEAD key. Matches PHASE3_SERVER_SPEC.md §5.7.
    public static func deriveSeedWrapKey(
        x25519Shared: Data,
        kyberShared: Data,
        blobID: Data
    ) -> SymmetricKey {
        precondition(x25519Shared.count == 32, "X25519 shared must be 32 bytes")
        precondition(kyberShared.count == 32, "Kyber shared must be 32 bytes")
        precondition(blobID.count == AttachmentDescriptor.blobIDByteCount)
        var ikm = Data(capacity: 64)
        ikm.append(x25519Shared)
        ikm.append(kyberShared)
        let key = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: ikm),
            salt: blobID,
            info: Data("\(domainPrefix)seed-wrap".utf8),
            outputByteCount: 32
        )
        // IKM contains two shared secrets; wipe it after derivation.
        ikm.securelyWipe()
        return key
    }
}
