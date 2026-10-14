// BucketPadding.swift — Phase 1
//
// Pads plaintext bytes up to the exact byte count of the bucket selected by
// ``AttachmentBucket.smallestFitting(_:)`` using cryptographically random
// bytes.
//
// The padding is AEAD-framed together with the payload in Phase 2, so the
// choice of random bytes (as opposed to zeros) matters only as
// defence-in-depth — AEAD hides all plaintext equally, but random padding
// makes compressed-side-channel analysis impossible should a future bug ever
// skip AEAD on a sub-path.
//
// Inert while ``FeatureFlags.attachmentsEnabled`` is false.

import Foundation
import CryptoKit
import Security

public enum BucketPadding {

    public enum Error: Swift.Error, Equatable {
        case exceedsLargestBucket(bytes: Int)
        case rngFailed
    }

    /// Pad ``data`` to the smallest bucket that can contain it. Returns the
    /// padded bytes *and* the chosen bucket so the receiver can recompute
    /// the same classification from the descriptor alone.
    public static func pad(
        _ data: Data
    ) throws -> (padded: Data, bucket: AttachmentBucket, realLength: Int) {
        guard data.count <= AttachmentLimits.plaintextHardCapBytes else {
            throw Error.exceedsLargestBucket(bytes: data.count)
        }
        guard let bucket = AttachmentBucket.smallestFitting(data.count) else {
            throw Error.exceedsLargestBucket(bytes: data.count)
        }

        let target = bucket.byteSize
        let padLen = target - data.count
        if padLen == 0 {
            return (data, bucket, data.count)
        }

        var padBytes = Data(count: padLen)
        let status = padBytes.withUnsafeMutableBytes { buf -> Int32 in
            guard let base = buf.baseAddress else { return errSecAllocate }
            return SecRandomCopyBytes(kSecRandomDefault, padLen, base)
        }
        guard status == errSecSuccess else {
            throw Error.rngFailed
        }

        var padded = Data(capacity: target)
        padded.append(data)
        padded.append(padBytes)
        return (padded, bucket, data.count)
    }

    /// Recover the original plaintext length from a padded buffer given the
    /// caller's known real length. Phase 2 stores ``realLength`` as an
    /// AEAD-protected chunk-0 header field; Phase 1 exposes this helper for
    /// round-trip testing only.
    public static func unpad(
        _ padded: Data,
        realLength: Int
    ) -> Data {
        precondition(realLength <= padded.count)
        return padded.prefix(realLength)
    }
}
