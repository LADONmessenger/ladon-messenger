// AttachmentMessagePayloadV2.swift — V2 wire-format
//
// Compact binary codec for attachment messages travelling inside a V2
// outer envelope. Reason this exists separately from the JSON-based
// `AttachmentMessagePayload`:
//
// V2 envelopes have a fixed 16 384 B outer size with a single-use Token
// (~3.4 KB) baked into every send, leaving roughly 11 765 B of space for
// the inner messageBody. The legacy JSON+double-base64 wire format
// produces ≈16.8 KB even for a small photo and bursts that limit. This
// binary codec brings the same data down to ≈7-8 KB after base64url.
//
// Wire layout (all integers little-endian, lengths are u16 unless noted):
//
//   magic_marker      "\u{E000}LADON-ATT-V2:"
//   body              base64url-encoded binary blob below
//
//   binary blob:
//     0   u8       version (=4)
//     1   u8       flags  (0x01 = separate thumbnail blob present)
//     2   16 B     blobID
//     18  u8       blobHost  (0=fi, 1=ch)               ← NEW in v4
//     19  u8       mime
//     20  u8       bucket
//     21  u16      width
//     23  u16      height
//     25  u32      durationMs
//     29  u32      chunkCount
//     33  32 B     sealedSeed
//     65  32 B     digest
//     97  4096 B   sealedThumbnail            (only if flags & 0x01 == 0)
//     ...  u16     sealedCaption_len  (0xFFFF == nil)
//     ...  ...     sealedCaption_bytes  (≤ 1024 B)
//     ---- thumbnail blob section (only if flags & 0x01) ----
//     ...  16 B    thumbBlobID
//     ...  u8      thumbBlobHost                          ← NEW in v4
//     ...  u8      thumbBucket
//     ...  u32     thumbChunkCount
//     ...  32 B    thumbDigest
//     ...  u16     thumbReadCap_len
//     ...  ...     thumbReadCap_utf8
//     -------------------------------------------------------
//     ...  1088 B  seed.kyberCiphertext
//     ...  32 B    seed.ephemeralX25519PublicKey
//     ...  u16     seed.aeadFrame_len
//     ...  ...     seed.aeadFrame_bytes
//     ...  u16     readCap_len
//     ...  ...     readCap_utf8
//
// HARD CUTOVER (14.05.2026, multi-shard rollout): only version==4 is
// accepted. v2/v3 messages will fail to decode. Tester base is two
// devices owned by the operator, so the migration window is irrelevant.

import Foundation
import CryptoKit

@available(iOS 15.0, macOS 12.0, *)
public enum AttachmentMessagePayloadV2 {

    /// Schema version baked into the binary blob.
    public static let currentVersion: UInt8 = 4

    /// Distinct from `AttachmentMessagePayload.wireMarker` (which is v1).
    public static let wireMarker: String = "\u{E000}LADON-ATT-V2:"

    public enum WireError: Error, Equatable {
        case notAnAttachmentMessage
        case base64DecodeFailed
        case truncated(stage: String)
        case unsupportedVersion(UInt8)
        case unknownMime(UInt8)
        case unknownBucket(UInt8)
        case unknownFlags(UInt8)
        case captionTooLarge(Int)
        case aeadFrameTooLarge(Int)
        case readCapTooLarge(Int)
        case structuralInvariant(String)
    }

    // MARK: - Decoded shape

    public struct Decoded: Equatable {
        public let payload: AttachmentMessagePayload
    }

    // MARK: - Encode

    /// Encode descriptor + seed + readCap into the V2 string wire-format
    /// suitable to be carried inside `Message.content` (the same channel
    /// the legacy JSON encoder uses).
    public static func encodedAsMessageContent(
        descriptor: AttachmentDescriptor,
        seed: AttachmentSeedWrap.WrappedSeedPayload,
        readCap: String
    ) throws -> String {
        let payload = AttachmentMessagePayload(
            descriptor: descriptor,
            seed: AttachmentMessagePayload.SeedPayload(from: seed),
            readCap: readCap
        )
        return try encodedAsMessageContent(payload: payload)
    }

    public static func encodedAsMessageContent(
        payload: AttachmentMessagePayload
    ) throws -> String {
        let blob = try encodeBlob(payload: payload)
        return wireMarker + base64URL(blob)
    }

    /// Encode just the binary blob (no marker, no base64) — exposed for
    /// test vectors and round-trip self-tests.
    public static func encodeBlob(
        descriptor: AttachmentDescriptor,
        seed: AttachmentSeedWrap.WrappedSeedPayload,
        readCap: String
    ) throws -> Data {
        let payload = AttachmentMessagePayload(
            descriptor: descriptor,
            seed: AttachmentMessagePayload.SeedPayload(from: seed),
            readCap: readCap
        )
        return try encodeBlob(payload: payload)
    }

    public static func encodeBlob(
        payload: AttachmentMessagePayload
    ) throws -> Data {
        let descriptor = payload.descriptor
        let seed = payload.seed.unwrap()
        // Pre-flight invariants — the codec assumes upstream layers already
        // produced a valid descriptor (sealer + uploader). We re-check here
        // so a wire-level corruption can never silently propagate.
        guard descriptor.blobID.count == AttachmentDescriptor.blobIDByteCount else {
            throw WireError.structuralInvariant("blobID size")
        }
        guard descriptor.sealedSeed.count == AttachmentDescriptor.sealedSeedByteCount else {
            throw WireError.structuralInvariant("sealedSeed size")
        }
        guard descriptor.digest.count == AttachmentDescriptor.digestByteCount else {
            throw WireError.structuralInvariant("digest size")
        }
        guard descriptor.sealedThumbnail.count == AttachmentDescriptor.sealedThumbnailByteCount else {
            throw WireError.structuralInvariant("sealedThumbnail size")
        }
        if let cap = descriptor.sealedCaption,
           cap.count > AttachmentDescriptor.sealedCaptionMaxByteCount {
            throw WireError.captionTooLarge(cap.count)
        }
        let aeadFrameLen = seed.aeadFrame.count
        guard aeadFrameLen <= 0xFFFE else {
            throw WireError.aeadFrameTooLarge(aeadFrameLen)
        }
        guard seed.kyberCiphertext.count == LadonV2.kyber768CtLen else {
            throw WireError.structuralInvariant("kyberCt size \(seed.kyberCiphertext.count)")
        }
        guard seed.ephemeralX25519PublicKey.count == LadonV2.x25519PkLen else {
            throw WireError.structuralInvariant("ephX25519 size \(seed.ephemeralX25519PublicKey.count)")
        }
        let readCap = payload.readCap
        let readCapBytesPayload = Data(readCap.utf8)
        guard readCapBytesPayload.count <= 0xFFFF else {
            throw WireError.readCapTooLarge(readCapBytesPayload.count)
        }
        let flags: UInt8 = descriptor.thumbnailBlob == nil ? 0 : 0x01
        if flags != 0 && payload.thumbnailReadCap == nil {
            throw WireError.structuralInvariant("missing thumbnail readCap")
        }
        let thumbnailReadCapBytes = Data((payload.thumbnailReadCap ?? "").utf8)
        guard thumbnailReadCapBytes.count <= 0xFFFF else {
            throw WireError.readCapTooLarge(thumbnailReadCapBytes.count)
        }

        var out = Data()
        let captionLen = descriptor.sealedCaption?.count ?? 0
        let hasThumbBlob = descriptor.thumbnailBlob != nil
        let thumbBlobLen: Int = hasThumbBlob ? (16 + 1 + 1 + 4 + 32 + 2 + thumbnailReadCapBytes.count) : 0
        // When a separate thumbnail blob is present, the inline 4096-byte
        // sealedThumbnail placeholder is omitted from the wire to stay within
        // the 16384-byte envelope bucket.
        let inlineThumbLen = hasThumbBlob ? 0 : 4096
        // Account for new blobHost byte in main and thumb sections (v4).
        let headerLen = 1 + 1 + 16 + 1 + 1 + 1 + 2 + 2 + 4 + 4 + 32 + 32 + inlineThumbLen
        let seedLen = 1088 + 32 + 2 + aeadFrameLen
        let readCapLen = 2 + readCapBytesPayload.count
        out.reserveCapacity(headerLen + 2 + captionLen + thumbBlobLen + seedLen + readCapLen)

        out.append(Self.currentVersion)                         // version (4)
        out.append(flags)                                       // flags
        out.append(descriptor.blobID)                           // blobID
        out.append(descriptor.blobHost.rawValue)                // blobHost  (v4)
        out.append(descriptor.mime.rawValue)                    // mime
        out.append(descriptor.bucket.rawValue)                  // bucket
        appendU16LE(&out, descriptor.dimensions.width)          // width
        appendU16LE(&out, descriptor.dimensions.height)         // height
        appendU32LE(&out, descriptor.dimensions.durationMs)     // duration
        appendU32LE(&out, descriptor.chunkCount)                // chunkCount
        out.append(descriptor.sealedSeed)
        out.append(descriptor.digest)
        if !hasThumbBlob {
            out.append(descriptor.sealedThumbnail)
        }

        // Caption: 0xFFFF means nil, else explicit length.
        if let cap = descriptor.sealedCaption {
            appendU16LE(&out, UInt16(cap.count))
            out.append(cap)
        } else {
            appendU16LE(&out, 0xFFFF)
        }

        if let thumb = descriptor.thumbnailBlob {
            out.append(thumb.blobID)
            out.append(thumb.blobHost.rawValue)                 // thumbBlobHost (v4)
            out.append(thumb.bucket.rawValue)
            appendU32LE(&out, thumb.chunkCount)
            out.append(thumb.digest)
            appendU16LE(&out, UInt16(thumbnailReadCapBytes.count))
            out.append(thumbnailReadCapBytes)
        }

        // Seed
        out.append(seed.kyberCiphertext)
        out.append(seed.ephemeralX25519PublicKey)
        appendU16LE(&out, UInt16(aeadFrameLen))
        out.append(seed.aeadFrame)

        // ReadCap
        appendU16LE(&out, UInt16(readCapBytesPayload.count))
        out.append(readCapBytesPayload)

        return out
    }

    // MARK: - Decode

    public static func isAttachmentContent(_ content: String) -> Bool {
        content.hasPrefix(Self.wireMarker)
    }

    public static func decode(fromMessageContent content: String) throws -> Decoded {
        guard isAttachmentContent(content) else {
            throw WireError.notAnAttachmentMessage
        }
        let body = String(content.dropFirst(Self.wireMarker.count))
        guard let blob = base64URLDecode(body) else {
            throw WireError.base64DecodeFailed
        }
        return try decodeBlob(blob)
    }

    public static func decodeBlob(_ blob: Data) throws -> Decoded {
        var p = 0
        let n = blob.count

        func need(_ count: Int, stage: String) throws {
            guard p + count <= n else { throw WireError.truncated(stage: stage) }
        }

        try need(1, stage: "version")
        let version = blob[blob.startIndex + p]; p += 1
        // Hard cutover — only v4 (active-active sharding) is accepted.
        guard version == 4 else {
            throw WireError.unsupportedVersion(version)
        }

        try need(1, stage: "flags")
        let flags = blob[blob.startIndex + p]; p += 1
        guard flags & ~0x01 == 0 else {
            throw WireError.unknownFlags(flags)
        }

        try need(16, stage: "blobID")
        let blobID = blob.subdata(in: (blob.startIndex + p)..<(blob.startIndex + p + 16)); p += 16

        try need(1, stage: "blobHost")
        let blobHostRaw = blob[blob.startIndex + p]; p += 1
        guard let blobHost = BlobHost(rawValue: blobHostRaw) else {
            throw WireError.structuralInvariant("unknown blobHost \(blobHostRaw)")
        }

        try need(1, stage: "mime")
        let mimeRaw = blob[blob.startIndex + p]; p += 1
        guard let mime = AttachmentMimeType(rawValue: mimeRaw) else {
            throw WireError.unknownMime(mimeRaw)
        }

        try need(1, stage: "bucket")
        let bucketRaw = blob[blob.startIndex + p]; p += 1
        guard let bucket = AttachmentBucket(rawValue: bucketRaw) else {
            throw WireError.unknownBucket(bucketRaw)
        }

        try need(2, stage: "width"); let width = readU16LE(blob, p); p += 2
        try need(2, stage: "height"); let height = readU16LE(blob, p); p += 2
        try need(4, stage: "duration"); let duration = readU32LE(blob, p); p += 4
        try need(4, stage: "chunkCount"); let chunkCount = readU32LE(blob, p); p += 4

        try need(32, stage: "sealedSeed")
        let sealedSeed = blob.subdata(in: (blob.startIndex + p)..<(blob.startIndex + p + 32)); p += 32

        try need(32, stage: "digest")
        let digest = blob.subdata(in: (blob.startIndex + p)..<(blob.startIndex + p + 32)); p += 32

        // sealedThumbnail is only on the wire when no separate thumbnail blob.
        let hasSeparateThumb = (flags & 0x01) != 0
        let sealedThumb: Data
        if hasSeparateThumb {
            sealedThumb = Data(count: 4096)
        } else {
            try need(4096, stage: "sealedThumbnail")
            sealedThumb = blob.subdata(in: (blob.startIndex + p)..<(blob.startIndex + p + 4096)); p += 4096
        }

        try need(2, stage: "sealedCaption_len")
        let capLenRaw = readU16LE(blob, p); p += 2
        let sealedCaption: Data?
        if capLenRaw == 0xFFFF {
            sealedCaption = nil
        } else {
            let capLen = Int(capLenRaw)
            guard capLen <= AttachmentDescriptor.sealedCaptionMaxByteCount else {
                throw WireError.captionTooLarge(capLen)
            }
            try need(capLen, stage: "sealedCaption")
            sealedCaption = blob.subdata(in: (blob.startIndex + p)..<(blob.startIndex + p + capLen))
            p += capLen
        }

        var thumbnailBlob: AttachmentRemoteBlobDescriptor?
        var thumbnailReadCap: String?
        if flags & 0x01 != 0 {
            try need(16, stage: "thumbnailBlobID")
            let thumbnailBlobID = blob.subdata(in: (blob.startIndex + p)..<(blob.startIndex + p + 16)); p += 16

            try need(1, stage: "thumbnailBlobHost")
            let thumbHostRaw = blob[blob.startIndex + p]; p += 1
            guard let thumbnailBlobHost = BlobHost(rawValue: thumbHostRaw) else {
                throw WireError.structuralInvariant("unknown thumbBlobHost \(thumbHostRaw)")
            }

            try need(1, stage: "thumbnailBucket")
            let thumbnailBucketRaw = blob[blob.startIndex + p]; p += 1
            guard let thumbnailBucket = AttachmentBucket(rawValue: thumbnailBucketRaw) else {
                throw WireError.unknownBucket(thumbnailBucketRaw)
            }

            try need(4, stage: "thumbnailChunkCount")
            let thumbnailChunkCount = readU32LE(blob, p); p += 4

            try need(32, stage: "thumbnailDigest")
            let thumbnailDigest = blob.subdata(in: (blob.startIndex + p)..<(blob.startIndex + p + 32)); p += 32

            try need(2, stage: "thumbnailReadCap_len")
            let thumbnailReadCapLen = Int(readU16LE(blob, p)); p += 2
            try need(thumbnailReadCapLen, stage: "thumbnailReadCap")
            let thumbnailReadCapBytes = blob.subdata(in: (blob.startIndex + p)..<(blob.startIndex + p + thumbnailReadCapLen)); p += thumbnailReadCapLen
            guard let decodedThumbnailReadCap = String(data: thumbnailReadCapBytes, encoding: .utf8) else {
                throw WireError.structuralInvariant("thumbnailReadCap not utf8")
            }
            thumbnailReadCap = decodedThumbnailReadCap

            do {
                thumbnailBlob = try AttachmentRemoteBlobDescriptor(
                    blobID: thumbnailBlobID,
                    bucket: thumbnailBucket,
                    chunkCount: thumbnailChunkCount,
                    digest: thumbnailDigest,
                    blobHost: thumbnailBlobHost
                )
            } catch {
                throw WireError.structuralInvariant("thumbnailBlob: \(error)")
            }
        }

        try need(1088, stage: "kyberCt")
        let kyberCt = blob.subdata(in: (blob.startIndex + p)..<(blob.startIndex + p + 1088)); p += 1088

        try need(32, stage: "ephX25519")
        let eph = blob.subdata(in: (blob.startIndex + p)..<(blob.startIndex + p + 32)); p += 32

        try need(2, stage: "aeadFrame_len")
        let aeadLen = Int(readU16LE(blob, p)); p += 2
        try need(aeadLen, stage: "aeadFrame")
        let aeadFrame = blob.subdata(in: (blob.startIndex + p)..<(blob.startIndex + p + aeadLen))
        p += aeadLen

        try need(2, stage: "readCap_len")
        let rcLen = Int(readU16LE(blob, p)); p += 2
        try need(rcLen, stage: "readCap")
        let rcBytes = blob.subdata(in: (blob.startIndex + p)..<(blob.startIndex + p + rcLen)); p += rcLen
        guard let readCap = String(data: rcBytes, encoding: .utf8) else {
            throw WireError.structuralInvariant("readCap not utf8")
        }

        // Reject trailing garbage — strict.
        guard p == n else {
            throw WireError.structuralInvariant("trailing \(n - p) bytes")
        }

        let descriptor: AttachmentDescriptor
        do {
            descriptor = try AttachmentDescriptor(
                blobID: blobID,
                version: AttachmentDescriptor.currentVersion,
                mime: mime,
                bucket: bucket,
                dimensions: AttachmentDimensions(width: width, height: height, durationMs: duration),
                chunkCount: chunkCount,
                sealedSeed: sealedSeed,
                digest: digest,
                sealedThumbnail: sealedThumb,
                sealedCaption: sealedCaption,
                thumbnailBlob: thumbnailBlob,
                blobHost: blobHost
            )
        } catch {
            throw WireError.structuralInvariant("descriptor: \(error)")
        }

        let payload = AttachmentMessagePayload(
            descriptor: descriptor,
            seed: AttachmentMessagePayload.SeedPayload(
                kyberCiphertext: kyberCt,
                aeadFrame: aeadFrame,
                ephemeralX25519PublicKey: eph
            ),
            readCap: readCap,
            thumbnailReadCap: thumbnailReadCap
        )
        return Decoded(payload: payload)
    }

    // MARK: - Bit-twiddlers

    private static func appendU16LE(_ out: inout Data, _ value: UInt16) {
        out.append(UInt8(value & 0xFF))
        out.append(UInt8((value >> 8) & 0xFF))
    }
    private static func appendU32LE(_ out: inout Data, _ value: UInt32) {
        out.append(UInt8(value & 0xFF))
        out.append(UInt8((value >> 8) & 0xFF))
        out.append(UInt8((value >> 16) & 0xFF))
        out.append(UInt8((value >> 24) & 0xFF))
    }
    private static func readU16LE(_ d: Data, _ off: Int) -> UInt16 {
        let b0 = UInt16(d[d.startIndex + off])
        let b1 = UInt16(d[d.startIndex + off + 1])
        return b0 | (b1 << 8)
    }
    private static func readU32LE(_ d: Data, _ off: Int) -> UInt32 {
        let b0 = UInt32(d[d.startIndex + off])
        let b1 = UInt32(d[d.startIndex + off + 1])
        let b2 = UInt32(d[d.startIndex + off + 2])
        let b3 = UInt32(d[d.startIndex + off + 3])
        return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
    }

    // MARK: - base64url (no padding) — same flavour as v1 codec

    private static func base64URL(_ data: Data) -> String {
        var s = data.base64EncodedString()
        s = s.replacingOccurrences(of: "+", with: "-")
        s = s.replacingOccurrences(of: "/", with: "_")
        s = s.replacingOccurrences(of: "=", with: "")
        return s
    }
    private static func base64URLDecode(_ string: String) -> Data? {
        var s = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let padding = (4 - (s.count % 4)) % 4
        if padding > 0 { s.append(String(repeating: "=", count: padding)) }
        return Data(base64Encoded: s)
    }
}
