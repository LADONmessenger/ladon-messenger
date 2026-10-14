// AttachmentTypes.swift — Phase 1 (Foundation)
//
// Wire-format enums and structs for the attachment feature. All types are
// Codable-stable so envelopes produced today remain decodable in later phases.
//
// Activation gate: ``FeatureFlags.attachmentsEnabled``. As long as the flag
// is false nothing in this file is exercised on any code path.
//
// DESIGN NOTES
// ------------
// * Every field that leaves the device is either AEAD-wrapped (blob seed,
//   caption, thumbnail ciphertext — see Phase 2) or lives in a fixed-size
//   bucket / enumerated space. No free-form strings (filenames, EXIF,
//   MIME strings) are ever serialized.
// * All numeric constants are duplicated from spec review (see session memory
//   /memories/session/attachment-plan.md) to have a single build-time source
//   of truth.

import Foundation

// MARK: - Whitelist MIME

/// MIME-type whitelist. Each case corresponds to a single acceptable output
/// format after client-side re-encoding. The raw `UInt8` value is what is
/// serialized on the wire — *never* a string.
///
/// NOTE — intentionally missing formats:
/// * PDF, Office (DOCX/XLSX), ZIP/RAR, SVG, GIF, APK, HTML/JS: explicitly
///   excluded per spec (RCE/parser-exploit surface area, user decision
///   21. April 2026).
public enum AttachmentMimeType: UInt8, Codable, Sendable, CaseIterable {
    case jpeg    = 0x01  // image/jpeg (re-encoded, EXIF stripped)
    case png     = 0x02  // image/png
    case webp    = 0x03  // image/webp (thumbnails + optional full images)
    case mp4h264 = 0x04  // video/mp4 + H.264/AAC (re-encoded 720p)
    case opus    = 0x05  // audio/ogg + Opus (voice memos, 32 kbps)
    case aac     = 0x06  // audio/m4a + AAC (re-encoded 64 kbps)

    /// Filesystem extension hint for UI "save to vault" flows.
    public var fileExtension: String {
        switch self {
        case .jpeg:    return "jpg"
        case .png:     return "png"
        case .webp:    return "webp"
        case .mp4h264: return "mp4"
        case .opus:    return "ogg"
        case .aac:     return "m4a"
        }
    }

    /// Apple UTI string for `UIDocumentInteractionController` and `QLPreview`.
    /// Only used client-side; never serialized.
    public var uti: String {
        switch self {
        case .jpeg:    return "public.jpeg"
        case .png:     return "public.png"
        case .webp:    return "org.webmproject.webp"
        case .mp4h264: return "public.mpeg-4"
        case .opus:    return "org.xiph.ogg-audio"
        case .aac:     return "public.mpeg-4-audio"
        }
    }

    public var isImage: Bool { self == .jpeg || self == .png || self == .webp }
    public var isVideo: Bool { self == .mp4h264 }
    public var isAudio: Bool { self == .opus || self == .aac }
}

// MARK: - Size buckets

/// Eight size buckets for padding the plaintext *before* chunking and
/// encryption. Classifying a payload into one of eight buckets reduces the
/// leak of exact file size to a global passive observer (stronger than
/// Signal's implicit padding).
///
/// The bucket bound is in *bytes of plaintext*, **after** re-encoding and
/// before chunk-level AEAD framing.
public enum AttachmentBucket: UInt8, Codable, Sendable, CaseIterable {
    case b1KB    = 0x01  // 1 024
    case b16KB   = 0x02  // 16 384
    case b128KB  = 0x03  // 131 072
    case b512KB  = 0x04  // 524 288
    case b1MB    = 0x05  // 1 048 576
    case b4MB    = 0x06  // 4 194 304
    case b16MB   = 0x07  // 16 777 216
    case b50MB   = 0x08  // 52 428 800 (hard cap after re-encode)

    /// Plaintext payload size this bucket pads up to.
    public var byteSize: Int {
        switch self {
        case .b1KB:   return 1_024
        case .b16KB:  return 16_384
        case .b128KB: return 131_072
        case .b512KB: return 524_288
        case .b1MB:   return 1_048_576
        case .b4MB:   return 4_194_304
        case .b16MB:  return 16_777_216
        case .b50MB:  return 52_428_800
        }
    }

    /// Select the smallest bucket that fits `size`. Returns `nil` when the
    /// payload exceeds the largest bucket (50 MB hard cap).
    public static func smallestFitting(_ size: Int) -> AttachmentBucket? {
        precondition(size >= 0, "negative size is impossible")
        for bucket in AttachmentBucket.allCases {
            if size <= bucket.byteSize { return bucket }
        }
        return nil
    }
}

// MARK: - Pixel dimensions (images / videos)

/// Pixel dimensions used for layout hinting in the receiver's UI (avoids
/// thumbnail re-computation). Serialized as two `UInt16` — we do not support
/// images wider than 65 535 px, which is well above our 4 096 px re-encode
/// cap.
public struct AttachmentDimensions: Codable, Sendable, Equatable {
    public let width: UInt16
    public let height: UInt16
    /// Duration in milliseconds for video/audio; 0 for images.
    public let durationMs: UInt32

    public init(width: UInt16, height: UInt16, durationMs: UInt32 = 0) {
        self.width = width
        self.height = height
        self.durationMs = durationMs
    }
}

// MARK: - External blob descriptor (Option-C)

/// Metadata for an attachment blob that travels outside the main descriptor's
/// inline slots. Used by Option-C where the thumbnail is uploaded as its own
/// blob instead of occupying the fixed 4 KB inline thumbnail field.
public struct AttachmentRemoteBlobDescriptor: Codable, Sendable, Equatable {
    public let blobID: Data
    public let bucket: AttachmentBucket
    public let chunkCount: UInt32
    public let digest: Data
    /// Blob-relay shard the blob lives on. Set by the sender at upload
    /// time, read by the receiver to route GET /chunk requests to the
    /// correct shard. Wire format v4+ carries this as a single byte.
    public let blobHost: BlobHost

    public static let blobIDByteCount = 16
    public static let digestByteCount = 32

    public enum ValidationError: Error, Equatable {
        case blobIDSize
        case digestSize
        case chunkCountRange
    }

    public init(
        blobID: Data,
        bucket: AttachmentBucket,
        chunkCount: UInt32,
        digest: Data,
        blobHost: BlobHost
    ) throws {
        guard blobID.count == Self.blobIDByteCount else {
            throw ValidationError.blobIDSize
        }
        guard digest.count == Self.digestByteCount else {
            throw ValidationError.digestSize
        }
        // chunkCount comes from the peer and sizes the receiver's download
        // buffer; unbounded it let one message crash the app (scan F30/F31).
        guard AttachmentLimits.isValidChunkCount(chunkCount) else {
            throw ValidationError.chunkCountRange
        }

        self.blobID = blobID
        self.bucket = bucket
        self.chunkCount = chunkCount
        self.digest = digest
        self.blobHost = blobHost
    }
}

// MARK: - Descriptor

/// Descriptor carried inside the Double-Ratchet message envelope.
///
/// Size budget: this struct, encoded with `JSONEncoder` for the Phase-1
/// in-memory path (a compact CBOR encoder will replace JSON in Phase 3
/// when the wire-format is finalised), must fit into the remaining envelope
/// payload *together with* the caption and thumbnail ciphertext. The 4 KB
/// thumbnail + 1 KB caption + ~200 B descriptor header leaves ~11 KB
/// headroom in a 16 KB envelope.
public struct AttachmentDescriptor: Codable, Sendable, Equatable {
    /// Random 16-byte blob identifier. Not derived from identity or content.
    public let blobID: Data
    /// Wire-format version. Phase-1 = 1. Older receivers reject newer
    /// descriptors explicitly.
    public let version: UInt8
    public let mime: AttachmentMimeType
    public let bucket: AttachmentBucket
    public let dimensions: AttachmentDimensions
    /// Number of 256 KB ciphertext chunks in the blob (set in Phase 2).
    public let chunkCount: UInt32
    /// Sealed 32-byte blob master seed. Phase-1 carries 0-filled placeholder;
    /// Phase-2 replaces with PQ-hybrid wrap of the real seed.
    public let sealedSeed: Data
    /// BLAKE3 digest of the padded plaintext. Filled in Phase 2.
    public let digest: Data
    /// WebP thumbnail ciphertext. Fixed 4 096 bytes (random-padded if the
    /// real thumbnail is smaller).
    public let sealedThumbnail: Data
    /// Optional AEAD-sealed caption (≤ 1 024 bytes, random-padded). Phase-1
    /// permits `nil`.
    public let sealedCaption: Data?
    /// Option-C thumbnail blob metadata. When present, the receiver fetches
    /// the thumbnail from a separate blob using `thumbnailReadCap` from the
    /// transport payload instead of opening `sealedThumbnail` inline.
    public let thumbnailBlob: AttachmentRemoteBlobDescriptor?
    /// Blob-relay shard the main blob lives on. Active-active sharding,
    /// added with wire format v4 (14.05.2026). Wire-encoded as a single
    /// byte by `AttachmentMessagePayloadV2`.
    public let blobHost: BlobHost

    public static let currentVersion: UInt8 = 1
    public static let blobIDByteCount = 16
    public static let sealedSeedByteCount = 32
    public static let digestByteCount = 32
    public static let sealedThumbnailByteCount = 4_096
    public static let sealedCaptionMaxByteCount = 1_024

    public enum ValidationError: Error, Equatable {
        case blobIDSize
        case sealedSeedSize
        case digestSize
        case sealedThumbnailSize
        case sealedCaptionSize
        case unsupportedVersion(UInt8)
        case chunkCountRange
    }

    public init(
        blobID: Data,
        version: UInt8 = AttachmentDescriptor.currentVersion,
        mime: AttachmentMimeType,
        bucket: AttachmentBucket,
        dimensions: AttachmentDimensions,
        chunkCount: UInt32,
        sealedSeed: Data,
        digest: Data,
        sealedThumbnail: Data,
        sealedCaption: Data?,
        thumbnailBlob: AttachmentRemoteBlobDescriptor? = nil,
        blobHost: BlobHost
    ) throws {
        guard blobID.count == Self.blobIDByteCount
            else { throw ValidationError.blobIDSize }
        guard sealedSeed.count == Self.sealedSeedByteCount
            else { throw ValidationError.sealedSeedSize }
        guard digest.count == Self.digestByteCount
            else { throw ValidationError.digestSize }
        guard sealedThumbnail.count == Self.sealedThumbnailByteCount
            else { throw ValidationError.sealedThumbnailSize }
        if let cap = sealedCaption,
           cap.count > Self.sealedCaptionMaxByteCount {
            throw ValidationError.sealedCaptionSize
        }
        guard version == Self.currentVersion
            else { throw ValidationError.unsupportedVersion(version) }
        // See AttachmentRemoteBlobDescriptor: peer-controlled, sizes the
        // download buffer (scan F30/F31).
        guard AttachmentLimits.isValidChunkCount(chunkCount)
            else { throw ValidationError.chunkCountRange }

        self.blobID = blobID
        self.version = version
        self.mime = mime
        self.bucket = bucket
        self.dimensions = dimensions
        self.chunkCount = chunkCount
        self.sealedSeed = sealedSeed
        self.digest = digest
        self.sealedThumbnail = sealedThumbnail
        self.sealedCaption = sealedCaption
        self.thumbnailBlob = thumbnailBlob
        self.blobHost = blobHost
    }
}
