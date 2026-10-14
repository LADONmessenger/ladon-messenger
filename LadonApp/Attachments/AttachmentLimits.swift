// AttachmentLimits.swift — Phase 1
//
// Hard limits consumed by sanitisation, chunking and UI validation. Values
// reflect the spec approved on 21. April 2026.

import Foundation

public enum AttachmentLimits {

    // MARK: Input (before re-encode)

    /// Maximum input file size for images. Larger inputs are rejected *before*
    /// decoding to avoid decompression-bomb attacks.
    public static let imageMaxInputBytes = 16 * 1_024 * 1_024          // 16 MB

    /// Maximum input file size for videos. Re-encode via `VideoSanitizer`
    /// (540p H.264 MediumQuality) brings typical iPhone 17 Pro recordings
    /// well under the server-side bucket ceiling regardless of input size.
    /// Raised 50 → 100 MB on 2026-05-14 to accept high-bitrate iPhone clips.
    public static let videoMaxInputBytes = 100 * 1_024 * 1_024         // 100 MB

    /// Maximum input file size for audio.
    public static let audioMaxInputBytes = 16 * 1_024 * 1_024          // 16 MB

    /// Maximum voice-memo duration in seconds (10 minutes).
    public static let voiceMaxDurationSeconds: Int = 600

    // MARK: Re-encode parameters

    /// Longest-edge pixel cap after re-encode. Downscale-only; images with
    /// either dimension above this are resized preserving aspect ratio.
    /// 2 048 px (was 4 096): a 12 MP iPhone photo at 4 096 px and quality
    /// 0.85 stayed at 2–3 MB and was padded to the 4 MB bucket — there is
    /// none between 1 MB and 4 MB — so every photo cost the recipient 4 MB
    /// over Tor. At 2 048 px it lands in the 1 MB bucket, ~4× less to fetch.
    public static let imageMaxPixelEdge: Int = 2_048

    /// JPEG quality factor (0.0–1.0).
    public static let jpegReencodeQuality: CGFloat = 0.85

    // #36: removed videoHeightCap / videoFrameRateCap / videoAudioBitrateBps —
    // they were never referenced in code. The actual re-encode is driven by
    // AVAssetExportPresetMediumQuality in VideoSanitizer (see its header note).

    /// Audio re-encode targets.
    public static let audioReencodeBitrateBps: Int = 64_000
    public static let voiceReencodeBitrateBps: Int = 32_000

    // MARK: Chunking

    /// Plaintext chunk size before AEAD wrapping. Phase 2 code will AEAD
    /// each chunk individually and HMAC-chain them.
    public static let plaintextChunkBytes: Int = 256 * 1_024           // 256 KB

    /// Hard ceiling on chunk count — in lockstep with the blob-relay
    /// `MAX_CHUNK_COUNT` (util.rs) and the capability chunk_mask width (128 bits).
    /// Blobs needing more are rejected by `AttachmentSealer.sealBlob`. #29 keeps
    /// the download/upload validators aligned with this instead of an ad-hoc 1024.
    public static let maxChunkCount: Int = 128

    /// True for 1...maxChunkCount. The single check for every chunk count
    /// that arrives from a peer (descriptors, download entry points): the
    /// receiver allocates per chunk, so an unchecked value let one message
    /// crash the app (scan F30/F31).
    public static func isValidChunkCount(_ count: UInt32) -> Bool {
        count >= 1 && count <= UInt32(maxChunkCount)
    }

    // MARK: Thumbnail

    /// Longest-edge for thumbnails (WebP).
    public static let thumbnailEdgePixels: Int = 256

    /// Target plaintext WebP thumbnail size (encoder quality targets this,
    /// final ciphertext is padded to the fixed envelope slot regardless).
    public static let thumbnailTargetPlaintextBytes: Int = 3 * 1_024   // ≈ 3 KB

    // MARK: Hard caps for safety nets

    /// Absolute ceiling for any plaintext payload before chunking. Anything
    /// above this is rejected even if the individual media type limit would
    /// accept it.
    // 16 MiB statt der frueheren 50 MB: Die Quittung des Blob-Relays ist eine
    // 128-Bit-Maske, also passen hoechstens 128 Stuecke a 256 KiB in einen
    // Upload. Der groesste Bucket, der darunter bleibt, ist b16MB (65 Stuecke);
    // b50MB braeuchte 201 und war damit nie sendbar. Die alte 50-MB-Angabe hat
    // dazu gefuehrt, dass Dateien zwischen 16 und 50 MB erst nach der kompletten
    // Aufbereitung scheiterten, statt vorher abgelehnt zu werden.
    public static let plaintextHardCapBytes: Int = 16 * 1_024 * 1_024  // 16 MiB
}
