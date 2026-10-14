// AttachmentPreparation.swift — Phase 1
//
// Glue layer that wires together the three Phase-1 building blocks
// (sanitise → thumbnail → pad) into a single call. Returns a prepared bundle
// that Phase 2 will encrypt and Phase 4 will upload.
//
// The public entry point is feature-flag-gated via
// ``FeatureFlags.attachmentsEnabled``. While the flag is false the function
// throws ``PreparationError.featureDisabled`` *before* touching any input.
// This keeps the code-path inert on release builds of the current version.

import Foundation
import AVFoundation
import CoreGraphics
import ImageIO
import Security
import UniformTypeIdentifiers

public enum AttachmentPreparation {

    public enum PreparationError: Swift.Error, Equatable {
        case featureDisabled
        case imageSanitizer(ImageSanitizer.Error)
        case thumbnail(ThumbnailGenerator.Error)
        case bucketing(BucketPadding.Error)
        case videoSanitizer(VideoSanitizer.Error)
        case audioSanitizer(AudioSanitizer.Error)
        case videoThumbnailFailed
    }

    /// Output bundle of the Phase-1 pipeline. Everything is plaintext still.
    /// Phase 2 will wrap ``paddedPlaintext`` and ``thumbnailPlaintext`` into
    /// AEAD chunks + a sealed thumbnail slot.
    public struct Prepared: Equatable {
        public let mime: AttachmentMimeType
        public let bucket: AttachmentBucket
        public let realLength: Int
        public let paddedPlaintext: Data
        public let thumbnailPlaintext: Data
        public let dimensions: AttachmentDimensions

        public init(
            mime: AttachmentMimeType,
            bucket: AttachmentBucket,
            realLength: Int,
            paddedPlaintext: Data,
            thumbnailPlaintext: Data,
            dimensions: AttachmentDimensions
        ) {
            self.mime = mime
            self.bucket = bucket
            self.realLength = realLength
            self.paddedPlaintext = paddedPlaintext
            self.thumbnailPlaintext = thumbnailPlaintext
            self.dimensions = dimensions
        }
    }

    /// Image pipeline. Returns a prepared bundle ready for Phase-2 sealing.
    ///
    /// - Parameter input: raw file bytes. Must be ≤
    ///   ``AttachmentLimits.imageMaxInputBytes``.
    /// - Throws: ``PreparationError`` on any stage failure. Errors are
    ///   intentionally coarse-grained — the caller either retries with a
    ///   smaller / different file or surfaces a generic UI error.
    public static func prepareImage(_ input: Data) throws -> Prepared {
        guard FeatureFlags.attachmentsEnabled else {
            throw PreparationError.featureDisabled
        }

        let sanitised: ImageSanitizer.Result
        do {
            sanitised = try ImageSanitizer.sanitise(input)
        } catch let error as ImageSanitizer.Error {
            throw PreparationError.imageSanitizer(error)
        }

        let thumbnail: Data
        do {
            thumbnail = try ThumbnailGenerator.thumbnailJPEG(from: sanitised.jpegData)
        } catch let error as ThumbnailGenerator.Error {
            throw PreparationError.thumbnail(error)
        }

        let padded: (padded: Data, bucket: AttachmentBucket, realLength: Int)
        do {
            padded = try BucketPadding.pad(sanitised.jpegData)
        } catch let error as BucketPadding.Error {
            throw PreparationError.bucketing(error)
        }

        return Prepared(
            mime: .jpeg,
            bucket: padded.bucket,
            realLength: padded.realLength,
            paddedPlaintext: padded.padded,
            thumbnailPlaintext: thumbnail,
            dimensions: sanitised.dimensions
        )
    }

    // MARK: - Video

    /// Video pipeline. Re-encodes to H.264 720p MP4 (no metadata), generates
    /// a thumbnail from the first extractable frame, and pads into a bucket.
    @available(iOS 15.0, macOS 12.0, *)
    public static func prepareVideo(_ input: Data) async throws -> Prepared {
        guard FeatureFlags.attachmentsEnabled else {
            throw PreparationError.featureDisabled
        }

        let sanitised: VideoSanitizer.Result
        do {
            sanitised = try await VideoSanitizer.sanitise(input)
        } catch let e as VideoSanitizer.Error {
            throw PreparationError.videoSanitizer(e)
        }

        // Thumbnail: first extractable frame, re-encoded via ImageSanitizer +
        // ThumbnailGenerator so the thumbnail carries no EXIF/orientation.
        // If extraction fails (corrupt input, 0-frame edge cases, codec
        // issues) we fall back to a random placeholder rather than aborting
        // the whole send — the receiver UI shows a play-icon placeholder.
        let thumb: Data
        if let vt = try? await videoThumbnail(mp4: sanitised.mp4Data) {
            thumb = vt
        } else {
            thumb = try randomThumbnailPlaceholder()
        }

        let padded: (padded: Data, bucket: AttachmentBucket, realLength: Int)
        do {
            padded = try BucketPadding.pad(sanitised.mp4Data)
        } catch let e as BucketPadding.Error {
            throw PreparationError.bucketing(e)
        }

        return Prepared(
            mime: .mp4h264,
            bucket: padded.bucket,
            realLength: padded.realLength,
            paddedPlaintext: padded.padded,
            thumbnailPlaintext: thumb,
            dimensions: sanitised.dimensions
        )
    }

    // MARK: - Audio / Voice

    /// Voice-memo pipeline. 32 kbps target (preset-limited) M4A/AAC,
    /// no metadata, duration-capped at ``voiceMaxDurationSeconds``.
    @available(iOS 15.0, macOS 12.0, *)
    public static func prepareVoice(_ input: Data) async throws -> Prepared {
        return try await prepareAudioCommon(input, mode: .voice)
    }

    /// Generic audio pipeline (music / longer clips). 64 kbps target
    /// M4A/AAC, no metadata, size-capped by the 50 MB hard cap.
    @available(iOS 15.0, macOS 12.0, *)
    public static func prepareAudio(_ input: Data) async throws -> Prepared {
        return try await prepareAudioCommon(input, mode: .audio)
    }

    @available(iOS 15.0, macOS 12.0, *)
    private static func prepareAudioCommon(
        _ input: Data,
        mode: AudioSanitizer.Mode
    ) async throws -> Prepared {
        guard FeatureFlags.attachmentsEnabled else {
            throw PreparationError.featureDisabled
        }

        let sanitised: AudioSanitizer.Result
        do {
            sanitised = try await AudioSanitizer.sanitise(input, mode: mode)
        } catch let e as AudioSanitizer.Error {
            throw PreparationError.audioSanitizer(e)
        }

        // Audio attachments still require a thumbnail slot (4 KB fixed).
        // Populate it with random bytes via BucketPadding — the receiver
        // UI shows a waveform icon, not the slot content.
        let thumb = try randomThumbnailPlaceholder()

        let padded: (padded: Data, bucket: AttachmentBucket, realLength: Int)
        do {
            padded = try BucketPadding.pad(sanitised.audioData)
        } catch let e as BucketPadding.Error {
            throw PreparationError.bucketing(e)
        }

        return Prepared(
            mime: sanitised.mime,
            bucket: padded.bucket,
            realLength: padded.realLength,
            paddedPlaintext: padded.padded,
            thumbnailPlaintext: thumb,
            dimensions: AttachmentDimensions(
                width: 0, height: 0, durationMs: sanitised.durationMs
            )
        )
    }

    // MARK: - Helpers

    /// Extract frame at t=0 and pass it through the image sanitiser +
    /// thumbnail generator so the output is a clean, metadata-free JPEG
    /// thumbnail. Falls back to a random-padded placeholder if the frame
    /// extraction fails (corrupt or 0-frame inputs).
    @available(iOS 15.0, macOS 12.0, *)
    private static func videoThumbnail(mp4: Data) async throws -> Data {
        let tempDir = FileManager.default.temporaryDirectory
        let url = tempDir.appendingPathComponent("ladon-vthumb-\(UUID().uuidString).mp4")
        // FIX AUDIT3-IOS-17: plaintext user video gets an explicit protection
        // class (see Audio/VideoSanitizer).
        // P8-AUDIT8-IOS-26: `.complete` — the strongest class: the plaintext is unreadable whenever the device is locked. `completeUnlessOpen` (used before) keeps a file readable through an open handle across lock and was a downgrade from the app's default (com.apple.developer.default-data-protection = NSFileProtectionComplete). A lock mid-transcode now fails the send (fail-closed).
        try mp4.write(to: url, options: [.atomic, .completeFileProtection])
        defer { try? FileManager.default.removeItem(at: url) }

        let asset = AVURLAsset(url: url)
        let generator = AVAssetImageGenerator(asset: asset)
        generator.appliesPreferredTrackTransform = true
        generator.requestedTimeToleranceBefore = .positiveInfinity
        generator.requestedTimeToleranceAfter = .positiveInfinity
        generator.maximumSize = CGSize(
            width: AttachmentLimits.thumbnailEdgePixels,
            height: AttachmentLimits.thumbnailEdgePixels
        )

        // Try a few candidate times: 0, 0.1s, 1s, duration*0.1. Some videos
        // have no dekodierbares frame at exactly t=0 (non-keyframe start,
        // black-frame intros, codec quirks).
        let duration: CMTime
        if #available(iOS 16.0, *) {
            duration = (try? await asset.load(.duration)) ?? .zero
        } else {
            duration = asset.duration
        }
        var candidates: [CMTime] = [
            CMTime(seconds: 0, preferredTimescale: 600),
            CMTime(seconds: 0.1, preferredTimescale: 600),
            CMTime(seconds: 1.0, preferredTimescale: 600),
        ]
        if duration.isValid, duration.seconds > 0 {
            candidates.append(CMTime(seconds: duration.seconds * 0.1, preferredTimescale: 600))
        }

        var cgImage: CGImage? = nil
        for time in candidates {
            if let img = try? await generator.image(at: time).image {
                cgImage = img
                break
            }
        }
        guard let cgImage else {
            throw PreparationError.videoThumbnailFailed
        }

        // Encode the frame as JPEG with no metadata, then run the result
        // through ThumbnailGenerator to enforce the size ladder.
        let mutable = NSMutableData()
        guard let dest = CGImageDestinationCreateWithData(
            mutable as CFMutableData,
            UTType.jpeg.identifier as CFString, 1, nil
        ) else {
            throw PreparationError.videoThumbnailFailed
        }
        let encodeOptions: [CFString: Any] = [
            kCGImageDestinationLossyCompressionQuality: AttachmentLimits.jpegReencodeQuality,
            kCGImagePropertyExifDictionary: [:],
            kCGImagePropertyGPSDictionary: [:],
            kCGImagePropertyIPTCDictionary: [:],
            kCGImagePropertyTIFFDictionary: [:],
        ]
        CGImageDestinationAddImage(dest, cgImage, encodeOptions as CFDictionary)
        guard CGImageDestinationFinalize(dest) else {
            throw PreparationError.videoThumbnailFailed
        }

        do {
            return try ThumbnailGenerator.thumbnailJPEG(from: mutable as Data)
        } catch let e as ThumbnailGenerator.Error {
            throw PreparationError.thumbnail(e)
        }
    }

    /// Random-bytes placeholder for the thumbnail slot in audio prepares.
    /// The slot is fixed-size at the AEAD layer; random bytes reveal no
    /// information beyond "this attachment has no visual thumbnail".
    private static func randomThumbnailPlaceholder() throws -> Data {
        let size = AttachmentLimits.thumbnailTargetPlaintextBytes
        var bytes = Data(count: size)
        let status = bytes.withUnsafeMutableBytes { buf -> Int32 in
            guard let base = buf.baseAddress else { return errSecAllocate }
            return SecRandomCopyBytes(kSecRandomDefault, size, base)
        }
        guard status == errSecSuccess else {
            throw PreparationError.bucketing(.rngFailed)
        }
        return bytes
    }
}
