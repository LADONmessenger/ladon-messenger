// VideoSanitizer.swift — Phase 6
//
// Re-encodes user-supplied video input into a clean H.264/AAC MP4 that
// carries NO writer/author/creation-date/GPS metadata and whose dimensions
// are bounded by AVAssetExportPresetMediumQuality (~540p, aspect ratio
// preserved; AVFoundation never up-scales).
//
// Threat model:
//   * Input containers may embed arbitrary "udta"/"meta" atoms (EXIF-style
//     metadata, GPS, author, software). Re-encode via `AVAssetExportSession`
//     with our preset and `metadata = []` strips all of that.
//   * Malicious/oversized inputs are rejected by ``videoMaxInputBytes``
//     BEFORE the asset is opened; this bounds memory and avoids parser
//     trivia being exercised on adversarial inputs.
//   * Output UTI is locked to ``AVFileType.mp4`` so the encoder cannot
//     emit e.g. M4A fragments.
//
// Feature-flag gated — callers must check ``FeatureFlags.attachmentsEnabled``.

import Foundation
import AVFoundation
import UniformTypeIdentifiers

public enum VideoSanitizer {

    public enum Error: Swift.Error, Equatable {
        case inputTooLarge(bytes: Int)
        case writeTempFailed
        case unreadableAsset
        case noVideoTrack
        case exportFailed(String)
        case outputTooLarge(bytes: Int)
    }

    public struct Result: Equatable {
        /// Sanitised MP4 bytes (H.264 video + AAC audio, no metadata).
        public let mp4Data: Data
        /// Output pixel dimensions.
        public let dimensions: AttachmentDimensions
        /// Duration in milliseconds.
        public let durationMs: UInt32
    }

    /// Re-encode `input` into a sanitised MP4. Async because AVFoundation's
    /// export is inherently asynchronous; callers typically run this on a
    /// background task.
    public static func sanitise(_ input: Data) async throws -> Result {
        guard input.count <= AttachmentLimits.videoMaxInputBytes else {
            throw Error.inputTooLarge(bytes: input.count)
        }

        // Write to a temp file — AVAsset expects a URL for reliable parsing
        // across formats.
        let tempDir = FileManager.default.temporaryDirectory
        let inURL = tempDir.appendingPathComponent("ladon-vid-in-\(UUID().uuidString).mov")
        let outURL = tempDir.appendingPathComponent("ladon-vid-out-\(UUID().uuidString).mp4")
        defer {
            try? FileManager.default.removeItem(at: inURL)
            try? FileManager.default.removeItem(at: outURL)
        }
        do {
            // FIX AUDIT3-IOS-16: plaintext user video gets an explicit
            // protection class; the `defer` removeItem limits the on-disk window.
            // P8-AUDIT8-IOS-26: `.complete` — the strongest class: the plaintext is unreadable whenever the device is locked. `completeUnlessOpen` (used before) keeps a file readable through an open handle across lock and was a downgrade from the app's default (com.apple.developer.default-data-protection = NSFileProtectionComplete). A lock mid-transcode now fails the send (fail-closed).
            try input.write(to: inURL, options: [.atomic, .completeFileProtection])
        } catch {
            throw Error.writeTempFailed
        }

        let asset = AVURLAsset(
            url: inURL,
            options: [AVURLAssetPreferPreciseDurationAndTimingKey: true]
        )

        // Sanity-check that the asset has a video track — refuses audio-only
        // inputs dressed as video files.
        let videoTracks = try await asset.loadTracks(withMediaType: .video)
        guard !videoTracks.isEmpty else { throw Error.noVideoTrack }

        let duration = try await asset.load(.duration)
        let durationMs = UInt32(
            clamping: Int(CMTimeGetSeconds(duration) * 1000.0)
        )

        // Use AVAssetExportSession with `MediumQuality` — roughly 540p
        // with conservative bitrate. AVFoundation never up-scales, so
        // smaller inputs stay smaller. This preset is ~2× faster to encode
        // than `1280x720` on A15-class chips and produces ~40-50% smaller
        // output, which directly cuts Tor upload time. Quality is fine for
        // chat-sized playback.
        // Zwei Anlaeufe statt eines: erst MediumQuality (~540p), und nur wenn
        // das Ergebnis groesser ist als das, was sich versenden laesst, ein
        // zweiter Durchgang mit LowQuality. Vorher wurde in diesem Fall
        // abgebrochen — der Nutzer hatte dann minutenlang auf die Kodierung
        // gewartet und bekam am Ende bloss einen Fehler, obwohl eine kleinere
        // Fassung problemlos moeglich gewesen waere.
        let presets = [
            AVAssetExportPresetMediumQuality,
            AVAssetExportPresetLowQuality,
        ]
        var outData = Data()

        for (durchgang, presetName) in presets.enumerated() {
        // Ergebnis des vorherigen Durchgangs entfernen — AVAssetExportSession
        // verweigert den Export, wenn die Zieldatei bereits existiert.
        try? FileManager.default.removeItem(at: outURL)

        guard let export = AVAssetExportSession(
            asset: asset,
            presetName: presetName
        ) else {
            throw Error.exportFailed("no compatible exporter")
        }

        export.outputURL = outURL
        export.outputFileType = .mp4
        // We don't stream-play during download (recipient reassembles the
        // full file before playback), so the moov-atom-at-front rewrite
        // pass is wasted work. Disable to skip the second AVFoundation
        // pass and shave additional time off the encode.
        export.shouldOptimizeForNetworkUse = false
        // Hard metadata strip — an empty array tells AVAssetExport to emit
        // no udta/meta atoms whatsoever.
        export.metadata = []
        // Avoid leaking timing information about the source file-system
        // (e.g. creation date) via the mp4 creation time atom.
        export.metadataItemFilter = AVMetadataItemFilter.forSharing()

        await export.export()

        switch export.status {
        case .completed:
            break
        case .failed, .cancelled:
            throw Error.exportFailed(export.error?.localizedDescription ?? "unknown")
        default:
            throw Error.exportFailed("unexpected status \(export.status.rawValue)")
        }

        // FIX AUDIT3-IOS-16: set AVAssetExportSession's output protection
        // explicitly — the re-encoded video is still plaintext.
        try? FileManager.default.setAttributes(
            [.protectionKey: FileProtectionType.complete],  // P8-AUDIT8-IOS-26
            ofItemAtPath: outURL.path
        )
        do {
            outData = try Data(contentsOf: outURL)
        } catch {
            throw Error.exportFailed("read output: \(error.localizedDescription)")
        }
        if outData.count <= AttachmentLimits.plaintextHardCapBytes {
            break
        }
        // Auch der letzte Durchgang war zu gross — jetzt hilft nur noch eine
        // Meldung, die die tatsaechliche Groesse nennt.
        if durchgang == presets.count - 1 {
            throw Error.outputTooLarge(bytes: outData.count)
        }
        }

        // Track dimensions. Use the video track's natural size + transform.
        let track = videoTracks[0]
        let naturalSize = try await track.load(.naturalSize)
        let transform = try await track.load(.preferredTransform)
        let applied = naturalSize.applying(transform)
        let outW = UInt16(clamping: Int(abs(applied.width).rounded()))
        let outH = UInt16(clamping: Int(abs(applied.height).rounded()))

        return Result(
            mp4Data: outData,
            dimensions: AttachmentDimensions(
                width: outW, height: outH, durationMs: durationMs
            ),
            durationMs: durationMs
        )
    }
}
