// AudioSanitizer.swift — Phase 6 (v2: AVAssetWriter)
//
// Re-encodes user-supplied audio input into a clean container with NO
// metadata and a bounded bitrate. Two modes:
//   * `.voice`: 32 kbps target, AAC-LC in M4A container, mono.
//   * `.audio`: 64 kbps target, AAC-LC in M4A container, mono.
//
// Implementation note (2026-05-07):
// We deliberately use `AVAssetReader` + `AVAssetWriter` instead of
// `AVAssetExportSession`. The export-session path produced M4A files
// whose `moov` atom landed at the *end* of the bytes for short voice
// recordings (despite `shouldOptimizeForNetworkUse=true`). The receiver
// loads the bytes with `AVAudioPlayer(data:fileTypeHint:)` — a non-
// seekable in-memory parser — which then fails with `OSStatus 56 …` /
// "Audio not playable" because it cannot find `moov` before the audio
// data. AVAssetWriter writes `moov` deterministically at the *front*
// when `shouldOptimizeForNetworkUse=true` after `finishWriting`, so the
// in-RAM player succeeds.
//
// Threat model mirrors ``VideoSanitizer``:
//   * Input size capped (``audioMaxInputBytes``).
//   * Duration capped for voice mode (``voiceMaxDurationSeconds`` = 600 s).
//   * All metadata stripped: writer is constructed with no `metadata`
//     entries, source PCM samples carry no metadata, and the output
//     container is rebuilt from scratch.
//
// Feature-flag gated — callers must check ``FeatureFlags.attachmentsEnabled``.

import Foundation
import AVFoundation
import AudioToolbox

public enum AudioSanitizer {

    public enum Mode: Sendable {
        case voice
        case audio
    }

    public enum Error: Swift.Error, Equatable {
        case inputTooLarge(bytes: Int)
        case writeTempFailed
        case unreadableAsset
        case noAudioTrack
        case durationExceeded(seconds: Int)
        case exportFailed(String)
        case outputTooLarge(bytes: Int)
    }

    public struct Result: Equatable {
        /// Sanitised M4A/AAC bytes, no metadata.
        public let audioData: Data
        /// Duration in milliseconds.
        public let durationMs: UInt32
        /// `.aac` — we always emit AAC-LC.
        public let mime: AttachmentMimeType
    }

    /// Output sample rate. 44.1 kHz keeps AAC-LC happy at low bitrates and
    /// matches the recorder side ([VoiceRecorderOverlay.swift]) so the
    /// re-encoder rarely has to up/down-sample.
    private static let outputSampleRate: Double = 44_100

    public static func sanitise(
        _ input: Data,
        mode: Mode
    ) async throws -> Result {
        guard input.count <= AttachmentLimits.audioMaxInputBytes else {
            throw Error.inputTooLarge(bytes: input.count)
        }

        let tempDir = FileManager.default.temporaryDirectory
        let inURL = tempDir.appendingPathComponent("ladon-aud-in-\(UUID().uuidString).m4a")
        let outURL = tempDir.appendingPathComponent("ladon-aud-out-\(UUID().uuidString).m4a")
        defer {
            try? FileManager.default.removeItem(at: inURL)
            try? FileManager.default.removeItem(at: outURL)
        }
        do {
            // FIX AUDIT3-IOS-16: plaintext user audio gets an explicit
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

        let audioTracks = try await asset.loadTracks(withMediaType: .audio)
        guard let sourceTrack = audioTracks.first else { throw Error.noAudioTrack }

        let duration = try await asset.load(.duration)
        let durationSecs = Int(CMTimeGetSeconds(duration))
        if mode == .voice, durationSecs > AttachmentLimits.voiceMaxDurationSeconds {
            throw Error.durationExceeded(seconds: durationSecs)
        }

        try await transcode(
            sourceAsset: asset,
            sourceTrack: sourceTrack,
            outputURL: outURL,
            mode: mode
        )

        // FIX AUDIT3-IOS-16: AVAssetWriter creates the file with the
        // default protection class; set it explicitly — the re-encoded
        // plaintext is still the user's voice.
        try? FileManager.default.setAttributes(
            [.protectionKey: FileProtectionType.complete],  // P8-AUDIT8-IOS-26
            ofItemAtPath: outURL.path
        )
        let outData: Data
        do {
            outData = try Data(contentsOf: outURL)
        } catch {
            throw Error.exportFailed("read output: \(error.localizedDescription)")
        }

        // Safety net: voice mode must fit in a 4 MB bucket; cap output here
        // so a pathologically long clip can't quietly hit the 50 MB cap.
        let softCap = (mode == .voice)
            ? 4 * 1_024 * 1_024
            : AttachmentLimits.plaintextHardCapBytes
        guard outData.count <= softCap else {
            throw Error.outputTooLarge(bytes: outData.count)
        }

        let durationMs = UInt32(
            clamping: Int(CMTimeGetSeconds(duration) * 1000.0)
        )

        // Self-test: we just produced bytes the recipient is going to
        // load via `AVAudioPlayer(data:fileTypeHint:.m4a)` — a non-
        // seekable in-RAM parser. Verify NOW that those bytes actually
        // satisfy that parser, on the SAME OS that just wrote them. If
        // they don't, fail the send loudly instead of silently shipping
        // unplayable bytes that will only blow up on the recipient.
        do {
            _ = try AVAudioPlayer(data: outData, fileTypeHint: AVFileType.m4a.rawValue)
        } catch {
            let ns = error as NSError
            throw Error.exportFailed(
                "self-test AVAudioPlayer load failed: \(ns.domain) \(ns.code) — \(error.localizedDescription)"
            )
        }

        return Result(
            audioData: outData,
            durationMs: durationMs,
            mime: .aac
        )
    }

    // MARK: - Transcode

    /// Decompress source samples to interleaved PCM via `AVAssetReader`,
    /// re-encode to AAC-LC via `AVAssetWriter`, and ensure `moov` sits at
    /// the front of the resulting M4A so a non-seekable in-RAM player
    /// like `AVAudioPlayer(data:)` can parse it.
    private static func transcode(
        sourceAsset: AVURLAsset,
        sourceTrack: AVAssetTrack,
        outputURL: URL,
        mode: Mode
    ) async throws {
        // Reader: pull interleaved 16-bit signed PCM, mono, at the
        // output sample rate. The decompressor handles the rate conversion
        // for free; we don't need vDSP/AudioConverter here.
        // nonisolated(unsafe): Die vier AVFoundation-Objekte werden weiter unten
        // in einem @Sendable-Block gefangen, den requestMediaDataWhenReady(on:)
        // garantiert seriell auf EINER Queue aufruft — es gibt kein Datenrennen.
        // AVFoundation deklariert diese Typen bis heute nicht als Sendable,
        // deshalb die explizite Zusicherung statt einer Umstrukturierung.
        nonisolated(unsafe) let reader: AVAssetReader
        do {
            reader = try AVAssetReader(asset: sourceAsset)
        } catch {
            throw Error.exportFailed("reader init: \(error.localizedDescription)")
        }

        let pcmSettings: [String: Any] = [
            AVFormatIDKey: kAudioFormatLinearPCM,
            AVSampleRateKey: outputSampleRate,
            AVNumberOfChannelsKey: 1,
            AVLinearPCMBitDepthKey: 16,
            AVLinearPCMIsFloatKey: false,
            AVLinearPCMIsBigEndianKey: false,
            AVLinearPCMIsNonInterleaved: false
        ]
        nonisolated(unsafe) let readerOutput = AVAssetReaderTrackOutput(track: sourceTrack, outputSettings: pcmSettings)
        readerOutput.alwaysCopiesSampleData = false
        guard reader.canAdd(readerOutput) else {
            throw Error.exportFailed("reader cannot add output")
        }
        reader.add(readerOutput)

        // Writer: AAC-LC, M4A, mono, target bitrate per mode. With
        // `shouldOptimizeForNetworkUse=true` the writer rearranges atoms
        // on `finishWriting` so `moov` lands before `mdat`.
        nonisolated(unsafe) let writer: AVAssetWriter
        do {
            writer = try AVAssetWriter(outputURL: outputURL, fileType: .m4a)
        } catch {
            throw Error.exportFailed("writer init: \(error.localizedDescription)")
        }
        writer.metadata = []
        writer.shouldOptimizeForNetworkUse = true
        // Non-fragmented MP4 — fragments would defeat the front-loaded
        // `moov` invariant we rely on for the in-RAM player.
        writer.movieFragmentInterval = .invalid

        let bitrate: Int = (mode == .voice) ? 32_000 : 64_000

        var channelLayout = AudioChannelLayout()
        channelLayout.mChannelLayoutTag = kAudioChannelLayoutTag_Mono
        let channelLayoutData = Data(
            bytes: &channelLayout,
            count: MemoryLayout<AudioChannelLayout>.size
        )

        let aacSettings: [String: Any] = [
            AVFormatIDKey: kAudioFormatMPEG4AAC,
            AVSampleRateKey: outputSampleRate,
            AVNumberOfChannelsKey: 1,
            AVChannelLayoutKey: channelLayoutData,
            AVEncoderBitRateKey: bitrate,
            AVEncoderAudioQualityKey: AVAudioQuality.medium.rawValue
        ]
        nonisolated(unsafe) let writerInput = AVAssetWriterInput(mediaType: .audio, outputSettings: aacSettings)
        writerInput.expectsMediaDataInRealTime = false
        guard writer.canAdd(writerInput) else {
            throw Error.exportFailed("writer cannot add input")
        }
        writer.add(writerInput)

        guard reader.startReading() else {
            throw Error.exportFailed(
                "reader.startReading: \(reader.error?.localizedDescription ?? "unknown")"
            )
        }
        guard writer.startWriting() else {
            throw Error.exportFailed(
                "writer.startWriting: \(writer.error?.localizedDescription ?? "unknown")"
            )
        }
        writer.startSession(atSourceTime: .zero)

        // Pump samples on a dedicated serial queue. We bridge to async via
        // a continuation so the caller stays cleanly `await`-able.
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Swift.Error>) in
            let queue = DispatchQueue(label: "app.ladon.audiosanitizer.transcode")
            writerInput.requestMediaDataWhenReady(on: queue) {
                while writerInput.isReadyForMoreMediaData {
                    if let sample = readerOutput.copyNextSampleBuffer() {
                        if !writerInput.append(sample) {
                            // Stop further requests; surface the writer error.
                            writerInput.markAsFinished()
                            reader.cancelReading()
                            let err = writer.error
                                ?? NSError(domain: "AudioSanitizer", code: -1,
                                           userInfo: [NSLocalizedDescriptionKey: "writer append failed"])
                            cont.resume(throwing: Error.exportFailed(err.localizedDescription))
                            return
                        }
                    } else {
                        // No more samples (or reader error). Wrap up.
                        writerInput.markAsFinished()
                        if reader.status == .failed {
                            let err = reader.error?.localizedDescription ?? "reader failed"
                            cont.resume(throwing: Error.exportFailed(err))
                            return
                        }
                        writer.finishWriting {
                            if writer.status == .completed {
                                cont.resume()
                            } else {
                                let err = writer.error?.localizedDescription
                                    ?? "writer status \(writer.status.rawValue)"
                                cont.resume(throwing: Error.exportFailed(err))
                            }
                        }
                        return
                    }
                }
            }
        }
    }
}
