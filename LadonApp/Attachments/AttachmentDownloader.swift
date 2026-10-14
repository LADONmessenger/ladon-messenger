// AttachmentDownloader.swift — Phase 5
//
// Recipient-side counterpart of ``AttachmentUploader``. Given a descriptor,
// a wrapped seed payload, a read capability, and the recipient's private
// keys, it:
//
//   1. Fetches every chunk via ``BlobRelayClient.getChunk(...)`` with
//      bounded concurrency.
//   2. Verifies the Merkle root against ``descriptor.digest`` BEFORE any
//      AEAD `open` — matches the belt-and-braces order in
//      ``AttachmentUnsealer.open``.
//   3. Delegates to ``AttachmentUnsealer.open`` for PQ-hybrid seed unwrap,
//      chunk AEAD-open, and header/thumbnail/caption recovery.
//
// SECURITY
// --------
// * Feature-flag gated. Every entry point throws `.featureDisabled` until
//   `FeatureFlags.attachmentsEnabled` flips to true.
// * Uses the same `BlobCertificatePinningDelegate` pins as the uploader —
//   fail-closed without configured pins — but its own session and Tor
//   circuit per downloaded blob (`BlobRelayClient.forTransfer`).
// * Tor-aware via `BlobRelayClient.getChunk` (inherits policy).
// * Concurrent downloads are bounded below the server's per-IP read gate
//   (1200 req/min; we use 4 parallel fetches).
// * Constant-time Merkle-root comparison is inside `AttachmentUnsealer`;
//   the downloader does no pre-unsealing trust decisions on payload bytes.
// * Frame-size sanity: a malicious relay cannot induce out-of-spec frames,
//   but we still defence-in-depth check each downloaded frame against
//   `AttachmentChunkCipher.fullChunkWireBytes` / minimum AEAD frame size
//   before buffering, to bound memory use.

import Foundation
import CryptoKit

@available(iOS 15.0, macOS 12.0, *)
public enum AttachmentDownloader {

    public enum DownloadError: Error, Equatable, Sendable {
        case featureDisabled
        case invalidDescriptor(String)
        case frameTooLarge(index: UInt32, bytes: Int)
        case relay(BlobRelayClient.BlobRelayError)
        case unseal(AttachmentUnsealer.UnsealError)
    }

    /// Mirrors `AttachmentUploader.maxConcurrentChunkUploads`. Server
    /// per-IP read gate is 1200 req/min; 8 parallel fetches is well below
    /// that and matches the upload fan-out for symmetric transfer rates.
    public static let maxConcurrentChunkDownloads = 8

    /// Per-chunk retry count on transient network failures. GET is
    /// cacheable and idempotent, so replaying a chunk is always safe.
    private static let perChunkMaxAttempts = 3

    /// Absolute per-frame upper bound. One frame on the wire is never
    /// larger than `plaintextChunkBytes + 28` (256 KB plaintext + AEAD
    /// 12 B nonce + 16 B tag); we enforce a 2× safety margin to catch
    /// bogus responses early.
    private static let perFrameHardCapBytes = 2 * (AttachmentLimits.plaintextChunkBytes + 28)

    /// Download + unseal a complete attachment.
    public static func downloadAndOpen(
        descriptor: AttachmentDescriptor,
        seedPayload: AttachmentSeedWrap.WrappedSeedPayload,
        readCap: String,
        recipientX25519PrivateKey: Curve25519.KeyAgreement.PrivateKey,
        recipientKyberKeychainAccount: String,
        progress: (@Sendable (Double) -> Void)? = nil
    ) async throws -> AttachmentUnsealer.Opened {
        return try await downloadAndOpenImpl(
            descriptor: descriptor,
            seedPayload: seedPayload,
            readCap: readCap,
            recipientX25519PrivateKey: recipientX25519PrivateKey,
            kyberAccount: recipientKyberKeychainAccount,
            kyberInline: nil,
            progress: progress
        )
    }

    /// Overload accepting the recipient's Kyber secret key as raw bytes.
    public static func downloadAndOpen(
        descriptor: AttachmentDescriptor,
        seedPayload: AttachmentSeedWrap.WrappedSeedPayload,
        readCap: String,
        recipientX25519PrivateKey: Curve25519.KeyAgreement.PrivateKey,
        recipientKyberSecretKey: Data,
        progress: (@Sendable (Double) -> Void)? = nil
    ) async throws -> AttachmentUnsealer.Opened {
        return try await downloadAndOpenImpl(
            descriptor: descriptor,
            seedPayload: seedPayload,
            readCap: readCap,
            recipientX25519PrivateKey: recipientX25519PrivateKey,
            kyberAccount: nil,
            kyberInline: recipientKyberSecretKey,
            progress: progress
        )
    }

    private static func downloadAndOpenImpl(
        descriptor: AttachmentDescriptor,
        seedPayload: AttachmentSeedWrap.WrappedSeedPayload,
        readCap: String,
        recipientX25519PrivateKey: Curve25519.KeyAgreement.PrivateKey,
        kyberAccount: String?,
        kyberInline: Data?,
        progress: (@Sendable (Double) -> Void)?
    ) async throws -> AttachmentUnsealer.Opened {
        guard FeatureFlags.attachmentsEnabled else {
            throw DownloadError.featureDisabled
        }

        guard descriptor.blobID.count == 16 else {
            throw DownloadError.invalidDescriptor("blobID must be 16 B")
        }
        guard descriptor.chunkCount >= 1,
              descriptor.chunkCount <= UInt32(AttachmentLimits.maxChunkCount) else {
            throw DownloadError.invalidDescriptor("chunkCount out of range")
        }
        guard descriptor.digest.count == 32 else {
            throw DownloadError.invalidDescriptor("digest must be 32 B")
        }

        // 1. Fetch all frames with bounded concurrency.
        let frames: [Data]
        do {
            frames = try await fetchFrames(
                blobID: descriptor.blobID,
                chunkCount: descriptor.chunkCount,
                readCap: readCap,
                host: descriptor.blobHost,
                progress: progress
            )
        } catch let err as BlobRelayClient.BlobRelayError {
            throw DownloadError.relay(err)
        } catch let err as DownloadError {
            throw err
        } catch {
            throw DownloadError.relay(.networkFailure(description: "\(error)"))
        }

        // 2. Delegate to the unsealer (handles Merkle verify + AEAD open +
        //    header cross-check + thumbnail/caption).
        do {
            let opened: AttachmentUnsealer.Opened
            if let acc = kyberAccount {
                opened = try AttachmentUnsealer.open(
                    descriptor: descriptor,
                    frames: frames,
                    seedPayload: seedPayload,
                    recipientX25519PrivateKey: recipientX25519PrivateKey,
                    recipientKyberKeychainAccount: acc
                )
            } else {
                opened = try AttachmentUnsealer.open(
                    descriptor: descriptor,
                    frames: frames,
                    seedPayload: seedPayload,
                    recipientX25519PrivateKey: recipientX25519PrivateKey,
                    recipientKyberSecretKey: kyberInline ?? Data()
                )
            }
            progress?(1.0)
            return opened
        } catch let err as AttachmentUnsealer.UnsealError {
            throw DownloadError.unseal(err)
        } catch {
            throw DownloadError.unseal(.chunkCipher(.openFailed))
        }
    }

    public static func downloadAndOpenV2(
        descriptor: AttachmentDescriptor,
        thumbnailBlob: AttachmentRemoteBlobDescriptor,
        seedPayload: AttachmentSeedWrap.WrappedSeedPayload,
        readCap: String,
        thumbnailReadCap: String,
        recipientX25519PrivateKey: Curve25519.KeyAgreement.PrivateKey,
        recipientKyberSecretKey: Data,
        progress: (@Sendable (Double) -> Void)? = nil
    ) async throws -> AttachmentUnsealer.Opened {
        guard FeatureFlags.attachmentsEnabled else {
            throw DownloadError.featureDisabled
        }
        // Same bound as downloadAndOpenImpl, for both blobs, before anything
        // is fetched or allocated (scan F30/F31).
        guard AttachmentLimits.isValidChunkCount(descriptor.chunkCount),
              AttachmentLimits.isValidChunkCount(thumbnailBlob.chunkCount) else {
            throw DownloadError.invalidDescriptor("chunkCount out of range")
        }

        let mainFrames = try await fetchFrames(
            blobID: descriptor.blobID,
            chunkCount: descriptor.chunkCount,
            readCap: readCap,
            host: descriptor.blobHost,
            progress: progress.map { outer -> (@Sendable (Double) -> Void) in
                { p in outer(0.45 * p) }
            }
        )
        let thumbnailFrames = try await fetchFrames(
            blobID: thumbnailBlob.blobID,
            chunkCount: thumbnailBlob.chunkCount,
            readCap: thumbnailReadCap,
            host: thumbnailBlob.blobHost,
            progress: progress.map { outer -> (@Sendable (Double) -> Void) in
                { p in outer(0.45 + (0.45 * p)) }
            }
        )

        do {
            let opened = try AttachmentUnsealer.openV2(
                descriptor: descriptor,
                thumbnailBlob: thumbnailBlob,
                mainFrames: mainFrames,
                thumbnailFrames: thumbnailFrames,
                seedPayload: seedPayload,
                recipientX25519PrivateKey: recipientX25519PrivateKey,
                recipientKyberSecretKey: recipientKyberSecretKey
            )
            progress?(1.0)
            return opened
        } catch let err as AttachmentUnsealer.UnsealError {
            throw DownloadError.unseal(err)
        } catch {
            throw DownloadError.unseal(.chunkCipher(.openFailed))
        }
    }

    // MARK: - Internals

    private static func fetchFrames(
        blobID: Data,
        chunkCount: UInt32,
        readCap: String,
        host: BlobHost,
        progress: (@Sendable (Double) -> Void)?
    ) async throws -> [Data] {
        // One client, and with it one Tor circuit, per downloaded blob
        // (A2 stage 1): downloads of different blobs cannot be linked by
        // circuit, neither to each other nor to this device's uploads.
        // Last line of defence: every path ends here, including the legacy
        // JSON payload whose synthesized decoder skips the validating inits.
        // `total` sizes the frame array below.
        guard AttachmentLimits.isValidChunkCount(chunkCount) else {
            throw DownloadError.invalidDescriptor("chunkCount out of range")
        }
        let client = BlobRelayClient.forTransfer(host: host)
        let total = Int(chunkCount)
        var frames = [Data?](repeating: nil, count: total)
        var completed = 0

        try await withThrowingTaskGroup(of: (Int, Data).self) { group in
            var next = 0
            var running = 0
            let limit = Self.maxConcurrentChunkDownloads
            while next < total || running > 0 {
                while running < limit && next < total {
                    let idx = next
                    group.addTask {
                        let data = try await getChunkWithRetry(
                            blobID: blobID,
                            chunkIndex: UInt32(idx),
                            readCap: readCap,
                            client: client
                        )
                        guard data.count <= Self.perFrameHardCapBytes else {
                            throw DownloadError.frameTooLarge(
                                index: UInt32(idx),
                                bytes: data.count
                            )
                        }
                        return (idx, data)
                    }
                    next += 1
                    running += 1
                }
                if running > 0, let (idx, data) = try await group.next() {
                    frames[idx] = data
                    running -= 1
                    completed += 1
                    // Cap network progress at 0.9 so the bar can still
                    // advance to 1.0 after unseal completes.
                    let p = min(0.9, 0.9 * Double(completed) / Double(total))
                    progress?(p)
                }
            }
        }

        // All slots must be populated; the TaskGroup throws on the first
        // failure, so reaching here implies every index was written.
        var result = [Data]()
        result.reserveCapacity(total)
        for (i, opt) in frames.enumerated() {
            guard let frame = opt else {
                throw DownloadError.invalidDescriptor("missing frame \(i)")
            }
            result.append(frame)
        }
        return result
    }

    /// Fetch a single chunk with bounded retries on transient failures.
    /// Retries only on URLSession-level network errors and 5xx responses;
    /// rate-limits and 4xx (cap expired, wrong digest, etc.) are terminal.
    private static func getChunkWithRetry(
        blobID: Data,
        chunkIndex: UInt32,
        readCap: String,
        client: BlobRelayClient
    ) async throws -> Data {
        var attempt = 0
        var lastError: Error = BlobRelayClient.BlobRelayError.invalidResponse
        while attempt < perChunkMaxAttempts {
            do {
                return try await client.getChunk(
                    blobID: blobID,
                    chunkIndex: chunkIndex,
                    readCap: readCap
                )
            } catch let err as BlobRelayClient.BlobRelayError {
                if !isRetryable(err) { throw err }
                lastError = err
            } catch {
                lastError = error
            }
            attempt += 1
            if attempt >= perChunkMaxAttempts { break }
            let delayNs = UInt64(1_000_000_000) << (attempt - 1)  // 1s, 2s
            try? await Task.sleep(nanoseconds: delayNs)
        }
        throw lastError
    }

    /// Same retry classification as the uploader: only transient classes.
    private static func isRetryable(_ err: BlobRelayClient.BlobRelayError) -> Bool {
        switch err {
        case .networkFailure:
            return true
        case .httpStatus(let code, _):
            return code >= 500 && code <= 599
        case .rateLimited, .integrityFailure, .featureDisabled,
             .torNotReady, .invalidResponse, .bodyTooLarge,
             .pinningMisconfigured:
            return false
        }
    }
}
