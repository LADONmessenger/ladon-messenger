// AttachmentUploader.swift — Phase 4
//
// Orchestrates the full lifecycle of uploading an ``AttachmentSealer.Sealed``
// bundle to the blob-relay:
//
//   1. POST /v1/blob/init    → obtain upload/read/delete caps
//   2. PUT  /v1/blob/{id}/{i} for each chunk (bounded concurrency)
//   3. POST /v1/blob/{id}/finalize with the Merkle root
//
// SECURITY
// --------
// * Feature-flag gated — every entry point rejects calls while
//   ``FeatureFlags.attachmentsEnabled`` is false.
// * Tor-aware — Tor is mandatory; uploads go through `BlobRelayClient`,
//   which refuses to dial out unless the Tor SOCKS5 proxy is ready.
// * On any chunk failure we invoke `BlobRelayClient.deleteBlob(...)`
//   with the delete cap to release the reserved quota. The delete is
//   best-effort (logged only); server-side GC would eventually reclaim it
//   anyway but explicit cleanup is hygienic and matches spec §7.2.
// * On finalize integrity failure the server has already deleted the blob;
//   we surface `.integrityFailure` so the caller can retry from the top.

import Foundation
import CryptoKit
#if DEBUG
import os.log
#endif

@available(iOS 15.0, macOS 12.0, *)
public enum AttachmentUploader {

    #if DEBUG
    private static let diagLog = OSLog(
        subsystem: "app.ladon.messenger.blob",
        category: "uploader"
    )
    #endif

    public enum UploadError: Error, Equatable, Sendable {
        case featureDisabled
        case invalidSealed(String)
        case relay(BlobRelayClient.BlobRelayError)
    }

    /// Receipt returned to the caller. `readCap` travels alongside the
    /// descriptor in the message body (so the recipient can pull chunks);
    /// `deleteCap` is retained by the sender for explicit revocation.
    ///
    /// `host` is the blob-relay shard this blob lives on. The receiver
    /// reads the same value out of the wire-format descriptor (v4+) to
    /// route its GET /chunk requests.
    public struct Receipt: Equatable, Sendable {
        public let blobID: Data
        public let readCap: String
        public let deleteCap: String
        public let chunkCount: UInt32
        public let bucket: UInt8
        public let expiresAt: UInt64
        public let host: BlobHost

        public init(
            blobID: Data,
            readCap: String,
            deleteCap: String,
            chunkCount: UInt32,
            bucket: UInt8,
            expiresAt: UInt64,
            host: BlobHost
        ) {
            self.blobID = blobID
            self.readCap = readCap
            self.deleteCap = deleteCap
            self.chunkCount = chunkCount
            self.bucket = bucket
            self.expiresAt = expiresAt
            self.host = host
        }
    }

    public struct ReceiptV2: Equatable, Sendable {
        public let main: Receipt
        public let thumbnail: Receipt

        public init(main: Receipt, thumbnail: Receipt) {
            self.main = main
            self.thumbnail = thumbnail
        }
    }

    /// Maximum concurrent chunk uploads per blob. Server-side per-IP gate
    /// is 8 (spec §8). V2 uploads main + thumbnail blob in parallel
    /// (`uploadV2`), so we cap each blob at 4 to keep total in-flight
    /// requests under the 8-permit gate.
    public static let maxConcurrentChunkUploads = 4

    /// Per-chunk retry count on transient network failures. Applies to
    /// URLSession errors and 5xx responses; rate-limits (429/503) and
    /// integrity failures are not retried by the uploader — they
    /// propagate so the caller can react.
    private static let perChunkMaxAttempts = 3

    /// Upload a sealed bundle to the blob-relay.
    ///
    /// - Parameters:
    ///   - sealed:      Output of `AttachmentSealer.seal(...)`.
    ///   - ttlSeconds:  Blob retention. Clamped to spec-allowed range
    ///                  [60, 48 × 3600]. Defaults to 24h.
    /// - Returns: `Receipt` with the caps that need to travel with the
    ///   message body (readCap) or be kept by the sender (deleteCap).
    public static func upload(
        _ sealed: AttachmentSealer.Sealed,
        host: BlobHost,
        ttlSeconds: UInt64 = 24 * 3600,
        progress: (@Sendable (Double) -> Void)? = nil
    ) async throws -> Receipt {
        guard FeatureFlags.attachmentsEnabled else {
            throw UploadError.featureDisabled
        }

        // Validate invariants before doing any network I/O.
        guard sealed.blobID.count == 16 else {
            throw UploadError.invalidSealed("blobID must be 16 B")
        }
        guard !sealed.frames.isEmpty, sealed.frames.count <= AttachmentLimits.maxChunkCount else {
            throw UploadError.invalidSealed("chunk count out of range")
        }
        guard sealed.descriptor.digest.count == 32 else {
            throw UploadError.invalidSealed("digest must be 32 B")
        }
        guard sealed.frames.count == Int(sealed.descriptor.chunkCount) else {
            throw UploadError.invalidSealed("frame count / descriptor mismatch")
        }

        return try await uploadBlob(
            blobID: sealed.blobID,
            frames: sealed.frames,
            chunkCount: sealed.descriptor.chunkCount,
            bucket: sealed.descriptor.bucket,
            digest: sealed.descriptor.digest,
            host: host,
            ttlSeconds: ttlSeconds,
            progress: progress
        )
    }

    public static func uploadV2(
        _ sealed: AttachmentSealer.SealedV2,
        host: BlobHost,
        ttlSeconds: UInt64 = 24 * 3600,
        progress: (@Sendable (Double) -> Void)? = nil
    ) async throws -> ReceiptV2 {
        guard FeatureFlags.attachmentsEnabled else {
            throw UploadError.featureDisabled
        }

        // Upload main + thumbnail in parallel. Both blobs are independent
        // (separate blobIDs, uploadCaps, sealed key material). The combined
        // per-blob chunk concurrency stays at or below the server's 8-permit
        // per-IP gate (see maxConcurrentChunkUploads). Progress is merged
        // additively from two independent halves.
        //
        // ProgressTracker is a reference-type Sendable container so the
        // concurrent uploadBlob tasks mutate via method calls instead of
        // capturing `var` (which is an error in Swift 6 concurrency mode).
        final class ProgressTracker: @unchecked Sendable {
            private let lock = NSLock()
            private var main = 0.0
            private var thumb = 0.0
            func updateMain(_ p: Double) -> Double {
                lock.lock(); defer { lock.unlock() }
                main = p
                return 0.5 * main + 0.5 * thumb
            }
            func updateThumb(_ p: Double) -> Double {
                lock.lock(); defer { lock.unlock() }
                thumb = p
                return 0.5 * main + 0.5 * thumb
            }
        }
        let tracker = ProgressTracker()

        async let mainTask = uploadBlob(
            blobID: sealed.mainBlob.blobID,
            frames: sealed.mainBlob.frames,
            chunkCount: sealed.mainBlob.chunkCount,
            bucket: sealed.mainBlob.bucket,
            digest: sealed.mainBlob.digest,
            host: host,
            ttlSeconds: ttlSeconds,
            progress: progress.map { outer -> (@Sendable (Double) -> Void) in
                { p in outer(tracker.updateMain(p)) }
            }
        )
        async let thumbTask = uploadBlob(
            blobID: sealed.thumbnailBlob.blobID,
            frames: sealed.thumbnailBlob.frames,
            chunkCount: sealed.thumbnailBlob.chunkCount,
            bucket: sealed.thumbnailBlob.bucket,
            digest: sealed.thumbnailBlob.digest,
            host: host,
            ttlSeconds: ttlSeconds,
            progress: progress.map { outer -> (@Sendable (Double) -> Void) in
                { p in outer(tracker.updateThumb(p)) }
            }
        )

        // Await both. If either fails, best-effort delete the one that succeeded.
        let mainResult: Result<Receipt, Error>
        let thumbResult: Result<Receipt, Error>
        do { mainResult = .success(try await mainTask) } catch { mainResult = .failure(error) }
        do { thumbResult = .success(try await thumbTask) } catch { thumbResult = .failure(error) }

        switch (mainResult, thumbResult) {
        case let (.success(main), .success(thumbnail)):
            return ReceiptV2(main: main, thumbnail: thumbnail)
        case let (.success(main), .failure(err)):
            await bestEffortDelete(
                blobID: main.blobID,
                deleteCap: main.deleteCap,
                client: BlobRelayClient.forTransfer(host: host)
            )
            throw err
        case let (.failure(err), .success(thumb)):
            await bestEffortDelete(
                blobID: thumb.blobID,
                deleteCap: thumb.deleteCap,
                client: BlobRelayClient.forTransfer(host: host)
            )
            throw err
        case let (.failure(err), .failure(_)):
            throw err
        }
    }

    // MARK: - Internals

    private static func uploadChunks(
        frames: [Data],
        blobID: Data,
        uploadCap: String,
        client: BlobRelayClient,
        progress: (@Sendable (Double) -> Void)?
    ) async throws {
        // Bounded concurrency via an actor-scoped semaphore implemented as a
        // simple counting queue. `TaskGroup` would run them all in parallel,
        // which violates the per-IP 8-permit gate if chunkCount > 8.
        let limit = Self.maxConcurrentChunkUploads
        let total = frames.count
        var completed = 0
        try await withThrowingTaskGroup(of: Void.self) { group in
            var next = 0
            var running = 0
            while next < frames.count || running > 0 {
                while running < limit && next < frames.count {
                    let idx = next
                    let frame = frames[idx]
                    group.addTask {
                        try await putChunkWithRetry(
                            blobID: blobID,
                            chunkIndex: UInt32(idx),
                            frame: frame,
                            uploadCap: uploadCap,
                            client: client
                        )
                    }
                    next += 1
                    running += 1
                }
                if running > 0 {
                    try await group.next()
                    running -= 1
                    completed += 1
                    // Cap at 0.95 so finalize() gets the last sliver.
                    let p = min(0.95, 0.95 * Double(completed) / Double(total))
                    progress?(p)
                }
            }
        }
    }

    private static func uploadBlob(
        blobID: Data,
        frames: [Data],
        chunkCount: UInt32,
        bucket: AttachmentBucket,
        digest: Data,
        host: BlobHost,
        ttlSeconds: UInt64,
        progress: (@Sendable (Double) -> Void)?
    ) async throws -> Receipt {
        guard blobID.count == 16 else {
            throw UploadError.invalidSealed("blobID must be 16 B")
        }
        guard !frames.isEmpty, frames.count <= AttachmentLimits.maxChunkCount else {
            throw UploadError.invalidSealed("chunk count out of range")
        }
        guard digest.count == 32 else {
            throw UploadError.invalidSealed("digest must be 32 B")
        }
        guard frames.count == Int(chunkCount) else {
            throw UploadError.invalidSealed("frame count / descriptor mismatch")
        }

        let ttl = max(UInt64(60), min(ttlSeconds, UInt64(48 * 3600)))
        // The blob relay checks `expires_at` against its own clock, so it is
        // stamped with the clock that relay feeds (A2 stage 1).
        let expiresAt = ClockSyncV2.blob.nowSec() + ttl
        // One client, and with it one Tor circuit, for this blob's whole
        // upload: init, chunks, finalize, and the clean-up delete on failure.
        let client = BlobRelayClient.forTransfer(host: host)
        #if DEBUG
        let blobHex = blobID.prefix(4).map { String(format: "%02x", $0) }.joined()
        os_log("phase=init.start blob=%{public}@… shard=%{public}@ chunks=%{public}d bucket=%{public}d",
               log: diagLog, type: .info, blobHex, host.regionTag, Int(chunkCount), Int(bucket.rawValue))
        #endif

        // No identity and no provisioning (Addendum A2 stage 1): init is
        // authorised by the relay's own limits, every later request by the
        // capability it returns.
        let initResp: BlobRelayClient.InitResponse
        do {
            initResp = try await client.initBlob(
                blobID: blobID,
                chunkCount: chunkCount,
                bucket: bucket.rawValue,
                expiresAt: expiresAt
            )
        } catch let err as BlobRelayClient.BlobRelayError {
            throw UploadError.relay(err)
        }

        #if DEBUG
        os_log("phase=init.ok blob=%{public}@… → chunks.start", log: diagLog, type: .info, blobHex)
        #endif
        do {
            try await uploadChunks(
                frames: frames,
                blobID: blobID,
                uploadCap: initResp.uploadCap,
                client: client,
                progress: progress
            )
        } catch let err as BlobRelayClient.BlobRelayError {
            #if DEBUG
            os_log("phase=chunks.FAIL blob=%{public}@… err=%{public}@",
                   log: diagLog, type: .error, blobHex, String(describing: err))
            #endif
            await bestEffortDelete(blobID: blobID, deleteCap: initResp.deleteCap, client: client)
            throw UploadError.relay(err)
        } catch {
            #if DEBUG
            os_log("phase=chunks.FAIL blob=%{public}@… err=%{public}@",
                   log: diagLog, type: .error, blobHex, String(describing: error))
            #endif
            await bestEffortDelete(blobID: blobID, deleteCap: initResp.deleteCap, client: client)
            throw UploadError.relay(.networkFailure(description: "\(error)"))
        }

        #if DEBUG
        os_log("phase=chunks.ok blob=%{public}@… → finalize.start", log: diagLog, type: .info, blobHex)
        #endif
        do {
            try await client.finalize(
                blobID: blobID,
                merkleRoot: digest,
                uploadCap: initResp.uploadCap
            )
        } catch let err as BlobRelayClient.BlobRelayError {
            #if DEBUG
            os_log("phase=finalize.FAIL blob=%{public}@… err=%{public}@",
                   log: diagLog, type: .error, blobHex, String(describing: err))
            #endif
            if case .integrityFailure = err {
                throw UploadError.relay(.integrityFailure)
            }
            await bestEffortDelete(blobID: blobID, deleteCap: initResp.deleteCap, client: client)
            throw UploadError.relay(err)
        }
        #if DEBUG
        os_log("phase=finalize.ok blob=%{public}@… chunks=%{public}d DONE",
               log: diagLog, type: .info, blobHex, Int(chunkCount))
        #endif

        return Receipt(
            blobID: blobID,
            readCap: initResp.readCap,
            deleteCap: initResp.deleteCap,
            chunkCount: chunkCount,
            bucket: bucket.rawValue,
            expiresAt: expiresAt,
            host: host
        )
    }

    /// Upload a single chunk with bounded retries. Retries only on transient
    /// errors (network failure, 5xx). The server PUT endpoint is idempotent
    /// for identical (index, bytes) payloads per spec §6.3, so re-sending
    /// the same frame is safe.
    private static func putChunkWithRetry(
        blobID: Data,
        chunkIndex: UInt32,
        frame: Data,
        uploadCap: String,
        client: BlobRelayClient
    ) async throws {
        var attempt = 0
        var lastError: Error = BlobRelayClient.BlobRelayError.invalidResponse
        while attempt < perChunkMaxAttempts {
            do {
                try await client.putChunk(
                    blobID: blobID,
                    chunkIndex: chunkIndex,
                    frame: frame,
                    uploadCap: uploadCap
                )
                return
            } catch let err as BlobRelayClient.BlobRelayError {
                if !isRetryable(err) { throw err }
                lastError = err
            } catch {
                lastError = error
            }
            attempt += 1
            if attempt >= perChunkMaxAttempts { break }
            // Exponential backoff: 1s, 2s (4s would only hit on attempt 4).
            let delayNs = UInt64(1_000_000_000) << (attempt - 1)
            try? await Task.sleep(nanoseconds: delayNs)
        }
        throw lastError
    }

    /// Classify which BlobRelayError variants are worth retrying. Rate
    /// limits and integrity failures are terminal for this transfer.
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

    private static func bestEffortDelete(
        blobID: Data,
        deleteCap: String,
        client: BlobRelayClient
    ) async {
        do {
            try await client.deleteBlob(blobID: blobID, deleteCap: deleteCap)
        } catch {
            // Swallow — GC will reclaim eventually. We do not log payload
            // data; only the fact that a cleanup attempt failed.
            #if DEBUG
            print("[BlobUpload] best-effort delete failed: \(error)")
            #endif
        }
    }
}
