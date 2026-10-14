// BlobRelayClient.swift — Phase 4 (sharded since 2026-05-14)
//
// HTTP client for a SPECIFIC blob-relay shard, for exactly ONE blob transfer
// (upload, download or delete of one blob). Each instance owns its own pinned
// URLSession and with it its own Tor circuit (Addendum A2 stage 1).
//
// Routes (v1, identical across shards — see docs/research/PHASE3_SERVER_SPEC.md):
//
//   POST   /v1/blob/init                init a blob, get 3 capability tokens
//   PUT    /v1/blob/{id}/{index}        upload one AEAD chunk
//   POST   /v1/blob/{id}/finalize       submit Merkle root, seal blob
//   GET    /v1/blob/{id}/{index}        download one AEAD chunk
//   DELETE /v1/blob/{id}                explicit delete via delete_cap
//   GET    /v1/blob/pubkey              fetch server Ed25519 verifying key
//
// SECURITY
// --------
// * Gated by `FeatureFlags.attachmentsEnabled` — every public method fails
//   closed with `.featureDisabled` until the flag is flipped.
// * TLS traffic runs through `BlobCertificatePinningDelegate.shared(for:)`
//   for THIS shard, whose pin set is empty by default — handshakes fail
//   until deploy-time pins are added. Defence-in-depth against flag flips
//   without deploys.
// * No identity (Addendum A2 stage 1). Uploads used to carry the long-term
//   Ed25519 key and an HMAC under a provisioned per-identity secret; that
//   gave the relay a stable pseudonym per upload (scan F9) while protecting
//   nothing — provisioning was open to any new key. Every request is now
//   authorised by its capability token alone (init by nothing but the
//   relay's own limits).
// * One Tor circuit per blob transfer: uploads and downloads of different
//   blobs cannot be linked to one client by circuit (scan F22).
// * The relay's `Date` header feeds only `ClockSyncV2.blob` (scan F21).
// * Tor enforcement: mandatory (no opt-out) — refuses to upload when Tor
//   is not ready (fail-closed).
// * No sensitive data is logged. On error we emit slug + HTTP status only.
//
// REENTRANCY
// ----------
// An `actor` to serialise cached state (server pubkey, last-known server
// time). Upload fan-out uses a bounded `TaskGroup` inside
// `AttachmentUploader` — this class exposes only per-chunk primitives.

import Foundation
import CryptoKit
import Security
#if DEBUG
import os.log
#endif

@available(iOS 15.0, macOS 12.0, *)
public actor BlobRelayClient {

    #if DEBUG
    /// Diagnostic logger — DEBUG builds only. Visible in macOS Console.app
    /// with filter `subsystem:app.ladon.messenger.blob`.
    nonisolated static let diagLog = OSLog(
        subsystem: "app.ladon.messenger.blob",
        category: "relay"
    )
    #endif

    // MARK: - Configuration

    /// Shard this client talks to. Fixed at init time.
    public nonisolated let host: BlobHost

    /// Hard cap on HTTP body size for PUT /chunk. Chunk wire size is
    /// `AttachmentChunkCipher.fullChunkWireBytes` = 256 KB + 28 B AEAD =
    /// 262 172 B. Spec §6.3 caps request bodies at 800 000 B.
    static let maxChunkBodyBytes = 800_000

    // MARK: - One client per transfer

    /// A client with its own Tor circuit for one blob transfer. Use one
    /// instance for every request of that transfer (init, chunks, finalize —
    /// or all chunk downloads of one blob) and a new one for the next blob.
    /// There is deliberately no shared instance: a shared session put every
    /// transfer of this device on one circuit.
    public static func forTransfer(host: BlobHost) -> BlobRelayClient {
        BlobRelayClient(host: host,
                        session: BlobCertificatePinningDelegate.shared(for: host).makeIsolatedSession())
    }

    /// Test seam — substitute a custom URLSession (e.g. bypassing pinning for
    /// a local blob-relay). Release builds ignore this.
    #if DEBUG
    nonisolated(unsafe) static var debugSessionOverride: URLSession?
    nonisolated(unsafe) static var debugBaseURLOverride: String?
    #endif

    /// This transfer's session; `nil` when Tor had no SOCKS endpoint at
    /// creation — every request then fails closed with `.torNotReady`.
    private let session: URLSession?

    private init(host: BlobHost, session: URLSession?) {
        self.host = host
        self.session = session
    }

    deinit {
        // Let in-flight requests finish, then release the session (a
        // URLSession retains its delegate until invalidated).
        session?.finishTasksAndInvalidate()
    }

    // MARK: - Errors

    public enum BlobRelayError: Error, Equatable, Sendable {
        case featureDisabled
        case torNotReady
        case invalidResponse
        case bodyTooLarge(bytes: Int)
        case httpStatus(code: Int, slug: String?)
        case rateLimited(retryAfter: TimeInterval?)
        case networkFailure(description: String)
        case integrityFailure
        case pinningMisconfigured
    }

    // MARK: - Public API

    /// Initialise a new blob. Server reserves disk quota and returns three
    /// capability tokens (upload/read/delete). The caller is responsible
    /// for persisting `readCap` / `deleteCap` alongside the message body;
    /// `uploadCap` is short-lived (15 min) and should be consumed immediately.
    public func initBlob(
        blobID: Data,
        chunkCount: UInt32,
        bucket: UInt8,
        expiresAt: UInt64
    ) async throws -> InitResponse {
        try Self.requireFeatureEnabled()
        try await Self.requireTorReady()

        guard blobID.count == 16 else { throw BlobRelayError.invalidResponse }
        // P7-BLOB-04: keep in lockstep with server `MAX_CHUNK_COUNT = 128`,
        // which is bounded by the 128-bit capability chunk_mask width.
        guard chunkCount >= 1 && chunkCount <= 128 else { throw BlobRelayError.invalidResponse }
        guard bucket >= 1 && bucket <= 8 else { throw BlobRelayError.invalidResponse }

        let body = try Self.encodeInitBody(
            blobID: blobID,
            chunkCount: chunkCount,
            bucket: bucket,
            expiresAt: expiresAt
        )
        var request = try Self.makeRequest(path: "/v1/blob/init", method: "POST", host: host)
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = body

        let (data, http) = try await perform(request)
        try Self.ensureStatus(http, data: data, expected: 200)
        return try Self.decodeInit(data)
    }

    /// Upload a single AEAD chunk frame. `chunkIndex` is 0-based.
    /// `uploadCap` must be the token returned by `initBlob`. Idempotent:
    /// replaying the same (index, bytes) returns 200; differing bytes for
    /// the same index returns 409 (`.httpStatus(409, "conflict")`).
    public func putChunk(
        blobID: Data,
        chunkIndex: UInt32,
        frame: Data,
        uploadCap: String
    ) async throws {
        try Self.requireFeatureEnabled()
        try await Self.requireTorReady()

        guard blobID.count == 16 else { throw BlobRelayError.invalidResponse }
        guard frame.count <= Self.maxChunkBodyBytes else {
            throw BlobRelayError.bodyTooLarge(bytes: frame.count)
        }

        let path = "/v1/blob/\(blobID.hexString())/\(chunkIndex)"
        var request = try Self.makeRequest(path: path, method: "PUT", host: host)
        request.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type")
        request.setValue(uploadCap, forHTTPHeaderField: "x-ladon-blob-capability")
        request.httpBody = frame

        let (data, http) = try await perform(request)
        try Self.ensureStatus(http, data: data, expected: 200)
    }

    /// Submit the Merkle root and seal the blob. Mismatch → server deletes
    /// the blob and returns 422 `.integrity`; we surface `.integrityFailure`.
    public func finalize(
        blobID: Data,
        merkleRoot: Data,
        uploadCap: String
    ) async throws {
        try Self.requireFeatureEnabled()
        try await Self.requireTorReady()

        guard blobID.count == 16, merkleRoot.count == 32 else {
            throw BlobRelayError.invalidResponse
        }

        let body = try Self.encodeFinalizeBody(digestHex: merkleRoot.hexString())
        let path = "/v1/blob/\(blobID.hexString())/finalize"
        var request = try Self.makeRequest(path: path, method: "POST", host: host)
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(uploadCap, forHTTPHeaderField: "x-ladon-blob-capability")
        request.httpBody = body

        let (data, http) = try await perform(request)
        if http.statusCode == 422 {
            throw BlobRelayError.integrityFailure
        }
        try Self.ensureStatus(http, data: data, expected: 200)
    }

    /// Download a single AEAD chunk.
    public func getChunk(
        blobID: Data,
        chunkIndex: UInt32,
        readCap: String
    ) async throws -> Data {
        try Self.requireFeatureEnabled()
        try await Self.requireTorReady()

        guard blobID.count == 16 else { throw BlobRelayError.invalidResponse }
        let path = "/v1/blob/\(blobID.hexString())/\(chunkIndex)"
        var request = try Self.makeRequest(path: path, method: "GET", host: host)
        request.setValue(readCap, forHTTPHeaderField: "x-ladon-blob-capability")

        let (data, http) = try await perform(request)
        try Self.ensureStatus(http, data: data, expected: 200)
        return data
    }

    /// Explicit delete via `deleteCap`. Server always returns 204 to
    /// prevent existence-probing; callers cannot distinguish "deleted"
    /// from "never existed".
    public func deleteBlob(blobID: Data, deleteCap: String) async throws {
        try Self.requireFeatureEnabled()
        try await Self.requireTorReady()

        guard blobID.count == 16 else { throw BlobRelayError.invalidResponse }
        let path = "/v1/blob/\(blobID.hexString())"
        var request = try Self.makeRequest(path: path, method: "DELETE", host: host)
        request.setValue(deleteCap, forHTTPHeaderField: "x-ladon-blob-capability")

        let (_, http) = try await perform(request)
        // 204 = success. 404/410 also acceptable (spec-defined idempotency).
        switch http.statusCode {
        case 204, 404, 410:
            return
        default:
            throw BlobRelayError.httpStatus(code: http.statusCode, slug: nil)
        }
    }

    /// Fetch the server's Ed25519 capability verifying key (unauthenticated).
    public func fetchServerPubkey() async throws -> Data {
        try Self.requireFeatureEnabled()
        try await Self.requireTorReady()

        var request = try Self.makeRequest(path: "/v1/blob/pubkey", method: "GET", host: host)
        request.setValue("application/json", forHTTPHeaderField: "Accept")

        let (data, http) = try await perform(request)
        try Self.ensureStatus(http, data: data, expected: 200)
        struct PubkeyResponse: Decodable { let pubkey: String }
        let decoded = try JSONDecoder().decode(PubkeyResponse.self, from: data)
        guard let bytes = Data(hexString: decoded.pubkey), bytes.count == 32 else {
            throw BlobRelayError.invalidResponse
        }
        return bytes
    }

    // MARK: - Responses

    public struct InitResponse: Equatable, Sendable {
        public let uploadCap: String
        public let readCap: String
        public let deleteCap: String
        public let chunkSize: Int
    }

    // MARK: - Feature gating

    private static func requireFeatureEnabled() throws {
        guard FeatureFlags.attachmentsEnabled else { throw BlobRelayError.featureDisabled }
    }

    private static func requireTorReady() async throws {
        // Tor is mandatory (security principle #1 — no opt-out toggle). Refuse
        // to dial out unless the Tor SOCKS5 proxy is ready — fail-closed.
        let ready = await MainActor.run { TorManager.shared.isTorReady }
        guard ready else { throw BlobRelayError.torNotReady }
    }

    // MARK: - Request building

    private static func makeRequest(path: String, method: String, host: BlobHost) throws -> URLRequest {
        #if DEBUG
        let base = debugBaseURLOverride ?? host.baseURLString
        #else
        let base = host.baseURLString
        #endif
        guard let url = URL(string: base + path) else {
            throw BlobRelayError.invalidResponse
        }
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        return request
    }

    private func perform(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        let resolved: URLSession?
        #if DEBUG
        resolved = Self.debugSessionOverride ?? self.session
        #else
        resolved = self.session
        #endif
        // FAIL-CLOSED (P8-AUDIT5-IOS-C2): the session is nil when no Tor
        // SOCKS5 config was available. Refuse to dial out over a non-Tor path
        // that would de-anonymize blob traffic. Symmetric with V2SessionManager.
        guard let session = resolved else {
            throw BlobRelayError.torNotReady
        }
        #if DEBUG
        let method = request.httpMethod ?? "?"
        let path = request.url?.path ?? "?"
        let t0 = Date()
        os_log("-> %{public}@ %{public}@", log: Self.diagLog, type: .info, method, path)
        #endif
        do {
            let (data, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse else {
                #if DEBUG
                os_log("<- %{public}@ %{public}@ invalidResponse (no HTTPURLResponse)",
                       log: Self.diagLog, type: .error, method, path)
                #endif
                throw BlobRelayError.invalidResponse
            }
            // The blob relay's own clock (A2 stage 1): its `Date` header must not
            // move the clock that stamps fetches or `sent_at` (scan F21).
            ClockSyncV2.blob.observe(http)
            #if DEBUG
            let ms = Int(Date().timeIntervalSince(t0) * 1000)
            os_log("<- %{public}@ %{public}@ status=%{public}d in %{public}dms",
                   log: Self.diagLog, type: .info, method, path, http.statusCode, ms)
            #endif
            return (data, http)
        } catch let err as BlobRelayError {
            throw err
        } catch {
            #if DEBUG
            let ns = error as NSError
            let ms = Int(Date().timeIntervalSince(t0) * 1000)
            os_log(
                "<- %{public}@ %{public}@ FAIL domain=%{public}@ code=%{public}d desc=%{public}@ after=%{public}dms",
                log: Self.diagLog, type: .error,
                method, path, ns.domain, ns.code, ns.localizedDescription, ms
            )
            #endif
            throw BlobRelayError.networkFailure(description: error.localizedDescription)
        }
    }

    private static func ensureStatus(
        _ http: HTTPURLResponse,
        data: Data,
        expected: Int
    ) throws {
        if http.statusCode == expected { return }
        if http.statusCode == 429 || http.statusCode == 503 {
            let retry = (http.value(forHTTPHeaderField: "Retry-After"))
                .flatMap(TimeInterval.init)
            throw BlobRelayError.rateLimited(retryAfter: retry)
        }
        let slug = try? JSONDecoder()
            .decode(ErrorResponse.self, from: data).error
        throw BlobRelayError.httpStatus(code: http.statusCode, slug: slug)
    }

    private struct ErrorResponse: Decodable { let error: String }

    // MARK: - Body encoders / decoders

    private static func encodeInitBody(
        blobID: Data,
        chunkCount: UInt32,
        bucket: UInt8,
        expiresAt: UInt64
    ) throws -> Data {
        // Spec §6.2: JSON { blob_id: 32hex, chunk_count, bucket, expires_at }
        struct InitBody: Encodable {
            let blob_id: String
            let chunk_count: UInt32
            let bucket: UInt8
            let expires_at: UInt64
        }
        let body = InitBody(
            blob_id: blobID.hexString(),
            chunk_count: chunkCount,
            bucket: bucket,
            expires_at: expiresAt
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(body)
    }

    private static func encodeFinalizeBody(digestHex: String) throws -> Data {
        struct FinalBody: Encodable { let digest: String }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(FinalBody(digest: digestHex))
    }

    private static func decodeInit(_ data: Data) throws -> InitResponse {
        struct Raw: Decodable {
            let upload_cap: String
            let read_cap: String
            let delete_cap: String
            let chunk_size: Int
        }
        let raw = try JSONDecoder().decode(Raw.self, from: data)
        guard raw.chunk_size > 0 else { throw BlobRelayError.invalidResponse }
        return InitResponse(
            uploadCap: raw.upload_cap,
            readCap: raw.read_cap,
            deleteCap: raw.delete_cap,
            chunkSize: raw.chunk_size
        )
    }
}

// MARK: - Hex helpers
//
// `Data.init?(hexString:)` and `Data.hexEncodedString` already exist in
// `Security/SecurityExtensions.swift`. We expose a local `hexString()`
// method for symmetry with callers written during Phase 4 prototyping.

private extension Data {
    func hexString() -> String { hexEncodedString }
}
