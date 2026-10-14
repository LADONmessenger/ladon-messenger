// AttachmentReceiveService.swift — Phase 8
//
// Recipient-side counterpart to ``AttachmentSendService``. Parses the
// wire payload embedded in ``Message.content``, downloads and unseals the
// blob via ``AttachmentDownloader``, and returns the plaintext bundle to
// the UI layer.
//
// A small in-memory cache keeps decrypted attachments around during the
// life of the chat view so tapping the bubble repeatedly does not
// re-download. Nothing is persisted to disk; the cache is purged on device
// lock and on emergency wipe, and entries expire via a short TTL (H1).

import Foundation
import CryptoKit
import ImageIO
#if canImport(UIKit)
import UIKit
#endif

@available(iOS 15.0, macOS 12.0, *)
public enum AttachmentReceiveService {

    public enum ReceiveError: Error, Equatable {
        case featureDisabled
        case notAnAttachmentMessage
        case malformed(String)
        case keysMissing
        case downloadFailed(String)
    }

    public struct Opened: Equatable {
        public let content: Data
        public let thumbnail: Data
        public let caption: Data?
        public let mime: AttachmentMimeType
        public let dimensions: AttachmentDimensions
    }

    /// Parse the payload (no network). Fast path for "is this an
    /// attachment message?" + descriptor inspection (mime/dimensions/size).
    ///
    /// Dispatches by wire marker:
    ///   * `\u{E000}LADON-ATT-V2:` — compact binary codec (used by V2 chats)
    ///   * `\u{E000}LADON-ATT-V1:` — legacy JSON codec (used by V1 chats)
    public static func parse(messageContent: String) throws -> AttachmentMessagePayload {
        // V2 binary codec (preferred — fits the V2 envelope budget).
        if AttachmentMessagePayloadV2.isAttachmentContent(messageContent) {
            do {
                return try AttachmentMessagePayloadV2.decode(fromMessageContent: messageContent).payload
            } catch let err as AttachmentMessagePayloadV2.WireError {
                throw ReceiveError.malformed("v2: " + String(describing: err))
            } catch {
                throw ReceiveError.malformed("v2: decode")
            }
        }
        // Legacy V1 JSON codec.
        guard AttachmentMessagePayload.isAttachmentContent(messageContent) else {
            throw ReceiveError.notAnAttachmentMessage
        }
        do {
            return try AttachmentMessagePayload.decode(fromMessageContent: messageContent)
        } catch let err as AttachmentMessagePayload.WireError {
            throw ReceiveError.malformed(String(describing: err))
        } catch {
            throw ReceiveError.malformed("decode")
        }
    }

    /// Download the blob and unseal everything. Called when the user taps
    /// the bubble. Networked; cancellable via Task cancellation.
    public static func downloadAndOpen(
        payload: AttachmentMessagePayload,
        contactID: String,
        progress: (@Sendable (Double) -> Void)? = nil
    ) async throws -> Opened {
        guard FeatureFlags.attachmentsEnabled else {
            throw ReceiveError.featureDisabled
        }

        // Pick the unwrap-key source based on whether this contact has a
        // V2 peer handle. V2 contacts carry no V1 ratchet session, so the
        // legacy `KeyManager` lookups would always fail — instead the
        // recipient identity for V2 lives in `IdentityStoreV2` and the
        // long-term HKEM keypair pairs `xSk` (X25519) with `kySk` (ML-KEM-768).
        let ourPrivKey: Curve25519.KeyAgreement.PrivateKey
        var ourKyberSK: Data
        if PeerStoreV2.exists(forContactId: contactID) {
            let identity: LocalIdentityV2
            do {
                identity = try IdentityStoreV2.loadOrGenerate()
            } catch {
                throw ReceiveError.keysMissing
            }
            ourPrivKey = identity.recipientHkemKp.xSk
            ourKyberSK = identity.recipientHkemKp.kySk
        } else {
            // Legacy V1 contacts have no V2 identity, and their attachment path
            // was retired with the V1 session store; such a blob cannot arrive
            // over the V2-only relay. Fail closed.
            throw ReceiveError.keysMissing
        }
        defer { ourKyberSK.securelyWipe() }

        let opened: AttachmentUnsealer.Opened
        do {
            if let thumbnailBlob = payload.descriptor.thumbnailBlob,
               let thumbnailReadCap = payload.thumbnailReadCap {
                opened = try await AttachmentDownloader.downloadAndOpenV2(
                    descriptor: payload.descriptor,
                    thumbnailBlob: thumbnailBlob,
                    seedPayload: payload.seed.unwrap(),
                    readCap: payload.readCap,
                    thumbnailReadCap: thumbnailReadCap,
                    recipientX25519PrivateKey: ourPrivKey,
                    recipientKyberSecretKey: ourKyberSK,
                    progress: progress
                )
            } else {
                opened = try await AttachmentDownloader.downloadAndOpen(
                    descriptor: payload.descriptor,
                    seedPayload: payload.seed.unwrap(),
                    readCap: payload.readCap,
                    recipientX25519PrivateKey: ourPrivKey,
                    recipientKyberSecretKey: ourKyberSK,
                    progress: progress
                )
            }
        } catch {
            throw ReceiveError.downloadFailed(describe(error))
        }

        // P8-AUDIT8-IOS-08: the bytes are chosen by the sending peer. Only
        // what our own sender produces is handed to the system decoders.
        try ContentGate.validate(opened.content, mime: payload.descriptor.mime)
        return Opened(
            content: opened.content,
            thumbnail: ContentGate.thumbnailOrEmpty(opened.thumbnail),
            caption: opened.caption,
            mime: payload.descriptor.mime,
            dimensions: payload.descriptor.dimensions
        )
    }

    /// Receive-side format gate (audit F11, CWE-1287).
    ///
    /// Decryption proves who sent an attachment, not what format it is.
    /// `UIImage(data:)` and AVFoundation sniff the format from the bytes, so a
    /// modified client could label any ImageIO/AVFoundation format as `.jpeg`
    /// and reach parsers the product never meant to expose — the delivery
    /// path of FORCEDENTRY/BLASTPASS-class exploits. Our sender only ever
    /// produces (and historically produced) JPEG images, MP4 video and M4A
    /// audio (AttachmentPreparation, ImageSanitizer, VideoSanitizer,
    /// AudioSanitizer), so everything else is refused here, before anything
    /// is cached or rendered. A well-formed but malicious JPEG/MP4/M4A still
    /// reaches its own decoder — this gate narrows the parser surface, it
    /// does not remove it.
    enum ContentGate {
        /// Longest accepted image edge. Senders re-encode to 2 048 px since
        /// 30.09.2026 and to 4 096 px before; 4 096 keeps older images valid.
        static let imageMaxPixelEdge = 4_096

        static func validate(_ content: Data, mime: AttachmentMimeType) throws {
            switch mime {
            case .jpeg:
                guard isJPEG(content, maxEdge: imageMaxPixelEdge) else {
                    throw ReceiveError.malformed("content is not the declared JPEG")
                }
            case .mp4h264, .aac:
                // ISO base media file: the first box is `ftyp` (bytes 4..7).
                // Measured on AVFoundation output for .mp4 and .m4a.
                guard isISOBaseMedia(content) else {
                    throw ReceiveError.malformed("content is not an ISO media file")
                }
            case .png, .webp, .opus:
                // Never produced by our sender.
                throw ReceiveError.malformed("unsupported attachment type")
            }
        }

        /// The thumbnail is a ≤ 256 px JPEG for images and (when available)
        /// videos, and deliberate random filler otherwise — so a thumbnail that
        /// is not a small JPEG is dropped, never rejected.
        static func thumbnailOrEmpty(_ thumbnail: Data) -> Data {
            isJPEG(thumbnail, maxEdge: 1_024) ? thumbnail : Data()
        }

        static func isJPEG(_ data: Data, maxEdge: Int) -> Bool {
            // Magic first, so no other ImageIO parser ever sees the bytes.
            guard data.count >= 4 else { return false }
            let b = [UInt8](data.prefix(3))
            guard b[0] == 0xFF, b[1] == 0xD8, b[2] == 0xFF else { return false }
            let options = [kCGImageSourceShouldCache: false] as CFDictionary
            guard let source = CGImageSourceCreateWithData(data as CFData, options),
                  let type = CGImageSourceGetType(source) as String?,
                  type == "public.jpeg",
                  CGImageSourceGetCount(source) == 1,
                  let props = CGImageSourceCopyPropertiesAtIndex(source, 0, options) as? [CFString: Any],
                  let w = props[kCGImagePropertyPixelWidth] as? Int,
                  let h = props[kCGImagePropertyPixelHeight] as? Int
            else { return false }
            return w > 0 && h > 0 && w <= maxEdge && h <= maxEdge
        }

        static func isISOBaseMedia(_ data: Data) -> Bool {
            guard data.count >= 12 else { return false }
            let b = [UInt8](data.prefix(8))
            return b[4] == 0x66 && b[5] == 0x74 && b[6] == 0x79 && b[7] == 0x70  // "ftyp"
        }
    }

    private static func describe(_ error: Error) -> String {
        #if DEBUG
        return String(describing: error)
        #else
        return "attachment_error"
        #endif
    }
}

// MARK: - In-memory cache

@available(iOS 15.0, macOS 12.0, *)
public actor AttachmentDownloadCache {

    public static let shared = AttachmentDownloadCache()

    private var entries: [String: AttachmentReceiveService.Opened] = [:]
    private var timestamps: [String: Date] = [:]
    private var inflight: [String: Task<AttachmentReceiveService.Opened, Error>] = [:]
    /// Bumped by `purge()`; a download that started before a purge must not
    /// put its plaintext back into the cache afterwards (P8-AUDIT8-IOS-09).
    private var generation = 0

    /// H1: decrypted attachment bundles are the largest plaintext-at-rest
    /// surface in RAM, so they expire faster than the 30-min message TTL.
    private static let ttlSeconds: TimeInterval = 600  // 10 min

    private init() {
        // H1 (security audit): previously the cache held decrypted media for
        // the whole app lifetime — purge() had no callers, no TTL, and it was
        // skipped by both the device-lock wipe and the panic wipe. Mirror
        // InMemoryMessageStore's forensic model: drop all plaintext when the
        // device locks (protected data unavailable) and on emergency wipe.
        // (.emergencyMemoryWipe is posted at the very start of
        // SecurityUtils.performComprehensiveWipe, so the purge runs before any
        // subsequent exit().)
        let purgeOnNotify: @Sendable (Notification) -> Void = { _ in
            Task { await AttachmentDownloadCache.shared.purge() }
        }
        #if canImport(UIKit)
        NotificationCenter.default.addObserver(
            forName: UIApplication.protectedDataWillBecomeUnavailableNotification,
            object: nil, queue: nil, using: purgeOnNotify)
        #endif
        NotificationCenter.default.addObserver(
            forName: .emergencyMemoryWipe,
            object: nil, queue: nil, using: purgeOnNotify)
    }

    /// Fetches or returns the cached decrypted attachment for the given
    /// payload. Re-entrant: concurrent callers share a single download.
    /// Only the first caller for a given blob receives progress updates;
    /// re-entrant callers await the same Task and return immediately with
    /// the cached result.
    public func fetch(
        payload: AttachmentMessagePayload,
        contactID: String,
        progress: (@Sendable (Double) -> Void)? = nil
    ) async throws -> AttachmentReceiveService.Opened {
        scrubExpired()
        let key = try Self.cacheKey(payload: payload, contactID: contactID)
        if let cached = entries[key] {
            progress?(1.0)
            return cached
        }
        if let running = inflight[key] { return try await running.value }

        let task = Task { () throws -> AttachmentReceiveService.Opened in
            try await AttachmentReceiveService.downloadAndOpen(
                payload: payload,
                contactID: contactID,
                progress: progress
            )
        }
        inflight[key] = task
        defer { inflight[key] = nil }
        let startedIn = generation
        do {
            let opened = try await task.value
            if generation == startedIn {
                entries[key] = opened
                timestamps[key] = Date()
            }
            return opened
        } catch {
            throw error
        }
    }

    /// Cache key bound to the whole authenticated payload and the conversation.
    ///
    /// P8-AUDIT8-IOS-09 (audit F30/F37): the key used to be the blobID alone —
    /// a value the sending peer chooses. A party that learns another
    /// conversation's blobID (the blob relay sees every one) could make a
    /// cached plaintext appear under a different message, contact or
    /// descriptor, skipping that message's Merkle/seed/AEAD checks. Now a hit
    /// requires the same contact and a byte-identical payload (descriptor,
    /// wrapped seed, read caps).
    static func cacheKey(payload: AttachmentMessagePayload, contactID: String) throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let encoded: Data
        do { encoded = try encoder.encode(payload) }
        catch { throw AttachmentReceiveService.ReceiveError.malformed("cache key") }
        var hasher = SHA256()
        hasher.update(data: Data(contactID.utf8))
        hasher.update(data: Data([0]))
        hasher.update(data: encoded)
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    /// H1: evict entries older than the TTL. Called opportunistically on each
    /// fetch so stale plaintext does not linger between chat sessions.
    private func scrubExpired() {
        let now = Date()
        let stale = timestamps.filter { now.timeIntervalSince($0.value) > Self.ttlSeconds }.map(\.key)
        for key in stale {
            entries.removeValue(forKey: key)
            timestamps.removeValue(forKey: key)
        }
    }

    /// Drop all cached plaintext. Inflight downloads keep running — their
    /// callers still receive the result, but it will not be retained here
    /// (the generation check in `fetch`).
    /// Note: Swift `Data` held in the immutable `Opened` value cannot be
    /// zeroed in place without risking a shared CoW buffer still rendered by a
    /// live view; eviction releases the reference so the buffer becomes
    /// reclaimable (the same limitation documented in InMemoryMessageStore).
    public func purge() {
        generation &+= 1
        entries.removeAll()
        timestamps.removeAll()
    }
}
