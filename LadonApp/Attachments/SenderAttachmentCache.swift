// SenderAttachmentCache.swift — Phase 8 (UX)
//
// In-memory only cache that lets the outgoing attachment bubble render the
// actual photo / video poster / waveform immediately — without re-fetching
// the encrypted blob from the relay just to show the sender their own
// media.
//
// SECURITY
// --------
// * RAM only. Nothing ever touches disk. App termination clears the cache,
//   and so do device lock, emergency wipe and a 10-minute TTL — the same
//   lifecycle as `AttachmentDownloadCache` (P8-AUDIT8-IOS-10, audit F24/F28).
// * Bounded by total byte count + entry count (LRU eviction). A misbehaving
//   sender cannot exhaust memory by sending many large attachments.
// * Stores the *sanitised* plaintext only — the same bytes that travel
//   inside the encrypted bucket payload. Original camera-roll metadata has
//   already been stripped by `ImageSanitizer` / `VideoSanitizer` /
//   `AudioSanitizer` before reaching this cache.
// * Full content is cached for photos ≤ 8 MB and videos ≤ 100 MB
//   (`fullContentIfWorthCaching`); audio and larger media keep only the
//   thumbnail — viewing the full content re-downloads via the normal
//   `AttachmentDownloadCache` path.
// * Eviction releases the references; a buffer still shown by a live view
//   stays alive until that view goes (same limitation as the receive cache).

import Foundation
#if canImport(UIKit)
import UIKit
#endif

@available(iOS 15.0, macOS 12.0, *)
public actor SenderAttachmentCache {

    public static let shared = SenderAttachmentCache()

    public struct Entry: Sendable {
        public let mime: AttachmentMimeType
        public let thumbnail: Data
        /// Optional full sanitised content. nil for audio and for media
        /// above the size limits — those re-download via the normal recipient
        /// pipeline if the sender taps the bubble later.
        public let fullContent: Data?
        public let cachedAt: Date
    }

    /// Hard ceiling on combined cache size. 128 MB easily holds the
    /// recently sent media of an active session, while staying far below
    /// the iOS jetsam threshold for foreground apps. LRU eviction kicks
    /// in above this.
    private let maxTotalBytes: Int = 128 * 1024 * 1024
    /// Hard ceiling on entries. Stops a fan-out send loop from starving the
    /// LRU eviction loop with thousands of tiny thumbnails.
    private let maxEntries: Int = 128

    /// Threshold for storing the full sanitised content alongside the
    /// thumbnail. Photos up to 8 MB and videos up to 32 MB qualify —
    /// covers virtually every sanitised photo and short clip while still
    /// bounded by the total cache budget.
    private static let fullPhotoMaxBytes: Int = 8 * 1024 * 1024  // 8 MB
    private static let fullVideoMaxBytes: Int = 100 * 1024 * 1024 // 100 MB (raised 32 → 100 on 2026-05-14)

    private var entries: [String: Entry] = [:]
    /// Insertion-order keys for cheap LRU. Most-recently-stored at the end.
    private var order: [String] = []
    private var totalBytes: Int = 0

    /// Sent plaintext is as sensitive as received plaintext, so it expires as
    /// fast as the receive cache (`AttachmentDownloadCache.ttlSeconds`).
    private static let ttlSeconds: TimeInterval = 600  // 10 min

    private init() {
        // P8-AUDIT8-IOS-10 (audit F24/F28): this cache held every photo and
        // video sent in the session (up to 128 MB) across device lock and
        // panic wipe — purge() had no caller. Drop it all when protected
        // data becomes unavailable and on emergency wipe, like
        // AttachmentDownloadCache (H1).
        let purgeOnNotify: @Sendable (Notification) -> Void = { _ in
            Task { await SenderAttachmentCache.shared.purge() }
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

    // MARK: - Public API

    /// Store an entry keyed by the blob ID hex string.
    public func store(
        blobID: Data,
        mime: AttachmentMimeType,
        thumbnail: Data,
        fullContent: Data?
    ) {
        scrubExpired()
        let key = Self.keyForBlobID(blobID)
        let entry = Entry(
            mime: mime,
            thumbnail: thumbnail,
            fullContent: fullContent,
            cachedAt: Date()
        )

        // If replacing, free the old bytes first.
        if let existing = entries[key] {
            totalBytes -= existing.thumbnail.count + (existing.fullContent?.count ?? 0)
            order.removeAll { $0 == key }
        }
        entries[key] = entry
        order.append(key)
        totalBytes += thumbnail.count + (fullContent?.count ?? 0)

        evictIfNeeded()
    }

    /// Look up an entry. nil = nothing cached for this blob (cache cleared,
    /// app restarted, or never stored).
    public func entry(for blobID: Data) -> Entry? {
        scrubExpired()
        return entries[Self.keyForBlobID(blobID)]
    }

    public func purge() {
        entries.removeAll()
        order.removeAll()
        totalBytes = 0
    }

    // MARK: - Internals

    private func scrubExpired() {
        let now = Date()
        let stale = entries.filter { now.timeIntervalSince($0.value.cachedAt) > Self.ttlSeconds }.map(\.key)
        for key in stale {
            if let gone = entries.removeValue(forKey: key) {
                totalBytes -= gone.thumbnail.count + (gone.fullContent?.count ?? 0)
            }
            order.removeAll { $0 == key }
        }
    }

    private func evictIfNeeded() {
        while (totalBytes > maxTotalBytes || entries.count > maxEntries) && !order.isEmpty {
            let oldestKey = order.removeFirst()
            if let evicted = entries.removeValue(forKey: oldestKey) {
                totalBytes -= evicted.thumbnail.count + (evicted.fullContent?.count ?? 0)
            }
        }
    }

    private static func keyForBlobID(_ blobID: Data) -> String {
        return blobID.map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - Helpers exposed to AttachmentSendService

    /// Decide whether to keep the full sanitised content of an outgoing
    /// attachment in RAM. Photos ≤ 8 MB and videos ≤ 100 MB qualify so the
    /// sender can view their own media in full quality offline. Audio is
    /// not previewed visually — the bubble already shows the waveform.
    public static func fullContentIfWorthCaching(
        prepared: AttachmentPreparation.Prepared
    ) -> Data? {
        let real = prepared.realLength
        guard real > 0 else { return nil }
        switch prepared.mime {
        case .jpeg, .png, .webp:
            guard real <= fullPhotoMaxBytes else { return nil }
            return Data(prepared.paddedPlaintext.prefix(real))  // own buffer, not a slice of the padded one
        case .mp4h264:
            guard real <= fullVideoMaxBytes else { return nil }
            return Data(prepared.paddedPlaintext.prefix(real))  // own buffer, not a slice of the padded one
        case .opus, .aac:
            return nil
        }
    }
}
