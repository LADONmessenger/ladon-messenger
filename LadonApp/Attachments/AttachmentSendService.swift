// AttachmentSendService.swift — Phase 8
//
// High-level orchestrator for the sender side of the attachment pipeline.
// Entry point for ChatView: given a media input and a conversation, it
//   1. prepares (sanitise + pad + thumbnail)
//   2. seals (PQ-hybrid + AEAD chunks + Merkle root)
//   3. uploads to the blob-relay
//   4. persists the sender-only deleteCap in Keychain (for later revocation)
//   5. produces an ``AttachmentMessagePayload`` ready to travel inside
//      ``Message.content`` via the normal Double-Ratchet path
//
// Every step is feature-flag gated (`FeatureFlags.attachmentsEnabled`).
// Errors are surfaced as ``AttachmentSendError`` — the UI layer should
// map them to human-readable strings.

import Foundation
import CryptoKit

@available(iOS 15.0, macOS 12.0, *)
public enum AttachmentSendService {

    public enum AttachmentSendError: Error, Equatable {
        case featureDisabled
        case recipientKyberKeyMissing
        case recipientX25519KeyMissing
        case prepareFailed(String)
        case sealFailed(String)
        case uploadFailed(String)
        case payloadEncodeFailed
        case payloadTooLarge(bytes: Int)
    }

    public enum Kind {
        case image(Data)
        case video(Data)
        case voice(Data)
        case audio(Data)
    }

    /// V2 variant — caller supplies the recipient's Kyber768 public key
    /// directly (typically split out of the V2 HKEM public key:
    /// `pk_x (32) || pk_ky (1,184)`). Mirrors the V1 entry point but skips
    /// the legacy `KeyManager` session lookup which V2 contacts have no
    /// equivalent of. Crypto is identical (X25519 + ML-KEM-768 PQ-hybrid).
    public static func buildAttachmentMessageV2(
        kind: Kind,
        caption: String?,
        recipientX25519PublicKey: Curve25519.KeyAgreement.PublicKey,
        recipientKyberPublicKey: Data,
        progress: (@Sendable (Double) -> Void)? = nil
    ) async throws -> String {
        guard FeatureFlags.attachmentsEnabled else {
            throw AttachmentSendError.featureDisabled
        }
        return try await buildAttachmentMessageImpl(
            kind: kind,
            caption: caption,
            recipientX25519PublicKey: recipientX25519PublicKey,
            recipientKyberPublicKey: recipientKyberPublicKey,
            useV2Codec: true,
            progress: progress
        )
    }

    /// Shared implementation between V1 and V2 entry points. Identical to
    /// the legacy V1 pipeline (prepare → seal → upload → encode); the only
    /// difference between the two callers is the source of the recipient
    /// Kyber768 public key.
    private static func buildAttachmentMessageImpl(
        kind: Kind,
        caption: String?,
        recipientX25519PublicKey: Curve25519.KeyAgreement.PublicKey,
        recipientKyberPublicKey kyberPK: Data,
        useV2Codec: Bool,
        progress: (@Sendable (Double) -> Void)?
    ) async throws -> String {

        // 2. Prepare.
        let prepared: AttachmentPreparation.Prepared
        do {
            switch kind {
            case .image(let data):
                prepared = try AttachmentPreparation.prepareImage(data)
            case .video(let data):
                prepared = try await AttachmentPreparation.prepareVideo(data)
            case .voice(let data):
                prepared = try await AttachmentPreparation.prepareVoice(data)
            case .audio(let data):
                prepared = try await AttachmentPreparation.prepareAudio(data)
            }
        } catch {
            throw AttachmentSendError.prepareFailed(describe(error))
        }

        // 3. Seal.
        let captionData: Data? = {
            guard let c = caption, !c.isEmpty else { return nil }
            var bytes = Data(c.utf8)
            // Hard-cap to slot limit. Caller should also pre-trim for UX.
            let cap = AttachmentDescriptor.sealedCaptionMaxByteCount - 28 // AEAD overhead
            if bytes.count > cap { bytes = bytes.prefix(cap) }
            return bytes
        }()

        let encoded: String
        let previewBlobID: Data
        var cleanupTargets: [(blobID: Data, deleteCap: String)] = []
        if useV2Codec {
            let sealed: AttachmentSealer.SealedV2
            do {
                sealed = try AttachmentSealer.sealV2(
                    prepared: prepared,
                    recipientKyberPublicKey: kyberPK,
                    recipientX25519PublicKey: recipientX25519PublicKey,
                    captionPlaintext: captionData
                )
            } catch {
                throw AttachmentSendError.sealFailed(describe(error))
            }

            let receipt: AttachmentUploader.ReceiptV2
            do {
                // Active-active sharding: pick the shard deterministically
                // from the main blob's random ID, so the 50/50 split is
                // free (no extra RNG, no probe). Main and thumbnail share
                // the shard — they are uploaded in one parallel batch and
                // the receiver gets a single descriptor.blobHost byte.
                let host = BlobHost.selectFor(blobID: sealed.mainBlob.blobID)
                receipt = try await AttachmentUploader.uploadV2(sealed, host: host, progress: progress)
            } catch {
                throw AttachmentSendError.uploadFailed(describe(error))
            }

            cleanupTargets = [
                (blobID: receipt.main.blobID, deleteCap: receipt.main.deleteCap),
                (blobID: receipt.thumbnail.blobID, deleteCap: receipt.thumbnail.deleteCap)
            ]
            previewBlobID = receipt.main.blobID

            let descriptor: AttachmentDescriptor
            do {
                descriptor = try AttachmentDescriptor(
                    blobID: sealed.mainBlob.blobID,
                    mime: prepared.mime,
                    bucket: sealed.mainBlob.bucket,
                    dimensions: prepared.dimensions,
                    chunkCount: sealed.mainBlob.chunkCount,
                    sealedSeed: sealed.sealedSeed,
                    digest: sealed.mainBlob.digest,
                    sealedThumbnail: Data(count: AttachmentDescriptor.sealedThumbnailByteCount),
                    sealedCaption: sealed.sealedCaption,
                    thumbnailBlob: try AttachmentRemoteBlobDescriptor(
                        blobID: sealed.thumbnailBlob.blobID,
                        bucket: sealed.thumbnailBlob.bucket,
                        chunkCount: sealed.thumbnailBlob.chunkCount,
                        digest: sealed.thumbnailBlob.digest,
                        blobHost: receipt.thumbnail.host
                    ),
                    blobHost: receipt.main.host
                )
            } catch {
                throw AttachmentSendError.payloadEncodeFailed
            }

            let payload = AttachmentMessagePayload(
                descriptor: descriptor,
                seed: AttachmentMessagePayload.SeedPayload(from: sealed.seedPayload),
                readCap: receipt.main.readCap,
                thumbnailReadCap: receipt.thumbnail.readCap
            )

            do {
                encoded = try AttachmentMessagePayloadV2.encodedAsMessageContent(payload: payload)
            } catch {
                await bestEffortDeleteAll(cleanupTargets)
                throw AttachmentSendError.payloadEncodeFailed
            }
        } else {
            let sealed: AttachmentSealer.Sealed
            do {
                sealed = try AttachmentSealer.seal(
                    prepared: prepared,
                    recipientKyberPublicKey: kyberPK,
                    recipientX25519PublicKey: recipientX25519PublicKey,
                    captionPlaintext: captionData
                )
            } catch {
                throw AttachmentSendError.sealFailed(describe(error))
            }

            let receipt: AttachmentUploader.Receipt
            do {
                // V1 codec path — sealer already chose blobHost via
                // BlobHost.selectFor(blobID:). Read it back from the
                // descriptor so uploader hits the matching shard.
                receipt = try await AttachmentUploader.upload(sealed, host: sealed.descriptor.blobHost, progress: progress)
            } catch {
                throw AttachmentSendError.uploadFailed(describe(error))
            }

            cleanupTargets = [(blobID: receipt.blobID, deleteCap: receipt.deleteCap)]
            previewBlobID = receipt.blobID

        // 6. Build wire payload.
        //
        // V2 chats use a compact binary codec (descriptor + seed packed,
        // single base64url wrap) because the V2 outer envelope reserves
        // ~3.4 KB for the per-message Single-Use-Token, leaving roughly
        // 11.7 KB of inner-body budget. The legacy JSON+per-Data-base64
        // encoder produces ~16.8 KB for a normal photo and would always
        // bust that limit. V1 chats keep the JSON encoder until V1 is
        // sunset; the receiver dispatches by wire-marker prefix.
            do {
                let payload = AttachmentMessagePayload(
                    descriptor: sealed.descriptor,
                    seed: AttachmentMessagePayload.SeedPayload(from: sealed.seedPayload),
                    readCap: receipt.readCap
                )
                encoded = try payload.encodedAsMessageContent()
            } catch {
                await bestEffortDelete(blobID: receipt.blobID, deleteCap: receipt.deleteCap)
                throw AttachmentSendError.payloadEncodeFailed
            }
        }

        // 7. Size guard (Envelope budget).
        //
        // V2: the attachment payload travels as a ratchet plaintext, so its
        // ceiling is V2RatchetPayload.maxPlaintextLen (derived from the wire
        // constants). The former 11,500 B figure exceeded it. V1 keeps its
        // historical ~15 KB budget.
        let bytes = encoded.utf8.count
        let limit = useV2Codec ? V2RatchetPayload.maxPlaintextLen : 15_000
        guard bytes <= limit else {
            await bestEffortDeleteAll(cleanupTargets)
            throw AttachmentSendError.payloadTooLarge(bytes: bytes)
        }

        // 8. Populate the in-memory sender preview cache so the outgoing
        //    bubble can render the actual media immediately, without
        //    re-downloading from the relay. Only the unsanitised plaintext
        //    thumbnail (4 KB max) and — for images small enough — the full
        //    sanitised image bytes are kept. Cache is RAM-only and cleared
        //    on app termination / explicit purge for security.
        await SenderAttachmentCache.shared.store(
            blobID: previewBlobID,
            mime: prepared.mime,
            thumbnail: prepared.thumbnailPlaintext,
            fullContent: SenderAttachmentCache.fullContentIfWorthCaching(
                prepared: prepared
            )
        )

        return encoded
    }

    // MARK: - Helpers

    private static func describe(_ error: Error) -> String {
        #if DEBUG
        return String(describing: error)
        #else
        return "attachment_error"
        #endif
    }

    private static func bestEffortDelete(blobID: Data, deleteCap: String) async {
        // Best-effort delete must route to the shard that holds the blob.
        // We derive it from the blobID via the same deterministic rule the
        // sealer used — the sender never persists the host separately for
        // the cleanup path.
        let host = BlobHost.selectFor(blobID: blobID)
        do {
            try await BlobRelayClient.forTransfer(host: host).deleteBlob(blobID: blobID, deleteCap: deleteCap)
        } catch {
            #if DEBUG
            SecureLogger.debug("[AttachmentSend] best-effort delete failed: \(error)")
            #endif
        }
    }

    private static func bestEffortDeleteAll(_ targets: [(blobID: Data, deleteCap: String)]) async {
        for target in targets {
            await bestEffortDelete(blobID: target.blobID, deleteCap: target.deleteCap)
        }
    }
}

// MARK: - Legacy deleteCap items

/// P8-AUDIT8-IOS-11 (audit F25): every sent attachment used to leave one or
/// two Keychain items `attachmentDeleteCap.v1.<blobID>` behind — bearer
/// delete capabilities nothing ever read (`load` had no caller), and with
/// their creation dates a durable send-time log of the user's attachments.
/// Nothing is written any more (the caps of a send stay in RAM for its own
/// failure clean-up); `purgeAll` removes what earlier builds left.
public enum AttachmentDeleteCapStore {
    private static let service = "app.ladon.messenger"
    private static let accountPrefix = "attachmentDeleteCap.v1."

    /// Delete every legacy deleteCap item. Attribute-only query: no secret
    /// is read into memory. Items are WhenUnlocked, so a run while locked
    /// finds nothing and the next launch tries again. Returns how many
    /// items were removed.
    @discardableResult
    public static func purgeAll() -> Int {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]
        var out: AnyObject?
        guard SecItemCopyMatching(query as CFDictionary, &out) == errSecSuccess,
              let items = out as? [[String: Any]] else { return 0 }
        var removed = 0
        for item in items {
            guard let account = item[kSecAttrAccount as String] as? String,
                  account.hasPrefix(accountPrefix) else { continue }
            let delete: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: account
            ]
            if SecItemDelete(delete as CFDictionary) == errSecSuccess { removed += 1 }
        }
        return removed
    }
}
