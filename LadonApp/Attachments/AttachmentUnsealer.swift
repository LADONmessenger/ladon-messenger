// AttachmentUnsealer.swift — Phase 2
//
// Recipient side: takes the descriptor, the wrapped seed payload, the list
// of downloaded frames, and the recipient's identity keys, and returns the
// original plaintext attachment bytes plus the unsealed thumbnail and
// optional caption.
//
// Inert while ``FeatureFlags.attachmentsEnabled`` is false.

import Foundation
import CryptoKit

public enum AttachmentUnsealer {

    public enum UnsealError: Swift.Error, Equatable {
        case featureDisabled
        case wrongFrameCount
        case digestMismatch
        case headerMismatch
        case chunkCipher(AttachmentChunkCipher.Error)
        case slotCipher(AttachmentSlotCipher.Error)
        case seedWrap(AttachmentSeedWrap.Error)
    }

    public struct Opened {
        public let content: Data
        public let thumbnail: Data
        public let caption: Data?
    }

    public static func open(
        descriptor: AttachmentDescriptor,
        frames: [Data],
        seedPayload: AttachmentSeedWrap.WrappedSeedPayload,
        recipientX25519PrivateKey: Curve25519.KeyAgreement.PrivateKey,
        recipientKyberKeychainAccount: String
    ) throws -> Opened {
        return try openCore(
            descriptor: descriptor,
            frames: frames,
            seedPayload: seedPayload,
            recipientX25519PrivateKey: recipientX25519PrivateKey,
            kyberSource: .keychain(recipientKyberKeychainAccount)
        )
    }

    public static func openV2(
        descriptor: AttachmentDescriptor,
        thumbnailBlob: AttachmentRemoteBlobDescriptor,
        mainFrames: [Data],
        thumbnailFrames: [Data],
        seedPayload: AttachmentSeedWrap.WrappedSeedPayload,
        recipientX25519PrivateKey: Curve25519.KeyAgreement.PrivateKey,
        recipientKyberSecretKey: Data
    ) throws -> Opened {
        guard FeatureFlags.attachmentsEnabled else {
            throw UnsealError.featureDisabled
        }
        guard mainFrames.count == Int(descriptor.chunkCount) else {
            throw UnsealError.wrongFrameCount
        }
        guard thumbnailFrames.count == Int(thumbnailBlob.chunkCount) else {
            throw UnsealError.wrongFrameCount
        }

        var seed: Data
        do {
            seed = try AttachmentSeedWrap.unwrap(
                descriptorFingerprint: descriptor.sealedSeed,
                payload: seedPayload,
                recipientX25519PrivateKey: recipientX25519PrivateKey,
                recipientKyberSecretKey: recipientKyberSecretKey,
                blobID: descriptor.blobID
            )
        } catch let e as AttachmentSeedWrap.Error {
            throw UnsealError.seedWrap(e)
        } catch {
            throw UnsealError.seedWrap(.unwrapFailed)
        }
        defer { seed.securelyWipe() }

        let content = try openBlob(
            blobID: descriptor.blobID,
            bucket: descriptor.bucket,
            chunkCount: descriptor.chunkCount,
            digest: descriptor.digest,
            mime: descriptor.mime,
            frames: mainFrames,
            seed: seed
        )

        var thumbnailSeed = AttachmentKeyDerivation.deriveThumbnailBlobSeed(
            masterSeed: seed,
            mainBlobID: descriptor.blobID
        )
        defer { thumbnailSeed.securelyWipe() }
        let thumbnail = try openBlob(
            blobID: thumbnailBlob.blobID,
            bucket: thumbnailBlob.bucket,
            chunkCount: thumbnailBlob.chunkCount,
            digest: thumbnailBlob.digest,
            mime: descriptor.mime,
            frames: thumbnailFrames,
            seed: thumbnailSeed
        )

        var caption: Data?
        if let capFrame = descriptor.sealedCaption {
            do {
                caption = try AttachmentSlotCipher.openCaption(
                    frame: capFrame,
                    seed: seed,
                    blobID: descriptor.blobID
                )
            } catch let e as AttachmentSlotCipher.Error {
                throw UnsealError.slotCipher(e)
            } catch {
                throw UnsealError.slotCipher(.openFailed)
            }
        }

        return Opened(content: content, thumbnail: thumbnail, caption: caption)
    }

    /// Overload accepting the Kyber secret key as raw bytes — used when
    /// the SK lives in the session struct (per-session PQ ratchet) rather
    /// than in a static Keychain slot.
    public static func open(
        descriptor: AttachmentDescriptor,
        frames: [Data],
        seedPayload: AttachmentSeedWrap.WrappedSeedPayload,
        recipientX25519PrivateKey: Curve25519.KeyAgreement.PrivateKey,
        recipientKyberSecretKey: Data
    ) throws -> Opened {
        return try openCore(
            descriptor: descriptor,
            frames: frames,
            seedPayload: seedPayload,
            recipientX25519PrivateKey: recipientX25519PrivateKey,
            kyberSource: .inline(recipientKyberSecretKey)
        )
    }

    private enum KyberSource {
        case keychain(String)
        case inline(Data)
    }

    private static func openCore(
        descriptor: AttachmentDescriptor,
        frames: [Data],
        seedPayload: AttachmentSeedWrap.WrappedSeedPayload,
        recipientX25519PrivateKey: Curve25519.KeyAgreement.PrivateKey,
        kyberSource: KyberSource
    ) throws -> Opened {
        guard FeatureFlags.attachmentsEnabled else {
            throw UnsealError.featureDisabled
        }
        guard frames.count == Int(descriptor.chunkCount) else {
            throw UnsealError.wrongFrameCount
        }

        // 1. Verify the Merkle root.
        let root = AttachmentMerkle.root(of: frames)
        guard constantTimeEqual(root, descriptor.digest) else {
            throw UnsealError.digestMismatch
        }

        // 2. Unwrap the seed (PQ hybrid).
        var seed: Data
        do {
            switch kyberSource {
            case .keychain(let acc):
                seed = try AttachmentSeedWrap.unwrap(
                    descriptorFingerprint: descriptor.sealedSeed,
                    payload: seedPayload,
                    recipientX25519PrivateKey: recipientX25519PrivateKey,
                    recipientKyberKeychainAccount: acc,
                    blobID: descriptor.blobID
                )
            case .inline(let sk):
                seed = try AttachmentSeedWrap.unwrap(
                    descriptorFingerprint: descriptor.sealedSeed,
                    payload: seedPayload,
                    recipientX25519PrivateKey: recipientX25519PrivateKey,
                    recipientKyberSecretKey: sk,
                    blobID: descriptor.blobID
                )
            }
        } catch let e as AttachmentSeedWrap.Error {
            throw UnsealError.seedWrap(e)
        } catch {
            throw UnsealError.seedWrap(.unwrapFailed)
        }
        defer { seed.securelyWipe() }

        // 3. Derive content key base.
        let contentKeyBase = AttachmentKeyDerivation.deriveContentKeyBase(
            seed: seed, blobID: descriptor.blobID
        )

        // 4. Open each frame.
        // FIX AUDIT3-IOS-14: wipe aggregated plaintext and per-chunk slices.
        // Without these wipes the full decrypted attachment (up to 32 MB)
        // lingers in heap after this function returns, and per-iteration
        // 256 KB plain slices linger until reuse. A memory dump captured
        // shortly after opening an attachment could harvest the entire
        // plaintext. defer ensures we wipe even on error paths below.
        var plainJoined = Data()
        plainJoined.reserveCapacity(Int(descriptor.chunkCount) * AttachmentLimits.plaintextChunkBytes)
        defer { plainJoined.securelyWipe() }
        for (i, frame) in frames.enumerated() {
            do {
                var plain = try AttachmentChunkCipher.open(
                    frame: frame,
                    contentKeyBase: contentKeyBase,
                    blobID: descriptor.blobID,
                    chunkIndex: UInt32(i),
                    chunkCount: descriptor.chunkCount,
                    bucket: descriptor.bucket
                )
                defer { plain.securelyWipe() }
                plainJoined.append(plain)
            } catch let e as AttachmentChunkCipher.Error {
                throw UnsealError.chunkCipher(e)
            } catch {
                throw UnsealError.chunkCipher(.openFailed)
            }
        }

        // 5. Parse and cross-check header.
        guard plainJoined.count >= 32 else { throw UnsealError.headerMismatch }
        let header = plainJoined.prefix(32)
        guard header[0] == AttachmentDescriptor.currentVersion else {
            throw UnsealError.headerMismatch
        }
        // real_length
        var realLen: UInt64 = 0
        for i in 0..<8 {
            realLen = (realLen << 8) | UInt64(header[3 + i])
        }
        // mime
        guard header[11] == 0 else { throw UnsealError.headerMismatch }
        guard header[12] == descriptor.mime.rawValue else {
            throw UnsealError.headerMismatch
        }
        // bucket
        guard header[13] == 0 else { throw UnsealError.headerMismatch }
        guard header[14] == descriptor.bucket.rawValue else {
            throw UnsealError.headerMismatch
        }
        // chunk_count
        let hcc = (UInt32(header[15]) << 8) | UInt32(header[16])
        guard hcc == descriptor.chunkCount else {
            throw UnsealError.headerMismatch
        }
        // thumbnail_length
        let thumbLen = (Int(header[17]) << 8) | Int(header[18])
        guard thumbLen >= 0, thumbLen <= AttachmentSlotCipher.thumbnailPlaintextLimit else {
            throw UnsealError.headerMismatch
        }
        // reserved
        guard header[19] == 0, header[20] == 0 else {
            throw UnsealError.headerMismatch
        }

        // 6. Extract content with padding stripped.
        let totalPlain = plainJoined.count - 32
        let bucketBytes = descriptor.bucket.byteSize
        guard totalPlain >= bucketBytes else { throw UnsealError.headerMismatch }
        let contentStart = 32
        let contentEnd = contentStart + (try checkedContentLength(realLen, bucketBytes: bucketBytes))
        let content = plainJoined.subdata(in: contentStart..<contentEnd)

        // 7. Thumbnail — length is known from header.
        let thumb: Data
        do {
            thumb = try AttachmentSlotCipher.openThumbnail(
                slot: descriptor.sealedThumbnail,
                plaintextLength: thumbLen,
                seed: seed,
                blobID: descriptor.blobID
            )
        } catch let e as AttachmentSlotCipher.Error {
            throw UnsealError.slotCipher(e)
        } catch {
            throw UnsealError.slotCipher(.openFailed)
        }

        // 8. Caption.
        var caption: Data?
        if let capFrame = descriptor.sealedCaption {
            do {
                caption = try AttachmentSlotCipher.openCaption(
                    frame: capFrame, seed: seed, blobID: descriptor.blobID
                )
            } catch let e as AttachmentSlotCipher.Error {
                throw UnsealError.slotCipher(e)
            } catch {
                throw UnsealError.slotCipher(.openFailed)
            }
        }

        return Opened(content: content, thumbnail: thumb, caption: caption)
    }

    // MARK: - Internals

    private static func openBlob(
        blobID: Data,
        bucket: AttachmentBucket,
        chunkCount: UInt32,
        digest: Data,
        mime: AttachmentMimeType,
        frames: [Data],
        seed: Data
    ) throws -> Data {
        let root = AttachmentMerkle.root(of: frames)
        guard constantTimeEqual(root, digest) else {
            throw UnsealError.digestMismatch
        }

        let contentKeyBase = AttachmentKeyDerivation.deriveContentKeyBase(
            seed: seed,
            blobID: blobID
        )

        // FIX AUDIT3-IOS-14: see openCore — same wipe pattern for V2 path.
        var plainJoined = Data()
        plainJoined.reserveCapacity(Int(chunkCount) * AttachmentLimits.plaintextChunkBytes)
        defer { plainJoined.securelyWipe() }
        for (i, frame) in frames.enumerated() {
            do {
                var plain = try AttachmentChunkCipher.open(
                    frame: frame,
                    contentKeyBase: contentKeyBase,
                    blobID: blobID,
                    chunkIndex: UInt32(i),
                    chunkCount: chunkCount,
                    bucket: bucket
                )
                defer { plain.securelyWipe() }
                plainJoined.append(plain)
            } catch let e as AttachmentChunkCipher.Error {
                throw UnsealError.chunkCipher(e)
            } catch {
                throw UnsealError.chunkCipher(.openFailed)
            }
        }

        guard plainJoined.count >= 32 else { throw UnsealError.headerMismatch }
        let header = plainJoined.prefix(32)
        guard header[0] == AttachmentDescriptor.currentVersion else {
            throw UnsealError.headerMismatch
        }
        var realLen: UInt64 = 0
        for i in 0..<8 {
            realLen = (realLen << 8) | UInt64(header[3 + i])
        }
        guard header[11] == 0, header[12] == mime.rawValue else {
            throw UnsealError.headerMismatch
        }
        guard header[13] == 0, header[14] == bucket.rawValue else {
            throw UnsealError.headerMismatch
        }
        let hcc = (UInt32(header[15]) << 8) | UInt32(header[16])
        guard hcc == chunkCount else {
            throw UnsealError.headerMismatch
        }
        guard header[19] == 0, header[20] == 0 else {
            throw UnsealError.headerMismatch
        }

        let totalPlain = plainJoined.count - 32
        let bucketBytes = bucket.byteSize
        guard totalPlain >= bucketBytes else { throw UnsealError.headerMismatch }
        let contentStart = 32
        let contentEnd = contentStart + (try checkedContentLength(realLen, bucketBytes: bucketBytes))
        return plainJoined.subdata(in: contentStart..<contentEnd)
    }

    /// The header's real_length as an Int, if it fits the bucket.
    ///
    /// P8-AUDIT8-IOS-06 (audit F20/F27): real_length is chosen by the sending
    /// peer. It is compared in UInt64 BEFORE any conversion — `Int(_:)` traps
    /// for values above Int.max, so a crafted header used to crash the app on
    /// every tap of the attachment.
    static func checkedContentLength(_ realLen: UInt64, bucketBytes: Int) throws -> Int {
        guard bucketBytes >= 0, realLen <= UInt64(bucketBytes) else { throw UnsealError.headerMismatch }
        return Int(realLen)
    }

    @inline(never)
    private static func constantTimeEqual(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        let aa = Array(a)
        let bb = Array(b)
        var result: UInt8 = 0
        for i in 0..<aa.count {
            result |= aa[i] ^ bb[i]
        }
        return result == 0
    }
}
