// AttachmentSealer.swift — Phase 2
//
// Top-level orchestrator: takes a Phase-1 ``AttachmentPreparation.Prepared``
// bundle plus the recipient's identity keys and produces a fully sealed
// attachment ready for upload (Phase 4) and for descriptor transmission
// inside the E2E message body (Phase 4).
//
// Output of a successful seal:
//   * ``descriptor``  — fits entirely inside the 16 KB envelope when the
//                       message text is small (descriptor ≈ 4.3 KB).
//   * ``frames``      — list of ciphertext chunks; uploaded to the blob-relay.
//   * ``seedPayload`` — PQ-hybrid wrap to be carried in the message body
//                       alongside the descriptor.
//
// Inert while ``FeatureFlags.attachmentsEnabled`` is false.

import Foundation
import CryptoKit
import Security

public enum AttachmentSealer {

    public enum SealError: Swift.Error, Equatable {
        case featureDisabled
        case rngFailed
        case bucketPadding(BucketPadding.Error)
        case chunkCountOverflow
        case headerPackFailed
        case chunkCipher(AttachmentChunkCipher.Error)
        case slotCipher(AttachmentSlotCipher.Error)
        case seedWrap(AttachmentSeedWrap.Error)
        case descriptorValidation(String)
    }

    public struct Sealed {
        public let descriptor: AttachmentDescriptor
        public let frames: [Data]
        public let seedPayload: AttachmentSeedWrap.WrappedSeedPayload
        public let blobID: Data

        public init(
            descriptor: AttachmentDescriptor,
            frames: [Data],
            seedPayload: AttachmentSeedWrap.WrappedSeedPayload,
            blobID: Data
        ) {
            self.descriptor = descriptor
            self.frames = frames
            self.seedPayload = seedPayload
            self.blobID = blobID
        }
    }

    /// Option-C building block: one encrypted blob with its own blob_id,
    /// chunk fan-out, and Merkle root. This is intentionally descriptor-free
    /// so the v2 payload work can decide later how these fields are carried.
    public struct SealedBlobV2 {
        public let blobID: Data
        public let frames: [Data]
        public let chunkCount: UInt32
        public let bucket: AttachmentBucket
        public let digest: Data
        public let realLength: Int

        public init(
            blobID: Data,
            frames: [Data],
            chunkCount: UInt32,
            bucket: AttachmentBucket,
            digest: Data,
            realLength: Int
        ) {
            self.blobID = blobID
            self.frames = frames
            self.chunkCount = chunkCount
            self.bucket = bucket
            self.digest = digest
            self.realLength = realLength
        }
    }

    /// Option-C output shape: main blob + separate thumbnail blob, both
    /// unlocked from a single wrapped master seed.
    public struct SealedV2 {
        public let mainBlob: SealedBlobV2
        public let thumbnailBlob: SealedBlobV2
        public let mime: AttachmentMimeType
        public let dimensions: AttachmentDimensions
        public let sealedSeed: Data
        public let seedPayload: AttachmentSeedWrap.WrappedSeedPayload
        public let sealedCaption: Data?

        public init(
            mainBlob: SealedBlobV2,
            thumbnailBlob: SealedBlobV2,
            mime: AttachmentMimeType,
            dimensions: AttachmentDimensions,
            sealedSeed: Data,
            seedPayload: AttachmentSeedWrap.WrappedSeedPayload,
            sealedCaption: Data?
        ) {
            self.mainBlob = mainBlob
            self.thumbnailBlob = thumbnailBlob
            self.mime = mime
            self.dimensions = dimensions
            self.sealedSeed = sealedSeed
            self.seedPayload = seedPayload
            self.sealedCaption = sealedCaption
        }
    }

    /// Seal a Phase-1 ``Prepared`` bundle for a single recipient.
    ///
    /// Design choices:
    ///  * 32-byte random master seed (`SecRandomCopyBytes`).
    ///  * 16-byte random blob_id.
    ///  * Chunk layout: `[header(32)][content(paddedPlaintext)]` split into
    ///    slices of exactly ``AttachmentLimits.plaintextChunkBytes`` (256 KB),
    ///    except the last slice which is the remainder (always < 256 KB).
    ///  * Merkle root is computed over the emitted *frames* (nonce ‖ ct ‖ tag).
    public static func seal(
        prepared: AttachmentPreparation.Prepared,
        recipientKyberPublicKey: Data,
        recipientX25519PublicKey: Curve25519.KeyAgreement.PublicKey,
        captionPlaintext: Data? = nil
    ) throws -> Sealed {
        guard FeatureFlags.attachmentsEnabled else {
            throw SealError.featureDisabled
        }

        let blobID = try randomBytes(count: AttachmentDescriptor.blobIDByteCount)
        var seed = try randomBytes(count: 32)
        defer { seed.securelyWipe() }

        // 1. Assemble full plaintext: [header 32B][paddedPlaintext].
        let header = try buildHeader(
            realLength: UInt64(prepared.realLength),
            mime: prepared.mime,
            bucket: prepared.bucket,
            chunkCount: 0, // temporary — patched after we know the count
            thumbnailLength: UInt16(prepared.thumbnailPlaintext.count)
        )
        var full = Data(capacity: 32 + prepared.paddedPlaintext.count)
        full.append(header)
        full.append(prepared.paddedPlaintext)

        let sealedBlob = try sealBlob(
            plaintext: &full,
            seed: seed,
            blobID: blobID,
            bucket: prepared.bucket,
            realLength: prepared.realLength
        )

        // Wipe the assembled plaintext.
        full.securelyWipe()

        // 5. Thumbnail seal (4096 B fixed slot).
        let sealedThumb: Data
        do {
            sealedThumb = try AttachmentSlotCipher.sealThumbnail(
                plaintext: prepared.thumbnailPlaintext,
                seed: seed,
                blobID: blobID
            )
        } catch let e as AttachmentSlotCipher.Error {
            throw SealError.slotCipher(e)
        } catch {
            throw SealError.slotCipher(.sealFailed)
        }

        // 6. Optional caption.
        var sealedCap: Data?
        if let cap = captionPlaintext, !cap.isEmpty {
            do {
                sealedCap = try AttachmentSlotCipher.sealCaption(
                    plaintext: cap, seed: seed, blobID: blobID
                )
            } catch let e as AttachmentSlotCipher.Error {
                throw SealError.slotCipher(e)
            } catch {
                throw SealError.slotCipher(.sealFailed)
            }
        }

        // 7. PQ-hybrid wrap the seed.
        let wrap: (descriptorFingerprint: Data, payload: AttachmentSeedWrap.WrappedSeedPayload)
        do {
            wrap = try AttachmentSeedWrap.wrap(
                seed: seed,
                recipientKyberPublicKey: recipientKyberPublicKey,
                recipientX25519PublicKey: recipientX25519PublicKey,
                blobID: blobID
            )
        } catch let e as AttachmentSeedWrap.Error {
            throw SealError.seedWrap(e)
        } catch {
            throw SealError.seedWrap(.wrapFailed)
        }

        // 8. Build descriptor.
        //
        // `blobHost` is derived from the random blobID via
        // `BlobHost.selectFor(blobID:)` (lowest bit of byte 0). Since the
        // blobID is uniform random, this produces a ~50/50 shard split
        // across many messages, with no extra RNG draw needed.
        let descriptor: AttachmentDescriptor
        do {
            descriptor = try AttachmentDescriptor(
                blobID: blobID,
                mime: prepared.mime,
                bucket: prepared.bucket,
                dimensions: prepared.dimensions,
                chunkCount: sealedBlob.chunkCount,
                sealedSeed: wrap.descriptorFingerprint,
                digest: sealedBlob.digest,
                sealedThumbnail: sealedThumb,
                sealedCaption: sealedCap,
                blobHost: BlobHost.selectFor(blobID: blobID)
            )
        } catch {
            throw SealError.descriptorValidation("\(error)")
        }

        return Sealed(
            descriptor: descriptor,
            frames: sealedBlob.frames,
            seedPayload: wrap.payload,
            blobID: blobID
        )
    }

    /// Option-C sealer: emits two independently encrypted blobs, one for the
    /// main attachment body and one for the thumbnail. Both are recoverable
    /// from a single wrapped master seed.
    public static func sealV2(
        prepared: AttachmentPreparation.Prepared,
        recipientKyberPublicKey: Data,
        recipientX25519PublicKey: Curve25519.KeyAgreement.PublicKey,
        captionPlaintext: Data? = nil
    ) throws -> SealedV2 {
        guard FeatureFlags.attachmentsEnabled else {
            throw SealError.featureDisabled
        }

        let mainBlobID = try randomBytes(count: AttachmentDescriptor.blobIDByteCount)
        let thumbnailBlobID = try randomBytes(count: AttachmentDescriptor.blobIDByteCount)
        var masterSeed = try randomBytes(count: 32)
        defer { masterSeed.securelyWipe() }

        let mainHeader = try buildHeader(
            realLength: UInt64(prepared.realLength),
            mime: prepared.mime,
            bucket: prepared.bucket,
            chunkCount: 0,
            thumbnailLength: 0
        )
        var mainFull = Data(capacity: 32 + prepared.paddedPlaintext.count)
        mainFull.append(mainHeader)
        mainFull.append(prepared.paddedPlaintext)
        let mainBlob = try sealBlob(
            plaintext: &mainFull,
            seed: masterSeed,
            blobID: mainBlobID,
            bucket: prepared.bucket,
            realLength: prepared.realLength
        )
        mainFull.securelyWipe()

        let thumbnailPrepared: (padded: Data, bucket: AttachmentBucket, realLength: Int)
        do {
            thumbnailPrepared = try BucketPadding.pad(prepared.thumbnailPlaintext)
        } catch let error as BucketPadding.Error {
            throw SealError.bucketPadding(error)
        } catch {
            throw SealError.bucketPadding(.rngFailed)
        }

        let thumbnailHeader = try buildHeader(
            realLength: UInt64(thumbnailPrepared.realLength),
            mime: prepared.mime,
            bucket: thumbnailPrepared.bucket,
            chunkCount: 0,
            thumbnailLength: 0
        )
        var thumbnailFull = Data(capacity: 32 + thumbnailPrepared.padded.count)
        thumbnailFull.append(thumbnailHeader)
        thumbnailFull.append(thumbnailPrepared.padded)

        var thumbnailSeed = AttachmentKeyDerivation.deriveThumbnailBlobSeed(
            masterSeed: masterSeed,
            mainBlobID: mainBlobID
        )
        defer { thumbnailSeed.securelyWipe() }
        let thumbnailBlob = try sealBlob(
            plaintext: &thumbnailFull,
            seed: thumbnailSeed,
            blobID: thumbnailBlobID,
            bucket: thumbnailPrepared.bucket,
            realLength: thumbnailPrepared.realLength
        )
        thumbnailFull.securelyWipe()

        var sealedCap: Data?
        if let cap = captionPlaintext, !cap.isEmpty {
            do {
                sealedCap = try AttachmentSlotCipher.sealCaption(
                    plaintext: cap,
                    seed: masterSeed,
                    blobID: mainBlobID
                )
            } catch let error as AttachmentSlotCipher.Error {
                throw SealError.slotCipher(error)
            } catch {
                throw SealError.slotCipher(.sealFailed)
            }
        }

        let wrap: (descriptorFingerprint: Data, payload: AttachmentSeedWrap.WrappedSeedPayload)
        do {
            wrap = try AttachmentSeedWrap.wrap(
                seed: masterSeed,
                recipientKyberPublicKey: recipientKyberPublicKey,
                recipientX25519PublicKey: recipientX25519PublicKey,
                blobID: mainBlobID
            )
        } catch let error as AttachmentSeedWrap.Error {
            throw SealError.seedWrap(error)
        } catch {
            throw SealError.seedWrap(.wrapFailed)
        }

        return SealedV2(
            mainBlob: mainBlob,
            thumbnailBlob: thumbnailBlob,
            mime: prepared.mime,
            dimensions: prepared.dimensions,
            sealedSeed: wrap.descriptorFingerprint,
            seedPayload: wrap.payload,
            sealedCaption: sealedCap
        )
    }

    // MARK: - Header helpers

    /// Pack the 32-byte header used as plaintext prefix of chunk 0, per
    /// PHASE3_SERVER_SPEC.md §5.4. The chunk_count field is written as u16
    /// BE at bytes [15..17] and may be patched after the header is built.
    ///
    /// Layout (32 bytes):
    ///   0        version      u8  = 1
    ///   1..3     flags        u16 BE = 0
    ///   3..11    real_length  u64 BE
    ///   11..13   mime         u16 BE (upper = 0, lower = AttachmentMimeType)
    ///   13..15   bucket       u16 BE (upper = 0, lower = AttachmentBucket)
    ///   15..17   chunk_count       u16 BE
    ///   17..19   thumbnail_length  u16 BE (plaintext bytes inside slot)
    ///   19..21   reserved          u16 BE = 0
    ///   21..32   entropy           11 random bytes
    static func buildHeader(
        realLength: UInt64,
        mime: AttachmentMimeType,
        bucket: AttachmentBucket,
        chunkCount: UInt16,
        thumbnailLength: UInt16
    ) throws -> Data {
        var h = Data(count: 32)
        h[0] = AttachmentDescriptor.currentVersion

        // flags = 0
        h[1] = 0
        h[2] = 0

        // real_length at bytes 3..11
        var rl = realLength.bigEndian
        withUnsafeBytes(of: &rl) { raw in
            for i in 0..<8 {
                h[3 + i] = raw[i]
            }
        }

        // mime at bytes 11..13
        h[11] = 0
        h[12] = mime.rawValue

        // bucket at bytes 13..15
        h[13] = 0
        h[14] = bucket.rawValue

        // chunk_count at bytes 15..17
        var cc = chunkCount.bigEndian
        withUnsafeBytes(of: &cc) { raw in
            h[15] = raw[0]
            h[16] = raw[1]
        }

        // reserved bytes 17..21 — now split into thumbnail_length (17..19)
        // and reserved u16 (19..21).
        var tl = thumbnailLength.bigEndian
        withUnsafeBytes(of: &tl) { raw in
            h[17] = raw[0]
            h[18] = raw[1]
        }
        h[19] = 0
        h[20] = 0

        // entropy bytes 21..32 (11 B)
        let entropy = try randomBytes(count: 11)
        for i in 0..<11 { h[21 + i] = entropy[i] }

        return h
    }

    private static func sealBlob(
        plaintext: inout Data,
        seed: Data,
        blobID: Data,
        bucket: AttachmentBucket,
        realLength: Int
    ) throws -> SealedBlobV2 {
        let chunkSize = AttachmentLimits.plaintextChunkBytes
        let total = plaintext.count
        let rawCount = (total + chunkSize - 1) / chunkSize
        // P7-BLOB-04: keep in lockstep with blob-relay `MAX_CHUNK_COUNT = 128`
        // (capability chunk_mask is 128 bits wide).
        guard rawCount <= 128 else { throw SealError.chunkCountOverflow }
        let chunkCount = UInt32(rawCount)

        patchChunkCount(in: &plaintext, chunkCount: chunkCount)

        let contentKeyBase = AttachmentKeyDerivation.deriveContentKeyBase(
            seed: seed,
            blobID: blobID
        )
        var frames: [Data] = []
        frames.reserveCapacity(Int(chunkCount))
        for i in 0..<Int(chunkCount) {
            let start = i * chunkSize
            let end = min(start + chunkSize, total)
            // FIX AUDIT3-IOS-13: per-iteration plaintext slice wipe.
            // subdata(in:) returns an independent buffer copy; without an
            // explicit memset the up-to-256 KB plaintext slot lingers in
            // the heap until ARC reclaims it (and the freed slot keeps the
            // bytes until reused). On a memory dump captured while sealing
            // a multi-chunk attachment, an attacker could harvest the
            // entire plaintext across chunks. var + defer wipes each slice
            // before the next iteration overwrites the binding.
            var plain = plaintext.subdata(in: start..<end)
            defer { plain.securelyWipe() }
            do {
                let frame = try AttachmentChunkCipher.seal(
                    plaintext: plain,
                    contentKeyBase: contentKeyBase,
                    blobID: blobID,
                    chunkIndex: UInt32(i),
                    chunkCount: chunkCount,
                    bucket: bucket
                )
                frames.append(frame)
            } catch let error as AttachmentChunkCipher.Error {
                throw SealError.chunkCipher(error)
            } catch {
                throw SealError.chunkCipher(.sealFailed)
            }
        }

        let digest = AttachmentMerkle.root(of: frames)
        precondition(digest.count == 32)

        return SealedBlobV2(
            blobID: blobID,
            frames: frames,
            chunkCount: chunkCount,
            bucket: bucket,
            digest: digest,
            realLength: realLength
        )
    }

    private static func patchChunkCount(in plaintext: inout Data, chunkCount: UInt32) {
        var hc = chunkCount.bigEndian
        withUnsafeBytes(of: &hc) { raw in
            let low = Array(raw)[2...3]
            plaintext[15] = low[low.startIndex]
            plaintext[16] = low[low.startIndex + 1]
        }
    }

    private static func randomBytes(count: Int) throws -> Data {
        var buf = Data(count: count)
        let status = buf.withUnsafeMutableBytes { ptr -> Int32 in
            guard let base = ptr.baseAddress else { return errSecAllocate }
            return SecRandomCopyBytes(kSecRandomDefault, count, base)
        }
        guard status == errSecSuccess else { throw SealError.rngFailed }
        return buf
    }
}
