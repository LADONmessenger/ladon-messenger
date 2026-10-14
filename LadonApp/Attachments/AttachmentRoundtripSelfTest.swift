// AttachmentRoundtripSelfTest.swift — Phase 7
//
// DEBUG-only end-to-end roundtrip over the full attachment envelope
// without touching the network. Exercises the wire path:
//
//   prepareImage → Sealer.seal → (frames + descriptor + seedPayload)
//                → AttachmentUnsealer.open → verified plaintext
//
// Complements `AttachmentCryptoSelfTest` (primitive-level) by validating
// the composition of the full envelope including the header patch in
// `AttachmentSealer`, the Merkle root computed over the frames, the
// thumbnail slot, and the optional caption.
//
// SCOPE BOUNDARY
// --------------
// This test does NOT hit `blob.ladon.app`. It installs a temporary
// `FeatureFlags.debugAttachmentsOverride` so Sealer/Unsealer will run; it
// never flips the public build-time flag. `BlobRelayClient`,
// `AttachmentUploader`, `AttachmentDownloader` are validated separately on
// a developer-controlled host by pointing `BlobRelayClient.debugBaseURLOverride`
// at a local instance — that path is not auto-invoked here because it
// requires an out-of-process dependency.

#if DEBUG
import Foundation
import CoreGraphics
import ImageIO
import UniformTypeIdentifiers
import CryptoKit
import Security

@available(iOS 15.0, macOS 12.0, *)
public enum AttachmentRoundtripSelfTest {

    public enum Failure: Swift.Error, Equatable {
        case pngEncodeFailed
        case sealUnavailable
        case contentMismatch
        case thumbnailMismatch
        case captionMismatch
        case digestMismatchUndetected
        case kyberUnavailable
        case preparation(String)
        case seal(String)
        case unseal(String)
        case contentGate(String)
    }

    /// Runs the default image roundtrip. Throws on the first failure.
    public static func runAll() throws {
        try testReceiveContentGate()
        try testImageRoundtripWithCaption()
        try testTamperedFrameRejected()
        try testImageRoundtripOptionC()
    }

    // MARK: - Tests

    /// P8-AUDIT8-IOS-08: the receive gate accepts what our sender produces
    /// (JPEG within the pixel cap, ISO media with `ftyp`) and refuses any
    /// other format behind a declared type.
    static func testReceiveContentGate() throws {
        typealias Gate = AttachmentReceiveService.ContentGate
        func encoded(_ uti: CFString, width: Int, height: Int) throws -> Data {
            guard let ctx = CGContext(data: nil, width: width, height: height, bitsPerComponent: 8,
                                      bytesPerRow: 0, space: CGColorSpaceCreateDeviceRGB(),
                                      bitmapInfo: CGImageAlphaInfo.noneSkipLast.rawValue),
                  let image = ctx.makeImage() else { throw Failure.contentGate("no CGImage") }
            let out = NSMutableData()
            guard let dest = CGImageDestinationCreateWithData(out, uti, 1, nil) else {
                throw Failure.contentGate("no destination for \(uti)")
            }
            CGImageDestinationAddImage(dest, image, nil)
            guard CGImageDestinationFinalize(dest) else { throw Failure.contentGate("finalize \(uti)") }
            return out as Data
        }
        let jpeg = try encoded(UTType.jpeg.identifier as CFString, width: 64, height: 48)
        let wideJpeg = try encoded(UTType.jpeg.identifier as CFString, width: Gate.imageMaxPixelEdge + 1, height: 1)
        let png = try encoded(UTType.png.identifier as CFString, width: 64, height: 48)
        let ftyp = Data([0, 0, 0, 0x1C]) + Data("ftypM4A ".utf8) + Data(count: 20)
        let notFtyp = Data([0, 0, 0, 0x1C]) + Data("moovM4A ".utf8) + Data(count: 20)

        try Gate.validate(jpeg, mime: .jpeg)
        try Gate.validate(ftyp, mime: .mp4h264)
        try Gate.validate(ftyp, mime: .aac)
        let refused: [(Data, AttachmentMimeType, String)] = [
            (png, .jpeg, "PNG labelled JPEG"),
            (wideJpeg, .jpeg, "JPEG above the pixel cap"),
            (Data(count: 64), .jpeg, "zeros labelled JPEG"),
            (notFtyp, .mp4h264, "no ftyp box"),
            (jpeg, .aac, "JPEG labelled audio"),
            (png, .png, ".png never sent"),
            (jpeg, .webp, ".webp never sent"),
            (ftyp, .opus, ".opus never sent"),
        ]
        for (data, mime, label) in refused {
            do {
                try Gate.validate(data, mime: mime)
                throw Failure.contentGate("accepted: \(label)")
            } catch AttachmentReceiveService.ReceiveError.malformed {
                // expected
            }
        }
        guard Gate.thumbnailOrEmpty(jpeg) == jpeg,
              Gate.thumbnailOrEmpty(png).isEmpty,
              Gate.thumbnailOrEmpty(Data(count: 3072)).isEmpty else {
            throw Failure.contentGate("thumbnail filter")
        }
    }

    static func testImageRoundtripWithCaption() throws {
        guard PostQuantumService.shared.isKyberAvailable else {
            throw Failure.kyberUnavailable
        }

        // 1. Synthesise a deterministic 64×64 RGBA PNG — small enough to
        //    encode fast but non-trivial enough to exercise the image
        //    pipeline (EXIF strip + re-encode to JPEG + thumbnail).
        let pngBytes = try makeCheckerPNG(size: 64)

        // 2. Generate recipient identity keypairs.
        let xPriv = Curve25519.KeyAgreement.PrivateKey()
        let xPub = xPriv.publicKey
        let kyberKP = try PostQuantumService.shared.generateKyberKeypair()
        let testAccount = "kyber768.attachments.roundtrip"
        try stageKyberSecretInKeychain(secret: kyberKP.secretKey, account: testAccount)
        defer { removeKyberSecretFromKeychain(account: testAccount) }

        // 3. Flip the DEBUG-only feature override for the duration of this
        //    test. Restore in `defer` to keep global state clean for
        //    subsequent tests.
        let prior = FeatureFlags.debugAttachmentsOverride
        FeatureFlags.debugAttachmentsOverride = true
        defer { FeatureFlags.debugAttachmentsOverride = prior }

        // 4. Prepare image.
        let prepared: AttachmentPreparation.Prepared
        do {
            prepared = try AttachmentPreparation.prepareImage(pngBytes)
        } catch {
            throw Failure.preparation("\(error)")
        }

        // 5. Seal with a short caption.
        let captionText = "Hallo Ladon – Roundtrip"
        let captionBytes = Data(captionText.utf8)
        let sealed: AttachmentSealer.Sealed
        do {
            sealed = try AttachmentSealer.seal(
                prepared: prepared,
                recipientKyberPublicKey: kyberKP.publicKey,
                recipientX25519PublicKey: xPub,
                captionPlaintext: captionBytes
            )
        } catch {
            throw Failure.seal("\(error)")
        }

        // 6. Open with the unsealer — bypasses network entirely.
        let opened: AttachmentUnsealer.Opened
        do {
            opened = try AttachmentUnsealer.open(
                descriptor: sealed.descriptor,
                frames: sealed.frames,
                seedPayload: sealed.seedPayload,
                recipientX25519PrivateKey: xPriv,
                recipientKyberKeychainAccount: testAccount
            )
        } catch {
            throw Failure.unseal("\(error)")
        }

        // 7. Content sanity — realLength bytes of plaintext must match the
        //    prepared sanitised JPEG exactly (the header+padding is
        //    stripped inside the unsealer).
        let expectedContent = prepared.paddedPlaintext.prefix(prepared.realLength)
        let actualContent = opened.content.prefix(prepared.realLength)
        guard expectedContent == actualContent else {
            throw Failure.contentMismatch
        }
        guard opened.thumbnail == prepared.thumbnailPlaintext else {
            throw Failure.thumbnailMismatch
        }
        guard opened.caption == captionBytes else {
            throw Failure.captionMismatch
        }

        // 8. P8-AUDIT8-IOS-08: what our own sender produces passes the
        //    receive gate unchanged (content and thumbnail).
        do {
            try AttachmentReceiveService.ContentGate.validate(Data(actualContent), mime: sealed.descriptor.mime)
        } catch {
            throw Failure.contentGate("own image refused: \(error)")
        }
        guard AttachmentReceiveService.ContentGate.thumbnailOrEmpty(opened.thumbnail) == opened.thumbnail else {
            throw Failure.contentGate("own thumbnail dropped")
        }

        // 9. P8-AUDIT8-IOS-09: the cache key binds contact and payload.
        let payload = AttachmentMessagePayload(
            descriptor: sealed.descriptor,
            seed: AttachmentMessagePayload.SeedPayload(from: sealed.seedPayload),
            readCap: "read-cap-a"
        )
        let otherCap = AttachmentMessagePayload(
            descriptor: sealed.descriptor,
            seed: AttachmentMessagePayload.SeedPayload(from: sealed.seedPayload),
            readCap: "read-cap-b"
        )
        let k1 = try AttachmentDownloadCache.cacheKey(payload: payload, contactID: "contact-a")
        let k2 = try AttachmentDownloadCache.cacheKey(payload: payload, contactID: "contact-a")
        let k3 = try AttachmentDownloadCache.cacheKey(payload: payload, contactID: "contact-b")
        let k4 = try AttachmentDownloadCache.cacheKey(payload: otherCap, contactID: "contact-a")
        guard k1 == k2, k1 != k3, k1 != k4 else {
            throw Failure.contentGate("cache key not bound to contact and payload")
        }
    }

    /// Flipping a single byte in any frame must cause `UnsealError.digestMismatch`.
    static func testTamperedFrameRejected() throws {
        guard PostQuantumService.shared.isKyberAvailable else {
            throw Failure.kyberUnavailable
        }

        let pngBytes = try makeCheckerPNG(size: 32)

        let xPriv = Curve25519.KeyAgreement.PrivateKey()
        let xPub = xPriv.publicKey
        let kyberKP = try PostQuantumService.shared.generateKyberKeypair()
        let testAccount = "kyber768.attachments.roundtrip.tamper"
        try stageKyberSecretInKeychain(secret: kyberKP.secretKey, account: testAccount)
        defer { removeKyberSecretFromKeychain(account: testAccount) }

        let prior = FeatureFlags.debugAttachmentsOverride
        FeatureFlags.debugAttachmentsOverride = true
        defer { FeatureFlags.debugAttachmentsOverride = prior }

        let prepared = try AttachmentPreparation.prepareImage(pngBytes)
        let sealed = try AttachmentSealer.seal(
            prepared: prepared,
            recipientKyberPublicKey: kyberKP.publicKey,
            recipientX25519PublicKey: xPub,
            captionPlaintext: nil
        )

        // Tamper the first byte of the first frame.
        var tampered = sealed.frames
        var firstFrame = tampered[0]
        firstFrame[0] ^= 0x01
        tampered[0] = firstFrame

        do {
            _ = try AttachmentUnsealer.open(
                descriptor: sealed.descriptor,
                frames: tampered,
                seedPayload: sealed.seedPayload,
                recipientX25519PrivateKey: xPriv,
                recipientKyberKeychainAccount: testAccount
            )
            throw Failure.digestMismatchUndetected
        } catch AttachmentUnsealer.UnsealError.digestMismatch {
            // expected — Merkle root check must fire before any AEAD open
        } catch Failure.digestMismatchUndetected {
            throw Failure.digestMismatchUndetected
        } catch {
            // Any unseal-side error is acceptable; the invariant is simply
            // “tampered input must not produce plaintext”. digestMismatch is
            // the expected specific branch, others are still fail-closed.
        }
    }

    static func testImageRoundtripOptionC() throws {
        guard PostQuantumService.shared.isKyberAvailable else {
            throw Failure.kyberUnavailable
        }

        let pngBytes = try makeCheckerPNG(size: 48)
        let xPriv = Curve25519.KeyAgreement.PrivateKey()
        let xPub = xPriv.publicKey
        let kyberKP = try PostQuantumService.shared.generateKyberKeypair()

        let prior = FeatureFlags.debugAttachmentsOverride
        FeatureFlags.debugAttachmentsOverride = true
        defer { FeatureFlags.debugAttachmentsOverride = prior }

        let prepared = try AttachmentPreparation.prepareImage(pngBytes)
        let captionBytes = Data("Option-C".utf8)
        let sealed = try AttachmentSealer.sealV2(
            prepared: prepared,
            recipientKyberPublicKey: kyberKP.publicKey,
            recipientX25519PublicKey: xPub,
            captionPlaintext: captionBytes
        )

        let descriptor = try AttachmentDescriptor(
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
                blobHost: BlobHost.selectFor(blobID: sealed.thumbnailBlob.blobID)
            ),
            blobHost: BlobHost.selectFor(blobID: sealed.mainBlob.blobID)
        )

        let opened = try AttachmentUnsealer.openV2(
            descriptor: descriptor,
            thumbnailBlob: descriptor.thumbnailBlob!,
            mainFrames: sealed.mainBlob.frames,
            thumbnailFrames: sealed.thumbnailBlob.frames,
            seedPayload: sealed.seedPayload,
            recipientX25519PrivateKey: xPriv,
            recipientKyberSecretKey: kyberKP.secretKey
        )

        let expectedContent = prepared.paddedPlaintext.prefix(prepared.realLength)
        let actualContent = opened.content.prefix(prepared.realLength)
        guard expectedContent == actualContent else {
            throw Failure.contentMismatch
        }
        guard opened.thumbnail == prepared.thumbnailPlaintext else {
            throw Failure.thumbnailMismatch
        }
        guard opened.caption == captionBytes else {
            throw Failure.captionMismatch
        }
    }

    // MARK: - PNG synthesis

    /// Produce a small RGBA PNG with a 2×2 colour checker pattern. Avoids
    /// bundling a binary fixture and gives the image pipeline real bytes to
    /// decode, re-encode, and thumbnail.
    private static func makeCheckerPNG(size: Int) throws -> Data {
        let colourSpace = CGColorSpaceCreateDeviceRGB()
        let bitmapInfo = CGBitmapInfo(rawValue: CGImageAlphaInfo.premultipliedLast.rawValue)
        guard let ctx = CGContext(
            data: nil,
            width: size,
            height: size,
            bitsPerComponent: 8,
            bytesPerRow: 4 * size,
            space: colourSpace,
            bitmapInfo: bitmapInfo.rawValue
        ) else {
            throw Failure.pngEncodeFailed
        }

        let half = CGFloat(size) / 2
        let tiles: [(CGRect, CGColor)] = [
            (CGRect(x: 0,    y: 0,    width: half, height: half), CGColor(red: 0.90, green: 0.20, blue: 0.20, alpha: 1)),
            (CGRect(x: half, y: 0,    width: half, height: half), CGColor(red: 0.20, green: 0.80, blue: 0.30, alpha: 1)),
            (CGRect(x: 0,    y: half, width: half, height: half), CGColor(red: 0.20, green: 0.30, blue: 0.90, alpha: 1)),
            (CGRect(x: half, y: half, width: half, height: half), CGColor(red: 0.95, green: 0.95, blue: 0.20, alpha: 1)),
        ]
        for (rect, colour) in tiles {
            ctx.setFillColor(colour)
            ctx.fill(rect)
        }
        guard let cgImage = ctx.makeImage() else { throw Failure.pngEncodeFailed }

        let data = NSMutableData()
        guard let dest = CGImageDestinationCreateWithData(
            data, UTType.png.identifier as CFString, 1, nil
        ) else {
            throw Failure.pngEncodeFailed
        }
        CGImageDestinationAddImage(dest, cgImage, nil)
        guard CGImageDestinationFinalize(dest) else {
            throw Failure.pngEncodeFailed
        }
        return data as Data
    }

    // MARK: - Keychain helpers

    private static func stageKyberSecretInKeychain(
        secret: Data,
        account: String
    ) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecAttrService as String: "app.ladon.messenger",
            kSecValueData as String: secret,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]
        SecItemDelete(query as CFDictionary)
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw NSError(domain: "AttachmentRoundtripSelfTest", code: Int(status))
        }
    }

    private static func removeKyberSecretFromKeychain(account: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecAttrService as String: "app.ladon.messenger"
        ]
        SecItemDelete(query as CFDictionary)
    }
}
#endif
