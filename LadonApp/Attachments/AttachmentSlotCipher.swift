// AttachmentSlotCipher.swift — Phase 2
//
// Encrypts and decrypts the two fixed-size AEAD slots inside the
// ``AttachmentDescriptor``:
//
//   * Thumbnail slot — fixed 4096 bytes, padded with random bytes after the
//                      AEAD frame so the envelope size does not leak the
//                      thumbnail's true size. See PHASE3_SERVER_SPEC.md §5.5.
//   * Caption slot  — variable, ≤ 1024 bytes (AEAD frame only, no padding).
//
// Both slots use a dedicated per-blob key derived via
// ``AttachmentKeyDerivation`` and a domain-separated AAD so a cross-slot
// replay fails immediately.

import Foundation
import CryptoKit
import Security

public enum AttachmentSlotCipher {

    public enum Error: Swift.Error, Equatable {
        case rngFailed
        case thumbnailTooLarge
        case captionTooLarge
        case sealFailed
        case openFailed
        case slotSizeMismatch
    }

    private static let slotByteCount = AttachmentDescriptor.sealedThumbnailByteCount
    private static let captionMax = AttachmentDescriptor.sealedCaptionMaxByteCount

    /// Maximum plaintext thumbnail bytes that fit inside the 4096-byte slot
    /// after AEAD framing (12-byte nonce + 16-byte tag = 28 bytes overhead).
    public static let thumbnailPlaintextLimit = slotByteCount - 12 - 16  // 4068 B

    /// Seal a thumbnail plaintext into the fixed 4096-byte slot.
    /// Layout (4096 bytes):
    ///   nonce (12) || ciphertext (plaintext.count) || tag (16) || random_pad
    public static func sealThumbnail(
        plaintext: Data,
        seed: Data,
        blobID: Data
    ) throws -> Data {
        guard plaintext.count <= thumbnailPlaintextLimit else {
            throw Error.thumbnailTooLarge
        }

        let key = AttachmentKeyDerivation.deriveThumbnailKey(seed: seed, blobID: blobID)
        let nonce = try randomBytes(count: 12)
        var aad = Data()
        aad.append(Data("\(AttachmentKeyDerivation.domainPrefix)thumb".utf8))
        aad.append(blobID)

        let chachaNonce: ChaChaPoly.Nonce
        let sealed: ChaChaPoly.SealedBox
        do {
            chachaNonce = try ChaChaPoly.Nonce(data: nonce)
            sealed = try ChaChaPoly.seal(plaintext, using: key, nonce: chachaNonce, authenticating: aad)
        } catch {
            throw Error.sealFailed
        }

        var frame = Data(capacity: 12 + plaintext.count + 16)
        frame.append(sealed.nonce.withUnsafeBytes { Data($0) })
        frame.append(sealed.ciphertext)
        frame.append(sealed.tag)

        let padLen = slotByteCount - frame.count
        if padLen > 0 {
            let pad = try randomBytes(count: padLen)
            frame.append(pad)
        }
        precondition(frame.count == slotByteCount)
        return frame
    }

    /// Open a 4096-byte thumbnail slot. Needs the explicit plaintext length
    /// to know where the AEAD tag ends; this length is carried in the header
    /// chunk of the attachment (see §5.4).
    public static func openThumbnail(
        slot: Data,
        plaintextLength: Int,
        seed: Data,
        blobID: Data
    ) throws -> Data {
        guard slot.count == slotByteCount else { throw Error.slotSizeMismatch }
        guard plaintextLength >= 0, plaintextLength <= thumbnailPlaintextLimit else {
            throw Error.openFailed
        }

        let key = AttachmentKeyDerivation.deriveThumbnailKey(seed: seed, blobID: blobID)
        var aad = Data()
        aad.append(Data("\(AttachmentKeyDerivation.domainPrefix)thumb".utf8))
        aad.append(blobID)

        let nonce = slot.prefix(12)
        let ct = slot.subdata(in: 12 ..< (12 + plaintextLength))
        let tag = slot.subdata(in: (12 + plaintextLength) ..< (12 + plaintextLength + 16))

        do {
            let chachaNonce = try ChaChaPoly.Nonce(data: nonce)
            let sealed = try ChaChaPoly.SealedBox(nonce: chachaNonce, ciphertext: ct, tag: tag)
            return try ChaChaPoly.open(sealed, using: key, authenticating: aad)
        } catch {
            throw Error.openFailed
        }
    }

    // MARK: Caption

    /// Seal a UTF-8 caption. Returns variable-length bytes ≤ 1024.
    /// A nil or empty caption returns nil; callers should set the descriptor's
    /// ``sealedCaption`` field accordingly.
    public static func sealCaption(
        plaintext: Data,
        seed: Data,
        blobID: Data
    ) throws -> Data {
        let maxInner = captionMax - 12 - 16
        guard plaintext.count <= maxInner else {
            throw Error.captionTooLarge
        }

        let key = AttachmentKeyDerivation.deriveCaptionKey(seed: seed, blobID: blobID)
        let nonce = try randomBytes(count: 12)
        var aad = Data()
        aad.append(Data("\(AttachmentKeyDerivation.domainPrefix)caption".utf8))
        aad.append(blobID)

        let chachaNonce: ChaChaPoly.Nonce
        let sealed: ChaChaPoly.SealedBox
        do {
            chachaNonce = try ChaChaPoly.Nonce(data: nonce)
            sealed = try ChaChaPoly.seal(plaintext, using: key, nonce: chachaNonce, authenticating: aad)
        } catch {
            throw Error.sealFailed
        }

        var frame = Data(capacity: 12 + plaintext.count + 16)
        frame.append(sealed.nonce.withUnsafeBytes { Data($0) })
        frame.append(sealed.ciphertext)
        frame.append(sealed.tag)
        return frame
    }

    public static func openCaption(
        frame: Data,
        seed: Data,
        blobID: Data
    ) throws -> Data {
        guard frame.count >= 12 + 16, frame.count <= captionMax else {
            throw Error.openFailed
        }

        let key = AttachmentKeyDerivation.deriveCaptionKey(seed: seed, blobID: blobID)
        var aad = Data()
        aad.append(Data("\(AttachmentKeyDerivation.domainPrefix)caption".utf8))
        aad.append(blobID)

        let nonce = frame.prefix(12)
        let tagStart = frame.count - 16
        let ct = frame.subdata(in: 12..<tagStart)
        let tag = frame.suffix(16)

        do {
            let chachaNonce = try ChaChaPoly.Nonce(data: nonce)
            let sealed = try ChaChaPoly.SealedBox(nonce: chachaNonce, ciphertext: ct, tag: tag)
            return try ChaChaPoly.open(sealed, using: key, authenticating: aad)
        } catch {
            throw Error.openFailed
        }
    }

    // MARK: - Internal

    private static func randomBytes(count: Int) throws -> Data {
        var buf = Data(count: count)
        let status = buf.withUnsafeMutableBytes { ptr -> Int32 in
            guard let base = ptr.baseAddress else { return errSecAllocate }
            return SecRandomCopyBytes(kSecRandomDefault, count, base)
        }
        guard status == errSecSuccess else { throw Error.rngFailed }
        return buf
    }
}
