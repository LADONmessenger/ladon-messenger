// AttachmentChunkCipher.swift — Phase 2
//
// Encrypts and decrypts 256 KB plaintext chunks using per-chunk keys and
// per-chunk random 12-byte nonces, per PHASE3_SERVER_SPEC.md §5.3.
//
//     AAD_i = blob_id (16B) || BE32(i) || BE32(chunk_count) || bucket (1B)
//     ct_i  = ChaCha20-Poly1305(key=chunk_key_i, nonce=n_i, AAD=AAD_i, pt_i)
//     frame = n_i (12B) || ct_i
//
// Because the key is derived from the content-key-base with HKDF using the
// chunk index in the info string (see AttachmentKeyDerivation), each chunk
// uses a unique key. The 12-byte nonce is random per chunk; with a unique
// key per chunk, nonce reuse is mathematically impossible.
//
// Chunk 0 additionally carries a 32-byte header as a plaintext prefix (see
// §5.4). The header is written by ``AttachmentSealer`` before this module is
// called; ``AttachmentChunkCipher`` has no special handling for it.

import Foundation
import CryptoKit
import Security

public enum AttachmentChunkCipher {

    public enum Error: Swift.Error, Equatable {
        case invalidBlobID
        case invalidChunkCount
        case chunkIndexOutOfRange
        case rngFailed
        case sealFailed
        case openFailed
    }

    /// Seal a single chunk. Returns the wire frame (nonce ‖ ciphertext ‖ tag).
    public static func seal(
        plaintext: Data,
        contentKeyBase: SymmetricKey,
        blobID: Data,
        chunkIndex: UInt32,
        chunkCount: UInt32,
        bucket: AttachmentBucket
    ) throws -> Data {
        try validate(blobID: blobID, chunkIndex: chunkIndex, chunkCount: chunkCount)

        let key = AttachmentKeyDerivation.deriveChunkKey(
            base: contentKeyBase,
            blobID: blobID,
            chunkIndex: chunkIndex
        )
        let nonce = try randomBytes(count: 12)
        let aad = buildAAD(blobID: blobID, chunkIndex: chunkIndex, chunkCount: chunkCount, bucket: bucket)

        let chachaNonce: ChaChaPoly.Nonce
        do {
            chachaNonce = try ChaChaPoly.Nonce(data: nonce)
        } catch {
            throw Error.sealFailed
        }

        let sealedBox: ChaChaPoly.SealedBox
        do {
            sealedBox = try ChaChaPoly.seal(
                plaintext,
                using: key,
                nonce: chachaNonce,
                authenticating: aad
            )
        } catch {
            throw Error.sealFailed
        }

        // Wire order: nonce (12) || ciphertext || tag (16)
        var frame = Data(capacity: 12 + plaintext.count + 16)
        frame.append(sealedBox.nonce.withUnsafeBytes { Data($0) })
        frame.append(sealedBox.ciphertext)
        frame.append(sealedBox.tag)
        return frame
    }

    /// Open a single chunk frame. Returns the plaintext on success.
    /// The caller must have derived ``contentKeyBase`` from the unwrapped seed.
    public static func open(
        frame: Data,
        contentKeyBase: SymmetricKey,
        blobID: Data,
        chunkIndex: UInt32,
        chunkCount: UInt32,
        bucket: AttachmentBucket
    ) throws -> Data {
        try validate(blobID: blobID, chunkIndex: chunkIndex, chunkCount: chunkCount)
        guard frame.count >= 12 + 16 else {
            throw Error.openFailed
        }

        let key = AttachmentKeyDerivation.deriveChunkKey(
            base: contentKeyBase,
            blobID: blobID,
            chunkIndex: chunkIndex
        )
        let aad = buildAAD(blobID: blobID, chunkIndex: chunkIndex, chunkCount: chunkCount, bucket: bucket)

        let nonceBytes = frame.prefix(12)
        let tagStart = frame.count - 16
        let ciphertext = frame.subdata(in: 12..<tagStart)
        let tag = frame.suffix(16)

        let chachaNonce: ChaChaPoly.Nonce
        let sealedBox: ChaChaPoly.SealedBox
        do {
            chachaNonce = try ChaChaPoly.Nonce(data: nonceBytes)
            sealedBox = try ChaChaPoly.SealedBox(
                nonce: chachaNonce,
                ciphertext: ciphertext,
                tag: tag
            )
        } catch {
            throw Error.openFailed
        }

        do {
            return try ChaChaPoly.open(sealedBox, using: key, authenticating: aad)
        } catch {
            throw Error.openFailed
        }
    }

    // MARK: - Internal

    /// Per-chunk AEAD AAD (visible to anyone who sees the frame, but
    /// cryptographically bound into the tag).
    /// Layout (25 bytes):
    ///   blob_id (16) || chunk_index BE (4) || chunk_count BE (4) || bucket (1)
    static func buildAAD(
        blobID: Data,
        chunkIndex: UInt32,
        chunkCount: UInt32,
        bucket: AttachmentBucket
    ) -> Data {
        var aad = Data(capacity: 25)
        aad.append(blobID)
        var i = chunkIndex.bigEndian
        withUnsafeBytes(of: &i) { aad.append(contentsOf: $0) }
        var c = chunkCount.bigEndian
        withUnsafeBytes(of: &c) { aad.append(contentsOf: $0) }
        aad.append(bucket.rawValue)
        return aad
    }

    private static func validate(
        blobID: Data,
        chunkIndex: UInt32,
        chunkCount: UInt32
    ) throws {
        guard blobID.count == AttachmentDescriptor.blobIDByteCount else {
            throw Error.invalidBlobID
        }
        guard chunkCount > 0 else { throw Error.invalidChunkCount }
        guard chunkIndex < chunkCount else { throw Error.chunkIndexOutOfRange }
    }

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
