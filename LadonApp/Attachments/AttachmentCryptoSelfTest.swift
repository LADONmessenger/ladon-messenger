// AttachmentCryptoSelfTest.swift — Phase 2
//
// Deterministic, self-contained round-trip tests for the Phase-2 crypto
// primitives. Does **not** depend on XCTest (the Ladon project has no test
// target) and does **not** depend on ``FeatureFlags.attachmentsEnabled`` —
// exercising crypto is safe regardless of the flag because all operations
// happen on ephemeral in-memory data.
//
// Call ``AttachmentCryptoSelfTest.runAll()`` from debug utilities or a
// developer menu. Never wired into app launch.

#if DEBUG
import Foundation
import CryptoKit

public enum AttachmentCryptoSelfTest {

    public enum Failure: Swift.Error, Equatable {
        case chunkRoundtrip(String)
        case chunkTamperingUndetected
        case merkleMismatch
        case thumbnailRoundtrip(String)
        case captionRoundtrip(String)
        case seedWrapRoundtrip(String)
        case kyberUnavailable
        case realLengthBound(String)
    }

    /// Runs every self-test in a fixed order. Throws on first failure.
    public static func runAll() throws {
        try testRealLengthBound()
        try testChunkRoundtrip()
        try testChunkAADTampering()
        try testMerkleDeterminism()
        try testThumbnailRoundtrip()
        try testCaptionRoundtrip()
        try testSeedWrapRoundtrip()
    }

    // MARK: - Individual tests

    /// P8-AUDIT8-IOS-06: a peer-chosen real_length above the bucket — including
    /// values above Int.max, which used to trap in Int(_:) — is rejected with
    /// headerMismatch instead of crashing; valid lengths pass unchanged.
    static func testRealLengthBound() throws {
        let bucket = 1024
        for bad in [UInt64(1) << 63, UInt64.max, UInt64(bucket) + 1] {
            do {
                _ = try AttachmentUnsealer.checkedContentLength(bad, bucketBytes: bucket)
                throw Failure.realLengthBound("accepted \(bad)")
            } catch AttachmentUnsealer.UnsealError.headerMismatch {
                // expected
            }
        }
        for good in [UInt64(0), UInt64(1), UInt64(bucket)] {
            let n = try AttachmentUnsealer.checkedContentLength(good, bucketBytes: bucket)
            guard n == Int(good) else { throw Failure.realLengthBound("\(good) → \(n)") }
        }
    }

    static func testChunkRoundtrip() throws {
        let blobID = randomBytes(16)
        let seed = randomBytes(32)
        let contentKeyBase = AttachmentKeyDerivation.deriveContentKeyBase(
            seed: seed, blobID: blobID
        )
        let pt = randomBytes(256 * 1024)
        let bucket = AttachmentBucket.b512KB
        let frame: Data
        do {
            frame = try AttachmentChunkCipher.seal(
                plaintext: pt,
                contentKeyBase: contentKeyBase,
                blobID: blobID,
                chunkIndex: 0,
                chunkCount: 1,
                bucket: bucket
            )
        } catch {
            throw Failure.chunkRoundtrip("seal failed: \(error)")
        }
        let opened: Data
        do {
            opened = try AttachmentChunkCipher.open(
                frame: frame,
                contentKeyBase: contentKeyBase,
                blobID: blobID,
                chunkIndex: 0,
                chunkCount: 1,
                bucket: bucket
            )
        } catch {
            throw Failure.chunkRoundtrip("open failed: \(error)")
        }
        guard opened == pt else {
            throw Failure.chunkRoundtrip("plaintext mismatch")
        }
    }

    static func testChunkAADTampering() throws {
        let blobID = randomBytes(16)
        let seed = randomBytes(32)
        let contentKeyBase = AttachmentKeyDerivation.deriveContentKeyBase(
            seed: seed, blobID: blobID
        )
        let pt = randomBytes(1024)
        let frame = try AttachmentChunkCipher.seal(
            plaintext: pt,
            contentKeyBase: contentKeyBase,
            blobID: blobID,
            chunkIndex: 3,
            chunkCount: 10,
            bucket: .b1KB
        )

        // Flip the chunk index — AAD changes, tag must fail.
        do {
            _ = try AttachmentChunkCipher.open(
                frame: frame,
                contentKeyBase: contentKeyBase,
                blobID: blobID,
                chunkIndex: 4, // wrong index
                chunkCount: 10,
                bucket: .b1KB
            )
            throw Failure.chunkTamperingUndetected
        } catch AttachmentChunkCipher.Error.openFailed {
            // expected
        } catch Failure.chunkTamperingUndetected {
            throw Failure.chunkTamperingUndetected
        } catch {
            // any crypto failure is acceptable — the point is that open does
            // not return the plaintext.
        }

        // Flip bucket — same expectation.
        do {
            _ = try AttachmentChunkCipher.open(
                frame: frame,
                contentKeyBase: contentKeyBase,
                blobID: blobID,
                chunkIndex: 3,
                chunkCount: 10,
                bucket: .b16KB // wrong
            )
            throw Failure.chunkTamperingUndetected
        } catch AttachmentChunkCipher.Error.openFailed {
            // expected
        } catch Failure.chunkTamperingUndetected {
            throw Failure.chunkTamperingUndetected
        } catch {
            // acceptable
        }

        // Flip one byte of the ciphertext — tag must fail.
        var tampered = frame
        tampered[12] ^= 0x01
        do {
            _ = try AttachmentChunkCipher.open(
                frame: tampered,
                contentKeyBase: contentKeyBase,
                blobID: blobID,
                chunkIndex: 3,
                chunkCount: 10,
                bucket: .b1KB
            )
            throw Failure.chunkTamperingUndetected
        } catch AttachmentChunkCipher.Error.openFailed {
            // expected
        } catch Failure.chunkTamperingUndetected {
            throw Failure.chunkTamperingUndetected
        } catch {
            // acceptable
        }
    }

    static func testMerkleDeterminism() throws {
        let frames = (0..<7).map { _ in randomBytes(1024) }
        let root1 = AttachmentMerkle.root(of: frames)
        let root2 = AttachmentMerkle.root(of: frames)
        guard root1 == root2 else { throw Failure.merkleMismatch }
        guard root1.count == 32 else { throw Failure.merkleMismatch }

        // Changing a leaf must change the root.
        var frames2 = frames
        frames2[3][0] ^= 0x01
        let root3 = AttachmentMerkle.root(of: frames2)
        guard root3 != root1 else { throw Failure.merkleMismatch }
    }

    static func testThumbnailRoundtrip() throws {
        let blobID = randomBytes(16)
        let seed = randomBytes(32)
        let pt = randomBytes(1500)
        let slot = try AttachmentSlotCipher.sealThumbnail(
            plaintext: pt, seed: seed, blobID: blobID
        )
        guard slot.count == AttachmentDescriptor.sealedThumbnailByteCount else {
            throw Failure.thumbnailRoundtrip("wrong slot size")
        }
        let opened = try AttachmentSlotCipher.openThumbnail(
            slot: slot, plaintextLength: pt.count, seed: seed, blobID: blobID
        )
        guard opened == pt else {
            throw Failure.thumbnailRoundtrip("plaintext mismatch")
        }
    }

    static func testCaptionRoundtrip() throws {
        let blobID = randomBytes(16)
        let seed = randomBytes(32)
        let pt = Data("Hello, from the future. 📎".utf8)
        let frame = try AttachmentSlotCipher.sealCaption(
            plaintext: pt, seed: seed, blobID: blobID
        )
        let opened = try AttachmentSlotCipher.openCaption(
            frame: frame, seed: seed, blobID: blobID
        )
        guard opened == pt else {
            throw Failure.captionRoundtrip("plaintext mismatch")
        }
    }

    static func testSeedWrapRoundtrip() throws {
        guard PostQuantumService.shared.isKyberAvailable else {
            throw Failure.kyberUnavailable
        }
        // Generate recipient identity keypairs.
        let xPriv = Curve25519.KeyAgreement.PrivateKey()
        let xPub = xPriv.publicKey
        let kyberKP = try PostQuantumService.shared.generateKyberKeypair()

        // Stage the Kyber secret key in the keychain under a well-known
        // test account so decapsulateKyberFromKeychain can find it.
        let testAccount = "kyber768.selftest.secret"
        try stageKyberSecretInKeychain(
            secret: kyberKP.secretKey,
            account: testAccount
        )
        defer { try? removeKyberSecretFromKeychain(account: testAccount) }

        let blobID = randomBytes(16)
        let seed = randomBytes(32)

        let (fp, payload) = try AttachmentSeedWrap.wrap(
            seed: seed,
            recipientKyberPublicKey: kyberKP.publicKey,
            recipientX25519PublicKey: xPub,
            blobID: blobID
        )
        let recovered = try AttachmentSeedWrap.unwrap(
            descriptorFingerprint: fp,
            payload: payload,
            recipientX25519PrivateKey: xPriv,
            recipientKyberKeychainAccount: testAccount,
            blobID: blobID
        )
        guard recovered == seed else {
            throw Failure.seedWrapRoundtrip("seed mismatch after unwrap")
        }

        // Tamper the descriptor fingerprint — unwrap must fail.
        var badFp = fp
        badFp[0] ^= 0x01
        do {
            _ = try AttachmentSeedWrap.unwrap(
                descriptorFingerprint: badFp,
                payload: payload,
                recipientX25519PrivateKey: xPriv,
                recipientKyberKeychainAccount: testAccount,
                blobID: blobID
            )
            throw Failure.seedWrapRoundtrip("fingerprint tampering undetected")
        } catch AttachmentSeedWrap.Error.unwrapFailed {
            // expected
        } catch Failure.seedWrapRoundtrip {
            throw Failure.seedWrapRoundtrip("fingerprint tampering undetected")
        } catch {
            // acceptable
        }
    }

    // MARK: - Keychain helpers (DEBUG only)

    private static func stageKyberSecretInKeychain(
        secret: Data,
        account: String
    ) throws {
        // Must match the service string used by
        // ``PostQuantumService.loadFromKeychain`` (= "app.ladon.messenger")
        // so ``decapsulateKyberFromKeychain`` can retrieve this test key.
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
            throw NSError(domain: "AttachmentCryptoSelfTest", code: Int(status))
        }
    }

    private static func removeKyberSecretFromKeychain(account: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecAttrService as String: "app.ladon.messenger"
        ]
        SecItemDelete(query as CFDictionary)
    }

    // MARK: - Randomness

    private static func randomBytes(_ n: Int) -> Data {
        var buf = Data(count: n)
        _ = buf.withUnsafeMutableBytes { ptr in
            SecRandomCopyBytes(kSecRandomDefault, n, ptr.baseAddress!)
        }
        return buf
    }
}
#endif
