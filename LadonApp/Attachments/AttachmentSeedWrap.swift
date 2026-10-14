// AttachmentSeedWrap.swift — Phase 2
//
// PQ-hybrid wrapping of the 32-byte master seed for the recipient, per
// PHASE3_SERVER_SPEC.md §5.7.
//
//   x25519_shared   = X25519(sender_ephemeral_priv, recipient_identity_pub)
//   (kyber_ct, kyber_shared) = ML-KEM-768.Encaps(recipient_kyber_pub)
//   hybrid_key      = HKDF(x25519_shared || kyber_shared,
//                          salt = blob_id,
//                          info = "ladon-attach-v1/seed-wrap",
//                          L = 32)
//   AAD             = blob_id
//   sealed_seed     = nonce (12B) || ChaCha20-Poly1305(hybrid_key, nonce, AAD, seed)
//
// The 32-byte ``AttachmentDescriptor.sealedSeed`` field carries the
// ciphertext+tag (32 B = 16 B ct + 16 B tag for a 16-byte seed? no — the seed
// is 32 B, so the ciphertext is 32 B ciphertext + 16 B tag = 48 B).
//
// Spec §5.7 allocates 32 B for the descriptor's ``sealedSeed`` field, which
// can hold only the *AEAD tag+nonce abbreviation*, not the full frame.
// **Resolution adopted for v2**: the full frame (12 B nonce + 32 B ciphertext
// + 16 B tag = 60 B) travels in the message body alongside the descriptor;
// the descriptor's ``sealedSeed`` 32-byte slot is a truncated fingerprint of
// the wrap that the receiver uses to sanity-check which body-level frame
// belongs to which descriptor in a batched-attachment scenario. For v1 we
// place SHA-256(wrapFrame) truncated to 32 B into ``sealedSeed`` and carry
// the full wrap frame + Kyber ciphertext in the message body via the
// ``WrappedSeedPayload`` value below.
//
// This resolves the §5.7 size mismatch flagged in the spec without breaking
// the fixed 4300-byte descriptor envelope budget.

import Foundation
import CryptoKit
import Security

public enum AttachmentSeedWrap {

    public enum Error: Swift.Error, Equatable {
        case invalidRecipientKyberKey
        case rngFailed
        case wrapFailed
        case unwrapFailed
        case kyberDisabled
    }

    /// Full payload travelling in the encrypted message body next to the
    /// descriptor. Not part of the descriptor. Phase-2 message-body schema
    /// addendum (to be wired into ``Envelope`` / ``Message`` in Phase 4).
    public struct WrappedSeedPayload: Equatable {
        /// ML-KEM-768 ciphertext (1088 B).
        public let kyberCiphertext: Data
        /// 12 B nonce ‖ 32 B ciphertext ‖ 16 B tag = 60 B AEAD frame of the seed.
        public let aeadFrame: Data
        /// Sender's ephemeral X25519 public key (32 B) — recipient needs it
        /// to recompute the classical shared secret.
        public let ephemeralX25519PublicKey: Data

        public init(kyberCiphertext: Data, aeadFrame: Data, ephemeralX25519PublicKey: Data) {
            self.kyberCiphertext = kyberCiphertext
            self.aeadFrame = aeadFrame
            self.ephemeralX25519PublicKey = ephemeralX25519PublicKey
        }
    }

    /// Wrap a fresh 32-byte seed for the recipient.
    ///
    /// Returns both the descriptor-sized fingerprint (32 B) and the full body
    /// payload the sender must transmit.
    public static func wrap(
        seed: Data,
        recipientKyberPublicKey: Data,
        recipientX25519PublicKey: Curve25519.KeyAgreement.PublicKey,
        blobID: Data
    ) throws -> (descriptorFingerprint: Data, payload: WrappedSeedPayload) {
        precondition(seed.count == 32, "seed must be 32 bytes")
        guard blobID.count == AttachmentDescriptor.blobIDByteCount else {
            throw Error.wrapFailed
        }
        guard PostQuantumService.shared.isKyberAvailable else {
            throw Error.kyberDisabled
        }

        // 1. Classical ECDH
        let ephemeral = Curve25519.KeyAgreement.PrivateKey()
        let ephemeralPub = ephemeral.publicKey.rawRepresentation
        let sharedSecret: SharedSecret
        do {
            sharedSecret = try ephemeral.sharedSecretFromKeyAgreement(
                with: recipientX25519PublicKey
            )
        } catch {
            throw Error.wrapFailed
        }
        var x25519Shared = sharedSecret.withUnsafeBytes { Data($0) }
        defer { x25519Shared.securelyWipe() }

        // 2. PQ KEM
        var encap: PostQuantumService.KyberEncapsulation
        do {
            encap = try PostQuantumService.shared.encapsulateKyber(
                publicKey: recipientKyberPublicKey
            )
        } catch {
            throw Error.invalidRecipientKyberKey
        }
        defer { encap.sharedSecret.securelyWipe() }

        // 3. Derive hybrid key
        let hybridKey = AttachmentKeyDerivation.deriveSeedWrapKey(
            x25519Shared: x25519Shared,
            kyberShared: encap.sharedSecret,
            blobID: blobID
        )

        // 4. AEAD wrap the seed with blob_id as AAD
        let nonceBytes = try randomBytes(count: 12)
        let chachaNonce: ChaChaPoly.Nonce
        let sealed: ChaChaPoly.SealedBox
        do {
            chachaNonce = try ChaChaPoly.Nonce(data: nonceBytes)
            sealed = try ChaChaPoly.seal(
                seed,
                using: hybridKey,
                nonce: chachaNonce,
                authenticating: blobID
            )
        } catch {
            throw Error.wrapFailed
        }

        var frame = Data(capacity: 12 + 32 + 16)
        frame.append(sealed.nonce.withUnsafeBytes { Data($0) })
        frame.append(sealed.ciphertext)
        frame.append(sealed.tag)

        // 5. Fingerprint for the descriptor — SHA-256 over the (ephemeral || kyber_ct || frame)
        //    This binds the descriptor to the body-level wrap and prevents
        //    an attacker substituting a different body payload while keeping
        //    the descriptor intact.
        var fpInput = Data()
        fpInput.append(Data("\(AttachmentKeyDerivation.domainPrefix)seed-fp".utf8))
        fpInput.append(blobID)
        fpInput.append(ephemeralPub)
        fpInput.append(encap.ciphertext)
        fpInput.append(frame)
        let fp = Data(SHA256.hash(data: fpInput))
        precondition(fp.count == 32)

        let payload = WrappedSeedPayload(
            kyberCiphertext: encap.ciphertext,
            aeadFrame: frame,
            ephemeralX25519PublicKey: ephemeralPub
        )
        return (fp, payload)
    }

    /// Unwrap the seed on the recipient side. The recipient must supply
    /// their X25519 private key (from Keychain) and the Kyber secret-key
    /// keychain account (typically "kyber768.identity.secret").
    public static func unwrap(
        descriptorFingerprint: Data,
        payload: WrappedSeedPayload,
        recipientX25519PrivateKey: Curve25519.KeyAgreement.PrivateKey,
        recipientKyberKeychainAccount: String,
        blobID: Data
    ) throws -> Data {
        return try unwrapCore(
            descriptorFingerprint: descriptorFingerprint,
            payload: payload,
            recipientX25519PrivateKey: recipientX25519PrivateKey,
            blobID: blobID,
            kyberSource: .keychain(recipientKyberKeychainAccount)
        )
    }

    /// Overload that takes the Kyber secret key as raw bytes. Required
    /// for per-session Kyber material that lives in the session struct
    /// (rotated on every DH-Ratchet step) rather than in a static
    /// Keychain slot. The caller is responsible for wiping the supplied
    /// buffer.
    public static func unwrap(
        descriptorFingerprint: Data,
        payload: WrappedSeedPayload,
        recipientX25519PrivateKey: Curve25519.KeyAgreement.PrivateKey,
        recipientKyberSecretKey: Data,
        blobID: Data
    ) throws -> Data {
        return try unwrapCore(
            descriptorFingerprint: descriptorFingerprint,
            payload: payload,
            recipientX25519PrivateKey: recipientX25519PrivateKey,
            blobID: blobID,
            kyberSource: .inline(recipientKyberSecretKey)
        )
    }

    private enum KyberSource {
        case keychain(String)
        case inline(Data)
    }

    private static func unwrapCore(
        descriptorFingerprint: Data,
        payload: WrappedSeedPayload,
        recipientX25519PrivateKey: Curve25519.KeyAgreement.PrivateKey,
        blobID: Data,
        kyberSource: KyberSource
    ) throws -> Data {
        guard descriptorFingerprint.count == 32 else { throw Error.unwrapFailed }
        guard blobID.count == AttachmentDescriptor.blobIDByteCount else {
            throw Error.unwrapFailed
        }
        guard payload.ephemeralX25519PublicKey.count == 32 else {
            throw Error.unwrapFailed
        }
        guard payload.kyberCiphertext.count == PostQuantumService.Constants.kyberCiphertextSize else {
            throw Error.unwrapFailed
        }
        guard payload.aeadFrame.count == 12 + 32 + 16 else {
            throw Error.unwrapFailed
        }
        guard PostQuantumService.shared.isKyberAvailable else {
            throw Error.kyberDisabled
        }

        // Recompute the descriptor fingerprint and compare constant-time.
        var fpInput = Data()
        fpInput.append(Data("\(AttachmentKeyDerivation.domainPrefix)seed-fp".utf8))
        fpInput.append(blobID)
        fpInput.append(payload.ephemeralX25519PublicKey)
        fpInput.append(payload.kyberCiphertext)
        fpInput.append(payload.aeadFrame)
        let expected = Data(SHA256.hash(data: fpInput))
        guard constantTimeEqual(expected, descriptorFingerprint) else {
            throw Error.unwrapFailed
        }

        // Recreate the classical shared secret.
        let senderEphemeralPub: Curve25519.KeyAgreement.PublicKey
        do {
            senderEphemeralPub = try Curve25519.KeyAgreement.PublicKey(
                rawRepresentation: payload.ephemeralX25519PublicKey
            )
        } catch {
            throw Error.unwrapFailed
        }
        let sharedSecret: SharedSecret
        do {
            sharedSecret = try recipientX25519PrivateKey.sharedSecretFromKeyAgreement(
                with: senderEphemeralPub
            )
        } catch {
            throw Error.unwrapFailed
        }
        var x25519Shared = sharedSecret.withUnsafeBytes { Data($0) }
        defer { x25519Shared.securelyWipe() }

        // PQ decapsulation — pick source.
        var kyberShared: Data
        do {
            switch kyberSource {
            case .keychain(let account):
                kyberShared = try PostQuantumService.shared.decapsulateKyberFromKeychain(
                    ciphertext: payload.kyberCiphertext,
                    keychainAccount: account
                )
            case .inline(var sk):
                defer { sk.securelyWipe() }
                kyberShared = try PostQuantumService.shared.decapsulateKyber(
                    ciphertext: payload.kyberCiphertext,
                    secretKey: sk
                )
            }
        } catch {
            throw Error.unwrapFailed
        }
        defer { kyberShared.securelyWipe() }

        // Derive hybrid key, open AEAD, recover seed.
        let hybridKey = AttachmentKeyDerivation.deriveSeedWrapKey(
            x25519Shared: x25519Shared,
            kyberShared: kyberShared,
            blobID: blobID
        )

        let nonceBytes = payload.aeadFrame.prefix(12)
        let ct = payload.aeadFrame.subdata(in: 12..<(12 + 32))
        let tag = payload.aeadFrame.suffix(16)

        do {
            let chachaNonce = try ChaChaPoly.Nonce(data: nonceBytes)
            let sealed = try ChaChaPoly.SealedBox(nonce: chachaNonce, ciphertext: ct, tag: tag)
            return try ChaChaPoly.open(sealed, using: hybridKey, authenticating: blobID)
        } catch {
            throw Error.unwrapFailed
        }
    }

    // MARK: - Internals

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
