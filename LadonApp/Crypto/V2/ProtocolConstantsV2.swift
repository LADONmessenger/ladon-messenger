//
//  ProtocolConstantsV2.swift
//  Ladon — wire-format constants mirroring `relay-core-v2/src/constants.rs`.
//
//  IMPORTANT: every value here is part of the on-the-wire Ladon v0.2 protocol
//  contract. Any change MUST be matched in the relay Rust crate AND covered by
//  the cross-language test vectors.
//

import Foundation

enum LadonV2 {

    // MARK: Protocol & limits
    /// Relay protocol version (Addendum A1): first byte of the delivery
    /// bundle. Mirrors `RELAY_PROTOCOL_VERSION`. Requests carry their own
    /// version since A2 (`SealedV2.version`, 0x06). Unrelated
    /// to the inner-plaintext version (0x02 real / 0x03 cover) and to the
    /// ratchet frame version.
    static let relayProtocolVersion: UInt8 = 0x05
    /// Version byte bound into the inner AAD (`INNER_AAD_VERSION`): the
    /// inner-plaintext version of a real message, unchanged by A1.
    static let innerAadVersion: UInt8 = 0x02
    static let clockSkewToleranceSec: UInt64 = 120
    static let mailboxTtlSec: UInt64 = 7 * 24 * 3_600
    static let fetchResponseMaxBytes: Int = 1_048_576
    /// A1 §8 step 4: the exit refuses an envelope whose `sent_at` is further
    /// than this from its clock (`SENT_AT_WINDOW_SEC`).
    static let sentAtWindowSec: UInt64 = 300

    // MARK: Identifier sizes
    static let recipientIdLen = 32
    static let exitIdLen = 16
    static let bundleIdLen = 16
    /// A1 §3.4: fresh random id per sealed envelope, the exit's replay key.
    static let envelopeIdLen = 16
    /// A1 §2: delivery key K, exit delivery key K_X and verifier V_X.
    static let deliveryKeyLen = 32
    static let deliveryVerifierLen = 32

    // MARK: Primitive sizes
    static let ed25519PkLen = 32
    static let ed25519SigLen = 64
    static let dilithium3PkLen = 1_952           // ML-DSA-65 (FIPS 204)
    static let dilithium3SigLen = 3_309
    static let kyber768PkLen = 1_184             // ML-KEM-768 (FIPS 203)
    static let kyber768CtLen = 1_088
    static let x25519PkLen = 32
    static let x25519CtLen = 32                  // sender's ephemeral X25519 pk
    static let aeadNonceLen = 12                 // ChaCha20-Poly1305
    static let aeadTagLen = 16

    // MARK: Hybrid sizes (derived)
    static let hkemPkLen = x25519PkLen + kyber768PkLen          // 1,216
    static let hkemCtLen = x25519CtLen + kyber768CtLen          // 1,120
    static let hsigPkLen = ed25519PkLen + dilithium3PkLen       // 1,984
    static let hsigSigLen = ed25519SigLen + dilithium3SigLen    // 3,373

    // MARK: Delivery bundle wire layout (A1 §3.2) — fixed 6,678 B
    static let bundleOffVersion = 0
    static let bundleOffRecipientId = 1
    static let bundleOffHsigPk = 33
    static let bundleOffHkemPk = 33 + hsigPkLen                 // 2,017
    static let bundleOffBundleId = bundleOffHkemPk + hkemPkLen  // 3,233
    static let bundleOffPublishedAt = bundleOffBundleId + bundleIdLen   // 3,249
    static let bundleOffExitId = bundleOffPublishedAt + 8               // 3,257
    static let bundleOffVerifier = bundleOffExitId + exitIdLen          // 3,273
    static let bundleOffSig = bundleOffVerifier + deliveryVerifierLen   // 3,305
    static let bundleBodyLen = bundleOffSig                             // 3,305
    static let bundleLen = bundleBodyLen + hsigSigLen                   // 6,678

    // MARK: Domain-separation strings (Spec §3.6)
    static let aadInnerV1 = Data("L1-Inner-v1".utf8)
    static let domainSign = Data("L1-Sig-v1".utf8)               // HSig prehash
    /// A1 §2.2 / §2.3: K_X = HKDF-SHA256(salt, K, info ‖ exit_id),
    /// V_X = SHA-256(verify-domain ‖ K_X).
    static let domainDeliverSalt = Data("L1-DeliverSalt-v1".utf8)
    static let domainDeliverInfo = Data("L1-Deliver-v1".utf8)
    static let domainDeliverVerify = Data("L1-DeliverVerify-v1".utf8)
    /// Acknowledged fetch: `"L1-FetchAck-v2" || exit_id16 || rid || ts_be8 || ack16`
    /// (mirrors `DOMAIN_FETCH_ACK_AUTH` in `relay-core-v2/src/constants.rs`).
    /// v2 (P8-AUDIT8-IOS-31, audit F12) binds the signature to the target exit;
    /// exits accept nothing else.
    static let domainFetchAck = Data("L1-FetchAck-v2".utf8)
    /// Batch id of an acknowledged fetch (`FETCH_BATCH_ID_LEN`); all-zero = no ack.
    static let fetchBatchIdLen = 16
    static let hkemSalt = Data("L1-HKEM-v1".utf8)

    // MARK: v2.1 push-relay (Spec §4.9, mirrors `relay-core-v2/src/constants.rs`)
    /// 32-byte APNs device token (raw bytes from `didRegisterForRemoteNotificationsWithDeviceToken`).
    static let apnsTokenLen = 32
    /// Push registration body length (carried by the sealed PUSH_REGISTER, A2 §4.4):
    ///   apns_token(32) || sandbox(1) || timestamp_be(8) || hsig(3,373) = 3,414 B.
    static let pushRegisterBodyLen = apnsTokenLen + 1 + 8 + hsigSigLen
    /// Domain separator for the hsig pre-image of a push registration.
    /// MUST match `DOMAIN_PUSH_REGISTER` in the Rust relay-core-v2 crate.
    static let domainPushRegister = Data("L1-PushRegister-v2.1".utf8)
}

/// Errors emitted by Ladon v2 wire-format and crypto operations.
enum LadonV2Error: Error, CustomStringConvertible {
    case shortBuffer(expected: Int, got: Int)
    case unsupportedVersion(UInt8)
    case structuralInvariant(String)
    case cryptoFailure(String)
    case signatureInvalid

    var description: String {
        switch self {
        case let .shortBuffer(expected, got):
            return "Short buffer: expected \(expected) bytes, got \(got)."
        case let .unsupportedVersion(v):
            return "Unsupported protocol version: 0x\(String(v, radix: 16, uppercase: false))."
        case let .structuralInvariant(msg):
            return "Structural invariant violated: \(msg)."
        case let .cryptoFailure(msg):
            return "Crypto failure: \(msg)."
        case .signatureInvalid:
            return "Signature verification failed."
        }
    }
}
