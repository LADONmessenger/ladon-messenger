//
//  BundleV2.swift
//  Ladon — delivery bundle wire format (Addendum A1 §3.2).
//
//  Layout (fixed 6,678 B):
//    off=0      1 B     version              = 0x05 (relay protocol)
//    off=1      32 B    recipient_id         = SHA-256(recipient_hsig_pk)
//    off=33     1,984 B recipient_hsig_pk    (Ed25519_PK || Dilithium3_PK)
//    off=2,017  1,216 B recipient_hkem_pk    (X25519_PK   || Kyber768_PK)
//    off=3,233  16 B    bundle_id
//    off=3,249  8 B     published_at         (unix-seconds, BE)
//    off=3,257  16 B    exit_id              (the one exit this bundle is for)
//    off=3,273  32 B    verifier             V_X = SHA-256("L1-DeliverVerify-v1" || K_X)
//    off=3,305  3,373 B bundle_hsig          = HSig(IK_R, bytes[0..3305), tag "L1-Bundle-v3")
//
//  Mirrors `relay-core-v2/src/wire/bundle.rs`. The bundle holds no secret:
//  the verifier is a hash of K_X, and K never leaves the owner's contacts.
//

import Foundation

struct BundleV2: Equatable {
    var version: UInt8
    var recipientId: RecipientIdV2
    var recipientHsigPk: Data           // 1,984 B
    var recipientHkemPk: Data           // 1,216 B
    var bundleId: BundleIdV2
    var publishedAt: UInt64
    var exitId: ExitIdV2
    var verifier: Data                  // 32 B
    var bundleHsig: Data                // 3,373 B

    static func parse(_ buf: Data) throws -> BundleV2 {
        guard buf.count == LadonV2.bundleLen else {
            throw LadonV2Error.shortBuffer(expected: LadonV2.bundleLen, got: buf.count)
        }
        let version = buf[buf.startIndex + LadonV2.bundleOffVersion]
        guard version == LadonV2.relayProtocolVersion else {
            throw LadonV2Error.unsupportedVersion(version)
        }
        return BundleV2(
            version: version,
            recipientId: RecipientIdV2(bytes: subdata(buf, LadonV2.bundleOffRecipientId, LadonV2.recipientIdLen)),
            recipientHsigPk: subdata(buf, LadonV2.bundleOffHsigPk, LadonV2.hsigPkLen),
            recipientHkemPk: subdata(buf, LadonV2.bundleOffHkemPk, LadonV2.hkemPkLen),
            bundleId: BundleIdV2(bytes: subdata(buf, LadonV2.bundleOffBundleId, LadonV2.bundleIdLen)),
            publishedAt: readU64BE(buf, at: LadonV2.bundleOffPublishedAt),
            exitId: ExitIdV2(bytes: subdata(buf, LadonV2.bundleOffExitId, LadonV2.exitIdLen)),
            verifier: subdata(buf, LadonV2.bundleOffVerifier, LadonV2.deliveryVerifierLen),
            bundleHsig: subdata(buf, LadonV2.bundleOffSig, LadonV2.hsigSigLen)
        )
    }

    /// The bytes covered by `bundle_hsig`: everything before it.
    func signingInput() -> Data {
        precondition(recipientHsigPk.count == LadonV2.hsigPkLen)
        precondition(recipientHkemPk.count == LadonV2.hkemPkLen)
        precondition(verifier.count == LadonV2.deliveryVerifierLen)
        var out = Data(capacity: LadonV2.bundleLen)
        out.append(version)
        out.append(recipientId.bytes)
        out.append(recipientHsigPk)
        out.append(recipientHkemPk)
        out.append(bundleId.bytes)
        out.append(u64BE(publishedAt))
        out.append(exitId.bytes)
        out.append(verifier)
        precondition(out.count == LadonV2.bundleBodyLen)
        return out
    }

    func encode() -> Data {
        precondition(bundleHsig.count == LadonV2.hsigSigLen)
        var out = signingInput()
        out.append(bundleHsig)
        precondition(out.count == LadonV2.bundleLen)
        return out
    }

    /// Structural invariants that need no signature check.
    func validateStructure() throws {
        guard version == LadonV2.relayProtocolVersion else {
            throw LadonV2Error.unsupportedVersion(version)
        }
        guard recipientHsigPk.count == LadonV2.hsigPkLen else {
            throw LadonV2Error.structuralInvariant("hsig_pk length")
        }
        guard recipientHkemPk.count == LadonV2.hkemPkLen else {
            throw LadonV2Error.structuralInvariant("hkem_pk length")
        }
        guard verifier.count == LadonV2.deliveryVerifierLen else {
            throw LadonV2Error.structuralInvariant("verifier length")
        }
        guard bundleHsig.count == LadonV2.hsigSigLen else {
            throw LadonV2Error.structuralInvariant("bundle_hsig length")
        }
        // rid = SHA-256(hsig_pk) — the exit enforces the same binding.
        guard RecipientIdV2.fromIdentityKey(recipientHsigPk) == recipientId else {
            throw LadonV2Error.structuralInvariant("recipient_id != SHA-256(hsig_pk)")
        }
    }

    // MARK: Construction

    /// Build & sign the delivery bundle for `exitId` (A1 §4). The verifier is
    /// derived here from the owner's delivery key, so a caller cannot publish
    /// a verifier that does not match K.
    static func issue(
        recipientId: RecipientIdV2,
        recipientHsigPk: Data,
        recipientHkemPk: Data,
        publishedAt: UInt64,
        exitId: ExitIdV2,
        deliveryKey: Data,
        signWith hsigKp: HSigKeyPairV2,
        bundleId: BundleIdV2 = .random()
    ) throws -> BundleV2 {
        var kx = try DeliveryKeyV2.exitDeliveryKey(deliveryKey, exitId: exitId)
        defer { _ = wipeSecretInPlace(&kx) }
        var b = BundleV2(
            version: LadonV2.relayProtocolVersion,
            recipientId: recipientId,
            recipientHsigPk: recipientHsigPk,
            recipientHkemPk: recipientHkemPk,
            bundleId: bundleId,
            publishedAt: publishedAt,
            exitId: exitId,
            verifier: DeliveryKeyV2.verifier(exitDeliveryKey: kx),
            bundleHsig: Data(count: LadonV2.hsigSigLen)
        )
        try b.validateStructure()
        b.bundleHsig = try HSigV2.sign(b.signingInput(), usecase: .bundle, with: hsigKp)
        return b
    }
}
