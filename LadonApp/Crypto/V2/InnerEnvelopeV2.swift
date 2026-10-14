//
//  InnerEnvelopeV2.swift
//  Ladon — recipient-layer (Inner-Envelope) seal/open per Spec §4.3.
//
//  POLICY CLARITY (FIX INFO-INNER-DOCS):
//  - Sender authentication via HSig is MANDATORY (not optional)
//  - Padding is included in the sealed plaintext (traffic-analysis resistance)
//  - Version byte distinguishes real messages (0x02) from cover traffic (0x03)
//  - AEAD AAD includes recipient identity to prevent cross-recipient confusion
//  - Replay protection is handled at outer layer (envelope id, exit Bloom filter)
//  - Forward secrecy is provided by ephemeral HKEM per-message
//
//  Layout (wire bytes):
//      hkem_ct_R (1,120) || aead_nonce (12) || aead_ct || aead_tag (16)
//      Total header = 1,132 B; tag is appended by AEAD.
//
//  AEAD plaintext (Spec §4.3.2 "Sealed Sender"):
//      [0]      version            (1 B; 0x02 real, 0x03 cover)
//      [1]      sender_hsig_pk     (1,984 B; sender identity, sealed)
//      [1985]   timestamp_be       (8 B)
//      [1993]   real_length_be     (4 B; uint32, message_body byte count)
//      [1997]   message_body       (l B)
//      [1997+l] pad                (p B; sender-chosen, contributes to traffic-analysis resistance)
//      [...]    sender_hsig        (3,373 B; HSig over plaintext[0..1997+l+p),
//                                  usecase tag "L1-InnerSender-v3", A1 §10)
//
//  AEAD AAD: "L1-Inner-v1" || version || rid_R   (28 B)
//
//  Plaintext length: L_p = 5,354 + l + p  (matches Spec §4.4.3 baseline calc).
//

import Foundation
import CryptoKit

extension LadonV2 {
    static let innerVersionRealMessage: UInt8 = 0x02
    static let innerVersionCoverTraffic: UInt8 = 0x03
    /// Inner-plaintext fixed prefix (everything before message_body).
    static let innerPlaintextPrefixLen = 1 + hsigPkLen + 8 + 4                  // 1,997
    /// Inner-plaintext fixed suffix (sender hsig appended after pad).
    static let innerPlaintextSuffixLen = hsigSigLen                             // 3,373

    /// Largest Inner-Envelope `message_body` that still fits the fixed inner
    /// envelope of relay protocol 0x06 (`SealedV2.innerEnvelopeLen`, 15,128 B,
    /// the ENQUEUE body filling lane S — A2 §5). Mirrors the inner layout
    /// above (inner = hkem_ct ‖ nonce ‖ AEAD(prefix ‖ body ‖ pad ‖
    /// sender_hsig) ‖ tag) and the padding step in `RelayClientV2.sendMessage`.
    /// This is 8,610 B (A1: 8,612 B; the sealed body length costs two).
    static var maxInnerMessageBodyLen: Int {
        let innerWireOverhead = hkemCtLen + aeadNonceLen + aeadTagLen
        return SealedV2.innerEnvelopeLen - innerWireOverhead - innerPlaintextPrefixLen - innerPlaintextSuffixLen
    }
}

enum InnerEnvelopeV2Error: Error, CustomStringConvertible {
    case shortBuffer(expected: Int, got: Int)
    case malformed(String)
    case cryptoFailure(String)
    case signatureInvalid
    case unsupportedVersion(UInt8)
    case lengthMismatch(declared: UInt32, available: Int)

    var description: String {
        switch self {
        case .shortBuffer(let e, let g): return "inner: short buffer expected=\(e) got=\(g)"
        case .malformed(let m): return "inner: malformed — \(m)"
        case .cryptoFailure(let m): return "inner: crypto — \(m)"
        case .signatureInvalid: return "inner: sender_hsig invalid"
        case .unsupportedVersion(let v): return "inner: unsupported version 0x\(String(format: "%02x", v))"
        case .lengthMismatch(let d, let a): return "inner: real_length=\(d) > available=\(a)"
        }
    }
}

/// Result of opening an Inner-Envelope.
struct OpenedInnerEnvelopeV2 {
    /// `0x02` real or `0x03` cover.
    let innerVersion: UInt8
    /// Sender identity public key (1,984 B). Verified via embedded sender_hsig.
    let senderHsigPk: Data
    /// Sender-side wall-clock at send time.
    let timestamp: UInt64
    /// Message body bytes (length = real_length).
    let messageBody: Data
    /// True if `innerVersion == 0x03` — caller must silently discard.
    var isCoverTraffic: Bool { innerVersion == LadonV2.innerVersionCoverTraffic }
}

enum InnerEnvelopeV2 {

    // MARK: - AAD

    /// `"L1-Inner-v1" || version || rid_R`  (11 + 1 + 32 = 44 B per spec).
    /// Spec §4.3.1 lists the byte string explicitly; the layout matches Rust
    /// `AAD_INNER_V1` constant.
    static func innerAAD(version: UInt8, recipientId: RecipientIdV2) -> Data {
        var d = Data(capacity: LadonV2.aadInnerV1.count + 1 + LadonV2.recipientIdLen)
        d.append(LadonV2.aadInnerV1)
        d.append(version)
        d.append(recipientId.bytes)
        return d
    }

    // MARK: - Plaintext build

    /// Returns the inner plaintext bytes (without the trailing sender_hsig).
    /// Caller signs THIS prefix and then appends the 3,373-byte signature.
    static func buildPlaintextBody(
        innerVersion: UInt8,
        senderHsigPk: Data,
        timestamp: UInt64,
        messageBody: Data,
        padLen: Int
    ) throws -> Data {
        guard senderHsigPk.count == LadonV2.hsigPkLen else {
            throw InnerEnvelopeV2Error.shortBuffer(expected: LadonV2.hsigPkLen, got: senderHsigPk.count)
        }
        guard padLen >= 0 else {
            throw InnerEnvelopeV2Error.malformed("padLen<0")
        }
        guard messageBody.count <= UInt32.max else {
            throw InnerEnvelopeV2Error.malformed("messageBody >= 2^32")
        }
        var d = Data(capacity: LadonV2.innerPlaintextPrefixLen + messageBody.count + padLen)
        d.append(innerVersion)
        d.append(senderHsigPk)
        d.append(u64BE(timestamp))
        d.append(u32BE(UInt32(messageBody.count)))
        d.append(messageBody)
        if padLen > 0 {
            d.append(randomBytes(padLen))
        }
        return d
    }

    // MARK: - Seal

    /// Build, sign, and HKEM-encrypt an Inner-Envelope addressed to `recipientHkemPk`.
    /// The recipient's HSig pk MUST equal the one inside the recipient's published Bundle
    /// — caller is expected to have already verified this binding.
    ///
    /// Returns the wire-format inner envelope bytes (header + ct + tag), suitable
    /// for embedding in a sealed ENQUEUE (`RelayClientV2.sendMessage`).
    static func seal(
        innerVersion: UInt8 = LadonV2.innerVersionRealMessage,
        recipientId: RecipientIdV2,
        recipientHkemPk: Data,
        senderHsigKp: HSigKeyPairV2,
        timestamp: UInt64,
        messageBody: Data,
        padLen: Int = 0
    ) throws -> Data {
        guard recipientHkemPk.count == LadonV2.hkemPkLen else {
            throw InnerEnvelopeV2Error.shortBuffer(expected: LadonV2.hkemPkLen, got: recipientHkemPk.count)
        }
        // 1. Build plaintext body (no sig yet).
        let body = try buildPlaintextBody(
            innerVersion: innerVersion,
            senderHsigPk: senderHsigKp.publicKeyBytes(),
            timestamp: timestamp,
            messageBody: messageBody,
            padLen: padLen
        )
        // 2. Sign the body — sender_hsig covers padding too (Spec §4.3.2 last line).
        let sig = try HSigV2.sign(body, usecase: .innerSender, with: senderHsigKp)
        var plaintext = Data(capacity: body.count + sig.count)
        plaintext.append(body)
        plaintext.append(sig)

        // 3. HKEM.Encaps to recipient.
        let kem = try HKEMV2.encaps(publicKey: recipientHkemPk)
        precondition(kem.ciphertext.count == LadonV2.hkemCtLen)
        precondition(kem.sharedKey.count == 32)

        // 4. AEAD seal.
        let nonce = randomBytes(LadonV2.aeadNonceLen)
        let aad = innerAAD(version: innerVersion, recipientId: recipientId)
        let key = SymmetricKey(data: kem.sharedKey)
        let chachaNonce: ChaChaPoly.Nonce
        do {
            chachaNonce = try ChaChaPoly.Nonce(data: nonce)
        } catch {
            throw InnerEnvelopeV2Error.cryptoFailure("ChaChaPoly.Nonce: \(error)")
        }
        let sealed: ChaChaPoly.SealedBox
        do {
            sealed = try ChaChaPoly.seal(plaintext, using: key, nonce: chachaNonce, authenticating: aad)
        } catch {
            throw InnerEnvelopeV2Error.cryptoFailure("ChaChaPoly.seal: \(error)")
        }

        // 5. Assemble wire format.
        var wire = Data(capacity: LadonV2.hkemCtLen + LadonV2.aeadNonceLen
                                  + sealed.ciphertext.count + sealed.tag.count)
        wire.append(kem.ciphertext)
        wire.append(nonce)
        wire.append(sealed.ciphertext)
        wire.append(sealed.tag)
        return wire
    }

    // MARK: - Open

    /// Decrypt + verify an Inner-Envelope received with a sealed FETCH.
    ///
    /// - Parameters:
    ///   - wire: raw inner-envelope bytes from the fetch response.
    ///   - innerVersion: the version byte the AAD must commit to. The caller
    ///     determines this (typically `0x02` for real-or-cover dispatch).
    ///   - recipientId: caller's own 32-byte recipient id.
    ///   - recipientHkemKp: caller's HKEM keypair (long-term).
    /// - Throws: on AEAD failure, structural mismatch, or invalid sender_hsig.
    static func open(
        wire: Data,
        innerVersion: UInt8 = LadonV2.innerVersionRealMessage,
        recipientId: RecipientIdV2,
        recipientHkemKp: HKEMKeyPairV2
    ) throws -> OpenedInnerEnvelopeV2 {
        let minHeader = LadonV2.hkemCtLen + LadonV2.aeadNonceLen + LadonV2.aeadTagLen
        guard wire.count >= minHeader else {
            throw InnerEnvelopeV2Error.shortBuffer(expected: minHeader, got: wire.count)
        }
        // 1. Slice wire fields.
        let hkemCt = subdata(wire, 0, LadonV2.hkemCtLen)
        let nonce = subdata(wire, LadonV2.hkemCtLen, LadonV2.aeadNonceLen)
        let ctAndTagStart = LadonV2.hkemCtLen + LadonV2.aeadNonceLen
        let ctAndTag = subdata(wire, ctAndTagStart, wire.count - ctAndTagStart)
        guard ctAndTag.count >= LadonV2.aeadTagLen else {
            throw InnerEnvelopeV2Error.malformed("ct+tag < tag-len")
        }

        // 2. HKEM.Decaps.
        let K = try HKEMV2.decaps(keyPair: recipientHkemKp, ciphertext: hkemCt)

        // 3. AEAD open. CryptoKit takes combined = nonce || ct || tag.
        var combined = Data(capacity: nonce.count + ctAndTag.count)
        combined.append(nonce)
        combined.append(ctAndTag)
        let aad = innerAAD(version: innerVersion, recipientId: recipientId)
        let key = SymmetricKey(data: K)
        let plaintext: Data
        do {
            let box = try ChaChaPoly.SealedBox(combined: combined)
            plaintext = try ChaChaPoly.open(box, using: key, authenticating: aad)
        } catch {
            throw InnerEnvelopeV2Error.cryptoFailure("ChaChaPoly.open: \(error)")
        }

        // 4. Parse plaintext.
        guard plaintext.count >= LadonV2.innerPlaintextPrefixLen + LadonV2.innerPlaintextSuffixLen else {
            throw InnerEnvelopeV2Error.shortBuffer(
                expected: LadonV2.innerPlaintextPrefixLen + LadonV2.innerPlaintextSuffixLen,
                got: plaintext.count)
        }
        let v = plaintext[plaintext.startIndex]
        guard v == innerVersion else {
            throw InnerEnvelopeV2Error.unsupportedVersion(v)
        }
        let senderPk = subdata(plaintext, 1, LadonV2.hsigPkLen)
        let ts = readU64BE(plaintext, at: 1 + LadonV2.hsigPkLen)
        let realLen = readU32BE(plaintext, at: 1 + LadonV2.hsigPkLen + 8)
        let bodyOff = LadonV2.innerPlaintextPrefixLen
        // body || pad must occupy plaintext[bodyOff .. plaintext.count - hsigSigLen]
        let trailingSigStart = plaintext.count - LadonV2.innerPlaintextSuffixLen
        guard trailingSigStart >= bodyOff else {
            throw InnerEnvelopeV2Error.malformed("plaintext too short for sig")
        }
        let bodyAndPadLen = trailingSigStart - bodyOff
        guard Int(realLen) <= bodyAndPadLen else {
            throw InnerEnvelopeV2Error.lengthMismatch(declared: realLen, available: bodyAndPadLen)
        }
        let messageBody = subdata(plaintext, bodyOff, Int(realLen))
        // padding bytes are bodyAndPadLen - realLen — we don't expose them.

        // 5. Verify sender_hsig over plaintext[0..trailingSigStart).
        let signedRange = plaintext.subdata(in: plaintext.startIndex..<plaintext.startIndex + trailingSigStart)
        let sig = subdata(plaintext, trailingSigStart, LadonV2.innerPlaintextSuffixLen)
        guard HSigV2.verify(message: signedRange, usecase: .innerSender, signature: sig, publicKey: senderPk) else {
            throw InnerEnvelopeV2Error.signatureInvalid
        }

        return OpenedInnerEnvelopeV2(
            innerVersion: v,
            senderHsigPk: senderPk,
            timestamp: ts,
            messageBody: messageBody
        )
    }
}
