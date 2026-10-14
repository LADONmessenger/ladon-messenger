//
//  SealedRequestV2.swift
//  Ladon — sealed requests and responses, Addendum A2 §4 (relay protocol 0x06).
//
//  Every client request is sealed to the HKEM key of its target (an exit or
//  the push relay). The entry routes it by `target_id` and sees nothing else;
//  sizes are fixed per lane, so it cannot tell the kinds apart either.
//  Mirror of `relay-core-v2/src/wire/sealed.rs` — keep both in lockstep and
//  check with the cross-language vectors (`LadonV2CrossLangVectors`).
//
//  request  (lane size, exactly):
//    off=0      1 B      version   = 0x06
//    off=1      16 B     target_id
//    off=17     1,120 B  hkem_ct   HKEM.Encaps(target pk)
//    off=1,137  12 B     nonce
//    off=1,149  …        ChaCha20-Poly1305(k_req, nonce, plaintext, aad_req) incl. 16 B tag
//    plaintext = kind (1) || body_len (u16 BE) || body || zeros
//
//  response (lane size, exactly):
//    off=0      12 B     nonce
//    off=12     …        ChaCha20-Poly1305(k_resp, nonce, plaintext, aad_resp) incl. 16 B tag
//    plaintext = status (1) || target_time (u64 BE) || body_len (u16 BE) || body || zeros
//
//  ss     = HKEM shared secret (32 B, as for the outer envelope)
//  k_req  = HKDF-SHA256(ikm = ss, salt = none, info = "L1-SealedReq-v1")
//  k_resp = HKDF-SHA256(ikm = ss, salt = none, info = "L1-SealedResp-v1")
//  aad_*  = info label || version || target_id
//
//  The padding is inside the AEAD and must be zero on open: a parser that
//  ignored it would give the other side a covert channel.
//

import Foundation
import CryptoKit

enum SealedV2 {
    /// Relay protocol version of sealed requests.
    static let version: UInt8 = 0x06

    static let offTargetId = 1
    static let offHkemCt = offTargetId + LadonV2.exitIdLen          // 17
    static let offNonce = offHkemCt + LadonV2.hkemCtLen               // 1,137
    static let requestHeaderLen = offNonce + LadonV2.aeadNonceLen      // 1,149

    /// kind || body_len
    static let requestPrefixLen = 1 + 2
    /// status || target_time || body_len
    static let responsePrefixLen = 1 + 8 + 2

    /// ENQUEUE body = rid 32 || K_X 32 || sent_at 8 || envelope id 16 || inner.
    static let enqueueHeaderLen = LadonV2.recipientIdLen + LadonV2.deliveryKeyLen + 8 + LadonV2.envelopeIdLen

    /// Fixed inner-envelope length under 0x06: the ENQUEUE body fills lane S
    /// exactly (A2 §5). 16,384 − 1,149 − 16 − 3 − 88 = 15,128.
    static let innerEnvelopeLen = SealedLaneV2.send.requestLen - requestHeaderLen
        - LadonV2.aeadTagLen - requestPrefixLen - enqueueHeaderLen

    /// A2 §5, decision D1: the lane tick, ±10 % uniform jitter.
    static let tickSec: Double = 3
    static let tickJitter: ClosedRange<Double> = 0.9...1.1
    /// A2 §5: lane-F fetch exchanges back to back on foreground and push wake.
    static let catchUpBurst = 4

    static let infoRequest = Data("L1-SealedReq-v1".utf8)
    static let infoResponse = Data("L1-SealedResp-v1".utf8)

    /// ENQUEUE body header (A2 §4.1, 88 B): rid || K_X || sent_at (u64 BE) ||
    /// envelope_id. The inner envelope follows. Checked byte for byte against
    /// `relay-core-v2` (`enqueue_body_header` vector).
    static func enqueueHeader(recipientId: RecipientIdV2, exitDeliveryKey: Data, sentAt: UInt64, envelopeId: Data) -> Data {
        precondition(exitDeliveryKey.count == LadonV2.deliveryKeyLen && envelopeId.count == LadonV2.envelopeIdLen)
        var h = Data(capacity: enqueueHeaderLen)
        h.append(recipientId.bytes)
        h.append(exitDeliveryKey)
        h.append(u64BE(sentAt))
        h.append(envelopeId)
        precondition(h.count == enqueueHeaderLen)
        return h
    }
}

/// The two fixed-rate lanes (A2 §5). Lane S runs on the send connection,
/// lane F on the identity connection: every kind that names our own rid is
/// a lane-F kind.
enum SealedLaneV2: Sendable {
    case send
    case fetch

    var requestLen: Int {
        switch self {
        case .send: return 16_384
        case .fetch: return 8_192
        }
    }

    var responseLen: Int {
        switch self {
        case .send: return 8_192
        case .fetch: return 16_384
        }
    }

    var maxRequestBody: Int {
        requestLen - SealedV2.requestHeaderLen - LadonV2.aeadTagLen - SealedV2.requestPrefixLen
    }

    var maxResponseBody: Int {
        responseLen - LadonV2.aeadNonceLen - LadonV2.aeadTagLen - SealedV2.responsePrefixLen
    }
}

/// Request kinds (A2 §4.1).
enum SealedKindV2: UInt8, Sendable {
    case enqueue = 0x11
    case fetch = 0x12
    case dirGet = 0x13
    case dirPut = 0x14
    case pushRegister = 0x15
    case cover = 0x16

    /// The only lane this kind may travel in.
    var lane: SealedLaneV2 {
        switch self {
        case .enqueue, .dirGet, .cover: return .send
        case .fetch, .dirPut, .pushRegister: return .fetch
        }
    }
}

/// Status byte inside a sealed response (A2 §4.2). The outer HTTP status is
/// 200 whenever the target could open the request.
enum SealedStatusV2 {
    static let ok: UInt8 = 0x00
    static let malformed: UInt8 = 0x01
    static let stale: UInt8 = 0x02
    static let replay: UInt8 = 0x03
    static let rate: UInt8 = 0x04
    static let deliveryKey: UInt8 = 0x05
    static let unknownRecipient: UInt8 = 0x06
    static let fetchSig: UInt8 = 0x07
    static let signature: UInt8 = 0x08
    static let unavailable: UInt8 = 0x09
    static let `internal`: UInt8 = 0x0A
}

/// One sealed request, ready to send, and the key that opens its response.
/// `responseKey` is secret: wiped by `wipe()`, never logged.
struct SealedRequestV2: Sendable {
    let bytes: Data
    let kind: SealedKindV2
    let targetId: Data
    fileprivate(set) var responseKey: Data

    var lane: SealedLaneV2 { kind.lane }

    mutating func wipe() {
        responseKey.securelyWipe()
    }
}

struct OpenedSealedResponseV2: Sendable {
    let status: UInt8
    let targetTime: UInt64
    /// May carry an inner envelope or a bundle — the caller wipes what it
    /// does not keep.
    let body: Data
}

enum SealedCodecV2 {

    /// Seal `body` as a `kind` request to the target with HKEM public key
    /// `targetHkemPk` and 16-byte id `targetId`.
    static func seal(targetHkemPk: Data, targetId: Data, kind: SealedKindV2, body: Data) throws -> SealedRequestV2 {
        guard body.count <= kind.lane.maxRequestBody else {
            throw LadonV2Error.structuralInvariant("sealed body \(body.count) > lane \(kind.lane.maxRequestBody)")
        }
        let kem = try HKEMV2.encaps(publicKey: targetHkemPk)
        // `result` holds the only reference to k_req once seal returns, so the
        // wipe hits its real storage.
        var result = try seal(ss: kem.sharedKey, hkemCt: kem.ciphertext, nonce: randomBytes(LadonV2.aeadNonceLen),
                              targetId: targetId, kind: kind, body: body)
        result.kReq.securelyWipe()
        return SealedRequestV2(bytes: result.request, kind: kind, targetId: targetId, responseKey: result.kResp)
    }

    /// Everything after HKEM and the nonce. Internal so production code seals
    /// with a fresh HKEM secret and a fresh nonce; the cross-language vectors
    /// call it with fixed ones.
    static func seal(ss: Data, hkemCt: Data, nonce: Data, targetId: Data, kind: SealedKindV2, body: Data)
        throws -> (request: Data, kReq: Data, kResp: Data)
    {
        let lane = kind.lane
        guard ss.count == 32, hkemCt.count == LadonV2.hkemCtLen,
              nonce.count == LadonV2.aeadNonceLen, targetId.count == LadonV2.exitIdLen else {
            throw LadonV2Error.structuralInvariant("sealed request inputs")
        }
        guard body.count <= lane.maxRequestBody else {
            throw LadonV2Error.structuralInvariant("sealed body \(body.count) > lane \(lane.maxRequestBody)")
        }
        let kReq = derive(ss, SealedV2.infoRequest)
        let kResp = derive(ss, SealedV2.infoResponse)

        var pt = Data(count: lane.requestLen - SealedV2.requestHeaderLen - LadonV2.aeadTagLen)
        defer { _ = wipeSecretInPlace(&pt) }
        pt[pt.startIndex] = kind.rawValue
        pt.replaceSubrange(pt.startIndex + 1 ..< pt.startIndex + 3, with: u16BE(UInt16(body.count)))
        pt.replaceSubrange(pt.startIndex + SealedV2.requestPrefixLen ..< pt.startIndex + SealedV2.requestPrefixLen + body.count,
                           with: body)

        let box: ChaChaPoly.SealedBox
        do {
            box = try ChaChaPoly.seal(pt, using: SymmetricKey(data: kReq),
                                      nonce: try ChaChaPoly.Nonce(data: nonce),
                                      authenticating: aad(SealedV2.infoRequest, targetId))
        } catch {
            throw LadonV2Error.cryptoFailure("sealed request seal: \(error)")
        }
        var out = Data(capacity: lane.requestLen)
        out.append(SealedV2.version)
        out.append(targetId)
        out.append(hkemCt)
        out.append(nonce)
        out.append(box.ciphertext)
        out.append(box.tag)
        guard out.count == lane.requestLen else {
            throw LadonV2Error.structuralInvariant("sealed request size \(out.count) != \(lane.requestLen)")
        }
        return (out, kReq, kResp)
    }

    /// Open the response to `request`. Refuses a wrong size, a failed AEAD, a
    /// body length past the plaintext and non-zero padding.
    static func openResponse(_ buf: Data, for request: SealedRequestV2) throws -> OpenedSealedResponseV2 {
        try openResponse(buf, kResp: request.responseKey, targetId: request.targetId, lane: request.lane)
    }

    static func openResponse(_ buf: Data, kResp: Data, targetId: Data, lane: SealedLaneV2) throws -> OpenedSealedResponseV2 {
        guard buf.count == lane.responseLen else {
            throw LadonV2Error.structuralInvariant("sealed response size \(buf.count) != \(lane.responseLen)")
        }
        let data = Data(buf)  // zero-based indices
        var pt: Data
        do {
            let box = try ChaChaPoly.SealedBox(combined: data)
            pt = try ChaChaPoly.open(box, using: SymmetricKey(data: kResp),
                                     authenticating: aad(SealedV2.infoResponse, targetId))
        } catch {
            throw LadonV2Error.cryptoFailure("sealed response open: \(error)")
        }
        defer { _ = wipeSecretInPlace(&pt) }
        let status = pt[pt.startIndex]
        let targetTime = readU64BE(pt, at: 1)
        let len = Int(readU16BE(pt, at: 9))
        let end = SealedV2.responsePrefixLen + len
        guard end <= pt.count else {
            throw LadonV2Error.structuralInvariant("sealed response body length")
        }
        guard paddingIsZero(pt, from: end) else {
            throw LadonV2Error.structuralInvariant("sealed response padding")
        }
        let body = Data(pt[(pt.startIndex + SealedV2.responsePrefixLen) ..< (pt.startIndex + end)])
        return OpenedSealedResponseV2(status: status, targetTime: targetTime, body: body)
    }

    // MARK: - Helpers

    private static func derive(_ ss: Data, _ info: Data) -> Data {
        let k = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: ss),
                                       salt: Data(), info: info, outputByteCount: 32)
        return k.withUnsafeBytes { Data($0) }
    }

    private static func aad(_ label: Data, _ targetId: Data) -> Data {
        var a = Data(capacity: label.count + 1 + LadonV2.exitIdLen)
        a.append(label)
        a.append(SealedV2.version)
        a.append(targetId)
        return a
    }

    /// No early exit: the time does not depend on where a non-zero byte is.
    private static func paddingIsZero(_ pt: Data, from offset: Int) -> Bool {
        var acc: UInt8 = 0
        for b in pt[(pt.startIndex + offset)...] { acc |= b }
        return acc == 0
    }

    #if DEBUG
    /// Cross-language vectors only: the target side's response with a fixed
    /// nonce, so the bytes can be compared with `relay-core-v2`.
    static func sealResponseForVectors(kResp: Data, nonce: Data, targetId: Data, lane: SealedLaneV2,
                                       status: UInt8, targetTime: UInt64, body: Data) throws -> Data {
        var pt = Data(count: lane.responseLen - LadonV2.aeadNonceLen - LadonV2.aeadTagLen)
        pt[0] = status
        pt.replaceSubrange(1..<9, with: u64BE(targetTime))
        pt.replaceSubrange(9..<11, with: u16BE(UInt16(body.count)))
        pt.replaceSubrange(SealedV2.responsePrefixLen ..< SealedV2.responsePrefixLen + body.count, with: body)
        let box = try ChaChaPoly.seal(pt, using: SymmetricKey(data: kResp),
                                      nonce: try ChaChaPoly.Nonce(data: nonce),
                                      authenticating: aad(SealedV2.infoResponse, targetId))
        return box.combined
    }
    #endif
}
