//
//  PairingCodeV4.swift
//  Ladon — the pairing code: identity + one fresh one-time prekey + the
//  owner's delivery key (Addendum A1 §5).
//
//  Every code carries the owner's long-term identity AND a one-time prekey
//  (OTPK) minted for this code alone, so the first message of a new session is
//  built against a key that opens exactly one session (see PrekeyStoreV2 and
//  V2RatchetPayload). Nothing is fetched from a relay: the code is complete.
//
//  Binary payload, fixed length 6,638 B (format v5, P8-AUDIT8-IOS-30):
//    body: [ver 0x05][hsigPk 1,984][otpkId 16][otpkSeq u64 BE][expiresAt u64 BE]
//          [otpkX 32][otpkKy 1,184][deliveryKey 32]            (3,265 B)
//    sig:  HSig(identity, body, usecase "L1-Pairing-v1")       (3,373 B)
//
//  The signature binds prekey, sequence, expiry hint and delivery key to the
//  identity the code names. v4 carried no signature: anyone who knew a
//  contact's public HSig key could forge a code for that contact and overwrite
//  the stored prekey and delivery key (audit F29/F36/F42) — a silent,
//  lasting denial of the conversation. A code whose signature does not verify
//  is rejected as damaged; v4 codes are refused as an older version.
//
//  The delivery key K is what lets the scanner deliver to the owner at all:
//  the exits accept only envelopes that present K_X (A1 §8). Anyone holding a
//  code can deliver to its owner until the owner rotates K (A1 §7) — the
//  same audience that learns the identity from the code.
//
//  expiresAt is relay-anchored unix time (ClockSyncV2) and only a HINT for the
//  scanner — two devices' relay-anchored clocks agree even when their wall
//  clocks do not. The authority is the owner, who deletes the prekey at its
//  own (device-clock) expiry; a code accepted here can still be refused there.
//
//  Text form (invite links, paste): "ladonv5:" + base64url(payload) = 8,859 chars.
//  QR form: the payload does not fit one QR code, so it is shown as four parts
//  that alternate on screen (each ≤ 2,331 B, QR level M):
//    "ladonv5q:<i>/4:<tag>:<base64url(chunk i)>"   i = 1 … 4
//  tag = base64url(SHA-256(payload)[0..<8]). The scanner only joins parts with
//  the same tag and re-checks the tag over the joined payload, so parts of two
//  different codes (e.g. after the screen rotated to a fresh code) never mix.
//

import Foundation
import CryptoKit

enum PairingCodeError: Error, Equatable {
    /// Not a LADON messenger code, or damaged.
    case malformed
    /// A code from an older version (`ladonv2:` without one-time prekey,
    /// `ladonv3:` without delivery key) — it cannot reach its owner.
    case oldFormat
    /// The expiry hint has passed (beyond the clock-skew tolerance).
    case expired
}

struct PairingCodeV4: Equatable {
    let hsigPk: Data
    let prekey: OneTimePrekeyPublicV2
    /// Relay-anchored unix seconds (hint for the scanner, see header).
    let expiresAt: UInt64
    /// The owner's delivery key K (32 B).
    let deliveryKey: Data
    /// HSig over the body under `.pairing` (3,373 B).
    let signature: Data

    var recipientId: RecipientIdV2 { RecipientIdV2.fromIdentityKey(hsigPk) }

    static let textPrefix = "ladonv5:"
    static let qrPrefix = "ladonv5q:"
    /// Text and QR prefixes of older code versions, refused as `.oldFormat`.
    static let legacyPrefixes = ["ladonv2:", "ladonv3:", "ladonv3q:", "ladonv4:", "ladonv4q:"]
    private static let version: UInt8 = 0x05
    static let bodyLen: Int = 1 + LadonV2.hsigPkLen + PrekeyStoreV2.idLen + 8 + 8 + LadonV2.x25519PkLen + LadonV2.kyber768PkLen + LadonV2.deliveryKeyLen
    static let payloadLen: Int = bodyLen + LadonV2.hsigSigLen

    /// True if `text` is a code of an older version.
    static func isLegacy(_ text: String) -> Bool {
        legacyPrefixes.contains { text.hasPrefix($0) }
    }
    static let qrPartCount = 4
    private static let tagLen = 8

    /// What the code is for — decides how long its prekey lives.
    enum Kind {
        case inPerson   // shown as a QR code: PrekeyStoreV2.inPersonLifetime
        case invite     // sent as a link or pasted text: PrekeyStoreV2.inviteLifetime

        var lifetime: TimeInterval {
            switch self {
            case .inPerson: return PrekeyStoreV2.inPersonLifetime
            case .invite: return PrekeyStoreV2.inviteLifetime
            }
        }
    }

    // MARK: Issuing

    /// Mint a fresh one-time prekey and return our code carrying it (text form).
    /// Every call issues a NEW prekey — never reuse a returned code for a
    /// second person.
    static func issue(_ kind: Kind) throws -> String {
        let identity = try IdentityStoreV2.loadOrGenerate()
        let prekey = try PrekeyStoreV2.generateOwn(expiresAt: Date().addingTimeInterval(kind.lifetime))
        let hint = ClockSyncV2.shared.nowSec() &+ UInt64(kind.lifetime)
        return encode(try signed(by: identity.senderHsigKp, prekey: prekey, expiresAt: hint,
                                 deliveryKey: try DeliveryKeyStoreV2.ownKey()))
    }

    /// A code signed by the identity `kp` (its public key becomes `hsigPk`).
    static func signed(by kp: HSigKeyPairV2, prekey: OneTimePrekeyPublicV2, expiresAt: UInt64,
                       deliveryKey: Data) throws -> PairingCodeV4 {
        let hsigPk = kp.publicKeyBytes()
        let b = body(hsigPk: hsigPk, prekey: prekey, expiresAt: expiresAt, deliveryKey: deliveryKey)
        let sig = try HSigV2.sign(b, usecase: .pairing, with: kp)
        return PairingCodeV4(hsigPk: hsigPk, prekey: prekey, expiresAt: expiresAt,
                             deliveryKey: deliveryKey, signature: sig)
    }

    // MARK: Text form

    static func encode(_ code: PairingCodeV4) -> String {
        textPrefix + base64url(payload(of: code))
    }

    /// Strict parse of the text form. Surrounding whitespace is tolerated
    /// (copy-paste); anything else must match exactly.
    static func parse(_ raw: String) throws -> PairingCodeV4 {
        let text = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if isLegacy(text) { throw PairingCodeError.oldFormat }
        guard text.hasPrefix(textPrefix),
              let payload = fromBase64url(String(text.dropFirst(textPrefix.count))) else {
            throw PairingCodeError.malformed
        }
        return try decode(payload)
    }

    /// True if the expiry hint has passed at `nowRelaySec`, beyond the same
    /// clock-skew tolerance the relays apply.
    func isExpired(nowRelaySec: UInt64) -> Bool {
        nowRelaySec > expiresAt &+ LadonV2.clockSkewToleranceSec
    }

    /// True if the expiry hint lies further ahead than any code we issue can
    /// (invite lifetime plus the skew tolerance). The hint is signed, so only
    /// the owner's own app could set it — refused as damaged all the same.
    func expiresImplausiblyLate(nowRelaySec: UInt64) -> Bool {
        expiresAt > nowRelaySec &+ UInt64(PrekeyStoreV2.inviteLifetime) &+ LadonV2.clockSkewToleranceSec
    }

    private static func body(hsigPk: Data, prekey: OneTimePrekeyPublicV2, expiresAt: UInt64, deliveryKey: Data) -> Data {
        var p = Data(capacity: bodyLen)
        p.append(version)
        p.append(hsigPk)
        p.append(prekey.id)
        p.append(u64BE(prekey.seq))
        p.append(u64BE(expiresAt))
        p.append(prekey.xPk)
        p.append(prekey.kyPk)
        p.append(deliveryKey)
        precondition(p.count == bodyLen, "pairing body length")
        return p
    }

    private static func payload(of code: PairingCodeV4) -> Data {
        var p = body(hsigPk: code.hsigPk, prekey: code.prekey, expiresAt: code.expiresAt, deliveryKey: code.deliveryKey)
        p.append(code.signature)
        precondition(p.count == payloadLen, "pairing payload length")
        return p
    }

    private static func decode(_ p: Data) throws -> PairingCodeV4 {
        guard p.count == payloadLen, p[p.startIndex] == version else { throw PairingCodeError.malformed }
        var o = 1
        let hsigPk = subdata(p, o, LadonV2.hsigPkLen); o += LadonV2.hsigPkLen
        let id = subdata(p, o, PrekeyStoreV2.idLen); o += PrekeyStoreV2.idLen
        let seq = readU64BE(p, at: o); o += 8
        let expiresAt = readU64BE(p, at: o); o += 8
        let xPk = subdata(p, o, LadonV2.x25519PkLen); o += LadonV2.x25519PkLen
        let kyPk = subdata(p, o, LadonV2.kyber768PkLen); o += LadonV2.kyber768PkLen
        let deliveryKey = subdata(p, o, LadonV2.deliveryKeyLen); o += LadonV2.deliveryKeyLen
        precondition(o == bodyLen)
        let signature = subdata(p, o, LadonV2.hsigSigLen); o += LadonV2.hsigSigLen
        precondition(o == payloadLen)
        guard id != Data(count: PrekeyStoreV2.idLen) else { throw PairingCodeError.malformed }
        // An all-zero K is never generated (CSPRNG) — refuse it as damaged.
        guard deliveryKey != Data(count: LadonV2.deliveryKeyLen) else { throw PairingCodeError.malformed }
        // P8-AUDIT8-IOS-30: both halves of the hybrid signature must verify
        // against the identity the code names, over the exact body bytes.
        guard HSigV2.verify(message: subdata(p, 0, bodyLen), usecase: .pairing,
                            signature: signature, publicKey: hsigPk) else {
            throw PairingCodeError.malformed
        }
        return PairingCodeV4(hsigPk: hsigPk,
                             prekey: OneTimePrekeyPublicV2(id: id, seq: seq, xPk: xPk, kyPk: kyPk),
                             expiresAt: expiresAt,
                             deliveryKey: deliveryKey,
                             signature: signature)
    }

    // MARK: QR form

    /// Split a text-form code into its QR parts (in order 1, 2).
    static func qrParts(ofCode text: String) throws -> [String] {
        let code = try parse(text)
        let p = payload(of: code)
        let tag = base64url(Data(SHA256.hash(data: p)).prefix(tagLen))
        let chunk = (p.count + qrPartCount - 1) / qrPartCount
        return (0..<qrPartCount).map { i in
            let lo = i * chunk, hi = min(p.count, lo + chunk)
            return "\(qrPrefix)\(i + 1)/\(qrPartCount):\(tag):\(base64url(p.subdata(in: lo..<hi)))"
        }
    }

    /// Collects scanned QR parts and yields the full text-form code once all
    /// parts of the same code are in.
    final class QRAssembler {
        enum Outcome: Equatable {
            case incomplete(have: Int, of: Int)
            case complete(String)
            case rejected
        }

        private var tag: String?
        private var parts: [Int: Data] = [:]

        func add(_ raw: String) -> Outcome {
            guard let part = PairingCodeV4.parsePart(raw) else { return .rejected }
            if part.tag != tag {                 // a different code is on screen now: start over
                tag = part.tag
                parts = [:]
            }
            parts[part.index] = part.chunk
            guard parts.count == PairingCodeV4.qrPartCount else {
                return .incomplete(have: parts.count, of: PairingCodeV4.qrPartCount)
            }
            var payload = Data(capacity: PairingCodeV4.payloadLen)
            for i in 1...PairingCodeV4.qrPartCount { payload.append(parts[i]!) }
            let expected = PairingCodeV4.base64url(Data(SHA256.hash(data: payload)).prefix(PairingCodeV4.tagLen))
            let joinedTag = tag
            tag = nil
            parts = [:]
            guard expected == joinedTag, let code = try? PairingCodeV4.decode(payload) else { return .rejected }
            return .complete(PairingCodeV4.encode(code))
        }
    }

    private static func parsePart(_ raw: String) -> (index: Int, tag: String, chunk: Data)? {
        let text = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard text.hasPrefix(qrPrefix) else { return nil }
        let fields = text.dropFirst(qrPrefix.count).split(separator: ":", omittingEmptySubsequences: false)
        guard fields.count == 3 else { return nil }
        let pos = fields[0].split(separator: "/", omittingEmptySubsequences: false)
        guard pos.count == 2, let index = Int(pos[0]), let total = Int(pos[1]),
              total == qrPartCount, (1...qrPartCount).contains(index),
              String(pos[0]) == String(index), String(pos[1]) == String(total),   // no "+1" / "01"
              fromBase64url(String(fields[1]))?.count == tagLen,
              let chunk = fromBase64url(String(fields[2])), !chunk.isEmpty else { return nil }
        let expectedLen = index < qrPartCount ? (payloadLen + qrPartCount - 1) / qrPartCount
                                              : payloadLen - (qrPartCount - 1) * ((payloadLen + qrPartCount - 1) / qrPartCount)
        guard chunk.count == expectedLen else { return nil }
        return (index, String(fields[1]), chunk)
    }

    // MARK: base64url (RFC 4648 §5, no padding)

    static func base64url(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    static func fromBase64url(_ s: String) -> Data? {
        guard !s.isEmpty, s.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_") }) else {
            return nil
        }
        var b64 = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        let rem = b64.count % 4
        if rem == 1 { return nil }
        if rem > 0 { b64 += String(repeating: "=", count: 4 - rem) }
        // Canonical only: re-encoding must give back exactly the input, so one
        // payload has exactly one text form.
        guard let data = Data(base64Encoded: b64), base64url(data) == s else { return nil }
        return data
    }
}

/// Control messages inside the ratchet payload (Addendum A1 §6).
///
/// Ordinary end-to-end encrypted, sealed-sender messages — same 16 KB envelope,
/// same path — that carry the sender's delivery key K and are never shown:
///   START  "\u{E000}LADON-CTL-V2:start:" ‖ base64url(K)   first message to a new contact
///   KEY    "\u{E000}LADON-CTL-V2:key:"   ‖ base64url(K)   after a rotation, or after
///                                                      re-adding a contact a session exists with
/// Anything else starting with "\u{E000}LADON-CTL-" (including the retired
/// V1 start message) is a malformed control message and is dropped — it never
/// becomes a chat message, a notification or an unread count.
enum ControlMessageV2 {
    static let prefix = "\u{E000}LADON-CTL-"
    private static let startPrefix = "\u{E000}LADON-CTL-V2:start:"
    private static let keyPrefix = "\u{E000}LADON-CTL-V2:key:"

    enum Parsed: Equatable {
        case start(deliveryKey: Data)
        case key(deliveryKey: Data)
        case malformed
    }

    static func start(deliveryKey k: Data) -> String { startPrefix + PairingCodeV4.base64url(k) }
    static func key(deliveryKey k: Data) -> String { keyPrefix + PairingCodeV4.base64url(k) }

    /// nil = not a control message (an ordinary chat text).
    static func parse(_ content: String) -> Parsed? {
        guard content.hasPrefix(prefix) else { return nil }
        for (p, make) in [(startPrefix, Parsed.start), (keyPrefix, Parsed.key)] where content.hasPrefix(p) {
            // Canonical base64url of exactly 32 non-zero bytes, nothing else.
            guard let k = PairingCodeV4.fromBase64url(String(content.dropFirst(p.count))),
                  k.count == LadonV2.deliveryKeyLen,
                  k != Data(count: LadonV2.deliveryKeyLen) else { return .malformed }
            return make(k)
        }
        return .malformed
    }
}

/// The invisible message sent right after pairing (P8-RCV2-IOS-10, A1 §6).
///
/// Without a session it is START: it builds the session at once — the scanned
/// one-time prekey is used within seconds instead of whenever the first real
/// message is written, so a photographed code has practically no window left
/// — and hands the contact our delivery key, so a contact who only scanned
/// back can reply. With a session already there (a fresh code exchanged with
/// a known contact) it is KEY: it hands over our current delivery key.
///
/// Sent only because the local user just added or re-added the contact —
/// never as an answer to anything received: an automatic answer would tell the
/// sender when this phone was online (a hidden read/online receipt, which this
/// app does not have). The receiver drops it before it can become a chat
/// message, a notification or an unread count.
enum PairingStartV2 {

    /// Send START or KEY to a contact that was just added. Runs detached from
    /// any screen; retries transient failures (Tor still starting, relay
    /// hiccup) with backoff until one send succeeded or the in-person code
    /// lifetime has passed.
    static func send(toContactId contactId: String) {
        // One loop per contact at a time (re-scans while one runs are no-ops).
        guard claim(contactId) else { return }
        Task.detached(priority: .utility) {
            await run(contactId)
            release(contactId)
        }
    }

    private static let runningLock = NSLock()
    private static var running: Set<String> = []
    private static func claim(_ id: String) -> Bool {
        runningLock.lock(); defer { runningLock.unlock() }
        return running.insert(id).inserted
    }
    private static func release(_ id: String) {
        runningLock.lock(); defer { runningLock.unlock() }
        running.remove(id)
    }

    /// START is a first-chain-only seal: it goes out only into no session or
    /// our own unanswered first chain. As soon as the peer's frame has arrived
    /// (their start, a crossing, a reply), the seal refuses with
    /// `.notFirstChain` and the loop ends — the peer could only answer because
    /// it already held our key.
    private static func run(_ contactId: String) async {
        guard let peer = try? PeerStoreV2.load(forContactId: contactId),
              let hasSession = try? V2RatchetPayload.hasSession(peerId: contactId) else { return }
        let ownKey: Data
        do { ownKey = try DeliveryKeyStoreV2.ownKey() }
        catch {
            SecureLogger.error("[V2] pairing control not sent: own delivery key unavailable: \(error)")
            return
        }
        let body = hasSession ? ControlMessageV2.key(deliveryKey: ownKey) : ControlMessageV2.start(deliveryKey: ownKey)
        let kind = hasSession ? "key" : "start"
        let deadline = Date().addingTimeInterval(PrekeyStoreV2.inPersonLifetime)
        var delaySec: UInt64 = 2
        while Date() < deadline, !Task.isCancelled {
            if let client = await V2SessionManager.shared.client {
                do {
                    // A control message: queued behind real messages in lane
                    // S. A push it causes shows no message; the receiver
                    // removes that banner after the wake (A2 §7).
                    _ = try await client.sendMessage(to: peer, messageBody: Data(body.utf8),
                                                     messageID: UUID().uuidString, isControl: true,
                                                     firstChainOnly: !hasSession)
                    SecureLogger.torDiag("[V2] pairing \(kind) sent")
                    return
                } catch RelayClientV2Error.ratchet(.notFirstChain) {
                    SecureLogger.torDiag("[V2] pairing start not needed — session already answered")
                    return
                } catch RelayClientV2Error.ratchet(let e) {
                    // No code on file, prekey refused, … — retrying cannot help.
                    SecureLogger.error("[V2] pairing \(kind) not sent: \(e)")
                    return
                } catch RelayClientV2Error.missingDeliveryKey {
                    // The contact's key is not on file — retrying cannot help.
                    SecureLogger.error("[V2] pairing \(kind) not sent: contact's delivery key missing")
                    return
                } catch {
                    SecureLogger.torDiag("[V2] pairing \(kind) retry in \(delaySec)s: \(error)")
                }
            }
            try? await Task.sleep(nanoseconds: delaySec * 1_000_000_000)
            delaySec = min(delaySec * 2, 60)
        }
    }
}
