//
//  RelayClientV2.swift
//  Ladon — high-level v2 client API.
//
//  Coordinates: ExitRegistry (geo-probe + selection) → DirectoryClient (fetch
//  the recipient's signed delivery bundle) → InnerEnvelope.seal → outer seal
//  with the recipient's exit delivery key (Addendum A1) → EnqueueClient.send.
//  On the receive path: FetchClient.fetch → InnerEnvelope.open; an exit that
//  does not know us gets our bundle published.
//
//  This orchestrator does NOT touch the legacy `RelayClient.swift`. Phase 4
//  cutover will swap the call sites in `LadonApp.swift` / SilentPushHandler.
//

import Foundation
import CryptoKit
#if canImport(UIKit)
import UIKit   // issue #38: protectedDataWillBecomeUnavailable → wipe held frames
#endif

enum V2RatchetError: Error, CustomStringConvertible {
    case keychain(OSStatus)
    case malformed(String)
    case crypto(String)
    case replayOrTooOld(UInt32)
    case skippedKeyLimitExceeded
    /// P7-IOS-CRYPTO-04: per-session ratchet message counter exhausted
    /// (UInt32.max reached). Caller must re-establish the session — we
    /// will NOT wrap silently to 0 (that would re-issue colliding
    /// message numbers and defeat replay protection).
    case counterExhausted
    /// The plaintext cannot fit the fixed-size envelope. Raised BEFORE any
    /// ratchet state is loaded or advanced, so a rejected send consumes no
    /// message number and cannot desynchronise the session.
    case plaintextTooLarge(size: Int, max: Int)
    /// No session yet and no unused one-time prekey of this contact on file:
    /// a fresh pairing code from the contact is needed. Raised before any
    /// state is created.
    case noPeerPrekey
    /// A bootstrap frame names a one-time prekey we do not hold (never issued,
    /// already used, or expired). The frame is rejected; nothing is stored.
    case prekeyUnavailable
    /// The one-time prekey store failed (Keychain). Fail-closed.
    case prekeyStore(String)
    /// A first-chain-only seal (the pairing start message) found a session
    /// that is not our own, still unanswered first chain — sending now would
    /// be an automatic answer. Nothing was sent or stored.
    case notFirstChain

    var description: String {
        switch self {
        case .noPeerPrekey: return "v2ratchet: no unused one-time prekey for this contact — a fresh code is needed"
        case .prekeyUnavailable: return "v2ratchet: one-time prekey unknown, already used or expired"
        case .prekeyStore(let m): return "v2ratchet: prekey store — \(m)"
        case .notFirstChain: return "v2ratchet: session is past its first chain — start message not sent"

        case .plaintextTooLarge(let size, let max): return "v2ratchet: plaintext \(size) B exceeds envelope limit \(max) B"
        case .keychain(let status): return "v2ratchet: keychain OSStatus=\(status)"
        case .malformed(let message): return "v2ratchet: malformed — \(message)"
        case .crypto(let message): return "v2ratchet: crypto — \(message)"
        case .replayOrTooOld(let n): return "v2ratchet: replay/old message n=\(n)"
        case .skippedKeyLimitExceeded: return "v2ratchet: skipped key limit exceeded"
        case .counterExhausted: return "v2ratchet: message counter at UInt32.max — re-establish session"
        }
    }
}

/// P8-IOS-RATCHET-PCS-01 (#6): merged per-peer Double Ratchet state. Replaces the
/// pre-0x03 two-simplex layout (separate `send.`/`recv.` blobs) with a single
/// `dr.<peerId>` entry that holds BOTH the sending and receiving chains under one
/// ping-pong root key — the textbook Signal Double Ratchet. This is what provides
/// post-compromise security: fresh ECDH entropy and (since v0x04) a fresh
/// one-time ML-KEM-768 secret are folded into `rootKey` on every DH turn, so a
/// captured chain key no longer
/// derives future keys once one new DH turn has happened.
private struct V2RatchetState: Codable {
    let version: UInt8
    var peerId: String
    /// Own current DH ratchet keypair. `dhsPriv` is the 32-byte X25519 scalar:
    /// for the initiator a fresh ephemeral; for the responder it starts as the
    /// long-term HKEM X25519 secret (the prekey/anchor) and becomes a fresh
    /// ephemeral on the first reply. Never nil under the merged DR.
    var dhsPriv: Data
    var dhsPub: Data
    /// Peer's current ratchet public key; nil only before the responder's very
    /// first receive (the initiator seeds it with the peer's long-term prekey).
    var dhr: Data?
    var rootKey: Data
    /// Sending chain key. `nil` is the ping-pong arming flag: it means "the next
    /// seal starts a new sending chain" (perform one send-side DH turn first).
    var cks: Data?
    /// Receiving chain key; nil until established.
    var ckr: Data?
    /// Messages sent / received in the CURRENT sending / receiving chain.
    var ns: UInt32
    var nr: UInt32
    /// Skipped per-message keys, keyed by `"<base64(dhr)>:<n>"` so keys from
    /// different DH chains never collide (the pre-0x03 map keyed by message
    /// number alone collided across chains).
    var skippedMessageKeys: [String: Data]
    /// Archived finished receiving chains — the no-header substitute for Signal's
    /// `PN` (the 16 KB constant-size envelope has no spare header byte for it).
    /// Keyed by `base64(old dhr)`; lets a late frame from a prior DH chain be
    /// advanced on demand. Bounded to the most recent `maxArchivedRecvChains`.
    var archivedRecvChains: [String: ArchivedRecvChain]
    /// Count of genuine DH turns performed. Orders archived-chain eviction and
    /// bounds the simultaneous-initiation crossing window (`dhTurns == 0`).
    var dhTurns: UInt32

    // Frame v0x04: a fresh ML-KEM-768 exchange on EVERY DH turn. Each sending
    // chain announces a one-time KEM public key of ours and carries the
    // ciphertext encapsulated to the one-time KEM key the peer announced last.
    // No long-term Kyber key is touched after the bootstrap.

    /// Secret key of the one-time KEM key we announce in the current sending
    /// chain. Set on our send-side turn (initiator: at bootstrap); cleared on
    /// the receive-side turn that decapsulates with it, so it is used at most
    /// once. nil = nothing outstanding.
    var kemSkOwn: Data?
    /// Public half of `kemSkOwn`, carried in every header of the current
    /// sending chain. Cleared together with `kemSkOwn`.
    var kemPkOwn: Data?
    /// Ciphertext produced on our last send-side turn (initiator: the bootstrap
    /// ciphertext), carried in every header of the current sending chain so the
    /// peer can run the turn from whichever frame of the chain arrives first.
    var kemCtOut: Data?
    /// One-time KEM public key the peer announced in its latest receiving chain.
    /// Consumed (cleared) by the send-side turn that encapsulates to it, so no
    /// peer KEM key is ever encapsulated to twice.
    var kemPkPeer: Data?
    /// Initiator only, first sending chain only: id of the contact's one-time
    /// prekey this session was bootstrapped against. While set, every frame
    /// carries the BOOT flag and this id so the responder can bootstrap from
    /// whichever first-chain frame arrives first. Cleared by our first send-side
    /// DH turn; nil on the responder.
    var bootPrekeyId: Data?
    /// Issue number of the prekey this session was built on (the responder's
    /// own, or — on the initiator — the contact's, as carried in its code).
    /// While unconfirmed, a session is restarted (initiator) or replaced
    /// (responder) only by a bootstrap against a prekey with a HIGHER number, so
    /// both sides always agree which attempt wins.
    var bootPrekeySeq: UInt64?
    /// True once we have run a receive-side DH turn, i.e. the peer has proven
    /// it holds this session (it answered a chain of ours). A confirmed session
    /// is never replaced by a bootstrap frame.
    var peerConfirmed: Bool
}

/// A finished receiving chain retained so late, out-of-order frames from a
/// previous DH turn can still be opened. `archivedAtTurn` orders eviction.
private struct ArchivedRecvChain: Codable {
    var ckr: Data
    var nr: UInt32
    var archivedAtTurn: UInt32
}

// MARK: - Wiping secrets where they actually live

/// Overwrite a secret in the storage it really lives in. Swift `Data` is
/// copy-on-write: if the storage is still shared with another `Data` value,
/// a wipe silently lands on a fresh private copy and the original bytes survive.
/// This compares the storage address before and after taking mutable access;
/// a change means the wipe missed the original. Returns false in that case.
/// DEBUG builds count both outcomes so a self-test can prove the ratchet and
/// prekey paths never hit shared storage. (Values up to 14 B may be stored
/// inline, where addresses mean nothing — every secret here is 32 B or more.)
@discardableResult
func wipeSecretInPlace(_ data: inout Data) -> Bool {
    guard data.count > 14 else { data.securelyWipe(); return true }
    let before = data.withUnsafeBytes { UInt(bitPattern: $0.baseAddress) }
    let after = data.withUnsafeMutableBytes { UInt(bitPattern: $0.baseAddress) }
    let inPlace = before == after
    data.securelyWipe()
    #if DEBUG
    SecretWipeAuditV2.record(inPlace: inPlace)
    #endif
    return inPlace
}

/// Wipe an optional secret and leave nil. The value is moved out first so the
/// wipe owns the only reference.
func wipeSecretInPlace(_ data: inout Data?) {
    guard var owned = data else { return }
    data = nil
    wipeSecretInPlace(&owned)
}

/// Put `new` into `slot` and wipe what was there. The old value is moved out
/// before the wipe, so it is the only reference to its storage.
fileprivate func replaceSecret(_ slot: inout Data, with new: Data) {
    var old = slot
    slot = new
    wipeSecretInPlace(&old)
}
fileprivate func replaceSecret(_ slot: inout Data?, with new: Data?) {
    var old = slot
    slot = new
    wipeSecretInPlace(&old)
}

/// A copy in storage of its own (never a slice sharing another buffer).
fileprivate func freshCopy(_ bytes: Data) -> Data {
    var out = Data(capacity: bytes.count)
    out.append(bytes)
    return out
}

/// `bytes[range]` copied into storage of its own — one allocation, no
/// intermediate copy left behind.
fileprivate func freshCopy(_ bytes: Data, _ range: Range<Int>) -> Data {
    var out = Data(capacity: range.count)
    out.append(contentsOf: bytes[(bytes.startIndex + range.lowerBound)..<(bytes.startIndex + range.upperBound)])
    return out
}

/// Give a just-decoded secret storage of its own and wipe the decoder's buffer.
/// Whether a decoder hands out slices of its input is an implementation detail;
/// after this, the session's secrets never share storage with the blob, so
/// wiping the blob and later the secrets both hit their real bytes.
fileprivate func rehomeSecret(_ data: inout Data) {
    var old = data
    data = freshCopy(old)
    old.securelyWipe()          // may be shared with the decoder input — not audited
}
fileprivate func rehomeSecret(_ data: inout Data?) {
    guard var value = data else { return }
    data = nil
    rehomeSecret(&value)
    data = value
}

#if DEBUG
/// Counts wipes that hit the original storage vs. only a copy (see above).
enum SecretWipeAuditV2 {
    private static let lock = NSLock()
    private static var inPlaceCount = 0
    private static var sharedCount = 0
    static func record(inPlace: Bool) {
        lock.lock(); defer { lock.unlock() }
        if inPlace { inPlaceCount += 1 } else { sharedCount += 1 }
    }
    static func reset() {
        lock.lock(); defer { lock.unlock() }
        inPlaceCount = 0; sharedCount = 0
    }
    static func counts() -> (inPlace: Int, shared: Int) {
        lock.lock(); defer { lock.unlock() }
        return (inPlaceCount, sharedCount)
    }
}
#endif

extension V2RatchetState {
    /// Overwrite every secret this session holds. Called on every seal/open
    /// exit — after the session was persisted, or when it is discarded.
    mutating func wipeSecrets() {
        wipeSecretInPlace(&dhsPriv)
        wipeSecretInPlace(&rootKey)
        wipeSecretInPlace(&cks)
        wipeSecretInPlace(&ckr)
        wipeSecretInPlace(&kemSkOwn)
        for key in Array(skippedMessageKeys.keys) {
            if var k = skippedMessageKeys.removeValue(forKey: key) { wipeSecretInPlace(&k) }
        }
        for key in Array(archivedRecvChains.keys) {
            if var a = archivedRecvChains.removeValue(forKey: key) { wipeSecretInPlace(&a.ckr) }
        }
    }

    /// Move every secret into storage of its own right after decoding.
    mutating func rehomeSecrets() {
        rehomeSecret(&dhsPriv)
        rehomeSecret(&rootKey)
        rehomeSecret(&cks)
        rehomeSecret(&ckr)
        rehomeSecret(&kemSkOwn)
        for key in Array(skippedMessageKeys.keys) {
            if var k = skippedMessageKeys.removeValue(forKey: key) { rehomeSecret(&k); skippedMessageKeys[key] = k }
        }
        for key in Array(archivedRecvChains.keys) {
            if var a = archivedRecvChains.removeValue(forKey: key) { rehomeSecret(&a.ckr); archivedRecvChains[key] = a }
        }
    }
}

struct V2RatchetOpenedPayload {
    let plaintext: Data
    let messageNumber: UInt32
    let senderRatchetPublicKey: Data
    /// True when this frame resolved a crossing start in the peer's favour:
    /// we had our own unanswered first chain and adopted the peer's session
    /// instead. Every frame we sent in our abandoned chain is never opened by
    /// the peer (it keeps its own session) and must be sent again.
    var adoptedCrossing: Bool = false
}

enum V2RatchetPayload {
    private static let magic = Data([0x4c, 0x32, 0x52, 0x50])
    // P8-IOS-CRYPTO-01: frame v0x02 introduces the in-band Kyber768 ciphertext
    // immediately after the AEAD nonce so that root-key derivation can mix in
    // an ML-KEM-768 shared secret (hybrid PQ) on top of the X25519 ECDH.
    // v0x01 frames are no longer accepted; existing ratchet sessions must
    // re-initialise. The old layout (54 B header) cannot be re-used opaquely
    // because the AAD (= header bytes) is bound into every per-message AEAD
    // and must match exactly on both peers.
    // Legacy pre-0x03 frame version (two-simplex chain, no DH ratchet). No longer
    // emitted or accepted: a 0x02 frame fails `parse`'s version guard and its
    // matching state evicts via loadState — the locked One-Message-Break on the
    // 0x02→0x03 upgrade (precedent: the v0x01→v0x02 transition).
    private static let frameVersionLegacy: UInt8 = 0x02
    private static let flagInitialOrCurrentDH: UInt8 = 0x01
    /// Set (together with 0x01) on every frame of the initiator's first chain:
    /// the header's otpkId names the responder's one-time prekey. The only two
    /// accepted flag bytes are 0x01 and 0x03.
    private static let flagBoot: UInt8 = 0x02
    private static let zeroPrekeyId = Data(count: PrekeyStoreV2.idLen)
    // P8-IOS-RATCHET-PCS-01 (#6): active DH-ratchet frame. open() performs a DH
    // ratchet step whenever the peer's ratchet public key changes — that key
    // change IS the authoritative new-chain signal (see ratchetDecrypt). An
    // explicit "new chain" flag was deliberately NOT kept: it can't be a
    // fail-closed gate without rejecting a new chain's non-first frame
    // delivered out of order, and the dhr comparison already decides correctly.
    // Folding a fresh DH secret into the root per round-trip is what gives PCS.
    //
    // v0x04 (P8-RCV2-IOS-07) replaces v0x03's "long-term Kyber key, re-encap
    // every 32 turns" with a fresh one-time ML-KEM-768 exchange on EVERY turn:
    // header = magic ‖ ver ‖ flags ‖ msgNo ‖ ratchetPk ‖ nonce ‖ otpkId ‖ kemPk ‖ kemCt
    // (otpkId added by P8-RCV2-IOS-08: one-time prekey bootstrap).
    // v0x03 is neither emitted nor accepted (pre-launch single break).
    private static let frameVersionPQTurn: UInt8 = 0x04
    /// The frame version emitted by seal() and the only version open() accepts.
    private static let emittedFrameVersion: UInt8 = frameVersionPQTurn
    private static let headerLen = 4 + 1 + 1 + 4 + LadonV2.x25519PkLen + LadonV2.aeadNonceLen + PrekeyStoreV2.idLen + LadonV2.kyber768PkLen + LadonV2.kyber768CtLen
    /// Bytes a ratchet frame adds on top of its plaintext: header ‖ ct ‖ tag,
    /// where ct has exactly the plaintext's length (ChaChaPoly).
    static let frameOverheadLen = headerLen + LadonV2.aeadTagLen
    /// Largest plaintext a real message may carry in the fixed 16,384-byte
    /// envelope. Derived from the wire constants, never hand-set (2,889 B today).
    static let maxPlaintextLen = LadonV2.maxInnerMessageBodyLen - frameOverheadLen
    // State v0x05: per-turn one-time KEM keys (v0x04) plus the one-time
    // prekey bootstrap fields. loadState evicts any older state (and the
    // orphaned `send.`/`recv.` blobs are best-effort evicted on fresh init) —
    // sessions re-establish once.
    private static let stateVersion: UInt8 = 0x05
    private static let maxSkippedKeys = 64
    private static let maxSkipAhead = 64
    /// Retain at most this many finished receiving chains for late out-of-order
    /// frames (the no-header substitute for Signal's PN). Kept deliberately small:
    /// every retained chain key is a forward-secrecy window for not-yet-delivered
    /// old-chain frames, so we favour FS over deep reorder tolerance. A genuinely
    /// in-order frame from a DH chain older than this is unrecoverable (bounded-
    /// reorder loss, fail-closed) — acceptable in a ping-pong where a new peer
    /// chain only starts after the peer received from us. Raising this trades FS
    /// for tolerance; do not raise without intending that trade-off.
    private static let maxArchivedRecvChains = 2
    private static let kcService = "app.ladon.messenger.v2.ratchet"

    /// P8-AUDIT5-IOS-A2 (2026-05-21): mutual exclusion for seal/open.
    ///
    /// Without this, V2SessionManager.fetchAndProcessV2Messages →
    /// receivePendingFromAllExits() issues per-exit fetches inside a
    /// TaskGroup. Two messages from the same sender that happen to land on
    /// different exits would race here: both tasks call open(), both
    /// loadState() the same `recv.<senderId>` Keychain item, both produce
    /// independent +1 increments to messageNumber and both call
    /// saveState(). The loser's write overwrites the winner's, so the
    /// next inbound message from that sender uses a stale (smaller)
    /// messageNumber — silently dropped by replayOrTooOld or accepted with
    /// the wrong chain-key (silent decryption failure).
    ///
    /// The lock is global rather than per-account because the contention
    /// frequency is tiny (~10 Hz aggregate seal+open across the whole app)
    /// and a global NSRecursiveLock is dramatically simpler to reason about
    /// than a per-account map with lifecycle. Recursive variant in case
    /// future code paths call seal from inside an open closure (e.g.
    /// auto-reply); cheap on the uncontended path.
    private static let stateMutex = NSRecursiveLock()

    static func isRatchetFrame(_ data: Data) -> Bool {
        data.count >= magic.count && Data(data.prefix(magic.count)) == magic
    }

    /// True if `frame` was sealed in our own still unanswered first chain
    /// (BOOT flag). Exactly these frames are lost if a crossing start later
    /// resolves in the peer's favour (see `adoptedCrossing`).
    static func isBootFrame(_ frame: Data) -> Bool {
        (try? parse(frame))?.isBoot ?? false
    }

    /// True if seal() to this peer can proceed: a session exists or an unused
    /// prekey of the peer is on file. Lets the send path refuse early — before
    /// an exit is picked or a single-use token is spent.
    static func canSeal(toPeer peerId: String) throws -> Bool {
        stateMutex.lock(); defer { stateMutex.unlock() }
        if var session = try loadState(account: drAccount(peerId)) {
            session.wipeSecrets()
            return true
        }
        return try loadPeerPrekey(peerId) != nil
    }

    /// True if a session with this peer is stored.
    static func hasSession(peerId: String) throws -> Bool {
        stateMutex.lock(); defer { stateMutex.unlock() }
        guard var session = try loadState(account: drAccount(peerId)) else { return false }
        session.wipeSecrets()
        return true
    }

    /// Delete the session with this peer — only ever on the user's own action
    /// (reset, or deleting the chat); never triggered by anything received.
    /// Succeeds only if no session item remains.
    static func deleteSession(peerId: String) throws {
        stateMutex.lock(); defer { stateMutex.unlock() }
        let status = deleteState(account: drAccount(peerId))
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw V2RatchetError.keychain(status)
        }
        // The record of first-chain sends belongs to the session.
        blobStore.delete(account: firstChainAccount(peerId))
    }

    // MARK: First-chain sends (crossing recovery)
    //
    // Ids of the application messages we sent in our own still unanswered
    // first chain to a peer. If a crossing start later resolves in the
    // peer's favour (`adoptedCrossing`), the peer never opens those frames
    // and the caller sends the messages again in the adopted session. Only
    // message ids are kept (no content), in the same protected store as the
    // session, and dropped with it.

    private static func firstChainAccount(_ peerId: String) -> String { "firstchain.\(peerId)" }
    /// Bound on kept ids; an unanswered first chain this long is far outside
    /// any real use, the oldest ids go first.
    private static let firstChainSendsCap = 1_000

    /// Record `messageID` as sent in our first chain to `peerId`.
    static func recordFirstChainSend(peerId: String, messageID: String) {
        guard isValidMessageID(messageID) else { return }
        stateMutex.lock(); defer { stateMutex.unlock() }
        var ids = loadFirstChainSends(peerId)
        guard !ids.contains(messageID) else { return }
        ids.append(messageID)
        if ids.count > firstChainSendsCap { ids.removeFirst(ids.count - firstChainSendsCap) }
        do { try blobStore.save(Data(ids.joined(separator: "\n").utf8), account: firstChainAccount(peerId)) }
        catch { SecureLogger.error("[V2] first-chain send not recorded: \(error)") }
    }

    /// Our first chain to `peerId` is answered (or gone): forget the record.
    static func clearFirstChainSends(peerId: String) {
        stateMutex.lock(); defer { stateMutex.unlock() }
        blobStore.delete(account: firstChainAccount(peerId))
    }

    /// Hand out and forget the recorded ids (to be sent again).
    static func takeFirstChainSends(peerId: String) -> [String] {
        stateMutex.lock(); defer { stateMutex.unlock() }
        let ids = loadFirstChainSends(peerId)
        blobStore.delete(account: firstChainAccount(peerId))
        return ids
    }

    private static func loadFirstChainSends(_ peerId: String) -> [String] {
        guard let data = try? blobStore.load(account: firstChainAccount(peerId)),
              let text = String(data: data, encoding: .utf8) else { return [] }
        return text.split(separator: "\n").map(String.init).filter(isValidMessageID)
    }

    /// Message ids are UUID strings; nothing else is stored.
    private static func isValidMessageID(_ id: String) -> Bool {
        !id.isEmpty && id.count <= 64 && id.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-") }
    }

    private static func loadPeerPrekey(_ peerId: String) throws -> OneTimePrekeyPublicV2? {
        do { return try PrekeyStoreV2.loadPeer(forPeer: peerId) }
        catch { throw V2RatchetError.prekeyStore("\(error)") }
    }

    /// `firstChainOnly` (the pairing start message): seal only into no session
    /// or our own, still unanswered first chain — decided under the same lock
    /// as the seal itself, so a peer frame that arrives in between can never
    /// turn the start message into an automatic answer.
    static func seal(plaintext: Data, peer: PeerHandleV2, recipientHkemPk: Data, localIdentity: LocalIdentityV2, firstChainOnly: Bool = false) throws -> Data {
        // Size gate first — before the lock, before loadState, before any
        // counter or chain key moves. The envelope-size check further down the
        // send path used to fire only AFTER saveState, silently burning a
        // message number on every oversized send.
        guard plaintext.count <= maxPlaintextLen else {
            throw V2RatchetError.plaintextTooLarge(size: plaintext.count, max: maxPlaintextLen)
        }
        stateMutex.lock()
        defer { stateMutex.unlock() }
        guard recipientHkemPk.count == LadonV2.hkemPkLen else {
            throw V2RatchetError.malformed("recipient HKEM pk length \(recipientHkemPk.count)")
        }
        let account = drAccount(peer.recipientId.description)
        var state = try loadState(account: account)
        defer { state?.wipeSecrets() }      // covers throws before `current` takes over
        var usedPeerPrekey: OneTimePrekeyPublicV2? = nil
        // Our own attempt was never answered (unconfirmed, still in its first
        // chain) and the contact has since given us a NEWER code: start over
        // against it. An older code (e.g. a re-opened old invite) never
        // triggers a restart — the responder would refuse it. This
        // is the recovery for a first message that was lost, arrived after its
        // prekey expired, or was refused. The responder accepts the new
        // bootstrap only against a prekey it issued later (see open()).
        var restart = false
        if let s = state, !s.peerConfirmed, let pending = s.bootPrekeyId, let usedSeq = s.bootPrekeySeq,
           let fresh = try loadPeerPrekey(peer.recipientId.description),
           fresh.id != pending, fresh.seq > usedSeq {
            restart = true
        }
        if restart {
            state?.wipeSecrets()             // the abandoned attempt's keys (`s` is out of scope now)
            state = nil
        }
        if firstChainOnly, let s = state, !(s.bootPrekeyId != nil && !s.peerConfirmed) {
            throw V2RatchetError.notFirstChain
        }
        if state == nil {
            // A new session needs an unused one-time prekey of the contact, taken
            // from its pairing code. Without one we do not start — there is no
            // fallback to the long-term key.
            guard let prekey = try loadPeerPrekey(peer.recipientId.description) else {
                throw V2RatchetError.noPeerPrekey
            }
            state = try bootstrapInitiator(peer: peer, recipientHkemPk: recipientHkemPk, prekey: prekey, localIdentity: localIdentity)
            usedPeerPrekey = prekey
            // Evict orphaned legacy two-simplex entries from the pre-0x03 layout.
            deleteState(account: legacySendAccount(peer.recipientId.description))
            deleteState(account: legacyReceiveAccount(peer.recipientId.description))
        }
        guard var current = state else {
            throw V2RatchetError.malformed("sending state missing")
        }
        state = nil                          // `current` is now the only owner of the secrets
        defer { current.wipeSecrets() }      // after saveState below, or on any throw
        guard current.dhsPriv.count == LadonV2.x25519PkLen,
              current.dhsPub.count == LadonV2.x25519PkLen else {
            throw V2RatchetError.malformed("sending state missing ratchet key")
        }

        // Ping-pong rule: cks == nil means "start a new sending chain" (perform
        // one send-side DH turn). Only the first send after a receive — or the
        // responder's first ever send — sees this, so a BURST of consecutive
        // sends performs exactly one DH turn, not one per message.
        if current.cks == nil {
            guard let dhrPub = current.dhr else {
                throw V2RatchetError.malformed("cannot start sending chain without peer ratchet key")
            }
            try dhRatchetSend(state: &current, dhrPub: dhrPub)
            current.ns = 0
        }
        guard current.cks != nil else {
            throw V2RatchetError.crypto("sending chain key unexpectedly nil")
        }
        guard let kemPkOwn = current.kemPkOwn, kemPkOwn.count == LadonV2.kyber768PkLen,
              let kemCtOut = current.kemCtOut, kemCtOut.count == LadonV2.kyber768CtLen else {
            throw V2RatchetError.malformed("sending chain missing its KEM key or ciphertext")
        }

        let messageNumber = current.ns
        // P7-IOS-CRYPTO-04: fail closed before the counter wraps. UInt32.max
        // is ~4.3e9 messages per chain; the only realistic way to hit this is a
        // bug or an attacker forcing a wrap to bypass replay protection.
        guard messageNumber < UInt32.max else {
            throw V2RatchetError.counterExhausted
        }
        var (messageKey, nextChainKey) = try deriveMessageKey(chainKey: current.cks!, messageNumber: messageNumber)
        defer { wipeSecretInPlace(&messageKey) }
        defer { wipeSecretInPlace(&nextChainKey) }   // no-op once handed to current.cks
        let nonce = randomBytes(LadonV2.aeadNonceLen)
        let flags = current.bootPrekeyId == nil ? flagInitialOrCurrentDH : (flagInitialOrCurrentDH | flagBoot)
        let header = buildHeader(version: emittedFrameVersion, flags: flags, messageNumber: messageNumber, ratchetPublicKey: current.dhsPub, nonce: nonce, otpkId: current.bootPrekeyId ?? zeroPrekeyId, kemPk: kemPkOwn, kemCt: kemCtOut)
        let ciphertextAndTag = try sealAEAD(plaintext: plaintext, keyData: messageKey, nonceData: nonce, aad: header)

        replaceSecret(&current.cks, with: nextChainKey)
        nextChainKey = Data()                // drop the second reference; current.cks owns it
        current.ns = messageNumber &+ 1
        try saveState(current, account: account)
        if let used = usedPeerPrekey {
            // Spent: the responder accepts a prekey once. Forget it (only if no
            // fresher code replaced it meanwhile). A failure here is logged but
            // does not discard the frame: the session is already stored, and a
            // leftover spent prekey is inert — seal() never re-bootstraps
            // against the id it already used, and the responder refuses it.
            do { try PrekeyStoreV2.deletePeer(forPeer: peer.recipientId.description, ifId: used.id) }
            catch { SecureLogger.error("[V2] spent peer prekey not removed: \(error)") }
        }

        var frame = Data(capacity: header.count + ciphertextAndTag.count)
        frame.append(header)
        frame.append(ciphertextAndTag)
        return frame
    }

    static func open(frame: Data, senderHsigPk: Data, localIdentity: LocalIdentityV2) throws -> V2RatchetOpenedPayload {
        stateMutex.lock()
        defer { stateMutex.unlock() }
        let parsed = try parse(frame)
        let senderId = RecipientIdV2.fromIdentityKey(senderHsigPk).description
        let account = drAccount(senderId)
        var state = try loadState(account: account)
        var bootstrappedFromPrekey = false
        if state == nil {
            state = try bootstrapResponder(
                senderId: senderId,
                senderHsigPk: senderHsigPk,
                parsed: parsed,
                localIdentity: localIdentity
            )
            bootstrappedFromPrekey = true
            deleteState(account: legacySendAccount(senderId))
            deleteState(account: legacyReceiveAccount(senderId))
        }
        guard var current = state else {
            throw V2RatchetError.malformed("missing receiving state")
        }
        state = nil                          // `current` is now the only owner of the secrets
        defer { current.wipeSecrets() }      // after saveState, or on any throw

        // What the adoption decision below needs from the session as it was
        // BEFORE this attempt (ratchetDecrypt mutates `current` even on the path
        // that ends in an AEAD failure). Only non-secret fields are kept — a
        // full copy would share the secrets' storage and defeat the wipe.
        let preDecrypt = (peerConfirmed: current.peerConfirmed, dhr: current.dhr,
                          bootPrekeyId: current.bootPrekeyId, bootPrekeySeq: current.bootPrekeySeq)
        do {
            let payload = try ratchetDecrypt(state: &current, parsed: parsed, localIdentity: localIdentity)
            // Authenticated (HSig before open, AEAD just now): burn the one-time
            // prekey BEFORE the session is stored. If the delete fails nothing
            // is stored — a prekey must never stay usable for a second session.
            if bootstrappedFromPrekey { try consumeOwnPrekey(parsed.otpkId) }
            try saveState(current, account: account)
            return payload
        } catch let e as V2RatchetError {
            // A BOOT frame from this (HSig-verified) peer that does not belong to
            // the session we hold. Only possible while our session is
            // unconfirmed — a confirmed session is never replaced, so a stolen
            // identity key plus a fresh code cannot hijack an established chat,
            // and a replayed old bootstrap (its prekey is spent) cannot roll one
            // back. Two cases:
            //  • crossing: both sides started (we still hold our own first
            //    chain). Only the canonical responder (smaller long-term HSig pk)
            //    adopts the peer's session; the other keeps its own.
            //  • restart: the peer started over (e.g. its first message was lost)
            //    before confirming our responder session. Adopt only a bootstrap
            //    against a prekey we issued AFTER the current session's, so a
            //    late frame of an abandoned older attempt never displaces a newer.
            // Either way the frame is first fully authenticated on a scratch
            // state; if it is genuine, our prekey it names is spent — burned even
            // when we do not adopt, so no copy of that code can use it later.
            guard case .crypto = e, !bootstrappedFromPrekey, parsed.isBoot,
                  !preDecrypt.peerConfirmed, preDecrypt.dhr != parsed.ratchetPublicKey else {
                throw e
            }
            var rebuilt = try bootstrapResponder(
                senderId: senderId,
                senderHsigPk: senderHsigPk,
                parsed: parsed,
                localIdentity: localIdentity
            )
            defer { rebuilt.wipeSecrets() }
            let payload = try ratchetDecrypt(state: &rebuilt, parsed: parsed, localIdentity: localIdentity)
            let adopt: Bool
            if preDecrypt.bootPrekeyId != nil {
                adopt = lexCompare(localIdentity.senderHsigKp.publicKeyBytes(), senderHsigPk) == .orderedAscending
            } else if let currentSeq = preDecrypt.bootPrekeySeq, let incomingSeq = rebuilt.bootPrekeySeq {
                adopt = incomingSeq > currentSeq
            } else {
                adopt = false
            }
            try consumeOwnPrekey(parsed.otpkId)
            guard adopt else { throw e }
            try saveState(rebuilt, account: account)
            var adopted = payload
            // Crossing (we held our own first chain), not a restart: our
            // abandoned chain's frames must be sent again by the caller.
            adopted.adoptedCrossing = preDecrypt.bootPrekeyId != nil
            return adopted
        }
    }

    /// Signal-style RatchetDecrypt over the merged state. Mutates `state` in place;
    /// the caller persists it ONLY on a clean return, so any throw (replay, gap
    /// bound, AEAD failure) leaves the persisted state untouched — fail-closed.
    private static func ratchetDecrypt(state current: inout V2RatchetState, parsed: ParsedFrame, localIdentity: LocalIdentityV2) throws -> V2RatchetOpenedPayload {
        let dhrKeyId = parsed.ratchetPublicKey.base64EncodedString()

        // 1. A previously skipped per-message key (any chain), keyed by (dhr, n).
        let skId = skKey(dhrPub: parsed.ratchetPublicKey, n: parsed.messageNumber)
        // Taken out of the map before use (the caller persists `current` only on
        // success, so a failed open leaves the stored key in place) and wiped.
        if var skipped = current.skippedMessageKeys.removeValue(forKey: skId) {
            defer { wipeSecretInPlace(&skipped) }
            let plaintext = try openAEAD(ciphertextAndTag: parsed.ciphertextAndTag, keyData: skipped, nonceData: parsed.nonce, aad: parsed.header)
            return V2RatchetOpenedPayload(plaintext: plaintext, messageNumber: parsed.messageNumber, senderRatchetPublicKey: parsed.ratchetPublicKey)
        }

        // 2. A late frame from a previous, archived receiving chain (PN substitute).
        if current.dhr != parsed.ratchetPublicKey, var archived = current.archivedRecvChains.removeValue(forKey: dhrKeyId) {
            let plaintext: Data
            do {
                plaintext = try advanceChainAndOpen(chainKey: &archived.ckr, nr: &archived.nr, parsed: parsed, skipped: &current.skippedMessageKeys, dhrPub: parsed.ratchetPublicKey)
            } catch {
                wipeSecretInPlace(&archived.ckr)
                throw error
            }
            current.archivedRecvChains[dhrKeyId] = archived
            return V2RatchetOpenedPayload(plaintext: plaintext, messageNumber: parsed.messageNumber, senderRatchetPublicKey: parsed.ratchetPublicKey)
        }

        // 3. A genuinely new peer ratchet key → DH ratchet step (the PCS turn).
        if parsed.ratchetPublicKey != (current.dhr ?? Data()) {
            try dhRatchetReceive(state: &current, parsed: parsed, localIdentity: localIdentity)
        }

        // 4. Skip within the current receiving chain, then derive + open.
        guard var ckr = current.ckr else { throw V2RatchetError.malformed("receiving chain key nil") }
        current.ckr = nil                    // moved out: `ckr` is the only owner while it advances
        let plaintext: Data
        do {
            plaintext = try advanceChainAndOpen(chainKey: &ckr, nr: &current.nr, parsed: parsed, skipped: &current.skippedMessageKeys, dhrPub: parsed.ratchetPublicKey)
        } catch {
            wipeSecretInPlace(&ckr)
            throw error
        }
        current.ckr = ckr
        return V2RatchetOpenedPayload(plaintext: plaintext, messageNumber: parsed.messageNumber, senderRatchetPublicKey: parsed.ratchetPublicKey)
    }

    /// Advance a receiving chain from `nr` up to `parsed.messageNumber`, banking
    /// skipped keys, then derive that message's key and open it. Bounded by
    /// maxSkipAhead / maxSkippedKeys; replay (target < nr) fails closed.
    private static func advanceChainAndOpen(chainKey: inout Data, nr: inout UInt32, parsed: ParsedFrame, skipped: inout [String: Data], dhrPub: Data) throws -> Data {
        let target = parsed.messageNumber
        guard target >= nr else { throw V2RatchetError.replayOrTooOld(target) }
        guard Int(target - nr) <= maxSkipAhead else { throw V2RatchetError.skippedKeyLimitExceeded }
        while nr < target {
            if skipped.count >= maxSkippedKeys { throw V2RatchetError.skippedKeyLimitExceeded }
            guard nr < UInt32.max else { throw V2RatchetError.counterExhausted }
            let (skippedKey, nextChainKey) = try deriveMessageKey(chainKey: chainKey, messageNumber: nr)
            skipped[skKey(dhrPub: dhrPub, n: nr)] = skippedKey
            replaceSecret(&chainKey, with: nextChainKey)
            nr &+= 1
        }
        guard nr < UInt32.max else { throw V2RatchetError.counterExhausted }
        var (messageKey, nextChainKey) = try deriveMessageKey(chainKey: chainKey, messageNumber: nr)
        defer { wipeSecretInPlace(&messageKey) }
        let plaintext: Data
        do {
            plaintext = try openAEAD(ciphertextAndTag: parsed.ciphertextAndTag, keyData: messageKey, nonceData: parsed.nonce, aad: parsed.header)
        } catch {
            wipeSecretInPlace(&nextChainKey)
            throw error
        }
        replaceSecret(&chainKey, with: nextChainKey)
        nextChainKey = Data()
        nr &+= 1
        return plaintext
    }

    private struct ParsedFrame {
        let header: Data
        let messageNumber: UInt32
        let ratchetPublicKey: Data
        let nonce: Data
        /// True on the initiator's first chain (flags 0x03).
        let isBoot: Bool
        /// Id of our one-time prekey the sender bootstrapped against (BOOT
        /// frames); all zero otherwise.
        let otpkId: Data
        /// One-time ML-KEM-768 public key (1,184 B) the sender announces for
        /// our next send-side turn. Identical in every frame of one chain.
        let kemPk: Data
        /// ML-KEM-768 ciphertext (1,088 B) of the sender's turn: encapsulated to
        /// the one-time key we announced last (bootstrap: to our long-term key).
        /// Identical in every frame of one chain.
        let kemCt: Data
        let ciphertextAndTag: Data
    }

    private static func parse(_ frame: Data) throws -> ParsedFrame {
        guard frame.count >= headerLen + LadonV2.aeadTagLen else { throw V2RatchetError.malformed("short frame \(frame.count)") }
        guard Data(frame.prefix(magic.count)) == magic else { throw V2RatchetError.malformed("missing magic") }
        guard frame[frame.startIndex + 4] == emittedFrameVersion else { throw V2RatchetError.malformed("unsupported frame version") }
        let flags = frame[frame.startIndex + 5]
        guard flags == flagInitialOrCurrentDH || flags == (flagInitialOrCurrentDH | flagBoot) else {
            throw V2RatchetError.malformed("unsupported flags")
        }
        let isBoot = flags & flagBoot != 0
        let messageNumber = readU32BE(frame, at: 6)
        var offset = 10
        let ratchetPublicKey = subdata(frame, offset, LadonV2.x25519PkLen); offset += LadonV2.x25519PkLen
        let nonce = subdata(frame, offset, LadonV2.aeadNonceLen); offset += LadonV2.aeadNonceLen
        let otpkId = subdata(frame, offset, PrekeyStoreV2.idLen); offset += PrekeyStoreV2.idLen
        // The id is present exactly on BOOT frames (it is public, not secret).
        guard isBoot == (otpkId != zeroPrekeyId) else { throw V2RatchetError.malformed("prekey id inconsistent with flags") }
        let kemPk = subdata(frame, offset, LadonV2.kyber768PkLen); offset += LadonV2.kyber768PkLen
        let kemCt = subdata(frame, offset, LadonV2.kyber768CtLen); offset += LadonV2.kyber768CtLen
        precondition(offset == headerLen)
        let header = subdata(frame, 0, headerLen)
        let ciphertextAndTag = subdata(frame, headerLen, frame.count - headerLen)
        return ParsedFrame(header: header, messageNumber: messageNumber, ratchetPublicKey: ratchetPublicKey, nonce: nonce, isBoot: isBoot, otpkId: otpkId, kemPk: kemPk, kemCt: kemCt, ciphertextAndTag: ciphertextAndTag)
    }

    private static func buildHeader(version: UInt8, flags: UInt8, messageNumber: UInt32, ratchetPublicKey: Data, nonce: Data, otpkId: Data, kemPk: Data, kemCt: Data) -> Data {
        precondition(otpkId.count == PrekeyStoreV2.idLen, "otpkId must be \(PrekeyStoreV2.idLen) B")
        precondition(kemPk.count == LadonV2.kyber768PkLen, "kemPk must be \(LadonV2.kyber768PkLen) B")
        precondition(kemCt.count == LadonV2.kyber768CtLen, "kemCt must be \(LadonV2.kyber768CtLen) B")
        var header = Data(capacity: headerLen)
        header.append(magic)
        header.append(version)
        header.append(flags)
        header.append(u32BE(messageNumber))
        header.append(ratchetPublicKey)
        header.append(nonce)
        header.append(otpkId)
        header.append(kemPk)
        header.append(kemCt)
        precondition(header.count == headerLen)
        return header
    }

    /// Initiator bootstrap (first sender), against the one-time prekey (OTPK)
    /// the recipient handed us in its pairing code. The root is fed by three
    /// independent secrets — DH(EK, OTPK.x), DH(EK, IK.x) and an ML-KEM-768
    /// encapsulation to OTPK.ky — so it stays secret unless all three are
    /// broken, and the recipient can derive it only once: it deletes the OTPK
    /// after the first authenticated message. IK is the recipient's long-term
    /// HKEM key from its HSig-signed directory bundle. `cks` is established
    /// immediately; the first DH turn is the responder's reply, which
    /// encapsulates to the one-time KEM key announced here. EK doubles as our
    /// first ratchet key, as before.
    private static func bootstrapInitiator(peer: PeerHandleV2, recipientHkemPk: Data, prekey: OneTimePrekeyPublicV2, localIdentity: LocalIdentityV2) throws -> V2RatchetState {
        guard recipientHkemPk.count == LadonV2.hkemPkLen else {
            throw V2RatchetError.malformed("recipient HKEM pk length \(recipientHkemPk.count)")
        }
        guard prekey.id.count == PrekeyStoreV2.idLen, prekey.id != zeroPrekeyId,
              prekey.xPk.count == LadonV2.x25519PkLen, prekey.kyPk.count == LadonV2.kyber768PkLen else {
            throw V2RatchetError.malformed("peer prekey field length")
        }
        let identityX = Data(recipientHkemPk.prefix(LadonV2.x25519PkLen))
        let ek = Curve25519.KeyAgreement.PrivateKey()
        var dh1 = try x25519(ek, peerPublicKey: prekey.xPk)
        defer { wipeSecretInPlace(&dh1) }
        var dh2 = try x25519(ek, peerPublicKey: identityX)
        defer { wipeSecretInPlace(&dh2) }
        var kyEncaps: PostQuantumService.KyberEncapsulation
        do {
            kyEncaps = try PostQuantumService.shared.encapsulateKyber(publicKey: prekey.kyPk)
        } catch {
            throw V2RatchetError.crypto("kyber encaps: \(error)")
        }
        // Independent copies before wiping the encaps buffers (CoW — same
        // pattern as HKEMV2.encaps).
        var kemCt = Data(capacity: LadonV2.kyber768CtLen)
        kemCt.append(kyEncaps.ciphertext)
        var kemSs = Data(capacity: 32)
        kemSs.append(kyEncaps.sharedSecret)
        kyEncaps.ciphertext.securelyWipe()
        kyEncaps.sharedSecret.securelyWipe()
        defer { wipeSecretInPlace(&kemSs) }
        guard kemSs.count == 32, kemCt.count == LadonV2.kyber768CtLen else {
            throw V2RatchetError.crypto("hybrid IKM component length mismatch")
        }
        let ownKem = try generateOneTimeKemKey()
        let ekPub = ek.publicKey.rawRepresentation
        let rootKey = deriveBootRootKey(
            dh1: dh1, dh2: dh2, kemSs: kemSs,
            initiatorHsigPk: localIdentity.senderHsigKp.publicKeyBytes(),
            responderHsigPk: peer.recipientHsigPk,
            initiatorEphemeralPk: ekPub,
            responderIdentityHkemPk: recipientHkemPk,
            prekey: prekey,
            kemCt: kemCt,
            initiatorKemPk: ownKem.publicKey
        )
        return V2RatchetState(
            version: stateVersion,
            peerId: peer.recipientId.description,
            dhsPriv: ek.rawRepresentation,
            dhsPub: ekPub,
            dhr: prekey.xPk,
            rootKey: rootKey,
            cks: deriveInitialChainKey(rootKey: rootKey),
            ckr: nil,
            ns: 0,
            nr: 0,
            skippedMessageKeys: [:],
            archivedRecvChains: [:],
            dhTurns: 0,
            kemSkOwn: ownKem.secretKey,
            kemPkOwn: ownKem.publicKey,
            kemCtOut: kemCt,
            kemPkPeer: nil,
            bootPrekeyId: prekey.id,
            bootPrekeySeq: prekey.seq,
            peerConfirmed: false
        )
    }

    /// X25519 with an explicit all-zero check (RFC 7748 §6.1): a low-order
    /// peer key would make the shared secret constant. Fail closed.
    private static func x25519(_ sk: Curve25519.KeyAgreement.PrivateKey, peerPublicKey: Data) throws -> Data {
        let pk: Curve25519.KeyAgreement.PublicKey
        do { pk = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerPublicKey) }
        catch { throw V2RatchetError.crypto("x25519 pk: \(error)") }
        let ss: SharedSecret
        do { ss = try sk.sharedSecretFromKeyAgreement(with: pk) }
        catch { throw V2RatchetError.crypto("x25519: \(error)") }
        var out = ss.withUnsafeBytes { Data($0) }
        var acc: UInt8 = 0
        for b in out { acc |= b }
        guard out.count == 32, acc != 0 else {
            out.securelyWipe()
            throw V2RatchetError.crypto("x25519: degenerate shared secret")
        }
        return out
    }

    /// Our own one-time prekey for a BOOT frame's id, if still valid.
    private static func loadOwnPrekey(id: Data) throws -> OwnOneTimePrekeyV2? {
        do { return try PrekeyStoreV2.loadOwnValid(id: id, now: Date()) }
        catch { throw V2RatchetError.prekeyStore("\(error)") }
    }

    /// Delete our own one-time prekey; fails unless it was really removed.
    private static func consumeOwnPrekey(_ id: Data) throws {
        do { try PrekeyStoreV2.consumeOwn(id: id) }
        catch { throw V2RatchetError.prekeyStore("\(error)") }
    }

    /// Fresh one-time ML-KEM-768 keypair. The secret is copied into a buffer of
    /// its own before the generator's copy is wiped (CoW: wiping a shared buffer
    /// would only wipe a private copy — same pattern as HKEMV2.encaps).
    private static func generateOneTimeKemKey() throws -> (publicKey: Data, secretKey: Data) {
        var kp: PostQuantumService.KyberKeypair
        do { kp = try PostQuantumService.shared.generateKyberKeypair() }
        catch { throw V2RatchetError.crypto("kyber keygen: \(error)") }
        var sk = Data(capacity: kp.secretKey.count)
        sk.append(kp.secretKey)
        kp.secretKey.securelyWipe()
        guard kp.publicKey.count == LadonV2.kyber768PkLen,
              sk.count == PostQuantumService.Constants.kyberSecretKeySize else {
            sk.securelyWipe()
            throw V2RatchetError.crypto("kyber keygen: unexpected key length")
        }
        return (kp.publicKey, sk)
    }

    /// Responder bootstrap (first receiver). Only a BOOT frame naming one of our
    /// own, still valid one-time prekeys can start a session — there is no
    /// fallback to the long-term key. Mirrors the initiator: DH(OTPK.x, EK),
    /// DH(IK.x, EK) and ML-KEM-768 decaps with OTPK.ky give the same root, so
    /// our first `ckr` equals the initiator's first `cks`. The prekey itself is
    /// deleted by open() once the frame has authenticated. Our initial DHs is a
    /// fresh random keypair that never enters a DH: `cks == nil` makes our
    /// first send a DH turn that replaces it, and a new peer chain cannot
    /// legitimately arrive before that. So neither the identity key nor the
    /// prekey is ever copied into the ratchet state.
    private static func bootstrapResponder(senderId: String, senderHsigPk: Data, parsed: ParsedFrame, localIdentity: LocalIdentityV2) throws -> V2RatchetState {
        guard parsed.isBoot else {
            throw V2RatchetError.malformed("no session and not a bootstrap frame")
        }
        guard parsed.kemCt.count == LadonV2.kyber768CtLen, parsed.kemPk.count == LadonV2.kyber768PkLen else {
            throw V2RatchetError.malformed("sender KEM field length")
        }
        guard var prekey = try loadOwnPrekey(id: parsed.otpkId) else {
            throw V2RatchetError.prekeyUnavailable
        }
        defer { prekey.wipeSecrets() }       // private halves out of memory once used
        let otpkX: Curve25519.KeyAgreement.PrivateKey
        do { otpkX = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: prekey.xSk) }
        catch { throw V2RatchetError.crypto("prekey x25519 sk: \(error)") }
        var dh1 = try x25519(otpkX, peerPublicKey: parsed.ratchetPublicKey)
        defer { wipeSecretInPlace(&dh1) }
        var dh2 = try x25519(localIdentity.recipientHkemKp.xSk, peerPublicKey: parsed.ratchetPublicKey)
        defer { wipeSecretInPlace(&dh2) }
        var kemSs: Data
        do {
            kemSs = try PostQuantumService.shared.decapsulateKyber(ciphertext: parsed.kemCt, secretKey: prekey.kySk)
        } catch {
            throw V2RatchetError.crypto("kyber decaps: \(error)")
        }
        defer { wipeSecretInPlace(&kemSs) }
        guard kemSs.count == 32 else {
            throw V2RatchetError.crypto("hybrid IKM component length mismatch")
        }
        let rootKey = deriveBootRootKey(
            dh1: dh1, dh2: dh2, kemSs: kemSs,
            initiatorHsigPk: senderHsigPk,
            responderHsigPk: localIdentity.senderHsigKp.publicKeyBytes(),
            initiatorEphemeralPk: parsed.ratchetPublicKey,
            responderIdentityHkemPk: localIdentity.recipientHkemKp.publicKeyBytes(),
            prekey: prekey.publicHalf,
            kemCt: parsed.kemCt,
            initiatorKemPk: parsed.kemPk
        )
        let placeholderDhs = Curve25519.KeyAgreement.PrivateKey()
        return V2RatchetState(
            version: stateVersion,
            peerId: senderId,
            dhsPriv: placeholderDhs.rawRepresentation,
            dhsPub: placeholderDhs.publicKey.rawRepresentation,
            dhr: parsed.ratchetPublicKey,
            rootKey: rootKey,
            cks: nil,
            ckr: deriveInitialChainKey(rootKey: rootKey),
            ns: 0,
            nr: 0,
            skippedMessageKeys: [:],
            archivedRecvChains: [:],
            dhTurns: 0,
            // Nothing announced yet: our first one-time KEM key is created on
            // our first send-side turn. The initiator's announced key is what
            // that turn encapsulates to.
            kemSkOwn: nil,
            kemPkOwn: nil,
            kemCtOut: nil,
            kemPkPeer: parsed.kemPk,
            bootPrekeyId: nil,
            bootPrekeySeq: prekey.seq,
            peerConfirmed: false
        )
    }

    /// Send-side DH turn (Signal KDF_RK, hybrid): generate a fresh ratchet
    /// keypair, encapsulate to the peer's announced one-time KEM key, generate
    /// our own next one-time KEM key, and fold `DH(newDHs, peer DHr) ‖ ML-KEM
    /// secret` into the root, producing the new sending chain. Every turn is
    /// hybrid — there is no classical-only turn. Mutates `state`.
    private static func dhRatchetSend(state current: inout V2RatchetState, dhrPub: Data) throws {
        // Fail closed: without a fresh peer KEM key this turn would be
        // classical-only (or reuse a key) — neither is allowed.
        guard let peerKemPk = current.kemPkPeer, peerKemPk.count == LadonV2.kyber768PkLen else {
            throw V2RatchetError.crypto("no unused peer KEM key for this turn")
        }
        let dhrKey: Curve25519.KeyAgreement.PublicKey
        do { dhrKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: dhrPub) }
        catch { throw V2RatchetError.crypto("peer ratchet pk: \(error)") }
        let newDhs = Curve25519.KeyAgreement.PrivateKey()
        let ss = try newDhs.sharedSecretFromKeyAgreement(with: dhrKey)
        var dh = ss.withUnsafeBytes { Data($0) }
        defer { wipeSecretInPlace(&dh) }

        var enc: PostQuantumService.KyberEncapsulation
        do { enc = try PostQuantumService.shared.encapsulateKyber(publicKey: peerKemPk) }
        catch { throw V2RatchetError.crypto("kyber encaps: \(error)") }
        // Independent copies before wiping the encaps buffers (CoW).
        var kemCt = Data(capacity: LadonV2.kyber768CtLen)
        kemCt.append(enc.ciphertext)
        var kemSs = Data(capacity: 32)
        kemSs.append(enc.sharedSecret)
        enc.ciphertext.securelyWipe()
        enc.sharedSecret.securelyWipe()
        defer { wipeSecretInPlace(&kemSs) }
        guard dh.count == 32, kemSs.count == 32, kemCt.count == LadonV2.kyber768CtLen else {
            throw V2RatchetError.crypto("hybrid turn component length mismatch")
        }

        let ownKem = try generateOneTimeKemKey()
        let newDhsPub = newDhs.publicKey.rawRepresentation
        let (newRoot, newChain) = ratchetRootStep(
            rootKey: current.rootKey, dhOutput: dh, kemSharedSecret: kemSs,
            ratchetPublicKey: newDhsPub, encapsulatedToKemPk: peerKemPk,
            kemCt: kemCt, announcedKemPk: ownKem.publicKey)
        current.dhTurns &+= 1
        replaceSecret(&current.rootKey, with: newRoot)
        replaceSecret(&current.cks, with: newChain)
        replaceSecret(&current.dhsPriv, with: newDhs.rawRepresentation)
        current.dhsPub = newDhsPub
        current.kemPkPeer = nil            // one-time: never encapsulate to it again
        current.bootPrekeyId = nil         // the first chain is over
        current.kemCtOut = kemCt
        current.kemPkOwn = ownKem.publicKey
        replaceSecret(&current.kemSkOwn, with: ownKem.secretKey)
    }

    /// Receive-side DH turn (Signal KDF_RK, hybrid): archive the finishing
    /// receiving chain, decapsulate the header ciphertext with the one-time KEM
    /// key we announced, fold `DH(own DHs, header DHr) ‖ ML-KEM secret` into the
    /// root to produce the new receiving chain, drop that one-time KEM key, then
    /// arm the next sending chain (`cks = nil`). The fresh sending keypairs are
    /// generated lazily on the next seal, so two consecutive receives do not
    /// waste keys. Mutates `state`; the caller persists only on AEAD success.
    private static func dhRatchetReceive(state current: inout V2RatchetState, parsed: ParsedFrame, localIdentity: LocalIdentityV2) throws {
        // Fail closed: a new peer chain is only legitimate after the peer saw a
        // one-time KEM key of ours that we have not used yet.
        guard var ownKemSk = current.kemSkOwn,
              let ownKemPk = current.kemPkOwn, ownKemPk.count == LadonV2.kyber768PkLen else {
            throw V2RatchetError.crypto("no unused own KEM key for this turn")
        }
        // Moved out and wiped when this turn ends, whatever the outcome: it is
        // used exactly once. (`current` is only persisted on AEAD success.)
        current.kemSkOwn = nil
        defer { wipeSecretInPlace(&ownKemSk) }
        if let oldDhr = current.dhr, let oldCkr = current.ckr {
            current.ckr = nil                // moved into the archive: one owner only
            current.archivedRecvChains[oldDhr.base64EncodedString()] =
                ArchivedRecvChain(ckr: oldCkr, nr: current.nr, archivedAtTurn: current.dhTurns)
            boundArchivedChains(&current.archivedRecvChains)
        }
        let dhrKey: Curve25519.KeyAgreement.PublicKey
        do { dhrKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: parsed.ratchetPublicKey) }
        catch { throw V2RatchetError.crypto("peer ratchet pk: \(error)") }
        let dhsKey: Curve25519.KeyAgreement.PrivateKey
        do { dhsKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: current.dhsPriv) }
        catch { throw V2RatchetError.crypto("own ratchet sk: \(error)") }
        let ss = try dhsKey.sharedSecretFromKeyAgreement(with: dhrKey)
        var dh = ss.withUnsafeBytes { Data($0) }
        defer { wipeSecretInPlace(&dh) }

        var kemSs: Data
        do { kemSs = try PostQuantumService.shared.decapsulateKyber(ciphertext: parsed.kemCt, secretKey: ownKemSk) }
        catch { throw V2RatchetError.crypto("kyber decaps: \(error)") }
        defer { wipeSecretInPlace(&kemSs) }
        guard dh.count == 32, kemSs.count == 32 else {
            throw V2RatchetError.crypto("hybrid turn component length mismatch")
        }

        let (newRoot, newChain) = ratchetRootStep(
            rootKey: current.rootKey, dhOutput: dh, kemSharedSecret: kemSs,
            ratchetPublicKey: parsed.ratchetPublicKey, encapsulatedToKemPk: ownKemPk,
            kemCt: parsed.kemCt, announcedKemPk: parsed.kemPk)
        current.dhTurns &+= 1
        replaceSecret(&current.rootKey, with: newRoot)
        // Plain assignment: the finished chain key lives on in the archive.
        current.ckr = newChain
        current.dhr = parsed.ratchetPublicKey
        current.nr = 0
        wipeSecretInPlace(&current.cks)      // an unfinished sending chain ends here
        // One-time: the key we just decapsulated with is gone (moved out above),
        // and so is the chain material announcing it.
        current.kemPkOwn = nil
        current.kemCtOut = nil
        current.kemPkPeer = parsed.kemPk
        current.peerConfirmed = true       // the peer answered a chain of ours
    }

    /// Byte-lexicographic comparison (Data is not Comparable). Used only for the
    /// crossing tie-break; both peers hold both long-term HSig pks so they agree.
    private static func lexCompare(_ a: Data, _ b: Data) -> ComparisonResult {
        let aa = [UInt8](a), bb = [UInt8](b)
        let n = min(aa.count, bb.count)
        var i = 0
        while i < n {
            if aa[i] != bb[i] { return aa[i] < bb[i] ? .orderedAscending : .orderedDescending }
            i += 1
        }
        if aa.count == bb.count { return .orderedSame }
        return aa.count < bb.count ? .orderedAscending : .orderedDescending
    }

    private static func skKey(dhrPub: Data, n: UInt32) -> String {
        "\(dhrPub.base64EncodedString()):\(n)"
    }

    /// Keep only the most recent `maxArchivedRecvChains` finished receiving
    /// chains, evicting the oldest by `archivedAtTurn`.
    private static func boundArchivedChains(_ chains: inout [String: ArchivedRecvChain]) {
        while chains.count > maxArchivedRecvChains {
            guard let oldest = chains.min(by: { $0.value.archivedAtTurn < $1.value.archivedAtTurn })?.key else { break }
            if var evicted = chains.removeValue(forKey: oldest) { wipeSecretInPlace(&evicted.ckr) }
        }
    }

    /// Bootstrap root (P8-RCV2-IOS-08). IKM = DH(EK, OTPK.x) ‖ DH(EK, IK.x) ‖
    /// ML-KEM-768(OTPK.ky), 96 B. `info` binds the complete public transcript
    /// of the bootstrap — both HSig identities, EK, the responder's long-term
    /// HKEM key, the prekey (id, issue number, both public halves; a code with
    /// an altered number fails instead of skewing the restart order), the KEM
    /// ciphertext and
    /// the initiator's first announced one-time KEM key — so both sides derive
    /// the same root only from exactly the same values. Every field has a fixed
    /// length, so the concatenation is unambiguous.
    private static func deriveBootRootKey(dh1: Data, dh2: Data, kemSs: Data, initiatorHsigPk: Data, responderHsigPk: Data, initiatorEphemeralPk: Data, responderIdentityHkemPk: Data, prekey: OneTimePrekeyPublicV2, kemCt: Data, initiatorKemPk: Data) -> Data {
        precondition(dh1.count == 32 && dh2.count == 32 && kemSs.count == 32, "boot IKM must be 3 × 32 B")
        var ikm = Data(capacity: 96)
        ikm.append(dh1)
        ikm.append(dh2)
        ikm.append(kemSs)
        defer { wipeSecretInPlace(&ikm) }
        var info = Data("LadonV2BootRoot-v4".utf8)
        info.append(initiatorHsigPk)
        info.append(responderHsigPk)
        info.append(initiatorEphemeralPk)
        info.append(responderIdentityHkemPk)
        info.append(prekey.id)
        info.append(u64BE(prekey.seq))
        info.append(prekey.xPk)
        info.append(prekey.kyPk)
        info.append(kemCt)
        info.append(initiatorKemPk)
        let key = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: ikm), salt: Data("LadonV2BootSalt-v4".utf8), info: info, outputByteCount: 32)
        return key.withUnsafeBytes { Data($0) }
    }

    private static func deriveInitialChainKey(rootKey: Data) -> Data {
        let key = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: rootKey), salt: Data("LadonV2RatchetChainSalt-v1".utf8), info: Data("send-chain".utf8), outputByteCount: 32)
        return key.withUnsafeBytes { Data($0) }
    }

    private static func deriveMessageKey(chainKey: Data, messageNumber: UInt32) throws -> (messageKey: Data, nextChainKey: Data) {
        var info = Data("LadonV2RatchetMessage-v1".utf8)
        info.append(u32BE(messageNumber))
        let material = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: chainKey), salt: Data("LadonV2RatchetStep-v1".utf8), info: info, outputByteCount: 64)
        var bytes = material.withUnsafeBytes { Data($0) }
        defer { wipeSecretInPlace(&bytes) }
        guard bytes.count == 64 else { throw V2RatchetError.crypto("message key material length \(bytes.count)") }
        // Separate storage for each half — slices would share `bytes`' buffer.
        return (freshCopy(bytes, 0..<32), freshCopy(bytes, 32..<64))
    }

    /// P8-IOS-RATCHET-PCS-01 (#6): DH-ratchet root step, invoked from
    /// dhRatchetSend / dhRatchetReceive on every DH turn. Signal-style KDF_RK:
    /// folds fresh secrets into the current root key and emits the next root key
    /// + a fresh chain key. Run on each round-trip, this is what provides
    /// post-compromise security — a captured chain key no longer derives future
    /// keys once one new DH turn has happened.
    ///
    /// v0x04: every turn is hybrid. IKM = X25519 secret ‖ ML-KEM-768 secret, so
    /// the new root stays secret unless BOTH are broken. `info` binds the turn's
    /// public transcript — the new ratchet key, the KEM key that was
    /// encapsulated to, the ciphertext, and the KEM key announced for the next
    /// turn — so the root commits to exactly the values both sides used.
    /// HKDF-SHA256(salt = current root key, ikm = dh ‖ kem) → 64 B split.
    private static func ratchetRootStep(rootKey: Data, dhOutput: Data, kemSharedSecret: Data, ratchetPublicKey: Data, encapsulatedToKemPk: Data, kemCt: Data, announcedKemPk: Data) -> (rootKey: Data, chainKey: Data) {
        precondition(dhOutput.count == 32 && kemSharedSecret.count == 32, "turn IKM must be x25519_ss(32) || kyber_ss(32)")
        var ikm = Data(capacity: 64)
        ikm.append(dhOutput)
        ikm.append(kemSharedSecret)
        defer { wipeSecretInPlace(&ikm) }
        var info = Data("LadonV2RatchetDHStep-PQ-v4".utf8)
        info.append(ratchetPublicKey)
        info.append(encapsulatedToKemPk)
        info.append(kemCt)
        info.append(announcedKemPk)
        let material = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: ikm),
            salt: rootKey,
            info: info,
            outputByteCount: 64)
        var bytes = material.withUnsafeBytes { Data($0) }
        defer { wipeSecretInPlace(&bytes) }
        // Separate storage for each half — slices would share `bytes`' buffer.
        return (freshCopy(bytes, 0..<32), freshCopy(bytes, 32..<64))
    }

    #if DEBUG
    /// Test seam (DEBUG): exposes the DH-ratchet root step so the self-test can
    /// pin its KDF behaviour independently of seal/open.
    static func _ratchetRootStepForTesting(rootKey: Data, dhOutput: Data, kemSharedSecret: Data, ratchetPublicKey: Data, encapsulatedToKemPk: Data, kemCt: Data, announcedKemPk: Data) -> (rootKey: Data, chainKey: Data) {
        ratchetRootStep(rootKey: rootKey, dhOutput: dhOutput, kemSharedSecret: kemSharedSecret,
                        ratchetPublicKey: ratchetPublicKey, encapsulatedToKemPk: encapsulatedToKemPk,
                        kemCt: kemCt, announcedKemPk: announcedKemPk)
    }

    /// Which one-time KEM material a session currently holds. Lets the
    /// self-tests prove "used once, then gone" without exposing any key bytes.
    struct KemSlotsForTesting: Equatable {
        let hasOwnSecret: Bool
        let hasOwnPublic: Bool
        let hasOutgoingCt: Bool
        let hasPeerPublic: Bool
    }
    static func _kemSlotsForTesting(peerId: String) throws -> KemSlotsForTesting? {
        stateMutex.lock(); defer { stateMutex.unlock() }
        guard var s = try loadState(account: drAccount(peerId)) else { return nil }
        defer { s.wipeSecrets() }
        return KemSlotsForTesting(hasOwnSecret: s.kemSkOwn != nil, hasOwnPublic: s.kemPkOwn != nil,
                                  hasOutgoingCt: s.kemCtOut != nil, hasPeerPublic: s.kemPkPeer != nil)
    }

    /// Header field offsets of a v0x04 frame, for tamper/inspection self-tests.
    static let _otpkIdOffsetForTesting = 10 + LadonV2.x25519PkLen + LadonV2.aeadNonceLen
    static let _kemPkOffsetForTesting = _otpkIdOffsetForTesting + PrekeyStoreV2.idLen
    static let _kemCtOffsetForTesting = _kemPkOffsetForTesting + LadonV2.kyber768PkLen

    /// Raw persisted session blob, to prove a rejected frame left it untouched.
    static func _rawStateForTesting(peerId: String) throws -> Data? {
        stateMutex.lock(); defer { stateMutex.unlock() }
        return try blobStore.load(account: drAccount(peerId))
    }

    /// Arm a single failing session save (in-memory store only).
    static func _failNextStateSaveForTesting() {
        stateMutex.lock(); defer { stateMutex.unlock() }
        (blobStore as? InMemoryRatchetBlobStore)?.failNextSave = true
    }

    /// The bootstrap root KDF, for the transcript-binding self-test.
    static func _bootRootForTesting(dh1: Data, dh2: Data, kemSs: Data, initiatorHsigPk: Data, responderHsigPk: Data, initiatorEphemeralPk: Data, responderIdentityHkemPk: Data, prekey: OneTimePrekeyPublicV2, kemCt: Data, initiatorKemPk: Data) -> Data {
        deriveBootRootKey(dh1: dh1, dh2: dh2, kemSs: kemSs, initiatorHsigPk: initiatorHsigPk, responderHsigPk: responderHsigPk,
                          initiatorEphemeralPk: initiatorEphemeralPk, responderIdentityHkemPk: responderIdentityHkemPk,
                          prekey: prekey, kemCt: kemCt, initiatorKemPk: initiatorKemPk)
    }

    /// Remove one stored session. The self-tests run several identities in one
    /// process and sessions are keyed by peer only, so a third identity talking
    /// to the same peer must not pick up another identity's session.
    static func _deleteStateForTesting(peerId: String) {
        stateMutex.lock(); defer { stateMutex.unlock() }
        deleteState(account: drAccount(peerId))
    }

    /// Store a session with KEM slots removed — a state no legitimate
    /// sequence produces — so the self-tests can prove the fail-closed guards.
    static func _dropKemSlotsForTesting(peerId: String, ownSecret: Bool, peerPublic: Bool) throws {
        stateMutex.lock(); defer { stateMutex.unlock() }
        let account = drAccount(peerId)
        guard var s = try loadState(account: account) else { throw V2RatchetError.malformed("no state") }
        defer { s.wipeSecrets() }
        if ownSecret { wipeSecretInPlace(&s.kemSkOwn) }
        if peerPublic { s.kemPkPeer = nil }
        try saveState(s, account: account)
    }
    #endif

    private static func sealAEAD(plaintext: Data, keyData: Data, nonceData: Data, aad: Data) throws -> Data {
        do {
            let nonce = try ChaChaPoly.Nonce(data: nonceData)
            let sealed = try ChaChaPoly.seal(plaintext, using: SymmetricKey(data: keyData), nonce: nonce, authenticating: aad)
            var out = Data(capacity: sealed.ciphertext.count + sealed.tag.count)
            out.append(sealed.ciphertext)
            out.append(sealed.tag)
            return out
        } catch {
            throw V2RatchetError.crypto("seal: \(error)")
        }
    }

    private static func openAEAD(ciphertextAndTag: Data, keyData: Data, nonceData: Data, aad: Data) throws -> Data {
        guard ciphertextAndTag.count >= LadonV2.aeadTagLen else { throw V2RatchetError.malformed("ct+tag too short") }
        let ciphertextLen = ciphertextAndTag.count - LadonV2.aeadTagLen
        do {
            let nonce = try ChaChaPoly.Nonce(data: nonceData)
            let box = try ChaChaPoly.SealedBox(nonce: nonce, ciphertext: Data(ciphertextAndTag.prefix(ciphertextLen)), tag: Data(ciphertextAndTag.suffix(LadonV2.aeadTagLen)))
            return try ChaChaPoly.open(box, using: SymmetricKey(data: keyData), authenticating: aad)
        } catch {
            throw V2RatchetError.crypto("open: \(error)")
        }
    }

    /// Merged Double-Ratchet state account (layout versioned by `stateVersion`). One entry per peer.
    private static func drAccount(_ peerId: String) -> String { "dr.\(peerId)" }
    /// Pre-0x03 two-simplex accounts — kept only so fresh-init can best-effort
    /// evict the orphaned blobs during the v0x02→v0x03 migration.
    private static func legacySendAccount(_ peerId: String) -> String { "send.\(peerId)" }
    private static func legacyReceiveAccount(_ peerId: String) -> String { "recv.\(peerId)" }

    // P8-IOS-RATCHET-PCS-01: ratchet-state persistence sits behind an injectable
    // blob store so DEBUG self-tests can exercise the ratchet deterministically
    // in memory without Keychain side effects. The store deals only in opaque
    // bytes; all V2RatchetState encode/decode + version self-heal stays here, so
    // V2RatchetState remains private.
    private static var blobStore: V2RatchetBlobStore = KeychainRatchetBlobStore(service: kcService)

    private static func loadState(account: String) throws -> V2RatchetState? {
        guard var data = try blobStore.load(account: account) else { return nil }
        defer { data.securelyWipe() }        // the encoded session holds every secret
        // P8-IOS-CRYPTO-01 (2026-05-20): self-heal across the v0x01 → v0x02
        // hybrid-PQ transition. An undecodable or wrong-version blob is evicted
        // and treated as "no state" so the next seal/open re-creates a current
        // state (one round of plaintext breakage is the explicit migration
        // trade-off; throwing here would leave the chat permanently wedged with
        // no UI recovery path).
        do {
            var state = try PropertyListDecoder().decode(V2RatchetState.self, from: data)
            state.rehomeSecrets()            // own storage, independent of `data`
            guard state.version == stateVersion else {
                state.wipeSecrets()
                _ = deleteState(account: account)
                return nil
            }
            return state
        } catch {
            _ = deleteState(account: account)
            return nil
        }
    }

    /// Best-effort delete used by loadState() to evict a stale/wrong-version
    /// entry. Returns the OSStatus only for diagnostics — callers do NOT
    /// propagate errors because the alternative (throw) would re-wedge the very
    /// migration this self-heal is here to fix.
    @discardableResult
    private static func deleteState(account: String) -> OSStatus {
        blobStore.delete(account: account)
    }

    private static func saveState(_ state: V2RatchetState, account: String) throws {
        var data: Data
        do {
            let encoder = PropertyListEncoder()
            encoder.outputFormat = .binary
            data = try encoder.encode(state)
        } catch {
            throw V2RatchetError.malformed("encode state: \(error)")
        }
        defer { data.securelyWipe() }        // the encoded session holds every secret
        try blobStore.save(data, account: account)
    }
}

// MARK: - Ratchet state persistence (injectable for self-tests)

/// Opaque per-account blob persistence for `V2RatchetPayload`. Production uses
/// the Keychain; DEBUG self-tests swap in an in-memory store so the ratchet can
/// be exercised deterministically without Keychain side effects.
fileprivate protocol V2RatchetBlobStore {
    func load(account: String) throws -> Data?
    func save(_ blob: Data, account: String) throws
    @discardableResult func delete(account: String) -> OSStatus
}

fileprivate final class KeychainRatchetBlobStore: V2RatchetBlobStore {
    let service: String
    init(service: String) { self.service = service }

    // P8-AUDIT8-IOS-33 (audit F2): values are sealed with the Secure Enclave.
    func load(account: String) throws -> Data? {
        try SealedKeychainV2.read(service: service, account: account)
    }

    func save(_ blob: Data, account: String) throws {
        try SealedKeychainV2.write(blob, service: service, account: account)
    }

    @discardableResult
    func delete(account: String) -> OSStatus {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: false,
        ]
        return SecItemDelete(query as CFDictionary)
    }
}

#if DEBUG
/// In-memory blob store for ratchet self-tests — never used in production.
fileprivate final class InMemoryRatchetBlobStore: V2RatchetBlobStore {
    private var blobs: [String: Data] = [:]
    /// Makes the next save fail like a Keychain error would.
    var failNextSave = false
    func load(account: String) throws -> Data? { blobs[account] }
    func save(_ blob: Data, account: String) throws {
        if failNextSave { failNextSave = false; throw V2RatchetError.keychain(errSecIO) }
        blobs[account] = blob
    }
    @discardableResult func delete(account: String) -> OSStatus {
        blobs.removeValue(forKey: account) != nil ? errSecSuccess : errSecItemNotFound
    }
}

extension V2RatchetPayload {
    /// Swap ratchet persistence to a throwaway in-memory store for self-tests.
    /// Pair with `_restoreKeychainStoreForTesting()` (ideally via `defer`).
    static func _installInMemoryStoreForTesting() {
        stateMutex.lock(); defer { stateMutex.unlock() }
        blobStore = InMemoryRatchetBlobStore()
        PrekeyStoreV2._installInMemoryBackendForTesting()
    }
    static func _restoreKeychainStoreForTesting() {
        stateMutex.lock(); defer { stateMutex.unlock() }
        blobStore = KeychainRatchetBlobStore(service: kcService)
        PrekeyStoreV2._restoreKeychainBackendForTesting()
    }
}
#endif

/// Long-term identity of the local user, needed to send and receive.
struct LocalIdentityV2 {
    /// Local recipient id derived from `senderHsigKp.publicKeyBytes()`.
    let recipientId: RecipientIdV2
    /// Long-term HSig keypair (Ed25519 + ML-DSA-65).
    let senderHsigKp: HSigKeyPairV2
    /// Long-term HKEM keypair (X25519 + ML-KEM-768) used to receive Inner-Envelopes.
    let recipientHkemKp: HKEMKeyPairV2

    /// Convenience: caller doesn't have to derive recipientId themselves.
    static func make(senderHsigKp: HSigKeyPairV2, recipientHkemKp: HKEMKeyPairV2) -> LocalIdentityV2 {
        let pkBytes = senderHsigKp.publicKeyBytes()
        return LocalIdentityV2(
            recipientId: RecipientIdV2.fromIdentityKey(pkBytes),
            senderHsigKp: senderHsigKp,
            recipientHkemKp: recipientHkemKp
        )
    }
}

/// One known peer (out-of-band trust anchor).
/// `recipientHsigPk` is the trust-on-first-use / QR-exchanged identity of the contact.
struct PeerHandleV2 {
    let recipientId: RecipientIdV2
    let recipientHsigPk: Data        // 1,984 B — verified out-of-band
}

/// A recipient's bundle is per exit: the verifier inside is exit-bound.
struct BundleCacheKey: Hashable {
    let recipientId: RecipientIdV2
    let exitId: ExitIdV2
}

enum RelayClientV2Error: Error, CustomStringConvertible {
    case noExitsConfigured
    case bundleHsigPkMismatch
    /// No delivery key of this contact on file (contact added before A1, or
    /// added from a code without one) — a fresh code exchange is needed.
    case missingDeliveryKey
    /// The contact's published verifier does not match the key we hold: it
    /// rotated its delivery key and ours is stale.
    case deliveryKeyOutdated
    /// The Keychain refused to read or write a delivery key.
    case deliveryKeyStore(String)
    /// The user blocked this contact — nothing is sent to it (A1 §7).
    case contactBlocked
    case directory(DirectoryClientV2Error)
    case enqueue(EnqueueClientV2Error)
    case inner(InnerEnvelopeV2Error)
    case ratchet(V2RatchetError)
    case wire(LadonV2Error)

    var description: String {
        switch self {
        case .noExitsConfigured: return "relayv2: no exits configured"
        case .bundleHsigPkMismatch: return "relayv2: peer's published bundle hsig_pk != trusted pk"
        case .missingDeliveryKey: return "relayv2: no delivery key of this contact on file"
        case .deliveryKeyOutdated: return "relayv2: contact's delivery key has changed"
        case .deliveryKeyStore(let m): return "relayv2: delivery key store — \(m)"
        case .contactBlocked: return "relayv2: contact is blocked"
        case .directory(let e): return "relayv2: directory — \(e)"
        case .enqueue(let e): return "relayv2: enqueue — \(e)"
        case .inner(let e): return "relayv2: inner — \(e)"
        case .ratchet(let e): return "relayv2: ratchet — \(e)"
        case .wire(let e): return "relayv2: wire — \(e)"
        }
    }
}

/// Top-level orchestrator. Single instance per app session.
actor RelayClientV2 {

    // MARK: - Dependencies

    let identity: LocalIdentityV2
    let registry: ExitRegistryV2
    /// Addendum A2 stage 2: every request travels as a sealed request in one
    /// of two constant-rate lanes. Lane S (send connection) carries ENQUEUE,
    /// contact bundle lookups and cover — never our own rid; lane F
    /// (identity connection) carries FETCH, our own bundle and the push
    /// token. The lanes own the connections; this client only builds and
    /// interprets requests.
    let lanes: LaneSchedulerV2

    /// Recipients' HKEM keys and verifiers per exit, from their signed
    /// bundles. Public data; per client instance (a Tor change builds a new
    /// client and the bundles are re-read on first use).
    private var recipientBundles: [BundleCacheKey: (hkemPk: Data, verifier: Data)] = [:]

    /// When a fetch last made us publish on an exit that did not know us
    /// (exit id hex → time). While a publish keeps failing, one attempt per
    /// exit per 15 s is enough.
    private var unknownExitPublishAt: [String: Date] = [:]

    /// `published_at` of the last bundle this client signed. The exit keeps
    /// a bundle only if it is strictly newer than the stored one, so two
    /// publishes in the same second (seen 02.10.2026: two concurrent push
    /// registrations) must not carry the same value — the second got 409.
    private var lastPublishedAt: UInt64 = 0
    /// A running publish on all exits; concurrent callers await it instead
    /// of publishing a second time.
    private var allExitsPublish: Task<[ExitIdV2], Never>?
    private static let unknownExitPublishMinInterval: TimeInterval = 15

    /// Lane F fetches rotate over the exits, one per tick (A2 §5).
    private var nextFetchExit = 0

    /// Issue #38: RAM-only hold of sealed frames whose delivery is unconfirmed,
    /// so a message discarded by a relay restart can be re-submitted. Never
    /// persisted — see `PendingSendCache` at the bottom of this file.
    let pendingSends = PendingSendCache()

    /// Holds the lock/panic observer tokens and deregisters them when this
    /// client goes away (see `init`).
    private let wipeObservers = NotificationObserverBox()

    // NOTE (2026-08-24): a transport-failure counter used to live here that
    // posted `TorHealthCheckRequested` every third consecutive failure, to wake
    // up TorController's (otherwise never-triggered) recovery path.
    //
    // REVERTED — it made things worse, on device. During bootstrap transport
    // failures are normal and expected, so the counter fired while Tor was
    // still coming up; `handleTorFailure` then tore down the half-built
    // circuit. The result was a bootstrap that crawled to 99 % and stalled
    // there — precisely the failure mode handleTorFailure's own comment warns
    // about ("NEWNYM too often can reset a half-built circuit and keep us stuck
    // at 99%"). Before the change Tor came up at 10-20 % within seconds.
    //
    // The underlying finding stands and is NOT fixed: nothing posts
    // `TorHealthCheckRequested`, so a proxy that dies after a healthy start is
    // still never noticed. Any future attempt must not act during bootstrap —
    // at minimum it needs `circuitEstablished` to have been true for a while,
    // and it needs to distinguish "never came up" from "died after running".

    init(identity: LocalIdentityV2,
         registry: ExitRegistryV2,
         lanes: LaneSchedulerV2) {
        self.identity = identity
        self.registry = registry
        self.lanes = lanes

        // Issue #38: held frames follow the same forensic model as the
        // decrypted attachment cache — dropped when the device locks
        // (protected data unavailable) and on emergency wipe. Captured as a
        // local constant so the closure holds the cache, never `self`.
        //
        // The tokens are kept in a box that deregisters on deinit:
        // V2SessionManager builds a fresh RelayClientV2 on every Tor change, so
        // registering without removal would accumulate observers for the life
        // of the process.
        let heldFrames = self.pendingSends
        let wipeOnNotify: @Sendable (Notification) -> Void = { _ in
            Task { await heldFrames.wipeAll() }
        }
        #if canImport(UIKit)
        wipeObservers.tokens.append(NotificationCenter.default.addObserver(
            forName: UIApplication.protectedDataWillBecomeUnavailableNotification,
            object: nil, queue: nil, using: wipeOnNotify))
        #endif
        wipeObservers.tokens.append(NotificationCenter.default.addObserver(
            forName: .emergencyMemoryWipe,
            object: nil, queue: nil, using: wipeOnNotify))
    }

    // MARK: - Bootstrap

    /// One-shot: probe all exits, select fastest, return its descriptor.
    func bootstrapAndSelectExit() async throws -> ExitDescriptorV2 {
        await registry.geoProbe()
        guard let exit = await registry.fastestExit() else {
            throw RelayClientV2Error.noExitsConfigured
        }
        return exit
    }

    /// Preview which exit a subsequent `sendMessage(..., excludingExits:)` call
    /// would pick. Used by retry logic to track which exits have already been
    /// tried so that subsequent attempts rotate to a different one.
    func previewNextExit(excluding excluded: Set<String> = []) async -> ExitDescriptorV2? {
        await registry.fastestExit(excluding: excluded)
    }

    /// Re-probe entry/exit health after transient upstream failures (e.g. HTTP 502)
    /// so subsequent retries can re-rank exits using fresh latency/failure data.
    func reprobeExits() async {
        await registry.geoProbe(perProbeTimeoutSec: 2.0)
    }

    // MARK: - Send

    /// Send `messageBody` to `peer` in the next free lane-S tick (A2 §5).
    /// Picks the fastest exit, resolves the recipient's bundle for it (a
    /// DIR_GET in an earlier lane-S tick if not cached), and pads the inner
    /// envelope to the fixed 15,128 B of relay protocol 0x06.
    ///
    /// - Parameters:
    ///   - peer: trusted peer handle.
    ///   - messageBody: opaque payload (UTF-8 text or attachment manifest bytes).
    ///   - isControl: a control message (pairing START, KEY after a block):
    ///     queued behind real messages (A2 §5 lane-S priority 2). It no
    ///     longer suppresses the push — there is no per-envelope push bit any
    ///     more (A2 §7); a banner it causes is removed after the wake.
    /// - Returns: the chosen exit and the envelope id the exit keys replay on.
    @discardableResult
    func sendMessage(
        to peer: PeerHandleV2,
        messageBody: Data,
        excludingExits: Set<String> = [],
        retryAfterReplay: Bool = true,
        messageID: String? = nil,
        isControl: Bool = false,
        /// Pairing start message: see V2RatchetPayload.seal(firstChainOnly:).
        firstChainOnly: Bool = false
    ) async throws -> (exitId: ExitIdV2, envelopeId: Data) {
        let traceId = String(UUID().uuidString.prefix(8))
        // P7-CRYPTO-10: do NOT log `bodyLen=messageBody.count` here — that
        // would persist the inner plaintext size into tor_diag.log.
        SecureLogger.torDiag("[V2][\(traceId)] sendMessage to peer.recipientId=\(peer.recipientId.description.prefix(16)) control=\(isControl) excluding=\(excludingExits.count)")
        // 0. Size gate — before an exit is picked or the ratchet advances.
        //    Same arithmetic as the padding step below, so a body that passes
        //    here always fits.
        let maxPlain = LadonV2.maxInnerMessageBodyLen - V2RatchetPayload.frameOverheadLen
        guard messageBody.count <= maxPlain else {
            throw RelayClientV2Error.ratchet(.plaintextTooLarge(size: messageBody.count, max: maxPlain))
        }
        // Same stage: no session and no unused prekey of the contact means
        // seal() would refuse — find out before anything is sent.
        let ready: Bool
        do { ready = try V2RatchetPayload.canSeal(toPeer: peer.recipientId.description) }
        catch let e as V2RatchetError { throw RelayClientV2Error.ratchet(e) }
        guard ready else { throw RelayClientV2Error.ratchet(.noPeerPrekey) }

        // 1. Not to a blocked contact (A1 §7; an unreadable block list means
        //    no send — fail closed). Then the recipient's delivery keys (A1 §2):
        //    without one no exit accepts the envelope, so fail before an exit
        //    is picked or the ratchet advances.
        let recipientKeys: [Data]
        do {
            if try BlockListV2.containsStrict(peer.recipientId) { throw RelayClientV2Error.contactBlocked }
            recipientKeys = try DeliveryKeyStoreV2.peerKeys(peer.recipientId)
            guard !recipientKeys.isEmpty else { throw RelayClientV2Error.missingDeliveryKey }
        } catch let e as RelayClientV2Error {
            throw e
        } catch {
            throw RelayClientV2Error.deliveryKeyStore("\(error)")
        }

        // 2. Pick exit (rotating away from previously failed ones for retries).
        guard let exit = await registry.fastestExit(excluding: excludingExits) else {
            throw RelayClientV2Error.noExitsConfigured
        }
        let exitId: ExitIdV2
        let exitPk: Data
        do { exitId = try exit.exitId(); exitPk = try exit.hkemPublicKey() }
        catch { throw RelayClientV2Error.wire(error as? LadonV2Error ?? .structuralInvariant("\(error)")) }
        SecureLogger.torDiag("[V2][\(traceId)] sendMessage chose exit=\(exitId.description.prefix(16)) entry=\(exit.entryUrl.host ?? "?")")

        // 3. The recipient's HKEM key for this exit, from its signed bundle.
        let key = BundleCacheKey(recipientId: peer.recipientId, exitId: exitId)
        let recipientHkemPk: Data
        let recipientKey: Data
        do {
            (recipientHkemPk, recipientKey) = try await ensureRecipientBundle(forKey: key, peer: peer, exit: exit, deliveryKeys: recipientKeys)
        } catch let RelayClientV2Error.directory(err) {
            // Rotate exits on both unknown recipient and unknown exit
            if case .unknownRecipient = err {} else if case .unknownExit = err {} else { throw RelayClientV2Error.directory(err) }
            var newExcluded = excludingExits
            newExcluded.insert(exitId.description)
            // Rotate only if another exit exists. With a single exit the
            // rotation found nothing and surfaced "no exits configured"
            // instead of the real reason (e.g. the recipient's bundle not
            // yet republished after a restart) — keep the real error; the
            // caller's retry loop tries the same exit again after a pause.
            guard await registry.fastestExit(excluding: newExcluded) != nil else {
                throw RelayClientV2Error.directory(err)
            }
            return try await sendMessage(to: peer, messageBody: messageBody, excludingExits: newExcluded, retryAfterReplay: retryAfterReplay, messageID: messageID, isControl: isControl, firstChainOnly: firstChainOnly)
        }

        // 4. Inner envelope (recipient layer), padded to the fixed length.
        //    Stamped with the send connection's clock: `sent_at` below is read
        //    by the exit (A2 stage 1).
        let nowSec = ClockSyncV2.sendLane.nowSec()
        let applicationPayload: Data
        do {
            applicationPayload = try V2RatchetPayload.seal(
                plaintext: messageBody,
                peer: peer,
                recipientHkemPk: recipientHkemPk,
                localIdentity: identity,
                firstChainOnly: firstChainOnly
            )
        } catch let e as V2RatchetError {
            throw RelayClientV2Error.ratchet(e)
        }
        // Each byte of inner-plaintext padding yields exactly one byte of
        // inner wire, so one probe seal gives the pad length.
        let inner: Data
        do {
            let probe = try InnerEnvelopeV2.seal(
                recipientId: peer.recipientId, recipientHkemPk: recipientHkemPk,
                senderHsigKp: identity.senderHsigKp, timestamp: nowSec,
                messageBody: applicationPayload, padLen: 0)
            let extra = SealedV2.innerEnvelopeLen - probe.count
            guard extra >= 0 else {
                throw RelayClientV2Error.wire(.structuralInvariant(
                    "inner envelope \(probe.count) B > \(SealedV2.innerEnvelopeLen) B"))
            }
            inner = try InnerEnvelopeV2.seal(
                recipientId: peer.recipientId, recipientHkemPk: recipientHkemPk,
                senderHsigKp: identity.senderHsigKp, timestamp: nowSec,
                messageBody: applicationPayload, padLen: extra)
        } catch let e as InnerEnvelopeV2Error {
            throw RelayClientV2Error.inner(e)
        }
        guard inner.count == SealedV2.innerEnvelopeLen else {
            throw RelayClientV2Error.wire(.structuralInvariant("inner envelope \(inner.count) B != \(SealedV2.innerEnvelopeLen) B"))
        }

        // 5. ENQUEUE body (A2 §4.1 kind 0x11): rid || K_X || sent_at ||
        //    envelope_id || inner — sealed to the exit. A fresh envelope id
        //    per attempt; a retry is a new request.
        let envelopeId = randomBytes(LadonV2.envelopeIdLen)
        var body: Data
        do {
            var kx = try DeliveryKeyV2.exitDeliveryKey(recipientKey, exitId: exitId)
            defer { _ = wipeSecretInPlace(&kx) }
            body = SealedV2.enqueueHeader(recipientId: peer.recipientId, exitDeliveryKey: kx,
                                          sentAt: nowSec, envelopeId: envelopeId)
            body.append(inner)
        } catch let e as LadonV2Error {
            throw RelayClientV2Error.wire(e)
        }
        let request: SealedRequestV2
        do {
            defer { _ = wipeSecretInPlace(&body) }
            request = try SealedCodecV2.seal(targetHkemPk: exitPk, targetId: exitId.bytes, kind: .enqueue, body: body)
        } catch let e as LadonV2Error {
            throw RelayClientV2Error.wire(e)
        }

        // 6. Send in the next free lane-S tick.
        let entryUrl = exit.entryUrl
        let outcome: Result<OpenedSealedResponseV2, Error>
        do {
            outcome = .success(try await lanes.sendLaneExchange(
                kind: .enqueue, priority: isControl ? .controlMessage : .realMessage,
                build: { (request, entryUrl) }))
        } catch {
            outcome = .failure(error)
        }
        let failure: EnqueueClientV2Error?
        switch outcome {
        case .success(let r):
            failure = Self.enqueueError(forStatus: r.status)
        case .failure(let e):
            failure = Self.enqueueError(forTransport: e)
        }
        if let e = failure {
            // P8-AUDIT5-IOS-A1, adapted to A2: a lost response can hide an
            // accepted envelope, so a retry always re-seals (new envelope id,
            // new sent_at; for 5xx a different exit when one exists). Worst
            // case the recipient gets the frame twice; its ratchet drops the
            // duplicate (replayOrTooOld). 409 = this envelope id was seen.
            if case .http(let status) = e, [400, 409, 502, 503, 504].contains(status), retryAfterReplay {
                // A refused delivery key or unknown recipient (now visible to
                // us, never to the path) drops the cached bundle so the retry
                // re-reads the current one. 400 is retried only as STALE,
                // after the clock took this response's sample.
                if status == 502 || status == 503 || status == 504 { recipientBundles[key] = nil }
                var newExcluded = excludingExits
                if status != 409 && status != 400,
                   await registry.fastestExit(excluding: excludingExits.union([exitId.description])) != nil {
                    newExcluded.insert(exitId.description)
                }
                SecureLogger.torDiag("[V2][\(traceId)] sendMessage status=\(status); re-sealing, retrying once")
                return try await sendMessage(to: peer, messageBody: messageBody, excludingExits: newExcluded,
                                             retryAfterReplay: false, messageID: messageID,
                                             isControl: isControl, firstChainOnly: firstChainOnly)
            }
            if case .http(let status) = e, status == 401 || status == 403 {
                recipientBundles[key] = nil
            }
            SecureLogger.torDiag("[V2][\(traceId)] sendMessage ENQUEUE FAILED exit=\(exitId.description.prefix(16)) entry=\(exit.entryUrl.host ?? "?") err=\(e)")
            throw RelayClientV2Error.enqueue(e)
        }
        // Issue #38: hold the sealed frame in RAM so it can be re-submitted if
        // the relay's memory-only mailbox is discarded before the recipient
        // fetches it. Held after a confirmed enqueue only; best effort.
        if let messageID {
            await pendingSends.hold(
                messageID: messageID,
                frame: applicationPayload,
                recipientId: peer.recipientId,
                recipientHsigPk: peer.recipientHsigPk
            )
        }
        // Crossing recovery: remember what went out in our own unanswered
        // first chain; once we send outside it, that chain is answered and the
        // record is obsolete.
        let peerId = peer.recipientId.description
        if V2RatchetPayload.isBootFrame(applicationPayload) {
            if let messageID { V2RatchetPayload.recordFirstChainSend(peerId: peerId, messageID: messageID) }
        } else {
            V2RatchetPayload.clearFirstChainSends(peerId: peerId)
        }
        SecureLogger.torDiag("[V2][\(traceId)] sendMessage OK exit=\(exitId.description.prefix(16)) peer=\(peer.recipientId.description.prefix(16))")
        return (exitId, envelopeId)
    }

    /// The sealed ENQUEUE status as the error the callers already know
    /// (`EnqueueClientV2Error`), or nil for OK. The status codes are the
    /// HTTP statuses the exit used to answer with; now only we see them.
    static func enqueueError(forStatus status: UInt8) -> EnqueueClientV2Error? {
        switch status {
        case SealedStatusV2.ok: return nil
        case SealedStatusV2.stale: return .http(status: 400)
        case SealedStatusV2.replay: return .http(status: 409)
        case SealedStatusV2.rate: return .http(status: 429)
        case SealedStatusV2.deliveryKey, SealedStatusV2.unknownRecipient: return .http(status: 502)
        case SealedStatusV2.unavailable, SealedStatusV2.internal: return .http(status: 503)
        default: return .http(status: 413)  // MALFORMED: never retried
        }
    }

    static func enqueueError(forTransport error: Error) -> EnqueueClientV2Error {
        switch error {
        case SealedTransportV2Error.http(let s): return .http(status: s)
        case SealedTransportV2Error.malformed(let m): return .malformed(m)
        default: return .transport(error)
        }
    }

    // MARK: - Lane defaults (A2 §5)

    /// Lane S default: one COVER request to the fastest exit. Built at the
    /// tick; the exit opens and discards it.
    func makeCoverJob() async -> LaneJobV2? {
        guard let exit = await registry.fastestExit(),
              let pk = try? exit.hkemPublicKey(),
              let id = try? exit.exitId() else { return nil }
        let entryUrl = exit.entryUrl
        return LaneJobV2(
            kind: .cover,
            build: {
                (try SealedCodecV2.seal(targetHkemPk: pk, targetId: id.bytes, kind: .cover, body: Data()), entryUrl)
            },
            complete: { result in
                if case .failure(let e) = result {
                    SecureLogger.debug("[V2] cover tick failed: \(e)")
                }
            })
    }

    /// Lane F default: one acknowledged FETCH, rotating over the exits. Built
    /// at the tick (fresh timestamp, current ack). `deliver` receives what
    /// the fetch handed out; it runs inside the lane tick, so the next fetch
    /// carries the ack of a batch that is already stored.
    func makeFetchJob(
        deliver: @escaping @Sendable (_ envelopes: [OpenedInnerEnvelopeV2], _ receipt: FetchReceiptV2) async -> Void
    ) async -> LaneJobV2? {
        let exits = await registry.exits
        guard !exits.isEmpty else { return nil }
        let exit = exits[nextFetchExit % exits.count]
        nextFetchExit = (nextFetchExit + 1) % exits.count
        guard let pk = try? exit.hkemPublicKey(), let exitId = try? exit.exitId() else { return nil }
        let entryUrl = exit.entryUrl
        return LaneJobV2(
            kind: .fetch,
            build: { [self] in
                (try await buildFetchRequest(exitPk: pk, exitId: exitId), entryUrl)
            },
            complete: { [self] result in
                await handleFetchResult(result, exit: exit, exitId: exitId, deliver: deliver)
            })
    }

    /// FETCH body: rid || ts || ack || HSig("L1-FetchAck-v2" || exit_id || rid || ts || ack).
    private func buildFetchRequest(exitPk: Data, exitId: ExitIdV2) throws -> SealedRequestV2 {
        let nowSec = ClockSyncV2.shared.nowSec()
        // Acknowledge the batch this exit handed out last time and we stored
        // (all zero if none) — only then does the exit delete it.
        let ack = FetchAckLedgerV2.shared.ack(for: exitId.description)
        let sig = try FetchClientV2.signFetchAck(exitId: exitId, recipientId: identity.recipientId, timestamp: nowSec,
                                                  ack: ack, with: identity.senderHsigKp)
        var body = Data(capacity: LadonV2.recipientIdLen + 8 + LadonV2.fetchBatchIdLen + sig.count)
        body.append(identity.recipientId.bytes)
        body.append(u64BE(nowSec))
        body.append(ack)
        body.append(sig)
        return try SealedCodecV2.seal(targetHkemPk: exitPk, targetId: exitId.bytes, kind: .fetch, body: body)
    }

    private func handleFetchResult(
        _ result: Result<OpenedSealedResponseV2, Error>,
        exit: ExitDescriptorV2,
        exitId: ExitIdV2,
        deliver: @Sendable ([OpenedInnerEnvelopeV2], FetchReceiptV2) async -> Void
    ) async {
        let prefix = String(exitId.description.prefix(16))
        let response: OpenedSealedResponseV2
        switch result {
        case .failure(let e):
            SecureLogger.torDiag("[V2] fetch FAILED on \(prefix): \(e)")
            return
        case .success(let r):
            response = r
        }
        switch response.status {
        case SealedStatusV2.ok:
            break
        case SealedStatusV2.unknownRecipient:
            // A1 §4 rule 1(c): this exit does not know us — first start, or
            // it restarted and lost its RAM-only directory. Publish there in
            // a later lane-F tick (never awaited inside this tick: it needs
            // the lane this tick is running in).
            if claimUnknownExitPublish(exitId) {
                SecureLogger.torDiag("[V2] exit \(prefix) does not know us — publishing bundle")
                Task { _ = await self.publishWithEntryFallback(exit) }
            }
            return
        default:
            SecureLogger.torDiag("[V2] fetch on \(prefix) refused, status=\(response.status)")
            return
        }
        let parsed: (hasMore: Bool, batchId: Data?, envelopes: [Data])
        do {
            parsed = try Self.parseFetchBody(response.body)
        } catch {
            SecureLogger.error("[V2] fetch body malformed on \(prefix): \(error)")
            return
        }
        var opened: [OpenedInnerEnvelopeV2] = []
        for wire in parsed.envelopes {
            do {
                opened.append(try InnerEnvelopeV2.open(wire: wire, innerVersion: LadonV2.innerVersionRealMessage,
                                                       recipientId: identity.recipientId,
                                                       recipientHkemKp: identity.recipientHkemKp))
            } catch {
                SecureLogger.torDiag("[V2] inner.open FAILED err=\(error) wire_len=\(wire.count)")
            }
        }
        if !parsed.envelopes.isEmpty {
            SecureLogger.torDiag("[V2] fetch exit=\(prefix) got=\(parsed.envelopes.count) opened=\(opened.count) hasMore=\(parsed.hasMore)")
        }
        await deliver(opened, FetchReceiptV2(exitHex: exitId.description, batchId: parsed.batchId))
    }

    /// Sealed FETCH body (A2 §5, one envelope per response):
    /// has_more (1) || batch_id (16, zero = none) || count (1) || [len u32 BE || inner].
    static func parseFetchBody(_ body: Data) throws -> (hasMore: Bool, batchId: Data?, envelopes: [Data]) {
        let b = Data(body)
        let head = 1 + LadonV2.fetchBatchIdLen + 1
        guard b.count >= head else { throw LadonV2Error.structuralInvariant("fetch body short") }
        guard b[0] <= 1 else { throw LadonV2Error.structuralInvariant("fetch has_more") }
        let hasMore = b[0] == 1
        let batch = Data(b[1..<(1 + LadonV2.fetchBatchIdLen)])
        let count = Int(b[head - 1])
        guard count <= 1 else { throw LadonV2Error.structuralInvariant("fetch count \(count)") }
        let records = try FetchClientV2.parseLengthPrefixedRecords(Data(b[head...]))
        guard records.count == count else { throw LadonV2Error.structuralInvariant("fetch record count") }
        // No length check on the record: one that does not open is logged and
        // acknowledged like before, never left to block the mailbox.
        let none = batch == Data(count: LadonV2.fetchBatchIdLen)
        // A batch id comes with an envelope, and only then.
        guard none == (count == 0) else { throw LadonV2Error.structuralInvariant("fetch batch id") }
        return (hasMore, none ? nil : batch, records)
    }

    // MARK: - Recipient HKEM lookup (used by attachments)

    /// Resolve the peer's full HKEM public key (X25519 || Kyber768, 1,216 B).
    /// Mirrors the lookup done internally by `sendMessage`: pick the fastest
    /// exit, fetch and verify the bundle if needed, then return its HKEM pk.
    /// Used by the attachment send path so that V2 contacts can encrypt seeds
    /// with the same keys the messaging layer already trusts (no parallel
    /// directory of recipient keys).
    func recipientHkemPublicKey(for peer: PeerHandleV2) async throws -> Data {
        return try await recipientHkemPublicKey(for: peer, excludingExits: [])
    }

    /// Internal: same as `recipientHkemPublicKey(for:)` but rotates exits when
    /// the chosen exit doesn't have the recipient's bundle (E-UNKNOWN-EXIT /
    /// E-UNKNOWN-RECIPIENT). Mirrors the rotation behaviour of `sendMessage`.
    private func recipientHkemPublicKey(
        for peer: PeerHandleV2,
        excludingExits: Set<String>
    ) async throws -> Data {
        guard let exit = await registry.fastestExit(excluding: excludingExits) else {
            // Out of exits to try → bubble up the most useful diagnostic.
            throw excludingExits.isEmpty
                ? RelayClientV2Error.noExitsConfigured
                : RelayClientV2Error.directory(.unknownExit)
        }
        let exitId: ExitIdV2
        do {
            exitId = try exit.exitId()
        } catch let e as LadonV2Error {
            throw RelayClientV2Error.wire(e)
        } catch {
            throw RelayClientV2Error.wire(.structuralInvariant("\(error)"))
        }
        let deliveryKeys: [Data]
        do {
            deliveryKeys = try DeliveryKeyStoreV2.peerKeys(peer.recipientId)
            guard !deliveryKeys.isEmpty else { throw RelayClientV2Error.missingDeliveryKey }
        } catch let e as RelayClientV2Error {
            throw e
        } catch {
            throw RelayClientV2Error.deliveryKeyStore("\(error)")
        }
        let key = BundleCacheKey(recipientId: peer.recipientId, exitId: exitId)
        do {
            return try await ensureRecipientBundle(forKey: key, peer: peer, exit: exit, deliveryKeys: deliveryKeys).hkemPk
        } catch let RelayClientV2Error.directory(err) {
            // Rotate exits on unknown-recipient / unknown-exit, mirroring
            // sendMessage(). Any other directory error propagates.
            if case .unknownRecipient = err {} else if case .unknownExit = err {} else {
                throw RelayClientV2Error.directory(err)
            }
            var newExcluded = excludingExits
            newExcluded.insert(exitId.description)
            return try await recipientHkemPublicKey(for: peer, excludingExits: newExcluded)
        }
    }

    // MARK: - Recipient bundles

    /// The recipient's HKEM public key for `key.exitId`, from its signed
    /// delivery bundle (cached per client; otherwise a DIR_GET in lane S),
    /// and the one of `deliveryKeys` (current, then previous) whose verifier
    /// matches that bundle.
    ///
    /// If none matches, the recipient has rotated its key and ours is stale —
    /// the exit would refuse the envelope, so fail here with a precise error
    /// instead. A cached bundle that matches none is re-read once first: it
    /// may predate a KEY message we received since.
    private func ensureRecipientBundle(
        forKey key: BundleCacheKey,
        peer: PeerHandleV2,
        exit: ExitDescriptorV2,
        deliveryKeys: [Data]
    ) async throws -> (hkemPk: Data, deliveryKey: Data) {
        if let cached = recipientBundles[key] {
            if let k = try Self.keyMatching(verifier: cached.verifier, candidates: deliveryKeys, exitId: key.exitId) {
                return (cached.hkemPk, k)
            }
            recipientBundles[key] = nil
        }
        let exitPk: Data
        do { exitPk = try exit.hkemPublicKey() }
        catch let e as LadonV2Error { throw RelayClientV2Error.wire(e) }
        let request: SealedRequestV2
        do {
            request = try SealedCodecV2.seal(targetHkemPk: exitPk, targetId: key.exitId.bytes,
                                             kind: .dirGet, body: peer.recipientId.bytes)
        } catch let e as LadonV2Error {
            throw RelayClientV2Error.wire(e)
        }
        let entryUrl = exit.entryUrl
        let response: OpenedSealedResponseV2
        do {
            response = try await lanes.sendLaneExchange(kind: .dirGet, priority: .directoryLookup,
                                                         build: { (request, entryUrl) })
        } catch SealedTransportV2Error.http(let s) {
            throw RelayClientV2Error.directory(s == 404 ? .unknownExit : .http(status: s))
        } catch {
            throw RelayClientV2Error.directory(.transport(error))
        }
        switch response.status {
        case SealedStatusV2.ok: break
        case SealedStatusV2.unknownRecipient: throw RelayClientV2Error.directory(.unknownRecipient)
        default: throw RelayClientV2Error.directory(.http(status: Int(response.status)))
        }
        let bundle: BundleV2
        do {
            bundle = try DirectoryClientV2.verifiedBundle(
                response.body, recipientId: peer.recipientId, exitId: key.exitId,
                recipientHsigPk: peer.recipientHsigPk, nowSec: ClockSyncV2.sendLane.nowSec())
        } catch let e as DirectoryClientV2Error {
            throw RelayClientV2Error.directory(e)
        } catch let e as LadonV2Error {
            throw RelayClientV2Error.wire(e)
        }
        // Defence-in-depth: verifiedBundle already cross-checked, but assert again here.
        guard bundle.recipientHsigPk == peer.recipientHsigPk else {
            throw RelayClientV2Error.bundleHsigPkMismatch
        }
        guard let k = try Self.keyMatching(verifier: bundle.verifier, candidates: deliveryKeys, exitId: key.exitId) else {
            throw RelayClientV2Error.deliveryKeyOutdated
        }
        recipientBundles[key] = (hkemPk: bundle.recipientHkemPk, verifier: bundle.verifier)
        return (bundle.recipientHkemPk, k)
    }

    /// The first candidate key whose V_X for `exitId` equals `verifier`, or
    /// nil. Pure; the derived K_X are wiped. (V_X itself is public.)
    static func keyMatching(verifier: Data, candidates: [Data], exitId: ExitIdV2) throws -> Data? {
        for k in candidates {
            var kx: Data
            do { kx = try DeliveryKeyV2.exitDeliveryKey(k, exitId: exitId) }
            catch let e as LadonV2Error { throw RelayClientV2Error.wire(e) }
            let matches = DeliveryKeyV2.verifier(exitDeliveryKey: kx).constantTimeEqual(verifier)
            _ = wipeSecretInPlace(&kx)
            if matches { return k }
        }
        return nil
    }

    /// Open the ratchet frame of a real message. `adoptedCrossing`: see
    /// `V2RatchetOpenedPayload` — the caller sends our abandoned first-chain
    /// messages again.
    func openApplicationPayload(_ envelope: OpenedInnerEnvelopeV2) throws -> (plaintext: Data, adoptedCrossing: Bool) {
        guard !envelope.isCoverTraffic else { return (envelope.messageBody, false) }
        guard V2RatchetPayload.isRatchetFrame(envelope.messageBody) else {
            throw RelayClientV2Error.ratchet(.malformed("missing V2 ratchet frame"))
        }
        do {
            let opened = try V2RatchetPayload.open(
                frame: envelope.messageBody,
                senderHsigPk: envelope.senderHsigPk,
                localIdentity: identity
            )
            return (opened.plaintext, opened.adoptedCrossing)
        } catch let e as V2RatchetError {
            throw RelayClientV2Error.ratchet(e)
        }
    }

    // MARK: - Bundle publishing

    /// True (and recorded) if a publish for an unknown-recipient report on
    /// `exitId` is due; false while the last one is less than 15 s ago.
    private func claimUnknownExitPublish(_ exitId: ExitIdV2) -> Bool {
        let now = Date()
        if let last = unknownExitPublishAt[exitId.description],
           now.timeIntervalSince(last) < Self.unknownExitPublishMinInterval {
            return false
        }
        unknownExitPublishAt[exitId.description] = now
        return true
    }

    /// Build & publish the local user's delivery bundle for `targetExit`
    /// (A1 §4) as a DIR_PUT in lane F. Called only when an exit does not know
    /// us (first start, exit or push relay restart) or after a rotation of
    /// the delivery key — there is no periodic republish: `published_at` is
    /// public and a fixed cadence exposed every foreground minute of the user.
    @discardableResult
    func publishBundle(on targetExit: ExitDescriptorV2) async throws -> ExitIdV2 {
        let exitId: ExitIdV2
        let exitPk: Data
        do { exitId = try targetExit.exitId(); exitPk = try targetExit.hkemPublicKey() }
        catch let e as LadonV2Error { throw RelayClientV2Error.wire(e) }
        let entryUrl = targetExit.entryUrl
        let response: OpenedSealedResponseV2
        do {
            // Built at the tick, so `published_at` is the time it goes out.
            response = try await lanes.fetchLaneExchange(kind: .dirPut, build: { [self] in
                (try await buildBundleRequest(exitId: exitId, exitPk: exitPk), entryUrl)
            })
        } catch let e as RelayClientV2Error {
            throw e
        } catch SealedTransportV2Error.http(let s) {
            throw RelayClientV2Error.directory(.http(status: s))
        } catch {
            throw RelayClientV2Error.directory(.transport(error))
        }
        guard response.status == SealedStatusV2.ok else {
            throw RelayClientV2Error.directory(.http(status: Int(response.status)))
        }
        return exitId
    }

    private func buildBundleRequest(exitId: ExitIdV2, exitPk: Data) throws -> SealedRequestV2 {
        // Strictly increasing per client (set before any await, so
        // interleaved calls on this actor never share a value).
        let publishedAt = max(ClockSyncV2.shared.nowSec(), lastPublishedAt &+ 1)
        lastPublishedAt = publishedAt
        let bundle: BundleV2
        do {
            var ownKey = try DeliveryKeyStoreV2.ownKey()
            defer { _ = wipeSecretInPlace(&ownKey) }
            bundle = try BundleV2.issue(
                recipientId: identity.recipientId,
                recipientHsigPk: identity.senderHsigKp.publicKeyBytes(),
                recipientHkemPk: identity.recipientHkemKp.publicKeyBytes(),
                publishedAt: publishedAt,
                exitId: exitId,
                deliveryKey: ownKey,
                signWith: identity.senderHsigKp
            )
        } catch let e as LadonV2Error {
            throw RelayClientV2Error.wire(e)
        } catch let e as DeliveryKeyStoreV2Error {
            throw RelayClientV2Error.deliveryKeyStore("\(e)")
        }
        do {
            return try SealedCodecV2.seal(targetHkemPk: exitPk, targetId: exitId.bytes, kind: .dirPut, body: bundle.encode())
        } catch let e as LadonV2Error {
            throw RelayClientV2Error.wire(e)
        }
    }

    /// Publish on one exit, trying every other entry if its own one fails.
    ///
    /// P8-AUDIT5-IOS-A3 (2026-05-21): if the exit's round-robin entry is
    /// unreachable from Tor (circuit not built, pinning miss, etc.), the
    /// bundle used to fail silently on that exit. Now every OTHER entry in the
    /// registry is tried before giving up, and a total failure is logged at
    /// error level (visible in the operator's redacted log stream).
    private func publishWithEntryFallback(_ ex: ExitDescriptorV2) async -> ExitIdV2? {
        let exitTag = (try? ex.exitId().description.prefix(16)) ?? "?"
        let allEntryUrls = await registry.entries.map { $0.url }
        var attempted: [URL] = [ex.entryUrl]
        var lastError: Error?
        do {
            return try await publishBundle(on: ex)
        } catch {
            lastError = error
            SecureLogger.torDiag("[V2] publishBundle PRIMARY FAILED exit=\(exitTag) entry=\(ex.entryUrl.host ?? "?"): \(error)")
        }
        for altEntry in allEntryUrls where !attempted.contains(altEntry) {
            attempted.append(altEntry)
            let altExit = ExitDescriptorV2(
                exitIdHex: ex.exitIdHex,
                entryUrl: altEntry,
                exitUrl: ex.exitUrl,
                hkemPkHex: ex.hkemPkHex,
                region: ex.region
            )
            do {
                let id = try await publishBundle(on: altExit)
                SecureLogger.torDiag("[V2] publishBundle RECOVERED exit=\(exitTag) via alt-entry=\(altEntry.host ?? "?")")
                return id
            } catch {
                lastError = error
                SecureLogger.torDiag("[V2] publishBundle ALT FAILED exit=\(exitTag) entry=\(altEntry.host ?? "?"): \(error)")
            }
        }
        SecureLogger.error("[V2] publishBundle TOTAL FAILURE exit=\(exitTag) after \(attempted.count) entry-attempts: \(lastError.map { String(describing: $0) } ?? "nil")")
        return nil
    }

    /// Publish the local user's bundle on **every** exit known to the registry
    /// (each exit gets its own bundle: the verifier is exit-bound). Used after
    /// a rotation of the delivery key and when the push relay reports us
    /// unknown. The DIR_PUTs go out in consecutive lane-F ticks.
    @discardableResult
    func publishBundleOnAllExits() async -> [ExitIdV2] {
        if let running = allExitsPublish { return await running.value }
        let task = Task { await self.publishOnAllExitsNow() }
        allExitsPublish = task
        defer { allExitsPublish = nil }
        return await task.value
    }

    private func publishOnAllExitsNow() async -> [ExitIdV2] {
        let allExits = await registry.exits
        let ok: [ExitIdV2] = await withTaskGroup(of: ExitIdV2?.self) { group in
            for ex in allExits {
                group.addTask { [self] in await publishWithEntryFallback(ex) }
            }
            var collected: [ExitIdV2] = []
            for await result in group {
                if let id = result { collected.append(id) }
            }
            return collected
        }
        if ok.count < allExits.count {
            SecureLogger.error("[V2] publishBundleOnAllExits: only \(ok.count)/\(allExits.count) exits reached after alt-entry retries")
        }
        return ok
    }

    // MARK: - Push registration (A2 §4.4)

    /// Register the APNs token as a PUSH_REGISTER sealed to the push relay,
    /// in lane F. Neither the entry nor an exit sees the token.
    func registerPushToken(apnsToken: Data, sandbox: Bool) async throws {
        guard let push = await registry.pushTarget,
              let pushPk = try? push.hkemPublicKey(),
              let pushId = try? push.targetId() else {
            throw PushRegistrationClientV2Error.entryHasNoPushRelay
        }
        guard let entryUrl = await registry.fastestExit()?.entryUrl else {
            throw RelayClientV2Error.noExitsConfigured
        }
        let identity = self.identity
        let response: OpenedSealedResponseV2
        do {
            // Built at the tick: the signed timestamp must be within ±120 s.
            response = try await lanes.fetchLaneExchange(kind: .pushRegister, build: {
                let body = try PushRegistrationClientV2.buildBody(
                    rid: identity.recipientId, apnsToken: apnsToken, sandbox: sandbox,
                    timestamp: ClockSyncV2.shared.nowSec(), hsigKp: identity.senderHsigKp)
                var sealedBody = Data(capacity: LadonV2.recipientIdLen + body.count)
                sealedBody.append(identity.recipientId.bytes)
                sealedBody.append(body)
                return (try SealedCodecV2.seal(targetHkemPk: pushPk, targetId: pushId,
                                               kind: .pushRegister, body: sealedBody), entryUrl)
            })
        } catch let e as PushRegistrationClientV2Error {
            throw e
        } catch SealedTransportV2Error.http(let s) {
            throw PushRegistrationClientV2Error.entryHttp(status: s)
        } catch {
            throw PushRegistrationClientV2Error.transport(error)
        }
        switch response.status {
        case SealedStatusV2.ok: return
        case SealedStatusV2.unknownRecipient: throw PushRegistrationClientV2Error.unknownRecipient
        case SealedStatusV2.signature: throw PushRegistrationClientV2Error.pushRelayRejected(status: 401)
        case SealedStatusV2.unavailable: throw PushRegistrationClientV2Error.pushRelayRejected(status: 503)
        default: throw PushRegistrationClientV2Error.pushRelayRejected(status: 400)
        }
    }
}

/// One successful fetch: which exit, and which batch to acknowledge next time.
/// Committed to `FetchAckLedgerV2` only after the batch's messages are stored.
struct FetchReceiptV2: Sendable {
    let exitHex: String
    let batchId: Data?
}

// MARK: - Pending-send hold (issue #38)

/// RAM-only hold of sealed frames whose delivery is unconfirmed.
///
/// A relay restart discards its mailbox — it is memory-only by design (Spec G1:
/// "V2 relays keep no on-disk state for sealed-sender material"). Anything not
/// yet fetched is gone, and nothing notices: there are no delivery receipts in
/// the V2 path, so an outgoing message sits on `.sent` whether it arrived or
/// not.
///
/// This is the sender's counterpart, and it deliberately mirrors the relay's
/// own discipline: **RAM only, never written anywhere.** Quit the app and the
/// held frames are gone, exactly like the relay's mailbox on restart. Nothing
/// is persisted, so a seized device yields nothing it would not already yield —
/// the plaintext of every message is in the encrypted store regardless.
///
/// Why hold the sealed frame rather than re-seal on retry: a repeat must
/// re-submit the IDENTICAL frame. Re-sealing advances the sending chain and the
/// recipient would see two distinct messages — the tradeoff documented at the
/// 5xx retry path above. Re-sending the same frame instead relies on the
/// recipient's own duplicate rejection (`replayOrTooOld` in
/// `advanceChainAndOpen`), so no dedup state is required anywhere. Only the
/// transport token is fresh on a repeat, so the exit's replay protection stays
/// armed.
actor PendingSendCache {

    private struct Entry {
        var frame: Data
        let recipientId: RecipientIdV2
        let recipientHsigPk: Data
        let heldAt: Date
        var attempts: Int
    }

    /// Bounded so a long offline stretch cannot grow the heap without limit.
    /// 32 × ~5 KiB inner frame ≈ 160 KiB worst case.
    static let maxEntries = 32

    /// How long a held frame stays useful. Deliberately short, and NOT derived
    /// from the relay's 7-day mailbox TTL: the recipient keeps only the last
    /// `maxArchivedRecvChains` (2) receiving chains and at most
    /// `maxSkippedKeys` (64) banked keys. Past that the frame can no longer be
    /// opened, so holding it longer would only re-send something undecryptable.
    static let maxAgeSeconds: TimeInterval = 2 * 60 * 60

    private var entries: [String: Entry] = [:]

    /// Hold a sealed frame under `messageID`, replacing (and wiping) any
    /// previous hold for the same id.
    func hold(messageID: String, frame: Data, recipientId: RecipientIdV2, recipientHsigPk: Data) {
        purgeExpired()
        if var existing = entries.removeValue(forKey: messageID) {
            existing.frame.securelyWipe()
        }
        if entries.count >= Self.maxEntries,
           let oldestKey = entries.min(by: { $0.value.heldAt < $1.value.heldAt })?.key {
            // Drop the oldest: a fresher frame is likelier to still be openable
            // by the recipient than one near the age bound.
            release(messageID: oldestKey)
        }
        entries[messageID] = Entry(
            frame: frame,
            recipientId: recipientId,
            recipientHsigPk: recipientHsigPk,
            heldAt: Date(),
            attempts: 0
        )
    }

    /// Release a hold and wipe the frame.
    func release(messageID: String) {
        guard var entry = entries.removeValue(forKey: messageID) else { return }
        entry.frame.securelyWipe()
    }

    /// Drop everything past `maxAgeSeconds`.
    func purgeExpired(now: Date = Date()) {
        let cutoff = now.addingTimeInterval(-Self.maxAgeSeconds)
        for (id, entry) in entries where entry.heldAt < cutoff {
            var expired = entry
            expired.frame.securelyWipe()
            entries.removeValue(forKey: id)
        }
    }

    /// Wipe every hold — device lock and panic, so held frames get the same
    /// treatment as the decrypted attachment cache.
    func wipeAll() {
        for id in Array(entries.keys) {
            release(messageID: id)
        }
        entries.removeAll()
    }

    /// Number of currently held frames. Diagnostics only; carries no
    /// identifying information.
    var heldCount: Int { entries.count }
}

/// Owns NotificationCenter observer tokens and removes them when it is
/// released. `V2SessionManager` builds a fresh `RelayClientV2` on every Tor
/// change, so observers registered in `init` must not outlive their client.
final class NotificationObserverBox: @unchecked Sendable {
    var tokens: [NSObjectProtocol] = []

    deinit {
        for token in tokens {
            NotificationCenter.default.removeObserver(token)
        }
    }
}
