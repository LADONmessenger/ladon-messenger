//
//  PrekeyStoreV2.swift
//  Ladon — one-time prekeys (OTPK) for the V2 session bootstrap.
//
//  An OTPK is a hybrid key (X25519 + ML-KEM-768) that the owner hands out only
//  inside a pairing code (QR / invite link / in-band refill) — never through a
//  relay. The first message of a new session is built against it, and the
//  owner deletes the private half the moment that message has been
//  authenticated, so the same code can never open a second session.
//
//  Two kinds of Keychain items, one service:
//    own.<hex id>   our own OTPK, private + public halves, issue number, expiry
//                   [ver 1][id 16][seq u64 BE][expiresAt u64 BE][xSk 32][xPk 32][kySk 2,400][kyPk 1,184] = 3,681 B
//    peer.<rid>     the unused OTPK public half a contact gave us
//                   [ver 1][id 16][seq u64 BE][xPk 32][kyPk 1,184] = 1,241 B
//    meta.seq       last issue number handed out (u64 BE)
//
//  Issue numbers order a device's prekeys: a session restart is valid only
//  against a NEWER code, and both sides apply that rule (the initiator from the
//  number carried in the code, the responder from its own record), so they
//  always agree which attempt wins. Numbers come from the persisted counter;
//  the current time in milliseconds is a floor, so losing the counter item
//  alone cannot make a later code look older.
//
//  Expiry uses the DEVICE clock on purpose: it is a local property ("valid for
//  10 minutes after I showed it"), measured at issue and at use by the same
//  clock. The relay-anchored ClockSyncV2 offset is set by relay responses —
//  the relay is adversary #1 and must not be able to stretch a key's life.
//
//  Keychain coordinates:
//    kSecClass      = kSecClassGenericPassword
//    service        = "app.ladon.messenger.v2.prekeys"
//    accessible     = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
//    synchronizable = false
//

import Foundation
import CryptoKit
import Security

/// Public half of a one-time prekey, as carried in a pairing code.
struct OneTimePrekeyPublicV2: Equatable {
    let id: Data      // 16 B, random
    let seq: UInt64   // issue number (see header)
    let xPk: Data     // 32 B, X25519
    let kyPk: Data    // 1,184 B, ML-KEM-768
}

/// Our own one-time prekey, both halves. Only the ratchet bootstrap reads it.
struct OwnOneTimePrekeyV2 {
    let id: Data
    let seq: UInt64         // issue number, strictly increasing per device
    let expiresAt: UInt64   // unix seconds, local clock
    var xSk: Data
    let xPk: Data
    var kySk: Data
    let kyPk: Data

    var publicHalf: OneTimePrekeyPublicV2 { OneTimePrekeyPublicV2(id: id, seq: seq, xPk: xPk, kyPk: kyPk) }

    /// Overwrite both private halves (each lives in storage of its own:
    /// decodeOwn copies them out of the blob).
    mutating func wipeSecrets() {
        wipeSecretInPlace(&xSk)
        wipeSecretInPlace(&kySk)
    }
}

enum PrekeyStoreV2Error: Error, CustomStringConvertible {
    case keychain(OSStatus)
    case malformed(String)
    case crypto(String)

    var description: String {
        switch self {
        case .keychain(let s): return "prekeyV2: keychain OSStatus=\(s)"
        case .malformed(let m): return "prekeyV2: malformed — \(m)"
        case .crypto(let m): return "prekeyV2: crypto — \(m)"
        }
    }
}

enum PrekeyStoreV2 {

    static let idLen = 16
    static let kcService = "app.ladon.messenger.v2.prekeys"

    /// Lifetimes and cap decided by the maintainer (29.09.2026).
    /// A code shown in person: 10 minutes. An invite link sent remotely: 24 h.
    static let inPersonLifetime: TimeInterval = 10 * 60
    static let inviteLifetime: TimeInterval = 24 * 60 * 60
    /// At most this many unused own prekeys at once; issuing one more deletes
    /// the oldest (lowest issue number).
    static let maxOwn = 10

    private static let blobVersion: UInt8 = 0x01
    private static let kySkLen: Int = PostQuantumService.Constants.kyberSecretKeySize
    private static let ownBlobLen: Int = 1 + idLen + 8 + 8 + LadonV2.x25519PkLen * 2 + kySkLen + LadonV2.kyber768PkLen
    private static let seqAccount = "meta.seq"
    private static let peerBlobLen: Int = 1 + idLen + 8 + LadonV2.x25519PkLen + LadonV2.kyber768PkLen

    // MARK: Own prekeys

    /// Create, persist and return a fresh one-time prekey that is valid until
    /// `expiresAt`. Expired own prekeys are purged first; if `maxOwn` unused
    /// ones remain, the oldest are deleted to make room.
    static func generateOwn(expiresAt: Date) throws -> OneTimePrekeyPublicV2 {
        backendLock.lock(); defer { backendLock.unlock() }
        try purgeExpiredOwn(now: Date())
        var own = try ownRecords()
        own.sort { $0.seq < $1.seq }
        let highestOwn = own.last?.seq ?? 0
        while own.count >= maxOwn {
            try deleteOwn(id: own.removeFirst().id)
        }
        let seq = try nextSeq(floor: highestOwn)
        let id = randomBytes(idLen)
        let x = Curve25519.KeyAgreement.PrivateKey()
        var kp: PostQuantumService.KyberKeypair
        do { kp = try PostQuantumService.shared.generateKyberKeypair() }
        catch { throw PrekeyStoreV2Error.crypto("kyber keygen: \(error)") }
        defer { kp.secretKey.securelyWipe() }
        guard kp.publicKey.count == LadonV2.kyber768PkLen, kp.secretKey.count == kySkLen else {
            throw PrekeyStoreV2Error.crypto("kyber keygen: unexpected key length")
        }
        let expiry = UInt64(max(0, expiresAt.timeIntervalSince1970.rounded(.down)))
        var xSk = x.rawRepresentation
        defer { wipeSecretInPlace(&xSk) }
        var blob = Data(capacity: ownBlobLen)
        blob.append(blobVersion)
        blob.append(id)
        blob.append(u64BE(seq))
        blob.append(u64BE(expiry))
        blob.append(xSk)
        blob.append(x.publicKey.rawRepresentation)
        blob.append(kp.secretKey)
        blob.append(kp.publicKey)
        defer { blob.securelyWipe() }
        guard blob.count == ownBlobLen else { throw PrekeyStoreV2Error.malformed("own blob length \(blob.count)") }
        try backendSave(blob, account: ownAccount(id))
        return OneTimePrekeyPublicV2(id: id, seq: seq, xPk: x.publicKey.rawRepresentation, kyPk: kp.publicKey)
    }

    /// Our own prekey for `id` if it exists and has not expired at `now`.
    /// An expired one is deleted and reported as unavailable.
    static func loadOwnValid(id: Data, now: Date) throws -> OwnOneTimePrekeyV2? {
        guard id.count == idLen, var blob = try backendLoad(account: ownAccount(id)) else { return nil }
        defer { blob.securelyWipe() }        // holds both private halves
        var prekey = try decodeOwn(blob)
        guard prekey.id == id else {
            prekey.wipeSecrets()
            throw PrekeyStoreV2Error.malformed("own prekey id mismatch")
        }
        guard UInt64(max(0, now.timeIntervalSince1970)) < prekey.expiresAt else {
            prekey.wipeSecrets()
            try deleteOwn(id: id)
            return nil
        }
        return prekey                        // the caller wipes it after use
    }

    /// Delete our own prekey. Succeeds only if the item was actually removed —
    /// the bootstrap relies on this to make a prekey unusable a second time.
    static func consumeOwn(id: Data) throws {
        let status = backendDelete(account: ownAccount(id))
        guard status == errSecSuccess else { throw PrekeyStoreV2Error.keychain(status) }
    }

    /// Delete our expired own prekeys now (takes the store lock).
    ///
    /// P8-AUDIT8-IOS-12 (audit F40): expired own prekeys were deleted only
    /// when the next code was generated (or when used), so the private halves
    /// (X25519 + ML-KEM) of a code that had run out stayed in the Keychain
    /// indefinitely — a later device extraction could still open withheld
    /// first-chain frames the design promises to be undecryptable after
    /// expiry. Called at V2 start and on every return to the foreground.
    static func purgeExpiredOwnNow() {
        backendLock.lock(); defer { backendLock.unlock() }
        do { try purgeExpiredOwn(now: Date()) }
        catch { SecureLogger.error("[V2] purging expired own prekeys failed: \(error)") }
    }

    /// Delete every own prekey whose expiry has passed at `now`.
    static func purgeExpiredOwn(now: Date) throws {
        let nowSec = UInt64(max(0, now.timeIntervalSince1970))
        for account in try backendAccounts() where account.hasPrefix("own.") {
            guard var blob = try backendLoad(account: account) else { continue }
            defer { blob.securelyWipe() }
            // An undecodable own item can never serve a bootstrap — remove it.
            guard let meta = decodeOwnMeta(blob) else { try deleteAccount(account); continue }
            if nowSec >= meta.expiresAt { try deleteAccount(account) }
        }
    }

    /// Number of own prekeys currently stored (expired ones included until purged).
    static func ownCount() throws -> Int {
        try backendAccounts().filter { $0.hasPrefix("own.") }.count
    }

    /// Id and issue number of every decodable own prekey (for the cap) — the
    /// private halves are never decoded here. Undecodable items are removed.
    private static func ownRecords() throws -> [(id: Data, seq: UInt64)] {
        var out: [(id: Data, seq: UInt64)] = []
        for account in try backendAccounts() where account.hasPrefix("own.") {
            guard var blob = try backendLoad(account: account) else { continue }
            defer { blob.securelyWipe() }
            if let meta = decodeOwnMeta(blob) { out.append((meta.id, meta.seq)) } else { try deleteAccount(account) }
        }
        return out
    }

    /// The non-secret head of an own blob: id, issue number, expiry.
    private static func decodeOwnMeta(_ blob: Data) -> (id: Data, seq: UInt64, expiresAt: UInt64)? {
        guard blob.count == ownBlobLen, blob[blob.startIndex] == blobVersion else { return nil }
        return (subdata(blob, 1, idLen), readU64BE(blob, at: 1 + idLen), readU64BE(blob, at: 1 + idLen + 8))
    }

    /// Next issue number: above the persisted counter, above every own prekey
    /// still stored, and at least the current time in ms. Caller holds backendLock.
    private static func nextSeq(floor highestOwn: UInt64) throws -> UInt64 {
        var last: UInt64 = 0
        if let blob = try backendLoad(account: seqAccount) {
            guard blob.count == 8 else { throw PrekeyStoreV2Error.malformed("seq blob") }
            last = readU64BE(blob, at: 0)
        }
        let base = max(last, highestOwn)
        guard base < UInt64.max else { throw PrekeyStoreV2Error.malformed("seq exhausted") }
        let nowMs = UInt64(max(0, (Date().timeIntervalSince1970 * 1000).rounded(.down)))
        let next = max(base + 1, nowMs)
        try backendSave(u64BE(next), account: seqAccount)
        return next
    }

    private static func deleteOwn(id: Data) throws { try deleteAccount(ownAccount(id)) }

    private static func decodeOwn(_ blob: Data) throws -> OwnOneTimePrekeyV2 {
        guard blob.count == ownBlobLen, blob[blob.startIndex] == blobVersion else {
            throw PrekeyStoreV2Error.malformed("own blob")
        }
        var o = 1
        let id = subdata(blob, o, idLen); o += idLen
        let seq = readU64BE(blob, at: o); o += 8
        let expiresAt = readU64BE(blob, at: o); o += 8
        let xSk = subdata(blob, o, LadonV2.x25519PkLen); o += LadonV2.x25519PkLen
        let xPk = subdata(blob, o, LadonV2.x25519PkLen); o += LadonV2.x25519PkLen
        let kySk = subdata(blob, o, kySkLen); o += kySkLen
        let kyPk = subdata(blob, o, LadonV2.kyber768PkLen); o += LadonV2.kyber768PkLen
        precondition(o == ownBlobLen)
        return OwnOneTimePrekeyV2(id: id, seq: seq, expiresAt: expiresAt, xSk: xSk, xPk: xPk, kySk: kySk, kyPk: kyPk)
    }

    // MARK: Peer prekeys

    /// Remember the unused prekey a contact handed us. An older code (lower
    /// issue number) never replaces a newer one on file; returns whether the
    /// given prekey is now the one on file.
    @discardableResult
    static func storePeer(_ prekey: OneTimePrekeyPublicV2, forPeer peerId: String) throws -> Bool {
        backendLock.lock(); defer { backendLock.unlock() }
        guard prekey.id.count == idLen, prekey.id != Data(count: idLen),
              prekey.xPk.count == LadonV2.x25519PkLen,
              prekey.kyPk.count == LadonV2.kyber768PkLen else {
            throw PrekeyStoreV2Error.malformed("peer prekey field length")
        }
        if let current = try loadPeer(forPeer: peerId), current.id != prekey.id, current.seq >= prekey.seq {
            return false
        }
        var blob = Data(capacity: peerBlobLen)
        blob.append(blobVersion)
        blob.append(prekey.id)
        blob.append(u64BE(prekey.seq))
        blob.append(prekey.xPk)
        blob.append(prekey.kyPk)
        try backendSave(blob, account: peerAccount(peerId))
        return true
    }

    static func loadPeer(forPeer peerId: String) throws -> OneTimePrekeyPublicV2? {
        guard let blob = try backendLoad(account: peerAccount(peerId)) else { return nil }
        guard blob.count == peerBlobLen, blob[blob.startIndex] == blobVersion else {
            throw PrekeyStoreV2Error.malformed("peer blob")
        }
        var o = 1
        let id = subdata(blob, o, idLen); o += idLen
        let seq = readU64BE(blob, at: o); o += 8
        let xPk = subdata(blob, o, LadonV2.x25519PkLen); o += LadonV2.x25519PkLen
        let kyPk = subdata(blob, o, LadonV2.kyber768PkLen)
        return OneTimePrekeyPublicV2(id: id, seq: seq, xPk: xPk, kyPk: kyPk)
    }

    /// Forget whatever prekey of this contact is on file (session reset, chat deleted).
    static func forgetPeer(forPeer peerId: String) throws {
        backendLock.lock(); defer { backendLock.unlock() }
        try deleteAccount(peerAccount(peerId))
    }

    /// Forget a contact's prekey, but only if it is still the one with `id` —
    /// a fresher code scanned in the meantime must survive.
    static func deletePeer(forPeer peerId: String, ifId id: Data) throws {
        backendLock.lock(); defer { backendLock.unlock() }
        guard let current = try loadPeer(forPeer: peerId), current.id == id else { return }
        try deleteAccount(peerAccount(peerId))
    }

    // MARK: Accounts

    private static func ownAccount(_ id: Data) -> String { "own." + id.map { String(format: "%02x", $0) }.joined() }
    private static func peerAccount(_ peerId: String) -> String { "peer." + peerId }

    /// Delete that tolerates "already gone" but nothing else.
    private static func deleteAccount(_ account: String) throws {
        let status = backendDelete(account: account)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw PrekeyStoreV2Error.keychain(status) }
    }

    // MARK: Backend (Keychain; in-memory for DEBUG self-tests)

    private static let backendLock = NSRecursiveLock()
    private static var backend: PrekeyBlobBackend = KeychainPrekeyBackend(service: kcService)

    private static func backendLoad(account: String) throws -> Data? {
        backendLock.lock(); defer { backendLock.unlock() }
        return try backend.load(account: account)
    }
    private static func backendSave(_ blob: Data, account: String) throws {
        backendLock.lock(); defer { backendLock.unlock() }
        try backend.save(blob, account: account)
    }
    private static func backendDelete(account: String) -> OSStatus {
        backendLock.lock(); defer { backendLock.unlock() }
        return backend.delete(account: account)
    }
    private static func backendAccounts() throws -> [String] {
        backendLock.lock(); defer { backendLock.unlock() }
        return try backend.accounts()
    }

    #if DEBUG
    /// Exercises the REAL Keychain backend (save/update/load/list/delete) on a
    /// throwaway service, so the in-memory test backend cannot hide a Keychain
    /// query bug. Returns nil on success, else what failed.
    static func _keychainBackendSelfTest() -> String? {
        let kc = KeychainPrekeyBackend(service: kcService + ".selftest")
        defer { for a in (try? kc.accounts()) ?? [] { _ = kc.delete(account: a) } }
        do {
            let a = Data([1, 2, 3]), b = Data([4, 5, 6, 7])
            try kc.save(a, account: "own.x")
            try kc.save(b, account: "own.x")                 // update path
            try kc.save(a, account: "peer.y")
            guard try kc.load(account: "own.x") == b else { return "update/load mismatch" }
            guard Set(try kc.accounts()) == ["own.x", "peer.y"] else { return "listing mismatch" }
            guard kc.delete(account: "own.x") == errSecSuccess else { return "delete failed" }
            guard kc.delete(account: "own.x") == errSecItemNotFound else { return "second delete not NotFound" }
            guard try kc.load(account: "own.x") == nil else { return "deleted item still loads" }
            return nil
        } catch { return "\(error)" }
    }

    static func _installInMemoryBackendForTesting() {
        backendLock.lock(); defer { backendLock.unlock() }
        backend = InMemoryPrekeyBackend()
    }
    static func _restoreKeychainBackendForTesting() {
        backendLock.lock(); defer { backendLock.unlock() }
        backend = KeychainPrekeyBackend(service: kcService)
    }
    #endif
}

fileprivate protocol PrekeyBlobBackend {
    func load(account: String) throws -> Data?
    func save(_ blob: Data, account: String) throws
    func delete(account: String) -> OSStatus
    func accounts() throws -> [String]
}

fileprivate final class KeychainPrekeyBackend: PrekeyBlobBackend {
    let service: String
    init(service: String) { self.service = service }

    func load(account: String) throws -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecAttrSynchronizable as String: false,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            guard let data = result as? Data else { throw PrekeyStoreV2Error.malformed("item is not Data") }
            return data
        case errSecItemNotFound:
            return nil
        default:
            throw PrekeyStoreV2Error.keychain(status)
        }
    }

    func save(_ blob: Data, account: String) throws {
        let baseQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        let update: [String: Any] = [
            kSecValueData as String: blob,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecAttrSynchronizable as String: false,
        ]
        let updateStatus = SecItemUpdate(baseQuery as CFDictionary, update as CFDictionary)
        if updateStatus == errSecSuccess { return }
        if updateStatus != errSecItemNotFound { throw PrekeyStoreV2Error.keychain(updateStatus) }
        var add = baseQuery
        add[kSecValueData as String] = blob
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        add[kSecAttrSynchronizable as String] = false
        let addStatus = SecItemAdd(add as CFDictionary, nil)
        if addStatus != errSecSuccess { throw PrekeyStoreV2Error.keychain(addStatus) }
    }

    func delete(account: String) -> OSStatus {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: false,
        ]
        return SecItemDelete(query as CFDictionary)
    }

    func accounts() throws -> [String] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecAttrSynchronizable as String: false,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            guard let items = result as? [[String: Any]] else { throw PrekeyStoreV2Error.malformed("attribute list") }
            return items.compactMap { $0[kSecAttrAccount as String] as? String }
        case errSecItemNotFound:
            return []
        default:
            throw PrekeyStoreV2Error.keychain(status)
        }
    }
}

#if DEBUG
fileprivate final class InMemoryPrekeyBackend: PrekeyBlobBackend {
    private var blobs: [String: Data] = [:]
    func load(account: String) throws -> Data? { blobs[account] }
    func save(_ blob: Data, account: String) throws { blobs[account] = blob }
    func delete(account: String) -> OSStatus {
        blobs.removeValue(forKey: account) != nil ? errSecSuccess : errSecItemNotFound
    }
    func accounts() throws -> [String] { Array(blobs.keys) }
}
#endif
