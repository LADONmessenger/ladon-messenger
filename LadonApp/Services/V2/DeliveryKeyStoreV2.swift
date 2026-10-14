//
//  DeliveryKeyStoreV2.swift
//  Ladon — Keychain storage of delivery keys (Addendum A1 §2, §5, §6).
//
//  Two kinds of entries, one Keychain service:
//    • own   — this user's delivery key K. Handed only to contacts (pairing
//              code v4, START/KEY control messages); the exits only ever see
//              K_X inside sealed envelopes and V_X in the public bundle.
//    • peer  — each contact's K, keyed by the contact's recipient id (hex).
//              Without it nothing can be delivered to that contact.
//
//  Keychain coordinates:
//    kSecClass      = kSecClassGenericPassword
//    service        = "app.ladon.messenger.v2.delivery"
//    account        = "own" | "peer.<rid hex>"
//    accessible     = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
//    synchronizable = false
//
//  Separate from PeerStoreV2 on purpose: a contact's K arrives later than
//  its identity can (START after a one-way scan, KEY after a rotation), and
//  the peer-handle blob format stays untouched.
//

import Foundation
import Security

enum DeliveryKeyStoreV2Error: Error, CustomStringConvertible {
    case keychain(OSStatus)
    case malformedKey(Int)

    var description: String {
        switch self {
        case .keychain(let s):     return "deliveryKey: keychain OSStatus=\(s)"
        case .malformedKey(let n): return "deliveryKey: expected \(LadonV2.deliveryKeyLen) B, got \(n)"
        }
    }
}

enum DeliveryKeyStoreV2 {

    static let kcService = "app.ladon.messenger.v2.delivery"
    private static let ownAccount = "own"
    private static func peerAccount(_ rid: RecipientIdV2) -> String { "peer.\(rid.description)" }
    private static func peerPrevAccount(_ rid: RecipientIdV2) -> String { "peerprev.\(rid.description)" }

    /// Serialises load-or-generate, so two first callers cannot both mint a key.
    private static let ownLock = NSLock()

    // MARK: Own key

    /// The local delivery key, generated on first use (A1 §2.1: 32 bytes from
    /// the system CSPRNG; `randomBytes` aborts on a failing status — fail-closed,
    /// never a weaker source).
    static func ownKey() throws -> Data {
        ownLock.lock(); defer { ownLock.unlock() }
        if let k = try load(account: ownAccount) { return k }
        let k = randomBytes(LadonV2.deliveryKeyLen)
        try store(k, account: ownAccount)
        return k
    }

    /// Replace the local delivery key (rotation, A1 §7). Returns the new key.
    /// The caller publishes new bundles and sends KEY to the remaining contacts.
    static func rotateOwnKey() throws -> Data {
        ownLock.lock(); defer { ownLock.unlock() }
        let k = randomBytes(LadonV2.deliveryKeyLen)
        try store(k, account: ownAccount)
        return k
    }

    // MARK: Peer keys

    static func peerKey(_ rid: RecipientIdV2) throws -> Data? {
        try load(account: peerAccount(rid))
    }

    /// The contact's current key and, if it changed, the one before (A1 §7).
    /// A contact that rotates sends KEY to everyone first and publishes its
    /// new bundle after that; whoever already holds the new key keeps
    /// reaching it with the previous one until then. The sender uses the one
    /// whose verifier matches the published bundle — the exit decides anyway.
    static func peerKeys(_ rid: RecipientIdV2) throws -> [Data] {
        guard let current = try load(account: peerAccount(rid)) else { return [] }
        if let prev = try load(account: peerPrevAccount(rid)), prev != current { return [current, prev] }
        return [current]
    }

    /// Store (or replace) a contact's delivery key; a different key on file
    /// becomes the previous one.
    static func storePeerKey(_ key: Data, for rid: RecipientIdV2) throws {
        if let current = try load(account: peerAccount(rid)), current != key {
            try store(current, account: peerPrevAccount(rid))
        }
        try store(key, account: peerAccount(rid))
    }

    /// Remove a contact's delivery keys (current and previous). No error if
    /// there are none.
    static func deletePeerKey(_ rid: RecipientIdV2) throws {
        try delete(account: peerAccount(rid))
        try delete(account: peerPrevAccount(rid))
    }

    // MARK: Generic items (block list, rotation job)

    static func loadItem(account: String) throws -> Data? {
        try loadRaw(account: account)
    }

    static func storeItem(_ data: Data, account: String) throws {
        try storeRaw(data, account: account)
    }

    static func delete(account: String) throws {
        let q: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: kcService,
            kSecAttrAccount as String: account,
        ]
        let status = SecItemDelete(q as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw DeliveryKeyStoreV2Error.keychain(status)
        }
    }

    // MARK: Keychain

    /// A 32-byte key item.
    private static func load(account: String) throws -> Data? {
        guard let k = try loadRaw(account: account) else { return nil }
        guard k.count == LadonV2.deliveryKeyLen else { throw DeliveryKeyStoreV2Error.malformedKey(k.count) }
        return k
    }

    private static func store(_ key: Data, account: String) throws {
        guard key.count == LadonV2.deliveryKeyLen else {
            throw DeliveryKeyStoreV2Error.malformedKey(key.count)
        }
        try storeRaw(key, account: account)
    }

    // P8-AUDIT8-IOS-33 (audit F2): values are sealed with the Secure Enclave.
    private static func loadRaw(account: String) throws -> Data? {
        try SealedKeychainV2.read(service: kcService, account: account)
    }

    private static func storeRaw(_ key: Data, account: String) throws {
        try SealedKeychainV2.write(key, service: kcService, account: account)
    }
}

/// Keychain state of the token scheme that A1 replaced. Only the spent-token
/// list was ever written (`SpentTokenStoreV2`); it records when this device
/// sent, so it is removed rather than left behind. Idempotent and cheap —
/// run at every V2 start.
enum RetiredTokenStateV2 {
    static func remove() {
        let q: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: "app.ladon.messenger.v2.spenttokens",
        ]
        let status = SecItemDelete(q as CFDictionary)
        if status != errSecSuccess && status != errSecItemNotFound {
            SecureLogger.error("[V2] retired spent-token list not removed: OSStatus=\(status)")
        }
    }
}
