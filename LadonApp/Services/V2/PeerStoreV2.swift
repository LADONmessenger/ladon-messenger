//
//  PeerStoreV2.swift
//  Ladon — Keychain-backed store for V2 peer contact handles.
//
//  Maps contactId (String) → PeerHandleV2.
//  Used by Phase 3 (send path) to resolve a contact's V2 identity before
//  calling RelayClientV2.sendMessage(to:messageBody:).
//
//  Wire format per Keychain item (fixed-length, no framing needed):
//    [ recipientId (32 B) ][ recipientHsigPk (1,984 B) ] = 2,016 B total
//
//  Keychain coordinates:
//    kSecClass   = kSecClassGenericPassword
//    service     = "app.ladon.messenger.v2.peers"
//    account     = <contactId>
//    accessible  = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
//    synchronizable = false
//

import Foundation
import Security

// MARK: - Error

enum PeerStoreV2Error: Error, CustomStringConvertible {
    case keychain(OSStatus)
    case malformedBlob(String)
    case invalidHsigPkLength(Int)

    var description: String {
        switch self {
        case .keychain(let s):         return "peerV2: keychain OSStatus=\(s)"
        case .malformedBlob(let m):    return "peerV2: malformed blob — \(m)"
        case .invalidHsigPkLength(let n):
            return "peerV2: hsigPk must be \(LadonV2.hsigPkLen) B, got \(n)"
        }
    }
}

// MARK: - Store

/// Static accessor for Keychain-persisted V2 peer handles.
enum PeerStoreV2 {

    private static let kcService = "app.ladon.messenger.v2.peers"

    /// Fixed blob length: 32 B (recipientId) + 1,984 B (hsigPk) = 2,016 B.
    private static let blobLen = LadonV2.recipientIdLen + LadonV2.hsigPkLen

    // MARK: Public API

    /// Persist a V2 peer handle for the given contact id.
    /// Overwrites any existing entry for that contact atomically.
    static func store(peer: PeerHandleV2, forContactId contactId: String) throws {
        guard peer.recipientHsigPk.count == LadonV2.hsigPkLen else {
            throw PeerStoreV2Error.invalidHsigPkLength(peer.recipientHsigPk.count)
        }

        var blob = Data(capacity: blobLen)
        blob.append(peer.recipientId.bytes)
        blob.append(peer.recipientHsigPk)
        precondition(blob.count == blobLen, "PeerStoreV2 blob size invariant violated")

        try storeAtomically(blob, account: contactId)
    }

    /// Load the V2 peer handle for the given contact id.
    /// Returns nil if no entry exists for that contact.
    static func load(forContactId contactId: String) throws -> PeerHandleV2? {
        // P8-AUDIT8-IOS-33 (audit F2): the value is sealed with the Secure Enclave.
        guard let data = try SealedKeychainV2.read(service: kcService, account: contactId) else {
            return nil
        }
        guard data.count == blobLen else {
            throw PeerStoreV2Error.malformedBlob("expected \(blobLen) B, got \(data.count)")
        }
        let recipientId = RecipientIdV2(bytes: Data(data.prefix(LadonV2.recipientIdLen)))
        let hsigPk      = Data(data.dropFirst(LadonV2.recipientIdLen))
        return PeerHandleV2(recipientId: recipientId, recipientHsigPk: hsigPk)
    }

    /// Delete the V2 peer handle for the given contact id.
    /// No-op (no error) if no entry exists.
    static func delete(forContactId contactId: String) throws {
        let query: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: kcService,
            kSecAttrAccount as String: contactId,
        ]
        let status = SecItemDelete(query as CFDictionary)
        if status != errSecSuccess && status != errSecItemNotFound {
            throw PeerStoreV2Error.keychain(status)
        }
    }

    /// Contact ids (recipient id hex) of every stored V2 peer handle.
    static func allContactIds() throws -> [String] {
        let query: [String: Any] = [
            kSecClass as String:            kSecClassGenericPassword,
            kSecAttrService as String:      kcService,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String:       kSecMatchLimitAll,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            let items = result as? [[String: Any]] ?? []
            return items.compactMap { $0[kSecAttrAccount as String] as? String }
        case errSecItemNotFound:
            return []
        default:
            throw PeerStoreV2Error.keychain(status)
        }
    }

    /// Returns true if a V2 peer handle is stored for the given contact id.
    static func exists(forContactId contactId: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String:              kSecClassGenericPassword,
            kSecAttrService as String:        kcService,
            kSecAttrAccount as String:        contactId,
            kSecReturnData as String:         false,
            kSecMatchLimit as String:         kSecMatchLimitOne,
        ]
        return SecItemCopyMatching(query as CFDictionary, nil) == errSecSuccess
    }

    // MARK: Internal

    /// Update-first / Add-on-NotFound upsert. P7-IOS-CRYPTO-08: previously
    /// Delete-then-Add had a brief TOCTOU window during which a concurrent
    /// `load()` saw the item missing — a parallel caller could then create
    /// a SECOND fresh entry, racing the store. Update-first is atomic at
    /// the Keychain layer and never leaves a gap.
    private static func storeAtomically(_ data: Data, account: String) throws {
        try SealedKeychainV2.write(data, service: kcService, account: account)
    }
}
