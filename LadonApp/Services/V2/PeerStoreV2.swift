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
        let query: [String: Any] = [
            kSecClass as String:              kSecClassGenericPassword,
            kSecAttrService as String:        kcService,
            kSecAttrAccount as String:        contactId,
            kSecReturnData as String:         true,
            kSecMatchLimit as String:         kSecMatchLimitOne,
            kSecAttrSynchronizable as String: false,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        switch status {
        case errSecSuccess:
            guard let data = result as? Data, data.count == blobLen else {
                let got = (result as? Data)?.count ?? 0
                throw PeerStoreV2Error.malformedBlob("expected \(blobLen) B, got \(got)")
            }
            let recipientId = RecipientIdV2(bytes: Data(data.prefix(LadonV2.recipientIdLen)))
            let hsigPk      = Data(data.dropFirst(LadonV2.recipientIdLen))
            return PeerHandleV2(recipientId: recipientId, recipientHsigPk: hsigPk)

        case errSecItemNotFound:
            return nil

        default:
            throw PeerStoreV2Error.keychain(status)
        }
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
        let baseQuery: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: kcService,
            kSecAttrAccount as String: account,
        ]
        let updateAttrs: [String: Any] = [
            kSecValueData as String:      data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        let updateStatus = SecItemUpdate(baseQuery as CFDictionary, updateAttrs as CFDictionary)
        if updateStatus == errSecSuccess { return }
        if updateStatus != errSecItemNotFound {
            throw PeerStoreV2Error.keychain(updateStatus)
        }

        var addQuery = baseQuery
        addQuery[kSecValueData as String] = data
        addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        addQuery[kSecAttrSynchronizable as String] = false

        let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
        // Treat `errSecDuplicateItem` as success — a concurrent thread won
        // the race and inserted first; semantically both threads agree on
        // what should be present.
        guard addStatus == errSecSuccess || addStatus == errSecDuplicateItem else {
            throw PeerStoreV2Error.keychain(addStatus)
        }
    }
}
