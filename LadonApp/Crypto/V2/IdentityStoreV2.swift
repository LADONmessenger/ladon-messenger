//
//  IdentityStoreV2.swift
//  Ladon — persistent storage of the local user's V2 hybrid identity
//          (HSig: Ed25519 + ML-DSA-65, HKEM: X25519 + ML-KEM-768).
//
//  Storage strategy:
//    • Single Keychain item (kSecClassGenericPassword)
//      service = "app.ladon.messenger.v2"
//      account = "identity.v1"
//      accessible = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
//      synchronizable = false
//    • The item value is a property-list-encoded `IdentityBlobV2` containing
//      all six raw key components (3 secrets, 3 publics).
//    • One atomic blob → no risk of partial state if a write is interrupted.
//
//  This file is INDEPENDENT of the legacy V1 identity stored by
//  `KeyManager.swift`. They share neither service name nor account, so a V1
//  wipe never affects V2 and vice versa.
//

import Foundation
import CryptoKit
import Security

enum IdentityStoreV2Error: Error, CustomStringConvertible {
    case keychain(OSStatus)
    case malformedBlob(String)
    case crypto(String)

    var description: String {
        switch self {
        case .keychain(let s): return "identityV2: keychain OSStatus=\(s)"
        case .malformedBlob(let m): return "identityV2: malformed blob — \(m)"
        case .crypto(let m): return "identityV2: crypto — \(m)"
        }
    }
}

/// Plist-encodable container holding all 6 raw key components.
private struct IdentityBlobV2: Codable {
    /// Format version of this blob (separate from protocol-level v2).
    let version: UInt8
    var edSk: Data        // 32 B
    var dilSk: Data       // ~4,032 B (ML-DSA-65 secret key)
    let dilPk: Data       // 1,952 B (ML-DSA-65 public key)
    var xSk: Data         // 32 B
    var kySk: Data        // ~2,400 B (ML-KEM-768 secret key)
    let kyPk: Data        // 1,184 B (ML-KEM-768 public key)
}

enum IdentityStoreV2 {

    private static let kcService = "app.ladon.messenger.v2"
    private static let kcAccount = "identity.v1"
    private static let blobVersion: UInt8 = 0x01

    // MARK: - Public API

    /// Load the persisted V2 identity, or generate+persist a new one if none
    /// exists. Idempotent: calling twice returns the same identity.
    static func loadOrGenerate() throws -> LocalIdentityV2 {
        if let id = try load() {
            return id
        }
        let id = try generateAndStore()
        return id
    }

    /// Returns the persisted identity if present; nil otherwise.
    /// Throws on corrupt blob, Keychain errors other than `errSecItemNotFound`.
    static func load() throws -> LocalIdentityV2? {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: kcService,
            kSecAttrAccount as String: kcAccount,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecAttrSynchronizable as String: false,
        ]
        var out: AnyObject?
        let status = SecItemCopyMatching(q as CFDictionary, &out)
        switch status {
        case errSecSuccess:
            guard var data = out as? Data else {
                throw IdentityStoreV2Error.malformedBlob("keychain returned non-Data")
            }
            out = nil
            // P8-AUDIT8-IOS-25: the serialized blob holds all four secret keys.
            defer { data.securelyWipe() }
            return try decode(data)
        case errSecItemNotFound:
            return nil
        default:
            throw IdentityStoreV2Error.keychain(status)
        }
    }

    /// Wipe the persisted identity. Use only on full app reset / factory wipe.
    static func wipe() throws {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: kcService,
            kSecAttrAccount as String: kcAccount,
        ]
        let status = SecItemDelete(q as CFDictionary)
        if status != errSecSuccess && status != errSecItemNotFound {
            throw IdentityStoreV2Error.keychain(status)
        }
    }

    /// True if a persisted identity already exists. Cheap probe.
    static func exists() -> Bool {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: kcService,
            kSecAttrAccount as String: kcAccount,
            kSecReturnData as String: false,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        return SecItemCopyMatching(q as CFDictionary, nil) == errSecSuccess
    }

    // MARK: - Internal: generate + persist

    private static func generateAndStore() throws -> LocalIdentityV2 {
        let hsig: HSigKeyPairV2
        let hkem: HKEMKeyPairV2
        do {
            hsig = try HSigKeyPairV2.generate()
        } catch {
            throw IdentityStoreV2Error.crypto("HSig generate: \(error)")
        }
        do {
            hkem = try HKEMKeyPairV2.generate()
        } catch {
            throw IdentityStoreV2Error.crypto("HKEM generate: \(error)")
        }

        let blob = IdentityBlobV2(
            version: blobVersion,
            edSk: hsig.edSk.rawRepresentation,
            dilSk: hsig.dilSk,
            dilPk: hsig.dilPk,
            xSk: hkem.xSk.rawRepresentation,
            kySk: hkem.kySk,
            kyPk: hkem.kyPk
        )
        let encoded: Data
        do {
            let enc = PropertyListEncoder()
            enc.outputFormat = .binary
            encoded = try enc.encode(blob)
        } catch {
            throw IdentityStoreV2Error.malformedBlob("encode: \(error)")
        }
        try storeAtomically(encoded)
        return LocalIdentityV2.make(senderHsigKp: hsig, recipientHkemKp: hkem)
    }

    /// Add or update the Keychain item. The Add-then-Update pattern keeps the
    /// access-control attributes consistent across reinstalls.
    ///
    /// Protection class (P8-AUDIT8-IOS-25, audit F2/F26 — the old comment here
    /// claimed a "FIX F-CRYPTO-001" that the code never contained):
    /// AfterFirstUnlockThisDeviceOnly, no access control, no Secure Enclave
    /// wrap. AFU is REQUIRED, not an oversight: a push wake on a locked device
    /// signs the FETCH with the HSig secret keys and opens envelopes with the
    /// HKEM secret keys (RelayClientV2 fetch/open), and no UI can be shown
    /// there. A "send-only" key under WhenUnlocked + userPresence does not
    /// help either — FETCH is signed with the same HSig key. Real hardening is
    /// Issue #11: a Secure-Enclave key (AFU, no biometry flag) wrapping this
    /// blob, or a separate fetch key, which changes bundle and exit checks.
    private static func storeAtomically(_ data: Data) throws {
        let baseQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: kcService,
            kSecAttrAccount as String: kcAccount,
        ]
        // Try update first.
        let updateAttrs: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecAttrSynchronizable as String: false,
        ]
        let updateStatus = SecItemUpdate(baseQuery as CFDictionary, updateAttrs as CFDictionary)
        if updateStatus == errSecSuccess { return }
        if updateStatus != errSecItemNotFound {
            throw IdentityStoreV2Error.keychain(updateStatus)
        }
        // Not found → add.
        var addQuery = baseQuery
        addQuery[kSecValueData as String] = data
        addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        addQuery[kSecAttrSynchronizable as String] = false
        let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
        if addStatus != errSecSuccess {
            throw IdentityStoreV2Error.keychain(addStatus)
        }
    }

    // MARK: - Internal: decode

    private static func decode(_ data: Data) throws -> LocalIdentityV2 {
        var blob: IdentityBlobV2
        do {
            blob = try PropertyListDecoder().decode(IdentityBlobV2.self, from: data)
        } catch {
            throw IdentityStoreV2Error.malformedBlob("decode: \(error)")
        }
        // P8-AUDIT8-IOS-25: the decoded secret fields are copies the key pairs
        // do not need once built — wipe them on every exit.
        defer {
            blob.edSk.securelyWipe()
            blob.dilSk.securelyWipe()
            blob.xSk.securelyWipe()
            blob.kySk.securelyWipe()
        }
        guard blob.version == blobVersion else {
            throw IdentityStoreV2Error.malformedBlob("unsupported blob version \(blob.version)")
        }
        let hsig: HSigKeyPairV2
        let hkem: HKEMKeyPairV2
        do {
            hsig = try HSigKeyPairV2(edSkRaw: blob.edSk, dilSk: blob.dilSk, dilPk: blob.dilPk)
        } catch {
            throw IdentityStoreV2Error.crypto("HSig reload: \(error)")
        }
        do {
            hkem = try HKEMKeyPairV2.fromRaw(xSkRaw: blob.xSk, kySk: blob.kySk, kyPk: blob.kyPk)
        } catch {
            throw IdentityStoreV2Error.crypto("HKEM reload: \(error)")
        }
        return LocalIdentityV2.make(senderHsigKp: hsig, recipientHkemKp: hkem)
    }
}
