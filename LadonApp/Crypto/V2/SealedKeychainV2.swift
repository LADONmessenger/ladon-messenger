//
//  SealedKeychainV2.swift
//  Ladon — Secure-Enclave sealing of the V2 Keychain secrets (audit F2).
//
//  The V2 secrets must stay readable after first unlock (a push wake on a
//  locked device signs the FETCH with the identity and opens envelopes with
//  it — IdentityStoreV2.storeAtomically). So the Keychain class stays
//  AfterFirstUnlockThisDeviceOnly, but the stored value is now ciphertext:
//
//    chip keys   one Secure-Enclave P-256 key-agreement key and one
//                Secure-Enclave ML-KEM-768 key (iOS 26+), created once,
//                default access control AfterFirstUnlockThisDeviceOnly with
//                no flags (no biometry — background use must work). Only the
//                device-bound `dataRepresentation` blobs are stored, under
//                `chipService`; the private keys never leave the chip.
//    per write   ephemeral P-256 ECDH with the chip key ‖ ML-KEM-768
//                encapsulation to the chip key
//                → HKDF-SHA256(info = domain ‖ service ‖ account ‖ eph ‖ ct)
//                → ChaChaPoly, AAD = magic ‖ service ‖ account.
//
//  Hybrid on purpose, like HKEM: the stored value stays sealed while either
//  half holds. A Keychain dump (forensic AFU extraction) yields only
//  ciphertext; opening needs the chip of this device. It does not stop code
//  running on the unlocked device, which can ask the chip itself.
//
//  Item value:  magic (4) ‖ ephemeral P-256 x9.63 (65) ‖ ML-KEM ct (1,088)
//               ‖ ChaChaPoly combined (12 nonce ‖ ciphertext ‖ 16 tag)
//
//  Fail-closed: no chip keys while sealed items exist → error, never a new
//  identity. Items written before this build are plaintext; they are sealed
//  in place on first contact and by a one-time sweep. After the sweep a
//  plaintext item is rejected.
//

import Foundation
import CryptoKit
import Security

enum SealedKeychainV2Error: Error, CustomStringConvertible {
    case chipUnavailable
    case chipKeyMissing
    case keychain(OSStatus)
    case malformed(String)
    case crypto(String)
    case plaintextAfterMigration(String)

    var description: String {
        switch self {
        case .chipUnavailable: return "sealedKeychain: Secure Enclave unavailable"
        case .chipKeyMissing: return "sealedKeychain: chip key missing while sealed items exist"
        case .keychain(let s): return "sealedKeychain: keychain OSStatus=\(s)"
        case .malformed(let m): return "sealedKeychain: malformed — \(m)"
        case .crypto(let m): return "sealedKeychain: crypto — \(m)"
        case .plaintextAfterMigration(let s): return "sealedKeychain: plaintext item in \(s) after migration"
        }
    }
}

enum SealedKeychainV2 {

    /// Holds the two chip-key blobs. Part of every wipe list (panic, dead
    /// man's switch, fresh install): deleting it alone makes every sealed
    /// item unreadable.
    static let chipService = "app.ladon.messenger.v2.chip"
    private static let chipAccount = "chip.v1"

    /// Every service whose values are sealed. The one-time sweep covers them.
    static let sealedServices = [
        "app.ladon.messenger.v2",           // identity (IdentityStoreV2)
        "app.ladon.messenger.v2.ratchet",   // ratchet sessions (RelayClientV2)
        "app.ladon.messenger.v2.prekeys",   // one-time prekeys (PrekeyStoreV2)
        "app.ladon.messenger.v2.delivery",  // delivery keys, block list (DeliveryKeyStoreV2)
        "app.ladon.messenger.v2.peers",     // contacts (PeerStoreV2)
    ]

    private static let migrationService = "app.ladon.messenger.migrations"
    private static let migrationAccount = "sealedKeychain.v1"

    private static let magic = Data([0x4C, 0x53, 0x4B, 0x01])   // "LSK" v1
    private static let domain = Data("L1-KeychainSeal-v1".utf8)
    private static let ephLen = 65
    private static let kemCtLen = 1_088
    private static let aeadOverhead = 12 + 16
    private static let headerLen = 4 + 65 + 1_088

    private struct ChipKeys {
        let agreement: SecureEnclave.P256.KeyAgreement.PrivateKey
        let kem: SecureEnclave.MLKEM768.PrivateKey
    }

    private static let lock = NSLock()
    /// Held for the whole sweep: a concurrent caller waits for it to finish
    /// instead of reading items while they are being sealed.
    private static let migrationLock = NSLock()
    /// Last sweep failure (service names only, no secrets) — for diagnosis.
    nonisolated(unsafe) private(set) static var lastMigrationError: String?
    nonisolated(unsafe) private static var cachedKeys: ChipKeys?
    nonisolated(unsafe) private static var migrated: Bool?
    nonisolated(unsafe) private static var migrationTried = false

    // MARK: - Public API

    /// The plaintext of `service`/`account`, or nil if there is no item.
    static func read(service: String, account: String) throws -> Data? {
        // A failed sweep must not block reads: until the flag is set,
        // plaintext items are still accepted (and sealed on contact).
        do { try migrateIfNeeded() } catch {
            SecureLogger.error("[SealedKeychainV2] migration not finished: \(error)")
        }
        guard var stored = try copyValue(service: service, account: account) else { return nil }
        defer { stored.securelyWipe() }
        if isSealed(stored) {
            return try open(stored, service: service, account: account)
        }
        // Plaintext from an earlier build.
        lock.lock(); let done = migrated == true; lock.unlock()
        if done { throw SealedKeychainV2Error.plaintextAfterMigration(service) }
        let plain = Data(stored)
        try write(plain, service: service, account: account)
        return plain
    }

    /// Seal `plaintext` and store it (update, or add if missing).
    static func write(_ plaintext: Data, service: String, account: String) throws {
        let sealed = try seal(plaintext, service: service, account: account)
        try upsertPlain(sealed, service: service, account: account)
    }

    /// Seal every plaintext item of `sealedServices` once. Idempotent; runs
    /// before the first read, at most once per launch. Leaves the flag unset
    /// on any failure, so the next launch retries and reads keep accepting
    /// plaintext until then.
    static func migrateIfNeeded() throws {
        migrationLock.lock(); defer { migrationLock.unlock() }
        lock.lock()
        if migrated == nil { migrated = (try? copyValue(service: migrationService, account: migrationAccount)) != nil }
        let skip = migrated == true || migrationTried
        migrationTried = true
        lock.unlock()
        if skip { return }

        do {
            try sweep()
        } catch {
            lastMigrationError = "\(error)"
            throw error
        }
    }

    private static func sweep() throws {
        var sealedNow = 0, alreadySealed = 0
        for service in sealedServices {
            for (account, value) in try allItems(service: service) {
                var v = value
                defer { v.securelyWipe() }
                if isSealed(v) { alreadySealed += 1; continue }
                let sealed = try seal(v, service: service, account: account)
                guard var check = try? open(sealed, service: service, account: account),
                      check.constantTimeEqual(v) else {
                    throw SealedKeychainV2Error.crypto("migration round trip failed in \(service)")
                }
                check.securelyWipe()
                try upsertPlain(sealed, service: service, account: account)
                sealedNow += 1
            }
        }
        try upsertPlain(Data([0x01]), service: migrationService, account: migrationAccount)
        lock.lock(); migrated = true; lock.unlock()
        // Counts only — no service, account or key material.
        SecureLogger.info("[SealedKeychainV2] migration done: sealed \(sealedNow), already sealed \(alreadySealed)")
    }

    // MARK: - Seal / open

    private static func isSealed(_ v: Data) -> Bool {
        v.count >= headerLen + aeadOverhead && v.prefix(4) == magic
    }

    private static func seal(_ plaintext: Data, service: String, account: String) throws -> Data {
        let keys = try chipKeys(create: true)
        let eph = P256.KeyAgreement.PrivateKey()
        let ephPub = eph.publicKey.x963Representation
        let ecdh: SharedSecret
        let kem: KEM.EncapsulationResult
        do {
            ecdh = try eph.sharedSecretFromKeyAgreement(with: keys.agreement.publicKey)
            kem = try keys.kem.publicKey.encapsulate()
        } catch {
            throw SealedKeychainV2Error.crypto("seal: \(error)")
        }
        guard ephPub.count == ephLen, kem.encapsulated.count == kemCtLen else {
            throw SealedKeychainV2Error.crypto("seal: unexpected key sizes")
        }
        let key = deriveKey(ecdh: ecdh, kem: kem.sharedSecret, service: service,
                            account: account, ephPub: ephPub, kemCt: kem.encapsulated)
        do {
            let box = try ChaChaPoly.seal(plaintext, using: key,
                                          authenticating: aad(service: service, account: account))
            return magic + ephPub + kem.encapsulated + box.combined
        } catch {
            throw SealedKeychainV2Error.crypto("seal: \(error)")
        }
    }

    private static func open(_ stored: Data, service: String, account: String) throws -> Data {
        guard isSealed(stored) else { throw SealedKeychainV2Error.malformed("not sealed") }
        let keys = try chipKeys(create: false)
        let base = stored.startIndex
        let ephPub = stored[(base + 4)..<(base + 4 + ephLen)]
        let kemCt = stored[(base + 4 + ephLen)..<(base + headerLen)]
        let combined = stored[(base + headerLen)...]
        do {
            let peer = try P256.KeyAgreement.PublicKey(x963Representation: ephPub)
            let ecdh = try keys.agreement.sharedSecretFromKeyAgreement(with: peer)
            let kemSecret = try keys.kem.decapsulate(kemCt)
            let key = deriveKey(ecdh: ecdh, kem: kemSecret, service: service,
                                account: account, ephPub: Data(ephPub), kemCt: Data(kemCt))
            let box = try ChaChaPoly.SealedBox(combined: combined)
            return try ChaChaPoly.open(box, using: key, authenticating: aad(service: service, account: account))
        } catch {
            throw SealedKeychainV2Error.crypto("open \(service): \(error)")
        }
    }

    private static func deriveKey(ecdh: SharedSecret, kem: SymmetricKey, service: String,
                                  account: String, ephPub: Data, kemCt: Data) -> SymmetricKey {
        var ikm = ecdh.withUnsafeBytes { Data($0) }
        kem.withUnsafeBytes { ikm.append(contentsOf: $0) }
        defer { ikm.securelyWipe() }
        var info = domain
        info.append(0x00); info.append(Data(service.utf8))
        info.append(0x00); info.append(Data(account.utf8))
        info.append(0x00); info.append(ephPub); info.append(kemCt)
        return HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: ikm),
                                      salt: Data(), info: info, outputByteCount: 32)
    }

    private static func aad(service: String, account: String) -> Data {
        var a = magic
        a.append(Data(service.utf8)); a.append(0x00); a.append(Data(account.utf8))
        return a
    }

    // MARK: - Chip keys

    private static func chipKeys(create: Bool) throws -> ChipKeys {
        lock.lock(); defer { lock.unlock() }
        if let k = cachedKeys { return k }
        guard SecureEnclave.isAvailable else { throw SealedKeychainV2Error.chipUnavailable }

        if var blob = try copyValue(service: chipService, account: chipAccount) {
            defer { blob.securelyWipe() }
            let keys = try decodeChipKeys(blob)
            cachedKeys = keys
            return keys
        }
        // No chip keys. Creating new ones is only safe when nothing sealed
        // exists — otherwise those items would be lost silently.
        guard create else { throw SealedKeychainV2Error.chipKeyMissing }
        for service in sealedServices {
            for (_, v) in try allItems(service: service) where isSealed(v) {
                throw SealedKeychainV2Error.chipKeyMissing
            }
        }
        let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, [], nil)
        guard let access else { throw SealedKeychainV2Error.crypto("access control") }
        let keys: ChipKeys
        do {
            keys = ChipKeys(
                agreement: try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access),
                kem: try SecureEnclave.MLKEM768.PrivateKey(accessControl: access))
        } catch {
            throw SealedKeychainV2Error.crypto("chip key create: \(error)")
        }
        try upsertPlain(encodeChipKeys(keys), service: chipService, account: chipAccount)
        cachedKeys = keys
        return keys
    }

    /// version (1) ‖ len (2) ‖ P-256 blob ‖ len (2) ‖ ML-KEM blob
    private static func encodeChipKeys(_ k: ChipKeys) -> Data {
        var d = Data([0x01])
        for part in [k.agreement.dataRepresentation, k.kem.dataRepresentation] {
            d.append(UInt8(part.count >> 8)); d.append(UInt8(part.count & 0xff)); d.append(part)
        }
        return d
    }

    private static func decodeChipKeys(_ d: Data) throws -> ChipKeys {
        var parts: [Data] = []
        var i = d.startIndex
        guard i < d.endIndex, d[i] == 0x01 else { throw SealedKeychainV2Error.malformed("chip key version") }
        i += 1
        for _ in 0..<2 {
            guard d.endIndex - i >= 2 else { throw SealedKeychainV2Error.malformed("chip key length") }
            let n = Int(d[i]) << 8 | Int(d[i + 1]); i += 2
            guard n > 0, d.endIndex - i >= n else { throw SealedKeychainV2Error.malformed("chip key blob") }
            parts.append(Data(d[i..<(i + n)])); i += n
        }
        guard i == d.endIndex else { throw SealedKeychainV2Error.malformed("chip key trailing bytes") }
        do {
            return ChipKeys(
                agreement: try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: parts[0]),
                kem: try SecureEnclave.MLKEM768.PrivateKey(dataRepresentation: parts[1]))
        } catch {
            throw SealedKeychainV2Error.crypto("chip key load: \(error)")
        }
    }

    // MARK: - Keychain primitives

    private static func copyValue(service: String, account: String) throws -> Data? {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecAttrSynchronizable as String: false,
        ]
        var out: AnyObject?
        let status = SecItemCopyMatching(q as CFDictionary, &out)
        switch status {
        case errSecSuccess:
            guard let d = out as? Data else { throw SealedKeychainV2Error.malformed("item is not Data") }
            return d
        case errSecItemNotFound:
            return nil
        default:
            throw SealedKeychainV2Error.keychain(status)
        }
    }

    private static func allItems(service: String) throws -> [(String, Data)] {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecReturnData as String: true,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecAttrSynchronizable as String: false,
        ]
        var out: AnyObject?
        let status = SecItemCopyMatching(q as CFDictionary, &out)
        switch status {
        case errSecSuccess:
            guard let rows = out as? [[String: Any]] else { throw SealedKeychainV2Error.malformed("item list") }
            return rows.compactMap { row in
                guard let a = row[kSecAttrAccount as String] as? String,
                      let v = row[kSecValueData as String] as? Data else { return nil }
                return (a, v)
            }
        case errSecItemNotFound:
            return []
        default:
            throw SealedKeychainV2Error.keychain(status)
        }
    }

    /// Update-first, add-if-missing — no window in which the item is absent.
    private static func upsertPlain(_ value: Data, service: String, account: String) throws {
        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        let update: [String: Any] = [
            kSecValueData as String: value,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecAttrSynchronizable as String: false,
        ]
        let u = SecItemUpdate(base as CFDictionary, update as CFDictionary)
        if u == errSecSuccess { return }
        guard u == errSecItemNotFound else { throw SealedKeychainV2Error.keychain(u) }
        var add = base
        add[kSecValueData as String] = value
        add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        add[kSecAttrSynchronizable as String] = false
        let a = SecItemAdd(add as CFDictionary, nil)
        if a == errSecSuccess { return }
        // A concurrent writer added the item between our update and add:
        // overwrite it with this value (last writer wins, as before).
        guard a == errSecDuplicateItem else { throw SealedKeychainV2Error.keychain(a) }
        let retry = SecItemUpdate(base as CFDictionary, update as CFDictionary)
        guard retry == errSecSuccess else { throw SealedKeychainV2Error.keychain(retry) }
    }
}

#if DEBUG
extension SealedKeychainV2 {
    /// Exercises the real Secure Enclave on a throwaway service: the stored
    /// value is ciphertext, it opens back to the plaintext, and a flipped
    /// byte or a different service/account is rejected. nil on success.
    /// Items checked in the five real stores by the last `_selfTest`.
    nonisolated(unsafe) static var lastStoreCheckCount = 0

    static func _selfTest() -> String? {
        let service = "app.ladon.messenger.v2.selftest"
        let account = "seal.\(UUID().uuidString)"
        defer {
            SecItemDelete([kSecClass as String: kSecClassGenericPassword,
                           kSecAttrService as String: service] as CFDictionary)
        }
        do {
            let plain = Data((0..<300).map { UInt8(truncatingIfNeeded: $0 &* 7) })
            try write(plain, service: service, account: account)
            guard let raw = try copyValue(service: service, account: account) else { return "item missing" }
            guard isSealed(raw), raw.range(of: plain) == nil else { return "stored value is not sealed" }
            guard let back = try read(service: service, account: account),
                  back.constantTimeEqual(plain) else { return "round trip mismatch" }
            var bad = raw
            bad[bad.index(before: bad.endIndex)] ^= 0x01
            if (try? open(bad, service: service, account: account)) != nil { return "tampered item opened" }
            if (try? open(raw, service: service, account: account + "x")) != nil { return "opened under another account" }
            if (try? open(raw, service: service + "x", account: account)) != nil { return "opened under another service" }
            // The real stores: after the sweep no plaintext item may remain.
            try migrateIfNeeded()
            var sealedCount = 0
            for s in sealedServices {
                for (_, v) in try allItems(service: s) {
                    guard isSealed(v) else {
                        return "plaintext item left in \(s); last migration error: \(lastMigrationError ?? "none")"
                    }
                    sealedCount += 1
                }
            }
            lastStoreCheckCount = sealedCount
            return nil
        } catch {
            return "\(error)"
        }
    }
}
#endif
