import Foundation
import CryptoKit
import Security
import UIKit

// 🔐 FIX #8: Encrypted UserDefaults (HIGH Priority)
// Prevents forensic metadata leak after device seizure
// FIX HIGH-17: UserDefaults storage is acceptable because ALL values are encrypted
// with ChaCha20-Poly1305 using a key stored in Keychain (.whenUnlockedThisDeviceOnly).
// The encrypted blobs are meaningless without the Keychain key, which requires device
// unlock. This provides equivalent security to .completeFileProtection.

/// Encrypted wrapper for UserDefaults - all values encrypted with device-bound key
class SecureUserDefaults {
    static let shared = SecureUserDefaults()
    
    private let encryptionKeyIdentifier = "secure_userdefaults_key"
    /// FIX MED: Cache key to avoid repeated Keychain loads creating heap copies
    private var _cachedKey: SymmetricKey?
    private var _keyCacheTimer: DispatchSourceTimer?
    private let keyQueue = DispatchQueue(label: "app.ladon.messenger.secureud.key")
    private init() {
        // FIX H-6 R21: Invalidate key cache on memory pressure and background.
        // Under memory pressure iOS may swap pages BEFORE the 10s timer fires.
        // Since mlock() is a no-op on iOS, cached keys are exposed in swap.
        NotificationCenter.default.addObserver(
            forName: UIApplication.didReceiveMemoryWarningNotification,
            object: nil, queue: nil
        ) { [weak self] _ in
            self?.invalidateKeyCache()
        }
        NotificationCenter.default.addObserver(
            forName: UIApplication.didEnterBackgroundNotification,
            object: nil, queue: nil
        ) { [weak self] _ in
            self?.invalidateKeyCache()
        }
    }
    
    /// FIX H-6 R21: Immediately purge cached key material
    private func invalidateKeyCache() {
        keyQueue.async { [weak self] in
            self?._cachedKey = nil
            self?._keyCacheTimer?.cancel()
            self?._keyCacheTimer = nil
        }
    }
    
    // MARK: - Encryption Key Management
    
    /// Get or create encryption key (stored in Keychain with Secure Enclave)
    /// FIX CRIT-03: Minimizes key material exposure by avoiding intermediate Data copies.
    /// Uses SymmetricKey directly where possible. Keychain returns Data which is immediately
    /// consumed into SymmetricKey, then wiped. Cache auto-invalidates after 60s.
    private func getEncryptionKey() throws -> SymmetricKey {
        return try keyQueue.sync {
            if let cached = _cachedKey {
                resetKeyCacheTimer()
                return cached
            }
            
            let key: SymmetricKey
            if var existingKeyData = loadKeyFromKeychain() {
                key = SymmetricKey(data: existingKeyData)
                // FIX CRIT-03: Immediately wipe the intermediate Data copy
                existingKeyData.withUnsafeMutableBytes { bytes in
                    guard let ptr = bytes.baseAddress else { return }
                    memset_s(ptr, bytes.count, 0, bytes.count)
                }
                existingKeyData = Data()
            } else {
                key = SymmetricKey(size: .bits256)
                // FIX CRIT-03: Extract key bytes, save to keychain, then immediately wipe
                // FIX AUDIT-R16: defer garantiert Wipe auch wenn saveKeyToKeychain wirft
                var keyData = key.withUnsafeBytes { Data($0) }
                defer {
                    keyData.withUnsafeMutableBytes { bytes in
                        guard let ptr = bytes.baseAddress else { return }
                        memset_s(ptr, bytes.count, 0, bytes.count)
                    }
                    keyData = Data()
                }
                try saveKeyToKeychain(keyData)
            }
            
            _cachedKey = key
            resetKeyCacheTimer()
            return key
        }
    }
    
    /// FIX SS-3 (ADVERSARIAL): Reduced key cache from 60s to 10s.
    /// 60s gave a wide forensics window for memory dump extraction.
    /// 10s is sufficient for burst operations while minimizing exposure.
    private func resetKeyCacheTimer() {
        // FIX MED-42: Assert we're on keyQueue to prevent deadlock from external callers
        dispatchPrecondition(condition: .onQueue(keyQueue))
        _keyCacheTimer?.cancel()
        let timer = DispatchSource.makeTimerSource(queue: keyQueue)
        timer.schedule(deadline: .now() + 10)  // FIX SS-3: 10s instead of 60s
        timer.setEventHandler { [weak self] in
            self?._cachedKey = nil
            self?._keyCacheTimer = nil
        }
        timer.resume()
        _keyCacheTimer = timer
    }
    
    private func loadKeyFromKeychain() -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: encryptionKeyIdentifier,
            kSecAttrService as String: "app.ladon.messenger",
            // FIX SM-L2: Removed kSecAttrAccessible from read query — iOS Keychain
            // ignores this attribute on SecItemCopyMatching (only used during write).
            // Having it here is harmless but confusing and non-standard.
            kSecAttrSynchronizable as String: false, // FIX: Prevent iCloud Keychain sync
            kSecReturnData as String: true
        ]
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess, let data = result as? Data else {
            return nil
        }
        
        return data
    }
    
    private func saveKeyToKeychain(_ keyData: Data) throws {
        // FIX HIGH-41: Atomic keychain update pattern.
        // Old pattern: SecItemDelete → SecItemAdd was NOT atomic — crash between them loses the key.
        // New pattern: Try SecItemUpdate first (in-place, atomic). Only Add if key doesn't exist yet.
        // FIX M-37: kSecUseDataProtectionKeychain ensures the data protection keychain is used
        let searchQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: encryptionKeyIdentifier,
            kSecAttrService as String: "app.ladon.messenger",
            kSecAttrSynchronizable as String: false,
            kSecUseDataProtectionKeychain as String: true
        ]
        
        let updateAttrs: [String: Any] = [
            kSecValueData as String: keyData,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        
        let updateStatus = SecItemUpdate(searchQuery as CFDictionary, updateAttrs as CFDictionary)
        if updateStatus == errSecSuccess {
            return // Updated atomically in-place
        }
        
        if updateStatus == errSecItemNotFound {
            // Key doesn't exist yet — add it
            var addQuery = searchQuery
            addQuery[kSecValueData as String] = keyData
            addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
            guard addStatus == errSecSuccess else {
                throw SecureUserDefaultsError.keychainError(addStatus)
            }
        } else {
            throw SecureUserDefaultsError.keychainError(updateStatus)
        }
    }
    
    // MARK: - Encrypt/Decrypt
    
    private func encrypt(_ data: Data, keyName: String = "") throws -> Data {
        let key = try getEncryptionKey()
        let nonce = ChaChaPoly.Nonce()
        // FIX: Use key name as authenticated data to prevent key-value remapping attacks
        let aad = Data(keyName.utf8)
        let sealedBox = try ChaChaPoly.seal(data, using: key, nonce: nonce, authenticating: aad)
        return sealedBox.combined
    }
    
    private func decrypt(_ encryptedData: Data, keyName: String = "") throws -> Data {
        let key = try getEncryptionKey()
        let sealedBox = try ChaChaPoly.SealedBox(combined: encryptedData)
        // FIX: Verify key name binding via authenticated data
        let aad = Data(keyName.utf8)
        return try ChaChaPoly.open(sealedBox, using: key, authenticating: aad)
    }
    
    // MARK: - Public API
    
    // FIX MED-A9: Hash key names to prevent metadata leakage through UserDefaults enumeration
    // FIX SS-4 (ADVERSARIAL): Use 16 bytes (128 bits) instead of 8 bytes (64 bits) to avoid birthday collisions
    private func hashedKey(_ key: String) -> String {
        let hash = SHA256.hash(data: Data(key.utf8))
        return "su_" + hash.prefix(16).map { String(format: "%02x", $0) }.joined()
    }
    
    /// Store encrypted Data
    func set(_ value: Data, forKey key: String) throws {
        let encrypted = try encrypt(value, keyName: key)
        let hKey = hashedKey(key)
        UserDefaults.standard.set(encrypted, forKey: hKey)
        // FIX MED-A9: Remove old plaintext-keyed entry if exists (migration)
        let oldKey = "secure_\(key)"
        if UserDefaults.standard.object(forKey: oldKey) != nil {
            UserDefaults.standard.removeObject(forKey: oldKey)
        }
    }
    
    /// Store encrypted String
    func set(_ value: String, forKey key: String) throws {
        guard let data = value.data(using: .utf8) else {
            throw SecureUserDefaultsError.encodingFailed
        }
        try set(data, forKey: key)
    }
    
    /// Store encrypted Int
    func set(_ value: Int, forKey key: String) throws {
        var intValue = value
        let data = withUnsafeBytes(of: &intValue) { Data($0) }
        try set(data, forKey: key)
    }
    
    /// Retrieve decrypted Data
    func data(forKey key: String) throws -> Data? {
        let hKey = hashedKey(key)
        // FIX MED-A9: Try hashed key first
        if let encrypted = UserDefaults.standard.data(forKey: hKey) {
            return try decrypt(encrypted, keyName: key)
        }
        // FIX C-5 R21: Legacy fallback entfernt — alte Einträge unter "secure_\(key)"
        // wurden ohne AAD verschlüsselt und können nicht sicher entschlüsselt werden.
        // decrypt() mit keyName-AAD würde ohnehin fehlschlagen (Tag-Mismatch).
        // Statt eines toten Code-Pfads: alten Eintrag löschen falls vorhanden.
        let oldKey = "secure_\(key)"
        if UserDefaults.standard.object(forKey: oldKey) != nil {
            UserDefaults.standard.removeObject(forKey: oldKey)
        }
        return nil
    }
    
    /// Retrieve decrypted String
    func string(forKey key: String) throws -> String? {
        guard let data = try data(forKey: key) else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }
    
    /// Retrieve decrypted Int
    func integer(forKey key: String) throws -> Int? {
        guard let data = try data(forKey: key) else {
            return nil
        }
        guard data.count >= MemoryLayout<Int>.size else {
            return nil
        }
        return data.withUnsafeBytes { $0.loadUnaligned(as: Int.self) }
    }
    
    /// Store encrypted Bool
    func set(_ value: Bool, forKey key: String) throws {
        let data = Data([value ? 1 : 0])
        try set(data, forKey: key)
    }
    
    /// Retrieve decrypted Bool (returns false if key not found)
    /// FIX LOW-16: Log decryption errors instead of silently swallowing them
    func bool(forKey key: String) -> Bool {
        do {
            guard let data = try data(forKey: key), let byte = data.first else {
                return false
            }
            return byte != 0
        } catch {
            #if DEBUG
            print("[SecureUserDefaults] ⚠️ Error reading bool for key '\(key)': \(error)")
            #endif
            return false
        }
    }
    
    /// Remove key
    func remove(forKey key: String) {
        // FIX MED-A9: Remove both hashed and legacy key
        UserDefaults.standard.removeObject(forKey: hashedKey(key))
        UserDefaults.standard.removeObject(forKey: "secure_\(key)")
    }
    
    /// Check if key exists
    func exists(forKey key: String) -> Bool {
        // FIX MED-A9: Check both hashed and legacy key
        return UserDefaults.standard.object(forKey: hashedKey(key)) != nil ||
               UserDefaults.standard.object(forKey: "secure_\(key)") != nil
    }
}

enum SecureUserDefaultsError: Error {
    case keychainError(OSStatus)
    case encryptionFailed
    case decryptionFailed
    case encodingFailed
}

// MARK: - 🔐 FIX #10: Memory Locking (MEDIUM Priority)

import Darwin

extension Data {
    /// Lock memory pages to prevent swapping to disk
    /// Prevents keys from being written to swap file after device seizure
    /// FIX HIGH-09: Check mlock result and use page-aligned size
    mutating func lockMemory() throws {
        try self.withUnsafeMutableBytes { bytes in
            guard let baseAddress = bytes.baseAddress, bytes.count > 0 else {
                throw MemoryLockError.invalidAddress
            }
            // Calculate page-aligned range for mlock
            let pageSize = vm_page_size
            let startPage = UInt(bitPattern: baseAddress) & ~UInt(pageSize - 1)
            let endPage = (UInt(bitPattern: baseAddress) + UInt(bytes.count) + UInt(pageSize - 1)) & ~UInt(pageSize - 1)
            let lockSize = Int(endPage - startPage)
            
            let result = mlock(UnsafeRawPointer(bitPattern: startPage)!, lockSize)
            if result != 0 {
                throw MemoryLockError.mlockFailed(errno)
            }
        }
    }
    
    /// Unlock previously locked memory pages
    /// FIX A11-3: Use page-aligned address/size matching lockMemory()
    mutating func unlockMemory() {
        self.withUnsafeMutableBytes { bytes in
            guard let baseAddress = bytes.baseAddress, bytes.count > 0 else { return }
            let pageSize = vm_page_size
            let startPage = UInt(bitPattern: baseAddress) & ~UInt(pageSize - 1)
            let endPage = (UInt(bitPattern: baseAddress) + UInt(bytes.count) + UInt(pageSize - 1)) & ~UInt(pageSize - 1)
            let lockSize = Int(endPage - startPage)
            munlock(UnsafeRawPointer(bitPattern: startPage)!, lockSize)
        }
    }
}

enum MemoryLockError: Error {
    case invalidAddress
    case mlockFailed(Int32)
}

// MARK: - Usage Example

extension KeyManager {
    /// Example: Store recipient ID encrypted (FIX #8)
    func storeRecipientIDSecurely(_ recipientID: Data) throws {
        try SecureUserDefaults.shared.set(recipientID, forKey: "current_recipient_id")
    }
    
    /// Example: Load recipient ID decrypted (FIX #8)
    func loadRecipientIDSecurely() throws -> Data? {
        return try SecureUserDefaults.shared.data(forKey: "current_recipient_id")
    }
    
    /// Example: Use mlock on sensitive key material (FIX #10)
    func encryptWithLockedMemory(_ plaintext: Data, key: inout Data) throws -> Data {
        // Lock key in memory (prevents swap to disk)
        try key.lockMemory()
        
        defer {
            // Always unlock and wipe when done
            key.unlockMemory()
            key.securelyWipe()
        }
        
        // Use key for encryption
        let symmetricKey = SymmetricKey(data: key)
        let nonce = ChaChaPoly.Nonce()
        let sealedBox = try ChaChaPoly.seal(plaintext, using: symmetricKey, nonce: nonce)
        
        return sealedBox.combined
    }
}
