import Foundation
import CryptoKit
import Security
import LocalAuthentication
// MARK: - Biometric-Only Keys Extension is in QuickWinsPhase1.swift

/// Manages cryptographic keys with Keychain storage
/// RFC 3: Hybrid identity = Ed25519 (signing) + X25519 (encryption)
/// RFC QUANTUM: Post-Quantum support infrastructure (Kyber768 framework ready)
class KeyManager {
    // FIX KM-M1: Constant-time comparison that does not leak length.
    // Pad shorter input to match longer, then compare all bytes.
    // Result is always false if lengths differ, but timing is constant.
    // FIX H-2 AUDIT-MAR-2026: @inline(never) prevents compiler from optimizing away constant-time loop
    @inline(never)
    private func constantTimeEqual(_ a: Data, _ b: Data) -> Bool {
        let maxLen = max(a.count, b.count)
        guard maxLen > 0 else { return a.count == b.count }
        var result: UInt8 = UInt8(a.count != b.count ? 1 : 0)
        for i in 0..<maxLen {
            let byteA = i < a.count ? a[a.startIndex + i] : 0
            let byteB = i < b.count ? b[b.startIndex + i] : 0
            result |= byteA ^ byteB
        }
        return result == 0
    }
    static let shared = KeyManager()
    
    // FIX MED-A2: Migration flags in Keychain instead of plaintext UserDefaults
    private func isMigrationDone(_ key: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecAttrService as String: "app.ladon.messenger.migrations",
            kSecReturnData as String: false,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        return SecItemCopyMatching(query as CFDictionary, nil) == errSecSuccess
    }
    
    private func markMigrationDone(_ key: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecAttrService as String: "app.ladon.messenger.migrations",
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecValueData as String: Data([1])
        ]
        SecItemAdd(query as CFDictionary, nil)
    }
    
    /// FIX CRYPTO-C04: Migrate existing keychain items that were stored without kSecAttrService.
    /// Reads items without service, filters by known Ladon prefixes, deletes old item, re-adds with service.
    private func migrateKeychainItemsToServiceNamespace() {
        let knownPrefixes = [
            KeychainKeys.sessionPrefix,  // "session_"
            "conv_private_", "conv_public_",
            "spk_private", "ephemeral_prekey_private",
            "kyber768_", "identity_", "signing_",
            "session_dh_sk_", "session_root_key_", "session_kyber_sk_",
            "app.ladon.messenger"  // cover sequence, auth secret, etc.
        ]
        
        // Query ALL generic password items WITHOUT service filter — attributes
        // only. P8-AUDIT8-IOS-24: this used to request kSecReturnData for every
        // item, pulling all Keychain secrets (V2 identity, ratchets, prekeys,
        // delivery keys) into the heap just to look at their attributes. Now
        // only the items that actually need migrating are read, one by one.
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrSynchronizable as String: false,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnAttributes as String: true
        ]
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let items = result as? [[String: Any]] else { return }
        
        var migratedCount = 0
        for item in items {
            guard let account = item[kSecAttrAccount as String] as? String else { continue }
            
            // Skip items that already have a service attribute
            if let existingService = item[kSecAttrService as String] as? String, !existingService.isEmpty {
                continue
            }
            
            // Only migrate items with known Ladon prefixes
            guard knownPrefixes.contains(where: { account.hasPrefix($0) }) else { continue }
            
            // Read this one item's data.
            var dataResult: AnyObject?
            let dataQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrAccount as String: account,
                kSecAttrSynchronizable as String: false,
                kSecMatchLimit as String: kSecMatchLimitOne,
                kSecReturnAttributes as String: true,
                kSecReturnData as String: true
            ]
            guard SecItemCopyMatching(dataQuery as CFDictionary, &dataResult) == errSecSuccess,
                  let found = dataResult as? [String: Any],
                  ((found[kSecAttrService as String] as? String) ?? "").isEmpty,
                  var data = found[kSecValueData as String] as? Data else { continue }
            dataResult = nil
            // FIX R16-KM1: Wipe migrated key data after re-storing
            defer { data.securelyWipe() }
            
            // Delete old item (without service)
            let deleteQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrAccount as String: account,
                kSecAttrSynchronizable as String: false
            ]
            SecItemDelete(deleteQuery as CFDictionary)
            
            // Re-add with service attribute
            let addQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrAccount as String: account,
                kSecAttrService as String: "app.ladon.messenger",
                kSecValueData as String: data,
                kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                kSecAttrSynchronizable as String: false
            ]
            let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
            if addStatus == errSecSuccess {
                migratedCount += 1
            }
        }
        
        #if DEBUG
        SecureLogger.debug("[KeyManager] 🔄 Migrated \(migratedCount) keychain items to service namespace")
        #endif
    }
    
    private init() {
        // One-time migration: clear sessions corrupted by the old SE key migration bug
        let sessionResetKey = "com.ladon.session-reset-v3"
        // FIX MED-A2: Check Keychain first, fall back to UserDefaults for legacy
        if !isMigrationDone(sessionResetKey) && !UserDefaults.standard.bool(forKey: sessionResetKey) {
            resetConversationState()
            let tag = "com.ladon.hwkey.session-wrap".data(using: .utf8)!
            let deleteQuery: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrApplicationTag as String: tag,
                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom
            ]
            SecItemDelete(deleteQuery as CFDictionary)
            markMigrationDone(sessionResetKey)
            markMigrationDone("com.ladon.se-key-migrated-v2")
            // Remove legacy UserDefaults keys
            UserDefaults.standard.removeObject(forKey: sessionResetKey)
            UserDefaults.standard.removeObject(forKey: "com.ladon.se-key-migrated-v2")
            #if DEBUG
            SecureLogger.debug("[KeyManager] 🔄 One-time session reset completed (v3 migration)")
            #endif
        }
        
        // Migration v4: Reset sessions after DH4 removal fix.
        // Old sessions were created with asymmetric DH4 (IK×OPK) which produced
        // different root keys on each phone — decryption always failed.
        // New sessions use only symmetric DH operations (DH1+DH2+DH3+EK).
        let sessionResetV4Key = "com.ladon.session-reset-v4-dh4fix"
        if !isMigrationDone(sessionResetV4Key) {
            resetConversationState()
            markMigrationDone(sessionResetV4Key)
            #if DEBUG
            SecureLogger.debug("Migration v4")
            #endif
        }
        
        // FIX CRYPTO-C04: Migration v5 — Add kSecAttrService to ALL keychain items.
        // Previously, KeyManager stored items without kSecAttrService, meaning
        // emergencyLockdown's service-scoped delete missed them. This migration
        // reads all unscoped items matching our account prefixes and re-saves them
        // with kSecAttrService = "app.ladon.messenger".
        let serviceAttrMigrationKey = "com.ladon.keychain-service-attr-v1"
        if !isMigrationDone(serviceAttrMigrationKey) {
            migrateKeychainItemsToServiceNamespace()
            markMigrationDone(serviceAttrMigrationKey)
            #if DEBUG
            SecureLogger.debug("[KeyManager] 🔄 Migration v5: Keychain items migrated to service namespace")
            #endif
        }
        
        // FIX FACEID-DEFINITIVE: Migration v7 — STRIP biometric protection from keychain items.
        // Previous migration v6 ADDED .biometryCurrentSet which caused iOS to trigger
        // Face ID on EVERY SecItemCopyMatching call. This migration removes that flag by
        // re-saving all identity/signing keys with just kSecAttrAccessibleWhenUnlockedThisDeviceOnly.
        // Biometric protection is now purely at the application level (BiometricAuthService).
        let stripBiometricProtectionKey = "com.ladon.strip-biometric-keys-v1"
        if !isMigrationDone(stripBiometricProtectionKey) {
            #if DEBUG
            SecureLogger.debug("[KeyManager] 🔄 Migration v7: REMOVING biometric protection from keychain items...")
            #endif
            
            let keysToMigrate = [
                KeychainKeys.identityPrivateKey,
                "signing_private_key"
            ]
            
            var migratedCount = 0
            for key in keysToMigrate {
                // Read key — may fail if biometric auth is needed, so try with interactionNotAllowed
                let readQuery: [String: Any] = [
                    kSecClass as String: kSecClassGenericPassword,
                    kSecAttrAccount as String: key,
                    kSecAttrService as String: "app.ladon.messenger",
                    kSecReturnData as String: true,
                    kSecAttrSynchronizable as String: false
                ]
                
                var result: AnyObject?
                var status = SecItemCopyMatching(readQuery as CFDictionary, &result)
                
                // If read fails (biometric required), try with interactionNotAllowed context
                if status != errSecSuccess {
                    var contextQuery = readQuery
                    let ctx = LAContext()
                    ctx.interactionNotAllowed = true
                    contextQuery[kSecUseAuthenticationContext as String] = ctx
                    status = SecItemCopyMatching(contextQuery as CFDictionary, &result)
                }
                
                guard status == errSecSuccess, var keyData = result as? Data else {
                    #if DEBUG
                    SecureLogger.debug("[KeyManager] Key \(key) not found or inaccessible, skipping migration")
                    #endif
                    continue
                }
                // FIX SEC-8: Wipe raw key bytes from heap after migration
                defer { keyData.securelyWipe() }
                
                // Delete old key (may have biometric access control)
                let deleteQuery: [String: Any] = [
                    kSecClass as String: kSecClassGenericPassword,
                    kSecAttrAccount as String: key,
                    kSecAttrService as String: "app.ladon.messenger"
                ]
                SecItemDelete(deleteQuery as CFDictionary)
                
                // Re-save WITHOUT biometric protection
                do {
                    try saveToKeychain(key: key, data: keyData)
                    migratedCount += 1
                    #if DEBUG
                    SecureLogger.debug("[KeyManager] ✅ Migrated key \(key) WITHOUT biometric flag")
                    #endif
                } catch {
                    #if DEBUG
                    SecureLogger.debug("[KeyManager] ⚠️ Failed to migrate key \(key): \(error)")
                    #endif
                }
            }
            
            markMigrationDone(stripBiometricProtectionKey)
            #if DEBUG
            SecureLogger.debug("[KeyManager] ✅ Migration v7 completed: \(migratedCount) keys stripped of biometric protection")
            #endif
        }
        
        
        // FIX ROTATION-PERIODIC: Check SPK rotation every hour while app is running.
        // Without this, rotation only fires at startup — meaning an app open for >48h
        // would never rotate its SPK during that session.
        DispatchQueue.main.async {
            Timer.scheduledTimer(withTimeInterval: 3600, repeats: true) { [weak self] _ in
                DispatchQueue.global(qos: .utility).async {
                    self?.rotateSPKIfNeeded()
                }
            }
        }
    }

    // ✅ DH-Ratchet ENABLED — Ratchet public key is now transmitted in message header.
    // Message header format: [1B version][1B flags][4B ratchetPKLen][32B ratchetPK][ciphertext...]
    // Flags: 0x01 = contains DH ratchet key, 0x00 = no ratchet step
    // Fix: sendingChainLength==0 skips ratchet (first message uses initial chain keys)
    private let dhRatchetEnabled = true
    private let legacyRecipientIDsKey = "legacy_recipient_ids"
    
    
    // Message header constants
    private let headerVersion: UInt8 = 0x05  // v5 = encrypted header (ratchet PK hidden from relay)
    private let headerFlagRatchet: UInt8 = 0x01
    private let headerFlagKyberCT: UInt8 = 0x02  // has Kyber768 ciphertext (1088B)
    private let headerFlagKyberPK: UInt8 = 0x04  // has new Kyber768 public key (1184B) for key rotation
    private let headerFlagUAKUpdate: UInt8 = 0x08 // FIX UAK-SYNC: has new UAK (32B) for recipient to sync
    private let headerFlagNoRatchet: UInt8 = 0x00
    private let ratchetKeySize = 32  // X25519 public key size
    private let kyberCTSize = PostQuantumService.Constants.kyberCiphertextSize
    private let kyberPKSize = PostQuantumService.Constants.kyberPublicKeySize
    private let uakUpdateSize = 32   // UAK size for header update
    
    // FIX INFO-DC: Named constants for magic numbers in crypto code
    private let symmetricKeySize = 32         // AES-256 / ChaCha20 key size
    private let kdfRootChainOutputSize = 64   // HKDF output: rootKey(32) + chainKey(32)
    private let chachaPolyNonceSize = 12      // ChaChaPoly1305 nonce size
    private let chachaPolyTagSize = 16        // ChaChaPoly1305 authentication tag size
    
    private let ed25519SignatureSize = 64     // Ed25519 signature size
    // FIX LOW: Updated from 16 to 32 bytes to match current UAK specification
    private let uakSize = 32                  // Unidentified Access Key size
    private let paddingBlockSize = 128        // Message padding block size
    
    // MARK: - Post-Quantum Support Framework
    
    /// ✅ REAL Post-Quantum Cryptography ACTIVE (2. Februar 2026)
    /// Powered by PostQuantumService (liboqs backend via OQSWrapper)
    /// - Kyber768: REAL KEM encapsulation (not simulated)
    /// - Dilithium3: REAL digital signatures (not simulated)
    /// - Hybrid mode: Classical X25519 + Quantum Kyber768
    /// - Store-Now-Decrypt-Later: PROTECTED (100/100)
    /// - Quantum Computer Resistance: ACTIVE
    /// 
    /// Migration from classical to hybrid is transparent:
    /// 1. New users get hybrid keys (classical + Kyber768)
    /// 2. Existing users rotate on next key rotation cycle
    /// 3. All messages: double-encrypted (classical + quantum)
    /// 4. Breaking either encryption still leaves other intact

    // MARK: - Identity Keys (Hybrid: Signing + Encryption)
    
    /// Check if identity keys exist
    func hasIdentityKey() -> Bool {
        // FIX: Check public keys instead of private keys to avoid triggering Face ID
        // just to check if keys exist (e.g. in background loops).
        return (try? getIdentityPublicKey()) != nil && (try? getSigningPublicKey()) != nil
    }
    
    /// FIX KEY-LOSS: Check if identity PRIVATE key exists in Keychain (existence only, no data read = no Face ID).
    /// Returns false if the private key was purged by iOS while the public key still exists.
    func hasIdentityPrivateKeyInKeychain() -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: KeychainKeys.identityPrivateKey,
            kSecAttrService as String: "app.ladon.messenger",
            kSecReturnData as String: false,
            kSecAttrSynchronizable as String: false
        ]
        return SecItemCopyMatching(query as CFDictionary, nil) == errSecSuccess
    }
    
    /// FIX KEY-LOSS: Regenerate identity keys when private key was lost from Keychain.
    /// This generates a NEW identity — contacts will see a key change warning.
    func regenerateIdentityKeys() throws {
        #if DEBUG
        SecureLogger.debug("[KeyManager] ⚠️ REGENERATING identity keys (private key was lost from Keychain)")
        #endif
        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        let publicKey = privateKey.publicKey
        let signingPrivateKey = Curve25519.Signing.PrivateKey()
        let signingPublicKey = signingPrivateKey.publicKey
        
        try saveIdentityPrivateKey(privateKey)
        try saveIdentityPublicKey(publicKey)
        try saveSigningPrivateKey(signingPrivateKey)
        try saveSigningPublicKey(signingPublicKey)
        
        // Cache the new private key immediately
        biometricLock.lock()
        cachedIdentityPrivateKeyData = privateKey.rawRepresentation
        cachedSigningPrivateKeyData = signingPrivateKey.rawRepresentation
        biometricLock.unlock()
        
        #if DEBUG
        SecureLogger.debug("[KeyManager] ✅ Identity keys regenerated successfully")
        #endif
    }
    
    /// Initialize keys on first launch
    func initializeIfNeeded() async {
        if !hasIdentityKey() {
            // Keys will be generated during onboarding
        }
        
        // FIX C-3: Identity Key rotation REMOVED — IK is permanent (Signal Protocol).
        // Rotating IK breaks ALL existing sessions and Safety Numbers.
        // Only the SPK rotates (see rotateSPKIfNeeded below).
        rotateSPKIfNeeded()
        
    }
    
    // MARK: - Ed25519 Signing Keys
    
    /// Generate Ed25519 signing key pair
    func generateSigningKeys() throws {
        let signingKey = Curve25519.Signing.PrivateKey()
        try saveSigningPrivateKey(signingKey)
        try saveSigningPublicKey(signingKey.publicKey)
    }
    
    /// Sign message with Ed25519
    func signMessage(_ message: Data) throws -> Data {
        guard let signingKey = loadSigningPrivateKey() else {
            throw KeyManagerError.signingKeyNotFound
        }
        
        let signature = try signingKey.signature(for: message)
        return signature
    }
    
    /// Verify Ed25519 signature
    func verifySignature(_ signature: Data, for message: Data, publicKey: Curve25519.Signing.PublicKey) throws -> Bool {
        return publicKey.isValidSignature(signature, for: message)
    }
    
    /// Get signing public key — derives from private key for consistency
    func getSigningPublicKey() throws -> Curve25519.Signing.PublicKey {
        // FIX KEYSYNC: Prefer deriving from private key to guarantee consistency
        if let signingKey = loadSigningPrivateKey() {
            return signingKey.publicKey
        }
        // Fallback: load stored public key if private key is unavailable (app locked)
        guard let keyData = loadFromKeychain(key: "signing_public_key") else {
            throw KeyManagerError.signingKeyNotFound
        }
        return try Curve25519.Signing.PublicKey(rawRepresentation: keyData)
    }
    
    /// Get current recipient ID (SHA256 of public key) for relay
    /// 🟠 FIX #9: This hash is rotated on key rotation to prevent long-term tracking
    func getCurrentRecipientID() throws -> Data {
        // Check if we have a stored recipient ID from key rotation
        if let storedID = loadFromKeychain(key: "current_recipient_id") {
            return storedID
        }
        
        // Otherwise derive from current public key
        let publicKey = try getIdentityPublicKey()
        return SHA256(publicKey.rawRepresentation)
    }

    /// Get legacy recipient IDs (hex strings) for backward compatibility
    func getLegacyRecipientIDHexes() -> [String] {
        do {
            guard let data = loadFromKeychain(key: legacyRecipientIDsKey) else {
                return []
            }
            return (try JSONDecoder().decode([String].self, from: data))
        } catch {
            #if DEBUG
            print("[KeyManager] ⚠️ Failed to decode legacy recipient IDs: \(error)")
            #endif
            return []
        }
    }

    private func addLegacyRecipientID(_ data: Data) {
        let hex = data.map { String(format: "%02x", $0) }.joined()
        var list = getLegacyRecipientIDHexes()
        if list.contains(hex) { return }
        list.insert(hex, at: 0)
        if list.count > 3 {
            list = Array(list.prefix(3))
        }
        do {
            let encoded = try JSONEncoder().encode(list)
            try saveToKeychain(key: legacyRecipientIDsKey, data: encoded)
        } catch {
            #if DEBUG
            print("[KeyManager] ⚠️ Failed to store legacy recipient IDs: \(error)")
            #endif
        }
    }
    
    // FIX F15: CryptoKit SHA256 instead of CommonCrypto (no CC_LONG truncation risk)
    private func SHA256(_ data: Data) -> Data {
        return Data(CryptoKit.SHA256.hash(data: data))
    }
    
    // MARK: - FIX C-3: SPK Rotation (Signal Protocol — IK is permanent)
    
    /// Signal Protocol: Identity Key is PERMANENT. Only SPK rotates.
    /// Rotating IK would break all sessions and Safety Numbers.
    /// SPK rotation provides break-in recovery without session destruction.
    /// FIX KM-L4: SPK rotation interval is now a stored property (configurable).
    /// Default: 48 hours (Signal standard). Can be adjusted via setSPKRotationInterval().
    /// FIX INFO-AC1: private(set) prevents bypassing setSPKRotationInterval() guard.
    private(set) var spkRotationInterval: TimeInterval {
        get {
            spkRotationLock.lock()
            defer { spkRotationLock.unlock() }
            return _spkRotationInterval
        }
        set {
            spkRotationLock.lock()
            _spkRotationInterval = newValue
            spkRotationLock.unlock()
        }
    }
    // FIX R21-A1-2: Backing store + lock for thread-safe spkRotationInterval access.
    // Previously unsynchronized read/write from background timer vs setter.
    private var _spkRotationInterval: TimeInterval = 48 * 60 * 60
    private let spkRotationLock = NSLock()
    
    /// FIX KM-L4: Allow adjusting SPK rotation interval (e.g., for testing or policy changes)
    func setSPKRotationInterval(_ seconds: TimeInterval) {
        guard seconds >= 3600 else { return } // Minimum 1 hour — prevent excessive rotation
        // FIX L-SPK: Maximum 30 days — prevent disabling rotation entirely
        spkRotationInterval = min(seconds, 30 * 24 * 3600)
    }
    
    private func rotateSPKIfNeeded() {
        
        guard let lastRotationData = loadFromKeychain(key: "spk_rotation_timestamp") else {
            // First launch: set SPK rotation timestamp
            do {
                var timestamp = Date().timeIntervalSince1970
                let timestampData = withUnsafeBytes(of: &timestamp) { Data($0) }
                try saveToKeychain(key: "spk_rotation_timestamp", data: timestampData)
            } catch {
                #if DEBUG
                print("[KeyManager] Error setting SPK rotation timestamp: \(error)")
                #endif
            }
            return
        }
        
        guard let timeInterval = lastRotationData.withUnsafeBytes({ buffer -> TimeInterval? in
            if buffer.count >= MemoryLayout<TimeInterval>.size {
                // FIX A12-LOW-6: loadUnaligned prevents UB from unaligned Keychain data
                return buffer.loadUnaligned(as: TimeInterval.self)
            }
            return nil
        }) else {
            return
        }
        
        let lastRotation = Date(timeIntervalSince1970: timeInterval)
        let timeSinceRotation = Date().timeIntervalSince(lastRotation)
        
        if timeSinceRotation > spkRotationInterval {
            rotateSPK()
        }
    }
    
    /// Rotate Signed PreKey only (Identity Key stays permanent)
    private func rotateSPK() {
        do {
            guard let signingKey = loadSigningPrivateKey() else { return }
            
            let newSpkPrivate = Curve25519.KeyAgreement.PrivateKey()
            let newSpkPublic = newSpkPrivate.publicKey
            _ = try signingKey.signature(for: newSpkPublic.rawRepresentation)
            
            let spkID = newSpkPublic.rawRepresentation.prefix(8).map { String(format: "%02x", $0) }.joined()
            
            // FIX M-5: Store previous SPK ID + rotation timestamp for 48h grace period.
            // Signal keeps previous SPK for 48h so in-flight messages can still be decrypted.
            // FIX KM-5: Delete old grace SPK AFTER saving new SPK — if save fails,
            // the old grace SPK is still available for in-flight message decryption.
            var oldGraceSPKID: String? = nil
            if let prevIDData = loadFromKeychain(key: "spk_current_id"),
               let prevID = String(data: prevIDData, encoding: .utf8) {
                // Remember the 2-generations-back SPK ID for later deletion
                if let graceSPKData = loadFromKeychain(key: "spk_grace_id"),
                   let graceSPKIDValue = String(data: graceSPKData, encoding: .utf8) {
                    oldGraceSPKID = graceSPKIDValue
                }
                // Move current SPK to grace period
                try saveToKeychain(key: "spk_grace_id", data: Data(prevID.utf8))
            }
            
            try saveToKeychain(key: "spk_private_\(spkID)", data: newSpkPrivate.rawRepresentation)
            try saveToKeychain(key: "spk_current_id", data: Data(spkID.utf8))
            try saveToKeychain(key: "spk_private", data: newSpkPrivate.rawRepresentation)
            
            // FIX KM-5: Now that the new SPK is safely persisted, delete the expired grace SPK
            if let oldID = oldGraceSPKID {
                deleteFromKeychain(key: "spk_private_\(oldID)")
            }
            
            // Update rotation timestamp
            var timestamp = Date().timeIntervalSince1970
            let timestampData = withUnsafeBytes(of: &timestamp) { Data($0) }
            try saveToKeychain(key: "spk_rotation_timestamp", data: timestampData)
            
            #if DEBUG
            print("[KeyManager] ✅ SPK rotated (IK permanent, Signal-compliant)")
            #endif
        } catch {
            #if DEBUG
            print("[KeyManager] ❌ SPK rotation error: \(error)")
            #endif
        }
    }
    
    /// Get time remaining until next SPK rotation
    func timeUntilKeyRotation() -> TimeInterval {
        // FIX CRYPTO-H01: Removed local shadow of spkRotationInterval.
        // Previously a local `let spkRotationInterval = 48*3600` shadowed the instance
        // property, causing setSPKRotationInterval() to be silently ignored.
        
        guard let lastRotationData = loadFromKeychain(key: "spk_rotation_timestamp") else {
            return spkRotationInterval
        }
        
        guard let timeInterval = lastRotationData.withUnsafeBytes({ buffer -> TimeInterval? in
            if buffer.count >= MemoryLayout<TimeInterval>.size {
                // FIX A12-LOW-6: loadUnaligned prevents UB from unaligned Keychain data
                return buffer.loadUnaligned(as: TimeInterval.self)
            }
            return nil
        }) else {
            return spkRotationInterval
        }
        
        let lastRotation = Date(timeIntervalSince1970: timeInterval)
        let timeSinceRotation = Date().timeIntervalSince(lastRotation)
        
        return max(0, spkRotationInterval - timeSinceRotation)
    }
    
    /// Generate identity key pair (X25519) + Signing keys (Ed25519)
    func generateIdentityKeys() async throws {
        // Generate X25519 key agreement keys
        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        let publicKey = privateKey.publicKey
        
        // Generate Ed25519 signing keys
        let signingPrivateKey = Curve25519.Signing.PrivateKey()
        let signingPublicKey = signingPrivateKey.publicKey
        
        // Store in Keychain
        try saveIdentityPrivateKey(privateKey)
        try saveIdentityPublicKey(publicKey)
        try saveSigningPrivateKey(signingPrivateKey)
        try saveSigningPublicKey(signingPublicKey)
        
        #if DEBUG
        print("[KeyManager] ✅ Identity keys generated (X25519 + Ed25519)")
        #endif
    }
    
    /// Generate identity keys SYNCHRONOUSLY (for app init)
    func generateIdentityKeysSync() throws {
        // Generate X25519 key agreement keys
        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        let publicKey = privateKey.publicKey
        
        // Generate Ed25519 signing keys
        let signingPrivateKey = Curve25519.Signing.PrivateKey()
        let signingPublicKey = signingPrivateKey.publicKey
        
        // Store in Keychain
        try saveIdentityPrivateKey(privateKey)
        try saveIdentityPublicKey(publicKey)
        try saveSigningPrivateKey(signingPrivateKey)
        try saveSigningPublicKey(signingPublicKey)
        
        #if DEBUG
        SecureLogger.debug("[KeyManager] ✅ Identity keys generated SYNCHRONOUSLY (X25519 + Ed25519)")
        #endif
    }
    
    /// Get identity public key
    func getIdentityPublicKey() throws -> Curve25519.KeyAgreement.PublicKey {
        guard let keyData = loadFromKeychain(key: KeychainKeys.identityPublicKey) else {
            throw KeyManagerError.keyNotFound
        }
        
        return try Curve25519.KeyAgreement.PublicKey(rawRepresentation: keyData)
    }
    
    /// Get identity private key
    private func loadIdentityPrivateKey() -> Curve25519.KeyAgreement.PrivateKey? {
        guard var keyData = loadFromKeychain(key: KeychainKeys.identityPrivateKey) else {
            return nil
        }
        defer { keyData.securelyWipe() }
        return try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: keyData)
    }
    
    /// Save identity private key to Keychain
    private func saveIdentityPrivateKey(_ key: Curve25519.KeyAgreement.PrivateKey) throws {
        try saveToKeychain(key: KeychainKeys.identityPrivateKey, data: key.rawRepresentation)
    }
    
    /// Save identity public key to Keychain
    private func saveIdentityPublicKey(_ key: Curve25519.KeyAgreement.PublicKey) throws {
        try saveToKeychain(key: KeychainKeys.identityPublicKey, data: key.rawRepresentation)
    }
    
    /// Save signing private key to Keychain (Ed25519)
    private func saveSigningPrivateKey(_ key: Curve25519.Signing.PrivateKey) throws {
        try saveToKeychain(key: "signing_private_key", data: key.rawRepresentation)
    }
    
    /// Save signing public key to Keychain (Ed25519)
    private func saveSigningPublicKey(_ key: Curve25519.Signing.PublicKey) throws {
        try saveToKeychain(key: "signing_public_key", data: key.rawRepresentation)
    }
    
    /// Load signing private key from Keychain
    private func loadSigningPrivateKey() -> Curve25519.Signing.PrivateKey? {
        guard var keyData = loadFromKeychain(key: "signing_private_key") else {
            return nil
        }
        defer { keyData.securelyWipe() }
        return try? Curve25519.Signing.PrivateKey(rawRepresentation: keyData)
    }
    
    /// Load signing public key from Keychain
    private func loadSigningPublicKey() -> Curve25519.Signing.PublicKey? {
        guard let keyData = loadFromKeychain(key: "signing_public_key") else {
            return nil
        }
        return try? Curve25519.Signing.PublicKey(rawRepresentation: keyData)
    }
    
    // MARK: - Session Storage (Secure Enclave wrapped)
    
    func invalidateAllCaches() {
        // FIX A9-KM-02: Wipe ORIGINAL buffer, not COW copy.
        // 'if var data =' creates a local binding → withUnsafeMutableBytes triggers COW.
        // Use optional chaining (?.withUnsafeMutableBytes) to mutate the original.
        biometricLock.lock()
        cachedIdentityPrivateKeyData?.withUnsafeMutableBytes { ptr in
            if let base = ptr.baseAddress, ptr.count > 0 {
                _ = Darwin.memset_s(base, ptr.count, 0, ptr.count)
            }
        }
        cachedSigningPrivateKeyData?.withUnsafeMutableBytes { ptr in
            if let base = ptr.baseAddress, ptr.count > 0 {
                _ = Darwin.memset_s(base, ptr.count, 0, ptr.count)
            }
        }
        cachedIdentityPrivateKeyData = nil
        cachedSigningPrivateKeyData = nil
        biometricLock.unlock()
    }
    
    func resetConversationState() {
        let prefixes = [KeychainKeys.sessionPrefix, "conv_private_", "conv_public_"]

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "app.ladon.messenger",
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnAttributes as String: true,
            kSecAttrSynchronizable as String: false
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let items = result as? [[String: Any]] else {
            #if DEBUG
            SecureLogger.debug("[KeyManager] ⚠️ resetConversationState: No Keychain items found, status: \(status)")
            #endif
            return
        }

        var deletedCount = 0
        for item in items {
            guard let account = item[kSecAttrAccount as String] as? String else { continue }
            if prefixes.contains(where: { account.hasPrefix($0) }) {
                let deleteQuery: [String: Any] = [
                    kSecClass as String: kSecClassGenericPassword,
                    kSecAttrAccount as String: account,
                    kSecAttrService as String: "app.ladon.messenger",
                    kSecAttrSynchronizable as String: false
                ]
                let delStatus = SecItemDelete(deleteQuery as CFDictionary)
                if delStatus == errSecSuccess || delStatus == errSecItemNotFound {
                    deletedCount += 1
                }
            }
        }

        #if DEBUG
        SecureLogger.debug("[KeyManager] 🧹 resetConversationState: \(deletedCount) items deleted")
        #endif
    }

    /// Delete pre-keys (SPK, EK, Kyber) so they'll be freshly generated on next bundle creation.
    /// Called during migration v12 to fix the SPK/EK regeneration bug.
    func clearPreKeys() {
        deleteFromKeychain(key: "spk_private")
        deleteFromKeychain(key: "ephemeral_prekey_private")
        deleteFromKeychain(key: "kyber768_session_sk")
        deleteFromKeychain(key: "kyber768_session_pk")
        // Also clear SPK ID tracking
        if let idData = loadFromKeychain(key: "spk_current_id"),
           let id = String(data: idData, encoding: .utf8) {
            deleteFromKeychain(key: "spk_private_\(id)")
        }
        deleteFromKeychain(key: "spk_current_id")
        // FIX KM-13: Also clear grace-period SPK for complete cleanup
        if let graceData = loadFromKeychain(key: "spk_grace_id"),
           let graceID = String(data: graceData, encoding: .utf8) {
            deleteFromKeychain(key: "spk_private_\(graceID)")
        }
        deleteFromKeychain(key: "spk_grace_id")
        #if DEBUG
        SecureLogger.debug("clearPreKeys done")
        #endif
    }

    /// Remove sessions not in active conversation list
    // MARK: - Keychain Operations
    
    /// Biometric LAContext management — reuse to avoid repeated Face ID prompts
    private var _biometricLAContext: LAContext?
    private let biometricLock = NSLock()
    private var _isAppLocked: Bool = true
    
    // In-memory cache for private keys to avoid hitting Keychain (and LAContext) repeatedly.
    // FIX FACEID-PERSIST: NO TTL — cache is valid until explicitly wiped on background transition.
    // Previously a 5-minute TTL caused a new LAContext to be created after expiry,
    // triggering Face ID again while the app was still in the foreground.
    private var cachedIdentityPrivateKeyData: Data?
    private var cachedSigningPrivateKeyData: Data?
    
    private func cachedPrivateKeysValid() -> Bool {
        // Cache is valid as long as data exists. It's wiped in invalidateBiometricContext()
        // when the app goes to background.
        return cachedIdentityPrivateKeyData != nil || cachedSigningPrivateKeyData != nil
    }
    
    private func biometricContext() -> LAContext {
        biometricLock.lock()
        defer { biometricLock.unlock() }
        
        // FIX FACEID-PERSIST: Reuse the authenticated LAContext WITHOUT time limit.
        // The context is invalidated in invalidateBiometricContext() on background.
        // Previously a 5-minute expiry created a NEW unauthenticated LAContext,
        // which triggered Face ID again while the app was still in the foreground.
        if let ctx = _biometricLAContext {
            #if DEBUG
            SecureLogger.debug("[KeyManager] Reusing biometric LAContext")
            #endif
            return ctx
        }
        
        // FIX FACEID-FINAL: NEVER create an un-evaluated LAContext as fallback.
        // Previously this created a new LAContext() which, when passed to
        // SecItemCopyMatching for a .biometryCurrentSet item, triggered a
        // SYSTEM Face ID prompt — completely outside our control.
        // Instead, return a context with interactionNotAllowed=true so any
        // Keychain read will FAIL SILENTLY instead of prompting Face ID.
        let ctx = LAContext()
        ctx.interactionNotAllowed = true
        #if DEBUG
        SecureLogger.debug("[KeyManager] ⚠️ No authenticated LAContext — returning non-interactive fallback (will fail silently)")
        #endif
        return ctx
    }
    
    /// Invalidate biometric context (called when app goes to background)
    func invalidateBiometricContext() {
        biometricLock.lock()
        defer { biometricLock.unlock() }
        _biometricLAContext?.invalidate()
        _biometricLAContext = nil
        // FIX KM-12: _biometricLAContextCreated removed (was never read)
        
        // FIX H-1: Clear cached keys — use withUnsafeMutableBytes BEFORE setting to nil
        // to wipe the ACTUAL buffer, not a COW copy.
        // Swift COW means `var data = cached` creates a reference-counted copy that
        // only duplicates the buffer on mutation. By calling withUnsafeMutableBytes
        // directly on the optional binding, we target the shared buffer.
        cachedIdentityPrivateKeyData?.withUnsafeMutableBytes { ptr in
            if let base = ptr.baseAddress, ptr.count > 0 {
                _ = Darwin.memset_s(base, ptr.count, 0, ptr.count)
            }
        }
        cachedSigningPrivateKeyData?.withUnsafeMutableBytes { ptr in
            if let base = ptr.baseAddress, ptr.count > 0 {
                _ = Darwin.memset_s(base, ptr.count, 0, ptr.count)
            }
        }
        cachedIdentityPrivateKeyData = nil
        cachedSigningPrivateKeyData = nil
        
        #if DEBUG
        SecureLogger.debug("[KeyManager] Invalidated biometric LAContext and cleared key cache")
        #endif
    }
    
    func setAppLocked(_ locked: Bool) {
        biometricLock.lock()
        _isAppLocked = locked
        biometricLock.unlock()
        #if DEBUG
        SecureLogger.debug("[KeyManager] App locked state set to: \(locked)")
        #endif
    }
    
    func isAppLocked() -> Bool {
        biometricLock.lock()
        defer { biometricLock.unlock() }
        return _isAppLocked
    }
    
    /// Accept an already-authenticated LAContext from BiometricAuthService.
    /// This prevents KeyManager from creating its own LAContext (which would trigger a SECOND Face ID prompt).
    /// Also pre-populates the private key cache so background tasks can sign without Face ID.
    func setBiometricContext(_ context: LAContext) {
        biometricLock.lock()
        _biometricLAContext = context
        // FIX KM-12: _biometricLAContextCreated removed (was never read)
        _isAppLocked = false
        biometricLock.unlock()
        
        // Pre-populate the key cache using the already-authenticated context.
        // This single keychain read (covered by the authenticated context) populates
        // the cache so all subsequent signMessage()/loadIdentityPrivateKey() calls
        // hit the cache instead of the Keychain — zero additional Face ID prompts.
        prePopulateKeyCache()
        
        #if DEBUG
        SecureLogger.debug("[KeyManager] Accepted authenticated LAContext from BiometricAuthService")
        #endif
    }
    
    /// Load both private keys into the in-memory cache using the current (authenticated) LAContext.
    /// Called once after successful biometric unlock. All subsequent reads hit the cache.
    private func prePopulateKeyCache() {
        // Read identity private key (triggers keychain read with authenticated LAContext)
        // FIX AUDIT-MAR-2026-14: Heap-Kopien werden nach dem Fuellen des Caches
        // genullt. Der Nutzen dieser Funktion ist der Seiteneffekt in
        // loadFromKeychain(), das die Werte in cachedIdentityPrivateKeyData bzw.
        // cachedSigningPrivateKeyData ablegt; die lokalen Kopien werden nicht
        // gebraucht. Frueher stand hier ein `defer` als letzte Anweisung des
        // Blocks — verhaltensgleich, aber der Compiler warnte zu Recht, dass es
        // sofort ausgefuehrt wird. Die Funktion wirft nicht, daher ist die
        // direkte Reihenfolge identisch.
        var identityData = loadFromKeychain(key: KeychainKeys.identityPrivateKey)
        var signingData = loadFromKeychain(key: "signing_private_key")

        #if DEBUG
        SecureLogger.debug("[KeyManager] Pre-populated key cache: identity=\(identityData != nil), signing=\(signingData != nil)")
        #endif

        identityData?.securelyWipe()
        signingData?.securelyWipe()
    }
    
    private func saveToKeychain(key: String, data: Data) throws {
        #if targetEnvironment(simulator)
        // SIMULATOR MODE: Use software keychain (Secure Enclave not available)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecAttrService as String: "app.ladon.messenger",
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecAttrSynchronizable as String: false
        ]
        
        // FIX F12: Atomic Keychain Save — Update first, Add only if not found
        let updateQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecAttrService as String: "app.ladon.messenger"
        ]
        let updateAttrs: [String: Any] = [
            kSecValueData as String: data
        ]
        var status = SecItemUpdate(updateQuery as CFDictionary, updateAttrs as CFDictionary)
        if status == errSecItemNotFound {
            status = SecItemAdd(query as CFDictionary, nil)
        }
        guard status == errSecSuccess else {
            #if DEBUG
            print("[KeyManager] ❌ KEYCHAIN SAVE FAILED for \(key): \(status)")
            #endif
            throw KeyManagerError.keychainError(status)
        }
        
        #if DEBUG
        print("[KeyManager] ✅ Key stored in SIMULATOR keychain (software-backed)")
        #endif
        #else
        // DEVICE MODE: Use hardware-backed keychain
        // FIX FACEID-DEFINITIVE: ALL keys use kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        // WITHOUT .biometryCurrentSet. Previously, .biometryCurrentSet caused iOS to
        // trigger a SYSTEM Face ID prompt on EVERY SecItemCopyMatching call.
        // Biometric protection is now PURELY at the application level:
        // - BiometricAuthService requires Face ID before showing any content
        // - _isAppLocked guard prevents key access before Face ID success
        // - Keys are wiped from RAM on background transition
        // This is the same architecture Signal uses for its biometric lock.
        
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecAttrService as String: "app.ladon.messenger",
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecAttrSynchronizable as String: false
        ]
        
        // FIX C-3: Atomic Keychain Save on device — Update first, Add only if not found.
        // Previously: SecItemDelete() → SecItemAdd() was non-atomic (app kill between = key loss).
        // SecItemUpdate cannot change kSecAttrAccessControl, so if update fails with
        // errSecParam (access control mismatch from old biometric flags), we fall back to
        // delete+add as a last resort migration step.
        
        let updateQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecAttrService as String: "app.ladon.messenger"
        ]
        let updateAttrs: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        let updateStatus = SecItemUpdate(updateQuery as CFDictionary, updateAttrs as CFDictionary)
        
        if updateStatus == errSecSuccess {
            // Atomic update succeeded
            #if DEBUG
            print("[KeyManager] ✅ Key atomically updated in device keychain")
            #endif
        } else if updateStatus == errSecItemNotFound {
            // Item doesn't exist yet — add it
            let status = SecItemAdd(query as CFDictionary, nil)
            guard status == errSecSuccess else {
                #if DEBUG
                print("[KeyManager] ❌ KEYCHAIN SAVE FAILED for \(key): \(status)")
                #endif
                throw KeyManagerError.keychainError(status)
            }
            #if DEBUG
            print("[KeyManager] ✅ Key stored in secure keychain (device-only, app-level biometric)")
            #endif
        } else {
            // Update failed (e.g., access control mismatch from old biometric flags)
            // Fall back to delete+add as migration step
            SecItemDelete(updateQuery as CFDictionary)
            let status = SecItemAdd(query as CFDictionary, nil)
            guard status == errSecSuccess else {
                #if DEBUG
                print("[KeyManager] ❌ KEYCHAIN MIGRATION FAILED for \(key): \(status)")
                #endif
                throw KeyManagerError.keychainError(status)
            }
            #if DEBUG
            print("[KeyManager] ✅ Key migrated in device keychain (old access control removed)")
            #endif
        }
        #endif
    }
    
    // MARK: - FIX H2: Secure Public APIs (instead of direct Keychain access)
    
    /// Public API: Returns only the PUBLIC Identity Key (safe)
    func getIdentityPublicKeyData() -> Data? {
        return loadFromKeychain(key: KeychainKeys.identityPublicKey)
    }
    
    // FIX H2: private — prevents other files from extracting Private Keys via loadFromKeychain()
    /// FIX FACEID-DEFINITIVE: Simplified loadFromKeychain — NO LAContext, NO biometric prompts.
    /// Biometric protection is at APPLICATION level (BiometricAuthService + _isAppLocked).
    /// Keys stored with kSecAttrAccessibleWhenUnlockedThisDeviceOnly only.
    private func loadFromKeychain(key: String) -> Data? {
        #if !targetEnvironment(simulator)
        // Identity/signing private keys use in-memory cache + app-level lock guard
        let isIdentityPrivateKey = key == KeychainKeys.identityPrivateKey
        let isSigningPrivateKey = key == "signing_private_key"
        let isSensitiveKey = isIdentityPrivateKey || isSigningPrivateKey
        
        if isSensitiveKey {
            // FIX A8-KM-01 + A9-KM-01: Atomic lock-check AND cache-read under single lock.
            // Previously split into two lock sections → TOCTOU race allowed lock bypass.
            biometricLock.lock()
            let isLocked = _isAppLocked
            let cachedData = isLocked ? nil : (isIdentityPrivateKey ? cachedIdentityPrivateKeyData : cachedSigningPrivateKeyData)
            biometricLock.unlock()
            
            if isLocked {
                #if DEBUG
                SecureLogger.debug("[KeyManager] \u{1F6AB} App locked, blocking keychain read for \(key)")
                #endif
                return nil
            }
            
            if let data = cachedData {
                #if DEBUG
                SecureLogger.debug("[KeyManager] Keychain read (cache hit): \(key)")
                #endif
                return data
            }
        }
        #endif
        
        // Plain keychain read — NO LAContext, NO biometric flags
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecAttrService as String: "app.ladon.messenger",
            kSecReturnData as String: true,
            kSecAttrSynchronizable as String: false
        ]
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess, let data = result as? Data else {
            #if DEBUG
            if status != errSecItemNotFound {
                SecureLogger.debug("[KeyManager] ⚠️ Keychain read failed for \(key): \(status)")
            }
            #endif
            return nil
        }
        
        #if !targetEnvironment(simulator)
        // Cache sensitive keys in memory
        if isSensitiveKey {
            biometricLock.lock()
            if isIdentityPrivateKey {
                cachedIdentityPrivateKeyData = data
            } else {
                cachedSigningPrivateKeyData = data
            }
            biometricLock.unlock()
        }
        #endif
        
        return data
    }
    
    /// Delete a key from Keychain (used for one-time prekey consumption)
    private func deleteFromKeychain(key: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecAttrService as String: "app.ladon.messenger",
            // FIX BUG-1: Match save/load attribute consistency.
            // Items are saved with kSecAttrSynchronizable: false — delete must match.
            kSecAttrSynchronizable as String: false
        ]
        SecItemDelete(query as CFDictionary)
    }
}

// MARK: - Supporting Types


enum KeyManagerError: Error, LocalizedError {
    case keyNotFound
    case sessionNotFound
    case keychainError(OSStatus)
    case encryptionFailed
    case decryptionFailed
    case authenticationFailed
    case signingKeyNotFound
    case signatureVerificationFailed
    case replayDetected(messageNumber: Int)  // 🟠 FIX #6: Replay attack detected
    case tooManySkippedMessages(Int)  // 🟠 FIX #8: OOM protection
    case invalidNonce  // 🔴 FIX #3: Proper nonce error
    case sealedSenderUAKMissing  // FIX H-4: Contact UAK not available for sealed sender
    case sessionCreationFailed(String)  // FIX HIGH-99: Abort when no SPK available
    case invalidPreKeyBundle  // FIX CRYPTO-H05: Invalid key material in pre-key bundle
    case invalidKeySize      // FIX KM-4: Key data has wrong size

    var errorDescription: String? {
        switch self {
        case .keyNotFound:
            return "Key not found"
        case .sessionNotFound:
            return "Session not found"
        case .keychainError(let status):
            return "Keychain error (OSStatus: \(status))"
        case .encryptionFailed:
            return "Encryption failed"
        case .decryptionFailed:
            return "Decryption failed"
        case .authenticationFailed:
            return "Authentication failed"
        case .signingKeyNotFound:
            return "Signing key not found"
        case .signatureVerificationFailed:
            return "Signature verification failed"
        case .replayDetected(let messageNumber):
            return "Replay detected (message #\(messageNumber))"
        case .tooManySkippedMessages(let count):
            return "Too many skipped messages (\(count))"
        case .invalidNonce:
            return "Invalid nonce"
        case .sealedSenderUAKMissing:
            return "Sealed sender UAK missing"
        case .sessionCreationFailed(let reason):
            return "Session creation failed: \(reason)"
        case .invalidPreKeyBundle:
            return "Invalid pre-key bundle"
        case .invalidKeySize:
            return "Invalid key size"
        }
    }
}

private enum KeychainKeys {
    static let identityPrivateKey = "identity_private_key"
    static let identityPublicKey = "identity_public_key"
    static let sessionPrefix = "session_"
}

// MARK: - Secure Memory Wiping
// securelyWipe() is defined in MemoryProtector.swift

// MARK: - Security Utils
// SecurityUtils class is defined in Security/SecurityUtils.swift
