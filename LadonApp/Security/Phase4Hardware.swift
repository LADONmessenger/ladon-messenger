import Foundation
import Security
import CryptoKit

/// Phase 4 - Hardware Security Integration
/// Secure Enclave key derivation and memory page protection

// MARK: - Hardware-Bound Key Derivation (Secure Enclave)

class HardwareKeyDerivation {
    static let shared = HardwareKeyDerivation()
    private init() {}
    
    /// Indicates the SE key was re-created (previous key lost → existing sessions invalidated)
    private(set) var didRecreateKey = false
    
    /// FIX AUDIT-R17-F5: Serialize Secure Enclave access to prevent race conditions.
    /// Concurrent calls could create duplicate SE keys or read stale Keychain state.
    private let seLock = NSLock()
    
    /// Derive a symmetric key bound to device hardware via Secure Enclave.
    /// The private key NEVER leaves the Secure Enclave — we derive a symmetric
    /// key by performing ECDH with ourselves (private × public) so the result
    /// is hardware-bound and cannot be extracted.
    /// FIX MED-8: Checks SE availability before attempting key creation.
    func deriveHardwareBoundKey(label: String) throws -> SymmetricKey {
        seLock.lock()
        defer { seLock.unlock() }
        
        let tag = "com.ladon.hwkey.\(label)".data(using: .utf8)!
        
        // FIX MED-8: Verify Secure Enclave availability before using it
        guard SecureEnclaveAvailability.isAvailable else {
            throw HardwareKeyError.secureEnclaveUnavailable
        }
        
        // Check if key already exists
        let existingQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
            kSecAttrSynchronizable as String: false
        ]
        
        var existingItem: CFTypeRef?
        let existingStatus = SecItemCopyMatching(existingQuery as CFDictionary, &existingItem)
        
        let privateKey: SecKey
        
        if existingStatus == errSecSuccess,
           let existingItem = existingItem,
           CFGetTypeID(existingItem) == SecKeyGetTypeID() {
            // FIX LOW: Safe to unwrap — CFTypeID check guarantees SecKey
            privateKey = unsafeBitCast(existingItem, to: SecKey.self)
        } else {
            // FIX LOW-13: Detect SE key re-creation — existing sessions become undecryptable
            // FIX LOW F-IA-3: Use Keychain instead of unencrypted UserDefaults for SE key flag
            // FIX RC-10: kSecAttrAccessible removed from read query — only relevant for writes
            let flagQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrAccount as String: "app.ladon.messenger.se_key_created",
                kSecAttrService as String: "app.ladon.messenger"
            ]
            let hadSessionsBefore = SecItemCopyMatching(flagQuery as CFDictionary, nil) == errSecSuccess
            if hadSessionsBefore {
                didRecreateKey = true
                #if DEBUG
                SecureLogger.debug("SE key was recreated")
                #endif
            }
            
            // Create new Secure Enclave key — hardware-bound but NO biometric gate.
            // Biometric on every key-use would trigger Face ID on every message send/receive.
            guard let access = SecAccessControlCreateWithFlags(
                nil,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                [.privateKeyUsage],
                nil
            ) else {
                throw HardwareKeyError.generationFailed
            }
            
            let attributes: [String: Any] = [
                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrKeySizeInBits as String: 256,
                kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
                kSecPrivateKeyAttrs as String: [
                    kSecAttrIsPermanent as String: true,
                    kSecAttrApplicationTag as String: tag,
                    kSecAttrAccessControl as String: access
                ]
            ]
            
            var error: Unmanaged<CFError>?
            guard let newKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
                throw HardwareKeyError.generationFailed
            }
            privateKey = newKey
            // FIX LOW-13: Mark that we have created an SE key
            // FIX LOW F-IA-3: Store SE key flag in Keychain
            // FIX R19-K2: Separate delete query without kSecValueData (unnecessary for delete ops)
            let flagDeleteQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrAccount as String: "app.ladon.messenger.se_key_created",
                kSecAttrService as String: "app.ladon.messenger"
            ]
            let flagStore: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrAccount as String: "app.ladon.messenger.se_key_created",
                kSecAttrService as String: "app.ladon.messenger",
                kSecValueData as String: Data([1]),
                kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                kSecAttrSynchronizable as String: false
            ]
            SecItemDelete(flagDeleteQuery as CFDictionary)
            let flagStatus = SecItemAdd(flagStore as CFDictionary, nil)
            if flagStatus != errSecSuccess {
                SecureLogger.error("[Phase4Hardware] Keychain write failed for SE key flag: \(flagStatus)")
            }
        }
        
        // Derive symmetric key: ECDH(private, public) → HKDF → 256-bit key
        // This is hardware-bound because the ECDH happens inside the Secure Enclave
        // FIX HIGH-14: Self-ECDH (priv × own-pub) is INTENTIONAL here:
        // • The SE private key NEVER leaves the Secure Enclave
        // • ECDH(priv, pub) produces a deterministic, hardware-bound secret
        // • The HKDF step below mixes in label+salt to derive unique per-purpose keys
        // • This is equivalent to a hardware KDF — the "peer" is ourselves by design
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw HardwareKeyError.exportFailed
        }
        
        // Use the public key as "peer" for key agreement inside Secure Enclave
        var error: Unmanaged<CFError>?
        guard var sharedSecret = SecKeyCopyKeyExchangeResult(
            privateKey,
            .ecdhKeyExchangeStandard,
            publicKey,
            [:] as CFDictionary,
            &error
        ) as Data? else {
            throw HardwareKeyError.generationFailed
        }
        
        // HKDF to derive final key from shared secret
        let inputKey = SymmetricKey(data: sharedSecret)
        let derivedKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: inputKey,
            salt: Data("LadonHWKey-v1".utf8),
            info: Data(label.utf8),
            outputByteCount: 32
        )
        
        // FIX MED-24: Wipe shared secret after key derivation
        sharedSecret.withUnsafeMutableBytes { buffer in
            if let base = buffer.baseAddress {
                memset_s(base, buffer.count, 0, buffer.count)
            }
        }
        
        // FIX M-40: Validate derived key has expected length (256 bits for AES/ChaCha20)
        guard derivedKey.bitCount == 256 else {
            throw HardwareKeyError.generationFailed
        }
        
        return derivedKey
    }
}

enum HardwareKeyError: Error {
    case generationFailed
    case exportFailed
    case secureEnclaveUnavailable
}

// MARK: - FIX MED-8: Secure Enclave Availability Check

enum SecureEnclaveAvailability {
    // FIX M-21: Cache the SE availability check result to avoid creating
    // a temporary Secure Enclave key on every call
    private static var _cachedResult: Bool?
    
    /// Check if the Secure Enclave is available on this device.
    /// Simulator and very old devices lack SE hardware.
    static var isAvailable: Bool {
        if let cached = _cachedResult { return cached }
        let result = _checkAvailability()
        _cachedResult = result
        return result
    }
    
    private static func _checkAvailability() -> Bool {
        #if targetEnvironment(simulator)
        return false
        #else
        // Try to create a temporary SE key to verify availability
        let testAccess = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage],
            nil
        )
        guard let access = testAccess else { return false }
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: false,
                kSecAttrAccessControl as String: access
            ]
        ]
        var error: Unmanaged<CFError>?
        if let key = SecKeyCreateRandomKey(attrs as CFDictionary, &error) {
            // Key created successfully, SE is available. Key is non-permanent, auto-cleaned.
            _ = key
            return true
        }
        return false
        #endif
    }
}

// MARK: - Memory Page Protection (mlock)

class MemoryPageProtection {
    static let shared = MemoryPageProtection()
    private init() {}
    
    // FIX LOW-27: Track allocated pointers to prevent leaks and enable bulk wipe
    private var allocations: [(UnsafeMutableRawPointer, Int)] = []
    private let allocLock = NSLock()
    
    /// Allocate memory locked to RAM (cannot be swapped to disk)
    func allocateLockedMemory(size: Int) -> UnsafeMutableRawPointer? {
        let ptr = malloc(size)
        if let ptr = ptr {
            // FIX MED-26: Zero-initialize buffer immediately to prevent stale heap data leaks
            memset(ptr, 0, size)
            
            let result = mlock(ptr, size)
            if result != 0 {
                // FIX L-8: Log mlock failure in all builds (not just DEBUG)
                // so operations can detect memory-pressure swapping risk
                let errCode = errno
                #if DEBUG
                print("[MemoryPageProtection] ⚠️ mlock failed with errno \(errCode) — memory may be swappable")
                #endif
                SecureLogger.info("[MemoryPageProtection] mlock failed (errno \(errCode), size \(size))")
                // Continue anyway — best effort. The data is still usable,
                // but may be paged to disk under memory pressure.
            }
            
            // FIX LOW-27: Track allocation for leak prevention
            allocLock.lock()
            allocations.append((ptr, size))
            allocLock.unlock()
        }
        return ptr
    }
    
    /// Free locked memory — wipe before releasing
    func freeLockedMemory(_ ptr: UnsafeMutableRawPointer, size: Int) {
        // FIX A13-5: Acquire lock BEFORE free() to prevent double-free race with wipeAllAllocations.
        // Previously: free(ptr) happened before lock → wipeAllAllocations could free same ptr.
        allocLock.lock()
        guard allocations.contains(where: { $0.0 == ptr }) else {
            allocLock.unlock()
            return  // Already freed by wipeAllAllocations
        }
        allocations.removeAll { $0.0 == ptr }
        allocLock.unlock()
        
        // Secure wipe before freeing
        // FIX MED-03: Use memset_s (C11 guaranteed, cannot be eliminated by optimizer)
        memset_s(ptr, size, 0xFF, size)
        memset_s(ptr, size, 0x00, size)
        
        munlock(ptr, size)
        free(ptr)
    }
    
    /// FIX LOW-27 + MED-A15: Wipe and free all tracked allocations (emergency cleanup)
    /// Holds lock during entire operation to prevent double-free race with freeLockedMemory
    func wipeAllAllocations() {
        allocLock.lock()
        let current = allocations
        allocations.removeAll()
        
        for (ptr, size) in current {
            memset_s(ptr, size, 0, size)
            munlock(ptr, size)
            free(ptr)
        }
        allocLock.unlock()
    }
    
    /// Copy sensitive data to locked memory page.
    /// The caller is responsible for wiping the original `data` after this call.
    func protectData(_ data: inout Data) -> UnsafeMutableRawPointer? {
        guard let ptr = allocateLockedMemory(size: data.count) else {
            return nil
        }
        
        data.withUnsafeBytes { dataPtr in
            guard let base = dataPtr.baseAddress else { return }
            memcpy(ptr, base, data.count)
        }
        
        // FIX H-5: Use memset_s (C11 guaranteed, cannot be eliminated by optimizer)
        // memset() could be dead-store eliminated since data is not read after this
        data.withUnsafeMutableBytes { bytes in
            guard let base = bytes.baseAddress else { return }
            memset_s(base, bytes.count, 0xFF, bytes.count)
            memset_s(base, bytes.count, 0x00, bytes.count)
        }
        
        return ptr
    }
}

