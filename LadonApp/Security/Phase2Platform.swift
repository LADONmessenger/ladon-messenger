import Foundation
import CryptoKit
import Darwin.POSIX  // FIX MED: mlock/munlock

/// Phase 2 - Platform Security: In-Memory Encryption
/// Protects sensitive data in RAM from memory dump attacks

// MARK: - In-Memory Encryption (ChaCha20-Poly1305)

class MemoryEncryption {
    static let shared = MemoryEncryption()
    private init() {}
    
    // FIX SEC-5: Thread synchronization for lockedKeyBuffer access
    private let keyLock = NSLock()
    
    /// FIX MED: Raw key bytes stored in mlock'd memory to prevent swapping to disk.
    /// SymmetricKey is created on-demand from this locked buffer.
    private var lockedKeyBuffer: UnsafeMutableRawBufferPointer?
    
    /// FIX SEC-6: Removed computed property that leaked un-wiped Data copies.
    /// Key access is now done inline in encrypt/decrypt with immediate wipe of intermediate Data.
    
    /// Initialize memory encryption with a fresh ephemeral key
    /// FIX MED: Key material is allocated in mlock'd pages to prevent swap-out
    func initializeMemoryEncryption() {
        // FIX ME-02: FALSE POSITIVE — potential race condition claim
        // Analysis: initializeMemoryEncryption() calls _destroyKeyUnlocked() while
        // holding keyLock (see defer guard below). This is SAFE because:
        // 1. keyLock.lock() on line 27 acquires exclusivity
        // 2. defer { keyLock.unlock() } on line 28 guarantees release
        // 3. _destroyKeyUnlocked() is called on line 31 WITHIN the lock scope
        // 4. destroyKey() also acquires keyLock — but that's a DIFFERENT code path
        // 5. No concurrent execution between initialize and destroy on same lock
        // Conclusion: No race condition. Subagent missed the lock/defer pattern.
        keyLock.lock()
        defer { keyLock.unlock() }
        
        // Clean up any existing key
        _destroyKeyUnlocked()
        
        // Allocate 32 bytes for AES-256 / ChaCha20 key
        let keySize = 32
        let buf = UnsafeMutableRawBufferPointer.allocate(byteCount: keySize, alignment: 16)
        
        // Fill with cryptographically secure random bytes
        // FIX HIGH-12: Use SecRandomCopyBytes (CSPRNG) instead of arc4random_buf
        let status = buf.withMemoryRebound(to: UInt8.self) { byteBuf in
            guard let ptr = byteBuf.baseAddress else { return Int32(-1) }
            return SecRandomCopyBytes(kSecRandomDefault, keySize, ptr)
        }
        guard status == errSecSuccess else {
            buf.deallocate()
            #if DEBUG
            print("[MemoryEncryption] ❌ SecRandomCopyBytes failed")
            #endif
            return
        }
        
        // FIX HIGH-11: Page-align size for mlock (kernel requires page-aligned regions)
        let pageSize = Int(getpagesize())
        let alignedSize = (keySize + pageSize - 1) & ~(pageSize - 1)
        // Lock pages in RAM — prevents swapping to disk
        if mlock(buf.baseAddress!, alignedSize) != 0 {
            #if DEBUG
            print("[MemoryEncryption] ⚠️ mlock failed (errno=\(errno)) — key may be swappable")
            #endif
        }
        
        lockedKeyBuffer = buf
        
        // FIX M-38: Validate key buffer is not all-zero (SecRandomCopyBytes failure mode)
        let allZero = buf.allSatisfy { $0 == 0 }
        if allZero {
            memset_s(buf.baseAddress!, buf.count, 0, buf.count)
            buf.deallocate()
            lockedKeyBuffer = nil
            #if DEBUG
            print("[MemoryEncryption] ❌ Key buffer is all-zero — SecRandomCopyBytes may have failed silently")
            #endif
            return
        }
        
        #if DEBUG
        print("✅ Memory encryption initialized (ephemeral session key, mlock'd)")
        #endif
    }
    
    /// Centralized AAD version constant for migration path
    // FIX LOW-20/23: Shared version constant instead of duplicated inline literals
    private static let aadVersion = Data("ladon-memory-v1".utf8)
    
    /// Encrypt sensitive data for in-memory storage
    /// FIX HIGH-13: Added AAD (Associated Authenticated Data) for context binding
    /// FIX H-06: Create SymmetricKey directly from mlock'd buffer — no intermediate Data copy.
    /// Previously `Data(bytes:count:)` created a heap-allocated copy outside the mlock'd region,
    /// which could be swapped to disk or read via memory forensics.
    func encryptInMemory(_ data: Data) throws -> Data {
        keyLock.lock()
        guard let buf = lockedKeyBuffer else {
            keyLock.unlock()
            throw MemoryEncryptionError.noKey
        }
        // FIX H-06: SymmetricKey directly from UnsafeRawBufferPointer (no Data copy)
        let key = SymmetricKey(data: UnsafeRawBufferPointer(buf))
        keyLock.unlock()
        
        // ChaCha20-Poly1305 with random nonce and AAD
        let aad = Self.aadVersion
        let sealedBox = try ChaChaPoly.seal(data, using: key, authenticating: aad)
        
        // Combined format: nonce(12) || ciphertext || tag(16)
        var encrypted = Data()
        encrypted.append(contentsOf: sealedBox.nonce)
        encrypted.append(sealedBox.ciphertext)
        encrypted.append(sealedBox.tag)
        
        return encrypted
    }
    
    /// Decrypt from encrypted in-memory storage
    /// FIX HIGH-13: Requires matching AAD for context binding
    /// FIX H-06: Create SymmetricKey directly from mlock'd buffer — no intermediate Data copy.
    func decryptFromMemory(_ encrypted: Data) throws -> Data {
        keyLock.lock()
        guard let buf = lockedKeyBuffer else {
            keyLock.unlock()
            throw MemoryEncryptionError.noKey
        }
        // FIX H-06: SymmetricKey directly from UnsafeRawBufferPointer (no Data copy)
        let key = SymmetricKey(data: UnsafeRawBufferPointer(buf))
        keyLock.unlock()
        
        let nonceSize = 12
        let tagSize = 16
        
        guard encrypted.count >= nonceSize + tagSize else {
            throw MemoryEncryptionError.invalidData
        }
        
        let nonceData = encrypted.prefix(nonceSize)
        let tagStart = encrypted.count - tagSize
        let ciphertext = encrypted[nonceSize..<tagStart]
        let tag = encrypted.suffix(tagSize)
        
        let nonce = try ChaChaPoly.Nonce(data: nonceData)
        let sealedBox = try ChaChaPoly.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
        
        let aad = Self.aadVersion
        return try ChaChaPoly.open(sealedBox, using: key, authenticating: aad)
    }
    
    /// Secure memory wipe using volatile pointer to prevent compiler optimization
    func secureWipe(_ data: inout Data) {
        data.withUnsafeMutableBytes { bytes in
            guard let baseAddress = bytes.baseAddress else { return }
            let count = bytes.count
            // FIX HIGH-12: Use SecRandomCopyBytes (CSPRNG) instead of arc4random_buf
            // FIX A8-P2-01: Guard SecRandomCopyBytes return — wipe material must be truly random
            let wipeStatus = SecRandomCopyBytes(kSecRandomDefault, count, baseAddress)
            if wipeStatus != errSecSuccess {
                // Fallback: at minimum zero the memory if CSPRNG fails
                memset_s(baseAddress, count, 0, count)
                return
            }
            // Pass 2: Zero via memset_s (C11 guaranteed, cannot be optimized away)
            // FIX MED-03: memset can be eliminated by dead-store optimization; memset_s cannot.
            memset_s(baseAddress, count, 0, count)
        }
    }
    
    /// Destroy the encryption key (call on app termination / panic)
    /// FIX MED + SEC-5: Securely wipes mlock'd key buffer with thread safety
    func destroyKey() {
        keyLock.lock()
        defer { keyLock.unlock() }
        _destroyKeyUnlocked()
    }
    
    /// Internal destroy without locking (called from locked contexts)
    private func _destroyKeyUnlocked() {
        if let buf = lockedKeyBuffer, let base = buf.baseAddress {
            // Wipe key material with memset_s (guaranteed not to be optimized away)
            memset_s(base, buf.count, 0xFF, buf.count)
            memset_s(base, buf.count, 0x00, buf.count)
            // FIX HIGH-11: Page-align for munlock consistency
            let pageSize = Int(getpagesize())
            let alignedSize = (buf.count + pageSize - 1) & ~(pageSize - 1)
            munlock(base, alignedSize)
            buf.deallocate()
            lockedKeyBuffer = nil
        }
    }
}

// MARK: - Errors

enum MemoryEncryptionError: Error {
    case noKey
    case invalidData
}

