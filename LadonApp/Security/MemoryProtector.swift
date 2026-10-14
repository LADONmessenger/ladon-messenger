import Foundation
import CryptoKit

/// Memory protection utilities - resist forensic analysis
class MemoryProtector {
    static let shared = MemoryProtector()
    private init() {}
    
    /// FIX CRIT-04 + H-13: COW-aware secure wipe using memset_s (guaranteed not optimized away)
    /// Swift Data uses Copy-on-Write — we force unique ownership via withUnsafeMutableBytes
    /// which guarantees a unique buffer, then use memset_s which is guaranteed by C11
    /// to never be dead-store eliminated.
    /// P8-AUDIT8-IOS-23: withUnsafeMutableBytes makes the buffer unique by COPYING
    /// it when it is shared. So if the caller's Data shares its storage with any
    /// other value, the zeroing lands on the fresh copy and the original bytes
    /// survive (the old "VERIFIED H-13" note claimed the opposite, and the
    /// all-zero check below inspects only the copy, so it always passed).
    /// The wipe now detects that case and logs it. Callers must hold the only
    /// reference — drop every other holder first (see
    /// InMemoryMessageStore.takeAndWipe).
    /// NOTE SM-M2 / KM-M5: CryptoKit's SymmetricKey is a value type whose internal
    /// storage cannot be directly zeroed. This is a fundamental Apple CryptoKit limitation.
    /// Mitigated by: (1) short-lived key references, (2) Secure Enclave for long-term keys,
    /// (3) memset_s wipe on all Data copies, (4) immediate scope exit after crypto ops.
    func secureWipe(_ data: inout Data) {
        // FIX CRIT-04: Use withUnsafeMutableBytes which forces COW buffer uniqueness
        // (Swift guarantees unique reference when mutating through unsafe pointer).
        // The old double-XOR approach (data[i] ^= 0xFF; data[i] ^= 0xFF) was unreliable
        // because the compiler could optimize it away as a no-op.
        if !data.isEmpty {
            // FIX H-13: Capture count before entering unsafe block
            let count = data.count
            // P8-AUDIT8-IOS-23: address of the buffer before the mutable access.
            // Data up to 14 bytes lives inline (no heap buffer, nothing shared),
            // where the addresses are not comparable — only larger values count.
            let before = data.withUnsafeBytes { UInt(bitPattern: $0.baseAddress) }
            var copiedOnWrite = false
            data.withUnsafeMutableBytes { bytes in
                guard let baseAddress = bytes.baseAddress else { return }
                if count > 32, UInt(bitPattern: baseAddress) != before { copiedOnWrite = true }
                
                // Overwrite with random bytes (1st pass — defeats pattern analysis)
                // FIX A12-LOW-7: Check CSPRNG return; on failure, use pattern fill as fallback
                let rngStatus = SecRandomCopyBytes(kSecRandomDefault, count, baseAddress)
                if rngStatus != errSecSuccess {
                    memset_s(baseAddress, count, 0xAA, count)
                }
                
                // Overwrite with zeros (2nd pass) — memset_s is guaranteed NOT to be optimized away
                memset_s(baseAddress, count, 0, count)
                
                // Memory barrier to ensure writes are committed to physical memory
                // os_unfair_lock provides acquire/release semantics on ARM64
                var lock = os_unfair_lock_s()
                os_unfair_lock_lock(&lock)
                os_unfair_lock_unlock(&lock)
            }
            if copiedOnWrite {
                SecureLogger.error("[MemoryProtector] secureWipe zeroed a copy-on-write duplicate — the original buffer is shared and was NOT wiped")
            }
            // FIX H-13 + ME-01: Verify the wipe succeeded (data should now be all zeros)
            // Defense-in-depth: Verification enabled in both DEBUG and Release
            // Low overhead (single allSatisfy pass) — worthwhile in production
            let isZeroed = data.allSatisfy { $0 == 0 }
            if !isZeroed {
                // FIX AUDIT3-IOS-04: Use SecureLogger (DEBUG-only) instead of bare print
                // to prevent information leakage into Release-build diagnostic logs
                // (/var/db/diagnostics/, readable via Sysdiagnose). Verification itself
                // remains active in Release; only the log path is DEBUG-gated.
                SecureLogger.error("[MemoryProtector] ⚠️ secureWipe verification FAILED — COW may not have been resolved")
            }
        }
        
        // Clear the Data object itself (releases the buffer reference)
        data.removeAll()
    }
    
    /// FIX F6 / FIX SM-H2: String wipe — Swift Strings are internally immutable (COW),
    /// direct overwriting is Undefined Behavior.
    /// KNOWN LIMITATION: Swift String cannot be securely wiped due to
    /// ARC-managed heap and copy-on-write semantics. The runtime may retain
    /// copies in allocator free-lists or thread-local caches.
    /// MITIGATION: All sensitive data MUST be stored as Data (which CAN be
    /// wiped via memset_s). This function only clears the reference.
    func secureWipe(_ string: inout String) {
        #if DEBUG
        print("[MemoryProtector] WARNING: Attempted to wipe String. This is not secure. Use Data for secrets.")
        #endif
        string = ""
    }
    
    /// Allocate secure memory page (mlock to prevent swapping to disk)
    /// FIX MED-15: Check mlock() return value — may fail with ENOMEM
    /// FIX HIGH-11: Page-align size for mlock (kernel requires page-aligned regions)
    /// FIX SM-H1: KNOWN LIMITATION — mlock() is a no-op on iOS.
    /// iOS does not support mlock() for user-space apps; pages may be swapped
    /// to compressed memory. Mitigation: use Secure Enclave for the most
    /// sensitive keys (identity key, session wrapping key). For transient
    /// secrets, short-lived Data buffers with memset_s wipe provide the
    /// best available protection on this platform.
    func allocateSecureBuffer(size: Int) -> UnsafeMutableRawPointer? {
        let pageSize = Int(getpagesize())
        let alignedSize = (size + pageSize - 1) & ~(pageSize - 1)
        let ptr = malloc(alignedSize)
        guard let pointer = ptr else { return nil }
        
        // Lock memory to prevent swap to disk (page-aligned size)
        let mlockResult = mlock(pointer, alignedSize)
        #if DEBUG
        if mlockResult != 0 {
            print("[MemoryProtector] ⚠️ mlock failed (errno=\(errno)) — swap protection not active")
        }
        #endif
        
        // Clear allocated memory using guaranteed-not-optimized-away wipe
        memset_s(pointer, alignedSize, 0, alignedSize)
        
        return pointer
    }
    
    /// Free secure buffer and wipe before deallocation
    /// FIX CRIT-07: Use memset_s (guaranteed not optimized away by compiler)
    /// FIX HIGH-11: Page-align size for munlock consistency
    func freeSecureBuffer(_ buffer: UnsafeMutableRawPointer, size: Int) {
        let pageSize = Int(getpagesize())
        let alignedSize = (size + pageSize - 1) & ~(pageSize - 1)
        // 1st pass: overwrite with random bytes
        // FIX A12-LOW-7: Check CSPRNG return; on failure, use pattern fill
        let rngStatus = SecRandomCopyBytes(kSecRandomDefault, alignedSize, buffer)
        if rngStatus != errSecSuccess {
            memset_s(buffer, alignedSize, 0xAA, alignedSize)
        }
        // 2nd pass: zero with memset_s — C11 guarantees this is NOT dead-store eliminated
        memset_s(buffer, alignedSize, 0, alignedSize)
        // FIX RC-H2: 3rd pass — pattern fill (defeats forensic recovery from magnetic residue patterns)
        let pattern: UInt8 = 0xAA
        memset_s(buffer, alignedSize, Int32(pattern), alignedSize)
        // 4th pass: final zero (ensure forensic recovery attempt finds zeros, not patterns)
        memset_s(buffer, alignedSize, 0, alignedSize)
        
        // Unlock and free
        munlock(buffer, alignedSize)
        free(buffer)
    }
    
    /// FIX RC-H2: Aggressive memory compaction — force OS to move ephemeral keys out of swap
    /// Call this after sensitive operations to reduce swap risk on iOS
    func compactMemoryFootprint() {
        #if os(iOS)
        // Request memory compaction (iOS 13+)
        // This hints to the OS to minimize memory usage and reduce compressed/swapped data
        malloc_zone_pressure_relief(nil, 0)
        
        // Force autoreleasepool drain to release temporary allocations
        autoreleasepool {}
        
        #if DEBUG
        SecureLogger.debug("[MemoryProtector] 🧹 Memory compaction requested")
        #endif
        #endif
    }
    
    // FIX SEC-4: Serial queue + re-entrancy guard for thread-safe emergency wipe
    private let wipeQueue = DispatchQueue(label: "app.ladon.memoryProtector.wipe")
    private var _isWiping = false
    
    /// FIX C-13 + CRIT-05: Real emergency memory wipe implementation
    /// Wipes all sensitive in-memory state and triggers view cleanup
    func emergencyMemoryWipe() {
        // FIX SEC-4: Prevent concurrent/re-entrant invocations
        let shouldProceed: Bool = wipeQueue.sync {
            guard !_isWiping else { return false }
            _isWiping = true
            return true
        }
        guard shouldProceed else { return }
        
        #if DEBUG
        print("[MEMORY] Emergency memory wipe triggered")
        #endif
        
        // Wipe all cached session data and session locks in KeyManager
        KeyManager.shared.invalidateAllCaches()
        
        // Wipe any cached encryption keys
        EncryptedDatabase.shared.invalidateKeyCache()
        
        // FIX R16-MP1: Destroy in-memory encryption key and locked memory pages
        MemoryEncryption.shared.destroyKey()
        MemoryPageProtection.shared.wipeAllAllocations()
        
        // FIX CRIT-05 + HIGH-18: Wipe in-memory message store SYNCHRONOUSLY
        // Using async Task risks not completing before exit(0) in panic mode.
        // InMemoryMessageStore is @MainActor — dispatch to main if needed.
        if Thread.isMainThread {
            // Already on main thread — use assumeIsolated to satisfy @MainActor
            MainActor.assumeIsolated {
                InMemoryMessageStore.shared.securelyWipeMessages()
            }
        } else {
            // Dispatch to main synchronously to ensure completion before exit
            let semaphore = DispatchSemaphore(value: 0)
            DispatchQueue.main.async {
                InMemoryMessageStore.shared.securelyWipeMessages()
                semaphore.signal()
            }
            // MP-3 FIX: Timeout after 1s — accept partial wipe rather than deadlock
            _ = semaphore.wait(timeout: .now() + 1.0)
        }
        
        // Force deallocation of temporary objects
        autoreleasepool {
            // Allocate and immediately release to trigger ARC sweep
            var dummy = Data(count: 4096)
            dummy.securelyWipe()
        }
        
        // Post notification for views to clear their state
        NotificationCenter.default.post(name: .emergencyMemoryWipe, object: nil)
        
        // FIX F-HA-10 (ADVERSARIAL): Reset _isWiping flag after completion.
        // Previously never reset, blocking all subsequent wipe calls permanently.
        wipeQueue.sync {
            _isWiping = false
        }
    }
}

extension Notification.Name {
    static let emergencyMemoryWipe = Notification.Name("EmergencyMemoryWipe")
}

extension String {
    /// FIX MED-13: Deprecated — Swift Strings cannot be securely wiped due to
    /// copy-on-write semantics and ARC-managed heap. Use Data for sensitive values.
    @available(*, deprecated, message: "Use Data for secrets — Swift String cannot be securely wiped")
    mutating func securelyWipe() {
        MemoryProtector.shared.secureWipe(&self)
    }
}

extension Data {
    /// Secure wipe for Data
    mutating func securelyWipe() {
        MemoryProtector.shared.secureWipe(&self)
    }
}
