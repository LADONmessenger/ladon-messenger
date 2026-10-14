import Foundation
import UIKit
import MachO

// MARK: - Dynamic Linker Functions
// _dyld_image_count and _dyld_get_image_name are available via MachO framework

// MARK: - Security Event Severity
enum SecurityEventSeverity: String {
    case low = "LOW"
    case medium = "MEDIUM"
    case high = "HIGH"
    case critical = "CRITICAL"
}

// MARK: - Panic Flag Filename (central constant — used by all wipe paths)
/// FIX M-12-AUDIT-MAR-2026: Single source of truth for panic flag filename.
/// Previously hardcoded as string literal in 4+ files — risk of typo causing missed panic detection.
let kPanicFlagFilename = ".app_state_cache"

/// Security utilities for device integrity checks
class SecurityUtils {
    static let shared = SecurityUtils()
    
    private init() {}
    
    // FIX SU-1: Replaced trivial "Ladon" 5-byte XOR key with random 16-byte key.
    // FIX XOR-01: Unique key per file — previously shared with JailbreakDetector.
    // If one key is extracted via binary RE, the other files remain protected.
    private static let _xorKey: [UInt8] = [
        0x3D, 0xE6, 0x52, 0xAB, 0x19, 0x7C, 0xF0, 0x8E,
        0xB4, 0x53, 0xC8, 0x2F, 0x76, 0xDA, 0x41, 0x93
    ]
    
    /// Runtime deobfuscation: XOR each byte with rotating key
    private static func deobfuscate(_ hex: String) -> String {
        var bytes: [UInt8] = []
        let chars = Array(hex)
        var i = 0
        while i + 1 < chars.count {
            let hi = UInt8(String(chars[i]), radix: 16) ?? 0
            let lo = UInt8(String(chars[i+1]), radix: 16) ?? 0
            bytes.append((hi << 4) | lo)
            i += 2
        }
        let key = _xorKey
        var decoded: [UInt8] = []
        for (idx, b) in bytes.enumerated() {
            decoded.append(b ^ key[idx % key.count])
        }
        return String(bytes: decoded, encoding: .utf8) ?? ""
    }
    // MARK: - Constant-Time Comparison
    
    /// FIX M-42: Constant-time data comparison wrapper.
    /// Use this for comparing MACs, hashes, or any security-critical byte sequences
    /// to prevent timing side-channel attacks.
    static func constantTimeEqual(_ a: Data, _ b: Data) -> Bool {
        return a.constantTimeEqual(b)
    }
    
    // MARK: - Security Event Logging
    
    /// Log security events (C3 fix: method was missing)
    func logSecurityEvent(_ event: String, severity: SecurityEventSeverity) {
        #if DEBUG
        print("[SECURITY] [\(severity.rawValue)] \(event)")
        #endif
        // In production, could write to encrypted local log
    }
    
    // MARK: - Jailbreak Detection
    
    /// Check if device is jailbroken or compromised
    /// K6 FIX: Delegates to authoritative JailbreakDetector.shared (single source of truth)
    /// FIX MED-11: Also checks isSuspiciousFilesPresent() (was dead code before)
    func isDeviceCompromised() -> Bool {
        let jailbrokenResult = JailbreakDetector.shared.isJailbroken()
        let debuggerResult = isDebuggerAttached()
        let suspiciousFiles = isSuspiciousFilesPresent()
        
        #if DEBUG
        print("[SECURITY] Device Compromise Check:")
        print("[SECURITY]   - Jailbroken (JailbreakDetector): \(jailbrokenResult)")
        print("[SECURITY]   - Debugger: \(debuggerResult)")
        print("[SECURITY]   - Suspicious Files: \(suspiciousFiles)")
        #endif
        
        #if DEBUG
        return jailbrokenResult
        #else
        return jailbrokenResult || debuggerResult || suspiciousFiles
        #endif
    }
    
    // FIX L-9: Removed duplicate isJailbroken() — SecurityUtils delegates to
    // JailbreakDetector.shared.isJailbroken() via isDeviceCompromised() (single source of truth)
    
    /// Check for debugger attachment
    private func isDebuggerAttached() -> Bool {
        var info = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var size = MemoryLayout<kinfo_proc>.stride
        
        let junk = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
        let debuggerIsAttached = junk == 0 && (info.kp_proc.p_flag & P_TRACED) != 0
        
        if debuggerIsAttached {
            #if DEBUG
            print("[SECURITY] DEBUGGER ATTACHED")
            #endif
        }
        
        return debuggerIsAttached
    }
    
    /// Check for suspicious files and code injection
    private func isSuspiciousFilesPresent() -> Bool {
        // FIX SU-1: Re-encoded with new 16-byte XOR key
        // FIX SU-2 (ADVERSARIAL): Removed Android path /data/local/tmp/frida-server (dead code on iOS)
        // FIX XOR-01: Re-encoded with unique SecurityUtils key (verified via Python)
        let suspiciousBinaries = [
            Self.deobfuscate("129321d9361e99e09b30b14c04b331e7"),                     // /usr/bin/cycript
            Self.deobfuscate("129321d936109fedd53fe74d1fb46ef0448520c26908"),           // /usr/local/bin/cycript
            Self.deobfuscate("129321d9361e99e09b2bbb4c19aa24"),                       // /usr/bin/xscope
            Self.deobfuscate("129321d9361e99e09b35ba4612bb6ce0589424ce6b")              // /usr/bin/frida-server
        ]
        
        for binary in suspiciousBinaries {
            if FileManager.default.fileExists(atPath: binary) {
                #if DEBUG
                print("[SECURITY] SUSPICIOUS BINARY FOUND: \(binary)")
                #endif
                return true
            }
        }
        
        return false
    }
    
    // MARK: - Runtime Protection
    
    /// Called on app launch - blocks if device compromised
    /// H16 FIX: Security checks now also run in DEBUG builds but only warn (don’t block).
    /// In RELEASE builds, compromised devices are fully blocked.
    func performSecurityCheck() {
        #if DEBUG
        // In DEBUG: run checks but only log warnings (allow simulator/dev devices)
        if isDeviceCompromised() {
            print("[SECURITY] ⚠️ Device appears compromised (DEBUG mode — not blocking)")
        }
        return
        #else
        if isDeviceCompromised() {
            lockAppDueToSecurityThreat()
        }
        #endif
    }
    
    /// Lock app and prevent access
    /// FIX SEC-B1: Now delegates to performComprehensiveWipe() — single consolidated wipe path.
    private func lockAppDueToSecurityThreat() {
        #if DEBUG
        print("[SECURITY] lockAppDueToSecurityThreat → performComprehensiveWipe()")
        #endif
        SecurityUtils.performComprehensiveWipe()
    }
    
    // MARK: - FIX SEC-B1 + LA-L1: Consolidated Wipe Path
    
    /// FIX SEC-B1: Single comprehensive wipe function used by ALL emergency paths.
    /// Previously, executePanicMode(), lockAppDueToSecurityThreat(), and emergencyLockdown()
    /// each contained ~130-160 lines of nearly identical wipe logic with subtle divergences
    /// (retry handling, service scope lists, threading). This consolidation ensures:
    /// 1. All paths perform exactly the same wipe steps — no coverage gaps
    /// 2. A single place to maintain when new Keychain services/key tags are added
    /// 3. Reduced code from ~450 lines across 3 functions to ~120 lines in one
    ///
    /// NOT @MainActor — can be called from any thread (RASP background timer, Main Thread, etc.)
    /// Uses Thread.isMainThread + semaphore for @MainActor-isolated InMemoryMessageStore access.
    static func performComprehensiveWipe() {
        // 1. Emergency memory wipe FIRST — before any other action
        MemoryProtector.shared.emergencyMemoryWipe()
        
        // 2. Set panic flag FIRST — before any Keychain deletions
        // If process crashes between KC deletion and flag write, app re-boots without lockout
        let panicAccount = "app_state_reset"
        let panicService = "app.ladon.messenger.state"
        let updateQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: panicAccount,
            kSecAttrService as String: panicService
        ]
        let updateAttrs: [String: Any] = [
            kSecValueData as String: Data([0x01]),
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]
        let updateStatus = SecItemUpdate(updateQuery as CFDictionary, updateAttrs as CFDictionary)
        if updateStatus == errSecItemNotFound {
            let addQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrAccount as String: panicAccount,
                kSecAttrService as String: panicService,
                kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                kSecValueData as String: Data([0x01])
            ]
            let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
            if addStatus != errSecSuccess {
                #if DEBUG
                print("[WIPE] ⚠️ Panic flag write failed: \(addStatus) — retrying...")
                #endif
                SecItemDelete(updateQuery as CFDictionary)
                let retryStatus = SecItemAdd(addQuery as CFDictionary, nil)
                if retryStatus != errSecSuccess {
                    #if DEBUG
                    print("[WIPE] ⚠️ Panic flag retry failed: \(retryStatus) — file-based fallback")
                    #endif
                    if let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first {
                        try? FileManager.default.createDirectory(at: appSupport, withIntermediateDirectories: true)
                        let panicFile = appSupport.appendingPathComponent(kPanicFlagFilename)
                        // P7-IOS-BUG-18: completeUnlessOpen so the file remains
                        // readable on next app launch before first unlock
                        // (panic flag is checked from LadonApp.init before any
                        // user interaction). `.complete` would block reads
                        // until the user unlocks, defeating the panic flag.
                        try? Data([0x01]).write(to: panicFile, options: [.atomic, .completeFileProtectionUnlessOpen])
                    }
                }
            }
        }
        
        // 3. Delete ALL Ladon-owned Keychain items
        deleteAllKeychainItems()
        
        // 4. Re-set panic flag after Keychain deletions
        // The AccessGroup fallback query in deleteAllKeychainItems() inadvertently
        // deletes the panic flag. Re-inserting ensures lockout survives.
        let reSetPanicFlag: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: panicAccount,
            kSecAttrService as String: panicService,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecValueData as String: Data([0x01])
        ]
        SecItemAdd(reSetPanicFlag as CFDictionary, nil)
        
        // 5. Destroy encrypted SQLite database
        EncryptedDatabase.shared.destroyAll()
        
        // 6. Wipe InMemoryMessageStore (@MainActor — requires thread-aware dispatch)
        // P7-IOS-BUG-08: replace DispatchSemaphore.wait with DispatchQueue.main.sync.
        // The old pattern timed out after 1 s and could silently drop the wipe
        // if the main queue happened to be busy under load (which is exactly
        // when a wipe matters most). Under Swift Concurrency, holding a
        // semaphore across a queue hop is also a deadlock smell (the awaiter
        // may itself be the future-resumer of the spawned work). The
        // Thread.isMainThread guard above already forbids main→main sync,
        // so DispatchQueue.main.sync from any non-main thread is deadlock-free
        // and runs the wipe to completion before we return.
        if Thread.isMainThread {
            MainActor.assumeIsolated {
                InMemoryMessageStore.shared.securelyWipeMessages()
                InMemoryMessageStore.shared.clearAll()
            }
        } else {
            DispatchQueue.main.sync {
                InMemoryMessageStore.shared.securelyWipeMessages()
                InMemoryMessageStore.shared.clearAll()
            }
        }
        
        // 7. Clear URL cache, cookies, UserDefaults
        URLCache.shared.removeAllCachedResponses()
        HTTPCookieStorage.shared.removeCookies(since: Date.distantPast)
        if let bundleID = Bundle.main.bundleIdentifier {
            UserDefaults.standard.removePersistentDomain(forName: bundleID)
        }

        // 8. Filesystem cleanup — remove all forensic artifacts
        let fm = FileManager.default
        // Documents/
        if let docsDir = fm.urls(for: .documentDirectory, in: .userDomainMask).first,
           let contents = try? fm.contentsOfDirectory(at: docsDir, includingPropertiesForKeys: nil) {
            for file in contents { try? fm.removeItem(at: file) }
        }
        // Application Support/ (DB, nonces, sequences, tor data — skip panic flag)
        if let appSupportDir = fm.urls(for: .applicationSupportDirectory, in: .userDomainMask).first,
           let contents = try? fm.contentsOfDirectory(at: appSupportDir, includingPropertiesForKeys: nil) {
            for file in contents {
                if file.lastPathComponent == kPanicFlagFilename { continue }
                try? fm.removeItem(at: file)
            }
        }
        // Caches/ (contents only — keep directory itself intact)
        if let cachesDir = fm.urls(for: .cachesDirectory, in: .userDomainMask).first,
           let cacheContents = try? fm.contentsOfDirectory(at: cachesDir, includingPropertiesForKeys: nil) {
            for file in cacheContents { try? fm.removeItem(at: file) }
        }
        // tmp/
        if let tmpContents = try? fm.contentsOfDirectory(at: fm.temporaryDirectory, includingPropertiesForKeys: nil) {
            for file in tmpContents { try? fm.removeItem(at: file) }
        }
        // Library/Preferences/
        if let libDir = fm.urls(for: .libraryDirectory, in: .userDomainMask).first {
            let prefsDir = libDir.appendingPathComponent("Preferences")
            if let contents = try? fm.contentsOfDirectory(at: prefsDir, includingPropertiesForKeys: nil) {
                for file in contents { try? fm.removeItem(at: file) }
            }
        }
        
        // 9. Terminate — no recoverable state should remain
        #if DEBUG
        print("[WIPE] 🔴 COMPREHENSIVE WIPE COMPLETE — terminating process")
        #endif
        kill(getpid(), SIGKILL)
        abort()
    }
    
    /// Delete ALL Ladon-owned Keychain items (emergency zeroize)
    /// FIX SU-5 (ADVERSARIAL): Delete ALL keychain classes, not just GenericPassword.
    /// FIX SU-1: All queries now scoped to Ladon-specific service/tag to avoid deleting
    /// system or third-party keychain items.
    /// FIX AUDIT-R9-12: Fix wrong kSecAttrApplicationTag, add missing services, preserve panic flag
    static func deleteAllKeychainItems() {
        let ladonService = "app.ladon.messenger"
        
        let queries: [[String: Any]] = [
            // P8-AUDIT8-IOS-33 (audit F2): the Secure-Enclave chip keys first —
            // without them every sealed V2 secret is unreadable, even if a
            // later delete in this list were interrupted.
            [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: SealedKeychainV2.chipService,
                kSecAttrSynchronizable as String: false
            ],
            // Generic passwords — all 5 active services
            [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: ladonService,
                kSecAttrSynchronizable as String: false
            ],
            [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: "app.ladon.messenger.migrations",
                kSecAttrSynchronizable as String: false
            ],
            [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: "app.ladon.messenger.rasp",
                kSecAttrSynchronizable as String: false
            ],
            [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: "app.ladon.messenger.msgstore",
                kSecAttrSynchronizable as String: false
            ],
            [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: "app.ladon.messenger.canary",
                kSecAttrSynchronizable as String: false
            ],
            [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: "app.ladon.messenger.v2",
                kSecAttrSynchronizable as String: false
            ],
            [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: "app.ladon.messenger.v2.peers",
                kSecAttrSynchronizable as String: false
            ],
            [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: "app.ladon.messenger.v2.ratchet",
                kSecAttrSynchronizable as String: false
            ],
            [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: "app.ladon.messenger.v2.prekeys",
                kSecAttrSynchronizable as String: false
            ],
            [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: "app.ladon.messenger.v2.spenttokens",
                kSecAttrSynchronizable as String: false
            ],
            // Delivery keys (own K, contacts' K), block list, rotation job —
            // Addendum A1. Contacts' recipient ids are part of the account names.
            [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: "app.ladon.messenger.v2.delivery",
                kSecAttrSynchronizable as String: false
            ],
            // AccessGroup fallback for pre-migration items
            [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrAccessGroup as String: Bundle.main.bundleIdentifier ?? ladonService,
                kSecAttrSynchronizable as String: false
            ],
            // FIX AUDIT-R9-12: Delete keys by EXACT known tags (was using wrong tag "app.ladon.messenger")
            [
                kSecClass as String: kSecClassKey,
                kSecAttrApplicationTag as String: "com.ladon.identity".data(using: .utf8)!,
                kSecAttrSynchronizable as String: false
            ],
            [
                kSecClass as String: kSecClassKey,
                kSecAttrApplicationTag as String: "com.ladon.signing".data(using: .utf8)!,
                kSecAttrSynchronizable as String: false
            ],
            [
                kSecClass as String: kSecClassKey,
                kSecAttrApplicationTag as String: "com.ladon.spk".data(using: .utf8)!,
                kSecAttrSynchronizable as String: false
            ],
            [
                kSecClass as String: kSecClassKey,
                kSecAttrApplicationTag as String: "com.ladon.biometric.key".data(using: .utf8)!,
                kSecAttrSynchronizable as String: false
            ],
            [
                kSecClass as String: kSecClassKey,
                kSecAttrApplicationTag as String: "com.ladon.prekey".data(using: .utf8)!,
                kSecAttrSynchronizable as String: false
            ],
            [
                kSecClass as String: kSecClassKey,
                kSecAttrApplicationTag as String: "com.ladon.ephemeral".data(using: .utf8)!,
                kSecAttrSynchronizable as String: false
            ],
            [
                kSecClass as String: kSecClassKey,
                kSecAttrApplicationTag as String: "com.ladon.hwkey.dataProtection".data(using: .utf8)!,
                kSecAttrSynchronizable as String: false
            ],
            [
                kSecClass as String: kSecClassKey,
                kSecAttrApplicationTag as String: "com.ladon.hwkey.sessionEphemeral".data(using: .utf8)!,
                kSecAttrSynchronizable as String: false
            ],
            [
                kSecClass as String: kSecClassKey,
                kSecAttrApplicationTag as String: "com.ladon.hwkey.messageSealing".data(using: .utf8)!,
                kSecAttrSynchronizable as String: false
            ],
            [
                kSecClass as String: kSecClassKey,
                kSecAttrApplicationTag as String: "com.ladon.hwkey.session-wrap".data(using: .utf8)!,
                kSecAttrSynchronizable as String: false
            ],
            // Also delete keys with Ladon label
            [
                kSecClass as String: kSecClassKey,
                kSecAttrLabel as String: ladonService,
                kSecAttrSynchronizable as String: false
            ],
            // FIX SU-5: Also delete internet passwords (app-scoped on iOS)
            [
                kSecClass as String: kSecClassInternetPassword,
                kSecAttrSynchronizable as String: false
            ],
            // FIX SU-5 + R12-F5: Delete certificates with Label-scoping (parity with emergencyLockdown/executePanicMode)
            [
                kSecClass as String: kSecClassCertificate,
                kSecAttrLabel as String: ladonService,
                kSecAttrSynchronizable as String: false
            ],
            // FIX SU-5 + R12-F5: Delete identity items with Label-scoping
            [
                kSecClass as String: kSecClassIdentity,
                kSecAttrLabel as String: ladonService,
                kSecAttrSynchronizable as String: false
            ]
            // FIX AUDIT-R9-12: Removed "app.ladon.messenger.state" — panic flag must survive emergency wipe
        ]
        for query in queries {
            let status = SecItemDelete(query as CFDictionary)
            if status != errSecSuccess && status != errSecItemNotFound {
                #if DEBUG
                print("[SECURITY] Failed to delete keychain items: \(status)")
                #endif
            }
        }
    }
}
