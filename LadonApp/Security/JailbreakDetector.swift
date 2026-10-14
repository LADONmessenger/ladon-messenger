import Foundation
import UIKit
import Darwin

/// Jailbreak Detection - App terminates if compromised device detected
class JailbreakDetector {
    
    static let shared = JailbreakDetector()
    private init() {}
    
    // FIX SM-H3 + HIGH-9: XOR-based obfuscation with non-obvious multi-byte key.
    // Previously used [0x4C, 0x61, 0x64, 0x6F, 0x6E] ("Ladon") — the app's own name,
    // trivially guessable. This 16-byte key is not related to any public string
    // and requires binary RE with IDA/Ghidra to extract.
    private static let _xorKey: [UInt8] = [
        0x7A, 0x3F, 0x91, 0xD4, 0x58, 0xE2, 0x1B, 0xA6,
        0xC3, 0x47, 0x0D, 0xF8, 0x65, 0x2E, 0x84, 0xB9
    ]
    
    /// Runtime deobfuscation: XOR each byte with rotating key, then decode UTF-8
    private static func deobfuscate(_ hex: String) -> String {
        // Decode hex string to bytes
        var bytes: [UInt8] = []
        let chars = Array(hex)
        var i = 0
        while i + 1 < chars.count {
            let hi = UInt8(String(chars[i]), radix: 16) ?? 0
            let lo = UInt8(String(chars[i+1]), radix: 16) ?? 0
            bytes.append((hi << 4) | lo)
            i += 2
        }
        // XOR-decode with rotating key
        let key = _xorKey
        var decoded: [UInt8] = []
        for (idx, b) in bytes.enumerated() {
            decoded.append(b ^ key[idx % key.count])
        }
        return String(bytes: decoded, encoding: .utf8) ?? ""
    }
    
    /// Compile-time helper: XOR-encode a path string to hex (for generating constants)
    /// Usage in playground: print(JailbreakDetector.obfuscate("/bin/bash"))
    #if DEBUG
    static func obfuscate(_ input: String) -> String {
        let key = _xorKey
        return Array(input.utf8).enumerated().map { idx, b in
            String(format: "%02x", b ^ key[idx % key.count])
        }.joined()
    }
    #endif
    
    /// Comprehensive jailbreak detection with multiple techniques
    func isJailbroken() -> Bool {
        #if targetEnvironment(simulator)
        // Allow simulator for development
        return false
        #else
        // P8-AUDIT8-IOS-13 (audit F6): no signal another app can produce.
        // Registering a URL scheme such as `sileo` or listening on
        // 127.0.0.1:27042 needs no jailbreak — any installed app could do it
        // and trigger the irreversible wipe below. Those two checks
        // (canOpenURL on jailbreak-app schemes, the Frida-port connect) are
        // removed; every remaining check observes this process or the system
        // itself.
        return checkSuspiciousFiles() ||
               checkWriteablePaths() ||
               checkFork() ||
               checkDynamicLibraries() ||
               checkBinaryIntegrity() ||  // 🟡 FIX #12: Enhanced checks
               checkKernelPatch() ||      // 🟡 FIX #12: Kernel-level checks
               checkDYLDInsertLibraries() ||  // FIX MED-12: Check DYLD injection
               checkSandboxIntegrity()        // FIX M-47: Sandbox escape detection
        #endif
    }
    
    /// 🟡 FIX #12: Check if binary has been modified (dyld injection possible)
    private func checkBinaryIntegrity() -> Bool {
        // Check if unexpected libraries are loaded (Jailbreak tweaks)
        let imageCount = ladon_dyld_image_count()
        for i in 0..<imageCount {
            guard let imageName = ladon_dyld_get_image_name(i) else { continue }
            let name = String(cString: imageName)
            
            // FIX SM-H3: XOR-obfuscated red flag strings (not base64)
            let redFlags = [
                "0e48f4b53391",       // tweaks
                "3946f5bd39",         // Cydia
                "1c4df8b039",         // frida
                "094af3a72c907ad2a6"  // substrate
            ].map { Self.deobfuscate($0) }
            if redFlags.contains(where: { !$0.isEmpty && name.contains($0) }) {
                #if DEBUG
                print("🚨 JAILBREAK: Suspicious dyld library: \(name)")
                #endif
                return true
            }
        }
        return false
    }
    
    /// K9 FIX: Removed false positive sysctl check — it succeeds on stock iOS.
    /// Instead check for rootless jailbreak artifacts.
    private func checkKernelPatch() -> Bool {
        // FIX SM-H3: XOR-obfuscated paths (not base64)
        // Only check paths that are EXCLUSIVELY jailbreak-related.
        // /var/containers/Bundle/Application is the NORMAL iOS app install path — NOT jailbreak.
        let rootlessPaths = [
            "5549f0a6778879",         // /var/jb
            "5549f0a677887989b6347fd70947e6",  // /var/jb/usr/lib
            "5549f0a677ae52e4ec",     // /var/LIB/
            "554fe3b13a8d74d2ec2d6f"  // /preboot/jb
        ].map { Self.deobfuscate($0) }
        for path in rootlessPaths {
            guard !path.isEmpty else { continue }
            if FileManager.default.fileExists(atPath: path) {
                #if DEBUG
                print("🚨 JAILBREAK: Rootless jailbreak path found: \(path)")
                #endif
                return true
            }
        }
        return false
    }
    
    /// Check for common jailbreak files
    private func checkSuspiciousFiles() -> Bool {
        // FIX SM-H3: XOR-obfuscated paths (not base64)
        let paths = [
            "557ee1a4348b78c7b72e62961601c7c01e56f0fa39926b",
            "5573f8b62a8369dfec0a629a0c42e1ea0f5de2a02a836fc3ec0a629a0c42e1ea0f5de2a02a836fc3ed2374940c4c",
            "555df8ba77807ad5ab",
            "554ae2a6779179cfad687e8b0d4a",
            "555ae5b777836bd2",
            "554fe3bd2e836fc3ec316c8a4a42eddb555ee1a077",
            "554fe3bd2e836fc3ec316c8a4a42eddb555ce8b03183",
            "554fe3bd2e836fc3ec316c8a4a43ebdb1353f4fb148b79d4a23574d7366cd7dc0e4bf8ba3f9134f2ab22609d16",
            "5573f8b62a8369dfec0a629a0c42e1ea0f5de2a02a836fc3ec0374960443edda3656f3a6399072c3b0684191134bc7d5155cfafa288e72d5b7",
            "556ce8a72c8776898f2e6f8a045cfd96365ee4ba3b8a5fc7a62a62961601e7d61711f8bf3d9b35c4a12879d61542edca0e",
            "556ce8a72c8776898f2e6f8a045cfd96365ee4ba3b8a5fc7a62a62961601e7d61711e2b52d9072cded04749c0c4faaea0e5ee3a02d9235d6af2e7e8c",
            "554ae2a6778e72c4a63f689b4a5de2cd0a12e2b12a947ed4",
            "554ae2a6778072c8ec347e9001",
            "554ae2a6778e72c4a63f689b4a5df7d15754f4ad2b8b7cc8",
            "555df8ba779173",
            "555ae5b7779168ceec347e900171e7d61459f8b3",
            "554ae2a6778e72c4a63f689b4a4dfddd135ebe",
            "5549f0a677817ac5ab222299155a",
            "5549f0a6778e72c4ec267d8c",
            "5549f0a6778e72c4ec24749c0c4f",
            "554ae2a6779173c7b12222920447e8db085af0bf778b75cca62479950000f4d5134ce5"
        ].map { Self.deobfuscate($0) }
        
        for path in paths {
            if FileManager.default.fileExists(atPath: path) {
                #if DEBUG
                print("🚨 JAILBREAK: Suspicious file detected: \(path)")
                #endif
                return true
            }
            
            // Check if we can open file (shouldn't be possible on stock iOS)
            if let file = fopen(path, "r") {
                fclose(file)
                #if DEBUG
                print("🚨 JAILBREAK: Can open restricted file: \(path)")
                #endif
                return true
            }
        }
        
        return false
    }
    
    /// Check if we can write to system directories (shouldn't be possible)
    /// FIX SEC-14: Paths XOR-encoded with _xorKey (same obfuscation as other paths)
    /// Previously stored as raw ASCII bytes, making them visible in static analysis
    private static let _writeTestPaths: [String] = [
        "554fe3bd2e836fc3ec33688b1171eedb544be9a0",                                 // /private/test_jb.txt
        "554fe3bd2e836fc3ec316c8a4a43ebdb1353f4fb2c8768d29c2d6fd61156f0"             // /private/var/mobile/test_jb.txt
    ]

    private func checkWriteablePaths() -> Bool {
        let testString = UUID().uuidString
        let testPaths = Self._writeTestPaths.map { Self.deobfuscate($0) }
        for path in testPaths {
            do {
                try testString.write(toFile: path, atomically: true, encoding: .utf8)
                try? FileManager.default.removeItem(atPath: path)
                #if DEBUG
                print("🚨 JAILBREAK: Can write to restricted path: \(path)")
                #endif
                return true
            } catch {
                // Expected behavior on stock iOS
            }
        }
        
        return false
    }
    
    /// Check if process spawning is possible (shouldn't be on stock iOS due to sandbox).
    /// fork() is unavailable on modern iOS SDKs, so we try posix_spawn instead.
    private func checkFork() -> Bool {
        #if arch(arm64)
        // Try to spawn a trivial process — should fail on stock iOS
        var pid: pid_t = 0
        let argv: [UnsafeMutablePointer<CChar>?] = [
            strdup("/usr/bin/true"),
            nil
        ]
        defer { argv.forEach { free($0) } }
        
        // FIX M-03: Obfuscate posix_spawn path — was cleartext in binary.
        // XOR with 16-byte key (same as JailbreakDetector.deobfuscate)
        let spawnPath = Self.deobfuscate("554ae2a6778072c8ec337f8d00")
        let result = posix_spawn(&pid, spawnPath, nil, nil, argv, nil)
        if result == 0 {
            // Process spawned — jailbroken
            var status: Int32 = 0
            waitpid(pid, &status, 0)
            #if DEBUG
            print("🚨 JAILBREAK: posix_spawn() succeeded (pid: \(pid))")
            #endif
            return true
        }
        #endif
        return false
    }
    
    /// Check for injected dynamic libraries
    private func checkDynamicLibraries() -> Bool {
        // FIX SEC-1: Correctly XOR+hex-encoded library names (previously Base64 strings
        // were fed to the hex decoder, producing garbage that never matched anything).
        // MobileSubstrate, cycript, frida, libcycript
        let suspiciousLibs = [
            "3750f3bd348748d3a134798a045ae1",
            "1946f2a631926f",
            "1c4df8b039",
            "1656f3b7218169cfb333"
        ].map { Self.deobfuscate($0) }
        
        let images = ladon_dyld_image_count()
        guard images > 0 else {
            return false
        }
        
        for i in 0..<images {
            guard let imageName = ladon_dyld_get_image_name(i) else { continue }
            let name = String(cString: imageName).lowercased()
            
            for lib in suspiciousLibs {
                if name.contains(lib.lowercased()) {
                    #if DEBUG
                    print("🚨 JAILBREAK: Suspicious library loaded: \(name)")
                    #endif
                    return true
                }
            }
        }
        
        return false
    }
    
    // FIX C-16: Removed dead checkURLSchemes() — always returned false
    
    /// FIX MED-12: Check for DYLD_INSERT_LIBRARIES environment variable (library injection attack)
    private func checkDYLDInsertLibraries() -> Bool {
        #if DEBUG
        // FIX DEV-RASP-FP: Xcode's debugger injects DYLD_INSERT_LIBRARIES on every
        // debug run (e.g. /usr/lib/libViewDebuggerSupport.dylib for the View
        // Debugger), which would trip this check and wipe the app under Xcode.
        // DEBUG builds are never shipped, so skip the injection check in DEBUG.
        // RELEASE keeps full detection (below) unchanged — nothing weaker ships.
        if let val = getenv("DYLD_INSERT_LIBRARIES"), strlen(val) > 0 {
            print("ℹ️ [DEBUG] DYLD_INSERT_LIBRARIES set (\(String(cString: val))) — ignored in DEBUG (Xcode debugger).")
        }
        return false
        #else
        if let val = getenv("DYLD_INSERT_LIBRARIES"), strlen(val) > 0 {
            _ = val
            return true
        }
        return false
        #endif
    }
    
    /// FIX M-47: Check sandbox integrity — jailbroken devices often have a weakened sandbox
    /// that allows reading paths outside the app container.
    private func checkSandboxIntegrity() -> Bool {
        // Attempt to access paths outside the app sandbox.
        // On stock iOS, the sandbox prevents access to these.
        // FIX M-04: Obfuscate sandbox check paths — were cleartext in binary.
        // All other jailbreak-detection paths are XOR-obfuscated; these were missed.
        let restrictedPaths = [
            Self.deobfuscate("554fe3bd2e836fc3ec316c8a4a5cebd60e"),  // /private/var/root
            Self.deobfuscate("554fe3bd2e836fc3ec316c8a4a43ebdb1353f4fb148b79d4a23574d7264fe7d11f4cbeb7378f35c7b337619d4b43ebdb1353f4bd36916fc7af2b6c8c0c41eadd")  // /private/var/mobile/Library/Caches/com.apple.mobileinstallationd
        ]
        for path in restrictedPaths {
            if access(path, R_OK) == 0 {
                #if DEBUG
                print("🚨 JAILBREAK: Sandbox escape — can read restricted path: \(path)")
                #endif
                return true
            }
        }
        
        // Check if we can list contents of a restricted directory
        // FIX M-06: Obfuscate cleartext path — was readable in binary via strings(1)
        let restrictedDir = Self.deobfuscate("554fe3bd2e836fc3ec316c8a4a5cebd60e") // /private/var/root
        if let _ = try? FileManager.default.contentsOfDirectory(atPath: restrictedDir) {
            #if DEBUG
            print("🚨 JAILBREAK: Sandbox escape — can list restricted directory")
            #endif
            return true
        }
        
        return false
    }
    
    /// Enforce: terminate app if jailbroken
    /// FIX SEC-B1: Now delegates to performComprehensiveWipe() — single consolidated wipe path.
    func enforceIntegrity() {
        if isJailbroken() {
            #if DEBUG
            print("🚨🚨🚨 JAILBREAK DETECTED - APP TERMINATING → performComprehensiveWipe() 🚨🚨🚨")
            #endif
            
            // Pre-wipe: invalidate caches (specific to jailbreak path — defensive, before keys are deleted)
            KeyManager.shared.resetConversationState()
            KeyManager.shared.invalidateAllCaches()
            EncryptedDatabase.shared.invalidateKeyCache()
            
            SecurityUtils.performComprehensiveWipe()
        }
    }
}
