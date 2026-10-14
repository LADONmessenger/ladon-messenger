import Foundation
import CryptoKit
import LadonArgon2

// =============================================================================
// SECURITY FEATURE TESTS — Verifies Argon2id
// =============================================================================
//
// Call SecurityFeatureTests.runAll() from AppDelegate or any debug entrypoint.
// Each test prints PASS/FAIL to the console.
// =============================================================================

// FIX LOW-08: Entire test suite is DEBUG-only to prevent console leaks in production
#if DEBUG
enum SecurityFeatureTests {
    
    /// Run all tests. Returns true if all pass.
    @discardableResult
    static func runAll() -> Bool {
        print("╔══════════════════════════════════════════════════════╗")
        print("║    LADON SECURITY FEATURE TESTS                     ║")
        print("╠══════════════════════════════════════════════════════╣")
        
        var allPassed = true
        
        // 1. Blake2b Tests
        allPassed = testBlake2b() && allPassed
        
        // 2. Argon2id Tests
        allPassed = testArgon2id() && allPassed
        
        // 3. FIX M-51: Constant-Time Comparison Tests
        allPassed = testConstantTimeComparison() && allPassed
        
        // 4. FIX M-51: Memory Wipe Tests
        allPassed = testSecureMemoryWipe() && allPassed
        
        print("╠══════════════════════════════════════════════════════╣")
        if allPassed {
            print("║  ✅ ALL TESTS PASSED                                ║")
        } else {
            print("║  ❌ SOME TESTS FAILED                               ║")
        }
        print("╚══════════════════════════════════════════════════════╝")
        
        return allPassed
    }
    
    // MARK: - Blake2b Tests
    
    private static func testBlake2b() -> Bool {
        print("║                                                      ║")
        print("║  [1] Blake2b (RFC 7693)                              ║")
        
        // Test vector from RFC 7693, Appendix A:
        // Input: "abc" (3 bytes)
        // Output (Blake2b-512):
        // BA 80 A5 3F 98 1C 4D 0D 6A 27 97 B6 9F 12 F6 E9
        // 4C 21 2F 14 68 5A C4 B7 4B 12 BB 6F DB FF A2 D1
        // 7D 87 C5 39 2A AB 79 2D C2 52 D5 DE 45 33 CC 95
        // 18 D3 8A A8 DB F1 92 5A B9 23 86 ED D4 00 99 23
        let input = Data("abc".utf8)
        let result = Blake2b.hash(input, digestLength: 64)
        
        let expected = Data([
            0xba, 0x80, 0xa5, 0x3f, 0x98, 0x1c, 0x4d, 0x0d,
            0x6a, 0x27, 0x97, 0xb6, 0x9f, 0x12, 0xf6, 0xe9,
            0x4c, 0x21, 0x2f, 0x14, 0x68, 0x5a, 0xc4, 0xb7,
            0x4b, 0x12, 0xbb, 0x6f, 0xdb, 0xff, 0xa2, 0xd1,
            0x7d, 0x87, 0xc5, 0x39, 0x2a, 0xab, 0x79, 0x2d,
            0xc2, 0x52, 0xd5, 0xde, 0x45, 0x33, 0xcc, 0x95,
            0x18, 0xd3, 0x8a, 0xa8, 0xdb, 0xf1, 0x92, 0x5a,
            0xb9, 0x23, 0x86, 0xed, 0xd4, 0x00, 0x99, 0x23
        ])
        
        let pass = result == expected
        print("║    Blake2b-512(\"abc\"):  \(pass ? "✅ PASS" : "❌ FAIL")                     ║")
        
        if !pass {
            print("║    Expected: \(expected.prefix(16).hex)...  ║")
            print("║    Got:      \(result.prefix(16).hex)...  ║")
        }
        
        // Empty input test
        let emptyResult = Blake2b.hash(Data(), digestLength: 64)
        let expectedEmpty = Data([
            0x78, 0x6a, 0x02, 0xf7, 0x42, 0x01, 0x59, 0x03,
            0xc6, 0xc6, 0xfd, 0x85, 0x25, 0x52, 0xd2, 0x72,
            0x91, 0x2f, 0x47, 0x40, 0xe1, 0x58, 0x47, 0x61,
            0x8a, 0x86, 0xe2, 0x17, 0xf7, 0x1f, 0x54, 0x19,
            0xd2, 0x5e, 0x10, 0x31, 0xaf, 0xee, 0x58, 0x53,
            0x13, 0x89, 0x64, 0x44, 0x93, 0x4e, 0xb0, 0x4b,
            0x90, 0x3a, 0x68, 0x5b, 0x14, 0x48, 0xb7, 0x55,
            0xd5, 0x6f, 0x70, 0x1a, 0xfe, 0x9b, 0xe2, 0xce
        ])
        
        let pass2 = emptyResult == expectedEmpty
        print("║    Blake2b-512(\"\"):     \(pass2 ? "✅ PASS" : "❌ FAIL")                     ║")
        
        return pass && pass2
    }
    
    // MARK: - Argon2id Tests
    
    private static func testArgon2id() -> Bool {
        print("║                                                      ║")
        print("║  [2] Argon2id (RFC 9106)                             ║")
        
        // RFC 9106 self-test
        let selfTestPass = Argon2id.runSelfTest()
        print("║    Argon2id self-test:    \(selfTestPass ? "✅ PASS" : "❌ FAIL")                    ║")
        
        // Determinism test: same input → same output
        let password = Data("testpassword".utf8)
        let salt = Data(repeating: 0x42, count: 16)
        
        guard let result1 = try? Argon2id.hash(
            password: password, salt: salt,
            timeCost: 1, memoryCost: 16, parallelism: 1, outputLength: 32
        ),
        let result2 = try? Argon2id.hash(
            password: password, salt: salt,
            timeCost: 1, memoryCost: 16, parallelism: 1, outputLength: 32
        ) else {
            print("║    Determinism test:    ❌ FAIL (exception)            ║")
            return false
        }
        
        let deterministicPass = result1 == result2
        print("║    Determinism test:    \(deterministicPass ? "✅ PASS" : "❌ FAIL")                    ║")
        
        // Different passwords → different outputs
        guard let result3 = try? Argon2id.hash(
            password: Data("different".utf8), salt: salt,
            timeCost: 1, memoryCost: 16, parallelism: 1, outputLength: 32
        ) else {
            print("║    Uniqueness test:     ❌ FAIL (exception)            ║")
            return false
        }
        
        let uniquePass = result1 != result3
        print("║    Uniqueness test:     \(uniquePass ? "✅ PASS" : "❌ FAIL")                    ║")
        
        // Different salts → different outputs
        guard let result4 = try? Argon2id.hash(
            password: password, salt: Data(repeating: 0x43, count: 16),
            timeCost: 1, memoryCost: 16, parallelism: 1, outputLength: 32
        ) else {
            print("║    Salt sensitivity:    ❌ FAIL (exception)            ║")
            return false
        }
        
        let saltPass = result1 != result4
        print("║    Salt sensitivity:    \(saltPass ? "✅ PASS" : "❌ FAIL")                    ║")
        
        // Input validation tests
        let shortSaltFails: Bool
        do {
            _ = try Argon2id.hash(password: password, salt: Data(count: 4), timeCost: 1, memoryCost: 16, parallelism: 1, outputLength: 32)
            shortSaltFails = false
        } catch Argon2Error.saltTooShort {
            shortSaltFails = true
        } catch {
            shortSaltFails = false
        }
        print("║    Short salt rejected: \(shortSaltFails ? "✅ PASS" : "❌ FAIL")                    ║")
        
        // RegLock convenience function
        guard let regLockKey = try? Argon2id.deriveRegistrationLockKey(
            pin: "123456", salt: salt
        ) else {
            print("║    RegLock derivation:  ❌ FAIL (exception)            ║")
            return false
        }
        let regLockPass = regLockKey.count == 32
        print("║    RegLock derivation:  \(regLockPass ? "✅ PASS" : "❌ FAIL") (32 bytes)            ║")
        
        return selfTestPass && deterministicPass && uniquePass && saltPass && shortSaltFails && regLockPass
    }
    
    // MARK: - FIX M-51: Constant-Time Comparison Tests
    
    private static func testConstantTimeComparison() -> Bool {
        print("║                                                      ║")
        print("║  [3] Constant-Time Comparison                        ║")
        
        // Equal data must compare as equal
        let a = Data([0x01, 0x02, 0x03, 0x04])
        let b = Data([0x01, 0x02, 0x03, 0x04])
        let equalPass = a.constantTimeEqual(b)
        print("║    Equal data:          \(equalPass ? "✅ PASS" : "❌ FAIL")                    ║")
        
        // Different data must compare as unequal
        let c = Data([0x01, 0x02, 0x03, 0x05])
        let diffPass = !a.constantTimeEqual(c)
        print("║    Different data:      \(diffPass ? "✅ PASS" : "❌ FAIL")                    ║")
        
        // Different lengths must compare as unequal
        let d = Data([0x01, 0x02, 0x03])
        let lenPass = !a.constantTimeEqual(d)
        print("║    Length mismatch:     \(lenPass ? "✅ PASS" : "❌ FAIL")                    ║")
        
        // Empty data must compare as equal
        let emptyPass = Data().constantTimeEqual(Data())
        print("║    Empty == empty:      \(emptyPass ? "✅ PASS" : "❌ FAIL")                    ║")
        
        return equalPass && diffPass && lenPass && emptyPass
    }
    
    // MARK: - FIX M-51: Memory Wipe Test
    
    private static func testSecureMemoryWipe() -> Bool {
        print("║                                                      ║")
        print("║  [4] Secure Memory Wipe                              ║")
        
        // Create data and wipe it
        var testData = Data([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
        testData.securelyWipe()
        
        let wipePass = testData.isEmpty
        print("║    Data wiped:          \(wipePass ? "✅ PASS" : "❌ FAIL")                    ║")
        
        // Verify MemoryProtector wipe clears data
        var testData2 = Data(repeating: 0x42, count: 64)
        MemoryProtector.shared.secureWipe(&testData2)
        let wipePass2 = testData2.isEmpty
        print("║    MemoryProtector:     \(wipePass2 ? "✅ PASS" : "❌ FAIL")                    ║")
        
        return wipePass && wipePass2
    }
    
}

// MARK: - Helper Extension

private extension Data {
    var hex: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
#endif // DEBUG
