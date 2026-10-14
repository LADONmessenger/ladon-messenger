import Foundation
import UIKit
import Darwin
import MachO

// P8-AUDIT8-IOS-14: the RASP monitor (RuntimeApplicationSelfProtection),
// AdvancedJailbreakDetector and the Mach-O __TEXT check that used to live
// here had no caller. RASP also carried a trap: isKeychainCompromised read a
// WhenUnlocked sentinel and treated any read failure — e.g. a locked device —
// as an attack, two seconds later triggering the irreversible wipe and the
// permanent panic flag. Removed rather than kept as dormant code.

// MARK: - FIX H-15: Constant-Time Data Comparison

extension Data {
    /// Constant-time comparison to prevent timing side-channel attacks.
    /// Swift's default Data == may short-circuit on the first differing byte,
    /// leaking information about how many bytes match.
    /// Uses XOR accumulation so every byte is always compared regardless of mismatches.
    /// FIX AUDIT-R17-F4: @inline(never) prevents compiler from optimizing away constant-time loop
    @inline(never)
    func constantTimeEqual(_ other: Data) -> Bool {
        // Length mismatch is NOT timing-safe, but lengths of cryptographic
        // outputs (hashes, MACs) are public knowledge, so this is acceptable.
        guard self.count == other.count else { return false }
        var accumulator: UInt8 = 0
        self.withUnsafeBytes { selfBytes in
            other.withUnsafeBytes { otherBytes in
                guard let selfPtr = selfBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                      let otherPtr = otherBytes.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                    accumulator = 1  // Fail if either buffer is nil
                    return
                }
                for i in 0..<self.count {
                    accumulator |= selfPtr[i] ^ otherPtr[i]
                }
            }
        }
        return accumulator == 0
    }
}

// MARK: - FIX M-44: Safe Hex Encoding/Decoding

extension Data {
    /// Encode Data to lowercase hex string
    var hexEncodedString: String {
        map { String(format: "%02x", $0) }.joined()
    }
    
    /// Decode hex string to Data. Returns nil for invalid hex (odd length, invalid chars).
    ///
    /// P7-IOS-CRYPTO-20: hard cap at 4096 chars (= 2048 bytes decoded). The
    /// hex decoder is on the parse path for APNs tokens, exit-id, hkem_pk
    /// and bundle hex strings; the largest legitimate caller is hkem_pk
    /// (1216 bytes -> 2432 hex chars). 4096 is comfortably above that and
    /// stops a forged 4-MiB hex blob from being walked byte-by-byte.
    init?(hexString: String) {
        let hex = hexString.trimmingCharacters(in: .whitespacesAndNewlines)
        guard hex.count <= 4096 else { return nil }
        guard hex.count.isMultiple(of: 2) else { return nil }
        guard !hex.isEmpty else {
            self = Data()
            return
        }
        var data = Data(capacity: hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let nextIndex = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<nextIndex], radix: 16) else { return nil }
            data.append(byte)
            index = nextIndex
        }
        self = data
    }
}
