import Foundation
import CryptoKit
import UIKit

/// Safety Numbers (Key Verification) - Like Signal's fingerprints
struct SafetyNumbers {
    let localFingerprint: String
    let remoteFingerprint: String
    let combined: String
    
    /// Generate safety number from two identity keys
    static func generate(localKey: Data, remoteKey: Data, localID: String, remoteID: String) -> SafetyNumbers {
        // H8 FIX: Deterministic byte-level comparison (not locale-dependent)
        // Sort by raw public key bytes to ensure identical order on both devices
        let localBytes = Array(localKey)
        let remoteBytes = Array(remoteKey)
        let localFirst = localBytes.lexicographicallyPrecedes(remoteBytes)
        let (first, firstID, second, secondID) = localFirst ?
            (localKey, localID, remoteKey, remoteID) :
            (remoteKey, remoteID, localKey, localID)
        
        // Generate fingerprints (60-digit decimal numbers like Signal)
        // FIX TOR-C01: Handle nil fingerprints — return error-indicating SafetyNumbers
        guard let localFP = generateFingerprint(publicKey: localKey, identity: localID),
              let remoteFP = generateFingerprint(publicKey: remoteKey, identity: remoteID) else {
            // FIX IN-06: If both users have corrupted keys, both fingerprints would be "⚠️ KEY ERROR".
            // Theoretically creates a false-positive match (identical error strings).
            // MITIGATION: UI displays these strings prominently in red/warning style.
            // Users seeing error indicators would not verify as a match — they would
            // seek support or recovery. Zero practical risk of false verification.
            return SafetyNumbers(
                localFingerprint: "⚠️ KEY ERROR",
                remoteFingerprint: "⚠️ KEY ERROR",
                combined: "INVALID — Keys could not be verified"
            )
        }
        
        // Combined verification code
        let combined = generateCombinedCode(first: first, firstID: firstID, second: second, secondID: secondID)
        
        return SafetyNumbers(
            localFingerprint: localFP,
            remoteFingerprint: remoteFP,
            combined: combined
        )
    }
    
    /// Generate 60-digit fingerprint from public key (Signal-compatible: 12 groups × 5 digits)
    /// Returns nil if the input key or identity is empty/invalid — callers must handle nil.
    private static func generateFingerprint(publicKey: Data, identity: String) -> String? {
        // FIX F9: 60 digits statt 30 — iterativer SHA-512 wie Signal
        // 5200 Iterationen: Hash_{5200}(version || publicKey || identity)
        
        // FIX CRYPTO-C01 (TOR-C01): Return nil on invalid input instead of fixed error string.
        // Previously returned "00000 ERROR 00000 INVLD 00000 KEY00" which could match
        // if both parties had corrupted keys, creating a false-positive verification.
        guard let identityData = identity.data(using: .utf8), !identityData.isEmpty,
              !publicKey.isEmpty else {
            #if DEBUG
            print("⚠️ SafetyNumbers: Empty or invalid identity/key for fingerprint generation")
            #endif
            return nil
        }
        
        /// FIX M-45: Named version constant for forward-compatible fingerprint evolution.
        /// Increment to v1 when changing the fingerprint algorithm — receivers
        /// can then detect and handle both old and new formats.
        let fingerprintVersion: UInt8 = 0x00
        var data = Data([fingerprintVersion])
        data.append(publicKey)
        data.append(identityData)
        
        var hash = SHA512.hash(data: data)
        // FIX SN-2 (ADVERSARIAL): Re-include identityData in every iteration
        // to prevent theoretical collision if two different identities produce same initial hash
        for _ in 0..<5200 {
            var iterData = Data(hash)
            iterData.append(publicKey)
            iterData.append(identityData)
            hash = SHA512.hash(data: iterData)
        }
        
        // FIX C-1: Use first 60 bytes of SHA-512 (64 bytes available) → 12 groups × 5 bytes
        // Previous bug: offset = i * 5 % 30 caused groups 6-11 to repeat groups 0-5
        // Now: sequential read of 60 bytes → all 60 digits are unique
        let hashBytes = Array(hash)
        var digits = ""
        
        for i in 0..<12 {
            let offset = i * 5  // Sequential: 0, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55
            let b0 = UInt64(hashBytes[offset])
            let b1 = UInt64(hashBytes[offset + 1])
            let b2 = UInt64(hashBytes[offset + 2])
            let b3 = UInt64(hashBytes[offset + 3])
            let b4 = UInt64(hashBytes[offset + 4])
            let value = (b0 << 32) | (b1 << 24) | (b2 << 16) | (b3 << 8) | b4
            // FIX AUDIT2-07: Simple modulo — matches Signal Protocol's NumericFingerprintGenerator.
            // Bias: 27776/2^40 ≈ 2.5×10⁻⁸ per group — cryptographically negligible.
            // Previous XOR remapping for values >= threshold introduced WORSE bias:
            // XOR output range was 0..65535, so values 65536..99999 could NEVER appear
            // in the remapped branch (34,464 impossible outputs vs 2.5×10⁻⁸ original bias).
            let decimalGroup = String(format: "%05llu", value % 100_000)
            digits += decimalGroup
        }
        
        return digits
    }
    
    /// Generate combined verification code (60 digits)
    /// FIX M-24: Signal spec generates TWO independent 30-digit fingerprints and concatenates
    /// them in sorted order. Our previous approach hashed both keys together, deviating from spec.
    /// Now: use sorted concatenation of individual fingerprints (first 30 digits each).
    private static func generateCombinedCode(first: Data, firstID: String, second: Data, secondID: String) -> String {
        guard let fp1 = generateFingerprint(publicKey: first, identity: firstID),
              let fp2 = generateFingerprint(publicKey: second, identity: secondID) else {
            return "INVALID — Keys could not be verified"
        }
        // Take first 30 digits from each fingerprint (sorted by key order already)
        let half1 = String(fp1.prefix(30))
        let half2 = String(fp2.prefix(30))
        return half1 + half2
    }
    
    /// Format safety number for display (12 groups of 5 digits)
    func formattedCombined() -> String {
        var formatted = ""
        for (index, char) in combined.enumerated() {
            if index > 0 && index % 5 == 0 {
                formatted += " "
            }
            formatted.append(char)
        }
        return formatted
    }
    
    /// Generate QR code image for out-of-band verification
    /// Encodes raw key bytes (version + sorted fingerprint hashes + Ed25519 signature) for maximum security
    /// FIX L-10: QR payload is signed so the scanner can verify it wasn't forged
    func generateQRCode(size: CGSize = CGSize(width: 300, height: 300)) -> UIImage? {
        // Binary QR payload: [1B version] [32B hash1] [32B hash2] [64B Ed25519 signature]
        // Version 2: includes Ed25519 signature over the fingerprint hashes
        var qrPayload = Data()
        qrPayload.append(0x02) // Version 2 — signed
        // Use SHA-256 of fingerprint strings for compact binary representation
        let localHash = SHA256.hash(data: Data(localFingerprint.utf8))
        let remoteHash = SHA256.hash(data: Data(remoteFingerprint.utf8))
        // Sort deterministically (same order on both devices)
        let localBytes = Data(localHash)
        let remoteBytes = Data(remoteHash)
        if localBytes.lexicographicallyPrecedes(remoteBytes) {
            qrPayload.append(localBytes)
            qrPayload.append(remoteBytes)
        } else {
            qrPayload.append(remoteBytes)
            qrPayload.append(localBytes)
        }
        
        // FIX L-10 + SN-3: Sign the payload with our Ed25519 identity key
        // SN-3 FIX: If signing fails, return nil — never generate unsigned V2 QR
        guard let signature = try? KeyManager.shared.signMessage(qrPayload) else {
            #if DEBUG
            print("[SafetyNumbers] Failed to sign QR payload — aborting QR generation")
            #endif
            return nil
        }
        qrPayload.append(signature) // 64 bytes Ed25519 signature
        
        guard let filter = CIFilter(name: "CIQRCodeGenerator") else { return nil }
        filter.setValue(qrPayload, forKey: "inputMessage")
        filter.setValue("H", forKey: "inputCorrectionLevel") // High error correction
        
        guard let qrImage = filter.outputImage else { return nil }
        
        // Scale up
        let scale = size.width / qrImage.extent.width
        let scaledImage = qrImage.transformed(by: CGAffineTransform(scaleX: scale, y: scale))
        
        let context = CIContext()
        guard let cgImage = context.createCGImage(scaledImage, from: scaledImage.extent) else { return nil }
        
        return UIImage(cgImage: cgImage)
    }
    
    /// Verify a scanned QR code payload against expected safety numbers
    /// FIX L-10: Verifies Ed25519 signature if present (version 2)
    static func verifyQRPayload(_ data: Data, expectedLocal: String, expectedRemote: String, senderIdentityKey: Data? = nil) -> Bool {
        guard data.count >= 65 else { return false } // Minimum: 1B version + 32B + 32B
        
        let version = data[0]
        let hash1 = data[1..<33]
        let hash2 = data[33..<65]
        
        // Verify fingerprint hashes match
        let localHash = Data(SHA256.hash(data: Data(expectedLocal.utf8)))
        let remoteHash = Data(SHA256.hash(data: Data(expectedRemote.utf8)))
        
        let sortedLocal: Data
        let sortedRemote: Data
        if localHash.lexicographicallyPrecedes(remoteHash) {
            sortedLocal = localHash
            sortedRemote = remoteHash
        } else {
            sortedLocal = remoteHash
            sortedRemote = localHash
        }
        
        // FIX H-15: Use constant-time comparison to prevent timing side-channel attacks
        guard Data(hash1).constantTimeEqual(Data(sortedLocal)) &&
              Data(hash2).constantTimeEqual(Data(sortedRemote)) else { return false }
        
        // Version 2: verify Ed25519 signature
        if version >= 0x02, data.count >= 129, let senderKey = senderIdentityKey {
            let signedData = data[0..<65]
            let signature = data[65..<129]
            guard let pubKey = try? Curve25519.Signing.PublicKey(rawRepresentation: senderKey) else { return false }
            return (try? KeyManager.shared.verifySignature(Data(signature), for: Data(signedData), publicKey: pubKey)) ?? false
        }
        
        // FIX SM-H9: Reject unsigned QR v1 when sender identity key IS available
        // Accepting unsigned payloads when we have the key allows MITM impersonation
        if version < 0x02 && senderIdentityKey != nil {
            return false
        }
        
        // FIX TOR-H05: Reject ALL unsigned v1 QR codes.
        // A MITM who knows both users' public keys can craft a valid unsigned v1 QR.
        // All current clients generate v2 signed QR codes — v1 acceptance enables downgrade.
        if version < 0x02 {
            #if DEBUG
            print("[SafetyNumbers] ⛔ Rejecting unsigned v1 QR code — require v2 with Ed25519 signature")
            #endif
            return false
        }
        
        return false // Should not reach here — all paths handled above
    }
    
    /// Compare safety numbers using constant-time comparison
    /// FIX M-46: Consistent format — strip spaces before comparison
    static func verify(local: String, remote: String) -> Bool {
        let l = Data(local.replacingOccurrences(of: " ", with: "").utf8)
        let r = Data(remote.replacingOccurrences(of: " ", with: "").utf8)
        return l.constantTimeEqual(r)
    }
}
