import Foundation
import CryptoKit
import Security

/// Errors emitted by PostQuantumService operations.
enum PostQuantumError: Error, CustomStringConvertible {
    case invalidInput(expected: Int, actual: Int)
    case providerFailure(String)
    case keychainFailure(OSStatus)
    case verificationFailed

    var description: String {
        switch self {
        case let .invalidInput(expected, actual):
            return "Invalid input size. Expected \(expected) bytes, got \(actual)."
        case let .providerFailure(message):
            return message
        case let .keychainFailure(status):
            return "Keychain operation failed with status \(status)."
        case .verificationFailed:
            return "Post-quantum verification failed."
        }
    }
}

/// FIX INFO-AC6: private — prevents external code from implementing custom providers
/// that bypass PostQuantumService's self-test gate.
private protocol PostQuantumProvider {
    var supportsKyber: Bool { get }
    var supportsDilithium: Bool { get }

    func generateKyberKeypair() throws -> PostQuantumService.KyberKeypair
    func encapsulateKyber(publicKey: Data) throws -> PostQuantumService.KyberEncapsulation
    func decapsulateKyber(ciphertext: Data, secretKey: Data) throws -> Data

    func generateDilithiumKeypair() throws -> PostQuantumService.DilithiumKeypair
    func signDilithium(message: Data, secretKey: Data) throws -> Data
    func verifyDilithium(message: Data, signature: Data, publicKey: Data) -> Bool
}

/// FIX INFO-AC5: private — prevents external code from calling raw liboqs operations
/// without going through PostQuantumService's self-test gate.
private final class LibOQSPostQuantumProvider: PostQuantumProvider {
    var supportsKyber: Bool { true }
    var supportsDilithium: Bool { true }

    func generateKyberKeypair() throws -> PostQuantumService.KyberKeypair {
        var publicKey = Data(count: PostQuantumService.Constants.kyberPublicKeySize)
        var secretKey = Data(count: PostQuantumService.Constants.kyberSecretKeySize)

        let result = publicKey.withUnsafeMutableBytes { pkPtr in
            secretKey.withUnsafeMutableBytes { skPtr in
                OQS_keypair_real(pkPtr.baseAddress!, UInt64(pkPtr.count), skPtr.baseAddress!, UInt64(skPtr.count), 1)
            }
        }

        guard result == 0 else {
            secretKey.securelyWipe()
            throw PostQuantumError.providerFailure("Kyber768 keypair generation failed (code \(result))")
        }
        return .init(publicKey: publicKey, secretKey: secretKey)
    }

    func encapsulateKyber(publicKey: Data) throws -> PostQuantumService.KyberEncapsulation {
        guard publicKey.count == PostQuantumService.Constants.kyberPublicKeySize else {
            throw PostQuantumError.invalidInput(expected: PostQuantumService.Constants.kyberPublicKeySize, actual: publicKey.count)
        }

        var ciphertext = Data(count: PostQuantumService.Constants.kyberCiphertextSize)
        var sharedSecret = Data(count: PostQuantumService.Constants.kyberSharedSecretSize)

        let result = publicKey.withUnsafeBytes { pkPtr in
            ciphertext.withUnsafeMutableBytes { ctPtr in
                sharedSecret.withUnsafeMutableBytes { ssPtr in
                    OQS_encaps_real(ctPtr.baseAddress!, UInt64(ctPtr.count), ssPtr.baseAddress!, UInt64(ssPtr.count), pkPtr.baseAddress!, UInt64(pkPtr.count), 1)
                }
            }
        }

        guard result == 0 else {
            // H7 FIX: Wipe shared secret on encapsulation failure
            sharedSecret.securelyWipe()
            ciphertext.securelyWipe()
            throw PostQuantumError.providerFailure("Kyber768 encapsulation failed (code \(result))")
        }

        return .init(ciphertext: ciphertext, sharedSecret: sharedSecret)
    }

    func decapsulateKyber(ciphertext: Data, secretKey: Data) throws -> Data {
        guard ciphertext.count == PostQuantumService.Constants.kyberCiphertextSize else {
            throw PostQuantumError.invalidInput(expected: PostQuantumService.Constants.kyberCiphertextSize, actual: ciphertext.count)
        }
        guard secretKey.count == PostQuantumService.Constants.kyberSecretKeySize else {
            throw PostQuantumError.invalidInput(expected: PostQuantumService.Constants.kyberSecretKeySize, actual: secretKey.count)
        }

        var sharedSecret = Data(count: PostQuantumService.Constants.kyberSharedSecretSize)
        let result = ciphertext.withUnsafeBytes { ctPtr in
            secretKey.withUnsafeBytes { skPtr in
                sharedSecret.withUnsafeMutableBytes { ssPtr in
                    OQS_decaps_real(ssPtr.baseAddress!, UInt64(ssPtr.count), ctPtr.baseAddress!, UInt64(ctPtr.count), skPtr.baseAddress!, UInt64(skPtr.count), 1)
                }
            }
        }

        guard result == 0 else {
            sharedSecret.securelyWipe()
            throw PostQuantumError.providerFailure("Kyber768 decapsulation failed (code \(result))")
        }
        return sharedSecret
    }

    func generateDilithiumKeypair() throws -> PostQuantumService.DilithiumKeypair {
        var publicKey = Data(count: PostQuantumService.Constants.dilithiumPublicKeySize)
        var secretKey = Data(count: PostQuantumService.Constants.dilithiumSecretKeySize)

        let result = publicKey.withUnsafeMutableBytes { pkPtr in
            secretKey.withUnsafeMutableBytes { skPtr in
                OQS_sig_keypair_real(pkPtr.baseAddress!, UInt64(pkPtr.count), skPtr.baseAddress!, UInt64(skPtr.count), 2)
            }
        }

        guard result == 0 else {
            secretKey.securelyWipe()
            throw PostQuantumError.providerFailure("Dilithium3 keypair generation failed (code \(result))")
        }
        return .init(publicKey: publicKey, secretKey: secretKey)
    }

    func signDilithium(message: Data, secretKey: Data) throws -> Data {
        guard secretKey.count == PostQuantumService.Constants.dilithiumSecretKeySize else {
            throw PostQuantumError.invalidInput(expected: PostQuantumService.Constants.dilithiumSecretKeySize, actual: secretKey.count)
        }

        var signature = Data(count: PostQuantumService.Constants.dilithiumSignatureSize)
        var signatureLength: UInt64 = UInt64(signature.count)

        let result = message.withUnsafeBytes { msgPtr in
            secretKey.withUnsafeBytes { skPtr in
                signature.withUnsafeMutableBytes { sigPtr in
                    OQS_sig_sign_real(
                        sigPtr.baseAddress!,
                        UInt64(sigPtr.count),
                        &signatureLength,
                        msgPtr.baseAddress!,
                        UInt64(message.count),
                        skPtr.baseAddress!,
                        UInt64(skPtr.count),
                        2
                    )
                }
            }
        }

        guard result == 0 else {
            // FIX R16-PQ2: Wipe partially-written signature buffer on error
            signature.securelyWipe()
            throw PostQuantumError.providerFailure("Dilithium3 signing failed (code \(result))")
        }

        return signature.prefix(Int(signatureLength))
    }

    func verifyDilithium(message: Data, signature: Data, publicKey: Data) -> Bool {
        guard publicKey.count == PostQuantumService.Constants.dilithiumPublicKeySize else { return false }

        let result = message.withUnsafeBytes { msgPtr in
            signature.withUnsafeBytes { sigPtr in
                publicKey.withUnsafeBytes { pkPtr in
                    OQS_sig_verify_real(
                        msgPtr.baseAddress!,
                        UInt64(message.count),
                        sigPtr.baseAddress!,
                        UInt64(signature.count),
                        pkPtr.baseAddress!,
                        UInt64(publicKey.count),
                        2
                    )
                }
            }
        }

        return result == 0
    }
}

/// Central entry point for all post-quantum cryptography features.
final class PostQuantumService {
    struct KyberKeypair {
        let publicKey: Data
        var secretKey: Data  // FIX F11: var instead of let for secure wipe
    }

    struct KyberEncapsulation {
        var ciphertext: Data     // FIX AUDIT-R14-F3: var for secure wipe after use
        var sharedSecret: Data   // FIX AUDIT-R14-F3: var for secure wipe after use
    }

    struct DilithiumKeypair {
        var publicKey: Data   // FIX: var for secure wipe in defer block
        var secretKey: Data  // FIX C-9: var instead of let for secure wipe
    }

    enum Constants {
        static let kyberPublicKeySize = 1184
        static let kyberSecretKeySize = 2400
        static let kyberCiphertextSize = 1088
        static let kyberSharedSecretSize = 32

        static let dilithiumPublicKeySize = 1952
        static let dilithiumSecretKeySize = 4032
        static let dilithiumSignatureSize = 3309
    }

    static let shared = PostQuantumService()

    private let provider: PostQuantumProvider
    
    /// FIX H-6: NSLock for thread-safe access to shared mutable state (isKyberAvailable, selfTestPassed)
    private let stateLock = NSLock()
    
    /// FIX TOCTOU: NSLock to serialize Dilithium key check-generate-store in signHybrid()
    private let dilithiumKeyLock = NSLock()
    
    /// FIX AUDIT-130: Flag to disable PQ if self-test fails in production
    /// FIX H-6: Backing store — access only via thread-safe selfTestPassed property
    private var _selfTestPassed = false
    private(set) var selfTestPassed: Bool {
        get { stateLock.withLock { _selfTestPassed } }
        set { stateLock.withLock { _selfTestPassed = newValue } }
    }

    /// FIX M-13: Provider must be a real PQ implementation (LibOQS). No simulated or stub
    /// providers are accepted. The PostQuantumProvider protocol is private to prevent external
    /// implementations that could bypass self-test gating.
    /// FIX M-14: No hardcoded test keys or fallback keys exist. Self-test generates fresh
    /// ephemeral keys each run and wipes them immediately.
    fileprivate init(provider: PostQuantumProvider = LibOQSPostQuantumProvider()) {
        self.provider = provider
    }
    
    /// FIX INFO-AC4: private — only called internally from runSelfTestOrDisable().
    /// Prevents external code from silently downgrading PQ features.
    private func disableDueToSelfTestFailure() {
        stateLock.withLock { _selfTestPassed = false }
    }
    
    /// Run PQ self-test; on failure, automatically disable PQ features.
    /// This encapsulates the disable logic so external callers cannot bypass the self-test.
    func runSelfTestOrDisable() {
        do {
            try runSelfTest()
        } catch {
            disableDueToSelfTestFailure()
            #if DEBUG
            print("[PQ] ❌ Post-Quantum self-test FAILED — PQ features disabled: \(error)")
            #endif
        }
    }

    /// FIX H-6: Thread-safe access via stateLock
    var isKyberAvailable: Bool { stateLock.withLock { provider.supportsKyber && _selfTestPassed } }
    var isDilithiumAvailable: Bool { stateLock.withLock { provider.supportsDilithium && _selfTestPassed } }

    // MARK: - Kyber768

    /// Generate a Kyber768 KEM keypair (1184B public key, 2400B secret key).
    /// Caller MUST `securelyWipe()` the secretKey after Keychain storage.
    /// FIX H-4: Gates on selfTestPassed — defective liboqs is never silently used.
    func generateKyberKeypair() throws -> KyberKeypair {
        guard selfTestPassed else {
            throw PostQuantumError.providerFailure("PQ self-test not passed — Kyber operations disabled")
        }
        return try provider.generateKyberKeypair()
    }

    /// Encapsulate a 32-byte shared secret against a Kyber768 public key.
    /// Returns ciphertext (1088B) and shared secret (32B). Used in hybrid DH-Ratchet.
    /// FIX H-4: Gates on selfTestPassed.
    func encapsulateKyber(publicKey: Data) throws -> KyberEncapsulation {
        guard selfTestPassed else {
            throw PostQuantumError.providerFailure("PQ self-test not passed — Kyber operations disabled")
        }
        return try provider.encapsulateKyber(publicKey: publicKey)
    }

    /// Decapsulate a Kyber768 ciphertext using the corresponding secret key.
    /// Returns the 32-byte shared secret. Throws on size mismatch or liboqs failure.
    /// FIX H-4: Gates on selfTestPassed.
    /// FIX M-11: Caller MUST securelyWipe() the secretKey after this call returns.
    func decapsulateKyber(ciphertext: Data, secretKey: Data) throws -> Data {
        guard selfTestPassed else {
            throw PostQuantumError.providerFailure("PQ self-test not passed — Kyber operations disabled")
        }
        return try provider.decapsulateKyber(ciphertext: ciphertext, secretKey: secretKey)
    }

    /// FIX M-12: Load Kyber secret key from Keychain, decapsulate, and wipe the key from memory.
    /// Use this instead of manually loading + decapsulating to ensure secret key lifetime is minimized.
    func decapsulateKyberFromKeychain(ciphertext: Data, keychainAccount: String = "kyber768.identity.secret") throws -> Data {
        guard var secretKey = loadFromKeychain(account: keychainAccount) else {
            throw PostQuantumError.providerFailure("Kyber768 secret key not found in Keychain (\(keychainAccount))")
        }
        defer { secretKey.securelyWipe() }
        return try decapsulateKyber(ciphertext: ciphertext, secretKey: secretKey)
    }

    // MARK: - Dilithium3

    /// Generate a Dilithium3 digital signature keypair (1952B public key, 4032B secret key).
    /// Caller MUST `securelyWipe()` the secretKey after Keychain storage.
    /// FIX H-4: Gates on selfTestPassed.
    func generateDilithiumKeypair() throws -> DilithiumKeypair {
        guard selfTestPassed else {
            throw PostQuantumError.providerFailure("PQ self-test not passed — Dilithium operations disabled")
        }
        return try provider.generateDilithiumKeypair()
    }

    /// Sign a message with Dilithium3. Returns a signature of up to 3309 bytes.
    /// The secretKey must be exactly 4032 bytes.
    /// FIX H-4: Gates on selfTestPassed.
    func signDilithium(message: Data, secretKey: Data) throws -> Data {
        guard selfTestPassed else {
            throw PostQuantumError.providerFailure("PQ self-test not passed — Dilithium operations disabled")
        }
        return try provider.signDilithium(message: message, secretKey: secretKey)
    }

    /// FIX M-12: Load Dilithium secret key from Keychain, sign, and wipe the key from memory.
    /// Use this instead of manually loading + signing to minimize secret key lifetime and heap copies.
    func signDilithiumFromKeychain(message: Data, keychainAccount: String = "dilithium3.identity.secret") throws -> Data {
        guard var secretKey = loadFromKeychain(account: keychainAccount) else {
            throw PostQuantumError.providerFailure("Dilithium3 secret key not found in Keychain (\(keychainAccount))")
        }
        defer { secretKey.securelyWipe() }
        return try signDilithium(message: message, secretKey: secretKey)
    }

    /// Verify a Dilithium3 signature against the given message and public key (1952B).
    /// Returns false on size mismatch or verification failure.
    /// FIX AUDIT-MAR-2026-13: Gate on selfTestPassed — consistent with all other PQ methods.
    func verifyDilithium(message: Data, signature: Data, publicKey: Data) -> Bool {
        guard selfTestPassed else { return false }
        return provider.verifyDilithium(message: message, signature: signature, publicKey: publicKey)
    }

    // MARK: - Hybrid helpers

    /// Generate a fresh hybrid identity keypair (classical Curve25519 + Kyber768).
    /// Secret Kyber material is stored inside the Keychain for later decapsulation.
    @discardableResult
    func generateHybridIdentityKey() throws -> (classical: Curve25519.KeyAgreement.PrivateKey, quantumPublicKey: Data) {
        let classicalKey = Curve25519.KeyAgreement.PrivateKey()
        var kyberKeypair = try generateKyberKeypair()
        // FIX F11: Wipe Kyber SK nach Keychain-Speicherung
        defer { kyberKeypair.secretKey.securelyWipe() }
        try storeInKeychain(account: "kyber768.identity.secret", data: kyberKeypair.secretKey)
        return (classical: classicalKey, quantumPublicKey: kyberKeypair.publicKey)
    }

    // FIX PQ-1: Removed performHybridKeyAgreement() — dead code with a fatal flaw:
    // a UUID-based salt was never transmitted to the peer, making key agreement
    // impossible. (The V1 session crypto it referenced was removed in #8; V2 uses HKEMV2.)

    /// Create a hybrid signature by combining Ed25519 and Dilithium3 signatures.
    /// FIX M-12: Uses signDilithiumFromKeychain to minimize secret key heap copies.
    func signHybrid(message: Data, ed25519Key: Curve25519.Signing.PrivateKey) throws -> Data {
        let classicalSignature = try ed25519Key.signature(for: message)

        // FIX TOCTOU: Ensure Dilithium keypair exists in Keychain (generate if absent)
        try dilithiumKeyLock.withLock {
            // FIX R16-PQ1: Existence check without loading 4032-byte SK onto heap
            if !keychainItemExists(account: "dilithium3.identity.secret") {
                var keypair = try generateDilithiumKeypair()
                defer {
                    keypair.secretKey.securelyWipe()
                    keypair.publicKey = Data()  // public key doesn't need secure wipe
                }
                try storeInKeychain(account: "dilithium3.identity.secret", data: keypair.secretKey)
                try storeInKeychain(account: "dilithium3.identity.public", data: keypair.publicKey)
            }
        }

        // FIX M-12: Sign from Keychain directly — key loaded, used, and wiped in one call
        let quantumSignature = try signDilithiumFromKeychain(message: message)

        var combined = Data(capacity: classicalSignature.count + quantumSignature.count)
        combined.append(classicalSignature)
        combined.append(quantumSignature)
        return combined
    }

    /// Verify a hybrid signature consisting of Ed25519 + Dilithium3 parts.
    func verifyHybrid(
        message: Data,
        signature: Data,
        ed25519PublicKey: Curve25519.Signing.PublicKey,
        dilithiumPublicKey: Data
    ) throws -> Bool {
        let classicalSize = 64
        guard signature.count >= classicalSize else { return false }

        let classicalSignature = signature.prefix(classicalSize)
        let quantumSignature = signature.suffix(from: classicalSize)

        let classicalValid = ed25519PublicKey.isValidSignature(classicalSignature, for: message)
        let quantumValid = verifyDilithium(message: message, signature: Data(quantumSignature), publicKey: dilithiumPublicKey)
        return classicalValid && quantumValid
    }

    /// Lightweight self-test to ensure the liboqs backend is wired correctly.
    /// FIX AUDIT-130: Runs in ALL builds. Validates key sizes. Wipes test keys.
    func runSelfTest() throws {
        // FIX PQ-C1: Call provider methods DIRECTLY to avoid circular dependency.
        // Public methods (generateKyberKeypair, encapsulateKyber, etc.) gate on selfTestPassed,
        // which is still false during the self-test. Using provider.* bypasses the gate.
        
        // Step 1: Kyber KEM round-trip
        var kyberKeypair = try provider.generateKyberKeypair()
        defer {
            // FIX AUDIT-114: Wipe test keys from memory
            kyberKeypair.secretKey.securelyWipe()
        }
        
        // FIX AUDIT-130: Validate generated key sizes
        guard kyberKeypair.publicKey.count == Constants.kyberPublicKeySize else {
            throw PostQuantumError.providerFailure("Kyber768 pk size \(kyberKeypair.publicKey.count) != expected \(Constants.kyberPublicKeySize)")
        }
        guard kyberKeypair.secretKey.count == Constants.kyberSecretKeySize else {
            throw PostQuantumError.providerFailure("Kyber768 sk size \(kyberKeypair.secretKey.count) != expected \(Constants.kyberSecretKeySize)")
        }

        // FIX AUDIT-R15-F11: var statt let für secure wipe nach Vergleich
        var encapsulation = try provider.encapsulateKyber(publicKey: kyberKeypair.publicKey)

        var recovered = try provider.decapsulateKyber(ciphertext: encapsulation.ciphertext, secretKey: kyberKeypair.secretKey)
        defer {
            recovered.securelyWipe()
            encapsulation.sharedSecret.securelyWipe()
            encapsulation.ciphertext.securelyWipe()
        }
        
        guard recovered == encapsulation.sharedSecret else {
            throw PostQuantumError.verificationFailed
        }

        // Step 2: Dilithium signature round-trip
        guard provider.supportsDilithium else {
            stateLock.withLock { _selfTestPassed = true }
            return
        }
        var dilithiumKeypair = try provider.generateDilithiumKeypair()
        defer {
            dilithiumKeypair.secretKey.securelyWipe()
        }
        
        // FIX AUDIT-130: Validate Dilithium key sizes
        guard dilithiumKeypair.publicKey.count == Constants.dilithiumPublicKeySize else {
            throw PostQuantumError.providerFailure("Dilithium3 pk size \(dilithiumKeypair.publicKey.count) != expected \(Constants.dilithiumPublicKeySize)")
        }
        guard dilithiumKeypair.secretKey.count == Constants.dilithiumSecretKeySize else {
            throw PostQuantumError.providerFailure("Dilithium3 sk size \(dilithiumKeypair.secretKey.count) != expected \(Constants.dilithiumSecretKeySize)")
        }

        let message = Data("ladon-pq-self-test".utf8)
        let signature = try provider.signDilithium(message: message, secretKey: dilithiumKeypair.secretKey)

        guard provider.verifyDilithium(message: message, signature: signature, publicKey: dilithiumKeypair.publicKey) else {
            throw PostQuantumError.verificationFailed
        }
        
        // FIX AUDIT-130: Mark self-test as passed — enables PQ features
        stateLock.withLock { _selfTestPassed = true }
    }

    // MARK: - FIX C-10: Dilithium Key Rotation

    /// Check if Dilithium identity key needs rotation (90-day cycle)
    func isDilithiumRotationNeeded() -> Bool {
        guard let tsData = loadFromKeychain(account: "dilithium3.identity.rotatedAt") else {
            // No rotation timestamp → first-time setup, store now
            let now = Data(withUnsafeBytes(of: Date().timeIntervalSince1970) { Data($0) })
            do {
                try storeInKeychain(account: "dilithium3.identity.rotatedAt", data: now)
            } catch {
                #if DEBUG
                print("[PQ] ❌ Failed to store Dilithium rotation timestamp: \(error)")
                #endif
            }
            return false
        }
        guard tsData.count == MemoryLayout<TimeInterval>.size else { return true }
        // FIX MUC-9: loadUnaligned — Data buffer has no alignment guarantee
        let ts = tsData.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 0, as: TimeInterval.self) }
        let age = Date().timeIntervalSince1970 - ts
        let ninetyDays: TimeInterval = 90 * 24 * 60 * 60
        return age >= ninetyDays
    }

    /// Rotate Dilithium3 identity keypair. Archives old public key for signature verification of in-flight messages.
    /// FIX MED-17: Keep up to 2 previous public keys instead of only 1, to handle slow message delivery
    func rotateDilithiumKeysIfNeeded() throws {
        guard isDilithiumRotationNeeded() else { return }

        // FIX MED-17: Archive chain: current previous → previous2, then current → previous
        if let oldPrevious = loadFromKeychain(account: "dilithium3.identity.public.previous") {
            try storeInKeychain(account: "dilithium3.identity.public.previous2", data: oldPrevious)
        }
        // Archive current public key for verification of old signatures
        if let oldPK = loadFromKeychain(account: "dilithium3.identity.public") {
            try storeInKeychain(account: "dilithium3.identity.public.previous", data: oldPK)
        }

        // Generate new keypair
        var newKeypair = try generateDilithiumKeypair()
        try storeInKeychain(account: "dilithium3.identity.secret", data: newKeypair.secretKey)
        try storeInKeychain(account: "dilithium3.identity.public", data: newKeypair.publicKey)
        // FIX MED-16: Wipe generated secret key from local memory immediately
        newKeypair.secretKey.securelyWipe()
        newKeypair.publicKey.securelyWipe()  // FIX AUDIT-R14-F4: Also wipe public key copy

        // Update rotation timestamp
        let now = Data(withUnsafeBytes(of: Date().timeIntervalSince1970) { Data($0) })
        try storeInKeychain(account: "dilithium3.identity.rotatedAt", data: now)

        #if DEBUG
        print("[PQ] 🔄 Dilithium3 identity keys rotated successfully")
        #endif
    }

    /// Get the previous Dilithium public key (for verifying signatures made before rotation)
    func previousDilithiumPublicKey() -> Data? {
        return loadFromKeychain(account: "dilithium3.identity.public.previous")
    }

    /// FIX MED-17: Get the second-previous public key (for slow delivery after 2 rotations)
    func previousDilithiumPublicKey2() -> Data? {
        return loadFromKeychain(account: "dilithium3.identity.public.previous2")
    }

    // MARK: - Keychain helpers

    /// FIX M-11: Atomic Keychain update — Update first, Add only if not found.
    /// Previously: SecItemDelete → SecItemAdd was non-atomic (key loss on app kill between).
    private func storeInKeychain(account: String, data: Data) throws {
        let baseQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecAttrService as String: "app.ladon.messenger",
            kSecAttrSynchronizable as String: false
        ]
        let updateAttrs: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        let updateStatus = SecItemUpdate(baseQuery as CFDictionary, updateAttrs as CFDictionary)
        if updateStatus == errSecSuccess {
            return  // Atomic update succeeded
        } else if updateStatus == errSecItemNotFound {
            // Item doesn't exist — add it
            var addQuery = baseQuery
            addQuery[kSecValueData as String] = data
            addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            let status = SecItemAdd(addQuery as CFDictionary, nil)
            guard status == errSecSuccess else {
                throw PostQuantumError.keychainFailure(status)
            }
        } else {
            // FIX R21-A8-1: Removed non-atomic Delete→Add fallback.
            // Previously SecItemDelete→SecItemAdd was used here. If the app was
            // killed between Delete and Add, the PQ key would be permanently lost.
            // Now we simply throw — the caller can retry on next launch.
            throw PostQuantumError.keychainFailure(updateStatus)
        }
    }

    private func loadFromKeychain(account: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecAttrService as String: "app.ladon.messenger",  // FIX H-11: Match service scope
            kSecReturnData as String: true,
            kSecAttrSynchronizable as String: false
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data else {
            return nil
        }
        return data
    }
    
    /// FIX R16-PQ1: Check Keychain item existence WITHOUT loading data onto heap
    private func keychainItemExists(account: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecAttrService as String: "app.ladon.messenger",
            kSecAttrSynchronizable as String: false
        ]
        return SecItemCopyMatching(query as CFDictionary, nil) == errSecSuccess
    }
}
