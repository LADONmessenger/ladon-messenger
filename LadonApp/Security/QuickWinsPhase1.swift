import Foundation
import Security
import LocalAuthentication
import CryptoKit
import DeviceCheck

/// Phase 1 Quick Wins - Immediately actionable security improvements

// MARK: - 1. Biometric-Only Keys (Secure Enclave)

extension KeyManager {
    
    /// Generate keys that ONLY work with biometric authentication
    /// Even if passcode is compromised: keys remain inaccessible
    func generateBiometricOnlyKeys() throws {
        
        // Create Access Control with STRICTEST flags
        // H12 FIX: .userPresence removed — allowed passcode fallback.
        // Only .biometryCurrentSet = true biometric-only.
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [
                .biometryCurrentSet,      // ← If biometrics change = key invalidated
                .privateKeyUsage          // ← Only for private key operations
            ],
            nil
        ) else {
            throw KeyManagerError.encryptionFailed
        }
        
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                // FIX SEC-1: Use Data for kSecAttrApplicationTag (consistent with deletion in SecurityExtensions.swift)
                kSecAttrApplicationTag as String: "com.ladon.biometric.key".data(using: .utf8)!,
                kSecAttrAccessControl as String: access
            ]
        ]
        
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw KeyManagerError.encryptionFailed
        }
        
        // FIX H-16: Verify the generated key has a valid public counterpart
        guard SecKeyCopyPublicKey(privateKey) != nil else {
            throw KeyManagerError.encryptionFailed
        }
        
        #if DEBUG
        print("✅ Biometric-only key generated in Secure Enclave")
        #endif
    }
    
    /// Decrypt mit biometric authentication (Secure Enclave ECDH)
    func decryptWithBiometric(ciphertext: Data, context: LAContext) throws -> Data {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            // FIX AUDIT-MAR-2026-5: Use Data for kSecAttrApplicationTag (consistent with storage)
            kSecAttrApplicationTag as String: "com.ladon.biometric.key".data(using: .utf8)!,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
            kSecUseAuthenticationContext as String: context
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        guard status == errSecSuccess else {
            throw KeyManagerError.keyNotFound
        }
        
        guard let item = item else {
            throw KeyManagerError.keyNotFound
        }

        guard CFGetTypeID(item) == SecKeyGetTypeID() else {
            throw KeyManagerError.keyNotFound
        }

        // FIX LOW: Safe to unwrap — CFTypeID check guarantees SecKey
        let privateKey = unsafeBitCast(item, to: SecKey.self)
        
        // Use the Secure Enclave key to decrypt via ECIES
        var error: Unmanaged<CFError>?
        guard let decrypted = SecKeyCreateDecryptedData(
            privateKey,
            .eciesEncryptionCofactorVariableIVX963SHA256AESGCM,
            ciphertext as CFData,
            &error
        ) as Data? else {
            throw KeyManagerError.decryptionFailed
        }
        
        return decrypted
    }
}

// MARK: - 2. Remote Attestation (DCAppAttestService)

class RemoteAttestation {
    static let shared = RemoteAttestation()
    private init() {}
    
    /// The attestation key ID, stored after first generation (encrypted in Keychain)
    private var attestKeyID: String? {
        get { try? SecureUserDefaults.shared.string(forKey: "ladon.attest.keyID") }
        set {
            if let newValue = newValue {
                try? SecureUserDefaults.shared.set(newValue, forKey: "ladon.attest.keyID")
            } else {
                SecureUserDefaults.shared.remove(forKey: "ladon.attest.keyID")
            }
        }
    }
    
    /// Generate or retrieve App Attest key
    func prepareAttestKey() async throws -> String {
        if let existing = attestKeyID {
            return existing
        }
        
        let service = DCAppAttestService.shared
        guard service.isSupported else {
            throw AttestationError.notSupported
        }
        
        let keyID = try await service.generateKey()
        self.attestKeyID = keyID
        
        #if DEBUG
        print("[Attestation] ✅ Generated App Attest key: \(keyID.prefix(16))...")
        #endif
        
        return keyID
    }
    
    /// Generate attestation for server verification
    /// The server challenge must be fetched from the server first
    func generateAttestation(serverChallenge: Data) async throws -> Data {
        let service = DCAppAttestService.shared
        guard service.isSupported else {
            throw AttestationError.notSupported
        }
        
        let keyID = try await prepareAttestKey()
        
        // Hash the server challenge
        let challengeHash = Data(SHA256.hash(data: serverChallenge))
        
        // Generate attestation object
        let attestation = try await service.attestKey(keyID, clientDataHash: challengeHash)
        
        #if DEBUG
        print("[Attestation] ✅ Generated attestation (\(attestation.count) bytes)")
        #endif
        
        return attestation
    }
    
    /// Generate assertion for subsequent requests (after initial attestation)
    func generateAssertion(requestData: Data) async throws -> Data {
        let service = DCAppAttestService.shared
        guard service.isSupported else {
            throw AttestationError.notSupported
        }
        
        guard let keyID = attestKeyID else {
            throw AttestationError.noKey
        }
        
        let requestHash = Data(SHA256.hash(data: requestData))
        let assertion = try await service.generateAssertion(keyID, clientDataHash: requestHash)
        
        return assertion
    }
    
    /// Full attestation flow (retired): the legacy V1 `/v1/attestation/*`
    /// endpoints are gone, so this throws `notSupported`. App Attest key/
    /// assertion support (above) stays available for a future V2 flow.
    func attestWithServer() async throws -> Bool {
        // Legacy `/v1/attestation/*` endpoints are retired. Keep local App Attest
        // key/assertion support available, but do not contact the V1 relay.
        throw AttestationError.notSupported
    }
}

enum AttestationError: Error {
    case notSupported
    case noKey
    case verificationFailed
}

