import Foundation
import Security
import CryptoKit
import os.log

private let pinningLog = OSLog(subsystem: "app.ladon.messenger", category: "CertPinning")

/// Centralized certificate pinning delegate (Singleton).
/// Enforces SPKI (Subject Public Key Info) pinning per RFC 7469.
/// Used by ALL URLSessions to ensure consistent security across the app.
///
/// THREAT MODEL:
/// - Protects against MITM attacks where attacker has compromised a subordinate CA
/// - Survives CA rotation because we pin the server's actual key, not the CA key
/// - TOFU (Trust On First Use) learning for non-production pin rotations (30-day TTL)
/// - H1 FIX: TOFU learning is DISABLED — new pins require admin review (code comment)
class CertificatePinningDelegate: NSObject, URLSessionDelegate, URLSessionTaskDelegate {
    
    /// Singleton instance — used by ALL URLSessions in the app
    static let shared = CertificatePinningDelegate()
    private override init() {
        super.init()
        #if DEBUG
        os_log("[CertPinning] 🔐 Singleton initialized", log: pinningLog, type: .info)
        os_log("[CertPinning] 📌 Loaded %d SPKI pins", log: pinningLog, type: .info, Self.pinnedSPKIHashes.count)
        if let _ = self.pinnedCertData {
            os_log("[CertPinning] 🔒 LadonRelay.cer bundle found", log: pinningLog, type: .info)
        } else {
            os_log("[CertPinning] ⚠️ LadonRelay.cer bundle NOT found (optional for strict pinning)", log: pinningLog, type: .error)
        }
        #endif
    }
    
    // MARK: - Cached URLSession
    
    /// Cached URLSession configured with this pinning delegate.
    /// Ephemeral configuration ensures no disk caching.
    /// Reused for all requests to reduce resource overhead.
    lazy var pinnedURLSession: URLSession = {
        let config = URLSessionConfiguration.ephemeral
        // FIX M-10: Enforce TLS 1.3 minimum — prevents downgrade to TLS 1.2
        config.tlsMinimumSupportedProtocolVersion = .TLSv13
        return URLSession(configuration: config, delegate: self, delegateQueue: nil)
    }()
    
    // MARK: - Configuration

    /// All hostnames the app may legally connect to. Any other hostname is rejected.
    /// Phase-5 cutover: V1 `entry.ladon.app` removed from trusted hosts.
    /// Stage B (2026-05-05): split-topology hostnames (entry-ch/fi, exit-is1/is2/pa1, push).
    /// Old per-region hostnames (ch1/fi1/is1/is2/pa1) removed — bootstrap.json no longer references them.
    // 2026-08-11: Die gemieteten Hosts wurden abbestellt; entry-fi und die drei
    // Exit-Hostnamen existieren nicht mehr im DNS und stehen nicht mehr in
    // exits-bootstrap.json. Der Exit laeuft jetzt rein intern hinter dem Entry
    // und wird vom Client nie direkt kontaktiert.
    private static let trustedHostnames: Set<String> = [
        "entry-ch.ladon.app",  // V2 Entry
    ]

    /// #23: bootstrap defense-in-depth. `ExitRegistryV2` asserts that every
    /// entry/push hostname it loads from the bundled bootstrap is a pinned host,
    /// so a tampered bundle is rejected fast at load rather than only failing
    /// the pinned TLS handshake later. Same source of truth as the challenge
    /// handler's `trustedHostnames.contains` check.
    static func isPinnedHostname(_ host: String) -> Bool {
        trustedHostnames.contains(host)
    }

    // MARK: - SPKI Pin Configuration

    // ── FIX CP-1 (2026-05-06): Per-host SERVER-KEY SPKI pins ────────────────
    // v1 had server-key SPKI pins for entry.ladon.app (primary + backup).
    // v2 had regressed to LE-Issuer-CA pins, which would let any compelled-LE
    // cert through. This restores v1-equivalent server-key pinning.
    //
    // Extracted live from each pilot host on 2026-05-06 via:
    //   openssl s_client -servername <host> -connect <host>:443 |
    //   openssl x509 -noout -pubkey | openssl pkey -pubin -outform DER |
    //   openssl dgst -sha256 -binary | openssl enc -base64
    //
    // SERVER PREREQUISITE (Caddy reuse_private_key, 2026-05-06):
    //   tls { issuer acme { reuse_private_key } } must be set in every pilot
    //   Caddyfile so LE renewal does NOT rotate the private key. Without
    //   reuse_private_key the leaf SPKI changes every ~60 d and these pins
    //   would brick the app at next renewal.
    //
    // ROTATION PLAYBOOK (when a pilot host is compromised or replaced):
    //   1. On the new host: openssl … -outform DER | sha256 | base64 → new pin
    //   2. Update the constant below + ship a new app version
    //   3. Old + new pin can be temporarily listed together during cutover
    // 2026-08-11: Relay umgezogen, neues ACME-Zertifikat.
    private static let entryChServerKeyPin = "ZM+4zB9tAadG79dLp8cNu8f3o6AcOM+w8UKWOFZh114="
    // Reserve key (14.10.2026, P-256): generated offline, never on a server.
    // Lets the entry switch keys after loss or compromise without bricking
    // installed apps. After a switch, remove the old pin in the next release.
    private static let entryChReserveKeyPin = "nQilVLX0SMzIbBj59VP2rbFLBmF9FtNR8WVFK3hgMmo="
    private static let entryFiServerKeyPin = "0dOcnlEH3D1OCs6mj2ZSIw17StOJXqdPtimr75e9MPc="
    private static let exitIs1ServerKeyPin = "GgL8/PJ3/aucCi2DhCTQIRtOCkOWBtVxcbGljQ1kExQ="
    private static let exitIs2ServerKeyPin = "y9qgitAQfJpqsCArnyxaIqtzFoXk/FLvoBsJYtRFQYU="
    private static let exitPa1ServerKeyPin = "A3aC0l08OVHCT5uefDLGCk3xCMMEUw7EqnC/n8aENvI="

    /// Per-hostname allowed SPKI set. A connection is accepted iff `trustedHostnames`
    /// contains the request host AND at least one cert in the validated chain has its
    /// SPKI in `pinsByHost[host]`.
    ///
    /// Each set contains ONLY the live server-key SPKI. Issuer-CA fallback was
    /// removed in FIX CP-1 because issuer pinning lets any compelled-LE cert
    /// through — it is not a meaningful defence against a state-level adversary.
    private static let pinsByHost: [String: Set<String>] = [
        "entry-ch.ladon.app": [entryChServerKeyPin, entryChReserveKeyPin],
    ]

    /// Convenience: union of all pins (for diagnostic logging only).
    private static let pinnedSPKIHashes: Set<String> = {
        var all: Set<String> = []
        for s in pinsByHost.values { all.formUnion(s) }
        return all
    }()
    
    /// Optional: Load a bundled DER certificate for strict pinning.
    /// If present, trust chain MUST end at this certificate.
    /// This provides an additional layer of pinning beyond SPKI pinning.
    private let pinnedCertData: Data? = {
        guard let url = Bundle.main.url(forResource: "LadonRelay", withExtension: "cer") else {
            return nil
        }
        return try? Data(contentsOf: url)
    }()
    
    // FIX H-05: All TOFU (Trust On First Use) pin storage code REMOVED.
    // Previously contained: pinStorageKey, hmacKeyAccount, tofuPinTTLSeconds,
    // getOrCreateHMACKey(), loadStoredPins(), loadStoredPinsWithTimestamps(), storePin().
    // This was dead code (never called after H-02 fix disabled TOFU loading),
    // but its presence was an attack surface — code injection could reactivate it.
    // TOFU is fundamentally incompatible with a state-level threat model.
    
    // MARK: - SPKI Hash Extraction
    
    /// Extract SPKI (Subject Public Key Info) SHA256 hash from a certificate.
    /// Returns BASE64-encoded hash suitable for comparison with RFC 7469 pins.
    ///
    /// Process:
    /// 1. Extract public key from certificate
    /// 2. Get raw key bytes (DER format)
    /// 3. Wrap with appropriate ASN.1 header for key type/size
    /// 4. SHA256 hash the complete SPKI structure
    /// 5. Return BASE64 encoding
    ///
    /// This matches the OpenSSL output:
    /// `openssl x509 -in cert.pem -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | openssl enc -base64`
    private func spkiHash(for certificate: SecCertificate) -> String? {
        // Step 1: Extract public key from certificate
        guard let publicKey = SecCertificateCopyKey(certificate) else {
            #if DEBUG
            os_log("[CertPinning] ❌ Failed to extract public key from certificate", log: pinningLog, type: .error)
            #endif
            return nil
        }
        
        // Step 2: Get raw key data
        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
            #if DEBUG
            os_log("[CertPinning] ❌ Failed to export public key data", log: pinningLog, type: .error)
            #endif
            return nil
        }
        
        // Step 3: Determine key type and size to select correct SPKI header
        let attributes = SecKeyCopyAttributes(publicKey) as? [String: Any]
        let keyType = attributes?[kSecAttrKeyType as String] as? String
        let keySize = attributes?[kSecAttrKeySizeInBits as String] as? Int ?? 0
        
        // Step 4: Select appropriate ASN.1 SPKI header based on key type
        let header: Data
        if keyType == (kSecAttrKeyTypeECSECPrimeRandom as String) {
            // Elliptic Curve key
            if keySize <= 256 {
                header = Self.ecP256SPKIHeader
            } else {
                header = Self.ecP384SPKIHeader
            }
        } else {
            // RSA key (default)
            // FIX SEC-6: Add RSA-3072 header — previously treated as RSA-4096 (wrong ASN.1 lengths)
            if keySize <= 2048 {
                header = Self.rsa2048SPKIHeader
            } else if keySize <= 3072 {
                header = Self.rsa3072SPKIHeader
            } else {
                header = Self.rsa4096SPKIHeader
            }
        }
        
        // Step 5: Combine ASN.1 header + raw key to form full SPKI DER
        var spkiData = Data()
        spkiData.append(header)
        spkiData.append(publicKeyData)
        
        // Step 6: SHA256 hash and BASE64 encode
        let hash = SHA256.hash(data: spkiData)
        let base64Hash = Data(hash).base64EncodedString()
        
        #if DEBUG
        os_log("[CertPinning] ℹ️ Extracted SPKI hash (key type: %@, size: %d bits): %@",
               log: pinningLog, type: .debug, keyType ?? "unknown", keySize, base64Hash)
        #endif
        
        return base64Hash
    }
    
    /// ASN.1 DER headers for different public key types.
    /// These headers are prepended to raw key bytes to form valid SPKI structures.
    /// Headers are defined per RFC 5480 (ECDSA in X.509) and RFC 3447 (PKCS #1).
    
    private static let ecP256SPKIHeader = Data([
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86,
        0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A,
        0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03,
        0x42, 0x00
    ])
    
    private static let ecP384SPKIHeader = Data([
        0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2A, 0x86,
        0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x05, 0x2B,
        0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00
    ])
    
    private static let rsa2048SPKIHeader = Data([
        0x30, 0x82, 0x01, 0x22, 0x30, 0x0D, 0x06, 0x09,
        0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01,
        0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0F, 0x00
    ])
    
    // FIX SEC-6: RSA-3072 SPKI header (ASN.1 DER for 384-byte RSA public key)
    private static let rsa3072SPKIHeader = Data([
        0x30, 0x82, 0x01, 0xA2, 0x30, 0x0D, 0x06, 0x09,
        0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01,
        0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x8F, 0x00
    ])
    
    private static let rsa4096SPKIHeader = Data([
        0x30, 0x82, 0x02, 0x22, 0x30, 0x0D, 0x06, 0x09,
        0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01,
        0x01, 0x05, 0x00, 0x03, 0x82, 0x02, 0x0F, 0x00
    ])
    
    // MARK: - URLSessionDelegate (Challenge Handling)
    
    /// Called when URLSession needs server trust validation.
    /// Performs both standard TLS verification AND SPKI pinning.
    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        handleChallenge(challenge, completionHandler: completionHandler)
    }
    
    /// Called first for task-specific challenges (takes precedence over session delegate).
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        handleChallenge(challenge, completionHandler: completionHandler)
    }
    
    /// Common handler for all trust challenges.
    /// SECURITY FLOW:
    /// 1. Validate hostname matches expected relay server
    /// 2. Verify it's a server trust challenge (not client auth, etc)
    /// 3. Perform standard TLS verification (certificate chain validation)
    /// 4. Extract SPKI hashes from entire certificate chain
    /// 5. Verify at least ONE certificate matches a pinned SPKI hash
    /// 6. Accept connection only if ALL checks pass
    private func handleChallenge(
        _ challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        // Step 1: Validate hostname against the trusted-host whitelist
        let requestHostname = challenge.protectionSpace.host
        guard Self.trustedHostnames.contains(requestHostname),
              let allowedPins = Self.pinsByHost[requestHostname] else {
            #if DEBUG
            os_log("[CertPinning] ❌ REJECT: Untrusted hostname %{public}@",
                   log: pinningLog, type: .error, requestHostname)
            #endif
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        // Step 2: Verify this is a server trust challenge
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust else {
            #if DEBUG
            os_log("[CertPinning] ❌ REJECT: Not a server trust challenge (got %@)",
                   log: pinningLog, type: .error, challenge.protectionSpace.authenticationMethod)
            #endif
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        // Step 3: Get the server trust object
        guard let serverTrust = challenge.protectionSpace.serverTrust else {
            #if DEBUG
            os_log("[CertPinning] ❌ REJECT: No server trust object", log: pinningLog, type: .error)
            #endif
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        // Step 4: If bundled certificate exists, configure it as trust anchor
        if let pinnedCertData, let pinnedCert = SecCertificateCreateWithData(nil, pinnedCertData as CFData) {
            SecTrustSetAnchorCertificates(serverTrust, [pinnedCert] as CFArray)
            SecTrustSetAnchorCertificatesOnly(serverTrust, true)
        }
        
        // Step 5: Perform standard TLS verification
        var trustError: CFError?
        let isTrusted = SecTrustEvaluateWithError(serverTrust, &trustError)
        guard isTrusted else {
            #if DEBUG
            os_log("[CertPinning] ❌ REJECT: TLS verification failed: %@",
                   log: pinningLog, type: .error, String(describing: trustError))
            #endif
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        // Step 6: Extract certificate chain and validate SPKI pins
        let certChain: [SecCertificate]
        if let chain = SecTrustCopyCertificateChain(serverTrust) as? [SecCertificate] {
            certChain = chain
        } else {
            #if DEBUG
            os_log("[CertPinning] ❌ REJECT: Cannot extract certificate chain", log: pinningLog, type: .error)
            #endif
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        // Step 7: Check if ANY certificate in chain matches ANY pin allowed for this host
        var matched = false
        var leafSPKI: String?

        for (index, cert) in certChain.enumerated() {
            guard let hash = spkiHash(for: cert) else {
                continue
            }

            // Track leaf SPKI for debugging
            if index == 0 {
                leafSPKI = hash
            }

            // Per-host pin lookup (allowedPins captured above for requestHostname).
            if allowedPins.contains(hash) {
                matched = true
                #if DEBUG
                os_log("[CertPinning] ✅ ACCEPT: SPKI pin matched at chain position %d for %{public}@",
                       log: pinningLog, type: .info, index, requestHostname)
                #endif
                break
            }
        }
        
        guard matched else {
            #if DEBUG
            os_log("[CertPinning] ❌ REJECT: No certificate in chain matched any pinned SPKI hash",
                   log: pinningLog, type: .error)
            if let leafSPKI {
                os_log("[CertPinning] ℹ️ Leaf SPKI found but not pinned: %@", log: pinningLog, type: .info, leafSPKI)
            }
            #endif
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        // FIX H-05: TOFU pin rotation notice removed (no backup CA pins to validate against).
        // With only server-key SPKI pins, leaf always matches directly or connection is rejected.
        
        // Accept connection
        #if DEBUG
        os_log("[CertPinning] ✅ All checks passed — accepting TLS connection to %{public}@",
               log: pinningLog, type: .info, requestHostname)
        #endif
        let credential = URLCredential(trust: serverTrust)
        completionHandler(.useCredential, credential)
    }
}
