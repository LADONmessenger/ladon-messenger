// BlobRelayPinning.swift — Phase 4
//
// Dedicated SPKI pinning delegate for `blob.ladon.app` (separate vhost from
// `entry.ladon.app`, see docs/research/PHASE3_SERVER_SPEC.md §2).
//
// WHY SEPARATE
// ------------
// The entry relay delegate (`CertificatePinningDelegate`) hard-codes its
// hostname check to `entry.ladon.app` and embeds entry-relay SPKI pins. We
// MUST NOT weaken that delegate by adding a second hostname, and we MUST
// NOT route blob traffic through the entry-relay pin set because their key
// rotation cadence is independent.
//
// FAIL-CLOSED BY DEFAULT
// ----------------------
// Until Phase 7 hardening, `pinnedBlobSPKIHashes` is empty — meaning every
// TLS handshake to `blob.ladon.app` fails. Combined with
// `FeatureFlags.attachmentsEnabled == false`, the client cannot speak to
// the blob relay at all on release builds.
//
// Before flipping `attachmentsEnabled` to true, the deployer MUST:
//   1. Deploy blob-relay to blob.ladon.app and extract the server SPKI hash.
//   2. Add the BASE64-encoded SHA-256(SPKI) to `pinnedBlobSPKIHashes`.
//   3. Add a pre-generated backup-key SPKI hash for rotation.
//   4. Rebuild and release a signed app version.

import Foundation
import Security
import CryptoKit
import Network
import os.log

private let blobPinLog = OSLog(subsystem: "app.ladon.messenger", category: "BlobCertPinning")

@available(iOS 15.0, macOS 12.0, *)
final class BlobCertificatePinningDelegate: NSObject, URLSessionDelegate, URLSessionTaskDelegate {

    // MARK: - Per-host singletons (active-active sharding 2026-05-14)

    /// One delegate per blob-relay shard. Each instance owns its own
    /// pinned URLSession with shard-specific hostname + pin set, so a
    /// compromise of one shard's leaf key cannot be replayed against
    /// the other.
    nonisolated(unsafe) private static var instances: [BlobHost: BlobCertificatePinningDelegate] = [:]
    private static let instancesLock = NSLock()

    static func shared(for host: BlobHost) -> BlobCertificatePinningDelegate {
        instancesLock.lock()
        defer { instancesLock.unlock() }
        if let existing = instances[host] { return existing }
        let made = BlobCertificatePinningDelegate(host: host)
        instances[host] = made
        return made
    }

    let host: BlobHost
    private init(host: BlobHost) {
        self.host = host
        super.init()
    }

    // MARK: - Configuration

    /// Hostname this delegate accepts. Derived from the shard at init time.
    var expectedHostname: String { host.hostname }

    /// SPKI SHA-256 base64 pins, per shard.
    ///
    /// Empty set for any shard = every handshake to that shard rejected
    /// (fail-closed). Populate BEFORE flipping `FeatureFlags.attachmentsEnabled`.
    ///
    /// PIN EXTRACTION (from running server):
    ///   echo | openssl s_client -connect HOST:443 -servername HOST 2>/dev/null \
    ///     | openssl x509 -pubkey -noout \
    ///     | openssl pkey -pubin -outform der \
    ///     | openssl dgst -sha256 -binary | openssl base64
    private static let pinnedBlobSPKIHashes: [BlobHost: Set<String>] = [
        // blob-fi.ladon.app — extracted 14.05.2026 (post-rename, fresh ACME cert)
        // Both shards point at blob-ch.ladon.app since 2026-08-11. Second pin:
        // reserve key (14.10.2026, P-256), generated offline, never on a
        // server — lets the blob vhost switch keys without bricking apps.
        .fi: [
            "qv0uMgD3Jy404l7bLhNyDtHeBywCSppI/24hNijWhUg=",
            "n3+AxbgBzKeIBzeC7xPVfnG25vVK1M/ZHJe3AU/AtKA=",
        ],
        // blob-ch.ladon.app — extracted 14.05.2026 (new shard, first ACME cert)
        .ch: [
            "qv0uMgD3Jy404l7bLhNyDtHeBywCSppI/24hNijWhUg=",
            "n3+AxbgBzKeIBzeC7xPVfnG25vVK1M/ZHJe3AU/AtKA=",
        ],
    ]

    private var hostPins: Set<String> {
        Self.pinnedBlobSPKIHashes[host] ?? []
    }

    /// A new pinned URLSession with its own Tor circuit, for exactly one blob
    /// transfer (Addendum A2 stage 1). Ephemeral configuration — no disk
    /// caching of chunk data.
    ///
    /// Each session carries fresh random SOCKS5 credentials; Tor isolates
    /// streams by SOCKS credentials by default (ISO_SOCKSAUTH in ISO_DEFAULT,
    /// tor or.h), so two blob transfers never share a circuit with each other
    /// or with the V2 connections. A cached session shared by all transfers
    /// let the blob relay link one client's uploads and downloads (scan F22).
    ///
    /// `nil` when no valid Tor SOCKS5 config is available — callers MUST treat
    /// that as fail-closed (refuse to dial out) rather than falling back to a
    /// direct connection. The caller owns the session and invalidates it when
    /// the transfer is done.
    func makeIsolatedSession() -> URLSession? {
        Self.buildSession(delegate: self)
    }

    private static func buildSession(delegate: URLSessionDelegate) -> URLSession? {
        let config = URLSessionConfiguration.ephemeral
        config.tlsMinimumSupportedProtocolVersion = .TLSv13
        // Tor circuits occasionally stall for 30–90 s on hop establishment.
        // With a 60 s request timeout a single stalled chunk tore down the
        // entire multi-MB transfer. Bump both timeouts so retries (in
        // AttachmentUploader/Downloader) get a chance before URLSession
        // forcibly kills the request.
        //   request  : per-chunk wall-clock        180 s
        //   resource : total including redirects  1800 s  (30 min for 50 MB)
        // httpMaximumConnectionsPerHost raised to 8 to match new parallel
        // chunk fan-out (server per-IP gate is 8).
        config.httpMaximumConnectionsPerHost = 8
        config.timeoutIntervalForRequest = 180
        config.timeoutIntervalForResource = 1800

        if let proxyData = TorController.loadSOCKS5ConfigFromKeychain(),
           let proxyConfig = try? JSONDecoder().decode(SOCKS5Config.self, from: proxyData),
           proxyConfig.port > 0,
           let socksPort = NWEndpoint.Port(rawValue: UInt16(clamping: proxyConfig.port)) {
            // Same construction as V2SessionManager.buildV2Session: random
            // credentials per session (circuit isolation), the host name goes
            // to the proxy, and no failover to a direct connection.
            var proxy = ProxyConfiguration(socksv5Proxy: .hostPort(host: NWEndpoint.Host(proxyConfig.host), port: socksPort))
            proxy.applyCredential(username: randomBytes(16).hexEncodedString,
                                  password: randomBytes(16).hexEncodedString)
            proxy.allowFailover = false
            config.proxyConfigurations = [proxy]
            #if DEBUG
            NSLog("[BlobPinning] 🧅 session via Tor SOCKS5 %@:%d", proxyConfig.host, proxyConfig.port)
            #endif
        } else {
            // FAIL-CLOSED (P8-AUDIT5-IOS-C2): a missing or undecodable SOCKS5
            // config means Tor is not available. Building a direct (clearnet)
            // session here would de-anonymize blob/attachment traffic, violating
            // the Tor-mandatory V2 invariant. Refuse to build a session —
            // mirrors V2SessionManager.buildV2Session(requireTor:)'s fail-closed
            // path. Callers (BlobRelayClient.perform) treat nil as torNotReady.
            #if DEBUG
            NSLog("[BlobPinning] ⛔️ no Tor SOCKS5 config in keychain — refusing to build session (fail-closed)")
            #endif
            return nil
        }
        return URLSession(configuration: config, delegate: delegate, delegateQueue: nil)
    }

    // MARK: - Pinning

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        // 1. Hostname guard — reject anything that isn't our shard hostname.
        if challenge.protectionSpace.host != expectedHostname {
            #if DEBUG
            os_log("[BlobCertPinning] ❌ hostname mismatch: got=%{public}@ expected=%{public}@",
                   log: blobPinLog, type: .error,
                   challenge.protectionSpace.host, expectedHostname)
            #endif
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        // 2. Pin set must be non-empty (fail-closed).
        let pins = hostPins
        guard !pins.isEmpty else {
            #if DEBUG
            os_log("[BlobCertPinning] ❌ pin set empty for shard %{public}@ — attachments cannot ship without pins",
                   log: blobPinLog, type: .error, host.regionTag)
            #endif
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        // 3. Evaluate default trust (chain validity, dates, hostname, etc.).
        var secError: CFError?
        guard SecTrustEvaluateWithError(serverTrust, &secError) else {
            #if DEBUG
            os_log("[BlobCertPinning] ❌ SecTrust eval failed", log: blobPinLog, type: .error)
            #endif
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        // 4. Any SPKI in the chain matches a pin → accept. No match → reject.
        guard let chain = SecTrustCopyCertificateChain(serverTrust) as? [SecCertificate] else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        for cert in chain {
            if let hash = Self.spkiHash(for: cert),
               pins.contains(hash) {
                completionHandler(.useCredential, URLCredential(trust: serverTrust))
                return
            }
        }
        #if DEBUG
        os_log("[BlobCertPinning] ❌ no pin match on chain for shard %{public}@",
               log: blobPinLog, type: .error, host.regionTag)
        #endif
        completionHandler(.cancelAuthenticationChallenge, nil)
    }

    // MARK: - SPKI hash (mirrors CertificatePinningDelegate.spkiHash)

    private static func spkiHash(for certificate: SecCertificate) -> String? {
        guard let publicKey = SecCertificateCopyKey(certificate),
              let keyData = SecKeyCopyExternalRepresentation(publicKey, nil) as Data?,
              let attrs = SecKeyCopyAttributes(publicKey) as? [String: Any],
              let keyType = attrs[kSecAttrKeyType as String] as? String,
              let keySize = attrs[kSecAttrKeySizeInBits as String] as? Int else {
            return nil
        }
        let asn1Header = asn1HeaderBytes(keyType: keyType, keySize: keySize)
        guard !asn1Header.isEmpty else { return nil }
        var spkiBytes = Data(asn1Header)
        spkiBytes.append(keyData)
        let digest = SHA256.hash(data: spkiBytes)
        return Data(digest).base64EncodedString()
    }

    private static func asn1HeaderBytes(keyType: String, keySize: Int) -> [UInt8] {
        let ecKeyType = kSecAttrKeyTypeECSECPrimeRandom as String
        let rsaKeyType = kSecAttrKeyTypeRSA as String
        switch (keyType, keySize) {
        case (ecKeyType, 256):
            // SubjectPublicKeyInfo header for EC P-256.
            return [
                0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
                0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
                0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
                0x42, 0x00,
            ]
        case (rsaKeyType, 2048):
            return [
                0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09,
                0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
                0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00,
            ]
        case (rsaKeyType, 4096):
            return [
                0x30, 0x82, 0x02, 0x22, 0x30, 0x0d, 0x06, 0x09,
                0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
                0x01, 0x05, 0x00, 0x03, 0x82, 0x02, 0x0f, 0x00,
            ]
        default:
            return []
        }
    }
}
