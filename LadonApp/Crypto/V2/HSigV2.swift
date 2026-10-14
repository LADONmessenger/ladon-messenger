//
//  HSigV2.swift
//  Ladon — Hybrid signature (Ed25519 + ML-DSA-65) per Spec §3.2.
//
//  Mirrors `relay-core-v2/src/hsig.rs`. Byte-identical signatures are NOT
//  required (both schemes are randomized), but verification across both
//  implementations IS required.
//
//  SECURITY PROPERTIES (FIX INFO-HSIG-DOCS):
//  - Ed25519 provides classical authentication + forward secrecy protection
//  - ML-DSA-65 provides post-quantum authentication against harvest-now-decrypt-later
//  - Both must verify independently — single-algorithm compromise doesn't break the protocol
//  - Prehashing with domain separator prevents transcript collisions
//  - Length validation at entry prevents interop confusion
//
//  Construction (Addendum A1 §10 — every signature carries a usecase tag):
//      pre   = BLAKE3("L1-Sig-v1" || u8(len(tag)) || tag || m)   (32 B)
//      σ_ed  = Ed25519.Sign(sk_ed, pre)            (64 B)
//      σ_dil = ML-DSA-65.Sign(sk_dil, pre)         (3,309 B detached)
//      σ     = σ_ed || σ_dil                       (3,373 B)
//      pk    = pk_ed || pk_dil                     (1,984 B)
//

import Foundation
import CryptoKit

/// Long-term hybrid signing keypair (signs bundles, fetches, push registrations
/// and the sealed-sender inner envelope — each under its own usecase tag).
struct HSigKeyPairV2 {
    let edSk: Curve25519.Signing.PrivateKey
    let edPk: Data                                       // 32 B
    /// Dilithium3 / ML-DSA-65 secret key bytes (4,032 B).
    let dilSk: Data
    /// Dilithium3 / ML-DSA-65 public key bytes (1,952 B).
    let dilPk: Data

    /// Generate a fresh keypair using OS randomness.
    static func generate() throws -> HSigKeyPairV2 {
        let edSk = Curve25519.Signing.PrivateKey()
        let edPk = edSk.publicKey.rawRepresentation
        let dil = try PostQuantumService.shared.generateDilithiumKeypair()
        return HSigKeyPairV2(edSk: edSk, edPk: edPk, dilSk: dil.secretKey, dilPk: dil.publicKey)
    }

    /// Reconstruct from raw key components (e.g. loaded from Keychain).
    init(edSkRaw: Data, dilSk: Data, dilPk: Data) throws {
        guard edSkRaw.count == LadonV2.ed25519PkLen else {
            throw LadonV2Error.shortBuffer(expected: LadonV2.ed25519PkLen, got: edSkRaw.count)
        }
        guard dilSk.count == LadonV2.dilithium3PkLen + 0 || dilSk.count == 4032 else {
            throw LadonV2Error.shortBuffer(expected: 4032, got: dilSk.count)
        }
        guard dilPk.count == LadonV2.dilithium3PkLen else {
            throw LadonV2Error.shortBuffer(expected: LadonV2.dilithium3PkLen, got: dilPk.count)
        }
        self.edSk = try Curve25519.Signing.PrivateKey(rawRepresentation: edSkRaw)
        self.edPk = self.edSk.publicKey.rawRepresentation
        self.dilSk = dilSk
        self.dilPk = dilPk
    }

    fileprivate init(edSk: Curve25519.Signing.PrivateKey, edPk: Data, dilSk: Data, dilPk: Data) {
        self.edSk = edSk
        self.edPk = edPk
        self.dilSk = dilSk
        self.dilPk = dilPk
    }

    /// 1,984-byte wire-format public key: `pk_ed (32) || pk_dil (1,952)`.
    func publicKeyBytes() -> Data {
        var out = Data(capacity: LadonV2.hsigPkLen)
        out.append(edPk)
        out.append(dilPk)
        precondition(out.count == LadonV2.hsigPkLen)
        return out
    }
}

/// Usecase tags (A1 §10), mirroring `HSIG_USECASE_*` in
/// `relay-core-v2/src/hsig.rs`. Signatures of different contexts live in
/// disjoint hash domains, so one can never be offered in another context.
/// There is no untagged signature anywhere — not as a fallback either.
enum HSigUsecaseV2 {
    case bundle
    case fetch
    case pushRegister
    case innerSender
    /// Pairing code (P8-AUDIT8-IOS-30): the owner signs one-time prekey, its
    /// sequence, expiry hint and delivery key. Verified only by apps.
    case pairing

    var tag: Data {
        switch self {
        case .bundle:       return Data("L1-Bundle-v3".utf8)
        case .fetch:        return Data("L1-Fetch-v2.1".utf8)
        case .pushRegister: return Data("L1-PushRegister-v3".utf8)
        case .innerSender:  return Data("L1-InnerSender-v3".utf8)
        case .pairing:      return Data("L1-Pairing-v1".utf8)
        }
    }
}

enum HSigV2 {

    /// `pre = BLAKE3("L1-Sig-v1" || u8(len(tag)) || tag || m)` — 32 B. The
    /// length prefix keeps two tags from colliding even if one is a prefix
    /// of the other.
    static func prehash(_ m: Data, usecase: HSigUsecaseV2) -> Data {
        let tag = usecase.tag
        precondition(tag.count <= Int(UInt8.max), "usecase tag too long")
        let h = Blake3.Hasher()
        h.update(LadonV2.domainSign)
        h.update(Data([UInt8(tag.count)]))
        h.update(tag)
        h.update(m)
        return h.finalize(outputLength: 32)
    }

    /// Sign message `m` under `usecase`. Returns the 3,373-byte hybrid
    /// signature `σ_ed || σ_dil`.
    static func sign(_ m: Data, usecase: HSigUsecaseV2, with kp: HSigKeyPairV2) throws -> Data {
        let pre = prehash(m, usecase: usecase)
        let sigEd = try kp.edSk.signature(for: pre)
        guard sigEd.count == LadonV2.ed25519SigLen else {
            throw LadonV2Error.cryptoFailure("Ed25519 signature wrong length \(sigEd.count)")
        }
        let sigDil = try PostQuantumService.shared.signDilithium(message: pre, secretKey: kp.dilSk)
        guard sigDil.count == LadonV2.dilithium3SigLen else {
            throw LadonV2Error.cryptoFailure("ML-DSA-65 signature wrong length \(sigDil.count)")
        }
        var out = Data(capacity: LadonV2.hsigSigLen)
        out.append(sigEd)
        out.append(sigDil)
        precondition(out.count == LadonV2.hsigSigLen)
        return out
    }

    /// Verify a hybrid signature made under `usecase`. Returns true iff BOTH
    /// classical and PQ verifications succeed.
    /// FIX F-CRYPTO-009: Robust length validation and interop handling.
    static func verify(message m: Data, usecase: HSigUsecaseV2, signature sig: Data, publicKey pk: Data) -> Bool {
        // F-CRYPTO-009: Strict length validation to prevent interop confusion.
        guard pk.count == LadonV2.hsigPkLen else {
            // Log length mismatch for security audit.
            SecureLogger.debug("[HSigV2] Invalid PK length: \(pk.count) != \(LadonV2.hsigPkLen)")
            return false
        }
        guard sig.count == LadonV2.hsigSigLen else {
            // Log signature length mismatch.
            SecureLogger.debug("[HSigV2] Invalid Sig length: \(sig.count) != \(LadonV2.hsigSigLen)")
            return false
        }
        
        let pre = prehash(m, usecase: usecase)
        let edPk = pk.prefix(LadonV2.ed25519PkLen)
        let dilPk = pk.suffix(from: LadonV2.ed25519PkLen)
        let sigEd = sig.prefix(LadonV2.ed25519SigLen)
        let sigDil = sig.suffix(from: LadonV2.ed25519SigLen)

        guard let edKey = try? Curve25519.Signing.PublicKey(rawRepresentation: Data(edPk)) else {
            SecureLogger.debug("[HSigV2] Failed to parse Ed25519 PK")
            return false
        }
        guard edKey.isValidSignature(Data(sigEd), for: pre) else {
            SecureLogger.debug("[HSigV2] Ed25519 verification failed")
            return false
        }
        
        // F-CRYPTO-009: Log PQ verification result for interop debugging.
        let pqResult = PostQuantumService.shared.verifyDilithium(
            message: pre, signature: Data(sigDil), publicKey: Data(dilPk)
        )
        if !pqResult {
            SecureLogger.debug("[HSigV2] Dilithium verification failed")
        }
        return pqResult
    }
}
