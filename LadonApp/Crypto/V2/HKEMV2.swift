//
//  HKEMV2.swift
//  Ladon — Hybrid KEM (X25519 + ML-KEM-768) per Spec §3.3.
//
//  Combiner (PQCrypto 2019, Bindel et al.) — v2.1 transcript (P7-RCV2-02):
//      K = HKDF-SHA256(
//            ikm  = K_x || K_ky,
//            salt = "L1-HKEM-v1",
//            info = "L1-HKEM-v2.1-info" || pk_bytes || epk_x || ct_ky,
//            L    = 32)
//
//  The recipient public key is bound into `info` to foreclose cross-PK
//  reuse of a (k_x, k_ky) pair. Must stay in lockstep with the Rust
//  reference at `relay-core-v2/src/hkem.rs`.
//

import Foundation
import CryptoKit

/// P7-RCV2-02 transcript tag. Must equal `HKEM_INFO_TAG` in Rust.
private let HKEM_INFO_TAG: Data = Data("L1-HKEM-v2.1-info".utf8)

/// Long-term HKEM keypair (recipient or exit-relay).
struct HKEMKeyPairV2 {
    let xSk: Curve25519.KeyAgreement.PrivateKey
    let xPk: Data                                       // 32 B
    let kySk: Data                                      // 2,400 B (Kyber768 sk)
    let kyPk: Data                                      // 1,184 B (Kyber768 pk)

    /// Generate a fresh HKEM keypair using OS randomness.
    static func generate() throws -> HKEMKeyPairV2 {
        let xSk = Curve25519.KeyAgreement.PrivateKey()
        let xPk = xSk.publicKey.rawRepresentation
        let ky = try PostQuantumService.shared.generateKyberKeypair()
        return HKEMKeyPairV2(xSk: xSk, xPk: xPk, kySk: ky.secretKey, kyPk: ky.publicKey)
    }

    /// 1,216-byte wire-format public key: `pk_x (32) || pk_ky (1,184)`.
    func publicKeyBytes() -> Data {
        var out = Data(capacity: LadonV2.hkemPkLen)
        out.append(xPk)
        out.append(kyPk)
        precondition(out.count == LadonV2.hkemPkLen)
        return out
    }
}

/// Output of `HKEMV2.encaps`.
struct HKEMEncapsResult {
    let sharedKey: Data        // 32 B
    let ciphertext: Data       // 1,120 B = epk_x (32) || ct_ky (1,088)
}

enum HKEMV2 {

    /// HKEM encapsulation. Spec §3.3 — `Encaps(pk) -> (ct, K)`.
    static func encaps(publicKey pk: Data) throws -> HKEMEncapsResult {
        guard pk.count == LadonV2.hkemPkLen else {
            throw LadonV2Error.shortBuffer(expected: LadonV2.hkemPkLen, got: pk.count)
        }
        // Parse classical and PQ halves of the recipient's public key.
        let xPkBytes = pk.prefix(LadonV2.x25519PkLen)
        let kyPkBytes = pk.suffix(from: LadonV2.x25519PkLen)
        let xPk: Curve25519.KeyAgreement.PublicKey
        do {
            xPk = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: Data(xPkBytes))
        } catch {
            throw LadonV2Error.cryptoFailure("invalid X25519 public key: \(error)")
        }

        // Ephemeral X25519 sender key.
        let eSk = Curve25519.KeyAgreement.PrivateKey()
        let ePk = eSk.publicKey.rawRepresentation
        let kX: SharedSecret
        do {
            kX = try eSk.sharedSecretFromKeyAgreement(with: xPk)
        } catch {
            throw LadonV2Error.cryptoFailure("X25519 ECDH failed: \(error)")
        }

        // ML-KEM-768 encapsulation.
        // FIX AUDIT3-IOS-05: var (not let) so we can in-place-wipe sharedSecret + ciphertext
        // copies after they're consumed (refcount=1 → no CoW). The returned `ct` is a
        // separately-allocated buffer (built via `ct.append(...)` below).
        var kyEncaps = try PostQuantumService.shared.encapsulateKyber(publicKey: Data(kyPkBytes))

        // Combiner: ikm = K_x || K_ky,
        // info = HKEM_INFO_TAG || pk_bytes || epk_x || ct_ky  (P7-RCV2-02).
        // FIX AUDIT3-IOS-05: var (not let) — refcount=1 so .securelyWipe() actually
        // zeros the backing buffer instead of triggering a CoW-detach.
        var xSecret = kX.withUnsafeBytes { Data($0) }
        defer { xSecret.securelyWipe() }
        guard xSecret.count == 32, kyEncaps.sharedSecret.count == 32 else {
            throw LadonV2Error.cryptoFailure("HKEM ikm component length mismatch")
        }
        var ikm = Data(capacity: 64)
        ikm.append(xSecret)
        ikm.append(kyEncaps.sharedSecret)
        defer { ikm.securelyWipe() }

        // Transcript MUST match `relay-core-v2/src/hkem.rs` (commit 9815ecc):
        // info = HKEM_INFO_TAG || pk_bytes || epk_x || ct_ky.
        var info = Data(capacity: HKEM_INFO_TAG.count + LadonV2.hkemPkLen + LadonV2.hkemCtLen)
        info.append(HKEM_INFO_TAG)
        info.append(pk)
        info.append(ePk)
        info.append(kyEncaps.ciphertext)

        let derived = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: ikm),
            salt: LadonV2.hkemSalt,
            info: info,
            outputByteCount: 32
        )
        let sharedKey = derived.withUnsafeBytes { Data($0) }

        // ct = epk_x || ct_ky.
        var ct = Data(capacity: LadonV2.hkemCtLen)
        ct.append(ePk)
        ct.append(kyEncaps.ciphertext)
        precondition(ct.count == LadonV2.hkemCtLen)

        // FIX AUDIT3-IOS-05: wipe Kyber sharedSecret + ciphertext copies held inside
        // `kyEncaps`. The struct was declared `var`, refcount on the inner Data buffers
        // is 1 (no other references), so in-place mutating wipe is effective.
        kyEncaps.sharedSecret.securelyWipe()
        kyEncaps.ciphertext.securelyWipe()

        return HKEMEncapsResult(sharedKey: sharedKey, ciphertext: ct)
    }

    /// HKEM decapsulation. Spec §3.3 — `Decaps(sk, ct) -> K`.
    /// (Used on the iOS side only when reading messages we addressed to ourselves
    /// or when implementing an exit-relay variant; not needed for the standard
    /// sender path. Provided for symmetry and self-test coverage.)
    static func decaps(keyPair kp: HKEMKeyPairV2, ciphertext ct: Data) throws -> Data {
        guard ct.count == LadonV2.hkemCtLen else {
            throw LadonV2Error.shortBuffer(expected: LadonV2.hkemCtLen, got: ct.count)
        }
        let epkBytes = ct.prefix(LadonV2.x25519CtLen)
        let ctKy = ct.suffix(from: LadonV2.x25519CtLen)

        let epk: Curve25519.KeyAgreement.PublicKey
        do {
            epk = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: Data(epkBytes))
        } catch {
            throw LadonV2Error.cryptoFailure("invalid X25519 ephemeral key: \(error)")
        }
        let kX = try kp.xSk.sharedSecretFromKeyAgreement(with: epk)
        // FIX AUDIT3-IOS-05: var so wipe is effective (refcount=1).
        var kKy = try PostQuantumService.shared.decapsulateKyber(ciphertext: Data(ctKy), secretKey: kp.kySk)
        defer { kKy.securelyWipe() }

        var xSecret = kX.withUnsafeBytes { Data($0) }
        defer { xSecret.securelyWipe() }
        var ikm = Data(capacity: 64)
        ikm.append(xSecret)
        ikm.append(kKy)
        defer { ikm.securelyWipe() }

        // Transcript MUST match encaps + Rust decaps:
        // info = HKEM_INFO_TAG || pk_bytes || epk_x || ct_ky  (P7-RCV2-02).
        let pkBytes = kp.publicKeyBytes()
        var info = Data(capacity: HKEM_INFO_TAG.count + LadonV2.hkemPkLen + LadonV2.hkemCtLen)
        info.append(HKEM_INFO_TAG)
        info.append(pkBytes)
        info.append(Data(epkBytes))
        info.append(Data(ctKy))

        let derived = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: ikm),
            salt: LadonV2.hkemSalt,
            info: info,
            outputByteCount: 32
        )
        let sharedKey = derived.withUnsafeBytes { Data($0) }
        return sharedKey
    }
}

// MARK: - Reload from raw bytes (Keychain / persisted identity)

extension HKEMKeyPairV2 {
    /// Reconstruct an HKEM keypair from raw byte components (e.g. previously
    /// generated and persisted in the Keychain).
    /// - Parameters:
    ///   - xSkRaw: 32-byte X25519 private scalar
    ///   - kySk: implementation-specific Kyber768 / ML-KEM-768 secret key
    ///   - kyPk: 1,184-byte Kyber768 public key
    static func fromRaw(xSkRaw: Data, kySk: Data, kyPk: Data) throws -> HKEMKeyPairV2 {
        guard xSkRaw.count == LadonV2.x25519PkLen else {
            throw LadonV2Error.shortBuffer(expected: LadonV2.x25519PkLen, got: xSkRaw.count)
        }
        guard kyPk.count == LadonV2.kyber768PkLen else {
            throw LadonV2Error.shortBuffer(expected: LadonV2.kyber768PkLen, got: kyPk.count)
        }
        guard !kySk.isEmpty else {
            throw LadonV2Error.shortBuffer(expected: 1, got: 0)
        }
        let priv = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: xSkRaw)
        return HKEMKeyPairV2(
            xSk: priv,
            xPk: priv.publicKey.rawRepresentation,
            kySk: kySk,
            kyPk: kyPk
        )
    }
}
