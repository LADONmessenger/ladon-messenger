import Foundation
import Security
import CArgon2

// =============================================================================
// ARGON2ID (RFC 9106) — on the reference implementation
// =============================================================================
//
// Until 13.10.2026 this was a pure-Swift implementation that, by its own
// comment, used a "simplified" data-independent PRNG and did not match the
// RFC 9106 test vectors (checked against the P-H-C reference: the RFC 9106
// §5.3 vector gave e9d881b2… instead of 0d640df5…). It now calls the
// reference C implementation by the Argon2 authors (P-H-C/phc-winner-argon2,
// commit f57e61e, CC0/Apache-2.0), vendored in the CArgon2 target: portable
// "ref" variant (the "opt" variant needs x86 SSE), compiled with
// optimisation in every configuration, one thread per lane. The reference
// clears its working memory after each run.
//
// Parameters used by LADON messenger (crypto-guard): m = 65536 KiB (64 MiB),
// t = 3, p = 4, 32-byte output.
// =============================================================================

public enum Argon2id {

    /// Derive a key from a password with Argon2id (version 0x13).
    ///
    /// - Parameters:
    ///   - password: The password bytes (P), not empty
    ///   - salt: Random salt, at least 8 bytes, recommended 16 (S)
    ///   - secret: Optional secret value (K)
    ///   - associatedData: Optional associated data (X)
    ///   - timeCost: Number of passes (t), at least 1
    ///   - memoryCost: Memory in KiB (m), at least 8 × parallelism
    ///   - parallelism: Number of lanes (p), at least 1 — also the thread count
    ///   - outputLength: Tag length in bytes (τ), at least 4
    public static func hash(
        password: Data,
        salt: Data,
        secret: Data = Data(),
        associatedData: Data = Data(),
        timeCost: UInt32 = 3,
        memoryCost: UInt32 = 65536,
        parallelism: UInt32 = 4,
        outputLength: UInt32 = 32
    ) throws -> Data {
        // Same input rules as before; the reference enforces them as well.
        guard !password.isEmpty else { throw Argon2Error.emptyPassword }
        guard salt.count >= 8 else { throw Argon2Error.saltTooShort }
        guard timeCost >= 1 else { throw Argon2Error.invalidTimeCost }
        guard parallelism >= 1 && parallelism <= 0xFFFFFF else { throw Argon2Error.invalidParallelism }
        guard outputLength >= 4 else { throw Argon2Error.outputTooShort }
        guard memoryCost >= 8 * parallelism else { throw Argon2Error.memoryCostTooLow }

        var out = Data(count: Int(outputLength))
        var pwd = password
        var sec = secret
        var ad = associatedData
        var sl = salt
        defer {
            pwd.securelyWipe()
            sec.securelyWipe()
        }
        let rc: Int32 = out.withUnsafeMutableBytes { outBuf in
            pwd.withUnsafeMutableBytes { pwdBuf in
                sl.withUnsafeMutableBytes { saltBuf in
                    sec.withUnsafeMutableBytes { secBuf in
                        ad.withUnsafeMutableBytes { adBuf in
                            var ctx = argon2_context()
                            ctx.out = outBuf.bindMemory(to: UInt8.self).baseAddress
                            ctx.outlen = outputLength
                            ctx.pwd = pwdBuf.bindMemory(to: UInt8.self).baseAddress
                            ctx.pwdlen = UInt32(pwdBuf.count)
                            ctx.salt = saltBuf.bindMemory(to: UInt8.self).baseAddress
                            ctx.saltlen = UInt32(saltBuf.count)
                            ctx.secret = secBuf.count > 0 ? secBuf.bindMemory(to: UInt8.self).baseAddress : nil
                            ctx.secretlen = UInt32(secBuf.count)
                            ctx.ad = adBuf.count > 0 ? adBuf.bindMemory(to: UInt8.self).baseAddress : nil
                            ctx.adlen = UInt32(adBuf.count)
                            ctx.t_cost = timeCost
                            ctx.m_cost = memoryCost
                            ctx.lanes = parallelism
                            ctx.threads = parallelism
                            ctx.version = UInt32(ARGON2_VERSION_13.rawValue)
                            ctx.allocate_cbk = nil
                            ctx.free_cbk = nil
                            ctx.flags = 0  // ARGON2_DEFAULT_FLAGS (UINT32_C(0), a macro Swift cannot import)
                            return argon2_ctx(&ctx, Argon2_id)
                        }
                    }
                }
            }
        }
        guard rc == ARGON2_OK.rawValue else {
            out.securelyWipe()
            if rc == ARGON2_MEMORY_ALLOCATION_ERROR.rawValue { throw Argon2Error.memoryAllocationFailed }
            throw Argon2Error.backend(rc)
        }
        return out
    }
}

// MARK: - Errors

public enum Argon2Error: Error, LocalizedError {
    case saltTooShort
    case invalidTimeCost
    case invalidParallelism
    case outputTooShort
    case memoryAllocationFailed
    /// FIX M-30: Empty password is rejected as an edge case
    case emptyPassword
    /// FIX M-27: Memory cost below minimum threshold (8 * parallelism)
    case memoryCostTooLow
    /// FIX H-11: Salt generation failure
    case saltGenerationFailed
    /// Any other error code from the reference implementation.
    case backend(Int32)

    public var errorDescription: String? {
        switch self {
        case .saltTooShort: return "Argon2id: Salt must be at least 8 bytes"
        case .invalidTimeCost: return "Argon2id: Time cost must be >= 1"
        case .invalidParallelism: return "Argon2id: Parallelism must be >= 1"
        case .outputTooShort: return "Argon2id: Output length must be >= 4 bytes"
        case .memoryAllocationFailed: return "Argon2id: Failed to allocate memory"
        case .emptyPassword: return "Argon2id: Password must not be empty"
        case .memoryCostTooLow: return "Argon2id: Memory cost must be >= 8 * parallelism"
        case .saltGenerationFailed: return "Argon2id: SecRandomCopyBytes failed during salt generation"
        case .backend(let rc): return "Argon2id: reference implementation error \(rc)"
        }
    }
}

// MARK: - Helpers kept from the previous implementation

extension Argon2id {

    /// FIX H-11: Generate a cryptographically secure random salt using SecRandomCopyBytes.
    public static func generateSecureSalt(length: Int = 16) throws -> Data {
        guard length >= 8 else { throw Argon2Error.saltTooShort }
        var salt = Data(count: length)
        let status = salt.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, length, $0.baseAddress!)
        }
        guard status == errSecSuccess else { throw Argon2Error.saltGenerationFailed }
        return salt
    }

    /// FIX M-31: Version identifier for stored hashes.
    /// 0x02 = RFC 9106 Argon2id (reference implementation). 0x01 was the
    /// non-conforming pure-Swift variant.
    static let algorithmVersion: UInt8 = 0x02

    /// Hash with version prefix — [version(1B)] || [argon2id output].
    public static func hashWithVersion(
        password: Data,
        salt: Data,
        timeCost: UInt32 = 3,
        memoryCost: UInt32 = 65536,
        parallelism: UInt32 = 4,
        outputLength: UInt32 = 32
    ) throws -> Data {
        let rawHash = try hash(password: password, salt: salt, timeCost: timeCost,
                               memoryCost: memoryCost, parallelism: parallelism,
                               outputLength: outputLength)
        var versioned = Data([algorithmVersion])
        versioned.append(rawHash)
        return versioned
    }

    /// PIN derivation with the LADON parameters (m = 64 MiB, t = 3, p = 4).
    public static func deriveRegistrationLockKey(pin: String, salt: Data) throws -> Data {
        try hash(password: Data(pin.utf8), salt: salt, timeCost: 3,
                 memoryCost: 65536, parallelism: 4, outputLength: 32)
    }

    /// Known-answer test: RFC 9106 §5.3 (Argon2id, secret + associated data,
    /// m = 32 KiB, t = 3, p = 4). A mismatch means the implementation is not
    /// Argon2id — fail closed at the caller.
    public static func runSelfTest() -> Bool {
        let expected: [UInt8] = [
            0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c, 0x08, 0xc0, 0x37, 0xa3, 0x4a, 0x8b, 0x53, 0xc9,
            0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75, 0xb6, 0x5e, 0xb5, 0x25, 0x20, 0xe9, 0x6b, 0x01, 0xe6, 0x59,
        ]
        guard let tag = try? hash(password: Data(repeating: 0x01, count: 32),
                                  salt: Data(repeating: 0x02, count: 16),
                                  secret: Data(repeating: 0x03, count: 8),
                                  associatedData: Data(repeating: 0x04, count: 12),
                                  timeCost: 3, memoryCost: 32, parallelism: 4, outputLength: 32)
        else { return false }
        return tag == Data(expected)
    }
}
