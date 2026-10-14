//
//  IdentifiersV2.swift
//  Ladon — strongly-typed wrappers around fixed-size byte identifiers.
//

import Foundation
import CryptoKit

/// 16-byte Exit-Relay identifier — `BLAKE3(hkem_pk)[..16]` (Spec §3.5).
struct ExitIdV2: Hashable, CustomStringConvertible {
    static let length = LadonV2.exitIdLen
    let bytes: Data
    init(bytes: Data) {
        precondition(bytes.count == Self.length, "ExitId must be \(Self.length) bytes, got \(bytes.count)")
        self.bytes = bytes
    }
    /// Derive ExitId from a 1,216-byte HKEM public key.
    static func fromHkemPk(_ hkemPk: Data) -> ExitIdV2 {
        let h = Blake3.hash(hkemPk, outputLength: 16)
        return ExitIdV2(bytes: h)
    }
    var description: String { bytes.map { String(format: "%02x", $0) }.joined() }
}

/// 32-byte Recipient identifier — `SHA-256(IK_R)` (Spec §3 / §4.1).
/// `IK_R` is the recipient's long-term HSig public key (1,984 B).
struct RecipientIdV2: Hashable, CustomStringConvertible {
    static let length = LadonV2.recipientIdLen
    let bytes: Data
    init(bytes: Data) {
        precondition(bytes.count == Self.length, "RecipientId must be \(Self.length) bytes")
        self.bytes = bytes
    }
    /// Derive RecipientId from the wire-format HSig public key (1,984 B).
    static func fromIdentityKey(_ ikR: Data) -> RecipientIdV2 {
        let h = SHA256.hash(data: ikR)
        return RecipientIdV2(bytes: Data(h))
    }
    var description: String { bytes.map { String(format: "%02x", $0) }.joined() }
}

/// 16-byte Bundle identifier — generator-chosen unique value.
struct BundleIdV2: Hashable, CustomStringConvertible {
    static let length = LadonV2.bundleIdLen
    let bytes: Data
    init(bytes: Data) {
        precondition(bytes.count == Self.length, "BundleId must be \(Self.length) bytes")
        self.bytes = bytes
    }
    /// Generate a fresh random BundleId.
    static func random() -> BundleIdV2 {
        var b = Data(count: Self.length)
        // FIX AUDIT3-IOS-03: Check CSPRNG status — discarded status would produce
        // a zero-filled BundleId on failure, enabling collision/spoofing.
        // Matches the pattern used in WireUtilV2.randomBytes().
        let status = b.withUnsafeMutableBytes { ptr -> Int32 in
            SecRandomCopyBytes(kSecRandomDefault, ptr.count, ptr.baseAddress!)
        }
        precondition(status == errSecSuccess, "SecRandomCopyBytes failed for BundleIdV2 (\(status))")
        return BundleIdV2(bytes: b)
    }
    var description: String { bytes.map { String(format: "%02x", $0) }.joined() }
}
