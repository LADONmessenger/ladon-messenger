// AttachmentMessagePayload.swift — Phase 8
//
// Wire-level wrapper carried inside the existing ``Message.content`` string.
// No Envelope format change is required: an attachment message is an
// ordinary text message whose content begins with a private-use magic
// marker followed by a single base64url blob that decodes to a JSON object
// holding the descriptor, PQ-hybrid seed payload, and read capability.
//
// Rationale:
//   * Reuses the whole Double-Ratchet + Envelope path end-to-end (same
//     ordering, same disappearing-timer, same retry machinery).
//   * The magic marker uses Unicode code point U+E000 (Private Use Area)
//     which is effectively impossible to type or paste accidentally.
//   * Size budget per message ≤ 15 KB (enforced in ``ChatViewModel``):
//       descriptor (≈ 5.6 KB JSON incl. 4 KB sealed thumbnail)
//       + seed payload (≈ 1.6 KB)
//       + readCap (≈ 0.1 KB)
//       ── total ≈ 7.3 KB raw, ≈ 9.8 KB base64url, ≈ 10 KB after marker.
//
// All fields are Codable. ``WrappedSeedPayload`` is transport-wrapped here
// because the underlying type deliberately lives in the attachments core
// without any transport dependency.

import Foundation

public struct AttachmentMessagePayload: Codable, Equatable {

    /// Schema version. Bump when breaking the encoding.
    public static let currentVersion: UInt8 = 1

    /// Private-use-area marker. Invisible to users, not valid inside any
    /// natural-language text, and stable across all Apple fonts.
    public static let wireMarker: String = "\u{E000}LADON-ATT-V1:"

    public let version: UInt8
    public let descriptor: AttachmentDescriptor
    public let seed: SeedPayload
    public let readCap: String
    public let thumbnailReadCap: String?

    /// Codable mirror of ``AttachmentSeedWrap.WrappedSeedPayload``.
    public struct SeedPayload: Codable, Equatable {
        public let kyberCiphertext: Data
        public let aeadFrame: Data
        public let ephemeralX25519PublicKey: Data

        public init(from wrapped: AttachmentSeedWrap.WrappedSeedPayload) {
            self.kyberCiphertext = wrapped.kyberCiphertext
            self.aeadFrame = wrapped.aeadFrame
            self.ephemeralX25519PublicKey = wrapped.ephemeralX25519PublicKey
        }

        public init(kyberCiphertext: Data, aeadFrame: Data, ephemeralX25519PublicKey: Data) {
            self.kyberCiphertext = kyberCiphertext
            self.aeadFrame = aeadFrame
            self.ephemeralX25519PublicKey = ephemeralX25519PublicKey
        }

        public func unwrap() -> AttachmentSeedWrap.WrappedSeedPayload {
            AttachmentSeedWrap.WrappedSeedPayload(
                kyberCiphertext: kyberCiphertext,
                aeadFrame: aeadFrame,
                ephemeralX25519PublicKey: ephemeralX25519PublicKey
            )
        }
    }

    public init(
        descriptor: AttachmentDescriptor,
        seed: SeedPayload,
        readCap: String,
        thumbnailReadCap: String? = nil,
        version: UInt8 = AttachmentMessagePayload.currentVersion
    ) {
        self.version = version
        self.descriptor = descriptor
        self.seed = seed
        self.readCap = readCap
        self.thumbnailReadCap = thumbnailReadCap
    }

    // MARK: - Wire

    public enum WireError: Error, Equatable {
        case notAnAttachmentMessage
        case base64DecodeFailed
        case jsonDecodeFailed
        case unsupportedVersion(UInt8)
        case encodeFailed
    }

    /// Returns true iff the content string begins with the attachment wire
    /// marker. Cheap, allocation-free.
    public static func isAttachmentContent(_ content: String) -> Bool {
        // Accept both wire-format generations so render/notification paths
        // don't have to know which codec a given message used. The V2
        // binary codec uses a sibling marker (`LADON-ATT-V2:`) and is
        // decoded via `AttachmentMessagePayloadV2.decode(...)`; the legacy
        // JSON decoder below only handles V1 content.
        return content.hasPrefix(Self.wireMarker)
            || content.hasPrefix(AttachmentMessagePayloadV2.wireMarker)
    }

    /// Encode to a `Message.content`-compatible string.
    public func encodedAsMessageContent() throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys] // deterministic — helps tests
        encoder.dataEncodingStrategy = .base64
        let json: Data
        do {
            json = try encoder.encode(self)
        } catch {
            throw WireError.encodeFailed
        }
        return Self.wireMarker + Self.base64URL(json)
    }

    /// Decode. Returns nil for non-attachment content.
    public static func decode(fromMessageContent content: String) throws -> AttachmentMessagePayload {
        // V1 JSON decoder. V2 binary content (different marker) must be
        // decoded via `AttachmentMessagePayloadV2.decode(...)` instead;
        // route accordingly to keep callers honest.
        guard content.hasPrefix(Self.wireMarker) else {
            throw WireError.notAnAttachmentMessage
        }
        let body = String(content.dropFirst(wireMarker.count))
        guard let jsonData = base64URLDecode(body) else {
            throw WireError.base64DecodeFailed
        }
        let decoder = JSONDecoder()
        decoder.dataDecodingStrategy = .base64
        let payload: AttachmentMessagePayload
        do {
            payload = try decoder.decode(AttachmentMessagePayload.self, from: jsonData)
        } catch {
            throw WireError.jsonDecodeFailed
        }
        guard payload.version == Self.currentVersion else {
            throw WireError.unsupportedVersion(payload.version)
        }
        return payload
    }

    // MARK: - base64url (no padding)

    private static func base64URL(_ data: Data) -> String {
        var s = data.base64EncodedString()
        s = s.replacingOccurrences(of: "+", with: "-")
        s = s.replacingOccurrences(of: "/", with: "_")
        s = s.replacingOccurrences(of: "=", with: "")
        return s
    }

    private static func base64URLDecode(_ string: String) -> Data? {
        var s = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let padding = (4 - (s.count % 4)) % 4
        if padding > 0 { s.append(String(repeating: "=", count: padding)) }
        return Data(base64Encoded: s)
    }
}
