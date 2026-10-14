// BlobHost.swift — Active-Active Sharding (14. Mai 2026)
//
// Identifies a specific blob-relay shard. The wire format v4 stores this
// as a single `UInt8` in the descriptor so the receiver knows which shard
// holds the blob. Cap-tokens are scoped to the issuing shard (each shard
// has its own Ed25519 capability signing key, see
// `/memories/repo/blob-sharding-2026-05-14.md`).
//
// MAPPING
// -------
//   rawValue 0x00 → fi (blob-fi.ladon.app, Hetzner FI)
//   rawValue 0x01 → ch (blob-ch.ladon.app, Hosttech CH)
//
// Adding a new shard:
//   1. Append a new case with the next rawValue.
//   2. Add hostname + pin set entry in `BlobRelayPinning`.
//   3. Add an entry to `exits-bootstrap.json#blobs[]`.
//   4. Receivers running an older client treat unknown values as
//      `unknownShard` and the unseal flow surfaces a hard error — there
//      is no soft fallback (hard-cutover policy, see session memory).

import Foundation

@available(iOS 15.0, macOS 12.0, *)
public enum BlobHost: UInt8, Codable, CaseIterable, Sendable {
    case fi = 0x00
    case ch = 0x01

    /// Public origin (https://hostname). All routes are relative to this.
    public var baseURLString: String {
        switch self {
        case .fi: return "https://blob-ch.ladon.app"  // 2026-08-11: nur noch ein Blob-Relay
        case .ch: return "https://blob-ch.ladon.app"
        }
    }

    /// Hostname for TLS SNI / cert hostname check.
    public var hostname: String {
        switch self {
        case .fi: return "blob-ch.ladon.app"  // 2026-08-11: nur noch ein Blob-Relay
        case .ch: return "blob-ch.ladon.app"
        }
    }

    /// Short region tag used in logs and Keychain accounts.
    public var regionTag: String {
        switch self {
        case .fi: return "fi"
        case .ch: return "ch"
        }
    }

    /// All shards in deterministic iteration order. Used by health
    /// probing and round-robin fallback when no latency data exists yet.
    public static var allHosts: [BlobHost] { Self.allCases }

    /// Try to decode from the wire byte. Returns `nil` for unknown
    /// rawValues so the receiver can produce a typed error.
    public static func decode(wireByte: UInt8) -> BlobHost? {
        BlobHost(rawValue: wireByte)
    }

    /// Deterministic shard selection from a random 16-byte blob ID. Used
    /// at send time: since `blobID` is generated via `SecRandomCopyBytes`
    /// (cryptographically uniform), `blobID[0] & 0x01` gives a 50/50
    /// split between `.fi` and `.ch` across many messages. Receivers
    /// learn the chosen shard from the wire descriptor — this function
    /// is sender-side only.
    ///
    /// Rationale for hash-based selection (vs latency-based):
    /// * No network round-trip before the first upload.
    /// * Deterministic for testability and traffic-analysis predictability.
    /// * Future iterations can layer latency probing on top; the wire
    ///   protocol does not change because the receiver always reads the
    ///   sender's choice from the descriptor.
    public static func selectFor(blobID: Data) -> BlobHost {
        // Mask to the lowest bit; works for any number of shards that
        // is a power of two. For more shards, widen the mask and add
        // cases. Falling back to `.fi` if `blobID` is empty (cannot
        // happen for a valid 16-byte ID) keeps this total.
        let lsb = (blobID.first ?? 0) & 0x01
        return BlobHost(rawValue: lsb) ?? .fi
    }
}
