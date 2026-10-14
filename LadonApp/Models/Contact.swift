import Foundation

/// Contact information
/// FIX HIGH-131: Custom Codable implementation excludes identityKey from JSON serialization
/// to prevent accidental plaintext key exposure via logging, pasteboard, or debug output.
struct Contact: Identifiable, Codable, CustomDebugStringConvertible {
    let id: String
    var name: String
    let identityKey: Data  // Their X25519 public identity key
    
    /// FIX HIGH-134 + LOW-1 (2026-02-20): identityKey length validation enforced.
    /// Throws on invalid key length instead of only logging — defense-in-depth.
    /// Empty Data() is allowed (Codable decoder uses it when identityKey is not serialized).
    enum ContactError: Error {
        case invalidIdentityKeyLength(Int)
    }
    
    init(id: String, name: String, identityKey: Data) throws {
        self.id = id
        // FIX LOW-133: Truncate display name to prevent UI abuse / buffer overflow
        self.name = String(name.prefix(256))
        // FIX LOW-1: REJECT invalid identity key length (must be 32 bytes for X25519 or empty for Codable)
        if !identityKey.isEmpty && identityKey.count != 32 {
            #if DEBUG
            print("[Contact] ❌ Invalid identityKey length: \(identityKey.count) (expected 32)")
            #endif
            throw ContactError.invalidIdentityKeyLength(identityKey.count)
        }
        self.identityKey = identityKey
    }
    
    // FIX HIGH-131: Exclude identityKey from Codable serialization
    enum CodingKeys: String, CodingKey {
        case id, name
        // identityKey intentionally excluded from Codable
    }
    
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(String.self, forKey: .id)
        // FIX AUDIT-R18-F9: Apply same 256-char truncation as primary init
        name = String((try container.decode(String.self, forKey: .name)).prefix(256))
        identityKey = Data() // Not serialized — must be loaded from encrypted storage
        // Note: Empty Data() is valid — bypasses the 32-byte check in the primary init
    }
    
    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(name, forKey: .name)
        // identityKey intentionally NOT encoded
    }
    
    // FIX MED-159 + LOW C-3: Fully redact all PII from debug output
    var debugDescription: String {
        "Contact(id: [REDACTED], name: [REDACTED])"
    }
}
