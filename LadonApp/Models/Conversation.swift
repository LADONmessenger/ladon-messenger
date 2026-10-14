import Foundation

/// FIX #5: Configurable disappearing message timer per conversation
enum DisappearingTimer: Int, Codable, CaseIterable, Hashable {
    case off = 0
    case thirtySeconds = 30
    case fiveMinutes = 300
    case oneHour = 3600
    case twentyFourHours = 86400
    case sevenDays = 604800
    
    var displayName: String {
        switch self {
        case .off: return "Off"
        case .thirtySeconds: return "30 Seconds"
        case .fiveMinutes: return "5 Minutes"
        case .oneHour: return "1 Hour"
        case .twentyFourHours: return "24 Hours"
        case .sevenDays: return "7 Days"
        }
    }
    
    var shortName: String {
        switch self {
        case .off: return "Off"
        case .thirtySeconds: return "30s"
        case .fiveMinutes: return "5m"
        case .oneHour: return "1h"
        case .twentyFourHours: return "24h"
        case .sevenDays: return "7d"
        }
    }
}

/// Represents a conversation with a contact
/// FIX HIGH-136/139: Custom Codable excludes recipientPublicKey and lastMessage content
/// from JSON serialization to prevent accidental plaintext exposure.
struct Conversation: Identifiable, Codable, Hashable, CustomDebugStringConvertible {
    let id: String
    let recipientID: String
    let recipientPublicKey: Data  // Store for encryption
    var contactName: String
    var lastMessage: Message?
    var relayRecipientID: String?
    var disappearingTimer: DisappearingTimer  // FIX #5: Configurable per conversation
    var isPinned: Bool  // Pinned conversations stay at top of list
    var pinnedAt: Date?  // When pinned — newest pinned first
    
    init(id: String, recipientID: String, recipientPublicKey: Data, contactName: String, lastMessage: Message? = nil, relayRecipientID: String? = nil, disappearingTimer: DisappearingTimer = .fiveMinutes, isPinned: Bool = false, pinnedAt: Date? = nil) {
        self.id = id
        // FIX LOW-137: Validate recipientID format (should be valid identifier)
        // FIX L-07: Generate a random fallback ID in Release instead of silently accepting empty.
        // assertionFailure is DEBUG-only — in Release, an empty recipientID could cause
        // message routing failures or data corruption.
        if recipientID.isEmpty {
            assertionFailure("[Conversation] Empty recipientID")
            // In Release: use a random UUID-based ID so the conversation doesn't corrupt state
            self.recipientID = UUID().uuidString
            SecureLogger.error("[Conversation] Empty recipientID — generated fallback")
        } else {
            self.recipientID = recipientID
        }
        // FIX MUC-5 + FIX AUDIT-R17-F6: Validate recipientPublicKey length (must be 32 bytes or empty).
        // Reject invalid lengths by clearing to empty Data — prevents using corrupt/truncated keys.
        if !recipientPublicKey.isEmpty && recipientPublicKey.count != 32 {
            SecureLogger.error("[Conversation] recipientPublicKey invalid length: \(recipientPublicKey.count) bytes (expected 32) — clearing")
            self.recipientPublicKey = Data()
        } else {
            self.recipientPublicKey = recipientPublicKey
        }
        // FIX MUC-6: Truncate contactName to 256 chars (consistent with Contact.init)
        self.contactName = String(contactName.prefix(256))
        self.lastMessage = lastMessage
        self.relayRecipientID = relayRecipientID
        self.disappearingTimer = disappearingTimer
        self.isPinned = isPinned
        self.pinnedAt = pinnedAt
    }
    
    // FIX HIGH-136/139: Custom CodingKeys — exclude recipientPublicKey from serialization
    enum CodingKeys: String, CodingKey {
        case id, contactName, disappearingTimer
        // recipientID included but redacted in debugDescription
        case recipientID
        // recipientPublicKey and lastMessage intentionally excluded
        case relayRecipientID
        case isPinned
        case pinnedAt
    }
    
    // Custom Codable: provide default for old sessions without disappearingTimer
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(String.self, forKey: .id)
        recipientID = try container.decode(String.self, forKey: .recipientID)
        recipientPublicKey = Data() // FIX HIGH-136: Not serialized — loaded from encrypted DB
        // FIX AUDIT-R18-F8: Apply same truncation as primary init (defense-in-depth)
        contactName = String((try container.decode(String.self, forKey: .contactName)).prefix(256))
        lastMessage = nil // FIX HIGH-139: Never persist plaintext message content
        relayRecipientID = try container.decodeIfPresent(String.self, forKey: .relayRecipientID)
        disappearingTimer = try container.decodeIfPresent(DisappearingTimer.self, forKey: .disappearingTimer) ?? .fiveMinutes
        isPinned = try container.decodeIfPresent(Bool.self, forKey: .isPinned) ?? false
        pinnedAt = try container.decodeIfPresent(Date.self, forKey: .pinnedAt)
    }
    
    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(recipientID, forKey: .recipientID)
        // FIX HIGH-136: recipientPublicKey NOT encoded
        try container.encode(contactName, forKey: .contactName)
        // FIX HIGH-139: lastMessage NOT encoded (no plaintext in serialization)
        try container.encodeIfPresent(relayRecipientID, forKey: .relayRecipientID)
        try container.encode(disappearingTimer, forKey: .disappearingTimer)
        try container.encode(isPinned, forKey: .isPinned)
        try container.encodeIfPresent(pinnedAt, forKey: .pinnedAt)
    }
    
    // FIX MED-159: Prevent default dump from leaking secrets
    // CV-01m FIX: Fully redact contact name — prefix(3) can still be identifying
    var debugDescription: String {
        "Conversation(id: [REDACTED], contact: ***, timer: \(disappearingTimer.shortName))"
    }
    
    // FIX LOW-138: Custom Hashable — exclude sensitive fields
    // Include contactName + disappearingTimer so SwiftUI detects UI-relevant changes
    static func == (lhs: Conversation, rhs: Conversation) -> Bool {
        lhs.id == rhs.id && lhs.contactName == rhs.contactName && lhs.disappearingTimer == rhs.disappearingTimer && lhs.isPinned == rhs.isPinned
    }
    
    func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
}
