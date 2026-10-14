import Foundation

/// Delivery status for outgoing messages
enum DeliveryStatus: String, Codable {
    case sending    // Message is being sent to relay
    case sent       // Relay accepted the message (server has it)
    case delivered  // Recipient decrypted the message (receipt received)
    case failed     // Send failed after all retries (FIX AUDIT-21APR-HIGH2)
}

/// Represents a single message in a conversation
/// FIX HIGH-142: Custom Codable excludes plaintext content from JSON serialization.
/// FIX MED-144: Timestamp quantized to minute-level in encoded output.
/// FIX MED-145: senderCurrentID/senderStableID excluded from Codable.
struct Message: Identifiable, Codable, CustomDebugStringConvertible {
    let id: String
    /// FIX MED-13 (2026-05-17): Plaintext payload stored as `Data`, not `String`.
    /// Swift Strings cannot be securely wiped (CoW + ARC over heap-allocated
    /// `_StringStorage`), so storing sensitive plaintext as `Data` lets
    /// `securelyWipe()` zero the actual backing buffer.
    /// UI/wire layers read/write the UTF-8 view via `contentString`.
    var content: Data
    let timestamp: Date
    let isOutgoing: Bool
    let conversationID: String
    let senderCurrentID: String?
    let senderStableID: String?
    var deliveryStatus: DeliveryStatus?  // nil for incoming messages

    /// UTF-8 decoded view of `content` for display / wire layers.
    /// Returns an empty string on invalid UTF-8 (which should never happen for
    /// app-generated content, but defends against malformed wire data).
    /// Setter applies the same byte-level 16 KB envelope-limit truncation as init.
    var contentString: String {
        get { String(data: content, encoding: .utf8) ?? "" }
        set {
            let utf8 = newValue.utf8
            if utf8.count <= 16384 {
                content = Data(utf8)
            } else {
                content = Data(utf8.prefix(16384))
            }
        }
    }

    init(id: String, content: String, timestamp: Date, isOutgoing: Bool, conversationID: String, senderCurrentID: String? = nil, senderStableID: String? = nil, deliveryStatus: DeliveryStatus? = nil) {
        self.id = id
        // FIX LOW: Use UTF-8 byte-level truncation instead of Character count.
        // String.prefix() counts Unicode Grapheme Clusters (1 emoji = 1 char but up to 25 bytes).
        // Envelope limit is 16KB = 16,384 bytes, not characters.
        let utf8 = content.utf8
        if utf8.count <= 16384 {
            self.content = Data(utf8)
        } else {
            self.content = Data(utf8.prefix(16384))
        }
        // FIX LOW-146 + LOW M-4: Clamp timestamp to valid range
        // Lower bound: 2024-01-01 (app inception). Upper bound: now + 60s clock skew.
        let minDate = Date(timeIntervalSince1970: 1704067200) // 2024-01-01T00:00:00Z
        self.timestamp = max(minDate, min(timestamp, Date().addingTimeInterval(60)))
        self.isOutgoing = isOutgoing
        self.conversationID = conversationID
        self.senderCurrentID = senderCurrentID
        self.senderStableID = senderStableID
        self.deliveryStatus = deliveryStatus
    }

    // FIX HIGH-142: Custom CodingKeys — exclude content and sender IDs
    enum CodingKeys: String, CodingKey {
        case id, timestamp, isOutgoing, conversationID
        // content, senderCurrentID, senderStableID intentionally excluded
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(String.self, forKey: .id)
        content = Data() // FIX HIGH-142: Never deserialize plaintext
        timestamp = try container.decode(Date.self, forKey: .timestamp)
        isOutgoing = try container.decode(Bool.self, forKey: .isOutgoing)
        conversationID = try container.decode(String.self, forKey: .conversationID)
        senderCurrentID = nil
        senderStableID = nil
    }
    
    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        // FIX HIGH-142: content NOT encoded
        // FIX MED-144: Round timestamp to 60s
        let quantized = Date(timeIntervalSince1970: (timestamp.timeIntervalSince1970 / 60).rounded(.down) * 60)
        try container.encode(quantized, forKey: .timestamp)
        try container.encode(isOutgoing, forKey: .isOutgoing)
        try container.encode(conversationID, forKey: .conversationID)
        // FIX MED-145: senderCurrentID/senderStableID NOT encoded
    }
    
    // FIX MED-159 + LOW M-5: Fully redact message ID to prevent correlation
    var debugDescription: String {
        "Message(id: [REDACTED], out: \(isOutgoing), conv: [REDACTED])"
    }
}

// FIX LOW-147: Custom Hashable — exclude content from hash
// FIX RECEIPT-UI: Include deliveryStatus in equality check.
// Previously only `id` was compared, so SwiftUI's ForEach never
// re-rendered MessageBubble when status changed from .sent → .delivered.
// This was the root cause of missing double-checkmarks (✅✅).
extension Message: Hashable {
    static func == (lhs: Message, rhs: Message) -> Bool {
        lhs.id == rhs.id && lhs.deliveryStatus == rhs.deliveryStatus
    }
    
    func hash(into hasher: inout Hasher) {
        hasher.combine(id)
        hasher.combine(deliveryStatus)
    }
}
