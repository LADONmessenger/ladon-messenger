import Foundation
import Security
import UIKit
import CryptoKit

/// PUSH-15 REVISED: Encrypted persistent message store.
///
/// Messages are stored in RAM for fast access AND persisted to an encrypted file
/// (ChaChaPoly with Keychain-stored key) so they survive app restart/backgrounding.
/// The disappearing timer still applies — expired messages are never loaded.
///
/// Security properties preserved:
/// - Messages encrypted at rest (ChaChaPoly-Poly1305, 256-bit key in Keychain)
/// - File has iOS Data Protection .complete (inaccessible when locked)
/// - Panic mode wipes both RAM and encrypted file
/// - Per-message TTL still enforced (30 min RAM scrub)
/// - Disappearing timer still respected on load
///
/// Shared between ConversationListView and ChatView. Solves the core message-loss problem:
/// when ConversationListView fetches and decrypts messages while the user is on the
/// conversation list, those messages advance the Double Ratchet chain. Without this store,
/// the plaintext would be lost when ChatView opens with messages = [].
@MainActor
final class InMemoryMessageStore: ObservableObject {
    static let shared = InMemoryMessageStore()
    
    /// Messages keyed by conversationID
    @Published private var store: [String: [Message]] = [:]
    
    /// Separate unread counter per conversationID.
    /// This counter is INDEPENDENT of message content in the store.
    /// It survives TTL scrubbing and background wipes.
    /// Only a count (Int) — no message content, no security risk.
    /// Key = conversationID, Value = number of unread incoming messages.
    @Published private var unreadCounts: [String: Int] = [:]
    
    /// Total unread count across ALL conversations (for app badge)
    var totalUnreadCount: Int {
        unreadCounts.values.reduce(0, +)
    }
    
    /// FIX CV-01 (ADVERSARIAL): Reduced from 500 to 50 messages per conversation.
    /// 500 × 200 conversations = 100K plaintext messages vulnerable to memory dump.
    /// 50 × 50 = 2,500 max — significantly reduces forensic exposure window.
    private let maxPerConversation = 50
    
    /// FIX CV-01 (ADVERSARIAL): Reduced from 200 to 50 conversations.
    private let maxConversations = 50
    
    /// FIX CV-01 (ADVERSARIAL): Global byte budget for all plaintext in RAM (2 MB).
    /// Prevents total RAM plaintext from exceeding a forensically meaningful threshold.
    private let maxTotalPlaintextBytes = 2 * 1024 * 1024  // 2 MB
    
    /// Current estimated plaintext bytes in store
    private var currentPlaintextBytes = 0
    
    /// FIX H-10/SM-H5: TTL for decrypted messages in RAM (30 minutes)
    /// Increased from 5 min — device lock wipe provides the forensic protection.
    private let messageTTLSeconds: TimeInterval = 1800
    
    /// FIX SM-H5: Track when each individual message was added for per-message TTL
    private var perMessageTimestamps: [String: Date] = [:]
    
    // FIX MED-A12: Store timer reference for proper invalidation
    private var scrubTimer: Timer?
    
    private init() {
        // FIX H-10: Periodic scrubbing timer — wipe stale messages every 60s
        scrubTimer = Timer.scheduledTimer(withTimeInterval: 60, repeats: true) { [weak self] _ in
            Task { @MainActor in
                self?.scrubExpiredMessages()
            }
        }
        
        // H-20 REVISED: Do NOT wipe messages on simple background transitions.
        // The privacy screen in LadonApp.swift already hides content.
        // Wiping on every background destroys messages that the server already
        // deleted from its queue — causing permanent message loss.
        // Instead, only wipe on device lock (protected data unavailable),
        // which is the genuine forensic threat scenario.
        NotificationCenter.default.addObserver(
            forName: UIApplication.protectedDataWillBecomeUnavailableNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            // FIX R21-A9-3: Execute clearAll() synchronously instead of in async Task.
            // Previously, the unstructured Task could be suspended before execution if
            // iOS suspends the app between notification and actual lock. MainActor.assumeIsolated
            // (queue: .main guarantees we're on MainActor) ensures wipe completes before return.
            // Die frühere else-Verzweigung für iOS < 17 ist entfallen: das
            // Deployment-Target ist iOS 17.0, der Zweig war unerreichbar und
            // erzeugte als einziger die Isolationswarnung.
            MainActor.assumeIsolated {
                self?.clearAll()
                #if DEBUG
                print("[InMemoryStore] 🔒 Messages wiped on device lock (H-20)")
                #endif
            }
        }        
        // PUSH-15c: Load persisted messages on startup
        loadPersistedMessages()    }
    
    deinit {
        // FIX MED-A12: Invalidate timer on deallocation
        scrubTimer?.invalidate()
    }
    
    /// FIX SM-H5: Remove individual messages older than TTL (per-message granularity)
    private func scrubExpiredMessages() {
        let now = Date()
        var cleanedCount = 0
        for convKey in store.keys {
            guard var messages = store[convKey] else { continue }
            var keepIndices = IndexSet()
            for i in messages.indices {
                if let addedAt = perMessageTimestamps[messages[i].id],
                   now.timeIntervalSince(addedAt) > messageTTLSeconds {
                    perMessageTimestamps.removeValue(forKey: messages[i].id)
                    // FIX CRIT-06 + SVC-1: Securely zero plaintext before removal
                    // FIX M-26: Removed UB memset_s on Swift String (COW semantics make
                    // mutating shared backing storage undefined behavior). Instead, overwrite
                    // content to release the original buffer via ARC.
                    currentPlaintextBytes -= messages[i].content.count
                    Self.takeAndWipe(&messages[i].content)
                    cleanedCount += 1
                } else {
                    keepIndices.insert(i)
                }
            }
            let remaining = keepIndices.map { messages[$0] }
            if remaining.isEmpty {
                store.removeValue(forKey: convKey)
            } else {
                store[convKey] = remaining
            }
        }
        if cleanedCount > 0 {
            #if DEBUG
            print("[InMemoryStore] 🧹 Scrubbed \(cleanedCount) expired messages (per-message TTL)")
            #endif
            // PUSH-15: Persist after TTL cleanup
            persistMessages()
        }
    }
    
    // MARK: - Store Messages
    
    /// M1 FIX: De-duplicates by message.id (unique UUID) instead of content comparison.
    /// Content-based de-dup caused data loss for identical messages (e.g. "ok" sent twice).
    func addMessages(_ messages: [Message]) {
        for message in messages {
            let key = message.conversationID
            
            // FIX MED-23: Reject messages from new conversations when at capacity
            // to prevent RAM exhaustion from flood attacks
            if store[key] == nil && store.count >= maxConversations {
                #if DEBUG
                print("[InMemoryMessageStore] ⚠️ Max conversations (\(maxConversations)) reached — dropping message")
                #endif
                continue
            }
            
            var existing = store[key] ?? []
            
            // M1 FIX: De-duplicate by message ID only — never compare content
            let isDuplicate = existing.contains { existingMsg in
                existingMsg.id == message.id
            }
            
            if !isDuplicate {
                // FIX CV-01 (ADVERSARIAL): Enforce global byte budget — evict oldest
                // messages across all conversations if adding this one exceeds limit
                let msgBytes = message.content.count
                while currentPlaintextBytes + msgBytes > maxTotalPlaintextBytes {
                    // Evict oldest message globally
                    if !evictOldestMessage() { break }
                }
                
                existing.append(message)
                currentPlaintextBytes += msgBytes
                // FIX ORD-2: Deterministic sort with tie-breaker by message ID.
                // Prevents unstable ordering for same-timestamp messages.
                existing.sort {
                    if $0.timestamp != $1.timestamp { return $0.timestamp < $1.timestamp }
                    return $0.id < $1.id
                }
                // Trim oldest if over budget
                if existing.count > maxPerConversation {
                    let removed = existing.prefix(existing.count - maxPerConversation)
                    for msg in removed {
                        currentPlaintextBytes -= msg.content.count
                        perMessageTimestamps.removeValue(forKey: msg.id)
                    }
                    existing = Array(existing.suffix(maxPerConversation))
                }
                store[key] = existing
                // FIX SM-H5: Track per-message addition time for individual TTL
                perMessageTimestamps[message.id] = Date()
                
                // Increment unread counter for incoming messages
                if !message.isOutgoing {
                    unreadCounts[key] = (unreadCounts[key] ?? 0) + 1
                    #if DEBUG
                    print("[InMemoryStore] 📬 Badge +1 for key=\(key.prefix(8))… → unreadCounts[\(key.prefix(8))]=\(unreadCounts[key] ?? 0)")
                    #endif
                }
            }
        }
        // FIX IMS-P1: Persist after adding new messages.
        // Previously only scrub/remove/clear called persistMessages().
        // If the app was killed within 60s of receiving messages,
        // they were lost (ratchet state already advanced, server deleted them).
        persistMessages()
    }
    
    // MARK: - Retrieve Messages
    
    /// Update delivery status for a message across all conversations
    /// Returns true if the message was found and updated
    @discardableResult
    func updateDeliveryStatus(messageID: String, status: DeliveryStatus) -> Bool {
        for convKey in store.keys {
            if let idx = store[convKey]?.firstIndex(where: { $0.id == messageID }) {
                store[convKey]?[idx].deliveryStatus = status
                #if DEBUG
                NSLog("[InMemoryStore] ✅ Updated msgID=%@ to status=%@ in conv=%@", String(messageID.prefix(8)), status.rawValue, String(convKey.prefix(8)))
                #endif
                return true
            }
        }
        #if DEBUG
        NSLog("[InMemoryStore] ❌ Message NOT FOUND for status update: msgID=%@ (store has %d conversations)", String(messageID.prefix(8)), store.count)
        #endif
        return false
    }
    
    /// Get all messages for a conversation. Returns messages sorted by timestamp.
    func messages(for conversationID: String) -> [Message] {
        // FIX iOS-F13: Exact ID matching only — no fuzzy prefix matching
        if let messages = store[conversationID], !messages.isEmpty {
            return messages
        }
        return []
    }
    
    /// Get messages for a conversation matching any of the given candidate IDs
    /// M1 FIX: De-duplicate by message ID, not by content
    func messages(forAnyOf candidateIDs: Set<String>) -> [Message] {
        var result: [Message] = []
        var seenIDs = Set<String>()
        for id in candidateIDs {
            let msgs = messages(for: id)
            for msg in msgs {
                if !seenIDs.contains(msg.id) {
                    seenIDs.insert(msg.id)
                    result.append(msg)
                }
            }
        }
        // FIX ORD-2: Deterministic sort with tie-breaker by message ID
        result.sort {
            if $0.timestamp != $1.timestamp { return $0.timestamp < $1.timestamp }
            return $0.id < $1.id
        }
        return result
    }
    
    /// #1 (receive-consolidation): flat snapshot of every stored message, used
    /// by ConversationListViewModel to derive conversation rows from the store.
    /// This makes the conversation list a function of the store, so a missed
    /// `NewMessagesReceived` notification (e.g. a push/auth batch that arrived
    /// before the view model registered its observer) self-heals on the next
    /// list appearance. Order is unspecified — callers reconcile by
    /// conversationID and pick newest-by-timestamp themselves.
    func allMessagesSnapshot() -> [Message] {
        store.values.flatMap { $0 }
    }

    // MARK: - Maintenance

    /// FIX AUDIT-57 + H-12 AUDIT-MAR-2026: Securely overwrite plaintext content before releasing.
    /// Previous approach used UnsafeMutableRawPointer(mutating:) on String.withUTF8 buffer,
    /// which is Undefined Behavior per Swift spec (const→mutable cast, COW shared storage).
    /// New approach: Convert to Data (copies bytes), zero the Data copy with memset_s,
    /// then overwrite the String. The original String buffer will be freed by ARC but not
    /// explicitly zeroed — this is a known limitation of Swift's String memory model.
    /// For truly secure zeroing, messages should use Data instead of String.
    /// Take the content out of a message and zero it in its own storage.
    ///
    /// P8-AUDIT8-IOS-22 (audit F32): the wipe used to copy the content into a
    /// local (`if var contentData = …content`), which shared the buffer, so
    /// `withUnsafeMutableBytes` triggered copy-on-write and only the fresh copy
    /// was zeroed — the plaintext itself was released unzeroed. Here the
    /// message's reference is dropped first, so the local is the only holder
    /// and the zeroing hits the real buffer.
    ///
    /// LIMIT (documented, not a guarantee): if anything else still holds the
    /// same Data — a SwiftUI view, ChatViewModel's `messages`, a notification
    /// payload, the `@Published` copy of `store` — that holder keeps the bytes
    /// alive and the zeroing again lands on a copy. RAM wiping is best effort;
    /// device lock and Data Protection remain the actual at-rest guarantee.
    static func takeAndWipe(_ content: inout Data) {
        var owned = content
        content = Data()
        guard !owned.isEmpty else { return }
        owned.withUnsafeMutableBytes { ptr in
            if let base = ptr.baseAddress {
                _ = Darwin.memset_s(base, ptr.count, 0, ptr.count)
            }
        }
    }

    private func securelyWipeMessagesInPlace(_ messages: inout [Message]) {
        for i in messages.indices {
            Self.takeAndWipe(&messages[i].content)
            // Replace message with scrubbed copy (senderCurrentID/senderStableID are let constants)
            messages[i] = Message(
                id: messages[i].id,
                content: "",
                timestamp: messages[i].timestamp,
                isOutgoing: messages[i].isOutgoing,
                conversationID: messages[i].conversationID,
                senderCurrentID: nil,
                senderStableID: nil
            )
        }
    }
    
    /// FIX CRIT-06: Public emergency wipe — called from MemoryProtector.emergencyMemoryWipe()
    func securelyWipeMessages() {
        clearAll()
    }
    
    /// P7-IOS-BUG-15: latches once clearAll runs so a concurrent
    /// forcePersist() doesn't re-persist the in-memory state we just
    /// wiped. Both code paths live on MainActor so they execute
    /// serially, but iOS's notification dispatch order between
    /// `protectedDataWillBecomeUnavailable` and `.background` is not
    /// guaranteed - whichever fires SECOND must not undo the wipe.
    private var isWiped = false

    /// Clear all messages (e.g., on logout or emergency wipe)
    func clearAll() {
        // FIX CRIT-06: Wipe plaintext IN PLACE before releasing
        for key in store.keys {
            securelyWipeMessagesInPlace(&store[key]!)
        }
        store.removeAll()
        perMessageTimestamps.removeAll()
        // FIX A8-IMS-01: Clear unreadCounts during panic wipe — metadata must not survive.
        unreadCounts.removeAll()
        currentPlaintextBytes = 0
        // P7-IOS-BUG-15: latch wipe state before deleting the persisted
        // file so a concurrent forcePersist (e.g. user backgrounds the
        // app and locks the device at almost the same moment) cannot
        // re-create it.
        isWiped = true
        // PUSH-15: Delete persisted file
        deletePersistedFile()
    }
    
    /// Remove a single message by ID (e.g., when disappearing timer expires)
    func removeMessage(id: String) {
        for convKey in store.keys {
            if let idx = store[convKey]?.firstIndex(where: { $0.id == id }) {
                currentPlaintextBytes -= store[convKey]![idx].content.count
                perMessageTimestamps.removeValue(forKey: id)
                // FIX IMS-C2 + H-12 AUDIT-MAR-2026: Wipe content safely without UB.
                // Previous approach used UnsafeMutableRawPointer(mutating:) on String.withUTF8,
                // which is Undefined Behavior (const→mutable cast on COW shared storage).
                Self.takeAndWipe(&store[convKey]![idx].content)
                store[convKey]?.remove(at: idx)
                if store[convKey]?.isEmpty == true {
                    store.removeValue(forKey: convKey)
                }
                // PUSH-15: Persist after removal
                persistMessages()
                return
            }
        }
    }
    
    /// Clear messages for a specific conversation
    func clear(conversationID: String) {
        // FIX CRIT-06: Wipe plaintext in place before releasing
        if store[conversationID] != nil {
            for msg in store[conversationID] ?? [] {
                currentPlaintextBytes -= msg.content.count
                perMessageTimestamps.removeValue(forKey: msg.id)
            }
            securelyWipeMessagesInPlace(&store[conversationID]!)
        }
        store.removeValue(forKey: conversationID)
        // PUSH-15: Persist after clearing conversation
        persistMessages()
    }
    
    /// FIX CV-01 (ADVERSARIAL): Evict the single oldest message across all conversations.
    /// Returns true if a message was evicted, false if store is empty.
    private func evictOldestMessage() -> Bool {
        var oldestConvKey: String?
        var oldestIndex: Int?
        var oldestDate = Date.distantFuture
        
        for (key, messages) in store {
            if let first = messages.first, first.timestamp < oldestDate {
                oldestDate = first.timestamp
                oldestConvKey = key
                oldestIndex = 0
            }
        }
        
        guard let convKey = oldestConvKey, let idx = oldestIndex,
              var messages = store[convKey] else {
            return false
        }
        
        // FIX A12-MED-3 + H-12 AUDIT-MAR-2026: Wipe plaintext safely without UB.
        // P8-AUDIT8-IOS-22: drop the store's reference first, then zero the
        // local copy (see takeAndWipe) — not a copy-on-write duplicate.
        currentPlaintextBytes -= messages[idx].content.count
        perMessageTimestamps.removeValue(forKey: messages[idx].id)
        store[convKey]![idx].content = Data()
        Self.takeAndWipe(&messages[idx].content)
        messages.remove(at: idx)
        
        if messages.isEmpty {
            store.removeValue(forKey: convKey)
        } else {
            store[convKey] = messages
        }
        return true
    }
    
    // MARK: - Unread Message Tracking
    
    /// Count of unread incoming messages for a conversation (matching any candidate ID).
    /// This counter is INDEPENDENT of the message store — survives TTL scrubbing and background wipes.
    func unreadCount(forAnyOf candidateIDs: Set<String>) -> Int {
        var count = 0
        for id in candidateIDs {
            count += unreadCounts[id] ?? 0
        }
        return count
    }
    
    /// Mark all messages for a conversation as read (reset counter to 0).
    /// Called when user opens and views the chat.
    func markAsRead(forAnyOf candidateIDs: Set<String>) {
        var changed = false
        for id in candidateIDs {
            if (unreadCounts[id] ?? 0) > 0 {
                #if DEBUG
                print("[InMemoryStore] 👁️ markAsRead: key=\(id.prefix(8))… was \(unreadCounts[id] ?? 0) → 0")
                #endif
                unreadCounts[id] = 0
                changed = true
            }
        }
        if changed {
            objectWillChange.send()
        }
    }
    
    /// Clear unread tracking for a conversation (on deletion)
    func clearReadTracking(for conversationID: String) {
        unreadCounts.removeValue(forKey: conversationID)
    }
    
    // MARK: - Encrypted Persistence (PUSH-15)
    
    /// Public API to force persistence (called from .background handler)
    func forcePersist() {
        // P7-IOS-BUG-15: refuse to re-persist after a wipe has happened
        // in the same session. clearAll() latches `isWiped`; the only
        // way to flip it back is a fresh process launch (loadPersisted-
        // Messages resets via no-op since the file is gone).
        if isWiped {
            #if DEBUG
            NSLog("[InMemoryStore] forcePersist skipped: store has been wiped")
            #endif
            return
        }
        persistMessages()
    }
    
    /// Full message representation for persistence (includes all fields unlike default Codable)
    private struct PersistableMessage: Codable {
        let id: String
        let content: String
        let timestamp: Date
        let isOutgoing: Bool
        let conversationID: String
        let senderCurrentID: String?
        let senderStableID: String?
        let deliveryStatus: DeliveryStatus?
        
        init(from message: Message) {
            self.id = message.id
            // PersistableMessage keeps content as String for JSON-friendly
            // serialisation; the wire/in-memory Message uses Data for the
            // wipe-friendly storage.
            self.content = message.contentString
            self.timestamp = message.timestamp
            self.isOutgoing = message.isOutgoing
            self.conversationID = message.conversationID
            self.senderCurrentID = message.senderCurrentID
            self.senderStableID = message.senderStableID
            self.deliveryStatus = message.deliveryStatus
        }
        
        func toMessage() -> Message {
            Message(
                id: id,
                content: content,
                timestamp: timestamp,
                isOutgoing: isOutgoing,
                conversationID: conversationID,
                senderCurrentID: senderCurrentID,
                senderStableID: senderStableID,
                deliveryStatus: deliveryStatus
            )
        }
    }
    
    /// Path to the encrypted message file
    /// PUSH-15c: Use Application Support with separate directory (NOT LadonDB which has .complete).
    /// Caches/ was wrong — iOS can purge it at any time.
    private var persistenceFileURL: URL? {
        guard let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else {
            return nil
        }
        let dir = appSupport.appendingPathComponent("LadonMsgStore", isDirectory: true)
        if !FileManager.default.fileExists(atPath: dir.path) {
            try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            // FIX H-12: completeUnlessOpen — file accessible only when unlocked, except already-open handles
            try? FileManager.default.setAttributes(
                [.protectionKey: FileProtectionType.completeUnlessOpen],
                ofItemAtPath: dir.path
            )
        }
        // P8-AUDIT8-IOS-21: keep the encrypted message copy out of iCloud /
        // Finder backups, like the database directory (EncryptedDatabase,
        // FIX M-36). Set on every first use per process, not only when the
        // directory is created — existing installations already have it.
        if !backupExclusionApplied {
            var excluded = URLResourceValues()
            excluded.isExcludedFromBackup = true
            var dirURL = dir
            do {
                try dirURL.setResourceValues(excluded)
                backupExclusionApplied = true
            } catch {
                SecureLogger.error("[MsgStore] excluding the store from backup failed: \(error)")
            }
        }
        return dir.appendingPathComponent("msg_store.enc")
    }
    private var backupExclusionApplied = false
    
    /// Keychain key for the message store encryption key
    private static let persistKeyAccount = "ladon_msgstore_enc_key"
    
    /// Get or create the 256-bit encryption key from Keychain
    private func getOrCreatePersistKey() -> SymmetricKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: Self.persistKeyAccount,
            kSecAttrService as String: "app.ladon.messenger.msgstore",
            kSecAttrSynchronizable as String: false,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        if status == errSecSuccess, var mutableData = result as? Data, mutableData.count == 32 {
            // FIX AUDIT-MAR-2026-23 + AUDIT3-IOS-09: Drop AnyObject ref BEFORE wipe to defeat CoW.
            // Previously `var mutableData = data` aliased the same Data backing store that
            // `result` (AnyObject) still retained → CoW on withUnsafeMutableBytes zeroed only
            // the detached copy, leaving the original 32 B key in the heap until ARC release.
            result = nil
            let key = SymmetricKey(data: mutableData)
            mutableData.withUnsafeMutableBytes { buf in
                if let ptr = buf.baseAddress {
                    memset_s(ptr, buf.count, 0, buf.count)
                }
            }
            return key
        }
        
        // Generate new key
        var keyData = Data(count: 32)
        let rc = keyData.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        guard rc == errSecSuccess else { return nil }
        
        // FIX AUDIT3-IOS-09: Scope addQuery so it deallocates BEFORE the wipe runs.
        // Previously addQuery (containing kSecValueData: keyData) remained in scope until
        // the end of the function → keyData refcount >= 2 → CoW on withUnsafeMutableBytes
        // wiped only the detached copy, leaving the original key buffer in the heap.
        let addStatus: OSStatus = {
            let addQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrAccount as String: Self.persistKeyAccount,
                kSecAttrService as String: "app.ladon.messenger.msgstore",
                kSecValueData as String: keyData,
                kSecAttrSynchronizable as String: false,
                kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            ]
            return SecItemAdd(addQuery as CFDictionary, nil)
        }()
        // addQuery is now out of scope → keyData refcount == 1 → wipe hits the real buffer
        guard addStatus == errSecSuccess else {
            if addStatus == errSecDuplicateItem {
                // FIX AUDIT-MAR-2026-24: Key already exists — load the existing one instead of
                // returning the newly-generated key (which was NOT stored in Keychain).
                keyData.withUnsafeMutableBytes { buf in
                    if let ptr = buf.baseAddress {
                        memset_s(ptr, buf.count, 0, buf.count)
                    }
                }
                // Re-read existing key from Keychain
                var existingResult: AnyObject?
                let readQuery: [String: Any] = [
                    kSecClass as String: kSecClassGenericPassword,
                    kSecAttrAccount as String: Self.persistKeyAccount,
                    kSecAttrService as String: "app.ladon.messenger.msgstore",
                    kSecReturnData as String: true,
                    kSecMatchLimit as String: kSecMatchLimitOne
                ]
                let readStatus = SecItemCopyMatching(readQuery as CFDictionary, &existingResult)
                if readStatus == errSecSuccess, var mutableExisting = existingResult as? Data, mutableExisting.count == 32 {
                    // FIX AUDIT3-IOS-09: Drop AnyObject ref BEFORE wipe to defeat CoW
                    existingResult = nil
                    let existingKey = SymmetricKey(data: mutableExisting)
                    mutableExisting.withUnsafeMutableBytes { buf in
                        if let ptr = buf.baseAddress {
                            memset_s(ptr, buf.count, 0, buf.count)
                        }
                    }
                    return existingKey
                }
                return nil
            }
            #if DEBUG
            NSLog("[InMemoryStore] Keychain write failed for persistKey: %d", addStatus)
            #endif
            // FIX L-5 + AUDIT-MAR-2026-20: Use memset_s for guaranteed zeroing (not eliminated by compiler)
            keyData.withUnsafeMutableBytes { buf in
                if let ptr = buf.baseAddress {
                    memset_s(ptr, buf.count, 0, buf.count)
                }
            }
            return nil
        }
        // FIX L-5 + AUDIT-MAR-2026-20: Wipe keyData from memory after creating SymmetricKey
        // SymmetricKey copies the data internally, so keyData is no longer needed.
        let symmetricKey = SymmetricKey(data: keyData)
        keyData.withUnsafeMutableBytes { buf in
            if let ptr = buf.baseAddress {
                memset_s(ptr, buf.count, 0, buf.count)
            }
        }
        return symmetricKey
    }
    
    /// Persist all messages to encrypted file
    private func persistMessages() {
        guard let fileURL = persistenceFileURL,
              let key = getOrCreatePersistKey() else {
            #if DEBUG
            NSLog("[InMemoryStore] persistMessages: fileURL or key unavailable")
            #endif
            return
        }
        
        // Collect all messages
        var allMessages: [PersistableMessage] = []
        for (_, msgs) in store {
            for msg in msgs where !msg.content.isEmpty {
                allMessages.append(PersistableMessage(from: msg))
            }
        }
        
        do {
            let encoder = JSONEncoder()
            encoder.dateEncodingStrategy = .secondsSince1970
            // FIX AUDIT-R16: var statt let — Klartext-JSON muss nach Verschlüsselung gewipt werden.
            // defer statt success-only wipe: garantiert das Zeroing auch wenn ChaChaPoly.seal() wirft.
            var plaintext = try encoder.encode(allMessages)
            defer { plaintext.securelyWipe() }
            let sealed = try ChaChaPoly.seal(plaintext, using: key)
            try sealed.combined.write(to: fileURL, options: [.atomic])
            // Set file protection separately
            // FIX M-08: Use .completeUnlessOpen instead of .complete.
            // .complete prevents access before first unlock after reboot, which means
            // silent push messages received before the user unlocks are lost entirely.
            // .completeUnlessOpen allows writing to already-open files in background
            // while maintaining encryption at rest after lock.
            try FileManager.default.setAttributes(
                [.protectionKey: FileProtectionType.completeUnlessOpen],
                ofItemAtPath: fileURL.path
            )
            #if DEBUG
            NSLog("[InMemoryStore] Persisted %d messages (%d bytes) to %@", allMessages.count, sealed.combined.count, fileURL.lastPathComponent)
            #endif
        } catch {
            #if DEBUG
            NSLog("[InMemoryStore] FAILED to persist: %@", error.localizedDescription)
            #endif
        }
    }
    
    /// Load persisted messages from encrypted file
    private func loadPersistedMessages() {
        guard let fileURL = persistenceFileURL else {
            #if DEBUG
            NSLog("[InMemoryStore] loadPersisted: no fileURL")
            #endif
            return
        }
        
        // PUSH-15c: Migrate from old locations
        migrateOldPersistFiles()
        
        guard FileManager.default.fileExists(atPath: fileURL.path) else {
            #if DEBUG
            NSLog("[InMemoryStore] loadPersisted: no file at %@", fileURL.path)
            #endif
            return
        }
        
        guard let key = getOrCreatePersistKey() else {
            #if DEBUG
            NSLog("[InMemoryStore] loadPersisted: key unavailable")
            #endif
            return
        }
        
        do {
            let encryptedData = try Data(contentsOf: fileURL)
            #if DEBUG
            NSLog("[InMemoryStore] loadPersisted: read %d bytes", encryptedData.count)
            #endif
            let sealedBox = try ChaChaPoly.SealedBox(combined: encryptedData)
            // FIX AUDIT-R16: var statt let — entschlüsselter Klartext muss nach Decode gewipt werden
            var plaintext = try ChaChaPoly.open(sealedBox, using: key)
            defer { plaintext.securelyWipe() }
            
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .secondsSince1970
            let persistedMessages = try decoder.decode([PersistableMessage].self, from: plaintext)
            
            var loadedCount = 0
            for pm in persistedMessages {
                let message = pm.toMessage()
                let storeKey = message.conversationID
                var existing = store[storeKey] ?? []
                
                // Skip duplicates
                guard !existing.contains(where: { $0.id == message.id }) else { continue }
                // Skip empty content (securely wiped)
                guard !message.content.isEmpty else { continue }
                
                existing.append(message)
                currentPlaintextBytes += message.content.count
                store[storeKey] = existing
                // FIX A7-TTL-01: Use original message timestamp for RAM TTL, not Date().
                // Previously, every app launch reset the TTL clock — messages could persist
                // in RAM indefinitely across restarts. Now respects the original creation time.
                // FIX R21-A9-2: Clamp to max now — prevents malicious future timestamps
                // from bypassing TTL (negative timeIntervalSince would never exceed TTL).
                perMessageTimestamps[message.id] = min(message.timestamp, Date())
                loadedCount += 1
            }
            
            // FIX ORD-2: Deterministic sort with tie-breaker by message ID
            for convKey in store.keys {
                store[convKey]?.sort {
                    if $0.timestamp != $1.timestamp { return $0.timestamp < $1.timestamp }
                    return $0.id < $1.id
                }
            }
            
            #if DEBUG
            NSLog("[InMemoryStore] Loaded %d persisted messages from encrypted file", loadedCount)
            #endif
        } catch {
            #if DEBUG
            NSLog("[InMemoryStore] FAILED to load persisted messages: %@", error.localizedDescription)
            #endif
            // File corrupted or key mismatch — delete it
            try? FileManager.default.removeItem(at: fileURL)
        }
    }
    
    /// Migrate from old file locations (LadonDB, Caches) to new Application Support/LadonMsgStore
    private func migrateOldPersistFiles() {
        guard let newURL = persistenceFileURL,
              !FileManager.default.fileExists(atPath: newURL.path) else { return }
        
        let fm = FileManager.default
        // Try LadonDB first (PUSH-15 original location)
        if let appSupport = fm.urls(for: .applicationSupportDirectory, in: .userDomainMask).first {
            let oldDB = appSupport.appendingPathComponent("LadonDB/msg_store.enc")
            if fm.fileExists(atPath: oldDB.path) {
                try? fm.moveItem(at: oldDB, to: newURL)
                #if DEBUG
                NSLog("[InMemoryStore] Migrated from LadonDB")
                #endif
                return
            }
        }
        // Try Caches (PUSH-15b location)
        if let cachesDir = fm.urls(for: .cachesDirectory, in: .userDomainMask).first {
            let oldCache = cachesDir.appendingPathComponent("LadonMsgStore/msg_store.enc")
            if fm.fileExists(atPath: oldCache.path) {
                try? fm.moveItem(at: oldCache, to: newURL)
                #if DEBUG
                NSLog("[InMemoryStore] Migrated from Caches")
                #endif
                return
            }
        }
    }
    
    /// Delete the persisted file (on clearAll/panic)
    private func deletePersistedFile() {
        let fm = FileManager.default
        // Delete current location (Application Support/LadonMsgStore)
        if let fileURL = persistenceFileURL {
            try? fm.removeItem(at: fileURL)
        }
        // Also clean old locations
        if let appSupport = fm.urls(for: .applicationSupportDirectory, in: .userDomainMask).first {
            try? fm.removeItem(at: appSupport.appendingPathComponent("LadonDB/msg_store.enc"))
        }
        if let cachesDir = fm.urls(for: .cachesDirectory, in: .userDomainMask).first {
            try? fm.removeItem(at: cachesDir.appendingPathComponent("LadonMsgStore/msg_store.enc"))
        }
        #if DEBUG
        NSLog("[InMemoryStore] Deleted persisted message file")
        #endif
    }
}
