//
//  BlockingV2.swift
//  Ladon — block / unblock a contact (Addendum A1 §7).
//
//  Blocking is enforced cryptographically at the exits, not only on this
//  device: the user's delivery key K is rotated, so the blocked contact's K_X
//  no longer matches the published verifier and every exit refuses its
//  envelopes. In order:
//
//    1. Put the contact on the block list (from now on anything it still
//       manages to deliver is discarded after decryption — no chat message,
//       no notification) and generate the new key K'.
//    2. Send KEY(K') to every other contact we have a session with, one
//       attempt each.
//    3. Publish bundles carrying V'_X on all exits — retried until every exit
//       has it. From then on the old key is refused everywhere.
//
//  The remaining work is kept as a job in the Keychain, so an app that is
//  terminated half-way continues on its next start instead of leaving the
//  blocked contact able to deliver (or other contacts without the new key).
//  Contacts whose KEY failed for a transient reason keep getting retries; the
//  publish does not wait for them — the block takes effect first. Until a
//  contact has K' it cannot reach us; a contact without a session cannot be
//  sent KEY at all and has to exchange a fresh code (A1 §7 limitation).
//
//  Unblock: remove from the list and send KEY(K) to that contact.
//

import Foundation

// MARK: - Block list

enum BlockListV2 {
    private static let account = "blocked"
    private static let lock = NSLock()
    /// Loaded once, then kept in step with every change made here.
    nonisolated(unsafe) private static var cache: Set<String>?

    /// True if `rid` is blocked. A Keychain read error counts as "not
    /// blocked" (and is logged): the exits refuse a blocked contact's key
    /// after the rotation regardless, and treating every sender as blocked
    /// would silently drop all incoming messages.
    static func contains(_ rid: RecipientIdV2) -> Bool {
        do { return try load().contains(rid.description) }
        catch {
            SecureLogger.error("[V2] block list unreadable — treated as empty: \(error)")
            return false
        }
    }

    /// Same, but a read error is an error (send path: fail closed).
    static func containsStrict(_ rid: RecipientIdV2) throws -> Bool {
        try load().contains(rid.description)
    }

    static func add(_ rid: RecipientIdV2) throws {
        lock.lock(); defer { lock.unlock() }
        var set = try loadLocked()
        set.insert(rid.description)
        try save(set)
    }

    static func remove(_ rid: RecipientIdV2) throws {
        lock.lock(); defer { lock.unlock() }
        var set = try loadLocked()
        set.remove(rid.description)
        try save(set)
    }

    private static func load() throws -> Set<String> {
        lock.lock(); defer { lock.unlock() }
        return try loadLocked()
    }

    private static func loadLocked() throws -> Set<String> {
        if let cache { return cache }
        // Only well-formed ids are ever written (encodeRids filters).
        let set = Set(BlockingCodecV2.decodeRids(try DeliveryKeyStoreV2.loadItem(account: account)))
        cache = set
        return set
    }

    private static func save(_ set: Set<String>) throws {
        try DeliveryKeyStoreV2.storeItem(BlockingCodecV2.encodeRids(set.sorted()), account: account)
        cache = set
    }
}

// MARK: - Rotation job

/// What is left to do after a block or unblock.
struct RotationJobV2: Equatable {
    /// Contacts (rid hex) still to be sent KEY with our current key.
    var keyRecipients: [String]
    /// New bundles still to be published on all exits.
    var publishPending: Bool

    var isDone: Bool { keyRecipients.isEmpty && !publishPending }
}

/// Plain text encodings of the block list and the job (pure, self-tested).
enum BlockingCodecV2 {
    /// A recipient id in hex: exactly 64 lowercase hex characters.
    static func isRidHex(_ s: String) -> Bool {
        s.count == LadonV2.recipientIdLen * 2 && s.allSatisfy { ("0"..."9").contains($0) || ("a"..."f").contains($0) }
    }

    static func encodeRids(_ rids: [String]) -> Data {
        Data(rids.filter(isRidHex).joined(separator: "\n").utf8)
    }

    static func decodeRids(_ data: Data?) -> [String] {
        guard let data, let text = String(data: data, encoding: .utf8) else { return [] }
        return text.split(separator: "\n").map(String.init).filter(isRidHex)
    }

    /// Line 1 `publish=1|0`, then one rid per line.
    static func encodeJob(_ job: RotationJobV2) -> Data {
        var lines = ["publish=\(job.publishPending ? 1 : 0)"]
        lines.append(contentsOf: job.keyRecipients.filter(isRidHex))
        return Data(lines.joined(separator: "\n").utf8)
    }

    static func decodeJob(_ data: Data?) -> RotationJobV2? {
        guard let data, let text = String(data: data, encoding: .utf8) else { return nil }
        var lines = text.split(separator: "\n").map(String.init)
        guard let first = lines.first, first == "publish=1" || first == "publish=0" else { return nil }
        lines.removeFirst()
        guard lines.allSatisfy(isRidHex) else { return nil }
        return RotationJobV2(keyRecipients: lines, publishPending: first == "publish=1")
    }
}

enum BlockingV2Error: Error, CustomStringConvertible {
    case notAContact
    case store(String)

    var description: String {
        switch self {
        case .notAContact: return "blocking: not a V2 contact"
        case .store(let m): return "blocking: store — \(m)"
        }
    }
}

enum DeliveryRotationV2 {
    private static let jobAccount = "rotation-job"
    private static let lock = NSLock()
    nonisolated(unsafe) private static var running = false

    // MARK: Public

    /// Block `rid` (steps 1–3 above). Returns once the block is recorded and
    /// the new key stored; KEY sending and publishing continue in the background.
    static func block(_ rid: RecipientIdV2) throws {
        do {
            try BlockListV2.add(rid)
            _ = try DeliveryKeyStoreV2.rotateOwnKey()
            var job = try loadJob() ?? RotationJobV2(keyRecipients: [], publishPending: false)
            let blocked = rid.description
            var recipients = Set(job.keyRecipients)
            for id in try PeerStoreV2.allContactIds() where BlockingCodecV2.isRidHex(id) && id != blocked {
                if let bytes = Data(hexString: id), !BlockListV2.contains(RecipientIdV2(bytes: bytes)) {
                    recipients.insert(id)
                }
            }
            recipients.remove(blocked)
            job.keyRecipients = recipients.sorted()
            job.publishPending = true
            try saveJob(job)
        } catch let e as BlockingV2Error {
            throw e
        } catch {
            throw BlockingV2Error.store("\(error)")
        }
        SecureLogger.torDiag("[V2] contact blocked — key rotated, KEY + publish scheduled")
        resume()
    }

    /// Unblock `rid`: off the list, and our current key goes to it as KEY.
    static func unblock(_ rid: RecipientIdV2) throws {
        do {
            try BlockListV2.remove(rid)
            var job = try loadJob() ?? RotationJobV2(keyRecipients: [], publishPending: false)
            if !job.keyRecipients.contains(rid.description) { job.keyRecipients.append(rid.description) }
            try saveJob(job)
        } catch {
            throw BlockingV2Error.store("\(error)")
        }
        SecureLogger.torDiag("[V2] contact unblocked — KEY scheduled")
        resume()
    }

    /// Continue an unfinished job (called after block/unblock and at every
    /// V2 start). One runner at a time; it retries with backoff until done.
    static func resume() {
        lock.lock()
        if running { lock.unlock(); return }
        running = true
        lock.unlock()
        Task.detached(priority: .utility) {
            await run()
            finished()
        }
    }

    /// Synchronous on purpose: NSLock must not be taken across an await.
    private static func finished() {
        lock.lock(); defer { lock.unlock() }
        running = false
    }

    // MARK: Runner

    private static func run() async {
        var delaySec: UInt64 = 5
        while !Task.isCancelled {
            guard let job = try? loadJob(), !job.isDone else { return }
            if let client = await V2SessionManager.shared.client {
                await pass(job, client: client)
                if (try? loadJob())?.isDone ?? true { return }
            }
            try? await Task.sleep(nanoseconds: delaySec * 1_000_000_000)
            delaySec = min(delaySec * 2, 60)
        }
    }

    /// One attempt for every pending recipient, then — if pending — the
    /// publish on all exits. The job is saved after every step.
    private static func pass(_ start: RotationJobV2, client: RelayClientV2) async {
        var job = start
        let ownKey: Data
        do { ownKey = try DeliveryKeyStoreV2.ownKey() }
        catch {
            SecureLogger.error("[V2] rotation: own delivery key unavailable: \(error)")
            return
        }
        let body = Data(ControlMessageV2.key(deliveryKey: ownKey).utf8)
        var dropped = 0
        for id in start.keyRecipients {
            guard let bytes = Data(hexString: id) else { continue }
            let rid = RecipientIdV2(bytes: bytes)
            guard let peer = try? PeerStoreV2.load(forContactId: id),
                  (try? V2RatchetPayload.hasSession(peerId: id)) == true,
                  !BlockListV2.contains(rid) else {
                // No contact, no session, or blocked meanwhile: KEY cannot or
                // must not go there (A1 §7 limitation: re-pair needed).
                job.keyRecipients.removeAll { $0 == id }
                dropped += 1
                try? saveJob(job)
                continue
            }
            do {
                _ = try await client.sendMessage(to: peer, messageBody: body, isControl: true)
                job.keyRecipients.removeAll { $0 == id }
                try? saveJob(job)
            } catch RelayClientV2Error.missingDeliveryKey,
                    RelayClientV2Error.deliveryKeyOutdated,
                    RelayClientV2Error.contactBlocked,
                    RelayClientV2Error.ratchet {
                // Permanent for this contact — retrying cannot help.
                job.keyRecipients.removeAll { $0 == id }
                dropped += 1
                try? saveJob(job)
            } catch {
                // Transient (network, relay): stays in the job for the next pass.
                SecureLogger.torDiag("[V2] rotation: KEY send to be retried: \(error)")
            }
        }
        if dropped > 0 {
            SecureLogger.torDiag("[V2] rotation: \(dropped) contact(s) cannot receive KEY — they need a fresh code")
        }
        if job.publishPending {
            let total = await client.registry.exits.count
            let ok = await client.publishBundleOnAllExits()
            if total > 0, ok.count == total {
                job.publishPending = false
                try? saveJob(job)
                SecureLogger.torDiag("[V2] rotation: new bundle published on all \(total) exits")
            } else {
                SecureLogger.error("[V2] rotation: bundle published on \(ok.count)/\(total) exits — retrying")
            }
        }
    }

    // MARK: Store

    private static func loadJob() throws -> RotationJobV2? {
        BlockingCodecV2.decodeJob(try DeliveryKeyStoreV2.loadItem(account: jobAccount))
    }

    private static func saveJob(_ job: RotationJobV2) throws {
        if job.isDone {
            try DeliveryKeyStoreV2.delete(account: jobAccount)
        } else {
            try DeliveryKeyStoreV2.storeItem(BlockingCodecV2.encodeJob(job), account: jobAccount)
        }
    }
}
