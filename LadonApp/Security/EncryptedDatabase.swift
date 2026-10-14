import Foundation
// SQLCipher provides sqlite3 symbols via the xcframework (linked as static lib)
// No 'import SQLite3' needed — headers come from Bridging-Header.h
import CryptoKit
import Security
import UIKit  // FIX SM-C3: Needed for UIApplication.didEnterBackgroundNotification

/// Encrypted SQLite database for messages and conversations
/// Replaces SecureUserDefaults blob storage with per-row encrypted SQLite
/// - WAL journaling for crash safety
/// - Per-field ChaCha20-Poly1305 encryption of sensitive data
/// - Efficient queries without loading entire dataset into RAM
/// - Indexed by conversation_id and timestamp
/// FIX CRIT-06: SQLITE_TRANSIENT tells SQLite to immediately copy bound data.
/// Without this, sqlite3_bind_text/blob uses a pointer that may be freed before sqlite3_step().
/// Using `nil` (SQLITE_STATIC) assumes the caller keeps the pointer valid until step() — unsafe in Swift.
private let SQLITE_TRANSIENT_DESTRUCTOR = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

final class EncryptedDatabase {
    static let shared = EncryptedDatabase()
    
    private var db: OpaquePointer?
    private let dbQueue = DispatchQueue(label: "app.ladon.messenger.database", qos: .userInitiated)
    private let keychainAccount = "ladon_db_encryption_key"
    
    /// FIX MED: WAL write counter — triggers periodic checkpoint to prevent unbounded growth
    private var _walWriteCount = 0
    private let walCheckpointInterval = 100  // Checkpoint every 100 writes
    
    private init() {
        do {
            try openDatabase()
            try createTables()
        } catch {
            // FIX A13-6: Close db on init failure — prevents unencrypted db connection
            // sqlite3_open() sets db even if sqlite3_key() fails → unencrypted connection
            if let openDB = db {
                sqlite3_close(openDB)
            }
            db = nil
            #if DEBUG
            print("[EncryptedDB] ❌ Failed to initialize: \(error)")
            #endif
        }
    }
    
    /// FIX MED: deinit dispatches close to dbQueue to prevent race condition
    deinit {
        let localDB = db
        dbQueue.sync {
            if let db = localDB {
                sqlite3_close(db)
            }
        }
    }
    
    // MARK: - Database Setup
    
    private func openDatabase() throws {
        let fileManager = FileManager.default
        guard let documentsURL = fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else {
            throw DatabaseError.openFailed
        }
        let dbDir = documentsURL.appendingPathComponent("LadonDB", isDirectory: true)
        
        if !fileManager.fileExists(atPath: dbDir.path) {
            try fileManager.createDirectory(at: dbDir, withIntermediateDirectories: true)
        }
        
        // FIX M-36: Exclude database directory from iCloud/iTunes backups
        // Prevents encrypted database from being included in device backups
        var dbDirExclude = dbDir
        var resourceValues = URLResourceValues()
        resourceValues.isExcludedFromBackup = true
        try dbDirExclude.setResourceValues(resourceValues)
        
        // FIX M3: .complete — DB only accessible when device is unlocked
        try fileManager.setAttributes(
            [.protectionKey: FileProtectionType.complete],
            ofItemAtPath: dbDir.path
        )
        
        let dbURL = dbDir.appendingPathComponent("ladon.db")
        let dbPath = dbURL.path
        
        if sqlite3_open(dbPath, &db) != SQLITE_OK {
            throw DatabaseError.openFailed
        }
        
        // FIX SM-C1: SQLCipher full-database encryption
        // Set the encryption key IMMEDIATELY after opening, before any other PRAGMA or query.
        // The key is derived from the Keychain-stored base key via HKDF.
        // FIX LOW F-IA-6: Use var so we can zero the key material after sqlite3_key
        var sqlcipherKey = try deriveSQLCipherKey()
        defer {
            // FIX LOW F-IA-6: Zero out derived key material after use via raw pointer
            // Using withUnsafeMutableBytes to bypass potential COW optimizations
            // FIX EDB-MS1: Use memset_s instead of memset.
            // memset can be eliminated by the compiler as a dead store.
            // memset_s is guaranteed to execute (C11 Annex K / Darwin).
            // All other key-wipe sites in this file already use memset_s.
            sqlcipherKey.withUnsafeMutableBytes { ptr in
                if let baseAddr = ptr.baseAddress {
                    _ = Darwin.memset_s(baseAddr, ptr.count, 0, ptr.count)
                }
            }
        }
        let keyStatus = sqlcipherKey.withUnsafeBytes { keyBytes -> Int32 in
            sqlite3_key(db, keyBytes.baseAddress, Int32(keyBytes.count))
        }
        guard keyStatus == SQLITE_OK else {
            sqlite3_close(db)
            db = nil
            throw DatabaseError.openFailed
        }
        
        // FIX AUD6-01: SQLCipher PRAGMAs MUST come AFTER sqlite3_key but BEFORE any query.
        // Previously set after SELECT count(*) FROM sqlite_master, which means they didn't
        // take effect for the verification query. If SQLCipher changes defaults in a future
        // version, the DB would silently fail to open with wrong parameters.
        applyCipherPragmas()
        
        // Verify SQLCipher key is correct by running a simple query
        var verifyStmt: OpaquePointer?
        if sqlite3_prepare_v2(db, "SELECT count(*) FROM sqlite_master", -1, &verifyStmt, nil) != SQLITE_OK {
            // The keyed open failed: EITHER a legacy unencrypted (plaintext) DB that
            // predates SQLCipher (safe to migrate by deleting) OR an encrypted DB we
            // could not open — wrong/rotated key or corruption.
            sqlite3_close(db)
            db = nil

            // #19: only delete when the on-disk file is a genuine plaintext SQLite DB
            // (magic "SQLite format 3\0") or an empty stub. A real encrypted DB whose
            // key we lack must NEVER be destroyed — fail closed instead, so a transient
            // keychain/key problem can't silently wipe the user's messages.
            let header: Data = FileHandle(forReadingAtPath: dbURL.path).map { fh in
                defer { try? fh.close() }
                return (try? fh.read(upToCount: 16)) ?? Data()
            } ?? Data()
            let plaintextMagic = Data("SQLite format 3\u{0}".utf8)
            let isLegacyPlaintext = header == plaintextMagic
            let isEmptyStub = header.count < 16   // 0-byte/truncated: no encrypted data at risk
            guard isLegacyPlaintext || isEmptyStub else {
                SecureLogger.error("[EncryptedDatabase] keyed open failed on a non-plaintext DB — refusing to delete (possible wrong key / corruption)")
                throw DatabaseError.openFailed
            }
            SecureLogger.debug("DB migration in progress")

            // Delete old plaintext database files (db, WAL, SHM)
            let walURL = dbDir.appendingPathComponent("ladon.db-wal")
            let shmURL = dbDir.appendingPathComponent("ladon.db-shm")
            try? fileManager.removeItem(at: dbURL)
            try? fileManager.removeItem(at: walURL)
            try? fileManager.removeItem(at: shmURL)
            
            // Re-open fresh database with SQLCipher
            if sqlite3_open(dbPath, &db) != SQLITE_OK {
                throw DatabaseError.openFailed
            }
            let rekeyStatus = sqlcipherKey.withUnsafeBytes { keyBytes -> Int32 in
                sqlite3_key(db, keyBytes.baseAddress, Int32(keyBytes.count))
            }
            guard rekeyStatus == SQLITE_OK else {
                sqlite3_close(db)
                db = nil
                throw DatabaseError.openFailed
            }
            
            // FIX AUD6-01: Set PRAGMAs for fresh DB before first query
            applyCipherPragmas()
            
            // Verify the fresh encrypted DB works
            var freshVerify: OpaquePointer?
            if sqlite3_prepare_v2(db, "SELECT count(*) FROM sqlite_master", -1, &freshVerify, nil) != SQLITE_OK {
                sqlite3_close(db)
                db = nil
                throw DatabaseError.openFailed
            }
            sqlite3_finalize(freshVerify)
            SecureLogger.debug("DB ready")
        } else {
            sqlite3_finalize(verifyStmt)
        }
        
        // FIX AUD6-01: PRAGMAs are now applied via applyCipherPragmas() above,
        // before the first query. No longer duplicated here.
        
        // FIX AUDIT-R9-02: Check security-critical PRAGMA return values
        // Enable WAL mode for better concurrent access and crash recovery
        if !exec("PRAGMA journal_mode=WAL") {
            SecureLogger.error("[EncryptedDB] PRAGMA journal_mode=WAL failed")
        }
        // Secure delete — overwrite deleted data with zeros
        if !exec("PRAGMA secure_delete=ON") {
            SecureLogger.error("[EncryptedDB] ⛔ PRAGMA secure_delete=ON failed — deleted data may remain on disk")
        }
        // Auto-vacuum to reclaim space from deleted records
        if !exec("PRAGMA auto_vacuum=INCREMENTAL") {
            SecureLogger.error("[EncryptedDB] PRAGMA auto_vacuum=INCREMENTAL failed")
        }
        // FIX C-4: Disable WAL checkpoint on close — prevents WAL journal leak of plaintext
        if !exec("PRAGMA wal_autocheckpoint=0") {
            SecureLogger.error("[EncryptedDB] ⛔ PRAGMA wal_autocheckpoint=0 failed — WAL may leak plaintext")
        }
        // FIX MED-09: Periodic WAL checkpoint to prevent unbounded WAL growth
        if !exec("PRAGMA wal_checkpoint(TRUNCATE)") {
            SecureLogger.error("[EncryptedDB] PRAGMA wal_checkpoint(TRUNCATE) failed")
        }
        
        // FIX MED-07 + MED-2: Use cipher_integrity_check for SQLCipher (not plain integrity_check)
        // FIX DB-9: Use while loop to consume all error rows, not just the first
        var integrityResult: OpaquePointer?
        if sqlite3_prepare_v2(db, "PRAGMA cipher_integrity_check", -1, &integrityResult, nil) == SQLITE_OK {
            while sqlite3_step(integrityResult) == SQLITE_ROW {
                if let text = sqlite3_column_text(integrityResult, 0) {
                    let result = String(cString: text)
                    if result != "ok" {
                        // FIX R17-EDB2: Release-Logging statt nur #if DEBUG
                        SecureLogger.error("[EncryptedDB] ⛔ Database integrity check failed: \(result)")
                    }
                }
            }
            sqlite3_finalize(integrityResult)
        }
        
        // FIX M3: .complete — DB only accessible when device is unlocked
        try fileManager.setAttributes(
            [.protectionKey: FileProtectionType.complete],
            ofItemAtPath: dbPath
        )
        // FIX C-4 + MED-4: Protect WAL/SHM journal files — log errors instead of swallowing
        let walPath = dbPath + "-wal"
        let shmPath = dbPath + "-shm"
        if fileManager.fileExists(atPath: walPath) {
            do {
                try fileManager.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath: walPath)
            } catch {
                #if DEBUG
                print("[EncryptedDB] ⚠️ Failed to protect WAL file: \(error)")
                #endif
                // FIX MED-4: In production, retry once
                try? fileManager.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath: walPath)
            }
        }
        if fileManager.fileExists(atPath: shmPath) {
            do {
                try fileManager.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath: shmPath)
            } catch {
                #if DEBUG
                print("[EncryptedDB] ⚠️ Failed to protect SHM file: \(error)")
                #endif
                try? fileManager.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath: shmPath)
            }
        }
    }
    
    private func createTables() throws {
        // FIX C-5: Social graph protection — conversation_id, sender IDs now encrypted.
        // Only opaque hashed IDs stored for indexing; actual values encrypted per-row.
        let createMessages = """
        CREATE TABLE IF NOT EXISTS messages (
            id TEXT PRIMARY KEY,
            conversation_id TEXT NOT NULL,
            encrypted_content BLOB NOT NULL,
            nonce BLOB NOT NULL,
            timestamp REAL NOT NULL,
            is_outgoing INTEGER NOT NULL DEFAULT 0,
            sender_current_id TEXT,
            sender_stable_id TEXT,
            encrypted_metadata BLOB,
            metadata_nonce BLOB,
            created_at BLOB
        )
        """
        // FIX AUDIT-R9-03: Check CREATE TABLE return values — missing tables crash all queries
        if !exec(createMessages) {
            SecureLogger.error("[EncryptedDB] ⛔ CREATE TABLE messages failed")
        }
        
        // Index for efficient conversation queries
        if !exec("CREATE INDEX IF NOT EXISTS idx_messages_conversation ON messages(conversation_id, timestamp)") {
            SecureLogger.error("[EncryptedDB] CREATE INDEX idx_messages_conversation failed")
        }
        
        // FIX SM-L4: Migration — add columns only if missing
        addColumnIfMissing(table: "messages", column: "encrypted_metadata", type: "BLOB")
        addColumnIfMissing(table: "messages", column: "metadata_nonce", type: "BLOB")
        
        // FIX C-5: Conversations table — recipient_id and relay_recipient_id now encrypted
        let createConversations = """
        CREATE TABLE IF NOT EXISTS conversations (
            id TEXT PRIMARY KEY,
            recipient_id TEXT NOT NULL,
            encrypted_public_key BLOB NOT NULL,
            pk_nonce BLOB NOT NULL,
            encrypted_contact_name BLOB NOT NULL DEFAULT X'',
            cn_nonce BLOB NOT NULL DEFAULT X'',
            relay_recipient_id TEXT,
            encrypted_recipient_data BLOB,
            recipient_data_nonce BLOB,
            last_message_timestamp REAL,
            last_message_is_outgoing INTEGER,
            disappearing_timer INTEGER NOT NULL DEFAULT 30,
            updated_at REAL NOT NULL DEFAULT (julianday('now'))
        )
        """
        if !exec(createConversations) {
            SecureLogger.error("[EncryptedDB] ⛔ CREATE TABLE conversations failed")
        }
        
        // FIX SM-L4: Migration — add columns only if missing (prevents SQLite errors on re-launch)
        addColumnIfMissing(table: "conversations", column: "disappearing_timer", type: "INTEGER NOT NULL DEFAULT 30")
        // FIX C-5: Migration — add encrypted recipient data columns
        addColumnIfMissing(table: "conversations", column: "encrypted_recipient_data", type: "BLOB")
        addColumnIfMissing(table: "conversations", column: "recipient_data_nonce", type: "BLOB")
        
        // FIX F7 Migration: contact_name -> encrypted_contact_name + cn_nonce (already implemented)
        // All CRUD operations now use encrypted_contact_name and cn_nonce only.
        
        // Key-value store for settings and metadata
        let createKV = """
        CREATE TABLE IF NOT EXISTS secure_kv (
            key TEXT PRIMARY KEY,
            encrypted_value BLOB NOT NULL,
            nonce BLOB NOT NULL
        )
        """
        if !exec(createKV) {
            SecureLogger.error("[EncryptedDB] ⛔ CREATE TABLE secure_kv failed")
        }
        
        // Verification status per contact
        let createVerification = """
        CREATE TABLE IF NOT EXISTS verification_status (
            contact_id TEXT PRIMARY KEY,
            is_verified INTEGER NOT NULL DEFAULT 0,
            verified_at REAL,
            last_known_identity_key BLOB,
            identity_key_nonce BLOB,
            key_changed_at REAL
        )
        """
        if !exec(createVerification) {
            SecureLogger.error("[EncryptedDB] ⛔ CREATE TABLE verification_status failed")
        }
        // FIX SM-L4 + FIX CRIT-03: Migration — add column only if missing
        addColumnIfMissing(table: "verification_status", column: "identity_key_nonce", type: "BLOB")
        
        // FIX M-35: Schema version tracking for controlled migrations
        let currentSchemaVersion: Int32 = 2
        var versionStmt: OpaquePointer?
        if sqlite3_prepare_v2(db, "PRAGMA user_version", -1, &versionStmt, nil) == SQLITE_OK {
            if sqlite3_step(versionStmt) == SQLITE_ROW {
                let dbVersion = sqlite3_column_int(versionStmt, 0)
                if dbVersion < currentSchemaVersion {
                    // All column migrations handled by addColumnIfMissing above.
                    // Bump version to track that schema is up-to-date.
                    if !exec("PRAGMA user_version = \(currentSchemaVersion)") {
                        SecureLogger.error("[EncryptedDB] PRAGMA user_version failed")
                    }
                    #if DEBUG
                    print("[EncryptedDB] Schema migrated from v\(dbVersion) to v\(currentSchemaVersion)")
                    #endif
                }
            }
            sqlite3_finalize(versionStmt)
        }
    }
    
    // MARK: - Encryption Key
    
    // FIX F10: DB key is derived once and cached (no key copies in heap per operation)
    // FIX SM-C3 + ED-2: Key auto-invalidates on background + 10s inactivity timer
    private var _cachedEncryptionKey: SymmetricKey?
    private var _keyCacheTimer: DispatchSourceTimer?
    
    private func getEncryptionKey() throws -> SymmetricKey {
        if let cached = _cachedEncryptionKey {
            resetKeyCacheTimer()
            return cached
        }
        
        let key = try deriveEncryptionKey()
        _cachedEncryptionKey = key
        setupBackgroundObserver()
        resetKeyCacheTimer()
        return key
    }
    
    /// FIX SM-C3 + ED-2: Clear cached key after 10s of inactivity (reduced from 60s)
    /// Shorter window = less exposure if device is seized while app is in foreground
    private func resetKeyCacheTimer() {
        _keyCacheTimer?.cancel()
        let timer = DispatchSource.makeTimerSource(queue: dbQueue)
        timer.schedule(deadline: .now() + 10)
        timer.setEventHandler { [weak self] in
            self?._cachedEncryptionKey = nil
            self?._keyCacheTimer = nil
        }
        timer.resume()
        _keyCacheTimer = timer
    }
    
    /// FIX SM-C3: Clear cached key when app enters background
    /// FIX MED: _backgroundObserverAdded access serialized on dbQueue to prevent data race
    private var _backgroundObserverAdded = false
    private func setupBackgroundObserver() {
        // Must be called from dbQueue (which it is, via getEncryptionKey)
        dispatchPrecondition(condition: .onQueue(dbQueue))
        guard !_backgroundObserverAdded else { return }
        _backgroundObserverAdded = true
        NotificationCenter.default.addObserver(
            forName: UIApplication.didEnterBackgroundNotification,
            object: nil,
            queue: nil
        ) { [weak self] _ in
            self?.invalidateKeyCache()
        }
    }
    
    /// Invalidate the cached key (e.g. on app backgrounding or emergency wipe)
    /// FIX HIGH-10: Thread-safe cache invalidation — dispatch to dbQueue
    /// FIX SEC-03: Best-effort zeroing of SymmetricKey — while CryptoKit's SymmetricKey
    /// struct cannot be directly wiped (no public API), setting to nil releases the
    /// reference. Combined with the 60s inactivity timer, the key's exposure window
    /// is minimized. On emergency wipe, this is called immediately.
    func invalidateKeyCache() {
        dbQueue.sync {
            _keyCacheTimer?.cancel()
            _keyCacheTimer = nil
            _cachedEncryptionKey = nil
        }
    }
    
    private func deriveEncryptionKey() throws -> SymmetricKey {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: keychainAccount,
            kSecAttrService as String: "app.ladon.messenger",
            // FIX HIGH-22: Do NOT include kSecAttrAccessible in read queries.
            // Including it causes key mismatch if the item was stored with a
            // different accessibility level (e.g., migration from older version).
            kSecReturnData as String: true,
            kSecAttrSynchronizable as String: false
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        // P8-AUDIT8-IOS-02: a new base key is created ONLY when none exists.
        // Any other failure (locked device, interaction not allowed, a transient
        // SecItem error) used to fall through to key generation, and the
        // SecItemUpdate below then overwrote the real key — every row of the
        // database became permanently unreadable. Now that is an error.
        guard status == errSecSuccess || status == errSecItemNotFound else {
            SecureLogger.error("[EncryptedDB] base key unreadable (status \(status)) — not regenerating")
            throw DatabaseError.keyGenerationFailed
        }
        let baseKey: SymmetricKey
        if status == errSecSuccess {
            guard var keyData = result as? Data else {
                SecureLogger.error("[EncryptedDB] base key item is not Data — not regenerating")
                throw DatabaseError.keyGenerationFailed
            }
            // FIX R16-EDB1: Drop AnyObject ref BEFORE wipe to defeat COW
            result = nil
            baseKey = SymmetricKey(data: keyData)
            // FIX HIGH-1: Wipe raw key material from heap immediately after use
            keyData.withUnsafeMutableBytes { ptr in
                if let base = ptr.baseAddress, ptr.count > 0 {
                    _ = Darwin.memset_s(base, ptr.count, 0, ptr.count)
                }
            }
        } else {
            // Generate new base key
            let newKey = SymmetricKey(size: .bits256)
            var keyData = newKey.withUnsafeBytes { Data($0) }
            
            // FIX R21-A3-1: Keychain operations in inner scope so addQuery/updateAttrs
            // are deallocated BEFORE the wipe runs. Previously, the dictionaries held
            // references to keyData → CoW on wipe → original buffer stayed unwiped.
            let addStatus: OSStatus = {
                let addQuery: [String: Any] = [
                    kSecClass as String: kSecClassGenericPassword,
                    kSecAttrAccount as String: keychainAccount,
                    kSecAttrService as String: "app.ladon.messenger",
                    kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                    kSecAttrSynchronizable as String: false,
                    kSecValueData as String: keyData
                ]
                // P8-AUDIT8-IOS-02: Add only, never Update. This branch runs
                // only when the read said "not found"; if another caller
                // created the key in the meantime, Add fails with
                // errSecDuplicateItem (thrown below) instead of overwriting a
                // key that may already protect data.
                return SecItemAdd(addQuery as CFDictionary, nil)
            }()
            // addQuery is now out-of-scope → ref count on keyData == 1
            // FIX HIGH-1: Wipe raw key material from heap after Keychain store
            keyData.withUnsafeMutableBytes { ptr in
                if let base = ptr.baseAddress, ptr.count > 0 {
                    _ = Darwin.memset_s(base, ptr.count, 0, ptr.count)
                }
            }
            guard addStatus == errSecSuccess else {
                throw DatabaseError.keyGenerationFailed
            }
            baseKey = newKey
        }
        
        // FIX C-14 + ED-10: legacy salt item if present (see loadPINSaltFromKeychain), otherwise per-device random salt
        // FIX M-07: var + defer wipe — previously let pinSalt persisted in heap indefinitely
        var pinSalt: Data
        if let existingSalt = loadPINSaltFromKeychain() {
            pinSalt = existingSalt
        } else {
            // ED-10 FIX: Random per-device salt replaces static "LadonDefaultSalt-v1"
            pinSalt = try loadOrCreateDeviceSalt()
        }
        defer {
            pinSalt.withUnsafeMutableBytes { ptr in
                guard let base = ptr.baseAddress else { return }
                memset_s(base, ptr.count, 0, ptr.count)
            }
        }
        
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: baseKey,
            salt: pinSalt,
            info: Data("LadonEncryptedDatabase-v1-storage-key".utf8),
            outputByteCount: 32
        )
    }
    
    /// FIX SM-C1 + SEC-02: Derive a SEPARATE 32-byte key for SQLCipher full-DB encryption.
    /// FIX SEC-02: Previously derived FROM the AEAD key (chain dependency) — if the AEAD
    /// key was compromised, the SQLCipher key could be computed. Now derives INDEPENDENTLY
    /// from the raw Keychain base key with a different HKDF info string, so compromising
    /// one key does not reveal the other.
    private func deriveSQLCipherKey() throws -> Data {
        // Load raw base key directly from Keychain (NOT via deriveEncryptionKey)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: keychainAccount,
            kSecAttrService as String: "app.ladon.messenger",
            // FIX HIGH-22: No kSecAttrAccessible in read queries
            kSecReturnData as String: true,
            kSecAttrSynchronizable as String: false
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess, var rawKeyData = result as? Data else {
            throw DatabaseError.keyGenerationFailed
        }
        // FIX R16-EDB2: Drop AnyObject ref to defeat COW — ensures wipe hits the only buffer
        result = nil
        defer {
            rawKeyData.withUnsafeMutableBytes { ptr in
                if let base = ptr.baseAddress, ptr.count > 0 {
                    _ = Darwin.memset_s(base, ptr.count, 0, ptr.count)
                }
            }
        }
        let rawBaseKey = SymmetricKey(data: rawKeyData)
        
        // FIX C-14 + ED-10: legacy salt item if present (see loadPINSaltFromKeychain), otherwise per-device random salt
        var pinSalt: Data
        if let existingSalt = loadPINSaltFromKeychain() {
            pinSalt = existingSalt
        } else {
            // ED-10 FIX: Random per-device salt replaces static "LadonDB-default-salt"
            pinSalt = try loadOrCreateDeviceSalt()
        }
        // FIX M-05: Wipe PIN salt from heap after HKDF derivation.
        // Previously the loaded salt Data persisted in memory indefinitely.
        defer {
            pinSalt.withUnsafeMutableBytes { ptr in
                guard let base = ptr.baseAddress else { return }
                memset_s(base, ptr.count, 0, ptr.count)
            }
        }
        
        let sqlcipherKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: rawBaseKey,
            salt: pinSalt,
            info: Data("LadonDB-sqlcipher-fde-v1-independent".utf8),
            outputByteCount: 32
        )
        return sqlcipherKey.withUnsafeBytes { Data($0) }
    }
    
    /// Legacy salt item, read for key derivation if present.
    ///
    /// P8-AUDIT8-IOS-03: nothing writes this item any more (its writer had no
    /// caller and was removed). The read stays because an installation that
    /// once stored it derives its database key with it — dropping the read
    /// would make that database unreadable. The database key is NOT bound to
    /// the LADON PIN or Face ID: the PIN is only a verifier (AppPinStore).
    private func loadPINSaltFromKeychain() -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: "ladon_reglock_pin_salt",
            kSecAttrService as String: "app.ladon.messenger",
            kSecReturnData as String: true,
            kSecAttrSynchronizable as String: false
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else { return nil }
        return data
    }
    
    /// ED-10 FIX: Load or create a random per-device salt stored in Keychain.
    /// Replaces static hardcoded salt fallback — each device gets a unique random salt.
    private func loadOrCreateDeviceSalt() throws -> Data {
        let account = "ladon_device_db_salt"
        let service = "app.ladon.messenger"
        
        // Try to load existing device salt
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecAttrService as String: service,
            kSecReturnData as String: true,
            kSecAttrSynchronizable as String: false
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecSuccess, let data = result as? Data, data.count == 32 {
            return data
        }
        
        // Generate new random 32-byte salt.
        //
        // P8-AUDIT5-IOS-C10 (2026-05-22): retry SecRandomCopyBytes up to 3
        // times before surrendering. The CSPRNG can transiently fail on
        // very-early boot (entropy starvation) or on jailbroken devices
        // where the Secure Enclave bridge is hooked; a one-shot failure
        // here used to set the door to "throw on every launch", and once
        // the user gets past it on attempt N the salt is fresh — i.e.
        // every prior DB row is permanently unreadable. Three retries
        // span enough time (a few hundred microseconds each) that an
        // entropy-starved boot will catch up; persistent failure remains
        // a hard error rather than producing a silently-broken DB.
        var salt = Data(count: 32)
        var lastRc: Int32 = errSecSuccess
        var rngSucceeded = false
        for attempt in 0..<3 {
            let rc = salt.withUnsafeMutableBytes { buf -> Int32 in
                guard let ptr = buf.baseAddress else { return -1 }
                return SecRandomCopyBytes(kSecRandomDefault, 32, ptr)
            }
            lastRc = rc
            if rc == errSecSuccess {
                rngSucceeded = true
                break
            }
            #if DEBUG
            print("[EncryptedDB] ⚠️ SecRandomCopyBytes failed attempt \(attempt + 1)/3: \(rc)")
            #endif
        }
        guard rngSucceeded else {
            SecureLogger.error("[EncryptedDB] ⛔ SecRandomCopyBytes persistently failed (rc=\(lastRc)) — refusing to generate device salt")
            throw DatabaseError.keyGenerationFailed
        }
        
        // Store in Keychain
        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecAttrService as String: service,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecValueData as String: salt,
            kSecAttrSynchronizable as String: false
        ]
        let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
        if addStatus != errSecSuccess {
            // FIX R17-EDB1: Throw statt silent-fail — verhindert Datenverlust
            // Wenn Salt nicht persistiert wird, würde nächster App-Start einen
            // neuen Salt generieren → anderer DB-Key → DB wird gelöscht
            SecureLogger.error("[EncryptedDB] ⛔ Device salt persist failed: \(addStatus)")
            throw DatabaseError.keyGenerationFailed
        }
        
        return salt
    }
    
    /// FIX F7: Migrate existing plaintext contact names to encrypted columns
    // Migration function removed: all code now uses encrypted_contact_name and cn_nonce exclusively.
    
    /// FIX SM-C4: Derive opaque HMAC token for database indexing.
    /// Uses HMAC-SHA256 keyed by a DEDICATED HMAC sub-key so the same ID always maps
    /// to the same token (deterministic for queries) but the plaintext ID is never
    /// stored in any SQL column. An attacker with disk access sees only opaque hashes.
    /// FIX CRIT-02: Uses separate sub-key derived via HKDF (not the AEAD key)
    private func opaqueToken(for plainID: String) throws -> String {
        let baseKey = try getEncryptionKey()
        // Derive a SEPARATE HMAC sub-key (CRIT-02: key separation)
        let hmacKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: baseKey,
            info: Data("LadonDB-hmac-index-v1".utf8),
            outputByteCount: 32
        )
        let hmac = HMAC<SHA256>.authenticationCode(
            for: Data(plainID.utf8),
            using: hmacKey
        )
        return Data(hmac).map { String(format: "%02x", $0) }.joined()
    }
    
    /// FIX HIGH-05: AAD context parameter prevents ciphertext transplant attacks.
    /// The context string (e.g. "messages.content" or "conversations.public_key") is bound
    /// as Additional Authenticated Data — swapping encrypted blobs between columns/rows fails.
    private func encrypt(_ data: Data, context: String = "") throws -> (ciphertext: Data, nonce: Data) {
        let baseKey = try getEncryptionKey()
        // FIX CRIT-02: Derive a SEPARATE AEAD sub-key (not the HMAC key)
        let aeadKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: baseKey,
            info: Data("LadonDB-aead-encrypt-v1".utf8),
            outputByteCount: 32
        )
        let nonce = ChaChaPoly.Nonce()
        let aad = Data(context.utf8)
        let sealed = try ChaChaPoly.seal(data, using: aeadKey, nonce: nonce, authenticating: aad)
        return (sealed.ciphertext + sealed.tag, Data(nonce))
    }
    
    /// FIX HIGH-05: Decrypt with AAD context. Falls back to no-AAD for legacy data migration.
    private func decrypt(ciphertext: Data, nonce: Data, context: String = "") throws -> Data {
        let baseKey = try getEncryptionKey()
        // FIX CRIT-02: Derive the SAME AEAD sub-key for decryption
        let aeadKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: baseKey,
            info: Data("LadonDB-aead-encrypt-v1".utf8),
            outputByteCount: 32
        )
        guard ciphertext.count >= 16 else { throw DatabaseError.decryptionFailed }
        let tag = ciphertext.suffix(16)
        let ct = ciphertext.prefix(ciphertext.count - 16)
        let sealedBox = try ChaChaPoly.SealedBox(
            nonce: ChaChaPoly.Nonce(data: nonce),
            ciphertext: ct,
            tag: tag
        )
        let aad = Data(context.utf8)
        // FIX H-4: AAD-only decryption — no fallback without AAD (prevents downgrade attack)
        return try ChaChaPoly.open(sealedBox, using: aeadKey, authenticating: aad)
    }
    
    // MARK: - Message Operations
    
    /// Store a message with encrypted content
    /// FIX MED-1: Stores precise timestamp and is_outgoing in encrypted_metadata
    /// to reduce forensic leakage. Plaintext timestamp rounded to 5 minutes.
    func storeMessage(_ message: Message) throws {
        try dbQueue.sync {
            // FIX MED-13: message.content is now Data (wipe-friendly); no
            // conversion needed.
            let contentData = message.content
            let (encryptedContent, nonce) = try encrypt(contentData, context: "messages.content")
            
            // FIX MED-1: Encrypt precise timestamp + is_outgoing in metadata blob
            let metadataDict: [String: Double] = [
                "ts": message.timestamp.timeIntervalSince1970,
                "out": message.isOutgoing ? 1.0 : 0.0
            ]
            let metadataJSON = try JSONSerialization.data(withJSONObject: metadataDict)
            let (encryptedMeta, metaNonce) = try encrypt(metadataJSON, context: "messages.metadata")
            
            // FIX MED-1: Round plaintext timestamp to 5-minute intervals to reduce forensic value
            let roundedTimestamp = (message.timestamp.timeIntervalSince1970 / 300.0).rounded() * 300.0
            
            let sql = """
            INSERT OR REPLACE INTO messages 
            (id, conversation_id, encrypted_content, nonce, timestamp, is_outgoing, 
             sender_current_id, sender_stable_id, encrypted_metadata, metadata_nonce)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            
            var stmt: OpaquePointer?
            guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
                throw DatabaseError.queryFailed
            }
            defer { sqlite3_finalize(stmt) }
            
            // NOTE F-LE-2: message.id as plaintext PRIMARY KEY is safe because
            // the entire database is SQLCipher-encrypted. HMAC tokenization would break
            // message lookups since HMAC is one-way and in-memory vs DB-loaded IDs diverge.
            sqlite3_bind_text(stmt, 1, (message.id as NSString).utf8String, -1, SQLITE_TRANSIENT_DESTRUCTOR)
            // FIX SM-C4: Store opaque HMAC token instead of plaintext conversation ID
            let convToken = try opaqueToken(for: message.conversationID)
            sqlite3_bind_text(stmt, 2, (convToken as NSString).utf8String, -1, SQLITE_TRANSIENT_DESTRUCTOR)
            encryptedContent.withUnsafeBytes { ptr in
                _ = sqlite3_bind_blob(stmt, 3, ptr.baseAddress, Int32(encryptedContent.count), SQLITE_TRANSIENT_DESTRUCTOR)
            }
            nonce.withUnsafeBytes { ptr in
                _ = sqlite3_bind_blob(stmt, 4, ptr.baseAddress, Int32(nonce.count), SQLITE_TRANSIENT_DESTRUCTOR)
            }
            // FIX MED-1: Store rounded timestamp (5-min granularity) in plaintext column
            sqlite3_bind_double(stmt, 5, roundedTimestamp)
            // FIX MED-1: Store constant 0 for is_outgoing in plaintext (real value in encrypted_metadata)
            sqlite3_bind_int(stmt, 6, 0)
            if let senderID = message.senderCurrentID {
                // FIX SM-C4: Opaque sender token
                let senderToken = try opaqueToken(for: senderID)
                sqlite3_bind_text(stmt, 7, (senderToken as NSString).utf8String, -1, SQLITE_TRANSIENT_DESTRUCTOR)
            } else {
                sqlite3_bind_null(stmt, 7)
            }
            if let stableID = message.senderStableID {
                // FIX SM-C4: Opaque stable ID token
                let stableToken = try opaqueToken(for: stableID)
                sqlite3_bind_text(stmt, 8, (stableToken as NSString).utf8String, -1, SQLITE_TRANSIENT_DESTRUCTOR)
            } else {
                sqlite3_bind_null(stmt, 8)
            }
            // FIX MED-1: Bind encrypted metadata (params 9, 10)
            encryptedMeta.withUnsafeBytes { ptr in
                _ = sqlite3_bind_blob(stmt, 9, ptr.baseAddress, Int32(encryptedMeta.count), SQLITE_TRANSIENT_DESTRUCTOR)
            }
            metaNonce.withUnsafeBytes { ptr in
                _ = sqlite3_bind_blob(stmt, 10, ptr.baseAddress, Int32(metaNonce.count), SQLITE_TRANSIENT_DESTRUCTOR)
            }
            
            guard sqlite3_step(stmt) == SQLITE_DONE else {
                throw DatabaseError.queryFailed
            }
            
            incrementWALCounter()
        }
    }
    
    /// Load messages for a conversation (decrypts on-demand)
    /// FIX MED-1: Prefers precise timestamp/is_outgoing from encrypted_metadata when available
    func loadMessages(conversationID: String, limit: Int = 100, offset: Int = 0) throws -> [Message] {
        try dbQueue.sync {
            let sql = """
            SELECT id, conversation_id, encrypted_content, nonce, timestamp, is_outgoing, 
                   sender_current_id, sender_stable_id, encrypted_metadata, metadata_nonce
            FROM messages 
            WHERE conversation_id = ?
            ORDER BY timestamp ASC
            LIMIT ? OFFSET ?
            """
            
            var stmt: OpaquePointer?
            guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
                throw DatabaseError.queryFailed
            }
            defer { sqlite3_finalize(stmt) }
            
            // FIX SM-C4: Query by opaque HMAC token
            let convToken = try opaqueToken(for: conversationID)
            sqlite3_bind_text(stmt, 1, (convToken as NSString).utf8String, -1, SQLITE_TRANSIENT_DESTRUCTOR)
            sqlite3_bind_int(stmt, 2, Int32(limit))
            sqlite3_bind_int(stmt, 3, Int32(offset))
            
            var messages: [Message] = []
            while sqlite3_step(stmt) == SQLITE_ROW {
                guard let id = sqlite3_column_text(stmt, 0).map({ String(cString: $0) }),
                      let convID = sqlite3_column_text(stmt, 1).map({ String(cString: $0) }) else {
                    continue
                }
                
                let encryptedLen = sqlite3_column_bytes(stmt, 2)
                let nonceLen = sqlite3_column_bytes(stmt, 3)
                
                guard encryptedLen > 0, nonceLen > 0,
                      let encPtr = sqlite3_column_blob(stmt, 2),
                      let noncePtr = sqlite3_column_blob(stmt, 3) else {
                    continue
                }
                
                let encryptedData = Data(bytes: encPtr, count: Int(encryptedLen))
                let nonceData = Data(bytes: noncePtr, count: Int(nonceLen))
                
                // FIX MED-8: Log decryption failures instead of silently skipping
                guard let contentData = try? decrypt(ciphertext: encryptedData, nonce: nonceData, context: "messages.content"),
                      let content = String(data: contentData, encoding: .utf8) else {
                    #if DEBUG
                    print("[EncryptedDB] ⚠️ Failed to decrypt message \(id) — possible corruption or key mismatch")
                    #endif
                    continue
                }
                
                // FIX MED-1: Prefer precise values from encrypted_metadata
                var timestamp = Date(timeIntervalSince1970: sqlite3_column_double(stmt, 4))
                var isOutgoing = sqlite3_column_int(stmt, 5) == 1
                
                // Try to decrypt metadata for precise timestamp + is_outgoing
                let metaLen = sqlite3_column_bytes(stmt, 8)
                let metaNonceLen = sqlite3_column_bytes(stmt, 9)
                if metaLen > 0, metaNonceLen > 0,
                   let metaPtr = sqlite3_column_blob(stmt, 8),
                   let metaNoncePtr = sqlite3_column_blob(stmt, 9) {
                    let metaData = Data(bytes: metaPtr, count: Int(metaLen))
                    let metaNonce = Data(bytes: metaNoncePtr, count: Int(metaNonceLen))
                    if let metaPlain = try? decrypt(ciphertext: metaData, nonce: metaNonce, context: "messages.metadata"),
                       let metaDict = try? JSONSerialization.jsonObject(with: metaPlain) as? [String: Double] {
                        if let ts = metaDict["ts"] {
                            timestamp = Date(timeIntervalSince1970: ts)
                        }
                        if let out = metaDict["out"] {
                            isOutgoing = out == 1.0
                        }
                    }
                }
                
                let senderCurrentID = sqlite3_column_text(stmt, 6).map { String(cString: $0) }
                let senderStableID = sqlite3_column_text(stmt, 7).map { String(cString: $0) }
                
                messages.append(Message(
                    id: id,
                    content: content,
                    timestamp: timestamp,
                    isOutgoing: isOutgoing,
                    conversationID: convID,
                    senderCurrentID: senderCurrentID,
                    senderStableID: senderStableID
                ))
            }
            
            return messages
        }
    }
    
    /// Delete a single message and securely overwrite its content
    func deleteMessage(id: String) throws {
        try dbQueue.sync {
            // FIX C1: Parameterized query statt String-Interpolation (SQL Injection verhindert)
            let sql = "DELETE FROM messages WHERE id = ?"
            var stmt: OpaquePointer?
            // FIX DB-5: throw instead of silent return on prepare failure
            guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
                throw DatabaseError.prepareFailed
            }
            defer { sqlite3_finalize(stmt) }
            sqlite3_bind_text(stmt, 1, (id as NSString).utf8String, -1, SQLITE_TRANSIENT_DESTRUCTOR)
            // FIX DB-4: Check sqlite3_step return value
            let result = sqlite3_step(stmt)
            guard result == SQLITE_DONE else {
                throw DatabaseError.deleteFailed
            }
            incrementWALCounter()
        }
    }
    
    /// Delete all messages for a conversation
    func deleteMessages(conversationID: String) throws {
        try dbQueue.sync {
            let sql = "DELETE FROM messages WHERE conversation_id = ?"
            var stmt: OpaquePointer?
            // FIX DB-5: throw instead of silent return on prepare failure
            guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
                throw DatabaseError.prepareFailed
            }
            defer { sqlite3_finalize(stmt) }
            // FIX SM-C4: Query by opaque token
            let convToken = try opaqueToken(for: conversationID)
            sqlite3_bind_text(stmt, 1, (convToken as NSString).utf8String, -1, SQLITE_TRANSIENT_DESTRUCTOR)
            // FIX DB-4: Check sqlite3_step return value
            let result = sqlite3_step(stmt)
            guard result == SQLITE_DONE else {
                throw DatabaseError.deleteFailed
            }
            incrementWALCounter()
        }
    }
    
    // MARK: - Conversation Operations
    
    /// Persist a conversation with per-field ChaCha20-Poly1305 encryption.
    /// Public key, contact name, and recipient IDs are encrypted; SQL columns store opaque HMAC tokens for indexing.
    func storeConversation(_ conversation: Conversation) throws {
        try dbQueue.sync {
            let (encPK, pkNonce) = try encrypt(conversation.recipientPublicKey, context: "conversations.public_key")
            // FIX F7: encrypt contact_name
            let nameData = conversation.contactName.data(using: .utf8) ?? Data()
            let (encName, cnNonce) = try encrypt(nameData, context: "conversations.contact_name")
            
            // FIX SM-C4: Encrypt real IDs into recipient_data blob for recovery
            // FIX SEC-04/05: Also include real metadata (timestamp, direction, timer)
            // so plaintext columns can store obfuscated dummy values
            var idPayload: [String: String] = [
                "id": conversation.id,
                "recipientID": conversation.recipientID
            ]
            if let relayID = conversation.relayRecipientID {
                idPayload["relayRecipientID"] = relayID
            }
            // SEC-04/05: Store real metadata in encrypted blob
            if let lastMsg = conversation.lastMessage {
                idPayload["lastMessageTimestamp"] = String(lastMsg.timestamp.timeIntervalSince1970)
                idPayload["lastMessageIsOutgoing"] = lastMsg.isOutgoing ? "1" : "0"
            }
            idPayload["disappearingTimer"] = String(conversation.disappearingTimer.rawValue)
            idPayload["isPinned"] = conversation.isPinned ? "1" : "0"
            if let pinnedAt = conversation.pinnedAt {
                idPayload["pinnedAt"] = String(pinnedAt.timeIntervalSince1970)
            }
            let idData = try JSONEncoder().encode(idPayload)
            let (encIDData, idNonce) = try encrypt(idData, context: "conversations.recipient_data")
            
            let sql = """
            INSERT OR REPLACE INTO conversations
            (id, recipient_id, encrypted_public_key, pk_nonce, encrypted_contact_name, cn_nonce,
             relay_recipient_id, last_message_timestamp, last_message_is_outgoing, disappearing_timer,
             encrypted_recipient_data, recipient_data_nonce, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, julianday('now'))
            """
            
            var stmt: OpaquePointer?
            guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
                throw DatabaseError.queryFailed
            }
            defer { sqlite3_finalize(stmt) }
            
            // FIX SM-C4: Store opaque tokens for ID fields
            let idToken = try opaqueToken(for: conversation.id)
            sqlite3_bind_text(stmt, 1, (idToken as NSString).utf8String, -1, SQLITE_TRANSIENT_DESTRUCTOR)
            let recipientToken = try opaqueToken(for: conversation.recipientID)
            sqlite3_bind_text(stmt, 2, (recipientToken as NSString).utf8String, -1, SQLITE_TRANSIENT_DESTRUCTOR)
            encPK.withUnsafeBytes { ptr in
                _ = sqlite3_bind_blob(stmt, 3, ptr.baseAddress, Int32(encPK.count), SQLITE_TRANSIENT_DESTRUCTOR)
            }
            pkNonce.withUnsafeBytes { ptr in
                _ = sqlite3_bind_blob(stmt, 4, ptr.baseAddress, Int32(pkNonce.count), SQLITE_TRANSIENT_DESTRUCTOR)
            }
            // FIX F7: Encrypted contact name
            encName.withUnsafeBytes { ptr in
                _ = sqlite3_bind_blob(stmt, 5, ptr.baseAddress, Int32(encName.count), SQLITE_TRANSIENT_DESTRUCTOR)
            }
            cnNonce.withUnsafeBytes { ptr in
                _ = sqlite3_bind_blob(stmt, 6, ptr.baseAddress, Int32(cnNonce.count), SQLITE_TRANSIENT_DESTRUCTOR)
            }
            if let relayID = conversation.relayRecipientID {
                // FIX SM-C4: Opaque relay recipient token
                let relayToken = try opaqueToken(for: relayID)
                sqlite3_bind_text(stmt, 7, (relayToken as NSString).utf8String, -1, SQLITE_TRANSIENT_DESTRUCTOR)
            } else {
                sqlite3_bind_null(stmt, 7)
            }
            if let lastMsg = conversation.lastMessage {
                // FIX SEC-04/05: Encrypt timestamp and direction metadata.
                // Previously stored as plaintext — reveals when messages were sent/received
                // and whether they were outgoing (direction analysis). Now:
                // - Timestamp rounded to 1-hour granularity (reduces precision)
                // - Real values stored in encrypted_recipient_data blob
                // - Plaintext columns store obfuscated dummy values
                let roundedTs = (lastMsg.timestamp.timeIntervalSince1970 / 3600.0).rounded() * 3600.0
                sqlite3_bind_double(stmt, 8, roundedTs)
                sqlite3_bind_int(stmt, 9, 0) // Always 0 in plaintext (real value in encrypted blob)
            } else {
                sqlite3_bind_null(stmt, 8)
                sqlite3_bind_null(stmt, 9)
            }
            // FIX SEC-04: disappearing_timer stored as 0 in plaintext
            // Real value is in the encrypted_recipient_data blob
            sqlite3_bind_int(stmt, 10, 0)
            
            // FIX SM-C4: Bind encrypted real IDs
            encIDData.withUnsafeBytes { ptr in
                _ = sqlite3_bind_blob(stmt, 11, ptr.baseAddress, Int32(encIDData.count), SQLITE_TRANSIENT_DESTRUCTOR)
            }
            idNonce.withUnsafeBytes { ptr in
                _ = sqlite3_bind_blob(stmt, 12, ptr.baseAddress, Int32(idNonce.count), SQLITE_TRANSIENT_DESTRUCTOR)
            }
            
            guard sqlite3_step(stmt) == SQLITE_DONE else {
                throw DatabaseError.queryFailed
            }
            
            incrementWALCounter()
        }
    }
    
    /// Load all conversations, decrypting public keys, contact names, and recipient IDs on-the-fly.
    /// Returns conversations ordered by last update timestamp.
    func loadConversations() throws -> [Conversation] {
        try dbQueue.sync {
            // FIX SM-C4: Also select encrypted_recipient_data for real ID recovery
            let sql = """
            SELECT id, recipient_id, encrypted_public_key, pk_nonce, encrypted_contact_name,
                   cn_nonce, relay_recipient_id, last_message_timestamp, last_message_is_outgoing,
                   disappearing_timer, encrypted_recipient_data, recipient_data_nonce
            FROM conversations
            ORDER BY updated_at DESC
            """
            
            var stmt: OpaquePointer?
            guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
                throw DatabaseError.queryFailed
            }
            defer { sqlite3_finalize(stmt) }
            
            var conversations: [Conversation] = []
            while sqlite3_step(stmt) == SQLITE_ROW {
                // FIX SM-C4: Recover real IDs from encrypted_recipient_data blob
                var realID: String
                var realRecipientID: String
                var realRelayRecipientID: String?
                // FIX DB-8: Cache decrypted idPayload to avoid double decryption
                var cachedIDPayload: [String: String]?
                
                let encIDLen = sqlite3_column_bytes(stmt, 10)
                let idNonceLen = sqlite3_column_bytes(stmt, 11)
                if encIDLen > 0, idNonceLen > 0,
                   let encIDPtr = sqlite3_column_blob(stmt, 10),
                   let idNoncePtr = sqlite3_column_blob(stmt, 11) {
                    let encIDData = Data(bytes: encIDPtr, count: Int(encIDLen))
                    let idNonceData = Data(bytes: idNoncePtr, count: Int(idNonceLen))
                    if let idData = try? decrypt(ciphertext: encIDData, nonce: idNonceData, context: "conversations.recipient_data"),
                       let idPayload = try? JSONDecoder().decode([String: String].self, from: idData) {
                        cachedIDPayload = idPayload
                        realID = idPayload["id"] ?? ""
                        realRecipientID = idPayload["recipientID"] ?? ""
                        realRelayRecipientID = idPayload["relayRecipientID"]
                    } else {
                        // Fallback: opaque tokens stored in columns (legacy/migration)
                        guard let id = sqlite3_column_text(stmt, 0).map({ String(cString: $0) }),
                              let recipientID = sqlite3_column_text(stmt, 1).map({ String(cString: $0) }) else {
                            continue
                        }
                        realID = id
                        realRecipientID = recipientID
                        realRelayRecipientID = sqlite3_column_text(stmt, 6).map { String(cString: $0) }
                    }
                } else {
                    // No encrypted ID data (legacy row) — use column values directly
                    guard let id = sqlite3_column_text(stmt, 0).map({ String(cString: $0) }),
                          let recipientID = sqlite3_column_text(stmt, 1).map({ String(cString: $0) }) else {
                        continue
                    }
                    realID = id
                    realRecipientID = recipientID
                    realRelayRecipientID = sqlite3_column_text(stmt, 6).map { String(cString: $0) }
                }
                
                let encPKLen = sqlite3_column_bytes(stmt, 2)
                let nonceLen = sqlite3_column_bytes(stmt, 3)
                guard encPKLen > 0, nonceLen > 0,
                      let encPtr = sqlite3_column_blob(stmt, 2),
                      let noncePtr = sqlite3_column_blob(stmt, 3) else {
                    continue
                }
                
                let encPK = Data(bytes: encPtr, count: Int(encPKLen))
                let nonce = Data(bytes: noncePtr, count: Int(nonceLen))
                // FIX HIGH-9: Throw on decryption failure instead of empty Data() fallback
                // An empty public key means NO encryption — must not silently degrade
                //
                // FIX V2: For V2 contacts (ladonv2:), recipientPublicKey is intentionally
                // empty (Data()) because all key material is keyed by recipientID via
                // PeerStoreV2 / DirectoryClientV2. An empty plaintext IS valid for V2;
                // only a hard decrypt failure should drop the row.
                let publicKey: Data
                do {
                    publicKey = try decrypt(ciphertext: encPK, nonce: nonce, context: "conversations.public_key")
                } catch {
                    #if DEBUG
                    print("[EncryptedDB] ⚠️ Failed to decrypt recipientPublicKey — skipping corrupted conversation: \(error)")
                    #endif
                    continue
                }
                
                // FIX F7: Decrypt contact name
                var contactName = "Unknown"
                let encCNLen = sqlite3_column_bytes(stmt, 4)
                let cnNonceLen = sqlite3_column_bytes(stmt, 5)
                if encCNLen > 0, cnNonceLen > 0,
                   let encCNPtr = sqlite3_column_blob(stmt, 4),
                   let cnNoncePtr = sqlite3_column_blob(stmt, 5) {
                    let encCN = Data(bytes: encCNPtr, count: Int(encCNLen))
                    let cnNonce = Data(bytes: cnNoncePtr, count: Int(cnNonceLen))
                    if let nameData = try? decrypt(ciphertext: encCN, nonce: cnNonce, context: "conversations.contact_name") {
                        contactName = String(data: nameData, encoding: .utf8) ?? "Unknown"
                    }
                }
                // FIX SM-C4: Use decrypted real IDs, not opaque column tokens
                
                // FIX SEC-04/05: Read real metadata from encrypted blob, not plaintext columns
                // The encrypted idPayload now contains the real timestamp, direction, and timer
                var lastMessage: Message? = nil
                var disappearingTimerValue: Int = 0
                var isPinnedValue = false
                var pinnedAtValue: Date? = nil
                
                // FIX DB-8: Reuse cached decrypted payload instead of decrypting again
                if let idPayload = cachedIDPayload {
                    if let tsStr = idPayload["lastMessageTimestamp"],
                       let ts = TimeInterval(tsStr) {
                        let isOutgoing = idPayload["lastMessageIsOutgoing"] == "1"
                        lastMessage = Message(
                            id: "preview",
                            content: "",
                            timestamp: Date(timeIntervalSince1970: ts),
                            isOutgoing: isOutgoing,
                            conversationID: realRecipientID
                        )
                    }
                    if let timerStr = idPayload["disappearingTimer"],
                       let timerVal = Int(timerStr) {
                        disappearingTimerValue = timerVal
                    }
                    isPinnedValue = idPayload["isPinned"] == "1"
                    if let pinnedAtStr = idPayload["pinnedAt"],
                       let pinnedAtTs = TimeInterval(pinnedAtStr) {
                        pinnedAtValue = Date(timeIntervalSince1970: pinnedAtTs)
                    }
                }
                
                // Fallback: use rounded plaintext timestamp if encrypted metadata unavailable
                if lastMessage == nil && sqlite3_column_type(stmt, 7) != SQLITE_NULL {
                    let ts = Date(timeIntervalSince1970: sqlite3_column_double(stmt, 7))
                    lastMessage = Message(
                        id: "preview",
                        content: "",
                        timestamp: ts,
                        isOutgoing: false, // Plaintext is always 0 (SEC-04 fix)
                        conversationID: realRecipientID
                    )
                }
                
                conversations.append(Conversation(
                    id: realID,
                    recipientID: realRecipientID,
                    recipientPublicKey: publicKey,
                    contactName: contactName,
                    lastMessage: lastMessage,
                    relayRecipientID: realRelayRecipientID,
                    // FIX SEC-04: Use timer from encrypted blob (plaintext is always 0)
                    disappearingTimer: DisappearingTimer(rawValue: disappearingTimerValue) ?? .fiveMinutes,
                    isPinned: isPinnedValue,
                    pinnedAt: pinnedAtValue
                ))
            }
            
            return conversations
        }
    }
    
    /// Delete a conversation and all its messages.
    /// Uses opaque HMAC token for the WHERE clause to prevent plaintext ID leakage in SQL.
    func deleteConversation(id: String) throws {
        try dbQueue.sync {
            // FIX DB-2: Wrap both DELETEs in a transaction for atomicity
            // FIX AUDIT-MAR-2026-16: Ensure ROLLBACK on any throw (including opaqueToken)
            // FIX AUDIT-R7-05: Guard BEGIN/COMMIT return values — silent failures cause data inconsistency
            guard exec("BEGIN TRANSACTION") else {
                throw DatabaseError.transactionFailed
            }
            do {
                // FIX SM-C4: Use opaque tokens for deletion queries
                let idToken = try opaqueToken(for: id)
                let sql = "DELETE FROM conversations WHERE id = ?"
                var stmt: OpaquePointer?
                // FIX DB-5: throw instead of silent return on prepare failure
                guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
                    throw DatabaseError.prepareFailed
                }
                defer { sqlite3_finalize(stmt) }
                sqlite3_bind_text(stmt, 1, (idToken as NSString).utf8String, -1, SQLITE_TRANSIENT_DESTRUCTOR)
                // FIX DB-4: Check sqlite3_step return value
                let result1 = sqlite3_step(stmt)
                guard result1 == SQLITE_DONE else {
                    throw DatabaseError.deleteFailed
                }
                
                // Also delete all messages for this conversation
                let convToken = try opaqueToken(for: id)
                let delMsgs = "DELETE FROM messages WHERE conversation_id = ?"
                var stmt2: OpaquePointer?
                // FIX DB-5: throw instead of silent return on prepare failure
                guard sqlite3_prepare_v2(db, delMsgs, -1, &stmt2, nil) == SQLITE_OK else {
                    throw DatabaseError.prepareFailed
                }
                defer { sqlite3_finalize(stmt2) }
                sqlite3_bind_text(stmt2, 1, (convToken as NSString).utf8String, -1, SQLITE_TRANSIENT_DESTRUCTOR)
                // FIX DB-4: Check sqlite3_step return value
                let result2 = sqlite3_step(stmt2)
                guard result2 == SQLITE_DONE else {
                    throw DatabaseError.deleteFailed
                }
                
                // FIX AUDIT-R7-05: Guard COMMIT — silent failure leaves DB in undefined state
                guard exec("COMMIT") else {
                    // FIX AUDIT-R10-P2: Log ROLLBACK failure — indicates corrupt DB connection
                    if !exec("ROLLBACK") {
                        #if DEBUG
                        print("[EncryptedDB] ⚠️ ROLLBACK failed after COMMIT failure in deleteConversation")
                        #endif
                    }
                    throw DatabaseError.commitFailed
                }
                incrementWALCounter()
            } catch {
                // FIX AUDIT-R10-P3: Log ROLLBACK failure in catch block
                if !exec("ROLLBACK") {
                    #if DEBUG
                    print("[EncryptedDB] ⚠️ ROLLBACK failed in deleteConversation catch")
                    #endif
                }
                throw error
            }
        }
    }
    
    /// Delete all conversations and messages from the encrypted database.
    /// FIX AUDIT-MAR-2026-17: Wrap in transaction for atomicity
    /// FIX AUDIT-MAR-2026-26: Check exec() return values and ROLLBACK on failure
    func deleteAllConversations() throws {
        try dbQueue.sync {
            // FIX AUDIT-R7-05: Guard BEGIN/COMMIT return values
            guard exec("BEGIN TRANSACTION") else {
                throw DatabaseError.transactionFailed
            }
            guard exec("DELETE FROM conversations") else {
                // FIX AUDIT-R10-P4: Log ROLLBACK failure
                if !exec("ROLLBACK") {
                    #if DEBUG
                    print("[EncryptedDB] ⚠️ ROLLBACK failed after DELETE conversations failure")
                    #endif
                }
                throw DatabaseError.deleteFailed
            }
            guard exec("DELETE FROM messages") else {
                // FIX AUDIT-R10-P5: Log ROLLBACK failure
                if !exec("ROLLBACK") {
                    #if DEBUG
                    print("[EncryptedDB] ⚠️ ROLLBACK failed after DELETE messages failure")
                    #endif
                }
                throw DatabaseError.deleteFailed
            }
            guard exec("COMMIT") else {
                // FIX AUDIT-R10-P6: Log ROLLBACK failure
                if !exec("ROLLBACK") {
                    #if DEBUG
                    print("[EncryptedDB] ⚠️ ROLLBACK failed after COMMIT failure in deleteAllConversations")
                    #endif
                }
                throw DatabaseError.commitFailed
            }
            incrementWALCounter()
        }
    }
    
    // MARK: - Verification Status
    
    /// Store or update a contact's identity key verification status.
    /// The identity key is encrypted before storage; the contact ID is stored as an opaque HMAC token.
    func setVerificationStatus(contactID: String, verified: Bool, identityKey: Data?) throws {
        try dbQueue.sync {
            let sql = """
            INSERT OR REPLACE INTO verification_status
            (contact_id, is_verified, verified_at, last_known_identity_key, identity_key_nonce)
            VALUES (?, ?, julianday('now'), ?, ?)
            """
            var stmt: OpaquePointer?
            guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
                throw DatabaseError.queryFailed
            }
            defer { sqlite3_finalize(stmt) }
            
            // FIX SM-C4: Opaque token for contact ID
            let contactToken = try opaqueToken(for: contactID)
            sqlite3_bind_text(stmt, 1, (contactToken as NSString).utf8String, -1, SQLITE_TRANSIENT_DESTRUCTOR)
            sqlite3_bind_int(stmt, 2, verified ? 1 : 0)
            // FIX CRIT-03: Encrypt identity key before storing
            if let key = identityKey {
                let (encrypted, nonce) = try encrypt(key, context: "verification.identity_key")
                encrypted.withUnsafeBytes { ptr in
                    _ = sqlite3_bind_blob(stmt, 3, ptr.baseAddress, Int32(encrypted.count), SQLITE_TRANSIENT_DESTRUCTOR)
                }
                nonce.withUnsafeBytes { ptr in
                    _ = sqlite3_bind_blob(stmt, 4, ptr.baseAddress, Int32(nonce.count), SQLITE_TRANSIENT_DESTRUCTOR)
                }
            } else {
                sqlite3_bind_null(stmt, 3)
                sqlite3_bind_null(stmt, 4)
            }
            
            // FIX AUDIT-MAR-2026-6 + FIX AUDIT-R9-05: Throw on step failure (not just DEBUG-log)
            let stepResult = sqlite3_step(stmt)
            if stepResult != SQLITE_DONE && stepResult != SQLITE_ROW {
                SecureLogger.error("[EncryptedDB] setVerificationStatus sqlite3_step failed: \(stepResult)")
                throw DatabaseError.queryFailed
            }
            incrementWALCounter()
        }
    }
    
    /// Retrieve a contact's verification status and last known identity key (decrypted).
    /// Returns (false, nil) if the contact has not been seen before.
    func getVerificationStatus(contactID: String) -> (verified: Bool, lastKnownKey: Data?) {
        dbQueue.sync {
            let sql = "SELECT is_verified, last_known_identity_key, identity_key_nonce FROM verification_status WHERE contact_id = ?"
            var stmt: OpaquePointer?
            guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return (false, nil) }
            defer { sqlite3_finalize(stmt) }
            
            // FIX HIGH-11: Propagate error instead of falling back to plaintext ID
            guard let contactToken = try? opaqueToken(for: contactID) else {
                return (false, nil)
            }
            sqlite3_bind_text(stmt, 1, (contactToken as NSString).utf8String, -1, SQLITE_TRANSIENT_DESTRUCTOR)
            
            guard sqlite3_step(stmt) == SQLITE_ROW else { return (false, nil) }
            
            let verified = sqlite3_column_int(stmt, 0) == 1
            var lastKey: Data? = nil
            // FIX CRIT-03: Decrypt identity key from encrypted storage
            let keyLen = sqlite3_column_bytes(stmt, 1)
            let nonceLen = sqlite3_column_bytes(stmt, 2)
            if keyLen > 0, let keyPtr = sqlite3_column_blob(stmt, 1) {
                let encryptedKey = Data(bytes: keyPtr, count: Int(keyLen))
                if nonceLen > 0, let noncePtr = sqlite3_column_blob(stmt, 2) {
                    let nonce = Data(bytes: noncePtr, count: Int(nonceLen))
                    lastKey = try? decrypt(ciphertext: encryptedKey, nonce: nonce, context: "verification.identity_key")
                }
                // ED-6 FIX: No legacy unencrypted key fallback — if no nonce, key is untrusted
                // An attacker stripping nonces from the DB could inject a known key
            }
            
            return (verified, lastKey)
        }
    }
    
    /// Record an identity key change for a contact: resets verification to false,
    /// stores the new encrypted identity key, and timestamps the change.
    func recordKeyChange(contactID: String, newKey: Data) throws {
        try dbQueue.sync {
            let sql = """
            UPDATE verification_status
            SET is_verified = 0, key_changed_at = julianday('now'), last_known_identity_key = ?, identity_key_nonce = ?
            WHERE contact_id = ?
            """
            var stmt: OpaquePointer?
            // FIX DB-5: throw instead of silent return on prepare failure
            guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
                throw DatabaseError.prepareFailed
            }
            defer { sqlite3_finalize(stmt) }
            
            // FIX CRIT-03: Encrypt identity key before storing
            let (encrypted, nonce) = try encrypt(newKey, context: "verification.identity_key")
            encrypted.withUnsafeBytes { ptr in
                _ = sqlite3_bind_blob(stmt, 1, ptr.baseAddress, Int32(encrypted.count), SQLITE_TRANSIENT_DESTRUCTOR)
            }
            nonce.withUnsafeBytes { ptr in
                _ = sqlite3_bind_blob(stmt, 2, ptr.baseAddress, Int32(nonce.count), SQLITE_TRANSIENT_DESTRUCTOR)
            }
            // FIX SM-C4: Opaque token for contact ID
            let contactToken = try opaqueToken(for: contactID)
            sqlite3_bind_text(stmt, 3, (contactToken as NSString).utf8String, -1, SQLITE_TRANSIENT_DESTRUCTOR)
            let result = sqlite3_step(stmt)
            // FIX AUDIT-R9-06: Check step result for errors (not just 0-rows)
            if result != SQLITE_DONE && result != SQLITE_ROW {
                SecureLogger.error("[EncryptedDB] recordKeyChange sqlite3_step failed: \(result)")
                throw DatabaseError.queryFailed
            }
            // FIX DB-13: Log warning if UPDATE affected 0 rows (contact not in verification_status)
            if result == SQLITE_DONE && sqlite3_changes(db) == 0 {
                #if DEBUG
                print("[EncryptedDB] \u{26a0}\u{fe0f} recordKeyChange: no rows updated for contact (may not exist in verification_status)")
                #endif
            }
        }
    }
    
    // MARK: - Secure Key-Value Store
    
    /// FIX LOW-05: Derive opaque token for KV keys to hide what settings exist
    private func opaqueKVToken(for key: String) throws -> String {
        let token = try opaqueToken(for: key)
        return token
    }
    
    /// Store an encrypted key-value pair in the secure_kv table.
    /// The key is hashed to an opaque HMAC token; the value is encrypted with context-bound ChaCha20-Poly1305.
    func setValue(_ value: Data, forKey key: String) throws {
        try dbQueue.sync {
            let (encrypted, nonce) = try encrypt(value, context: "secure_kv.\(key)")
            let opaqueKey = try opaqueKVToken(for: key)
            let sql = "INSERT OR REPLACE INTO secure_kv (key, encrypted_value, nonce) VALUES (?, ?, ?)"
            var stmt: OpaquePointer?
            guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
                throw DatabaseError.queryFailed
            }
            defer { sqlite3_finalize(stmt) }
            
            sqlite3_bind_text(stmt, 1, (opaqueKey as NSString).utf8String, -1, SQLITE_TRANSIENT_DESTRUCTOR)
            encrypted.withUnsafeBytes { ptr in
                _ = sqlite3_bind_blob(stmt, 2, ptr.baseAddress, Int32(encrypted.count), SQLITE_TRANSIENT_DESTRUCTOR)
            }
            nonce.withUnsafeBytes { ptr in
                _ = sqlite3_bind_blob(stmt, 3, ptr.baseAddress, Int32(nonce.count), SQLITE_TRANSIENT_DESTRUCTOR)
            }
            
            guard sqlite3_step(stmt) == SQLITE_DONE else {
                throw DatabaseError.queryFailed
            }
            
            incrementWALCounter()
        }
    }
    
    /// Retrieve and decrypt a value from the secure_kv table by its key.
    /// Returns nil if the key does not exist.
    func getValue(forKey key: String) throws -> Data? {
        try dbQueue.sync {
            let opaqueKey = try opaqueKVToken(for: key)
            let sql = "SELECT encrypted_value, nonce FROM secure_kv WHERE key = ?"
            var stmt: OpaquePointer?
            guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
                // FIX AUDIT-R14-F7: Throw on prepare failure — returning nil masks DB corruption
                throw NSError(domain: "EncryptedDatabase", code: Int(sqlite3_errcode(db)),
                              userInfo: [NSLocalizedDescriptionKey: "getValue prepare failed: \(String(cString: sqlite3_errmsg(db)))"])
            }
            defer { sqlite3_finalize(stmt) }
            
            sqlite3_bind_text(stmt, 1, (opaqueKey as NSString).utf8String, -1, SQLITE_TRANSIENT_DESTRUCTOR)
            
            guard sqlite3_step(stmt) == SQLITE_ROW else { return nil }
            
            let encLen = sqlite3_column_bytes(stmt, 0)
            let nonceLen = sqlite3_column_bytes(stmt, 1)
            guard encLen > 0, nonceLen > 0,
                  let encPtr = sqlite3_column_blob(stmt, 0),
                  let noncePtr = sqlite3_column_blob(stmt, 1) else { return nil }
            
            let encrypted = Data(bytes: encPtr, count: Int(encLen))
            let nonce = Data(bytes: noncePtr, count: Int(nonceLen))
            
            return try decrypt(ciphertext: encrypted, nonce: nonce, context: "secure_kv.\(key)")
        }
    }
    
    /// Convenience: Set a string value
    func setSecureValue(_ value: String, forKey key: String) throws {
        try setValue(Data(value.utf8), forKey: key)
    }
    
    /// Convenience: Get a string value
    func getSecureValue(forKey key: String) throws -> String? {
        guard let data = try getValue(forKey: key) else { return nil }
        return String(data: data, encoding: .utf8)
    }
    
    /// Remove a key-value pair
    /// FIX CRIT-04: Use opaqueToken for DELETE query — the `key` column stores HMAC tokens,
    /// not plaintext keys. Without this, the DELETE never matches any row.
    func removeSecureValue(forKey key: String) throws {
        try dbQueue.sync {
            let sql = "DELETE FROM secure_kv WHERE key = ?"
            var stmt: OpaquePointer?
            guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
                throw DatabaseError.queryFailed
            }
            defer { sqlite3_finalize(stmt) }
            let opaqueKey = try opaqueToken(for: key)
            sqlite3_bind_text(stmt, 1, (opaqueKey as NSString).utf8String, -1, SQLITE_TRANSIENT_DESTRUCTOR)
            // FIX AUDIT-MAR-2026-7 + FIX AUDIT-R9-07: Throw on step failure (not just DEBUG-log)
            let stepResult = sqlite3_step(stmt)
            if stepResult != SQLITE_DONE && stepResult != SQLITE_ROW {
                SecureLogger.error("[EncryptedDB] removeSecureValue sqlite3_step failed: \(stepResult)")
                throw DatabaseError.queryFailed
            }
            incrementWALCounter()
        }
    }
    
    // MARK: - Wipe
    
    /// FIX SM-M4: Securely delete all data (panic mode)
    /// Overwrites sensitive blobs with random data before DELETE to defeat forensic recovery
    /// FIX AUDIT-R9-01: Check every exec() return value — if overwrite fails, data survives wipe
    func destroyAll() {
        dbQueue.sync {
            var anyFailed = false
            // Overwrite encrypted content with random bytes before deletion
            if !exec("UPDATE messages SET encrypted_content = randomblob(32), nonce = randomblob(12), encrypted_metadata = NULL, metadata_nonce = NULL") { anyFailed = true }
            if !exec("UPDATE conversations SET encrypted_public_key = randomblob(32), pk_nonce = randomblob(12), encrypted_contact_name = randomblob(16), cn_nonce = randomblob(12), encrypted_recipient_data = NULL, recipient_data_nonce = NULL") { anyFailed = true }
            if !exec("UPDATE secure_kv SET encrypted_value = randomblob(32), nonce = randomblob(12)") { anyFailed = true }
            // FIX AUDIT-MAR-2026-18: Also wipe identity_key_nonce for complete forensic cleanup
            if !exec("UPDATE verification_status SET last_known_identity_key = randomblob(32), identity_key_nonce = randomblob(12)") { anyFailed = true }
            
            // Now delete the rows
            if !exec("DELETE FROM messages") { anyFailed = true }
            if !exec("DELETE FROM conversations") { anyFailed = true }
            if !exec("DELETE FROM secure_kv") { anyFailed = true }
            if !exec("DELETE FROM verification_status") { anyFailed = true }
            
            // FIX LOW-06: Switch journal mode and VACUUM to prevent WAL remnants
            if !exec("PRAGMA journal_mode=DELETE") { anyFailed = true }
            if !exec("VACUUM") { anyFailed = true }
            if !exec("PRAGMA journal_mode=WAL") { anyFailed = true }
            
            // FIX AUDIT-R9-01: If any SQL failed, attempt DROP TABLE as fallback
            if anyFailed {
                SecureLogger.error("[EncryptedDB] ⚠️ destroyAll: some exec() failed — attempting DROP TABLE fallback")
                exec("DROP TABLE IF EXISTS messages")
                exec("DROP TABLE IF EXISTS conversations")
                exec("DROP TABLE IF EXISTS secure_kv")
                exec("DROP TABLE IF EXISTS verification_status")
            }
        }
        
        // Invalidate cached key
        invalidateKeyCache()
        
        // FIX DB-1: Purge master key and salt from Keychain
        // Without this, the encryption key survives destroyAll() and could be recovered
        let masterKeyQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: keychainAccount,
            kSecAttrService as String: "app.ladon.messenger"
        ]
        SecItemDelete(masterKeyQuery as CFDictionary)
        
        let saltQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: "ladon_reglock_pin_salt",
            kSecAttrService as String: "app.ladon.messenger"
        ]
        SecItemDelete(saltQuery as CFDictionary)
        
        // FIX AUDIT-MAR-2026-19: Also delete device DB salt — survives wipe otherwise
        let dbSaltQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: "ladon_device_db_salt",
            kSecAttrService as String: "app.ladon.messenger"
        ]
        SecItemDelete(dbSaltQuery as CFDictionary)
        
        // FIX AUDIT-R14-F8: Close DB connection after wipe — SQLCipher session key lingers in RAM
        // destroyAll() is only called during panic wipe; process terminates immediately after.
        dbQueue.sync {
            if let dbPtr = db {
                // FIX R16-EDB3: sqlite3_close_v2 ensures close even with pending stmts
                sqlite3_close_v2(dbPtr)
                db = nil
            }
        }
    }
    
    // MARK: - Helpers
    
    /// FIX AUD6-01: SQLCipher cipher PRAGMAs — must be called after sqlite3_key()
    /// but BEFORE any query (including verification queries).
    /// Pinning these values ensures the database can be opened even if SQLCipher
    /// changes its defaults in a future version.
    /// FIX AUDIT-R9-04: Check cipher PRAGMA return values — silent failures weaken encryption
    private func applyCipherPragmas() {
        if !exec("PRAGMA cipher_memory_security = ON") {
            SecureLogger.error("[EncryptedDB] ⛔ PRAGMA cipher_memory_security=ON failed — key material may linger in heap")
        }
        // FIX HIGH-5: Pin KDF iterations explicitly to prevent downgrades.
        // SQLCipher 4.x default is 256000, but pinning ensures consistency
        // across versions and prevents silent security reduction on upgrade.
        if !exec("PRAGMA kdf_iter = 256000") {
            SecureLogger.error("[EncryptedDB] ⛔ PRAGMA kdf_iter=256000 failed — weaker KDF may be used")
        }
        // Pin cipher page size and HMAC algorithm for integrity
        if !exec("PRAGMA cipher_page_size = 4096") {
            SecureLogger.error("[EncryptedDB] PRAGMA cipher_page_size=4096 failed")
        }
        if !exec("PRAGMA cipher_hmac_algorithm = HMAC_SHA512") {
            SecureLogger.error("[EncryptedDB] PRAGMA cipher_hmac_algorithm failed")
        }
        if !exec("PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA512") {
            SecureLogger.error("[EncryptedDB] PRAGMA cipher_kdf_algorithm failed")
        }
        // FIX H-08: Explicitly pin the encryption algorithm to AES-256-CBC.
        // Without this, a future SQLCipher version could change the default cipher,
        // making existing databases unreadable or reducing security.
        if !exec("PRAGMA cipher = 'aes-256-cbc'") {
            // Note: cipher PRAGMA may not be supported on all SQLCipher builds.
            // If it fails, AES-256-CBC is still the default for SQLCipher 4.x.
            SecureLogger.error("[EncryptedDB] PRAGMA cipher=aes-256-cbc failed (may be default)")
        }
    }
    
    // FIX C-15 + MED-10: exec() checks return code and logs errors (including Release)
    @discardableResult
    private func exec(_ sql: String) -> Bool {
        var errorMessage: UnsafeMutablePointer<CChar>?
        let result = sqlite3_exec(db, sql, nil, nil, &errorMessage)
        if result != SQLITE_OK {
            let msg = errorMessage.map { String(cString: $0) } ?? "unknown"
            sqlite3_free(errorMessage)
            // FIX MED-10: Log errors in Release too (privacy-safe: truncate SQL)
            SecureLogger.error("SQLite exec failed (\(result)): \(msg)")
            return false
        }
        return true
    }
    
    /// FIX SM-L4: Check if a column exists before ALTER TABLE ADD COLUMN.
    /// Prevents duplicate-column SQLite errors on every launch after initial migration.
    /// FIX TOR-C03 (DB-01): Validate table name against whitelist to prevent SQL injection.
    /// FIX H-7: Added verification_status and secure_kv tables for migrations.
    private static let allowedTableNames: Set<String> = [
        "conversations", "contacts", "messages", "key_bundles", "settings",
        "seen_nonces", "cover_seq", "receipts", "verification_status", "secure_kv"
    ]
    
    /// Safe regex for column name validation — hardcoded pattern always succeeds
    private static let allowedColumnPattern: NSRegularExpression? = {
        try? NSRegularExpression(pattern: "^[a-zA-Z_][a-zA-Z0-9_]*$")
    }()
    
    private func columnExists(table: String, column: String) -> Bool {
        // FIX DB-01: Whitelist validation for table/column names
        guard Self.allowedTableNames.contains(table) else {
            SecureLogger.error("[EncryptedDB] ⛔ columnExists: Unknown table '\(table)' — rejected")
            return false
        }
        guard let columnPattern = Self.allowedColumnPattern,
              columnPattern.firstMatch(in: column, range: NSRange(column.startIndex..., in: column)) != nil else {
            SecureLogger.error("[EncryptedDB] ⛔ columnExists: Invalid column name — rejected")
            return false
        }
        var stmt: OpaquePointer?
        let sql = "PRAGMA table_info(\(table))"
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return false }
        defer { sqlite3_finalize(stmt) }
        while sqlite3_step(stmt) == SQLITE_ROW {
            if let cName = sqlite3_column_text(stmt, 1) {
                let name = String(cString: cName)
                if name == column { return true }
            }
        }
        return false
    }
    
    /// FIX SM-L4: Safe migration helper — only adds column if it doesn't already exist.
    /// FIX DB-01: Validates table/column/type against whitelist patterns.
    /// FIX H-8: Type regex now allows digits and common SQL keywords.
    /// Previously ^[A-Z ]+$ rejected "INTEGER NOT NULL DEFAULT 30" (has a digit).
    private static let allowedTypePattern: NSRegularExpression? = {
        try? NSRegularExpression(pattern: "^[A-Z0-9 ()_]+$", options: .caseInsensitive)
    }()
    
    private func addColumnIfMissing(table: String, column: String, type: String) {
        // FIX DB-01: Validate all interpolated values
        guard Self.allowedTableNames.contains(table) else {
            SecureLogger.error("[EncryptedDB] ⛔ addColumnIfMissing: Unknown table — rejected")
            return
        }
        guard let columnPattern = Self.allowedColumnPattern,
              columnPattern.firstMatch(in: column, range: NSRange(column.startIndex..., in: column)) != nil else {
            SecureLogger.error("[EncryptedDB] ⛔ addColumnIfMissing: Invalid column name — rejected")
            return
        }
        guard let typePattern = Self.allowedTypePattern,
              typePattern.firstMatch(in: type, range: NSRange(type.startIndex..., in: type)) != nil else {
            SecureLogger.error("[EncryptedDB] ⛔ addColumnIfMissing: Invalid type — rejected")
            return
        }
        if !columnExists(table: table, column: column) {
            // FIX AUDIT-R9-08: Check ALTER TABLE return — silent failure means column is missing
            if !exec("ALTER TABLE \(table) ADD COLUMN \(column) \(type)") {
                SecureLogger.error("[EncryptedDB] ⛔ ALTER TABLE \(table) ADD COLUMN \(column) failed")
            }
        }
    }
    
    /// FIX MED: Periodic WAL checkpoint to prevent unbounded WAL growth.
    /// Called after write operations. When write count exceeds threshold,
    /// performs TRUNCATE checkpoint to reset WAL file.
    /// Must be called from dbQueue.
    private func incrementWALCounter() {
        _walWriteCount += 1
        if _walWriteCount >= walCheckpointInterval {
            _walWriteCount = 0
            // FIX AUDIT-R10-P1: Check exec() return — unbounded WAL growth if checkpoint fails
            if !exec("PRAGMA wal_checkpoint(TRUNCATE)") {
                #if DEBUG
                print("[EncryptedDB] ⚠️ WAL checkpoint failed")
                #endif
            } else {
                #if DEBUG
                print("[EncryptedDB] ✅ WAL checkpoint performed")
                #endif
            }
        }
    }
}

enum DatabaseError: Error {
    case openFailed
    case queryFailed
    case keyGenerationFailed
    case encryptionFailed
    case decryptionFailed
    case encodingFailed
    case prepareFailed      // FIX DB-5: sqlite3_prepare_v2 failed
    case deleteFailed       // FIX DB-4: sqlite3_step on DELETE returned error
    case transactionFailed  // FIX AUDIT-R7-05: BEGIN TRANSACTION failed
    case commitFailed       // FIX AUDIT-R7-05: COMMIT failed
}
