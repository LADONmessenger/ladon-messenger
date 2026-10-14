import Foundation
import UIKit
import UserNotifications
import Security
import CryptoKit

/// Silent Push Notification Handler
/// Wakes app in background to fetch new messages WITHOUT revealing content
/// FIX MED-61: Marked @MainActor to prevent race conditions on mutable state
/// (pushToken, lastTokenKey etc. accessed from main thread and background push callbacks)
/// FIX C-05 (ADVERSARIAL): Supports polling-only mode — disables APNs entirely
/// to prevent Apple from learning app installation, message timing, and device token
@MainActor
class SilentPushHandler {
    
    static let shared = SilentPushHandler()
    
    /// FIX C-05 (ADVERSARIAL): User-configurable polling-only mode key.
    /// When enabled, APNs is not registered and no push token is sent to server.
    /// The app relies exclusively on foreground polling for message delivery.
    /// Trade-off: No background message delivery, but Apple learns nothing.
    static let pollingOnlyModeKey = "ladon.privacy.pollingOnlyMode"

    /// Legacy Phase 4b rollout flag key. Kept only so existing encrypted user
    /// defaults can be ignored safely after the v1 push cutover.
    static let v2PushEnabledKey = "ladon.push.v2_1Enabled"

    /// Check if v2.1 additive push registration is enabled.
    ///
    /// FIX 2026-05-14 (push-cutover): the V1 server (`entry.ladon.app`) is
    /// decommissioned and the V1 RelayClient was removed entirely (2026-05-23).
    /// The v1 `uploadPushToken` path is therefore a permanent no-op. v2.1 is
    /// the only working push-registration path and must not be disabled by a
    /// stale DEBUG rollout flag stored on older test devices.
    static var isV2PushEnabled: Bool {
        return true
    }
    
    /// Check if polling-only mode is active
    /// FIX M-28: Read from SecureUserDefaults (encrypted) instead of plain UserDefaults
    static var isPollingOnlyMode: Bool {
        return SecureUserDefaults.shared.bool(forKey: pollingOnlyModeKey)
    }
    
    private var pushToken: Data?
    private let lastTokenKey = "push_last_token"
    private let lastUploadStatusKey = "push_last_upload_status"
    private let lastUploadDateKey = "push_last_upload_date"
    
    // FIX M-07: Rate-limit silent push processing
    /// FIX LO-04: No explicit lock needed — iOS serializes all push callbacks through
    /// the main AppDelegate thread, ensuring single-threaded access to this property.
    /// This is documented in Apple's WWDC 2022 presentation on push notification handling.
    private var lastSilentPushTime: Date?
    
    private init() {
        // FIX M-60: Zero push token from memory when app enters background.
        // Prevents token extraction via memory forensics on a seized device.
        NotificationCenter.default.addObserver(
            forName: UIApplication.didEnterBackgroundNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor in
                self?.pushToken = nil
            }
        }
    }
    
    // MARK: - APNs Registration
    
    /// Register for silent push notifications
    /// FIX C-05 (ADVERSARIAL): Respects polling-only mode — skips APNs if enabled
    func registerForSilentPush() {
        #if DEBUG
        NSLog("[Push] registerForSilentPush() called")
        #endif
        // FIX C-05: If polling-only mode is active, do NOT register with APNs.
        // This prevents Apple from learning that this device has Ladon installed,
        // and eliminates the 1:1 push-to-message timing correlation.
        guard !SilentPushHandler.isPollingOnlyMode else {
            #if DEBUG
            NSLog("[Push] BLOCKED by pollingOnlyMode!")
            #endif
            return
        }
        
        #if !targetEnvironment(simulator)
        let center = UNUserNotificationCenter.current()
        
        // Request authorization for visible notifications
        center.requestAuthorization(options: [.alert, .badge, .sound]) { granted, error in
            #if DEBUG
            NSLog("[Push] requestAuthorization result: granted=%d error=%@", granted ? 1 : 0, error?.localizedDescription ?? "none")
            #endif
            if granted {
                DispatchQueue.main.async {
                    #if DEBUG
                    NSLog("[Push] Calling registerForRemoteNotifications()")
                    #endif
                    UIApplication.shared.registerForRemoteNotifications()
                }
            }
        }
        #else
        #if DEBUG
        NSLog("[Push] Simulator — skipping APNs")
        #endif
        #endif
    }
    
    /// Store APNs device token
    func didRegisterForRemoteNotifications(withDeviceToken token: Data) {
        self.pushToken = token
        
        let tokenString = token.map { String(format: "%02.2hhx", $0) }.joined()
        #if DEBUG
        NSLog("[Push] didRegisterForRemoteNotifications — token prefix=%@, length=%d", String(tokenString.prefix(8)), token.count)
        #endif
        // M9 FIX: Store push token in Keychain instead of plaintext UserDefaults
        let tokenData = tokenString.data(using: .utf8) ?? Data()
        // FIX BUGHUNT-3: Atomic update-first pattern (no delete→add gap).
        // Previously used SecItemDelete→SecItemAdd which has a brief window where
        // the token is absent. SecItemUpdate keeps the item present at all times.
        let updateQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: lastTokenKey,
            kSecAttrService as String: "app.ladon.messenger"
        ]
        let updateAttrs: [String: Any] = [
            kSecValueData as String: tokenData
        ]
        let updateStatus = SecItemUpdate(updateQuery as CFDictionary, updateAttrs as CFDictionary)
        if updateStatus == errSecItemNotFound {
            let addQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrAccount as String: lastTokenKey,
                kSecAttrService as String: "app.ladon.messenger",
                kSecValueData as String: tokenData,
                kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            ]
            let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
            if addStatus != errSecSuccess {
                SecureLogger.error("[Push] Keychain write failed for push token: \(addStatus)")
            }
        } else if updateStatus != errSecSuccess {
            SecureLogger.error("[Push] Keychain update failed for push token: \(updateStatus)")
        }
        
        // FIX M-06: Store HMAC of push token alongside it for integrity verification.
        // Without HMAC, an attacker with device access could swap the token to redirect pushes.
        // FIX BUGHUNT-3: Atomic update-first pattern for HMAC too
        if let hmacKey = getPushTokenHMACKey() {
            let hmac = HMAC<SHA256>.authenticationCode(for: tokenData, using: hmacKey)
            let hmacData = Data(hmac)
            let hmacUpdateQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrAccount as String: "\(lastTokenKey)_hmac",
                kSecAttrService as String: "app.ladon.messenger"
            ]
            let hmacUpdateAttrs: [String: Any] = [
                kSecValueData as String: hmacData
            ]
            let hmacStatus = SecItemUpdate(hmacUpdateQuery as CFDictionary, hmacUpdateAttrs as CFDictionary)
            if hmacStatus == errSecItemNotFound {
                let hmacAddQuery: [String: Any] = [
                    kSecClass as String: kSecClassGenericPassword,
                    kSecAttrAccount as String: "\(lastTokenKey)_hmac",
                    kSecAttrService as String: "app.ladon.messenger",
                    kSecValueData as String: hmacData,
                    kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
                ]
                SecItemAdd(hmacAddQuery as CFDictionary, nil)
            }
        }
        try? SecureUserDefaults.shared.set(Int(Date().timeIntervalSince1970), forKey: lastUploadDateKey)
        try? SecureUserDefaults.shared.set("token received", forKey: lastUploadStatusKey)
        
        // Upload token to relay server
        Task {
            await uploadPushToken(token)
        }
        // Phase 4b (v2.1): Additive registration via Entry-Relay proxy.
        // Gated by isV2PushEnabled (default OFF). NEVER replaces v1 above.
        Task {
            await uploadPushTokenV2(token)
        }
    }
    
    /// Handle registration failure
    func didFailToRegisterForRemoteNotifications(withError error: Error) {
        #if DEBUG
        NSLog("[Push] FAILED to register for remote notifications: %@", error.localizedDescription)
        #endif
    }
    
    // MARK: - Push Token Integrity
    
    /// FIX M-06: Get or create HMAC key for push token integrity verification
    private func getPushTokenHMACKey() -> SymmetricKey? {
        let account = "ladon_push_token_hmac_key"
        let service = "app.ladon.messenger"
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecAttrService as String: service,
            kSecReturnData as String: true
        ]
        var result: AnyObject?
        if SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
           var keyData = result as? Data, keyData.count == 32 {
            // FIX AUDIT2-04: Wipe Keychain-returned key material from heap after use.
            // SymmetricKey copies the bytes internally; the Data buffer must not linger.
            defer { keyData.securelyWipe() }
            return SymmetricKey(data: keyData)
        }
        // Create new key
        var keyData = Data(count: 32)
        let status = keyData.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        guard status == errSecSuccess else { return nil }
        // FIX AUDIT3-IOS-11: Race-safe create.
        // Previous code called SecItemAdd unconditionally and ignored its status.
        // If two concurrent callers raced on the first-time create path, the loser
        // received errSecDuplicateItem, but proceeded to MAC the push token with its
        // locally-generated key. The next read would return the *stored* (winner's)
        // key, causing HMAC verification to fail and the token to be rejected as
        // tampered — triggering a spurious re-registration with the server.
        // Fix: on errSecDuplicateItem, re-read the existing key from Keychain.
        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecAttrService as String: service,
            kSecValueData as String: keyData,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
        // FIX AUDIT2-04: Wipe generated key material from heap after Keychain storage + SymmetricKey creation
        defer { keyData.securelyWipe() }
        if addStatus == errSecDuplicateItem {
            // Concurrent caller won the race — re-read its key from Keychain.
            var existing: AnyObject?
            if SecItemCopyMatching(query as CFDictionary, &existing) == errSecSuccess,
               var existingData = existing as? Data, existingData.count == 32 {
                defer { existingData.securelyWipe() }
                return SymmetricKey(data: existingData)
            }
            SecureLogger.error("[Push] HMAC key duplicate but re-read failed")
            return nil
        }
        if addStatus != errSecSuccess {
            SecureLogger.error("[Push] HMAC key Keychain add failed: \(addStatus)")
            return nil
        }
        return SymmetricKey(data: keyData)
    }
    
    // MARK: - Server Communication
    
    /// Upload push token to relay server
    ///
    /// FIX 2026-05-14 (push-cutover): the V1 entry-relay (`entry.ladon.app`) is
    /// decommissioned and the V1 RelayClient was removed entirely (2026-05-23).
    /// This method would POST to a black-hole hostname, blocking until DNS
    /// timeout and logging spurious failures on every launch. Push registration
    /// is now handled exclusively by `uploadPushTokenV2` (v2.1 proxy via
    /// entry-relay-v2). Return immediately.
    private func uploadPushToken(_ token: Data) async {
        // V1 path retired; v2.1 is the only registration path. See uploadPushTokenV2.
        // (Argument `_ token` kept for API compatibility with existing callers.)
        _ = token
    }
    
    // MARK: - Background Fetch
    
    /// Handle incoming silent push
    func handleSilentPush(_ userInfo: [AnyHashable: Any], completion: @escaping (UIBackgroundFetchResult) -> Void) {
        // FIX M-07: Rate-limit silent push handling to prevent push-flood attacks.
        // An attacker controlling the push server could flood the device with pushes
        // to drain battery or trigger excessive network requests.
        let now = Date()
        if let lastPush = lastSilentPushTime, now.timeIntervalSince(lastPush) < 5.0 {
            #if DEBUG
            print("[Push] ⏸️ Rate limited — ignoring push (< 5s since last)")
            #endif
            completion(.noData)
            return
        }
        lastSilentPushTime = now
        
        #if DEBUG
        print("[Push] 🔔 Silent push received — fetching messages")
        #endif
        
        // Handle both silent pushes (content-available only) and alert pushes
        // FIX PUSH-03: Accept alert pushes too — server now sends alert+content-available
        guard let aps = userInfo["aps"] as? [String: Any] else {
            completion(.noData)
            return
        }
        // Accept if content-available:1 OR if there's an alert (server sends both)
        let contentAvailable = aps["content-available"] as? Int ?? 0
        let hasAlert = aps["alert"] != nil
        guard contentAvailable == 1 || hasAlert else {
            completion(.noData)
            return
        }
        
        // Fetch messages from relay server in background
        let wokeAt = Date()
        Task {
            // A push wakes a suspended app whose Tor listeners may be dead.
            // Give the recovery coordinator up to 10 s first (local probes and
            // in-process control commands only); the fetch itself stays
            // Tor-only and fails closed if Tor is still not usable.
            let torUsable = await TorController.shared.waitUntilUsable(timeoutSeconds: 10)
            SecureLogger.torDiag("[PUSH] wake: Tor usable=\(torUsable) before fetch")
            let (messages, controlMessages) = await V2SessionManager.shared.fetchForWake()
            #if DEBUG
            print("[Push] 📥 V2 fetched \(messages.count) messages")
            #endif
            // Woken in the background: park Tor again before iOS suspends the
            // app (TorController.prepareForBackground). In the foreground the
            // app keeps its connection.
            let inBackground = await MainActor.run { UIApplication.shared.applicationState == .background }
            if inBackground {
                await TorController.shared.prepareForBackground()
            }
            // #1: fetchPendingMessages() now delivers centrally (store write +
            // NewMessagesReceived) and coalesces with the V2 receive loop. The
            // push handler only decides the completion result and the
            // background-fallback notification — no local store/post here (that
            // would double-deliver the batch).
            guard !messages.isEmpty else {
                // A2 §7: without a per-envelope push bit, a control message
                // (pairing START, KEY) to an offline device triggers a push
                // too, and iOS has already shown its banner. Remove it when
                // this wake handled a control message and nothing to show —
                // never on a failed fetch, which says nothing about why the
                // push came.
                if hasAlert && controlMessages > 0 {
                    await Self.removeBanners(deliveredSince: wokeAt.addingTimeInterval(-10))
                }
                completion(.noData)
                return
            }

            // FIX PUSH-FALLBACK: Schedule local notification ONLY when the app
            // is in true background AND the waking push carried no alert of its
            // own. The server sends alert + content-available, and iOS has
            // already shown that alert — a second, local one here doubled every
            // notification (seen 01.10.2026). The fallback stays for a push
            // without alert. Avoid .inactive to prevent firing while the app is
            // being opened (app state transition).
            await MainActor.run {
                if UIApplication.shared.applicationState == .background && !hasAlert {
                    self.scheduleLocalNotification(count: messages.filter { !$0.isOutgoing }.count)
                }
            }
            completion(.newData)
        }
    }
    
    /// Remove the remote-push banners iOS delivered since `date` (best
    /// effort, A2 §7). All our banners carry the same generic text, so only
    /// the time tells them apart; older ones stay.
    private static func removeBanners(deliveredSince date: Date) async {
        let center = UNUserNotificationCenter.current()
        let ids = await center.deliveredNotifications()
            .filter { $0.date >= date && $0.request.trigger is UNPushNotificationTrigger }
            .map(\.request.identifier)
        guard !ids.isEmpty else { return }
        center.removeDeliveredNotifications(withIdentifiers: ids)
        SecureLogger.torDiag("[PUSH] wake brought only control messages — \(ids.count) banner(s) removed")
    }

    /// Privacy-safe local notification — generic content, no message details
    private func scheduleLocalNotification(count: Int = 1) {
        let content = UNMutableNotificationContent()
        // FIX A13-10: constant body, no title — no app name, no count. Same key
        // as the server's alert push (loc-key), localised on the device.
        content.body = NSString.localizedUserNotificationString(forKey: "PUSH_NEW_ENCRYPTED_MESSAGE", arguments: nil)
        content.sound = .default
        // FIX BADGE-01: Set badge to total unread count across all conversations
        Task { @MainActor in
            let total = InMemoryMessageStore.shared.totalUnreadCount
            if total > 0 {
                try? await UNUserNotificationCenter.current().setBadgeCount(total)
            }
        }
        // FIX SVC-9: Use neutral threadIdentifier — "ladon-messages" leaks app identity in notification DB
        content.threadIdentifier = "m"

        // FIX NOTIF-01: Unique identifier per notification so each message creates its own banner.
        // Previously used fixed "ladon-new-message" which caused iOS to REPLACE the existing
        // notification instead of adding a new one.
        // FIX AUDIT-MAR-2026-4: Neutral identifier — "ladon-msg-" leaks app identity in notification DB
        let request = UNNotificationRequest(
            identifier: "m-\(UUID().uuidString)",
            content: content,
            trigger: nil
        )

        UNUserNotificationCenter.current().add(request) { error in
            if let error = error {
                #if DEBUG
                print("[Push] ❌ Failed to schedule notification: \(error)")
                #endif
            }
        }
    }

    // MARK: - UI Helpers

    /// Trigger a local notification (for testing only)
    func sendTestNotification() {
        scheduleLocalNotification()
    }

    /// Retry token upload or re-register if no token yet
    /// On every foreground: ensure server has our push token (tokens are lost on server restart)
    func retryPushRegistration() {
        #if DEBUG
        NSLog("[Push] retryPushRegistration() called — pushToken=%@", pushToken != nil ? "SET(\(pushToken!.count)bytes)" : "NIL")
        #endif
        if let token = pushToken {
            // In-memory token available — re-upload immediately
            #if DEBUG
            NSLog("[Push] retryPush PATH 1: in-memory token — uploading")
            #endif
            Task { await uploadPushToken(token) }
            // Phase 4b (v2.1): mirror in the retry path.
            Task { await uploadPushTokenV2(token) }
        } else if let tokenString = lastTokenString(),
                  let tokenData = tokenStringToData(tokenString) {
            // FIX PUSH-KEYCHAIN-FALLBACK: In-memory token was nil (cleared on background).
            // Load from Keychain (persisted in didRegisterForRemoteNotifications) and re-upload.
            // This fixes the race where retryPushRegistration runs before iOS delivers the
            // cached APNs token via the delegate callback.
            #if DEBUG
            NSLog("[Push] retryPush PATH 2: Keychain token found (len=%d) — uploading + re-registering", tokenData.count)
            #endif
            self.pushToken = tokenData
            Task { await uploadPushToken(tokenData) }
            // Phase 4b (v2.1): mirror in the Keychain-fallback path.
            Task { await uploadPushTokenV2(tokenData) }
            // Also trigger re-registration for token refresh
            registerForSilentPush()
        } else {
            // No token anywhere — force re-registration. iOS returns cached token quickly.
            #if DEBUG
            NSLog("[Push] retryPush PATH 3: no token — calling registerForSilentPush()")
            #endif
            registerForSilentPush()
        }
    }
    
    /// Convert hex token string back to Data
    private func tokenStringToData(_ hex: String) -> Data? {
        var data = Data()
        var index = hex.startIndex
        while index < hex.endIndex {
            guard let nextIndex = hex.index(index, offsetBy: 2, limitedBy: hex.endIndex) else { return nil }
            guard let byte = UInt8(hex[index..<nextIndex], radix: 16) else { return nil }
            data.append(byte)
            index = nextIndex
        }
        return data.isEmpty ? nil : data
    }

    func lastTokenString() -> String? {
        // FIX AUDIT-R7-02: kSecAttrService added — must match write query (L116)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: lastTokenKey,
            kSecAttrService as String: "app.ladon.messenger",
            kSecReturnData as String: true,
            kSecAttrSynchronizable as String: false
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data else { return nil }
        
        // FIX M-03: Verify HMAC integrity before returning token.
        // Without verification, an attacker with device access could swap the stored
        // token to redirect push notifications to a different device.
        if let hmacKey = getPushTokenHMACKey() {
            let hmacQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrAccount as String: "\(lastTokenKey)_hmac",
                kSecAttrService as String: "app.ladon.messenger",
                kSecReturnData as String: true,
                kSecAttrSynchronizable as String: false
            ]
            var hmacResult: CFTypeRef?
            if SecItemCopyMatching(hmacQuery as CFDictionary, &hmacResult) == errSecSuccess,
               let storedHMAC = hmacResult as? Data {
                // Verify HMAC matches stored token
                if !HMAC<SHA256>.isValidAuthenticationCode(storedHMAC, authenticating: data, using: hmacKey) {
                    SecureLogger.error("[Push] Token HMAC verification failed — rejecting stored token")
                    return nil
                }
            }
            // No HMAC stored (legacy token before M-06 fix) — accept but will be re-HMACed on next save
        }
        
        return String(data: data, encoding: .utf8)
    }

    func lastUploadStatus() -> String? {
        try? SecureUserDefaults.shared.string(forKey: lastUploadStatusKey)
    }

    func lastUploadDate() -> Date? {
        guard let ts = try? SecureUserDefaults.shared.integer(forKey: lastUploadDateKey),
              ts > 0 else { return nil }
        return Date(timeIntervalSince1970: TimeInterval(ts))
    }

    func currentAPNsEnvironment() -> String {
        isSandboxAPNs() ? "development" : "production"
    }

    // MARK: - Phase 4b: v2.1 Push Registration (additive to v1)

    /// Register the APNs device token with the push relay: a sealed
    /// PUSH_REGISTER in lane F (Addendum A2 §4.4) — neither the entry nor an
    /// exit sees the token.
    ///
    /// Failure modes are logged but never thrown to the caller: a v2.1 failure
    /// must never break the v1 path that this method runs in parallel with.
    private func uploadPushTokenV2(_ token: Data) async {
        let sandbox = isSandboxAPNs()
        #if DEBUG
        NSLog("[Push] v2.1 register START (sandbox=%@, len=%d)", sandbox ? "true" : "false", token.count)
        #endif
        do {
            try await V2SessionManager.shared.registerPushTokenV2(token, sandbox: sandbox)
            #if DEBUG
            NSLog("[Push] v2.1 register OK (sandbox=%@, len=%d)", sandbox ? "true" : "false", token.count)
            #endif
        } catch V2SessionManager.PushRegistrationV2Error.notInitialized {
            #if DEBUG
            NSLog("[Push] v2.1 register skipped — V2SessionManager not initialized yet")
            #endif
        } catch V2SessionManager.PushRegistrationV2Error.noExitsConfigured {
            SecureLogger.error("[Push] v2.1 register failed — no v2 exits configured")
            #if DEBUG
            NSLog("[Push] v2.1 register failed — no v2 exits configured")
            #endif
        } catch PushRegistrationClientV2Error.entryHasNoPushRelay {
            // The bootstrap file names no push relay target (A2 §4.4):
            // registration is impossible; fail closed.
            SecureLogger.error("[Push] register: no push relay target in the bootstrap file")
        } catch let PushRegistrationClientV2Error.pushRelayRejected(status) {
            SecureLogger.error("[Push] v2.1 register: push-relay rejected status=\(status)")
            #if DEBUG
            NSLog("[Push] v2.1 register: push-relay rejected status=%d", status)
            #endif
        } catch let PushRegistrationClientV2Error.entryHttp(status) {
            SecureLogger.error("[Push] v2.1 register: entry HTTP \(status)")
            #if DEBUG
            NSLog("[Push] v2.1 register: entry HTTP %d", status)
            #endif
        } catch {
            SecureLogger.error("[Push] v2.1 register failed: \(error)")
            #if DEBUG
            NSLog("[Push] v2.1 register failed: %@", String(describing: error))
            #endif
        }
    }

    // MARK: - Environment

    private func isSandboxAPNs() -> Bool {
        // P8-PUSH-ENV-02 (2026-05-20): build-config-driven detection.
        //
        // Until this fix, `Ladon.entitlements` hardcoded `aps-environment =
        // production` for every config; a Debug build signed with an Apple
        // Development cert (provisioning-profile says "development") thus
        // landed in a hybrid state — Apple's APNs registered the device in
        // the SANDBOX env while the entitlement claimed production, and the
        // mobileprovision-string-grep heuristic this method used previously
        // would mis-classify it. Push-relay sent every notification to
        // `api.push.apple.com` (production) → APNs replied `BadDeviceToken`,
        // every push silently dropped.
        //
        // The proper Apple fix is per-config entitlement files:
        //   * Debug build   → `Ladon.Debug.entitlements`, aps-environment = development
        //   * Release build → `Ladon.entitlements`,       aps-environment = production
        //
        // With that wired (CODE_SIGN_ENTITLEMENTS is per-config in pbxproj),
        // the cert family and the entitlement value are forced to match,
        // so this method just needs to mirror the build config. The Debug
        // config defines `DEBUG=1` in `GCC_PREPROCESSOR_DEFINITIONS`, which
        // Swift surfaces as `#if DEBUG`.
        //
        // Edge case (Debug-built binary signed with a Distribution cert —
        // e.g. someone manually re-signing): caller would need to override
        // entitlements explicitly AND rebuild without DEBUG to keep token-
        // env and APNs-target aligned. We do NOT try to catch that here —
        // runtime profile-introspection is fragile (CMS blob ASCII-decode,
        // false-positive on unrelated `<string>development</string>` matches)
        // and the entitlement is now the single source of truth at build time.
        #if DEBUG
        return true
        #else
        return false
        #endif
    }
}

// MARK: - AppDelegate Integration

extension SilentPushHandler {
    
    /// Call this from AppDelegate.application(_:didFinishLaunchingWithOptions:)
    static func setupInAppDelegate() {
        #if DEBUG
        NSLog("[Push] setupInAppDelegate() called — triggering registerForSilentPush")
        #endif
        SilentPushHandler.shared.registerForSilentPush()
    }
    
    /// Call from AppDelegate.application(_:didRegisterForRemoteNotificationsWithDeviceToken:)
    static func handleTokenRegistration(_ token: Data) {
        SilentPushHandler.shared.didRegisterForRemoteNotifications(withDeviceToken: token)
    }
    
    /// Call from AppDelegate.application(_:didFailToRegisterForRemoteNotificationsWithError:)
    static func handleRegistrationFailure(_ error: Error) {
        SilentPushHandler.shared.didFailToRegisterForRemoteNotifications(withError: error)
    }
    
    /// Call from AppDelegate.application(_:didReceiveRemoteNotification:fetchCompletionHandler:)
    static func handleIncomingPush(_ userInfo: [AnyHashable: Any], completion: @escaping (UIBackgroundFetchResult) -> Void) {
        SilentPushHandler.shared.handleSilentPush(userInfo, completion: completion)
    }
}

// MARK: - Server-Side APNs Payload

struct APNsPayloadExample {
    static let silentPushPayload = """
    {
      "aps": {
        "content-available": 1
      }
    }
    
    NO "alert", "badge", or "sound" fields!
    
    This wakes app in background WITHOUT:
    ❌ Showing notification
    ❌ Revealing message content
    ❌ Making sound
    ❌ Updating badge
    
    User only sees messages when they OPEN the app.
    
    Server sends this when:
    ✅ New message arrives for user
    ✅ App has push token registered
    ✅ User's device is online
    
    Benefits:
    ✅ Near-instant delivery (15-30 seconds)
    ✅ Zero metadata leakage
    ✅ Battery efficient
    ✅ Works even when app closed
    """
}

// MARK: - Privacy Guarantees

struct SilentPushPrivacy {
    static let guarantees = """
    🔒 Privacy Guarantees:
    
    What APNs LEARNS:
    - Your device has app.ladon.messenger installed
    - A message notification was sent (timestamp)
    - Device token (random identifier)
    
    What APNs NEVER LEARNS:
    ✅ Message content (not in push payload)
    ✅ Sender identity (not in push payload)
    ✅ Recipient identity (token is pseudonymous)
    ✅ Message metadata (encrypted envelope)
    
    Apple's Promises:
    - Push tokens rotated periodically
    - Notifications encrypted in transit (TLS 1.3)
    - No long-term storage of push content
    - Cannot decrypt message envelopes
    
    Alternative (No APNs):
    - Background fetch every 15-30 minutes
    - Higher battery usage
    - Slower delivery (up to 30 min delay)
    - No dependency on Apple infrastructure
    """
}
