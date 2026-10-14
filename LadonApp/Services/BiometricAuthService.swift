import Foundation
import LocalAuthentication
import SwiftUI
import CryptoKit
import LadonArgon2

extension Notification.Name {
    static let biometricAuthSuccess = Notification.Name("BiometricAuthSuccess")
}

/// Biometric authentication service for FaceID/TouchID
@MainActor
class BiometricAuthService: ObservableObject {
    @Published var isAuthenticated = false
    @Published var isLocked = true
    @Published var authError: String?
    @Published var isAuthenticating = false
    /// P7-IOS-BUG-16: previously the backoff `Task { sleep + reset }` was
    /// spawned anonymously and never cancellable. If the user then
    /// successfully authenticated through a different path before the
    /// sleep elapsed, the stale task would fire later and clobber the
    /// fresh `isAuthenticating` state. Keeping a handle lets us cancel
    /// it on success.
    private var backoffTask: Task<Void, Never>?
    @Published var faceIDFailureCount: Int = 0  // Bio-Failsafe tracking (H5: now persisted)

    // MARK: LADON PIN gate (scan finding F15, 13.10.2026)
    //
    // Face ID alone accepted any face enrolled later — whoever knew the
    // device passcode could add their own face and open the app. After every
    // successful Face ID check the enrolled-biometry state is compared with
    // the one stored at the last unlock; on a change the LADON PIN is
    // required before the app opens. The PIN is mandatory: Apple notes the
    // state value can also change across major iOS updates
    // (LADomainState.h), so a missing PIN must never mean "wipe".
    enum PinStage: Equatable { case none, setup, verify }
    @Published var pinStage: PinStage = .none
    @Published var pinError: String?
    @Published var isCheckingPin = false
    /// Face ID succeeded but the PIN step is still open. The authenticated
    /// context is held back from KeyManager until the PIN step completes.
    private var pendingContext: LAContext?
    private var pendingStateHash: Data?
    static let pinPanicThreshold = 10
    
    // FIX M-61: Removed stale class-level LAContext — each operation creates a fresh one
    // to ensure biometry type and availability reflect the current device state.
    private var lastBackgroundTime: Date?
    private var lastAuthPromptTime: Date?
    private let authTimeoutSeconds: TimeInterval = 10  // Short grace to avoid repeated prompts
    private let minPromptInterval: TimeInterval = 8
    private let bioFailsafeWarningThreshold = 5   // K5 FIX: Raised from 3 — trigger warning at 5
    private let bioFailsafePanicThreshold = 10    // K5 FIX: Raised from 5 — trigger panic at 10
    private static let failureCountKeychainKey = "app.ladon.messenger.faceIDFailureCount"
    
    init() {
        // H5 FIX: Load persisted failure count from Keychain (survives app kill)
        self.faceIDFailureCount = BiometricAuthService.loadFailureCount()
        
        // FIX M-61: Create a fresh LAContext for init-time check (not retained)
        let initContext = LAContext()
        var error: NSError?
        if initContext.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
            #if DEBUG
            print("[BiometricAuth] Biometrics available: \(biometricType)")
            #endif
        } else {
            #if DEBUG
            print("[BiometricAuth] Biometrics not available: \(error?.localizedDescription ?? "Unknown")")
            #endif
        }
    }
    
    // MARK: - H5 FIX: Persistent Failure Count (Keychain-backed)
    
    private static func loadFailureCount() -> Int {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: failureCountKeychainKey,
            // FIX AUDIT-MAR-2026-25: Include kSecAttrService for emergency wipe scope
            kSecAttrService as String: "app.ladon.messenger",
            kSecReturnData as String: true,
            kSecAttrSynchronizable as String: false
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data, data.count == 4 else {
            return 0
        }
        // FIX A13-8: loadUnaligned statt load — Data-Buffer hat keine Alignment-Garantie
        return data.withUnsafeBytes { Int($0.loadUnaligned(fromByteOffset: 0, as: Int32.self)) }
    }
    
    private static func saveFailureCount(_ count: Int) {
        var value = Int32(count)
        let data = Data(bytes: &value, count: 4)
        // FIX A12-HIGH-1: kSecAttrAccessible removed from search query — prevents
        // accessibility mismatch that silently blocked SecItemUpdate, causing failure
        // counter to never persist. Attacker could reset brute-force counter via app kill.
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: failureCountKeychainKey,
            // FIX AUDIT-MAR-2026-25: Include kSecAttrService for emergency wipe scope
            kSecAttrService as String: "app.ladon.messenger",
            kSecAttrSynchronizable as String: false
        ]
        let update: [String: Any] = [kSecValueData as String: data]
        let updateStatus = SecItemUpdate(query as CFDictionary, update as CFDictionary)
        if updateStatus == errSecItemNotFound {
            var addQuery = query
            addQuery[kSecValueData as String] = data
            addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
            if addStatus != errSecSuccess {
                #if DEBUG
                print("[BiometricAuth] Keychain write failed for failureCount: \(addStatus)")
                #endif
            }
        // FIX A12-MED-4: Log unexpected SecItemUpdate failures instead of swallowing
        } else if updateStatus != errSecSuccess {
            #if DEBUG
            print("[BiometricAuth] Keychain update failed for failureCount: \(updateStatus)")
            #endif
        }
    }
    
    var biometricType: String {
        // FIX M-61: Fresh LAContext ensures biometryType reflects current device state
        let freshContext = LAContext()
        _ = freshContext.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        switch freshContext.biometryType {
        case .faceID:
            return "Face ID"
        case .touchID:
            return "Touch ID"
        case .opticID:
            return "Optic ID"
        case .none:
            return "Passcode"
        @unknown default:
            return "Biometric"
        }
    }
    
    var isBiometricsAvailable: Bool {
        // FIX M-61: Fresh LAContext ensures availability check is current
        LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
    }
    
    /// Authenticate user with biometrics or device passcode
    func authenticate() async {
        // Prevent multiple simultaneous authentication attempts
        guard !isAuthenticating else {
            #if DEBUG
            print("[BiometricAuth] Authentication already in progress, skipping")
            #endif
            return
        }

        if let lastPrompt = lastAuthPromptTime,
           Date().timeIntervalSince(lastPrompt) < minPromptInterval {
            #if DEBUG
            print("[BiometricAuth] Throttling auth prompt")
            #endif
            return
        }
        lastAuthPromptTime = Date()
        
        // FIX HIGH-03: Read persisted backoff timestamp from Keychain on entry.
        // Without this check, an attacker can bypass time-delay backoff by force-quitting
        // and relaunching the app between attempts.
        // FIX AUDIT-R7-01: kSecAttrService added — without it, item survives emergency wipe
        let backoffQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: "app.ladon.messenger.authBackoffUntil",
            kSecAttrService as String: "app.ladon.messenger",
            kSecReturnData as String: true,
            kSecAttrSynchronizable as String: false
        ]
        var backoffResult: AnyObject?
        if SecItemCopyMatching(backoffQuery as CFDictionary, &backoffResult) == errSecSuccess,
           let backoffData = backoffResult as? Data,
           backoffData.count == 8 {
            // FIX A13-8: loadUnaligned statt load — Data-Buffer hat keine Alignment-Garantie
            let storedBits = backoffData.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 0, as: UInt64.self) }.bigEndian
            let nextAllowed = Double(bitPattern: storedBits)
            let now = Date().timeIntervalSince1970
            if now < nextAllowed {
                // FIX SVC-4: Cap consistent with write cap (3600s) — 300s allowed bypass
                let waitSeconds = min(nextAllowed - now, 3600)
                #if DEBUG
                print("[BiometricAuth] ⏳ Backoff active: waiting \(String(format: "%.1f", waitSeconds))s")
                #endif
                isAuthenticating = true
                try? await Task.sleep(for: .seconds(waitSeconds))
                await MainActor.run { self.isAuthenticating = false }
                return
            }
        }
        
        isAuthenticating = true
        // FIX K-3: Removed 'defer { isAuthenticating = false }' — the defer fires when
        // authenticate() returns, which is BEFORE handleAuthenticationFailure()'s backoff
        // Task finishes sleeping. This immediately resets isAuthenticating=false, defeating
        // the exponential backoff. Instead, we manually set isAuthenticating=false at each
        // exit point: immediately for success/cancel/lockout, or via the backoff Task for failures.
        
        let context = LAContext()
        // P8-AUDIT8-IOS-04: no touchIDAuthenticationAllowableReuseDuration.
        // With a reuse window, evaluatePolicy succeeds WITHOUT a face match
        // if the phone was unlocked with Face ID on the lock screen within
        // that window — anyone handed the unlocked phone passed the app lock.
        // The default (0) demands a fresh match on every app unlock. No
        // Keychain item needs the context any more (biometric item
        // protection was stripped in KeyManager migration v7).
        // Don't show cancel button to force authentication
        context.localizedCancelTitle = ""
        // Don't show fallback button - force Face ID only
        context.localizedFallbackTitle = ""
        
        var error: NSError?
        
        // First check if biometrics are available at all
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            #if DEBUG
            print("[BiometricAuth] ⚠️ Biometrics not available: \(error?.localizedDescription ?? "unknown")")
            #endif
            
            // M1 FIX: NO passcode fallback — require biometric enrollment.
            // Allowing device PIN as fallback lets an attacker with the PIN bypass Face ID.
            // All iOS 17+ devices have Face ID or Touch ID hardware.
            await MainActor.run {
                self.authError = LanguageManager.localized("Face ID / Touch ID required. Please enable biometric authentication in Settings.")
                self.isAuthenticated = false
                self.isLocked = true
                self.isAuthenticating = false  // FIX K-3: No backoff here, reset immediately
            }
            return
        }
        
        #if DEBUG
        print("[BiometricAuth] ✅ Face ID available, prompting for biometric authentication")
        #endif
        
        // FIX M-12 (ADVERSARIAL): Generic reason string — does not reveal app name.
        // Previous "Unlock Ladon to access your secure conversations" identified the app
        // on the lock screen to shoulder-surfers.
        let reason = LanguageManager.localized("Authenticate to continue")
        
        do {
            let success = try await context.evaluatePolicy(
                .deviceOwnerAuthenticationWithBiometrics,
                localizedReason: reason
            )
            
            await MainActor.run {
                if success {
                    self.isAuthenticating = false  // FIX K-3: Success — reset immediately
                    self.authError = nil
                    // FIX A8-BIO-01: Reset failure count AND persist to Keychain.
                    // Previously only set in-memory → after restart, old count loaded → premature panic.
                    // A matching face is a successful Face ID attempt even when
                    // the PIN step still follows.
                    self.faceIDFailureCount = 0
                    BiometricAuthService.saveFailureCount(0)
                    // FIX AUDIT-21APR-LOW2: Clear persisted backoff timestamp on success.
                    BiometricAuthService.clearBackoffTimestamp()
                    // P7-IOS-BUG-16: cancel any pending backoff sleep so
                    // a previously-scheduled isAuthenticating=false
                    // doesn't fire later and override fresh state.
                    self.backoffTask?.cancel()
                    self.backoffTask = nil
                    self.routeAfterBiometricSuccess(context)
                } else {
                    self.isAuthenticated = false
                    self.isLocked = true
                    self.authError = LanguageManager.localized("Authentication failed")
                    self.handleAuthenticationFailure()
                    // isAuthenticating stays true — backoff Task in handleAuthenticationFailure resets it
                }
            }
        } catch let error as LAError {
            await MainActor.run {
                // FIX MED-37: Only increment panic counter for actual auth failures.
                // biometryLockout is an iOS system lockout — not a new failure attempt.
                // Cancel/system-cancel are user-initiated, not failed attempts.
                switch error.code {
                case .userCancel, .systemCancel, .appCancel:
                    self.authError = LanguageManager.localized("Authentication cancelled")
                    self.isAuthenticating = false  // FIX K-3: Cancel — no backoff needed
                    // Do NOT increment failure counter for user-initiated cancels
                case .biometryLockout:
                    self.authError = LanguageManager.localized("Biometrics locked out by iOS. Try again later.")
                    self.isAuthenticating = false  // FIX K-3: iOS lockout — no backoff needed
                    // Do NOT increment — iOS already enforces lockout
                case .biometryNotAvailable:
                    self.authError = LanguageManager.localized("Biometric authentication not available")
                    self.isAuthenticating = false  // FIX K-3: Not available — no backoff needed
                case .biometryNotEnrolled:
                    self.authError = LanguageManager.localized("No biometrics enrolled")
                    self.isAuthenticating = false  // FIX K-3: Not enrolled — no backoff needed
                case .passcodeNotSet:
                    self.authError = LanguageManager.localized("Device passcode not set")
                    self.isAuthenticating = false  // FIX K-3: No passcode — no backoff needed
                case .userFallback:
                    self.authError = LanguageManager.localized("User chose fallback")
                    self.handleAuthenticationFailure()
                    // isAuthenticating stays true — backoff Task resets it
                default:
                    self.authError = LanguageManager.localized("Authentication failed")
                    self.handleAuthenticationFailure()
                    // isAuthenticating stays true — backoff Task resets it
                }
                
                self.isAuthenticated = false
                self.isLocked = true
                
                #if DEBUG
                print("[BiometricAuth] Authentication failed: \(self.authError ?? "Unknown")")
                #endif
            }
        } catch {
            await MainActor.run {
                self.handleAuthenticationFailure()
                self.authError = LanguageManager.localized("Authentication failed")
                self.isAuthenticated = false
                self.isLocked = true
                #if DEBUG
                print("[BiometricAuth] Authentication error: \(error.localizedDescription)")
                #endif
            }
        }
    }
    
    /// Lock the app (called when going to background)
    func lockApp() {
        isAuthenticated = false  // Always lock on background
        isLocked = true
        // An open PIN step never survives the background: the next return
        // starts again with Face ID.
        resetPinStep()
        lastBackgroundTime = Date()
        KeyManager.shared.setAppLocked(true)
        KeyManager.shared.invalidateBiometricContext()
        #if DEBUG
        print("[BiometricAuth] 🔒 App locked on background - Face ID required on next open")
        #endif
    }
    
    /// Quick check without UI prompt (for background/foreground transitions)
    /// Handle authentication failure and track for bio-failsafe
    /// H4 FIX: Exponential backoff between attempts to slow brute-force
    /// FIX M-18: Backoff is client-side but reinforced by:
    /// - Keychain-persisted failure count (survives app kill)
    /// - iOS LAContext enforces device-level lockouts after N failures
    /// - Panic wipe at bioFailsafePanicThreshold (10) failures makes brute-force self-defeating
    /// P8-AUDIT8-IOS-05 (audit F45): only real mismatches count. Cancel and the
    /// iOS biometry lockout do not — .systemCancel fires on every move to the
    /// background and must never feed the panic wipe. Cancelling before a
    /// mismatch therefore avoids the count; the LADON PIN step after a changed
    /// biometry set (routeAfterBiometricSuccess) is the guard against an
    /// enrolled foreign face, not this counter.
    /// - Backoff timestamp persisted to prevent clock manipulation
    private func handleAuthenticationFailure() {
        faceIDFailureCount += 1
        // H5 FIX: Persist to Keychain so app-kill doesn't reset brute-force counter
        BiometricAuthService.saveFailureCount(faceIDFailureCount)
        
        // FIX M-18: Persist next-allowed timestamp in Keychain to prevent bypass via app restart
        // FIX HIGH-20: Increased backoff cap from 60s to 3600s (1 hour)
        // 60s max allows ~60 attempts/hour; 3600s makes brute-force infeasible
        let backoffSeconds = min(3600.0, pow(2.0, Double(faceIDFailureCount - 1)))
        let nextAllowed = Date().timeIntervalSince1970 + backoffSeconds
        var nextAllowedBytes = nextAllowed.bitPattern.bigEndian
        let nextAllowedData = Data(bytes: &nextAllowedBytes, count: 8)
        // Note: backoff uses max 3600s; [weak self] not needed as self is singleton service
        // FIX A12-HIGH-2: kSecAttrAccessible removed from delete query — same bug
        // as SOCKS5 (A11 fix). Accessibility mismatch caused SecItemDelete to fail,
        // then SecItemAdd hit errSecDuplicateItem → backoff timestamp never persisted.
        // FIX AUDIT-MAR-2026-11: Atomic Update→Add pattern (crash-safe)
        // FIX AUDIT-R7-01: kSecAttrService added — without it, item survives emergency wipe
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: "app.ladon.messenger.authBackoffUntil",
            kSecAttrService as String: "app.ladon.messenger",
            kSecAttrSynchronizable as String: false
        ]
        let updateAttrs: [String: Any] = [
            kSecValueData as String: nextAllowedData,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        let updateStatus = SecItemUpdate(query as CFDictionary, updateAttrs as CFDictionary)
        if updateStatus == errSecItemNotFound {
            var addQuery = query
            addQuery[kSecValueData as String] = nextAllowedData
            addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
            if addStatus != errSecSuccess {
                #if DEBUG
                print("[BiometricAuth] Keychain write failed for backoff: \(addStatus)")
                #endif
            }
        } else if updateStatus != errSecSuccess {
            #if DEBUG
            print("[BiometricAuth] Keychain update failed for backoff: \(updateStatus)")
            #endif
        }
        
        isAuthenticating = true  // Block UI during backoff
        // P7-IOS-BUG-16: cancel any prior in-flight backoff task before
        // spawning a new one so we don't end up with multiple sleeps
        // racing to reset isAuthenticating to false at different times.
        backoffTask?.cancel()
        backoffTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(backoffSeconds))
            // If the sleep was cancelled (because the user succeeded via
            // another path or a newer failure superseded us), skip the
            // reset so we don't clobber the now-current state.
            if Task.isCancelled { return }
            await MainActor.run {
                self?.isAuthenticating = false
            }
        }
        
        #if DEBUG
        print("[BiometricAuth] ❌ Authentication failed - Failure count: \(faceIDFailureCount)")
        #endif
        
        // Trigger inactivity warning at bioFailsafeWarningThreshold failures
        if faceIDFailureCount == bioFailsafeWarningThreshold {
            #if DEBUG
            print("[BiometricAuth] ⚠️ BIO-FAILSAFE: \(bioFailsafeWarningThreshold) failures reached - Activating inactivity warning")
            #endif
            InactivityManager.shared.activateInactivityWarning()
        }
        
        // Trigger immediate panic at bioFailsafePanicThreshold failures
        if faceIDFailureCount >= bioFailsafePanicThreshold {
            #if DEBUG
            print("[BiometricAuth] 🔴 BIO-FAILSAFE: \(bioFailsafePanicThreshold) failures reached - TRIGGERING PANIC MODE")
            #endif
            InactivityManager.shared.triggerPanic()
        }
    }
    
    /// Reset Face ID failure count (called on successful authentication)
    func resetFaceIDFailures() {
        faceIDFailureCount = 0
        BiometricAuthService.saveFailureCount(0)
        // FIX AUDIT-21APR-LOW2: Clear stale backoff timestamp. Otherwise a user
        // who authenticated successfully would still be blocked on the next
        // authenticate() call by the old nextAllowed timestamp.
        BiometricAuthService.clearBackoffTimestamp()
        #if DEBUG
        print("[BiometricAuth] ✅ Face ID failure count reset")
        #endif
    }

    /// FIX AUDIT-21APR-LOW2: Remove persisted backoff timestamp from Keychain.
    /// Brute-force protection is unaffected — the failure counter is the source
    /// of truth (triggers warning at 5, panic at 10, backoff re-written on each
    /// new failure via atomic Update→Add).
    private static func clearBackoffTimestamp() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: "app.ladon.messenger.authBackoffUntil",
            kSecAttrService as String: "app.ladon.messenger",
            kSecAttrSynchronizable as String: false
        ]
        let status = SecItemDelete(query as CFDictionary)
        if status != errSecSuccess && status != errSecItemNotFound {
            #if DEBUG
            print("[BiometricAuth] Keychain delete failed for backoff: \(status)")
            #endif
        }
    }
    
    // MARK: - LADON PIN gate

    /// Face ID succeeded with `context`: open the app, or ask for the PIN
    /// (first time: set it; biometry changed: enter it).
    private func routeAfterBiometricSuccess(_ context: LAContext) {
        guard let current = Self.biometryStateHash(context) else {
            // Cannot happen after a successful biometric check; stay locked.
            authError = LanguageManager.localized("Authentication failed")
            isAuthenticated = false
            isLocked = true
            return
        }
        let hasPin: Bool
        let stored: Data?
        do {
            hasPin = try AppPinStore.hasPin()
            stored = try AppPinStore.storedBiometryState()
        } catch {
            // Keychain unreadable: fail closed, nothing is unlocked.
            authError = LanguageManager.localized("Authentication failed")
            isAuthenticated = false
            isLocked = true
            return
        }
        let changed = stored.map { !$0.constantTimeEqual(AppPinStore.digest(current)) } ?? true
        if hasPin && !changed {
            completeUnlock(context)
            return
        }
        pendingContext = context
        pendingStateHash = current
        pinError = nil
        pinStage = hasPin ? .verify : .setup
        isAuthenticated = false
        isLocked = true
    }

    /// The unlock that used to follow every successful Face ID check.
    private func completeUnlock(_ context: LAContext) {
        resetPinStep()
        isAuthenticated = true
        isLocked = false
        // FIX FACEID-RACE: Pass the ALREADY-AUTHENTICATED LAContext to KeyManager.
        // This prevents KeyManager from creating its own LAContext (which triggers
        // a SECOND Face ID prompt). The authenticated context also pre-populates
        // the key cache so all background tasks (provision, UAK, push) can sign
        // without any additional Face ID prompts.
        KeyManager.shared.setBiometricContext(context)
        authError = nil
        lastBackgroundTime = nil  // Reset timer after successful auth
        #if DEBUG
        print("[BiometricAuth] Authentication successful")
        #endif
        // FIX PUSH-INIT: Notify app that biometric auth succeeded.
        // This triggers provisioning + push token registration + message fetch
        // on ALL paths (first launch, background return, lock screen unlock).
        // Previously, only the .background → .active path ran this flow,
        // so on first launch (.inactive → .active) the push token was never registered.
        NotificationCenter.default.post(name: .biometricAuthSuccess, object: nil)
    }

    private func resetPinStep() {
        pinStage = .none
        pinError = nil
        isCheckingPin = false
        pendingContext = nil
        pendingStateHash = nil
    }

    /// First PIN: at least six digits, entered twice.
    func submitNewPin(_ pin: String, confirm: String) async {
        guard pinStage == .setup, let context = pendingContext, let state = pendingStateHash,
              !isCheckingPin else { return }
        if let problem = AppPinStore.validationError(pin: pin, confirm: confirm) {
            pinError = problem
            return
        }
        isCheckingPin = true
        do {
            try await AppPinStore.setPin(pin)
            try AppPinStore.storeBiometryState(state)
            AppPinStore.resetFailures()
            completeUnlock(context)
        } catch {
            isCheckingPin = false
            pinError = LanguageManager.localized("The PIN could not be saved. Please try again.")
        }
    }

    /// Face ID changed: the PIN decides. Ten wrong PINs trigger the panic wipe.
    func submitPin(_ pin: String) async {
        guard pinStage == .verify, let context = pendingContext, let state = pendingStateHash,
              !isCheckingPin, !pin.isEmpty else { return }
        isCheckingPin = true
        // Wait out a backoff that is still running (persisted, so quitting
        // the app does not skip it).
        let wait = AppPinStore.backoffRemaining()
        if wait > 0 { try? await Task.sleep(for: .seconds(wait)) }
        guard pinStage == .verify, pendingContext === context else { return }
        let ok: Bool
        do {
            ok = try await AppPinStore.verify(pin)
        } catch {
            isCheckingPin = false
            pinError = LanguageManager.localized("Authentication failed")
            return
        }
        guard pinStage == .verify, pendingContext === context else { return }
        if ok {
            do { try AppPinStore.storeBiometryState(state) } catch {
                isCheckingPin = false
                pinError = LanguageManager.localized("Authentication failed")
                return
            }
            AppPinStore.resetFailures()
            completeUnlock(context)
            return
        }
        let failures = AppPinStore.recordFailure()
        isCheckingPin = false
        if failures >= Self.pinPanicThreshold {
            resetPinStep()
            InactivityManager.shared.triggerPanic()
            return
        }
        pinError = String(format: LanguageManager.localized("Wrong PIN. %d attempts left."),
                          Self.pinPanicThreshold - failures)
    }

    /// Settings: replace the PIN, authorised by the current one. Wrong
    /// current PINs count towards the same limit.
    static func changePin(current: String, new: String, confirm: String) async -> String? {
        if let problem = AppPinStore.validationError(pin: new, confirm: confirm) { return problem }
        let wait = AppPinStore.backoffRemaining()
        if wait > 0 { try? await Task.sleep(for: .seconds(wait)) }
        do {
            guard try await AppPinStore.verify(current) else {
                let failures = AppPinStore.recordFailure()
                if failures >= Self.pinPanicThreshold {
                    InactivityManager.shared.triggerPanic()
                    return LanguageManager.localized("Authentication failed")
                }
                return String(format: LanguageManager.localized("Wrong PIN. %d attempts left."),
                              Self.pinPanicThreshold - failures)
            }
            try await AppPinStore.setPin(new)
            AppPinStore.resetFailures()
            return nil
        } catch {
            return LanguageManager.localized("The PIN could not be saved. Please try again.")
        }
    }

    /// The enrolled-biometry state after a successful biometric evaluation.
    private static func biometryStateHash(_ context: LAContext) -> Data? {
        if #available(iOS 18.0, *) {
            return context.domainState.biometry.stateHash
        } else {
            return context.evaluatedPolicyDomainState
        }
    }

    func requiresAuthentication() -> Bool {
        // If never authenticated, require it
        if !isAuthenticated {
            isLocked = true
            return true
        }
        
        // If no background time recorded, don't require re-auth (inactive states)
        guard let backgroundTime = lastBackgroundTime else {
            return false
        }
        
        // Check if enough time has passed to require re-auth
        let timeInBackground = Date().timeIntervalSince(backgroundTime)
        if timeInBackground > authTimeoutSeconds {
            isLocked = true
            return true
        }
        
        // Within timeout window - no re-auth needed
        return false
    }
}

// MARK: - LADON PIN storage

/// The LADON PIN (Argon2id, m=64 MiB, t=3, p=4 — crypto-guard), the digest
/// of the enrolled-biometry state at the last unlock, and the PIN failure
/// counter with its backoff. All in the Keychain service
/// "app.ladon.messenger", this device only, available while unlocked — so
/// the panic wipe and the fresh-install wipe remove them with the rest.
enum AppPinStore {
    private static let service = "app.ladon.messenger"
    /// v2: RFC 9106 Argon2id (reference implementation, LadonArgon2).
    private static let pinAccount = "app.ladon.messenger.appPin.v2"
    /// Written on 13.10.2026 by the former non-conforming pure-Swift
    /// "Argon2id" — test devices only, never released. Removed on sight so
    /// such a device is simply asked to set its PIN again.
    private static let legacyPinAccount = "app.ladon.messenger.appPin"
    private static let biometryAccount = "app.ladon.messenger.biometryState"
    private static let failuresAccount = "app.ladon.messenger.pinFailureCount"
    private static let backoffAccount = "app.ladon.messenger.pinBackoffUntil"
    private static let saltLen = 16
    private static let hashLen = 32

    enum StoreError: Error { case keychain(OSStatus), malformed, random }

    static func digest(_ state: Data) -> Data { Data(SHA256.hash(data: state)) }

    static func hasPin() throws -> Bool {
        delete(legacyPinAccount)
        return try read(pinAccount) != nil
    }

    static func storedBiometryState() throws -> Data? { try read(biometryAccount) }

    static func storeBiometryState(_ state: Data) throws {
        try write(biometryAccount, digest(state))
    }

    /// nil if acceptable, otherwise the (localized) reason.
    static func validationError(pin: String, confirm: String) -> String? {
        guard pin.count >= 6 else { return LanguageManager.localized("PIN must be at least 6 digits") }
        guard pin.allSatisfy({ ("0"..."9").contains($0) }) else {
            return LanguageManager.localized("PIN must contain only digits")
        }
        guard pin == confirm else { return LanguageManager.localized("PINs do not match") }
        return nil
    }

    static func setPin(_ pin: String) async throws {
        var salt = Data(count: saltLen)
        let status = salt.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, saltLen, $0.baseAddress!) }
        guard status == errSecSuccess else { throw StoreError.random }
        var derived = try await derive(pin, salt: salt)
        defer { derived.securelyWipe() }
        try write(pinAccount, salt + derived)
    }

    static func verify(_ pin: String) async throws -> Bool {
        guard let stored = try read(pinAccount), stored.count == saltLen + hashLen else {
            throw StoreError.malformed
        }
        var derived = try await derive(pin, salt: Data(stored.prefix(saltLen)))
        defer { derived.securelyWipe() }
        return derived.constantTimeEqual(Data(stored.suffix(hashLen)))
    }

    /// Argon2id off the main actor (64 MiB, ~1 s on a phone).
    /// The PIN arrives as a String from a SecureField; like RegLock before
    /// (FIX MED-A8) its bytes cannot be reliably wiped — copy-on-write would
    /// zero only a copy — so no wipe is pretended here.
    private static func derive(_ pin: String, salt: Data) async throws -> Data {
        let input = Data(pin.utf8)
        return try await Task.detached(priority: .userInitiated) {
            try Argon2id.hash(password: input, salt: salt, timeCost: 3,
                              memoryCost: 65536, parallelism: 4, outputLength: UInt32(hashLen))
        }.value
    }

    /// Count a wrong PIN; returns the new count. Persists an exponential
    /// backoff (capped at one hour), so quitting the app does not skip it.
    static func recordFailure() -> Int {
        let current = (try? read(failuresAccount)).flatMap { $0 }.flatMap { d -> Int? in
            d.count == 4 ? Int(d.withUnsafeBytes { $0.loadUnaligned(as: Int32.self) }) : nil
        } ?? 0
        let next = current + 1
        var value = Int32(next)
        try? write(failuresAccount, Data(bytes: &value, count: 4))
        let until = Date().timeIntervalSince1970 + min(3600, pow(2, Double(next - 1)))
        var bits = until.bitPattern.bigEndian
        try? write(backoffAccount, Data(bytes: &bits, count: 8))
        return next
    }

    static func backoffRemaining() -> TimeInterval {
        guard let d = (try? read(backoffAccount)).flatMap({ $0 }), d.count == 8 else { return 0 }
        let until = Double(bitPattern: d.withUnsafeBytes { $0.loadUnaligned(as: UInt64.self) }.bigEndian)
        return min(3600, max(0, until - Date().timeIntervalSince1970))
    }

    static func resetFailures() {
        delete(failuresAccount)
        delete(backoffAccount)
    }

    // MARK: Keychain

    private static func baseQuery(_ account: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: account,
         kSecAttrSynchronizable as String: false]
    }

    private static func read(_ account: String) throws -> Data? {
        var q = baseQuery(account)
        q[kSecReturnData as String] = true
        var result: AnyObject?
        let status = SecItemCopyMatching(q as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else { throw StoreError.keychain(status) }
        return data
    }

    private static func write(_ account: String, _ data: Data) throws {
        let q = baseQuery(account)
        let update = SecItemUpdate(q as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if update == errSecSuccess { return }
        guard update == errSecItemNotFound else { throw StoreError.keychain(update) }
        var add = q
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess else { throw StoreError.keychain(status) }
    }

    private static func delete(_ account: String) {
        _ = SecItemDelete(baseQuery(account) as CFDictionary)
    }
}

/// Lock screen view
struct BiometricLockView: View {
    @Environment(\.colorScheme) private var ladonAppearanceTick
    @ObservedObject var authService: BiometricAuthService
    
    var body: some View {
        ZStack {
            MeshBackground()

            if authService.pinStage != .none {
                PinStepView(authService: authService)
            } else if !AppearanceManager.isDarkStored {
                lightBody
            } else {
            VStack(spacing: 30) {
                Image(systemName: authService.biometricType == "Face ID" ? "faceid" : "touchid")
                    .font(.system(size: 80))
                    .foregroundColor(LadonTheme.brandGreen)
                    .shadow(color: LadonTheme.brandGreen.opacity(0.6), radius: 20)

                // FIX A12-LOW-6: Generic text — doesn't reveal app identity to shoulder surfers
                Text("Locked")
                    .font(.manrope(34, .extrabold))
                    .foregroundColor(LadonTheme.textPrimary)

                Text("Authenticate to continue")
                    .font(.subheadline)
                    .foregroundColor(LadonTheme.textSecondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal)

                if let error = authService.authError {
                    Text(error)
                        .font(.caption)
                        .foregroundColor(LadonTheme.coral)
                        .padding()
                }

                Button {
                    Task {
                        await authService.authenticate()
                    }
                } label: {
                    HStack {
                        Image(systemName: "lock.open")
                        Text("Unlock with \(authService.biometricType)")
                    }
                    .font(.headline)
                    .foregroundColor(LadonTheme.background)
                    .padding(.horizontal, 24)
                    .padding(.vertical, 14)
                    .background(LadonTheme.greenGradient)
                    .clipShape(Capsule())
                    .overlay(Capsule().strokeBorder(Color.white.opacity(0.3), lineWidth: 1))
                    .shadow(color: LadonTheme.brandGreen.opacity(0.5), radius: 14, y: 6)
                }
                .buttonStyle(.plain)
                .padding(.top, 20)
            }
            .padding()
            }
        }
    }

    /// Light (ladon.app): lock badge, "Locked", lead, green pill at the bottom.
    /// Generic text on purpose — nothing names the app (FIX A12-LOW-6).
    private var lightBody: some View {
        VStack(spacing: 0) {
            Spacer()
            LadonStatusBadge(systemImage: "lock")
            LadonStatusText(title: "Locked", lead: "Authenticate to continue")
                .padding(.top, 22)
            if let error = authService.authError {
                Text(error)
                    .font(.manrope(14, relativeTo: .footnote))
                    .foregroundColor(LadonTheme.coralInk)
                    .multilineTextAlignment(.center)
                    .padding(.top, 14)
            }
            Spacer()
            PairingPrimaryButton(title: "Unlock with \(authService.biometricType)",
                                 systemImage: authService.biometricType == "Face ID" ? "faceid" : "touchid") {
                Task { await authService.authenticate() }
            }
        }
        .padding(.horizontal, 24)
        .padding(.bottom, 12)
    }
}

// MARK: - LADON PIN step

/// The PIN step on the lock screen: set the PIN (first unlock) or enter it
/// (Face ID changed). Built from the lock screen's own parts — status
/// badge and text, the pairing name field's look, the primary pill.
private struct PinStepView: View {
    @Environment(\.colorScheme) private var ladonAppearanceTick
    @ObservedObject var authService: BiometricAuthService
    @StateObject private var secrets = PinSecretState()
    @FocusState private var focusedField: Int?

    private var isSetup: Bool { authService.pinStage == .setup }

    var body: some View {
        VStack(spacing: 0) {
            Spacer()
            LadonStatusBadge(systemImage: isSetup ? "lock" : "faceid", tint: isSetup ? .green : .coral)
            LadonStatusText(title: isSetup ? "Set your LADON PIN" : "Face ID has changed",
                            lead: isSetup ? "You'll need it if Face ID changes on this iPhone."
                                          : "Enter your LADON PIN to continue.")
                .padding(.top, 22)
            VStack(spacing: 12) {
                PinField(placeholder: isSetup ? "Enter PIN (min 6 digits)" : "LADON PIN", text: $secrets.pin)
                    .focused($focusedField, equals: 0)
                if isSetup {
                    PinField(placeholder: "Confirm PIN", text: $secrets.confirm)
                        .focused($focusedField, equals: 1)
                }
            }
            .padding(.top, 28)
            if let error = authService.pinError {
                Text(error)
                    .font(.manrope(14, relativeTo: .footnote))
                    .foregroundColor(LadonTheme.coralInk)
                    .multilineTextAlignment(.center)
                    .padding(.top, 14)
            }
            Spacer()
            PairingPrimaryButton(title: "Continue", systemImage: "lock.open",
                                 isBusy: authService.isCheckingPin) {
                submit()
            }
            .disabled(secrets.pin.count < 6 || (isSetup && secrets.confirm.count < 6) || authService.isCheckingPin)
        }
        .padding(.horizontal, 24)
        .padding(.bottom, 12)
        .onAppear { focusedField = 0 }
        .onChange(of: authService.pinStage) { _, _ in secrets.wipe() }
        .onDisappear { secrets.wipe() }
    }

    private func submit() {
        let pin = secrets.pin
        let confirm = secrets.confirm
        secrets.wipe()
        focusedField = 0
        Task {
            if isSetup {
                await authService.submitNewPin(pin, confirm: confirm)
            } else {
                await authService.submitPin(pin)
            }
        }
    }
}

/// A PIN field in the look of the pairing name field: white, 16 pt
/// corners, ink-14 % hairline (light); thin material (dark).
private struct PinField: View {
    @Environment(\.colorScheme) private var ladonAppearanceTick
    let placeholder: LocalizedStringKey
    @Binding var text: String

    var body: some View {
        let dark = AppearanceManager.isDarkStored
        SecureField(placeholder, text: $text)
            .keyboardType(.numberPad)
            .privacySensitive()
            .font(dark ? nil : .manrope(16, relativeTo: .body))
            .padding(.vertical, dark ? 12 : 14)
            .padding(.horizontal, dark ? 12 : 16)
            .background {
                if dark {
                    RoundedRectangle(cornerRadius: 10)
                        .fill(.ultraThinMaterial.opacity(0.55))
                        .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(LadonTheme.glassStroke, lineWidth: 1))
                } else {
                    RoundedRectangle(cornerRadius: 16, style: .continuous)
                        .fill(Color.white)
                        .overlay(
                            RoundedRectangle(cornerRadius: 16, style: .continuous)
                                .strokeBorder(LadonTheme.onSurface(0.14), lineWidth: 1)
                        )
                }
            }
    }
}

/// PIN entry held only while typing (same caveat as RegLock, FIX MED-A8:
/// Swift Strings cannot be reliably wiped; the references are dropped).
final class PinSecretState: ObservableObject {
    @Published var pin: String = ""
    @Published var confirm: String = ""
    @Published var current: String = ""
    deinit { pin = ""; confirm = ""; current = "" }
    func wipe() { pin = ""; confirm = ""; current = "" }
}
