import Foundation
import SwiftUI
import Security

/// Manages device inactivity tracking and Dead Man's Switch
/// FIX MED-21: @MainActor ensures all @Published properties and Timer access
/// are confined to the main thread (previously unguarded race conditions)
@MainActor
class InactivityManager: NSObject, ObservableObject {
    @Published var isInactivityWarningActive = false
    @Published var countdownSeconds = 86400  // 24 hours
    @Published var daysSinceLastActive = 0
    @Published var inactivityThresholdDays = 14  // Default: 14 days
    @Published var isInactivityEnabled = true
    
    /// Alias used by SettingsView and ContentView for backward compatibility
    var showInactivityWarning: Bool {
        get { isInactivityWarningActive }
        set { isInactivityWarningActive = newValue }
    }
    
    private var countdownTimer: Timer?
    private let countdownInterval = 1  // Update every second
    // FIX H-05: Monotonic clock reference for countdown (immune to system time manipulation)
    private var monotonicCountdownStart: TimeInterval?
    
    // H5/H6 FIX: Use Keychain-backed storage instead of plaintext UserDefaults
    private let defaults = SecureUserDefaults.shared
    private let lastActiveDateKey = "lastActiveDate"
    private let inactivityThresholdKey = "inactivityThresholdDays"
    private let inactivityEnabledKey = "inactivityEnabled"
    private let countdownStartTimeKey = "countdownStartTime"
    
    static let shared = InactivityManager()
    
    private override init() {
        super.init()
        // Load settings
        if let threshold = try? defaults.integer(forKey: inactivityThresholdKey) {
            inactivityThresholdDays = threshold
        }
        if inactivityThresholdDays == 0 {
            inactivityThresholdDays = 14
        }
        
        isInactivityEnabled = defaults.bool(forKey: inactivityEnabledKey)
        if !defaults.bool(forKey: "inactivityEnabledInitialized") {
            isInactivityEnabled = true
            // FIX MED-79: Log errors instead of silently swallowing
            do {
                try defaults.set(true, forKey: inactivityEnabledKey)
                try defaults.set(true, forKey: "inactivityEnabledInitialized")
            } catch {
                SecureLogger.error("Failed to initialize inactivity defaults: \(error.localizedDescription)")
            }
        }
        
        updateLastActiveDate()
        checkInactivityThreshold()
        
        // FIX MED-38: Register for foreground notification so we can re-check
        // the countdown immediately when the app returns from background.
        // Timer.scheduledTimer does NOT fire while backgrounded, so the panic
        // could be delayed until the next timer tick after foregrounding.
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(appWillEnterForeground),
            name: UIApplication.willEnterForegroundNotification,
            object: nil
        )
    }
    
    // FIX MED-38: Immediately re-evaluate countdown on foreground
    @objc private func appWillEnterForeground() {
        if isInactivityWarningActive {
            updateCountdown()
            // Restart the timer in case it was suspended
            startCountdownTimer()
        } else {
            checkInactivityThreshold()
        }
    }
    
    /// Update last active date to now
    func updateLastActiveDate() {
        // FIX MED-79: Log error instead of silently swallowing with try?
        do {
            try defaults.set(Int(Date().timeIntervalSince1970), forKey: lastActiveDateKey)
        } catch {
            SecureLogger.error("Failed to persist last active date: \(error.localizedDescription)")
        }
        
        #if DEBUG
        print("[InactivityManager] ✅ Updated last active date: \(Date())")
        #endif
    }
    
    /// Check if device has been inactive too long
    func checkInactivityThreshold() {
        guard isInactivityEnabled else { return }
        
        let lastActiveTS = try? defaults.integer(forKey: lastActiveDateKey)
        let lastActive: Date = {
            if let ts = lastActiveTS {
                return Date(timeIntervalSince1970: TimeInterval(ts))
            }
            return Date()
        }()
        let daysDiff = Calendar.current.dateComponents([.day], from: lastActive, to: Date()).day ?? 0
        self.daysSinceLastActive = daysDiff
        
        #if DEBUG
        print("[InactivityManager] 📊 Days inactive: \(daysDiff) / \(inactivityThresholdDays)")
        #endif
        
        if daysDiff >= inactivityThresholdDays {
            activateInactivityWarning()
        }
    }
    
    /// Activate inactivity warning and start countdown
    func activateInactivityWarning() {
        guard !isInactivityWarningActive else { return }
        
        #if DEBUG
        print("[InactivityManager] ⚠️ INACTIVITY WARNING ACTIVATED - 24h countdown started")
        #endif
        
        isInactivityWarningActive = true
        countdownSeconds = 86400  // 24 hours in seconds
        // FIX MED-79: Log error instead of silently swallowing
        do {
            try defaults.set(Int(Date().timeIntervalSince1970), forKey: countdownStartTimeKey)
        } catch {
            SecureLogger.error("Failed to persist countdown start time: \(error.localizedDescription)")
        }
        
        startCountdownTimer()
    }
    
    /// Start countdown timer (ticks every second)
    private func startCountdownTimer() {
        countdownTimer?.invalidate()
        
        countdownTimer = Timer.scheduledTimer(withTimeInterval: TimeInterval(countdownInterval), repeats: true) { [weak self] _ in
            // Der Timer wird von einer @MainActor-Methode erzeugt und haengt
            // damit am Main-RunLoop; der Block feuert garantiert auf dem
            // Main-Thread. Der Compiler kann das nicht beweisen, daher die
            // explizite Zusicherung — dasselbe Muster wie in
            // InMemoryMessageStore beim Wipe auf Geraetesperre.
            MainActor.assumeIsolated {
                self?.updateCountdown()
            }
        }
    }
    
    /// Update countdown and check if should trigger panic
    private func updateCountdown() {
        let countdownStartTS: Int
        do {
            guard let ts = try defaults.integer(forKey: countdownStartTimeKey) else {
                SecureLogger.error("Countdown active but start time missing")
                return
            }
            countdownStartTS = ts
        } catch {
            SecureLogger.error("Failed to read countdown start time: \(error.localizedDescription)")
            return
        }
        let countdownStart = Date(timeIntervalSince1970: TimeInterval(countdownStartTS))
        
        // FIX H-05: Use monotonic clock (ProcessInfo.systemUptime) as primary source.
        // Date() uses wall clock which can be manipulated by setting system time backward
        // (extending countdown indefinitely) or forward (premature panic trigger).
        // Monotonic clock is immune to NTP/manual clock changes.
        // We still use Date() as a cross-check: if wall clock suggests MORE time has
        // passed than monotonic, we trust the higher value (prevents backward-clock attack).
        let wallElapsed = Int(Date().timeIntervalSince(countdownStart))
        let monotonicElapsed: Int
        if let monotonicStart = monotonicCountdownStart {
            monotonicElapsed = Int(ProcessInfo.processInfo.systemUptime - monotonicStart)
        } else {
            // First tick after app (re)launch — initialize monotonic reference
            // Use wall clock elapsed to set correct offset
            monotonicCountdownStart = ProcessInfo.processInfo.systemUptime - Double(max(0, wallElapsed))
            monotonicElapsed = wallElapsed
        }
        // Take the MAXIMUM of both clocks — attacker must manipulate BOTH to extend countdown
        let elapsedSeconds = max(wallElapsed, monotonicElapsed)
        countdownSeconds = max(0, 86400 - elapsedSeconds)
        
        // Trigger panic if countdown reached zero
        if countdownSeconds <= 0 {
            triggerPanic()
        }
    }
    
    /// Dismiss warning and reset countdown
    func dismissWarning(biometricAuth: BiometricAuthService) {
        guard isInactivityWarningActive else { return }
        
        #if DEBUG
        print("[InactivityManager] ✅ Inactivity warning dismissed - countdown reset")
        #endif
        
        isInactivityWarningActive = false
        countdownTimer?.invalidate()
        countdownTimer = nil
        
        // FIX LO-03: Reset monotonic clock reference. Without this reset, the next
        // time a warning activates, the old monotonicCountdownStart value would still be set,
        // causing incorrect elapsed time calculation on the first updateCountdown() call.
        monotonicCountdownStart = nil
        
        // Reset last active date
        updateLastActiveDate()
        
        // Reset failure count when user successfully authenticates
        Task { @MainActor in
            biometricAuth.resetFaceIDFailures()
        }
    }
    
    /// Trigger immediate panic mode
    func triggerPanic() {
        #if DEBUG
        print("[InactivityManager] 🔴 INACTIVITY TIMEOUT - TRIGGERING PANIC MODE")
        #endif
        
        // FIX IM-F1: Reset flag to prevent repeated panic triggers on every foreground.
        // Without this, appWillEnterForeground() sees isInactivityWarningActive == true
        // and re-enters updateCountdown() → triggerPanic() on every foreground event.
        isInactivityWarningActive = false
        
        countdownTimer?.invalidate()
        countdownTimer = nil
        
        // FIX M-63: Securely wipe in-memory messages on lock/panic.
        // Prevents memory forensics from extracting decrypted plaintext.
        InMemoryMessageStore.shared.clearAll()
        
        // FIX M-9 AUDIT-MAR-2026 + FIX AUDIT-R9-13: Delete critical identity keys DIRECTLY before posting notification.
        // Defense-in-depth: if NotificationCenter delivery fails (e.g., view not yet mounted,
        // process termination race), keys are already destroyed. executePanicMode() will
        // redundantly delete again (idempotent — SecItemDelete on missing item is a no-op).
        // FIX AUDIT-R9-13: Use correct service "app.ladon.messenger" (was using phantom services
        // like "app.ladon.identityKey" that don't exist — all items use "app.ladon.messenger" with different accounts)
        // P8-AUDIT8-IOS-33 (audit F2): the Secure-Enclave chip keys first —
        // this one delete makes every sealed V2 secret (identity, ratchet,
        // prekeys, delivery keys, contacts) unreadable at once.
        let chipStatus = SecItemDelete([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: SealedKeychainV2.chipService,
        ] as CFDictionary)
        if chipStatus != errSecSuccess && chipStatus != errSecItemNotFound {
            SecureLogger.error("Panic mode: Failed to delete chip keys: OSStatus \(chipStatus)")
        }
        let criticalKeychainAccounts = [
            "identity_key",
            "identity_key_private",
            "signing_key",
            "signing_key_private",
            "signed_prekey"
        ]
        for account in criticalKeychainAccounts {
            let deleteQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: "app.ladon.messenger",
                kSecAttrAccount as String: account
            ]
            // FIX AUDIT2-02: Check SecItemDelete return value — silent failure in panic mode
            // means key material survives despite user expecting full wipe.
            let status = SecItemDelete(deleteQuery as CFDictionary)
            if status != errSecSuccess && status != errSecItemNotFound {
                SecureLogger.error("Panic mode: Failed to delete Keychain item '\(account)': OSStatus \(status)")
            }
        }
        // Also delete kSecClassKey items (SE-backed keys, identity keys by tag)
        let criticalKeyTags = [
            "com.ladon.identity",
            "com.ladon.signing",
            "com.ladon.spk"
        ]
        for tag in criticalKeyTags {
            if let tagData = tag.data(using: .utf8) {
                let keyDeleteQuery: [String: Any] = [
                    kSecClass as String: kSecClassKey,
                    kSecAttrApplicationTag as String: tagData
                ]
                // FIX AUDIT2-02: Check SecItemDelete return value for SE-backed keys
                let status = SecItemDelete(keyDeleteQuery as CFDictionary)
                if status != errSecSuccess && status != errSecItemNotFound {
                    SecureLogger.error("Panic mode: Failed to delete Keychain key '\(tag)': OSStatus \(status)")
                }
            }
        }
        
        // FIX MED-217: Pass self as object so receiver can verify sender
        NotificationCenter.default.post(name: NSNotification.Name("InactivityPanicTriggered"), object: self)
    }
    
    /// Set inactivity threshold (7, 14, or 30 days)
    func setInactivityThreshold(_ days: Int) {
        inactivityThresholdDays = days
        // FIX MED-79: Log errors instead of silently swallowing
        do {
            try defaults.set(days, forKey: inactivityThresholdKey)
        } catch {
            SecureLogger.error("Failed to persist inactivity threshold: \(error.localizedDescription)")
        }
        
        #if DEBUG
        print("[InactivityManager] 🔧 Inactivity threshold changed to \(days) days")
        #endif
    }
    
    /// Enable/disable inactivity checking
    func setInactivityEnabled(_ enabled: Bool) {
        isInactivityEnabled = enabled
        // FIX MED-79: Log errors instead of silently swallowing
        do {
            try defaults.set(enabled, forKey: inactivityEnabledKey)
        } catch {
            SecureLogger.error("Failed to persist inactivity enabled state: \(error.localizedDescription)")
        }
        
        if enabled {
            checkInactivityThreshold()
        } else {
            isInactivityWarningActive = false
            countdownTimer?.invalidate()
            countdownTimer = nil
        }
        
        #if DEBUG
        print("[InactivityManager] 🔧 Inactivity checking: \(enabled ? "ENABLED" : "DISABLED")")
        #endif
    }
    
    /// Format countdown to HH:MM:SS
    func formattedCountdown() -> String {
        let hours = countdownSeconds / 3600
        let minutes = (countdownSeconds % 3600) / 60
        let seconds = countdownSeconds % 60
        return String(format: "%02d:%02d:%02d", hours, minutes, seconds)
    }
    
    deinit {
        countdownTimer?.invalidate()
    }
    
    /// Reset timer and update last active date (used by SettingsView)
    func resetInactivityTimer() {
        // FIX R21-A9-1: Never reset if inactivity warning is active.
        // Defense-in-depth: even if caller forgets to check, the timer
        // cannot be silently reset while the Dead Man's Switch is armed.
        guard !isInactivityWarningActive else { return }
        updateLastActiveDate()
        countdownTimer?.invalidate()
        countdownTimer = nil
    }
    
    /// Handle scene phase changes
    func handleScenePhaseChange(_ phase: ScenePhase) {
        if phase == .active {
            // Fix 9: Do NOT auto-reset timer if inactivity warning is active.
            // Requires explicit biometric authentication via dismissWarning().
            // Without this guard, an attacker could simply open the app to bypass the Dead Man's Switch.
            if isInactivityWarningActive {
                #if DEBUG
                print("[InactivityManager] ⚠️ App became active but inactivity warning is active — NOT resetting timer (requires biometric auth)")
                #endif
                return
            }
            resetInactivityTimer()
        }
    }
}
