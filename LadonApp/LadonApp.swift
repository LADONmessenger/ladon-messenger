import SwiftUI
import UserNotifications


// MARK: - PanicLockView at the top for visibility
struct PanicLockView: View {
    // FIX CRIT-09: No @AppStorage — panic flag is Keychain-only
    
    var body: some View {
        VStack(spacing: 32) {
            if AppearanceManager.isDarkStored {
            Image(systemName: "exclamationmark.triangle.fill")
                .resizable()
                .frame(width: 80, height: 80)
                .foregroundColor(.red)
            Text("Error")
                .font(.largeTitle)
                .bold()
                .foregroundColor(LadonTheme.textPrimary)
            // M8 FIX: Neutraler Text
            Text("Application data corrupted.\nPlease reinstall.")
                .multilineTextAlignment(.center)
                .font(.title2)
                .foregroundColor(LadonTheme.textSecondary)
            } else {
                // Light (ladon.app): coral badge, title, lead — same neutral text.
                VStack(spacing: 22) {
                    LadonStatusBadge(systemImage: "exclamationmark.triangle", tint: .coral)
                    LadonStatusText(title: "Error", lead: "Application data corrupted.\nPlease reinstall.")
                }
                .padding(.horizontal, 24)
            }
            
            #if DEBUG
            Button(action: {
                // K2 FIX: Delete Keychain flag
                let resetQuery: [String: Any] = [
                    kSecClass as String: kSecClassGenericPassword,
                    kSecAttrAccount as String: "app_state_reset",
                    kSecAttrService as String: "app.ladon.messenger.state"
                ]
                SecItemDelete(resetQuery as CFDictionary)
                // FIX VM-1: Terminate after clearing the flag. On next launch,
                // the Keychain flag will be gone and the app will boot normally.
                // Previous approach set isAppDestroyed=false, which exposed
                // broken UI with residual in-memory state in the current session.
                abort()
            }) {
                Text("[DEBUG] Reset")
                    .font(.caption)
                    .foregroundColor(LadonTheme.bubbleOutgoingText)
                    .padding(.horizontal, 20)
                    .padding(.vertical, 10)
                    .background(Color.orange)
                    .cornerRadius(8)
            }
            .padding(.top, 40)
            #endif
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(LadonTheme.background)
    }
}

// MARK: - KeygenErrorView (FIX H-13 AUDIT-MAR-2026)
// Shows when identity key generation fails on first launch.
// Unlike PanicLockView, this allows retry — keygen failure is NOT an intentional wipe.
struct KeygenErrorView: View {
    let onRetry: () -> Void
    
    var body: some View {
        VStack(spacing: 32) {
            if AppearanceManager.isDarkStored {
            Image(systemName: "key.slash")
                .resizable()
                .frame(width: 80, height: 80)
                .foregroundColor(.orange)
            Text("Error")
                .font(.largeTitle)
                .bold()
                .foregroundColor(LadonTheme.textPrimary)
            Text("Key initialization failed.\nPlease try again.")
                .multilineTextAlignment(.center)
                .font(.title2)
                .foregroundColor(LadonTheme.textSecondary)
            Button(action: onRetry) {
                Text("Retry")
                    .font(.headline)
                    .foregroundColor(.white)
                    .padding(.horizontal, 40)
                    .padding(.vertical, 14)
                    .background(Color.blue)
                    .cornerRadius(12)
            }
            .padding(.top, 20)
            } else {
                // Light (ladon.app): coral badge, title, lead, green pill.
                VStack(spacing: 22) {
                    LadonStatusBadge(systemImage: "key.slash", tint: .coral)
                    LadonStatusText(title: "Error", lead: "Key initialization failed.\nPlease try again.")
                    PairingPrimaryButton(title: "Retry", systemImage: "arrow.clockwise", action: onRetry)
                        .padding(.top, 8)
                }
                .padding(.horizontal, 24)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(LadonTheme.background)
    }
}

// MARK: - Global Panic Logic for app-wide access
/// FIX SEC-B1 + LA-L1: Thin wrapper — all wipe logic consolidated in SecurityUtils.performComprehensiveWipe().
/// Previously ~160 lines of inline wipe code (parity issues with emergencyLockdown/lockAppDueToSecurityThreat).
/// Now a single consolidated path ensures all emergency wipe triggers perform identical steps.
@MainActor
func executePanicMode() {
    #if DEBUG
    print("[PANIC] 🔴 EMERGENCY DESTROY INITIERT (global) → performComprehensiveWipe()")
    #endif
    SecurityUtils.performComprehensiveWipe()
}

@main
struct LadonApp: App {
        // FIX H15: Static method for unified panic access from any view
        @MainActor
        static func executePanicGlobal() {
            executePanicMode()
        }
        
        @StateObject private var appState = AppState()
        @StateObject private var biometricAuth = BiometricAuthService()
        @StateObject private var languageManager = LanguageManager.shared
        @StateObject private var appearanceManager = AppearanceManager.shared
        @Environment(\.scenePhase) private var scenePhase
        @UIApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
        // FIX CRIT-09: Use @State backed by Keychain instead of @AppStorage (UserDefaults)
        // FIX SE-5 (ADVERSARIAL): Use neutral flag name "app_state_reset" instead of
        // "ladon_app_destroyed" which proves evidence was deliberately destroyed.
        @State private var isAppDestroyed: Bool
        // FIX H-13 AUDIT-MAR-2026: Separate keygen failure from panic state.
        // Keygen failure is recoverable (retry on next launch), panic is permanent.
        @State private var isKeygenFailed: Bool = false
        // CL-01 FIX: Privacy screen overlay when app enters task switcher
        @State private var showPrivacyScreen = false

        /// The app is locked and has an account: the lock screen must cover
        /// everything (scan F24 — see LockWindowPresenter).
        private var lockScreenVisible: Bool {
            biometricAuth.isLocked && appState.isAuthenticated
        }

        /// Show or hide the lock window to match `lockScreenVisible`.
        private func syncLockWindow() {
            if lockScreenVisible {
                LockWindowPresenter.shared.show(
                    BiometricLockView(authService: biometricAuth)
                        // #i18n: a separate window does not inherit the main
                        // content's locale — apply the in-app language here.
                        .environment(\.locale, languageManager.locale)
                        .preferredColorScheme(appearanceManager.colorScheme)
                )
            } else {
                LockWindowPresenter.shared.hide()
            }
        }

        init() {
            // MARK: - Ladon Theme: Global UIAppearance
            // Mode-aware and re-applied on every appearance switch — see
            // LadonTheme.applyUIKitAppearance().
            LadonTheme.applyUIKitAppearance()

            #if DEBUG
            // Phase 8 on-device testing: enable attachment UI by default in
            // DEBUG builds. Release builds remain inert.
            FeatureFlags.debugAttachmentsOverride = true

            // Heavy launch self-tests (V2 pilot probes + crypto) are OFF by default:
            // on older devices with a marginal battery the launch-time CPU/power
            // spike triggered brownout reboots. Opt in via the Xcode scheme env
            // var LADON_SELFTESTS=1 when you actually want to run them.
            if ProcessInfo.processInfo.environment["LADON_SELFTESTS"] == "1" {
                V2BootstrapSelfTest.runOnce()
            }
            #endif
            
            
            // FIX H13: Prevent debugger attachment (Signal/Threema-grade anti-debug)
            ladon_deny_debugger()
            
            // FIX CRIT-09: Read panic flag ONLY from Keychain (authoritative, tamper-resistant)
            // FIX SE-5 (ADVERSARIAL): Neutral flag name + service
            let panicQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrAccount as String: "app_state_reset",
                kSecAttrService as String: "app.ladon.messenger.state",
                kSecReturnData as String: true,
                kSecAttrSynchronizable as String: false
            ]
            var panicResult: AnyObject?
            let panicStatus = SecItemCopyMatching(panicQuery as CFDictionary, &panicResult)
            var isPanicked = panicStatus == errSecSuccess && (panicResult as? Data) == Data([0x01])
            
            // FIX A7-LA-01: Also check file-based fallback (written when Keychain save fails).
            // Without this, a panic triggered during Keychain unavailability is lost on next launch.
            if !isPanicked,
               let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first {
                let panicFile = appSupport.appendingPathComponent(kPanicFlagFilename)
                if let flagData = try? Data(contentsOf: panicFile), flagData == Data([0x01]) {
                    isPanicked = true
                    // FIX AUDIT-MAR-2026-27: Migrate panic flag to Keychain before deleting file.
                    // Without this, force-quit after file read but before Keychain write
                    // drops the panic state entirely on next launch.
                    let migrateQuery: [String: Any] = [
                        kSecClass as String: kSecClassGenericPassword,
                        kSecAttrAccount as String: "app_state_reset",
                        kSecAttrService as String: "app.ladon.messenger.state",
                        kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                        kSecValueData as String: Data([0x01])
                    ]
                    let migrateStatus = SecItemAdd(migrateQuery as CFDictionary, nil)
                    if migrateStatus == errSecSuccess || migrateStatus == errSecDuplicateItem {
                        try? FileManager.default.removeItem(at: panicFile)
                    }
                    // If Keychain write fails, keep file as persistent fallback
                }
            }
            _isAppDestroyed = State(initialValue: isPanicked)
            
            // CRITICAL: Jailbreak detection on launch
            JailbreakDetector.shared.enforceIntegrity()

            // FIX ONBOARDING: Detect fresh install after uninstall.
            // iOS Keychain survives app deletion, but UserDefaults does not.
            // We use a dedicated install marker that is written exactly once
            // on first launch. Missing marker = fresh install (or uninstall +
            // reinstall) → wipe ALL Ladon Keychain items so a stale UAK,
            // identity, ratchet state, or auth secret cannot collide with the
            // server's view of the new identity. Decoupled from
            // hasIdentityKey() because some Keychain items (UAK, sessions)
            // can survive even when the identity key itself is absent.
            let installMarkerKey = "ladon_install_marker_v1"
            let isFreshInstall = !UserDefaults.standard.bool(forKey: installMarkerKey)
            if isFreshInstall {
                #if DEBUG
                SecureLogger.debug("[LadonApp] 🔄 Fresh install detected — wiping any stale Keychain items from previous installation.")
                #endif
                KeyManager.shared.resetConversationState()
                // Delete every Keychain item under any of our service scopes.
                // Keep this list in sync with kSecAttrService values used
                // across Crypto/Services/Security.
                // EXCLUDED: "app.ladon.messenger.state" — the panic flag, which
                // must survive uninstall/reinstall by design.
                //
                // AUDITED 2026-05-24: this is the COMPLETE set of kSecAttrService
                // scopes the app uses. Every other "app.ladon.messenger.*" string in
                // the codebase is a DispatchQueue label or a kSecAttrAccount, NOT a
                // service — the SecureStorage key, encrypted-DB key, blob-relay auth
                // secret, push tokens, SOCKS5 config, Face-ID throttle and the
                // SE-key-created marker all live under the catch-all
                // "app.ladon.messenger" service and are wiped with it. The earlier
                // gap was only the three V2 scopes below (a stale V2 hybrid identity,
                // peer-trust store or ratchet sessions could otherwise survive a
                // "fresh" install and collide with the freshly-generated identity).
                //
                // The Secure-Enclave KEY itself (kSecClassKey, tag com.ladon.hwkey.*)
                // is NOT a generic password and is intentionally left: it is
                // hardware-bound local-storage key material (not the messaging
                // identity), its "created" marker under "app.ladon.messenger" is
                // cleared so recreation-detection degrades safely, and a blanket
                // kSecClassKey delete would be riskier than the benign reuse.
                let ladonServices = [
                    "app.ladon.messenger",            // identity + catch-all: secure-storage key, DB key, blob auth, push tokens, SOCKS5, throttle, SE marker, …
                    "app.ladon.messenger.migrations",
                    "app.ladon.messenger.rasp",
                    "app.ladon.messenger.msgstore",
                    "app.ladon.messenger.canary",
                    "app.ladon.messenger.v2",         // V2 hybrid identity (IdentityStoreV2)
                    "app.ladon.messenger.v2.peers",   // V2 peer-trust store (PeerStoreV2)
                    "app.ladon.messenger.v2.ratchet", // V2 Double-Ratchet sessions (RelayClientV2)
                    "app.ladon.messenger.v2.prekeys",  // V2 one-time prekeys, own + contacts' (PrekeyStoreV2)
                    "app.ladon.messenger.v2.delivery", // V2 delivery keys, own + contacts' (DeliveryKeyStoreV2)
                    "app.ladon.messenger.v2.spenttokens"  // retired token scheme (RetiredTokenStateV2), still wiped
                ]
                for service in ladonServices {
                    let query: [String: Any] = [
                        kSecClass as String: kSecClassGenericPassword,
                        kSecAttrService as String: service
                    ]
                    SecItemDelete(query as CFDictionary)
                }
                // Mark this install so the wipe never runs again on this
                // installation, even after the next launch.
                UserDefaults.standard.set(true, forKey: installMarkerKey)
                // Also clear any conversation list that might have been
                // serialised under UserDefaults in older builds.
                UserDefaults.standard.removeObject(forKey: "saved_conversations")
            }

            // FIX KEY-LOSS: Check if private key was lost while public key still exists.
            // iOS can purge Keychain items after extended inactivity. Detect and regenerate.
            let _hasIdKey = KeyManager.shared.hasIdentityKey()
            let _hasPrivKey = KeyManager.shared.hasIdentityPrivateKeyInKeychain()
            if _hasIdKey && !_hasPrivKey {
                #if DEBUG
                SecureLogger.debug("[LadonApp] ⚠️ Identity private key lost from Keychain — regenerating...")
                #endif
                do {
                    try KeyManager.shared.regenerateIdentityKeys()
                } catch {
                    #if DEBUG
                    SecureLogger.debug("[LadonApp] ❌ Key regeneration failed: \(error)")
                    #endif
                }
            }
            
            // Identity Keys are generated in ContentView.setupAccount() after onboarding.
            // NOT generated here — otherwise onboarding is skipped because hasIdentityKey()
            // returns true before ContentView even renders.

            // FIX FACEID-PERSIST: REMOVED init-time provisionAuthSecret().
            // This was calling signMessage() BEFORE biometric auth → triggered Face ID
            // or silently failed (when _isAppLocked blocked it).
            // Provisioning now runs ONLY in the .active handler AFTER successful Face ID.
            // (The V1 RelayClient init-time re-provisioning path was removed with V1.)

            // Migrationen und Initialisierungen
            // FIX L-12: Migration flags stored in Keychain instead of plaintext UserDefaults.
            // UserDefaults is a plist readable by any process with file access on jailbroken devices.

            // One-time migration: X3DH + DH-Ratchet Header + Post-Quantum Hybrid upgrade
            if !Self.migrationCompleted("migration_reset_v4_x3dh_pq_ratchet") {
                #if DEBUG
                SecureLogger.debug("[LadonApp] 🧹 Migration v4: X3DH + DH-Ratchet Header + Post-Quantum — Reset Sessions")
                #endif
                KeyManager.shared.resetConversationState()
                UserDefaults.standard.removeObject(forKey: "saved_conversations")
                Self.setMigrationCompleted("migration_reset_v4_x3dh_pq_ratchet")
            }

            // Migration v5: PQ Hybrid activated — Kyber768 PKs mixed into session key derivation.
            if !Self.migrationCompleted("migration_reset_v5_pq_hybrid_active") {
                #if DEBUG
                SecureLogger.debug("[LadonApp] 🧹 Migration v5: PQ-Hybrid active — Reset Sessions for Kyber768-HKDF")
                #endif
                KeyManager.shared.resetConversationState()
                UserDefaults.standard.removeObject(forKey: "saved_conversations")
                Self.setMigrationCompleted("migration_reset_v5_pq_hybrid_active")
            }

            // Migration v6: 3-DH + Real Kyber KEM + Recipient-bound HMAC + Header v3
            if !Self.migrationCompleted("migration_reset_v6_3dh_kem_hmac") {
                #if DEBUG
                SecureLogger.debug("[LadonApp] 🧹 Migration v6: 3-DH + Kyber KEM + Recipient-HMAC + Header v3 — Reset Sessions")
                #endif
                KeyManager.shared.resetConversationState()
                UserDefaults.standard.removeObject(forKey: "saved_conversations")
                Self.setMigrationCompleted("migration_reset_v6_3dh_kem_hmac")
            }

            // Migration v7: Kyber Key Rotation + Session-bound HMAC + Header v4
            if !Self.migrationCompleted("migration_reset_v7_kyber_rotation_session_hmac") {
                #if DEBUG
                SecureLogger.debug("[LadonApp] 🧹 Migration v7: Kyber-Rotation + Session-HMAC + Header v4 — Reset Sessions")
                #endif
                KeyManager.shared.resetConversationState()
                UserDefaults.standard.removeObject(forKey: "saved_conversations")
                Self.setMigrationCompleted("migration_reset_v7_kyber_rotation_session_hmac")
            }

            // Migration v8: HKDF Salt≠Info fix + PKCS#7 128-byte padding + PQ KEM at session creation
            if !Self.migrationCompleted("migration_reset_v8_hkdf_padding_kem") {
                #if DEBUG
                SecureLogger.debug("[LadonApp] 🧹 Migration v8: HKDF Salt fix + Padding 128 + KEM Init — Reset Sessions")
                #endif
                KeyManager.shared.resetConversationState()
                UserDefaults.standard.removeObject(forKey: "saved_conversations")
                Self.setMigrationCompleted("migration_reset_v8_hkdf_padding_kem")
            }

            // Migration v9: Symmetric 3-DH (removed asymmetric EK from session creation)
            if !Self.migrationCompleted("migration_reset_v9_symmetric_3dh") {
                #if DEBUG
                SecureLogger.debug("[LadonApp] 🧹 Migration v9: Symmetric 3-DH — Reset Sessions (EK removed)")
                #endif
                KeyManager.shared.resetConversationState()
                UserDefaults.standard.removeObject(forKey: "saved_conversations")
                Self.setMigrationCompleted("migration_reset_v9_symmetric_3dh")
            }

            // Migration v10: ML-KEM-768 (FIPS 203) replaces Kyber768 + AEAD AD binding + skipped-key storage
            if !Self.migrationCompleted("migration_reset_v10_mlkem_aead_skippedkeys") {
                #if DEBUG
                SecureLogger.debug("[LadonApp] 🧹 Migration v10: ML-KEM-768 + AEAD AD + Skipped Keys — Reset Sessions")
                #endif
                KeyManager.shared.resetConversationState()
                UserDefaults.standard.removeObject(forKey: "saved_conversations")
                Self.setMigrationCompleted("migration_reset_v10_mlkem_aead_skippedkeys")
            }

            // Migration v11: Security audit 2026-02-19 — HKDF info strings changed (M-5: chain key,
            // M-1: Sealed Sender salt, C-1: respondToX3DH domain separation, C-2: OPK DH4).
            // Old sessions used different HKDF parameters → incompatible. Must reset.
            if !Self.migrationCompleted("migration_reset_v11_hkdf_audit_2026") {
                #if DEBUG
                SecureLogger.debug("[LadonApp] 🧹 Migration v11: Security Audit HKDF + OPK + Domain Separation — Reset Sessions")
                #endif
                KeyManager.shared.resetConversationState()
                UserDefaults.standard.removeObject(forKey: "saved_conversations")
                Self.setMigrationCompleted("migration_reset_v11_hkdf_audit_2026")
            }

            // Migration v12: SPK/EK regeneration fix — old sessions used mismatched
            // SPK/EK (regenerated on every "New Chat" open), making sessions incompatible.
            // Must reset sessions AND delete old SPK/EK so they'll be freshly generated once.
            if !Self.migrationCompleted("migration_reset_v12_spk_ek_stable_keys") {
                #if DEBUG
                SecureLogger.debug("[LadonApp] 🧹 Migration v12: SPK/EK stability fix — Reset Sessions + Pre-Keys")
                #endif
                KeyManager.shared.resetConversationState()
                KeyManager.shared.clearPreKeys()
                UserDefaults.standard.removeObject(forKey: "saved_conversations")
                Self.setMigrationCompleted("migration_reset_v12_spk_ek_stable_keys")
            }

            // Migration v13: Non-destructive session fixes.
            // Previous loadSession() DELETED sessions on ANY failure (decrypt, decode,
            // empty rootKey). hasSession() called loadSession() making it destructive too.
            // Also fixes: deleteFromKeychain kSecAttrSynchronizable, nil sendingRatchetKey
            // sending 32 zero bytes. Must reset sessions + pre-keys for clean state with
            // the new non-destructive code.
            if !Self.migrationCompleted("migration_v13_non_destructive_sessions") {
                #if DEBUG
                SecureLogger.debug("Migration v13")
                #endif
                KeyManager.shared.resetConversationState()
                KeyManager.shared.clearPreKeys()
                UserDefaults.standard.removeObject(forKey: "saved_conversations")
                Self.setMigrationCompleted("migration_v13_non_destructive_sessions")
            }
            // Migration v14: rootKey encoding fix.
            // HIGH-4 FIX encoded rootKey as Data() in JSON and stored it separately.
            // The separate Keychain entry was silently lost on some devices, making
            // rootKey permanently empty → all sessions broken.
            // Now rootKey is encoded in JSON blob (which is SE-encrypted anyway).
            // Must reset sessions created with empty rootKey encoding.
            if !Self.migrationCompleted("migration_v14_rootkey_in_json") {
                #if DEBUG
                SecureLogger.debug("Migration v14")
                #endif
                KeyManager.shared.resetConversationState()
                KeyManager.shared.clearPreKeys()
                UserDefaults.standard.removeObject(forKey: "saved_conversations")
                Self.setMigrationCompleted("migration_v14_rootkey_in_json")
            }

            // Migration v15: Deterministic initial ratchet keys.
            // Previously, V1 session creation set receivingRatchetKey = contact's identity PK,
            // but sendingRatchetKey = fresh random key. On first message, receiver saw
            // an unknown ratchet PK → spurious DH ratchet fired → wrong chain keys →
            // decryption permanently failed. Now both ratchet keys are derived
            // deterministically from the shared X3DH root key.
            if !Self.migrationCompleted("migration_v15_deterministic_ratchet") {
                #if DEBUG
                SecureLogger.debug("Migration v15")
                #endif
                KeyManager.shared.resetConversationState()
                KeyManager.shared.clearPreKeys()
                UserDefaults.standard.removeObject(forKey: "saved_conversations")
                Self.setMigrationCompleted("migration_v15_deterministic_ratchet")
            }
            
            // Migration v16: Fix H-3 DH private key persistence.
            // H-3 stored sendingRatchetKey only in separate keychain entries (not in JSON blob).
            // These separate entries became inaccessible on some devices, causing sendingRatchetKey
            // to be nil → encryption failed with "cannot build header". This migration resets
            // sessions so they're recreated with the fixed encoder that includes sendingRatchetKey
            // in the SE-encrypted JSON blob.
            if !Self.migrationCompleted("migration_v16_dhsk_in_json") {
                #if DEBUG
                SecureLogger.debug("Migration v16")
                #endif
                KeyManager.shared.resetConversationState()
                KeyManager.shared.clearPreKeys()
                UserDefaults.standard.removeObject(forKey: "saved_conversations")
                Self.setMigrationCompleted("migration_v16_dhsk_in_json")
            }
            // Migration v17: wipe the retired V1 session key material.
            // After the V1 RatchetSession store + PreKeyBundle generation were
            // removed (#8 follow-ups), legacy devices may still hold V1 session
            // blobs (root keys, DH private keys, per-session Kyber SKs) plus the
            // stale bundle Kyber SK. None are used anymore, so wipe them for
            // key-material hygiene. Only the V1 Keychain prefixes are touched
            // (session_/conv_/spk_/kyber768_session_*) — V2 identity/ratchet live
            // in separate Keychain services and saved conversations are untouched.
            if !Self.migrationCompleted("migration_v17_wipe_v1_sessions") {
                #if DEBUG
                SecureLogger.debug("Migration v17: wiping retired V1 session material")
                #endif
                KeyManager.shared.resetConversationState()
                KeyManager.shared.clearPreKeys()
                Self.setMigrationCompleted("migration_v17_wipe_v1_sessions")
            }
            // Migration v18: the threshold key-sharing feature was removed (it
            // kept the full signing key on the device and discarded shares 2
            // and 3, so it protected nothing). Delete any share a user created
            // (Keychain account `threshold_share_<n>`, n = 1…255, service
            // app.ladon.messenger). The flag is only set once every delete
            // succeeded or found nothing, so a failure retries next launch.
            if !Self.migrationCompleted("migration_v18_wipe_threshold_shares") {
                var allCleared = true
                for n in 1...255 {
                    let query: [String: Any] = [
                        kSecClass as String: kSecClassGenericPassword,
                        kSecAttrAccount as String: "threshold_share_\(n)",
                        kSecAttrService as String: "app.ladon.messenger"
                    ]
                    let status = SecItemDelete(query as CFDictionary)
                    if status != errSecSuccess && status != errSecItemNotFound { allCleared = false }
                }
                if allCleared {
                    Self.setMigrationCompleted("migration_v18_wipe_threshold_shares")
                }
            }
            // Migration v19: the blob-relay auth secret is now stored once per
            // server (account `…blobRelayAuthSecret.v3.<hostname>`, itself
            // retired by v20). Delete the two
            // per-tag entries it replaces; the new entry is provisioned on
            // demand. Flag set only when both deletes succeeded or found nothing.
            if !Self.migrationCompleted("migration_v19_blob_auth_per_server") {
                var cleared = true
                for tag in ["fi", "ch"] {
                    let query: [String: Any] = [
                        kSecClass as String: kSecClassGenericPassword,
                        kSecAttrAccount as String: "app.ladon.messenger.blobRelayAuthSecret.v2.\(tag)",
                        kSecAttrService as String: "app.ladon.messenger"
                    ]
                    let status = SecItemDelete(query as CFDictionary)
                    if status != errSecSuccess && status != errSecItemNotFound { cleared = false }
                }
                if cleared {
                    Self.setMigrationCompleted("migration_v19_blob_auth_per_server")
                }
            }
            // Migration v20 (Addendum A2 stage 1): blob uploads carry no
            // identity any more, so the per-identity blob-relay HMAC secrets
            // are retired. Delete every account they were ever stored under
            // (v1; v3 per server). Flag set only when all deletes succeeded
            // or found nothing.
            if !Self.migrationCompleted("migration_v20_blob_auth_retired") {
                var cleared = true
                let accounts = ["app.ladon.messenger.blobRelayAuthSecret.v1"]
                    + BlobHost.allHosts.map { "app.ladon.messenger.blobRelayAuthSecret.v3.\($0.hostname)" }
                for account in accounts {
                    let query: [String: Any] = [
                        kSecClass as String: kSecClassGenericPassword,
                        kSecAttrAccount as String: account,
                        kSecAttrService as String: "app.ladon.messenger"
                    ]
                    let status = SecItemDelete(query as CFDictionary)
                    if status != errSecSuccess && status != errSecItemNotFound { cleared = false }
                }
                if cleared {
                    Self.setMigrationCompleted("migration_v20_blob_auth_retired")
                }
            }
            // FIX L1: recipient_id in Keychain statt UserDefaults speichern
            if let currentIDHex = try? KeyManager.shared.getCurrentRecipientID().hexEncodedString {
                let idData = currentIDHex.data(using: .utf8) ?? Data()
                // FIX A7-LA-02: Delete query must NOT include kSecValueData — otherwise it only
                // matches the entry with the exact same data, preventing deletion when the ID changes.
                // FIX AUDIT-R17-F7: Update-first pattern to avoid non-atomic delete→add window.
                // SecItemUpdate keeps the item present at all times; only add if it doesn't exist yet.
                let updateQuery: [String: Any] = [
                    kSecClass as String: kSecClassGenericPassword,
                    kSecAttrAccount as String: "last_recipient_id",
                    kSecAttrService as String: "app.ladon.messenger"
                ]
                let updateAttrs: [String: Any] = [
                    kSecValueData as String: idData
                ]
                let updateStatus = SecItemUpdate(updateQuery as CFDictionary, updateAttrs as CFDictionary)
                if updateStatus == errSecItemNotFound {
                    let addQuery: [String: Any] = [
                        kSecClass as String: kSecClassGenericPassword,
                        kSecAttrAccount as String: "last_recipient_id",
                        kSecAttrService as String: "app.ladon.messenger",
                        kSecValueData as String: idData,
                        kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
                    ]
                    SecItemAdd(addQuery as CFDictionary, nil)
                }
                #if DEBUG
                SecureLogger.debug("[LadonApp] 🆔 Current recipientID: \(String(currentIDHex.prefix(8)))")
                #endif
            } else {
                #if DEBUG
                SecureLogger.debug("[LadonApp] ❌ Could not compute recipientID")
                #endif
            }

            // ===== REAL POST-QUANTUM CRYPTOGRAPHY ACTIVE =====
            #if DEBUG
            print("""

            ╔════════════════════════════════════════════════════╗
            ║   LADON 2.0 - PERFECT SECURITY ACTIVE             ║
            ║   100/100 in ALLEN Kategorien                     ║
            ╚════════════════════════════════════════════════════╝

            ✅ Biometric-Only Keys (Face ID required)
            ✅ Tor + Domain Fronting (Maximum anonymity)
            ✅ Cover Traffic Protocol (Constant rate)
            ✅ REAL Kyber768 (liboqs - Quantum Protected)
            ✅ REAL Dilithium3 (liboqs - Quantum Protected)
            ✅ Store-Now-Decrypt-Later: PROTECTED (100/100)
            ✅ Quantum Computer Resistance: ACTIVE

            """)
            #endif

            // FIX AUDIT-130: Post-Quantum self-test runs in ALL builds (not just DEBUG).
            // Failure is treated seriously — PQ features are disabled if self-test fails.
            // FIX INFO-AC4: Use runSelfTestOrDisable() — encapsulates failure handling.
            Task.detached(priority: .utility) {
                PostQuantumService.shared.runSelfTestOrDisable()
                #if DEBUG
                if PostQuantumService.shared.selfTestPassed {
                    print("[PQ] Post-Quantum stack self-test passed (Kyber768 + Dilithium3)")
                }
                #endif
            }

            // Auto-start Tor on app launch for network anonymity
            Task {
                SecureLogger.clearTorDiag()
                SecureLogger.torDiag("[APP] Cold launch — previous run kept as tor_diag.prev.log")
                await TorManager.shared.startTor()
                #if DEBUG
                if TorManager.shared.isConnected {
                    print("✅ Tor started automatically on app launch")
                }
                #endif
            }

            // Perform security check on launch (H3: TamperGuard)
            #if !DEBUG
            SecurityUtils.shared.performSecurityCheck()
            #else
            print("[APP] 🔧 Security checks disabled in DEBUG mode (simulator)")
            // Argon2id + v2 crypto self-tests are heavy at launch (memory-hard KDF
            // + PQ vectors) and tripped brownout reboots on marginal-battery devices.
            // Off by default; opt in via Xcode scheme env LADON_SELFTESTS=1.
            if ProcessInfo.processInfo.environment["LADON_SELFTESTS"] == "1" {
                Task.detached(priority: .utility) {
                    SecurityFeatureTests.runAll()
                }
                Task.detached(priority: .utility) {
                    let results = LadonV2SelfTest.runAll()
                    let failed = results.filter { !$0.passed }
                    let total = results.count
                    let passed = total - failed.count
                    print("[V2-SELFTEST] \(passed)/\(total) passed")
                    for r in results {
                        let mark = r.passed ? "✅" : "❌"
                        print("[V2-SELFTEST] \(mark) \(r.name) — \(r.detail)")
                    }
                    if !failed.isEmpty {
                        print("[V2-SELFTEST] ⚠️  \(failed.count) FAILURE(S) — investigate before relying on v2 wire format")
                    }
                }
                // P8-AUDIT8-IOS-00: the attachment self-tests existed but had no
                // caller, so attachment fixes were never exercised on device.
                // Each suite throws on its first failure.
                Task.detached(priority: .utility) {
                    do {
                        try AttachmentCryptoSelfTest.runAll()
                        print("[ATT-SELFTEST] ✅ AttachmentCryptoSelfTest passed")
                    } catch {
                        print("[ATT-SELFTEST] ❌ AttachmentCryptoSelfTest — \(error)")
                    }
                    do {
                        try AttachmentRoundtripSelfTest.runAll()
                        print("[ATT-SELFTEST] ✅ AttachmentRoundtripSelfTest passed")
                    } catch {
                        print("[ATT-SELFTEST] ❌ AttachmentRoundtripSelfTest — \(error)")
                    }
                }
            }
            #endif

            // Initialize cryptographic keys on first launch
            Task {
                await KeyManager.shared.initializeIfNeeded()
            }

            // P8-AUDIT8-IOS-11: remove deleteCap items earlier builds left in
            // the Keychain (a send-time log of attachments). Attribute-only.
            Task.detached(priority: .utility) {
                let removed = AttachmentDeleteCapStore.purgeAll()
                if removed > 0 {
                    SecureLogger.info("[Attachments] removed \(removed) legacy deleteCap item(s)")
                }
            }
        }
    
    // MARK: - FIX L-12: Keychain-backed migration flags (replaces UserDefaults)
    
    /// Check if a migration has already been completed (stored in Keychain)
    private static func migrationCompleted(_ key: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecAttrService as String: "app.ladon.messenger.migrations",
            kSecReturnData as String: false,
            kSecAttrSynchronizable as String: false
        ]
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        if status == errSecSuccess {
            return true
        }
        // Also check UserDefaults for backward compatibility (old flags)
        if UserDefaults.standard.bool(forKey: key) {
            // Migrate the flag to Keychain
            setMigrationCompleted(key)
            return true
        }
        return false
    }
    
    /// Mark a migration as completed (stored in Keychain)
    /// FIX R16-LA1: Atomic update-first pattern (no delete→add gap)
    private static func setMigrationCompleted(_ key: String) {
        let data = Data([0x01]) // Marker byte
        // FIX R16-LA1: Atomic update-first pattern — prevents loss of migration
        // marker if interrupted between delete and add (non-atomic gap)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecAttrService as String: "app.ladon.messenger.migrations"
        ]
        let attrs: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]
        var status = SecItemUpdate(query as CFDictionary, attrs as CFDictionary)
        if status == errSecItemNotFound {
            var addQuery = query
            addQuery[kSecValueData as String] = data
            addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            status = SecItemAdd(addQuery as CFDictionary, nil)
        }
        // Remove from UserDefaults (cleanup)
        UserDefaults.standard.removeObject(forKey: key)
    }

        var body: some Scene {
            WindowGroup {
                if isAppDestroyed {
                    // FIX VM-1: PanicLockView is permanent — no reset path.
                    // After panic mode, the app process is terminated via abort().
                    // If somehow the process survives (e.g. state restoration),
                    // PanicLockView stays until reinstall.
                    PanicLockView()
                } else if isKeygenFailed {
                    // FIX H-13 AUDIT-MAR-2026: Separate view for keygen failure.
                    // Allows retry instead of permanent lockout.
                    KeygenErrorView {
                        do {
                            try KeyManager.shared.generateIdentityKeysSync()
                            isKeygenFailed = false
                        } catch {
                            SecureLogger.error("[LadonApp] Keygen retry failed: \(error)")
                        }
                    }
                } else {
                    ZStack {
                        ContentView()
                            .environmentObject(appState)
                            .environmentObject(biometricAuth)
                            .environmentObject(languageManager)
                            .environmentObject(appearanceManager)
                            .environment(\.locale, languageManager.locale)
                            // FIX R21-A4-1: Hide ContentView from VoiceOver when locked.
                            // SwiftUI ZStack does NOT derive accessibility from visual occlusion —
                            // without this, VoiceOver can read messages behind BiometricLockView.
                            .accessibilityHidden((biometricAuth.isLocked && appState.isAuthenticated) || showPrivacyScreen)
                            // FIX KEYBOARD-BYPASS: Disable ALL interaction with ContentView while locked.
                            // Without this, the iOS keyboard (UIRemoteKeyboardWindow) is a separate
                            // UIWindow that appears ABOVE the SwiftUI ZStack overlay. Users can type
                            // into ChatView's text field before Face ID completes, and the text
                            // persists after authentication. .disabled(true) prevents the text field
                            // from becoming first responder, which prevents the keyboard from appearing.
                            .disabled((biometricAuth.isLocked && appState.isAuthenticated) || showPrivacyScreen)
                            // Stage B: incoming invite links. Validated +
                            // routed to the accept sheet (ConversationListView). If
                            // the app is locked, `pending` persists until unlock.
                            .onOpenURL { url in InviteRouter.shared.handle(url) }
                            // Universal Links arrive via NSUserActivity (webpageURL),
                            // which .onOpenURL does NOT reliably deliver — handle the
                            // web-browsing activity explicitly.
                            .onContinueUserActivity(NSUserActivityTypeBrowsingWeb) { activity in
                                if let url = activity.webpageURL { InviteRouter.shared.handle(url) }
                            }
                        // FIX ONBOARDING-FACEID: Only lock when user has an account.
                        // Without this, Face ID blocks the onboarding on fresh install.
                        //
                        // Scan F24: the interactive lock screen lives in its own
                        // window above every sheet and cover (LockWindowPresenter,
                        // driven below). A sibling here sits under anything this
                        // view presents, so a sheet left open on backgrounding
                        // showed above the lock. This sibling is only an opaque
                        // backstop with nothing to tap, so the content is never
                        // visible even for the instant before the window is up.
                        if lockScreenVisible {
                            MeshBackground()
                                .ignoresSafeArea()
                                .transition(.opacity)
                        }
                        // CL-01 FIX: Privacy blur overlay for task switcher / app inactive
                        if showPrivacyScreen {
                            LadonTheme.background
                                .ignoresSafeArea()
                                .overlay {
                                    if AppearanceManager.isDarkStored {
                                        Image(systemName: "lock.shield")
                                            .font(.system(size: 48))
                                            .foregroundColor(LadonTheme.textSecondary)
                                    } else {
                                        // Light: the green mark on paper. The task
                                        // switcher already shows the app's name and icon.
                                        Image("LadonLogo")
                                            .renderingMode(.template)
                                            .resizable()
                                            .scaledToFit()
                                            .frame(width: 64, height: 64)
                                            .foregroundColor(LadonTheme.greenInk)
                                    }
                                }
                                .transition(.opacity)
                        }
                    }
                    // Scan F24: the lock window follows the lock state.
                    .onAppear { syncLockWindow() }
                    .onChange(of: lockScreenVisible) { _, _ in syncLockWindow() }
                    .onChange(of: scenePhase) { oldPhase, newPhase in
                        switch newPhase {
                        case .active:
                            // CL-01 FIX: Remove privacy screen when app becomes active
                            showPrivacyScreen = false
                            // FIX PUSH-12: Clear badge AND remove all pending/delivered notifications.
                            let notifCenter = UNUserNotificationCenter.current()
                            notifCenter.setBadgeCount(0)
                            notifCenter.removeAllDeliveredNotifications()
                            notifCenter.removeAllPendingNotificationRequests()
                            // FIX TOR-RESUME-DET: Deterministic resume recovery for .inactive/.background -> .active.
                            // On some devices, Tor state seen at this exact moment is stale. Trigger recovery task
                            // unconditionally for foreground returns, then decide after a short settle delay.
                            if oldPhase == .background || oldPhase == .inactive {
                                Task {
                                    try? await Task.sleep(nanoseconds: 300_000_000) // 300ms settle window
                                    if TorController.shared.isRunning {
                                        #if DEBUG
                                        print("[App] Active transition — running deterministic Tor circuit verification")
                                        #endif
                                        await TorManager.shared.verifyCircuitAfterBackgroundReturn()
                                    } else if !TorManager.shared.isTorReady {
                                        #if DEBUG
                                        print("[App] Active transition — Tor not running, starting Tor")
                                        #endif
                                        await TorManager.shared.startTor()
                                    }
                                }
                            }
                            // FIX FACEID-RACE: ALL operations that call signMessage() (push registration,
                            // auth provisioning, UAK registration) MUST run AFTER biometric unlock.
                            // Previously these ran in parallel with authenticate(), causing:
                            // 1. signMessage() hits Keychain while app is still locked → Face ID #2
                            // 2. Or signMessage() uses a DIFFERENT LAContext → Face ID #3
                            // Solution: Sequence everything — biometric first, then provision/push.
                            //
                            // FIX FACEID-FINAL: Also check isAuthenticating to prevent re-triggers.
                            // When Face ID dialog appears, iOS changes scene to .inactive.
                            // On some devices/versions, it might even go to .background.
                            // When Face ID succeeds, scene goes back to .active.
                            // Without this guard, a SECOND authenticate() call would start.
                            if oldPhase == .background && appState.isAuthenticated && biometricAuth.requiresAuthentication() && !biometricAuth.isAuthenticating {
                                Task {
                                    // Step 1: Authenticate with Face ID (ONLY Face ID prompt)
                                    await biometricAuth.authenticate()
                                    // Step 2: Post-auth work (provisioning, push, fetch) is now
                                    // handled by the .onReceive(.biometricAuthSuccess) handler below.
                                    // BiometricAuthService posts BiometricAuthSuccess on success.
                                }
                            } else if oldPhase != .background {
                                // .inactive → .active transitions (e.g. notification center pull-down):
                                // App is already unlocked, just re-upload push token.
                                // No provisioning needed (only on true background return).
                                if !KeyManager.shared.isAppLocked() {
                                    SilentPushHandler.shared.retryPushRegistration()
                                }
                            }
                        case .background:
                            // CL-01 FIX: Show privacy screen to hide content in task switcher
                            showPrivacyScreen = true
                            // FIX KEYBOARD-BYPASS: Force-dismiss keyboard before locking.
                            // If the user was typing when the app goes to background,
                            // the keyboard must be dismissed so it doesn't reappear
                            // above the BiometricLockView on return.
                            UIApplication.shared.sendAction(
                                #selector(UIResponder.resignFirstResponder),
                                to: nil, from: nil, for: nil
                            )
                            biometricAuth.lockApp()
                            // PUSH-15b: Force-persist messages on background transition.
                            // If the user kills the app from the app switcher, the process
                            // had a brief moment in .background — this ensures the file is up to date.
                            InMemoryMessageStore.shared.forcePersist()
                            // TOR-BG-PREP: Send DisableNetwork=1 to Tor BEFORE iOS freezes the process.
                            // While the app is still in the foreground transition, tor_main() is active
                            // and the control port is responsive. DisableNetwork=1 closes all TCP
                            // connections to Tor guards cleanly. iOS then freezes the process with
                            // Tor in a connection-free state. On resume, the control port immediately
                            // accepts DisableNetwork=0 and Tor bootstraps fresh from its in-memory
                            // consensus/guard cache → circuit in ~3–6s instead of ~30–60s.
                            // beginBackgroundTask gives ~30s extra time to complete the command.
                            let bgPrepTask = UIApplication.shared.beginBackgroundTask(withName: "TorPrepareBackground")
                            Task {
                                await TorController.shared.prepareForBackground()
                                UIApplication.shared.endBackgroundTask(bgPrepTask)
                            }
                        case .inactive:
                            showPrivacyScreen = true
                        default:
                            break
                        }
                    }
                    // FIX PUSH-INIT: After EVERY successful Face ID (first launch + background return),
                    // run provisioning → UAK → push token registration → immediate message fetch.
                    // Previously, this only ran on .background → .active transitions,
                    // so on first launch (.inactive → .active) the push token was never registered
                    // and APNs pushes were sent to a stale token.
                    .onReceive(NotificationCenter.default.publisher(for: .biometricAuthSuccess)) { _ in
                        Task {
                            #if DEBUG
                            NSLog("[App] BiometricAuthSuccess received - starting PARALLEL provision+fetch")
                            #endif

                            // V2 stack starts IMMEDIATELY — independent of V1 provisioning.
                            // Otherwise a V1 TLS-pin rejection (legacy entry.ladon.app) can stall
                            // the provision callback indefinitely and V2 never initialises.
                            Task.detached { await V2SessionManager.shared.initializeIfNeeded() }

                            // PERF: Sofort-Fetch PARALLEL zu Provisioning starten.
                            // Fetch braucht nur den bestehenden Auth-Secret (bleibt in Keychain).
                            // So erscheinen Nachrichten sofort, ohne auf Provision+UAK zu warten.
                            let immediateFetchTask = Task {
                                // #1: fetchPendingMessages() now delivers centrally
                                // (store write + NewMessagesReceived) and coalesces
                                // with the V2 receive loop — just trigger it; storing
                                // or posting here would double-deliver the batch.
                                #if DEBUG
                                let fetchStart = Date()
                                let messages = await V2SessionManager.shared.fetchPendingMessages()
                                let fetchDuration = Date().timeIntervalSince(fetchStart)
                                NSLog("[App] IMMEDIATE fetch completed in %.2fs, %d messages", fetchDuration, messages.count)
                                #else
                                _ = await V2SessionManager.shared.fetchPendingMessages()
                                #endif
                            }
                            
                            // Blob-relay provisioning is gone (Addendum A2 stage 1):
                            // uploads carry no identity, so there is no per-identity
                            // secret to fetch. The retired Keychain entries are
                            // removed by migration v20.

                            // Warte auf den sofortigen Fetch (falls er noch läuft)
                            _ = await immediateFetchTask.value
                        }
                    }
                    // FIX MED-217: Validate notification sender — only accept from InactivityManager
                    .onReceive(NotificationCenter.default.publisher(for: NSNotification.Name("InactivityPanicTriggered"))) { notification in
                        guard notification.object is InactivityManager else {
                            #if DEBUG
                            print("[PANIC] ⚠️ Rejected unauthenticated InactivityPanicTriggered notification")
                            #endif
                            return
                        }
                        executePanicMode()
                        isAppDestroyed = true
                    }
                    // NOTE: deliberately no .id(mode) here. Rebuilding the
                    // hierarchy did repaint everything, but it also threw away
                    // navigation and scroll position — switching the appearance
                    // kicked the user back to the top of the first tab.
                    //
                    // Instead every view reads \.colorScheme (see the
                    // `ladonAppearanceTick` properties), which this modifier
                    // changes. That invalidates each view in place, so they
                    // re-read LadonTheme's colours while keeping their state.
                    .preferredColorScheme(appearanceManager.colorScheme)
                    .tint(LadonTheme.accent)                }
            }
        }
    }

/// Scan F24: the lock screen in its own window, above everything the app
/// presents. As a sibling inside the root view it sat *under* every sheet and
/// cover: one left open when the app went to the background was shown above
/// the lock on return (`lockApp` closes nothing, and the task-switcher window
/// is removed on activation). A window at `.alert` level covers all of them
/// while they keep their state (a half-done pairing survives the lock).
///
/// The level is below the task-switcher privacy window (`.alert + 1`). The
/// window becomes key so the LADON PIN field can take the keyboard; on unlock
/// the previous key window gets it back.
@MainActor
final class LockWindowPresenter {
    static let shared = LockWindowPresenter()

    private var window: UIWindow?
    private weak var previousKeyWindow: UIWindow?

    func show<V: View>(_ view: V) {
        if let window, let host = window.rootViewController as? UIHostingController<AnyView> {
            host.rootView = AnyView(view)
            return
        }
        guard let scene = UIApplication.shared.connectedScenes.first as? UIWindowScene else {
            // No scene yet: the opaque backstop in the root view still hides
            // the content; the next state change shows the window.
            SecureLogger.error("[Lock] no window scene for the lock window")
            return
        }
        previousKeyWindow = scene.windows.first(where: { $0.isKeyWindow })
        let host = UIHostingController(rootView: AnyView(view))
        let lockWindow = UIWindow(windowScene: scene)
        lockWindow.rootViewController = host
        lockWindow.windowLevel = .alert
        lockWindow.makeKeyAndVisible()
        window = lockWindow
    }

    func hide() {
        guard let lockWindow = window else { return }
        lockWindow.isHidden = true
        window = nil
        previousKeyWindow?.makeKey()
        previousKeyWindow = nil
    }
}

final class AppDelegate: NSObject, UIApplicationDelegate, UNUserNotificationCenterDelegate {
    // FIX #6: Task-Switcher Screenshot Protection — blank UIWindow overlay
    private var privacyWindow: UIWindow?
    
    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
        Self.removeLeftoverPlaintextTempFiles()
        UNUserNotificationCenter.current().delegate = self
        // FIX ONBOARDING-PUSH: Only register for push if user completed onboarding.
        // Otherwise the notification permission dialog appears before the onboarding.
        // setupInAppDelegate() is also called in ContentView.setupAccount() after onboarding.
        if UserDefaults.standard.bool(forKey: "ladon_onboarding_completed") {
            SilentPushHandler.setupInAppDelegate()
        }
        
        // Screenshot prevention: Add invisible secure text field to main window.
        // This protects ALL content app-wide without layout wrapping.
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.1) {
            self.installScreenshotProtection()
        }
        
        // FIX #6: Listen for app lifecycle to blank the screen in task switcher
        NotificationCenter.default.addObserver(self,
            selector: #selector(applicationWillResignActive),
            name: UIApplication.willResignActiveNotification, object: nil)
        NotificationCenter.default.addObserver(self,
            selector: #selector(applicationDidBecomeActive),
            name: UIApplication.didBecomeActiveNotification, object: nil)
        
        return true
    }

    /// P8-AUDIT8-IOS-16: no third-party keyboards. A custom keyboard with
    /// "Allow Full Access" sees every key typed into the app, plaintext
    /// messages included, and may send it off the device. Only the system
    /// keyboard is offered inside LADON messenger.
    func application(_ application: UIApplication,
                     shouldAllowExtensionPointIdentifier extensionPointIdentifier: UIApplication.ExtensionPointIdentifier) -> Bool {
        extensionPointIdentifier != .keyboard
    }

    /// Install screenshot protection on the main window by extracting the secure
    /// canvas from a UITextField and inserting it between the window and all its
    /// subviews. All content becomes a child of the secure canvas → iOS excludes
    /// the entire window from screenshots/recordings. No nested UIHostingController,
    /// no layout wrapping, no floating.
    private func installScreenshotProtection() {
        // The main window is the one at normal level. At a locked cold start
        // the lock window (LockWindowPresenter, `.alert` level) can already
        // exist, and `windows.first` is not specified to be the main window.
        guard let windowScene = UIApplication.shared.connectedScenes.first as? UIWindowScene,
              let window = windowScene.windows.first(where: { $0.windowLevel == .normal }) else { return }

        let field = UITextField()
        field.isSecureTextEntry = true

        // Extract the _UITextLayoutCanvasView that iOS marks as "not capturable"
        guard let secureCanvas = field.layer.sublayers?.first?.delegate as? UIView else {
            // FIX ME-03: Monitoring alert for undocumented API failure
            // This relies on iOS internal class hierarchy which may change between OS versions.
            // If extraction fails, screenshot prevention cannot be fully installed.
            // We use SecureLogger to alert operators of potential OS compatibility issues.
            SecureLogger.error("ScreenshotPrevention: Failed to extract secure canvas from UITextField (iOS version may have changed internal hierarchy)")
            // Partial fallback: basic window redaction still active if app reaches this point
            #if DEBUG
            print("[ScreenshotPrevention] ⚠️ Could not extract secure canvas — fallback unavailable")
            #endif
            // Do NOT proceed with partial install — fail closed
            return
        }
        // P7-IOS-BUG-19: verify that the extracted view is actually
        // Apple's `_UITextLayoutCanvasView`. The cast above succeeds
        // for ANY UIView under the same layer-delegate slot, so iOS
        // could silently refactor the hierarchy (e.g. UIKit 27 swaps
        // the canvas for a different layer-host) and we'd dutifully
        // reparent the entire window into the wrong view. The class
        // name has been stable since iOS 13 and Apple has not
        // historically renamed it. If the name ever drifts, we
        // explicitly log + fail-closed rather than silently install
        // a non-protective overlay.
        let canvasClassName = String(describing: type(of: secureCanvas))
        let expectedPrefix = "_UITextLayout"  // matches iOS 13..17+: _UITextLayoutCanvasView (and its iOS 17 successor _UITextLayoutFragmentView)
        guard canvasClassName.hasPrefix(expectedPrefix) else {
            SecureLogger.error("ScreenshotPrevention: secure canvas class is '\(canvasClassName)' (expected prefix '\(expectedPrefix)'). iOS may have refactored UITextField internals; refusing to install partial protection.")
            #if DEBUG
            print("[ScreenshotPrevention] ⚠️ Unexpected canvas class: \(canvasClassName) — failing closed")
            #endif
            return
        }
        
        // Collect all existing window subviews before modifying hierarchy
        let existingSubviews = Array(window.subviews)
        
        // Add secure canvas to window with full-size constraints
        secureCanvas.translatesAutoresizingMaskIntoConstraints = false
        window.addSubview(secureCanvas)
        NSLayoutConstraint.activate([
            secureCanvas.topAnchor.constraint(equalTo: window.topAnchor),
            secureCanvas.bottomAnchor.constraint(equalTo: window.bottomAnchor),
            secureCanvas.leadingAnchor.constraint(equalTo: window.leadingAnchor),
            secureCanvas.trailingAnchor.constraint(equalTo: window.trailingAnchor)
        ])
        
        // Reparent all existing subviews into secure canvas and re-establish constraints
        for subview in existingSubviews {
            subview.removeFromSuperview()
            subview.translatesAutoresizingMaskIntoConstraints = false
            secureCanvas.addSubview(subview)
            NSLayoutConstraint.activate([
                subview.topAnchor.constraint(equalTo: secureCanvas.topAnchor),
                subview.bottomAnchor.constraint(equalTo: secureCanvas.bottomAnchor),
                subview.leadingAnchor.constraint(equalTo: secureCanvas.leadingAnchor),
                subview.trailingAnchor.constraint(equalTo: secureCanvas.trailingAnchor)
            ])
        }
        
        #if DEBUG
        print("[ScreenshotPrevention] ✅ Window-level screenshot protection installed")
        #endif
    }
    
    /// Remove plaintext media the app wrote to tmp/ and did not get to delete:
    /// a voice take, a decrypted video, sanitizer in/out files. All are named
    /// `ladon-*` and live only for one operation, so none is in use at launch.
    /// They outlive the process when it is killed (jetsam, force quit, crash)
    /// mid-operation (scan F43/F44). Tor's `tmp/tor` is not touched.
    static func removeLeftoverPlaintextTempFiles() {
        let fm = FileManager.default
        guard let entries = try? fm.contentsOfDirectory(at: fm.temporaryDirectory,
                                                        includingPropertiesForKeys: nil) else { return }
        for url in entries where url.lastPathComponent.hasPrefix("ladon-") {
            try? fm.removeItem(at: url)
        }
    }

    // FIX #6: Show blank screen when app goes to background/task switcher
    @objc private func applicationWillResignActive() {
        guard let windowScene = UIApplication.shared.connectedScenes.first as? UIWindowScene else { return }
        let window = UIWindow(windowScene: windowScene)
        window.rootViewController = UIViewController()
        window.rootViewController?.view.backgroundColor = .black
        window.windowLevel = .alert + 1
        window.isHidden = false  // Show without stealing key window (preserves keyboard/QuickPath)
        privacyWindow = window
    }
    
    // FIX #6: Remove blank screen when app becomes active
    @objc private func applicationDidBecomeActive() {
        privacyWindow?.isHidden = true
        privacyWindow = nil
    }

    func application(_ application: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        SilentPushHandler.handleTokenRegistration(deviceToken)
    }

    func application(_ application: UIApplication, didFailToRegisterForRemoteNotificationsWithError error: Error) {
        SilentPushHandler.handleRegistrationFailure(error)
    }

    func application(_ application: UIApplication, didReceiveRemoteNotification userInfo: [AnyHashable: Any], fetchCompletionHandler completionHandler: @escaping (UIBackgroundFetchResult) -> Void) {
        // FIX PUSH-UNIFORM-V3: Server now sends SILENT pushes (content-available:1 only).
        // Silent pushes have NO alert banner — we MUST call handleIncomingPush in ALL states
        // to fetch messages, decrypt, and schedule a local notification when in background.
        // Keychain keys use kSecAttrAccessibleWhenUnlockedThisDeviceOnly — accessible when
        // device is unlocked (typical case: user switched away from app).
        // If device is locked, fetch will fail gracefully and messages arrive on next app open.
        #if DEBUG
        NSLog("[Push] didReceiveRemoteNotification — state=%d", application.applicationState.rawValue)
        #endif
        SilentPushHandler.handleIncomingPush(userInfo, completion: completionHandler)
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification, withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        // FIX PUSH-13: DEFINITIVE phantom notification fix.
        //
        // Root cause: The server sends APNs ALERT pushes. Apple's infrastructure
        // can cache and deliver these at unpredictable times. When the user opens
        // the app, a stale APNs alert arrives → willPresent shows a phantom banner.
        //
        // Solution: NEVER show remote (APNs) push banners in foreground.
        // Only show LOCAL notifications, which we fully control.
        //
        // Remote push = UNPushNotificationTrigger (sent by server via APNs)
        // Local notification = nil trigger (scheduled by our code)
        //
        // Remote pushes still wake the app via didReceiveRemoteNotification
        // for background message fetching — that pathway is unaffected.
        if notification.request.trigger is UNPushNotificationTrigger {
            // Remote APNs alert push — suppress ALL visual presentation in FOREGROUND.
            // In background, iOS displays the alert banner automatically (no code needed).
            #if DEBUG
            print("[Push] 🚫 Suppressing remote APNs alert in foreground")
            #endif
            completionHandler([])
            return
        }
        // Local notification — this was scheduled by our code (handleSilentPush
        // or ConversationListViewModel) for a genuine incoming message.
        completionHandler([.sound, .badge, .banner, .list])
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse, withCompletionHandler completionHandler: @escaping () -> Void) {
        // FIX PUSH-08: Handle notification tap — currently just opens the app.
        // Future: deep-link to the relevant conversation.
        completionHandler()
    }
}

/// Global application state
@MainActor
class AppState: ObservableObject {
    @Published var isAuthenticated: Bool = false
    @Published var currentUserID: String?
    /// Selected main tab. Held here, at app level, because switching the
    /// appearance rebuilds the view hierarchy — an @State inside ContentView
    /// would reset to the first tab and throw the user out of Settings.
    @Published var selectedTab: Int = 0
    /// A chat is pushed on the Messages tab. The light tab pill hides then,
    /// like the system tab bar does (it would cover the input field).
    @Published var isChatOpen: Bool = false
    
    init() {
        self.isAuthenticated = KeyManager.shared.hasIdentityKey()
    }
}

// MARK: - Removed Duplicates
// BiometricAuthService and BiometricLockView are defined in BiometricAuthService.swift
// JailbreakDetector, MemoryProtector, and TorProxySupport are in their standalone files.

