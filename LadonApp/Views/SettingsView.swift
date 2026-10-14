import SwiftUI
import CryptoKit
import CommonCrypto
import Security
import Foundation
import LocalAuthentication

// InactivityManager is defined in Services/InactivityManager.swift

struct SettingsView: View {
    // Creates the dependency that makes this view repaint when the
    // appearance changes. LadonTheme's colours are static reads, so
    // without it SwiftUI sees no reason to call body again and the view
    // keeps the previous mode's colours. Unused on purpose.
    @Environment(\.colorScheme) private var ladonAppearanceTick
    @StateObject private var inactivityManager = InactivityManager.shared
    @StateObject private var torManager = TorManager.shared
    @ObservedObject private var languageManager = LanguageManager.shared
    @ObservedObject private var appearanceManager = AppearanceManager.shared
    private var isDark: Bool { AppearanceManager.isDarkStored }
    // FIX CRIT-09: Removed @AppStorage("ladon_app_destroyed") — panic flag is Keychain-only
    @State private var userID: String = ""
    @State private var userIDBase64: String = ""
    @State private var showPanicConfirmation = false
    @EnvironmentObject private var appState: AppState
    #if DEBUG
    @State private var showOnboardingPreview = false
    #endif
    @State private var showKeyRotationNotice = false
    @State private var pushTokenPreview: String = "—"
    @State private var pushTokenFull: String = ""
    @State private var pushUploadStatus: String = "—"
    @State private var pushUploadDate: String = "—"
    @State private var pushRecipientID: String = "—"
    @State private var pushEnvironment: String = "—"
    // LADON PIN (replaces the Registration Lock, which had no effect: the V1
    // relay endpoint it reported to was retired, nothing ever checked it).
    @StateObject private var pinSecrets = PinSecretState()
    @State private var showChangePinSheet = false
    @State private var changePinError = ""
    @State private var isChangingPin = false
    
    /// FIX C-05 (ADVERSARIAL): Polling-only mode toggle state
    @State private var pollingOnlyMode = SilentPushHandler.isPollingOnlyMode

    #if DEBUG
    /// V2.1 Push-Relay rollout flag (Phase 4b, 2026-05). Default OFF, DEBUG-only
    /// toggle for staged E2E validation against ch1 + push.ladon.app.
    #endif

    // Local convenience wrappers — delegate to the global GlassSection / CardDivider
    // (defined in LadonTheme.swift) so the style stays consistent across the whole app.
    @ViewBuilder
    private func glassSection<Content: View>(
        header: LocalizedStringKey? = nil,
        footer: LocalizedStringKey? = nil,
        @ViewBuilder _ content: @escaping () -> Content
    ) -> some View {
        GlassSection(header: header, footer: footer, content: content)
            .staggerIn()
    }
    private var cardDivider: some View { CardDivider() }

    /// Standard padding inside a glass-card row.
    private func cardRowPadding<V: View>(_ v: V) -> some View {
        v.padding(.horizontal, 16).padding(.vertical, 12)
    }

    var body: some View {
        NavigationStack {
            ZStack {
            MeshBackground()
            VStack(spacing: 0) {
                HStack(alignment: .center, spacing: 8) {
                    PulsingLogo(size: 28)
                    Text("Settings")
                        .font(.manrope(34, .extrabold))
                        .tracking(isDark ? 0 : LadonTheme.titleTracking(34))
                        .foregroundColor(LadonTheme.textPrimary)
                    Spacer()
                }
                .padding(.horizontal, 20)
                .padding(.top, 20)
                .padding(.bottom, 16)
                
                ScrollView {
                VStack(spacing: 22) {
                // #UI: prominent, always-visible Lockdown Mode recommendation at
                // the very top of Settings (eye-catching). No status detection —
                // iOS exposes no reliable public API — so it recommends + guides.

                glassSection(header: "Your User ID") {
                    Group {
                    if !userID.isEmpty {
                        VStack(alignment: .leading, spacing: 12) {
                            HStack {
                                Text("ID")
                                    .fontWeight(.semibold)
                                Spacer()
                                Text(userID)
                                    .font(isDark ? .caption : .jbMono(11.5, relativeTo: .caption))
                                    .lineLimit(1)
                                    .truncationMode(.middle)
                                    .foregroundColor(isDark ? nil : LadonTheme.textSecondary)
                                    .padding(.horizontal, isDark ? 0 : 9)
                                    .padding(.vertical, isDark ? 0 : 5)
                                    .background(RoundedRectangle(cornerRadius: 8).fill(isDark ? Color.clear : LadonTheme.paper2))
                                    // FIX MED: Prevent VoiceOver from reading full user ID aloud
                                    .accessibilityLabel("User ID")
                                    .accessibilityHint("Your unique identifier")
                            }
                            
                            Button(action: copyUserID) {
                                Label("Copy ID", systemImage: "doc.on.doc")
                            }
                            .tint(LadonTheme.greenInk)
                            // P8-AUDIT8-IOS-15 (audit F33): the former "Generate
                            // New ID" button only rotated the retired V1 key while
                            // telling the user a new identity was created — the V2
                            // messaging identity stayed in use. Removed; the panic
                            // wipe is the real, complete reset.
                        }
                    } else {
                        HStack {
                            Spinner()
                            Text("Loading User ID...")
                                .foregroundColor(LadonTheme.textSecondary)
                        }
                    }
                    }
                    .padding(16)
                }

                // 🧅 TOR NETWORK
                glassSection(
                    header: "Privacy",
                    footer: "Your messages are routed through 3 encrypted relays. No one — not even your internet provider — can see who you're talking to."
                ) {
                    Group {
                    NavigationLink {
                        TorSettingsView()
                    } label: {
                        HStack {
                            Image(systemName: torManager.isConnected ? "network" : "network.slash")
                                .foregroundColor(isDark ? (torManager.isConnected ? .green : .orange)
                                                         : (torManager.isConnected ? LadonTheme.greenInk : LadonTheme.inkMuted))
                            VStack(alignment: .leading) {
                                Text("Anonymous Connection")
                                    .font(isDark ? .body : .manrope(15.5, .bold))
                                    .foregroundColor(isDark ? LadonTheme.brandGreen : LadonTheme.textPrimary)
                                if torManager.isStarting {
                                    Text("Connecting…")
                                        .font(.caption)
                                        .foregroundColor(isDark ? .orange : LadonTheme.inkMuted)
                                } else if torManager.isConnected {
                                    Text("Active — your IP is hidden")
                                        .font(.caption)
                                        .foregroundColor(isDark ? .green : LadonTheme.greenInk)
                                } else {
                                    Text("Not connected")
                                        .font(.caption)
                                        .foregroundColor(isDark ? .red : LadonTheme.coralInk)
                                }
                            }
                            Spacer()
                            if torManager.isConnected {
                                Image(systemName: "checkmark.shield.fill")
                                    .foregroundColor(isDark ? .green : LadonTheme.greenInk)
                            } else if torManager.isStarting {
                                ProgressView()
                                    .scaleEffect(0.7)
                            }
                            if !isDark {
                                Image(systemName: "chevron.right")
                                    .font(.system(size: 13, weight: .semibold))
                                    .foregroundColor(LadonTheme.inkMuted)
                            }
                        }
                    }
                    }
                    .padding(16)
                }

                // FIX C-05 (ADVERSARIAL): Polling-Only Mode
                glassSection(
                    header: "Privacy Mode",
                    footer: "When enabled, Apple cannot see that you use LADON messenger or when you receive messages. Messages are only delivered while the app is open. Requires manual polling."
                ) {
                    Group {
                    Toggle(isOn: $pollingOnlyMode) {
                        VStack(alignment: .leading) {
                            Text("Polling-Only Mode")
                            Text("Disable Apple Push Notifications")
                                .font(.caption)
                                .foregroundColor(LadonTheme.textSecondary)
                        }
                    }
                    .onChange(of: pollingOnlyMode) { _, newValue in
                        // FIX M-28: Use SecureUserDefaults (encrypted) instead of plaintext UserDefaults
                        // FIX R21-A6-4: Handle persistence failure — revert toggle if write fails.
                        // Previously `try?` silently swallowed errors, causing UI/state desync.
                        do {
                            try SecureUserDefaults.shared.set(newValue, forKey: SilentPushHandler.pollingOnlyModeKey)
                        } catch {
                            pollingOnlyMode = !newValue  // Revert toggle
                            #if DEBUG
                            print("[Settings] ⚠️ Failed to persist polling mode: \(error)")
                            #endif
                            return  // Don't (de)register APNs if persistence failed
                        }
                        if newValue {
                            // Deregister from APNs
                            UIApplication.shared.unregisterForRemoteNotifications()
                        } else {
                            // Re-register with APNs
                            SilentPushHandler.shared.registerForSilentPush()
                        }
                    }
                    }
                    .padding(16)
                }

                // LADON PIN — asked for when Face ID changes on this iPhone.
                glassSection(header: "LADON PIN") {
                    Button {
                        showChangePinSheet = true
                    } label: {
                        Text("Change LADON PIN")
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .padding(16)
                }

                glassSection(header: "Dead Man's Switch") {
                    Group {
                    VStack(alignment: .leading, spacing: 12) {
                        Text("Inactivity Threshold")
                            .font(.subheadline)
                            .fontWeight(.semibold)
                        
                        Picker("Inactivity Threshold", selection: $inactivityManager.inactivityThresholdDays) {
                            ForEach(1...14, id: \.self) { day in
                                Text("\(day) days").tag(day)
                            }
                        }
                        .pickerStyle(.wheel)
                        .frame(height: 150)
                        .clipped()
                        // FIX A7-DMS-01: Persist threshold when picker value changes.
                        // Previously only the in-memory @Published value was updated —
                        // on app restart the old value was restored from SecureUserDefaults.
                        .onChange(of: inactivityManager.inactivityThresholdDays) { _, newValue in
                            inactivityManager.setInactivityThreshold(newValue)
                        }
                        
                        if inactivityManager.showInactivityWarning {
                            VStack(alignment: .leading, spacing: 8) {
                                HStack {
                                    Image(systemName: "exclamationmark.triangle.fill")
                                        .foregroundColor(.orange)
                                    Text("Inactivity Warning Active")
                                        .fontWeight(.semibold)
                                }
                                Text("Your device has been inactive. After the countdown reaches zero, all keys will be destroyed.")
                                    .font(.caption)
                                    .foregroundColor(LadonTheme.textSecondary)
                            }
                            .padding(10)
                            .background(Color.orange.opacity(0.1))
                            .cornerRadius(8)
                        }
                        
                        Text("If your device is stolen or you cannot access it for the configured period, a 24-hour countdown timer will begin. After the countdown reaches zero, all encryption keys and conversations will be automatically destroyed. You can reset the countdown by unlocking with Face ID.")
                            .font(.caption)
                            .foregroundColor(LadonTheme.textSecondary)
                    }
                    }
                    .padding(16)
                }

                // H3: Key Rotation Status

                // 🔔 PUSH NOTIFICATIONS
                glassSection(header: "Push Notifications") {
                    Group {
                    HStack {
                        Text("Recipient ID")
                        Spacer()
                        Text(pushRecipientID)
                            .font(.caption)
                            .foregroundColor(LadonTheme.textSecondary)
                            .lineLimit(1)
                    }
                    if pushRecipientID != "—" {
                        Button("Copy Recipient ID") {
                            // FIX L-02 AUDIT-MAR-2026: Reduced clipboard expiry from 30s to 10s
                            UIPasteboard.general.setItems(
                                [[UIPasteboard.typeAutomatic: pushRecipientID]],
                                options: [.expirationDate: Date().addingTimeInterval(10), .localOnly: true]
                            )
                        }
                    }
                    HStack {
                        Text("APNs Environment")
                        Spacer()
                        Text(pushEnvironment)
                            .font(.caption)
                            .foregroundColor(LadonTheme.textSecondary)
                    }
                    HStack {
                        Text("Token")
                        Spacer()
                        Text(pushTokenPreview)
                            .font(.caption)
                            .foregroundColor(LadonTheme.textSecondary)
                            .lineLimit(1)
                    }
                    #if DEBUG
                    if !pushTokenFull.isEmpty && pushTokenFull != "—" {
                        Text(pushTokenFull)
                            .font(.footnote)
                            .foregroundColor(LadonTheme.textSecondary)
                            // FIX UI-5: Removed .textSelection(.enabled) — bypasses clipboard expiry
                        Button("Copy Token") {
                            // FIX L-02 AUDIT-MAR-2026: Reduced clipboard expiry from 30s to 10s
                            UIPasteboard.general.setItems(
                                [[UIPasteboard.typeAutomatic: pushTokenFull]],
                                options: [.expirationDate: Date().addingTimeInterval(10), .localOnly: true]
                            )
                        }
                    }
                    #endif
                    HStack {
                        Text("Upload")
                        Spacer()
                        Text(pushUploadStatus)
                            .font(.caption)
                            .foregroundColor(LadonTheme.textSecondary)
                            .lineLimit(1)
                    }
                    HStack {
                        Text("Last Update")
                        Spacer()
                        Text(pushUploadDate)
                            .font(.caption)
                            .foregroundColor(LadonTheme.textSecondary)
                    }

                    // SV-01 FIX: Test notification button only in DEBUG builds
                    #if DEBUG
                    Button("Test Notification") {
                        SilentPushHandler.shared.sendTestNotification()
                    }
                    #endif
                    Button("Retry Push Registration") {
                        SilentPushHandler.shared.retryPushRegistration()
                        refreshPushStatus()
                    }
                    #if DEBUG
                    if let curl = buildPushRegisterCurl() {
                        Button("Copy Register cURL") {
                            // FIX L-02 AUDIT-MAR-2026: Reduced clipboard expiry from 30s to 10s
                            UIPasteboard.general.setItems(
                                [[UIPasteboard.typeAutomatic: curl]],
                                options: [.expirationDate: Date().addingTimeInterval(10), .localOnly: true]
                            )
                        }
                    }
                    #endif
                    }
                    .padding(16)
                }

                #if DEBUG
                // DEBUG-only: review the onboarding screen-0 intro animation on
                // device without wiping the identity (real onboarding only shows
                // when there is no identity key). Never compiled into Release.
                glassSection(header: "DEBUG") {
                    // Full onboarding as a full-screen cover (no tab pill over
                    // it); "Get started" only closes it — no keys generated.
                    Button("Preview onboarding") { showOnboardingPreview = true }
                        .padding(16)
                }
                .fullScreenCover(isPresented: $showOnboardingPreview) {
                    OnboardingView(debugPreviewDismiss: { showOnboardingPreview = false })
                        .environmentObject(appState)
                }
                #endif

                // 🔐 Advanced Security Features (Tier 2+3)

                #if DEBUG
                // Phase-4 cutover (2026-05-04): V2 Developer panel removed.
                // V2 endpoints are reached via the production CertificatePinning
                // pin set (ch1/fi1/pa1/is1/is2.ladon.app) and the bundled
                // exits-bootstrap.json. No runtime override.
                #endif

                glassSection(header: "Language") {
                    VStack(spacing: 0) {
                        ForEach(Array(LanguageManager.supportedLanguages.enumerated()), id: \.element.code) { idx, lang in
                            Button(action: {
                                languageManager.selectedLanguage = lang.code
                            }) {
                                HStack {
                                    Text(lang.name)
                                        .foregroundColor(LadonTheme.textPrimary)
                                    Spacer()
                                    if languageManager.selectedLanguage == lang.code {
                                        Image(systemName: "checkmark")
                                            .foregroundColor(LadonTheme.greenInk)
                                    }
                                }
                                .padding(.horizontal, 16).padding(.vertical, 13)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                            if idx < LanguageManager.supportedLanguages.count - 1 {
                                cardDivider
                            }
                        }
                    }
                }

                glassSection(header: "Appearance") {
                    VStack(spacing: 0) {
                        ForEach(Array(AppearanceManager.Mode.allCases.enumerated()), id: \.element) { idx, mode in
                            Button(action: { appearanceManager.mode = mode }) {
                                HStack {
                                    Text(mode == .light ? "Light" : "Dark")
                                        .foregroundColor(LadonTheme.textPrimary)
                                    Spacer()
                                    if appearanceManager.mode == mode {
                                        Image(systemName: "checkmark")
                                            .foregroundColor(LadonTheme.greenInk)
                                    }
                                }
                                .padding(.horizontal, 16).padding(.vertical, 13)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                            if idx < AppearanceManager.Mode.allCases.count - 1 {
                                cardDivider
                            }
                        }
                    }
                }
                

                glassSection(header: "Info") {
                    FreeOpenSourceNotice()
                        .padding(16)
                }

                // H3: Panic Button - Emergency Zeroize
                glassSection(
                    footer: "⚠️ IRREVERSIBLE: Destroys all encryption keys and conversations. Device will be unable to decrypt any messages. Use only if you believe your device is compromised."
                ) {
                    Button(role: .destructive, action: { showPanicConfirmation = true }) {
                        HStack {
                            Image(systemName: "exclamationmark.octagon.fill")
                            Text("Emergency Destroy All Keys")
                                .fontWeight(.semibold)
                        }
                        .frame(maxWidth: .infinity, alignment: .center)
                        .foregroundColor(LadonTheme.coralInk)
                    }
                    .buttonStyle(.plain)
                    .padding(16)
                }
            }
            .padding(.horizontal, 14)
            .padding(.bottom, 32)
            }
            .navigationTitle("")
            .navigationBarTitleDisplayMode(.inline)
            .toolbarBackground(.hidden, for: .navigationBar)
            .tint(LadonTheme.brandGreen)
            .onAppear {
                loadUserID()
                refreshPushStatus()
                // The retired Registration Lock left its PIN hash in the
                // database; nothing ever read it, and the LADON PIN replaces it.
                try? EncryptedDatabase.shared.removeSecureValue(forKey: "registration_lock_pin_hash")
                try? EncryptedDatabase.shared.removeSecureValue(forKey: "registration_lock_kdf_method")
            }
            .alert("Destroy All Keys?", isPresented: $showPanicConfirmation) {
                Button("Cancel", role: .cancel) { }
                Button("DESTROY KEYS", role: .destructive) {
                    // FIX HIGH-07: Require biometric auth before destruction
                    // Prevents unauthorized destruction by someone with physical access
                    Task {
                        let context = LAContext()
                        context.localizedCancelTitle = LanguageManager.localized("Cancel")
                        do {
                            // FIX R21-A6-3: Use .deviceOwnerAuthentication (passcode fallback)
                            // instead of .deviceOwnerAuthenticationWithBiometrics.
                            // If biometrics are locked (5 failed attempts), the panic button
                            // would silently fail — an attacker could intentionally lock biometrics.
                            let success = try await context.evaluatePolicy(
                                .deviceOwnerAuthentication,
                                localizedReason: LanguageManager.localized("Authenticate to destroy all keys")
                            )
                            if success {
                                await MainActor.run { executePanicMode() }
                            }
                        } catch {
                            // Biometric auth failed or cancelled — don't execute
                            #if DEBUG
                            print("[Settings] Panic auth failed: \(error)")
                            #endif
                        }
                    }
                }
            } message: {
                Text("This will permanently destroy all encryption keys and conversations. This action cannot be undone.")
            }
            .sheet(isPresented: $showChangePinSheet) {
                NavigationStack {
                    Form {
                        Section("Change LADON PIN") {
                            SecureField("Current PIN", text: $pinSecrets.current)
                                .keyboardType(.numberPad)
                                .privacySensitive()
                            SecureField("Enter PIN (min 6 digits)", text: $pinSecrets.pin)
                                .keyboardType(.numberPad)
                                .privacySensitive()
                            SecureField("Confirm PIN", text: $pinSecrets.confirm)
                                .keyboardType(.numberPad)
                                .privacySensitive()
                        }

                        if !changePinError.isEmpty {
                            Section {
                                Text(changePinError)
                                    .foregroundColor(.red)
                                    .font(.caption)
                            }
                        }
                    }
                    .navigationTitle("LADON PIN")
                    .navigationBarTitleDisplayMode(.inline)
                    .toolbar {
                        ToolbarItem(placement: .cancellationAction) {
                            Button("Cancel") {
                                showChangePinSheet = false
                                pinSecrets.wipe()
                                changePinError = ""
                            }
                        }
                        ToolbarItem(placement: .confirmationAction) {
                            Button("Save") {
                                changeAppPin()
                            }
                            .disabled(pinSecrets.current.count < 6 || pinSecrets.pin.count < 6
                                      || pinSecrets.confirm.count < 6 || isChangingPin)
                        }
                    }
                }
                .presentationDetents([.medium])
            }
            .onDisappear {
                pinSecrets.wipe()
                // FIX AUDIT-R18-F7: Wipe identity public key from memory
                userIDBase64 = ""
                userID = ""
            }
            }
            }
        }
    }
    
    // MARK: - LADON PIN

    private func changeAppPin() {
        let current = pinSecrets.current
        let new = pinSecrets.pin
        let confirm = pinSecrets.confirm
        pinSecrets.wipe()
        changePinError = ""
        isChangingPin = true
        Task { @MainActor in
            let problem = await BiometricAuthService.changePin(current: current, new: new, confirm: confirm)
            isChangingPin = false
            if let problem {
                changePinError = problem
            } else {
                showChangePinSheet = false
            }
        }
    }

    private func loadUserID() {
        do {
            let publicKey = try KeyManager.shared.getIdentityPublicKey()
            let publicKeyData = publicKey.rawRepresentation
            
            // Create User ID as SHA256 hash of public key
            let digest = SHA256.hash(data: publicKeyData)
            userID = digest.withUnsafeBytes { Data($0) }.base64EncodedString()
            userIDBase64 = publicKeyData.base64EncodedString()
        } catch {
            #if DEBUG
            print("[Settings] ⚠️ Failed to load user ID: \(error)")
            #endif
            userID = "Error loading ID"
        }
    }
    
    private func copyUserID() {
        // FIX L-02 AUDIT-MAR-2026: Reduced clipboard expiry from 30s to 10s
        UIPasteboard.general.setItems(
            [[UIPasteboard.typeAutomatic: userID]],
            options: [.expirationDate: Date().addingTimeInterval(10), .localOnly: true]
        )
    }
    

    private func refreshPushStatus() {
        if let token = SilentPushHandler.shared.lastTokenString(), !token.isEmpty {
            pushTokenPreview = token.count > 16 ? "\(token.prefix(16))…" : token
            // FIX SV-01: Only store full token in DEBUG builds.
            // In Release, the full APNs token (unique device identifier) should not
            // remain in @State memory where it could be captured by memory dumps.
            #if DEBUG
            pushTokenFull = token
            #endif
        } else {
            pushTokenPreview = "—"
            #if DEBUG
            pushTokenFull = "—"
            #endif
        }

        pushUploadStatus = SilentPushHandler.shared.lastUploadStatus() ?? "—"
        pushEnvironment = SilentPushHandler.shared.currentAPNsEnvironment()

        if let data = try? KeyManager.shared.getCurrentRecipientID() {
            pushRecipientID = data.map { String(format: "%02x", $0) }.joined()
        } else {
            pushRecipientID = "—"
        }

        if let date = SilentPushHandler.shared.lastUploadDate() {
            let formatter = DateFormatter()
            formatter.dateStyle = .short
            formatter.timeStyle = .short
            pushUploadDate = formatter.string(from: date)
        } else {
            pushUploadDate = "—"
        }
    }

    // FIX SV-02: cURL builder only in DEBUG. Contains recipientId + full token + sandbox flag.
    #if DEBUG
    private func buildPushRegisterCurl() -> String? {
        // V1 push registration is retired; V2 push registration is handled by
        // PushRegistrationClientV2 via entry-relay-v2.
        return nil
    }
    #endif
    
    // MARK: - Panic Button Implementation (H3: Emergency Zeroize)
    // FIX H15: Unified — delegates to global executePanicMode() in LadonApp.swift
    // which correctly sets Keychain flag, scopes deletion, and preserves panic state
    private func executePanicMode() {
        // Call the global implementation (free function in LadonApp.swift)
        // Note: executePanicGlobal() calls abort() — this line is terminal, no code after it runs.
        LadonApp.executePanicGlobal()
    }
    
}

struct Spinner: View {
    // Creates the dependency that makes this view repaint when the
    // appearance changes. LadonTheme's colours are static reads, so
    // without it SwiftUI sees no reason to call body again and the view
    // keeps the previous mode's colours. Unused on purpose.
    @Environment(\.colorScheme) private var ladonAppearanceTick
    @State private var isSpinning = false
    
    var body: some View {
        Image(systemName: "arrowtriangle.right.circle.fill")
            .font(.caption)
            .foregroundColor(LadonTheme.accent)
            .rotationEffect(.degrees(isSpinning ? 360 : 0))
            .animation(.linear(duration: 1).repeatForever(autoreverses: false), value: isSpinning)
            .onAppear {
                isSpinning = true
            }
    }
}

#Preview {
    SettingsView()
}

// InactivityWarningView is defined in InactivityWarningView.swift
