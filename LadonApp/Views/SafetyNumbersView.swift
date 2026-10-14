import SwiftUI
import CryptoKit

/// Safety Numbers Verification View — like Signal's "Verify Safety Number" screen.
/// Allows users to compare fingerprints visually or via QR code scan.
struct SafetyNumbersView: View {
    // Creates the dependency that makes this view repaint when the
    // appearance changes. LadonTheme's colours are static reads, so
    // without it SwiftUI sees no reason to call body again and the view
    // keeps the previous mode's colours. Unused on purpose.
    @Environment(\.colorScheme) private var ladonAppearanceTick
    let conversation: Conversation
    @State private var safetyNumbers: SafetyNumbers?
    @State private var showQRCode = false
    @State private var verificationStatus: VerificationStatus = .unverified
    @State private var showCopied = false
    @State private var showVerifyConfirmation = false
    @State private var showSaveError = false
    /// "Reset secure session": confirmation, then the outcome.
    @State private var showResetConfirmation = false
    @State private var resetOutcome: String?
    private var isDark: Bool { AppearanceManager.isDarkStored }
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    /// Stamp at rest (scale 1, visible). Springs in only when the user
    /// confirms right here; a contact already verified shows it still.
    @State private var stampLanded = true
    
    enum VerificationStatus {
        case unverified, verified, mismatch
    }
    
    var body: some View {
        ZStack {
        MeshBackground()
        ScrollView {
            VStack(spacing: 22) {
                // Header
                if isDark {
                    Image(systemName: "lock.shield")
                        .font(.system(size: 48))
                        .foregroundColor(LadonTheme.brandGreen)
                        .padding(.top, 8)
                } else {
                    // ladon.app: green-tinted circle behind the shield
                    Image(systemName: "lock.shield")
                        .font(.system(size: 28, weight: .medium))
                        .foregroundColor(LadonTheme.greenInk)
                        .frame(width: 64, height: 64)
                        .background(Circle().fill(LadonTheme.brandGreenSoft))
                        .padding(.top, 8)
                        .accessibilityHidden(true)
                }

                Text("Safety Number")
                    .font(isDark ? .manrope(22, .bold) : .manrope(28, .extrabold))
                    .tracking(isDark ? 0 : LadonTheme.titleTracking(28))
                    .foregroundColor(LadonTheme.textPrimary)

                Text("Compare these numbers with \(conversation.contactName) on their device. If they match, your conversation is end-to-end encrypted.")
                    .font(isDark ? .subheadline : .manrope(16, relativeTo: .subheadline))
                    .foregroundColor(LadonTheme.textSecondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal)

                if let numbers = safetyNumbers {
                    // Fingerprint display (60-digit number in 12 groups of 5)
                    GlassSection {
                        VStack(spacing: 12) {
                            fingerprintGrid(numbers.formattedCombined())
                        }
                        .overlay {
                            // Light (maintainer, 02.10.2026): the ladon.app stamp, in green —
                            // coral is for warnings only. Dark unchanged.
                            if !isDark && verificationStatus == .verified {
                                VerifiedStamp()
                                    .scaleEffect(stampLanded ? 1 : 1.6)
                                    .opacity(stampLanded ? 1 : 0)
                                    .offset(x: 28)
                                    .allowsHitTesting(false)
                                    .accessibilityHidden(true)
                            }
                        }
                        .padding(isDark ? 16 : 20)
                        .background {
                            // ladon.app stage: 22 pt dot grid, light only
                            if !isDark {
                                Canvas { ctx, size in
                                    let step: CGFloat = 22
                                    var y = step / 2
                                    while y < size.height {
                                        var x = step / 2
                                        while x < size.width {
                                            ctx.fill(Path(ellipseIn: CGRect(x: x - 0.5, y: y - 0.5, width: 1, height: 1)),
                                                     with: .color(LadonTheme.onSurface(0.14)))
                                            x += step
                                        }
                                        y += step
                                    }
                                }
                                .clipShape(RoundedRectangle(cornerRadius: 24, style: .continuous))
                                .accessibilityHidden(true)
                            }
                        }
                    }

                    // Action buttons — same glass capsule style on both
                    HStack(spacing: 12) {
                        Button {
                            showQRCode.toggle()
                        } label: {
                            Label("QR Code", systemImage: "qrcode")
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, 12)
                        }
                        .buttonStyle(.plain)
                        .font(isDark ? .body : .manrope(15, .bold))
                        .foregroundColor(isDark ? LadonTheme.brandGreen : LadonTheme.textPrimary)
                        .background { ghostCapsule }

                        Button {
                            // FIX M3: .localOnly prevents Safety-Number leak via iCloud Clipboard
                            // FIX F-01: Reduced clipboard expiry from 30s to 10s — consistent with
                            // all other copy operations (SettingsView, QRDisplayView). 30s gives a physical
                            // attacker too much time to read the clipboard.
                            UIPasteboard.general.setItems(
                                [[UIPasteboard.typeAutomatic: numbers.combined]],
                                options: [.expirationDate: Date().addingTimeInterval(10), .localOnly: true]
                            )
                            showCopied = true
                            DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
                                showCopied = false
                            }
                        } label: {
                            Label(showCopied ? "Copied!" : "Copy", systemImage: showCopied ? "checkmark" : "doc.on.doc")
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, 12)
                        }
                        .buttonStyle(.plain)
                        .font(isDark ? .body : .manrope(15, .bold))
                        .foregroundColor(isDark ? LadonTheme.brandGreen : LadonTheme.textPrimary)
                        .background { ghostCapsule }
                    }

                    // QR Code display
                    if showQRCode, let qrImage = numbers.generateQRCode(size: CGSize(width: 250, height: 250)) {
                        Image(uiImage: qrImage)
                            .interpolation(.none)
                            .resizable()
                            .scaledToFit()
                            .frame(width: 250, height: 250)
                            .padding()
                            .background(Color.white)
                            .cornerRadius(12)
                            .privacySensitive()  // FIX AUDIT-R17-F8: Hide QR code from VoiceOver/screen recording
                            .accessibilityLabel("Safety number QR code")
                    }

                    // Verification toggle in its own glass card
                    GlassSection {
                        Toggle(isOn: Binding(
                            get: { verificationStatus == .verified },
                            set: { newValue in
                                if newValue {
                                    // Show confirmation before marking as verified
                                    showVerifyConfirmation = true
                                } else {
                                    verificationStatus = .unverified
                                    saveVerificationStatus(verified: false)
                                }
                            }
                        )) {
                            VStack(alignment: .leading) {
                                Text("Verified")
                                    .font(isDark ? .headline : .manrope(15.5, .bold))
                                Text("Mark this contact's safety number as verified")
                                    .font(.caption)
                                    .foregroundColor(LadonTheme.textSecondary)
                            }
                        }
                        .padding(16)
                    }

                    // Recovery for a broken session — only ever on the user's own
                    // action here, never triggered by anything received.
                    GlassSection {
                        VStack(alignment: .leading, spacing: 8) {
                            Button(role: .destructive) { showResetConfirmation = true } label: {
                                Label("Reset secure session", systemImage: "arrow.counterclockwise")
                                    .font(.headline)
                            }
                            Text("Only if messages stop arriving. You both reset, then exchange a fresh code.")
                                .font(.caption)
                                .foregroundColor(LadonTheme.textSecondary)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(16)
                    }

                } else {
                    ProgressView("Generating safety number...")
                        .padding()
                }
            }
            .padding(.horizontal, 14)
            .padding(.top, 16)
            .padding(.bottom, 32)
        }
        }
        .navigationTitle("Verify Safety Number")
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(.hidden, for: .navigationBar)
        .tint(LadonTheme.brandGreen)
        // FIX MED: Confirmation dialog before marking contact as verified
        .alert("Verify Safety Number", isPresented: $showVerifyConfirmation) {
            Button("I have verified", role: .none) {
                if !isDark && !reduceMotion {
                    var still = Transaction()
                    still.disablesAnimations = true
                    withTransaction(still) { stampLanded = false }
                    DispatchQueue.main.async {
                        withAnimation(.timingCurve(0.34, 1.56, 0.64, 1, duration: 0.55)) { stampLanded = true }
                    }
                }
                verificationStatus = .verified
                saveVerificationStatus(verified: true)
            }
            Button("Cancel", role: .cancel) { }
        } message: {
            Text("Have you compared the safety numbers above with your contact in person or through a trusted channel? Only mark as verified if the numbers match exactly.")
        }
        .confirmationDialog("Reset secure session?", isPresented: $showResetConfirmation, titleVisibility: .visible) {
            Button("Reset", role: .destructive) { resetSession() }
            Button("Cancel", role: .cancel) { }
        } message: {
            Text("This deletes the keys of this conversation on this device. Messages still on their way are lost. Ask them to reset too, then exchange a fresh code.")
        }
        .alert("Reset secure session", isPresented: Binding(
            get: { resetOutcome != nil },
            set: { if !$0 { resetOutcome = nil } }
        )) {
            Button("OK", role: .cancel) { resetOutcome = nil }
        } message: {
            Text(resetOutcome ?? "")
        }
        // SN-03 FIX: Alert when verification save fails
        .alert("Save Failed", isPresented: $showSaveError) {
            Button("OK", role: .cancel) { }
        } message: {
            Text("Could not save verification status. Please try again.")
        }
        .onAppear {
            generateSafetyNumbers()
            loadVerificationStatus()
        }
        // FIX AUDIT-R18-F6: Clear safety numbers from memory on navigation away
        .onDisappear {
            safetyNumbers = nil
        }
    }
    
    /// Button capsule: dark = original glass; light = ladon.app ghost pill.
    @ViewBuilder
    private var ghostCapsule: some View {
        if isDark {
            Capsule().fill(.ultraThinMaterial).opacity(0.55)
                .overlay(Capsule().strokeBorder(LadonTheme.glassStroke, lineWidth: 1))
        } else {
            Capsule().fill(Color.white.opacity(0.6))
                .overlay(Capsule().strokeBorder(LadonTheme.onSurface(0.14), lineWidth: 1))
        }
    }

    // MARK: - Fingerprint Grid
    
    @ViewBuilder
    private func fingerprintGrid(_ formatted: String) -> some View {
        let groups = formatted.split(separator: " ").map(String.init)
        let columns = Array(repeating: GridItem(.flexible(), spacing: 8), count: 4)
        
        LazyVGrid(columns: columns, spacing: 8) {
            ForEach(Array(groups.enumerated()), id: \.offset) { _, group in
                Text(group)
                    .font(isDark ? .system(.body, design: .monospaced) : .jbMono(17, .medium, relativeTo: .body))
                    .tracking(isDark ? 0 : 1)
                    .foregroundColor(LadonTheme.textPrimary)
                    .privacySensitive()  // FIX SN-01 (ADVERSARIAL): Hide from VoiceOver, screen recording, screenshots
            }
        }
        // FIX R19-V9: Prevent VoiceOver from reading safety number digits aloud
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Safety number fingerprint")
    }
    
    // MARK: - Logic
    
    /// The public key this conversation's verification is bound to.
    ///
    /// V2 contacts authenticate with the hybrid HSig key (1,984 B, Ed25519 +
    /// Dilithium3). `conversation.recipientPublicKey` is the V1 X25519 field and
    /// is deliberately left empty for them (EncryptedDatabase.swift:1180), which
    /// is why this screen used to return without generating anything — the only
    /// defence against a substituted contact was missing for exactly the contacts
    /// that exist today.
    private var boundIdentityKey: Data {
        if let peerV2 = try? PeerStoreV2.load(forContactId: conversation.recipientID) {
            return peerV2.recipientHsigPk
        }
        return conversation.recipientPublicKey
    }

    /// Delete this conversation's session and any unused code of the contact
    /// on this device. The contact identity stays (same person, same safety
    /// number); the next send asks for a fresh code exchange.
    private func resetSession() {
        do {
            try V2RatchetPayload.deleteSession(peerId: conversation.recipientID)
            try PrekeyStoreV2.forgetPeer(forPeer: conversation.recipientID)
            resetOutcome = LanguageManager.localized("Session reset. Once they have reset too, exchange a fresh code.")
        } catch {
            resetOutcome = LanguageManager.localized("Could not reset the session. Please try again.")
        }
    }

    private func generateSafetyNumbers() {
        // V2 path: both sides derive the number from the hybrid HSig keys, so
        // both halves — classical and post-quantum — are covered by the digits.
        if let peerV2 = try? PeerStoreV2.load(forContactId: conversation.recipientID),
           let localV2 = try? IdentityStoreV2.load() {
            let localHsig = localV2.senderHsigKp.publicKeyBytes()
            let remoteHsig = peerV2.recipientHsigPk
            guard !localHsig.isEmpty, !remoteHsig.isEmpty else { return }

            safetyNumbers = SafetyNumbers.generate(
                localKey: localHsig,
                remoteKey: remoteHsig,
                localID: localV2.recipientId.description,
                remoteID: peerV2.recipientId.description
            )
            #if DEBUG
            // Branch and outcome only — never the digits or any key material.
            print("[SafetyNumbers] V2 branch taken — local \(localHsig.count) B, remote \(remoteHsig.count) B (1984 = Ed25519 + Dilithium3)")
            #endif
            return
        }

        // FIX H2: Sichere API statt direktem Keychain-Zugriff
        guard let localKeyData = KeyManager.shared.getIdentityPublicKeyData() else {
            return
        }

        // Get contact's identity key from conversation
        let remoteKeyData = conversation.recipientPublicKey

        guard !remoteKeyData.isEmpty else { return }
        
        // FIX HIGH-10: Guard against empty local ID — if getCurrentRecipientID() fails,
        // all safety numbers would be identical (MITM undetectable)
        guard let localIDData = try? KeyManager.shared.getCurrentRecipientID(), !localIDData.isEmpty else {
            return
        }
        let localID = localIDData.map { String(format: "%02x", $0) }.joined()
        let remoteID = conversation.recipientID
        
        safetyNumbers = SafetyNumbers.generate(
            localKey: localKeyData,
            remoteKey: remoteKeyData,
            localID: localID,
            remoteID: remoteID
        )
    }
    
    private func saveVerificationStatus(verified: Bool) {
        // SN-03 FIX: Show user-facing error if save fails — don't silently swallow
        // Bind the verification to the key that actually authenticates this
        // contact. Storing nil for V2 contacts left "verified" bound to nothing,
        // so a later key substitution could not be detected.
        let identityKey = boundIdentityKey
        do {
            try EncryptedDatabase.shared.setVerificationStatus(
                contactID: conversation.recipientID,
                verified: verified,
                identityKey: identityKey.isEmpty ? nil : identityKey
            )
        } catch {
            #if DEBUG
            SecureLogger.debug("[SafetyNumbers] ❌ Failed to save verification status: \(error)")
            #endif
            // SN-03 FIX: Revert UI state and show error to user
            if verified {
                verificationStatus = .unverified
            }
            showSaveError = true
        }
    }
    
    private func loadVerificationStatus() {
        let status = EncryptedDatabase.shared.getVerificationStatus(contactID: conversation.recipientID)
        if status.verified {
            // If the stored key matches the current key, verified. Otherwise mismatch (key changed).
            if let storedKey = status.lastKnownKey,
               !storedKey.isEmpty,
               storedKey != boundIdentityKey {
                verificationStatus = .mismatch
            } else {
                verificationStatus = .verified
            }
        } else {
            verificationStatus = .unverified
        }
    }
}


/// "VERIFIED" stamp on the safety number (ladon.app "ENCRYPTED" stamp:
/// mono, wide tracking, 2.5 pt frame, −8°), in green ink.
private struct VerifiedStamp: View {
    var body: some View {
        Text("VERIFIED")
            .font(.jbMono(21, .medium, relativeTo: .title3))
            .tracking(21 * 0.18)
            .foregroundColor(LadonTheme.greenInk)
            .padding(.vertical, 8)
            .padding(.horizontal, 16)
            .background(RoundedRectangle(cornerRadius: 8, style: .continuous).fill(Color.white.opacity(0.94)))
            .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(LadonTheme.greenInk, lineWidth: 2.5))
            .shadow(color: LadonTheme.onSurface(0.25), radius: 15, y: 10)
            .rotationEffect(.degrees(-8))
    }
}
