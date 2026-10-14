import SwiftUI

struct InactivityWarningView: View {
    // Creates the dependency that makes this view repaint when the
    // appearance changes. LadonTheme's colours are static reads, so
    // without it SwiftUI sees no reason to call body again and the view
    // keeps the previous mode's colours. Unused on purpose.
    @Environment(\.colorScheme) private var ladonAppearanceTick
    @EnvironmentObject var inactivityManager: InactivityManager
    @EnvironmentObject var biometricAuth: BiometricAuthService
    @State private var showConfirmation = false
    @State private var showBiometricForDestroy = false
    
    // FIX F-04: Bucketed inactivity display — prevents precise last-active time leakage
    private static func bucketedInactivityDisplay(_ days: Int) -> LocalizedStringKey {
        switch days {
        case 0...1: return "Recently"
        case 2...3: return "A few days"
        case 4...7: return "Several days"
        case 8...14: return "Over a week"
        case 15...30: return "Over two weeks"
        default: return "Over a month"
        }
    }
    
    var body: some View {
        ZStack {
            // Brand mesh background — same look as Settings/Tor
            MeshBackground()

            if !AppearanceManager.isDarkStored {
                lightBody
            } else {
            VStack(spacing: 22) {
                // Header Icon
                VStack(spacing: 16) {
                    Image(systemName: "exclamationmark.circle.fill")
                        .font(.system(size: 60))
                        .foregroundColor(LadonTheme.coral)

                    Text("Device Inactivity Detected")
                        .font(.manrope(22, .bold))
                        .foregroundColor(LadonTheme.textPrimary)
                }

                // Inactivity Stats
                GlassSection {
                    VStack(spacing: 12) {
                        HStack {
                            Text("Inactive for:")
                            Spacer()
                            // FIX F-04: Use bucketed display instead of exact days — prevents
                            // an attacker with physical access from deriving precise last-active time.
                            Text(Self.bucketedInactivityDisplay(inactivityManager.daysSinceLastActive))
                                .fontWeight(.semibold)
                                .foregroundColor(LadonTheme.coral)
                        }
                        .font(.subheadline)

                        CardDivider()

                        Text("For security, all encryption keys and conversations will be PERMANENTLY DESTROYED in:")
                            .font(.caption)
                            .foregroundColor(LadonTheme.textSecondary)
                            .multilineTextAlignment(.center)
                    }
                    .padding(16)
                }

                // Countdown Timer — coral-tinted glass card
                VStack(spacing: 8) {
                    Text(inactivityManager.formattedCountdown())
                        .font(.jbMono(40, .medium))
                        .fontWeight(.bold)
                        .foregroundColor(LadonTheme.coral)

                    Text("Hours : Minutes : Seconds")
                        .font(.caption2)
                        .foregroundColor(LadonTheme.textSecondary)
                }
                .padding(16)
                .frame(maxWidth: .infinity)
                .background(
                    RoundedRectangle(cornerRadius: 14, style: .continuous)
                        .fill(LadonTheme.coral.opacity(0.10))
                        .overlay(
                            RoundedRectangle(cornerRadius: 14, style: .continuous)
                                .strokeBorder(LadonTheme.coral.opacity(0.35), lineWidth: 1)
                        )
                )

                // Warning Message
                VStack(spacing: 8) {
                    Label("IRREVERSIBLE ACTION", systemImage: "lock.shield.fill")
                        .font(.caption)
                        .fontWeight(.bold)
                        .foregroundColor(LadonTheme.coral)

                    Text("This action cannot be undone. You will need to reinstall LADON messenger and generate new encryption keys.")
                        .font(.caption)
                        .foregroundColor(LadonTheme.coral.opacity(0.85))
                        .multilineTextAlignment(.center)
                }
                .padding(16)
                .frame(maxWidth: .infinity)
                .background(
                    RoundedRectangle(cornerRadius: 14, style: .continuous)
                        .fill(LadonTheme.coral.opacity(0.08))
                        .overlay(
                            RoundedRectangle(cornerRadius: 14, style: .continuous)
                                .strokeBorder(LadonTheme.coral.opacity(0.25), lineWidth: 1)
                        )
                )

                Spacer()

                // Action Buttons
                VStack(spacing: 12) {
                    // Unlock to Reset — green gradient pill (positive action)
                    Button(action: unlockToReset) {
                        HStack(spacing: 8) {
                            Image(systemName: "faceid")
                            Text("Unlock with Face ID to Reset")
                        }
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 14)
                        .background(LadonTheme.greenGradient)
                        .foregroundColor(LadonTheme.background)
                        .clipShape(Capsule())
                        .overlay(Capsule().strokeBorder(LadonTheme.onSurface(0.3), lineWidth: 1))
                        .fontWeight(.semibold)
                    }
                    .buttonStyle(.plain)

                    // FIX HIGH-162: Emergency Destroy requires biometric auth first
                    // Prevents DoS attack where attacker with brief physical access destroys all data
                    Button(action: requestEmergencyDestroy) {
                        HStack(spacing: 8) {
                            Image(systemName: "exclamationmark.triangle.fill")
                            Text("Emergency Destroy Now")
                        }
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 14)
                        .background(LadonTheme.coralGradient)
                        .foregroundColor(LadonTheme.background)
                        .clipShape(Capsule())
                        .overlay(Capsule().strokeBorder(LadonTheme.onSurface(0.3), lineWidth: 1))
                        .fontWeight(.semibold)
                    }
                    .buttonStyle(.plain)

                    // H4 FIX: Cancel requires Face ID authentication (prevents unauthorized dismissal)
                    Button(action: unlockToReset) {
                        Text("Cancel")
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 10)
                            .foregroundColor(LadonTheme.textSecondary)
                    }
                    .buttonStyle(.plain)
                }
                .padding(.bottom, 20)
            }
            .padding(24)
            }
        }
        .alert("Destroy All Keys Now?", isPresented: $showConfirmation) {
            Button("DESTROY", role: .destructive) {
                // FIX MED-8: Re-verify biometric auth at use-time (eliminates TOCTOU gap)
                // Between showing the dialog and pressing DESTROY, auth may have expired
                guard biometricAuth.isAuthenticated && !biometricAuth.isLocked else { return }
                // IW-03 FIX: Call executePanicMode() directly instead of posting notification
                // Direct call cannot be intercepted, suppressed, or spoofed
                executePanicMode()
            }
            Button("Cancel", role: .cancel) { }
        } message: {
            Text("All encryption keys and conversations will be PERMANENTLY destroyed. This cannot be undone.")
        }
    }
    
    /// Light (ladon.app): coral eyebrow, title, white countdown card, coral
    /// banner, green / coral-ghost pills. Same actions as the dark layout.
    private var lightBody: some View {
        VStack(spacing: 0) {
            Spacer(minLength: 12)
            LadonEyebrow(text: "Dead Man's Switch", color: LadonTheme.coralInk)
            Text("Device Inactivity Detected")
                .font(.manrope(30, .extrabold, relativeTo: .largeTitle))
                .tracking(LadonTheme.titleTracking(30))
                .foregroundColor(LadonTheme.textPrimary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.top, 12)
            HStack(spacing: 4) {
                Text("Inactive for:")
                    .foregroundColor(LadonTheme.textSecondary)
                // FIX F-04: bucketed display — no precise last-active time.
                Text(Self.bucketedInactivityDisplay(inactivityManager.daysSinceLastActive))
                    .fontWeight(.bold)
                    .foregroundColor(LadonTheme.textPrimary)
            }
            .font(.manrope(15, relativeTo: .subheadline))
            .padding(.top, 10)

            VStack(spacing: 8) {
                Text("For security, all encryption keys and conversations will be PERMANENTLY DESTROYED in:")
                    .font(.manrope(13, relativeTo: .footnote))
                    .foregroundColor(LadonTheme.textSecondary)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
                Text(inactivityManager.formattedCountdown())
                    .font(.jbMono(40, .medium))
                    .monospacedDigit()
                    .foregroundColor(LadonTheme.coralInk)
                Text("Hours : Minutes : Seconds")
                    .font(.jbMono(10.5, relativeTo: .caption2))
                    .tracking(1.05)
                    .textCase(.uppercase)
                    .foregroundColor(LadonTheme.textSecondary)
            }
            .padding(.vertical, 18)
            .padding(.horizontal, 20)
            .frame(maxWidth: .infinity)
            .background(LadonCardBackground())
            .padding(.top, 18)

            HStack(alignment: .top, spacing: 12) {
                Image(systemName: "exclamationmark.triangle")
                    .font(.system(size: 16, weight: .semibold))
                    .foregroundColor(LadonTheme.coralInk)
                    .padding(.top, 2)
                VStack(alignment: .leading, spacing: 2) {
                    Text("IRREVERSIBLE ACTION")
                        .font(.manrope(14.5, .bold, relativeTo: .subheadline))
                        .foregroundColor(LadonTheme.textPrimary)
                    Text("This action cannot be undone. You will need to reinstall LADON messenger and generate new encryption keys.")
                        .font(.manrope(14, relativeTo: .footnote))
                        .foregroundColor(LadonTheme.textPrimary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 0)
            }
            .padding(.vertical, 12)
            .padding(.horizontal, 14)
            .background(RoundedRectangle(cornerRadius: 18, style: .continuous)
                .fill(LadonTheme.coral.opacity(0.14)))
            .padding(.top, 12)

            Spacer(minLength: 12)

            PairingPrimaryButton(title: "Unlock with Face ID to Reset", systemImage: "faceid", action: unlockToReset)
            // FIX HIGH-162: Emergency Destroy requires biometric auth first.
            Button(action: requestEmergencyDestroy) {
                Label("Emergency Destroy Now", systemImage: "exclamationmark.triangle")
                    .font(.manrope(15.2, .bold, relativeTo: .subheadline))
                    .foregroundColor(LadonTheme.coralInk)
                    .frame(maxWidth: .infinity)
                    .padding(13)
                    .background(GhostPillBackground())
            }
            .buttonStyle(.plain)
            .padding(.top, 10)
            // H4 FIX: Cancel requires Face ID authentication.
            Button(action: unlockToReset) {
                Text("Cancel")
                    .font(.manrope(15, .semibold, relativeTo: .subheadline))
                    .foregroundColor(LadonTheme.textSecondary)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 10)
            }
            .buttonStyle(.plain)
            .padding(.top, 4)
        }
        .padding(.horizontal, 24)
        .padding(.bottom, 8)
    }

    // FIX HIGH-162: Emergency Destroy requires biometric auth first
    // Prevents DoS attack where attacker with brief physical access destroys all data
    private func requestEmergencyDestroy() {
        showBiometricForDestroy = true
        Task {
            await biometricAuth.authenticate()
            if biometricAuth.isAuthenticated {
                showConfirmation = true
            }
            showBiometricForDestroy = false
        }
    }

    private func unlockToReset() {
        Task {
            await biometricAuth.authenticate()
            
            // If authentication successful, dismiss warning
            if biometricAuth.isAuthenticated && !biometricAuth.isLocked {
                inactivityManager.dismissWarning(biometricAuth: biometricAuth)
            }
        }
    }
    
    // FIX L1: Dead dismissWarning() removed — eliminates biometric bypass risk in future refactoring
}

#Preview {
    InactivityWarningView()
        .environmentObject(InactivityManager.shared)
        .environmentObject(BiometricAuthService())
}
