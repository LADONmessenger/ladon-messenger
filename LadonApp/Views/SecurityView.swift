import SwiftUI

// Sicherheitsuebersicht — getrennt von SettingsView (Umbau 2026-08-20).
//
// Aufteilung nach einem einfachen Kriterium: Was man BEDIENT, steht in den
// Einstellungen; was die App von sich aus TUT, steht hier. Vorher lagen beide
// Arten in SettingsView, wo allein der About-Abschnitt 603 der 1233 Zeilen
// ausmachte und 133 weitere Zeilen reine Statusanzeigen ohne ein einziges
// Bedienelement waren.
//
// Die Bloecke sind wortwoertlich aus SettingsView uebernommen, damit Wortlaut
// und Darstellung identisch bleiben; nur ihr Ort hat sich geaendert.
struct SecurityView: View {
    // Creates the dependency that makes this view repaint when the
    // appearance changes. LadonTheme's colours are static reads, so
    // without it SwiftUI sees no reason to call body again and the view
    // keeps the previous mode's colours. Unused on purpose.
    @Environment(\.colorScheme) private var ladonAppearanceTick
    @State private var showEncryptionDetails = false
    private var isDark: Bool { AppearanceManager.isDarkStored }

    // Gleiche Huelle wie in SettingsView, damit beide Seiten identisch wirken.
    @ViewBuilder
    private func glassSection<Content: View>(
        header: LocalizedStringKey? = nil,
        footer: LocalizedStringKey? = nil,
        @ViewBuilder _ content: @escaping () -> Content
    ) -> some View {
        GlassSection(header: header, footer: footer, content: content)
            .staggerIn()
    }

    /// Lockdown recommendation. Dark renders exactly the original elements;
    /// light swaps in the ladon.app pieces (tag pill, mono path chip).
    private var lockdownContent: some View {
        VStack(alignment: .leading, spacing: isDark ? 8 : 10) {
            HStack(spacing: 8) {
                Image(systemName: "lock.shield.fill")
                    .font(.title3)
                    .foregroundColor(LadonTheme.greenInk)
                Text("Lockdown Mode")
                    .font(isDark ? .headline : .manrope(17, .extrabold))
                    .tracking(isDark ? 0 : -0.3)
                    .foregroundColor(LadonTheme.textPrimary)
                Spacer()
                if isDark {
                    Text("Recommended")
                        .font(.caption2).bold()
                        .padding(.horizontal, 8)
                        .padding(.vertical, 3)
                        .background(LadonTheme.brandGreen.opacity(0.2))
                        .foregroundColor(LadonTheme.brandGreen)
                        .clipShape(Capsule())
                } else {
                    LadonTagPill(text: "Recommended")
                }
            }
            Text("Apple's strongest defense against targeted spyware like Pegasus. LADON messenger can't enable it — turn it on in iOS:")
                .font(isDark ? .caption : .manrope(13.5, relativeTo: .caption))
                .foregroundColor(LadonTheme.textSecondary)
            // No "Open Settings" button: openSettingsURLString can only
            // land on Ladon's own app page, from which Lockdown Mode
            // (Settings root → Privacy & Security) isn't reachable — a
            // button there would be misleading. The step line guides
            // accurately instead.
            if isDark {
                Text("Settings → Privacy & Security → Lockdown Mode")
                    .font(.caption).bold()
                    .foregroundColor(LadonTheme.textPrimary)
                    .padding(.top, 2)
            } else {
                Text("Settings → Privacy & Security → Lockdown Mode")
                    .font(.jbMono(11, relativeTo: .caption))
                    .foregroundColor(LadonTheme.textPrimary)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 9)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(
                        RoundedRectangle(cornerRadius: 12, style: .continuous)
                            .fill(Color.white)
                            .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous)
                                .strokeBorder(LadonTheme.onSurface(0.08), lineWidth: 1))
                    )
            }
        }
    }

    /// One "Advanced Security" row. Dark = the original HStack; light adds the
    /// ladon.app check circle and Manrope title.
    private func protectionRow(_ icon: String, _ title: LocalizedStringKey, _ subtitle: LocalizedStringKey) -> some View {
        HStack {
            Image(systemName: icon)
            VStack(alignment: .leading) {
                Text(title)
                    .font(isDark ? .body : .manrope(15.5, .bold))
                Text(subtitle)
                    .font(.caption)
                    .foregroundColor(LadonTheme.textSecondary)
            }
            Spacer()
            if isDark {
                Image(systemName: "checkmark.circle")
                    .foregroundColor(LadonTheme.accent)
            } else {
                LadonCheckCircle()
            }
        }
    }

    var body: some View {
        NavigationStack {
            ZStack {
            MeshBackground()
            VStack(spacing: 0) {
                HStack(alignment: .center, spacing: 8) {
                    PulsingLogo(size: 28)
                    Text("Security")
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
                if isDark {
                    glassSection { lockdownContent.padding(16) }
                } else {
                    // ladon.app band: soft paper panel with a faint logo watermark.
                    lockdownContent
                        .padding(18)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(
                            RoundedRectangle(cornerRadius: 24, style: .continuous)
                                .fill(LadonTheme.paper2)
                                .overlay(alignment: .topTrailing) {
                                    Image("LadonLogo")
                                        .resizable()
                                        .renderingMode(.template)
                                        .scaledToFit()
                                        .frame(width: 170, height: 170)
                                        .foregroundColor(LadonTheme.onSurface(0.03))
                                        .offset(x: 40, y: -50)
                                        .accessibilityHidden(true)
                                }
                                .clipShape(RoundedRectangle(cornerRadius: 24, style: .continuous))
                        )
                }

                glassSection(header: "Security Status") {
                    Group {
                    // Frueher stand hier ein Countdown auf die naechste
                    // Signed-PreKey-Rotation (alle 48 h) samt Fortschrittsbalken.
                    // Dieser Schluessel stammt aus dem alten X3DH-Verfahren und
                    // wird von V2 nirgends mehr gelesen — die Anzeige zaehlte
                    // also auf ein folgenloses Ereignis, und der Warntext
                    // ("rotiert beim naechsten Senden") stimmte ebenfalls nicht.
                    // Was wirklich laeuft, ist ungleich staerker und steht jetzt
                    // hier: der Double Ratchet, belegt in RelayClientV2
                    // (dhRatchetSend/dhRatchetReceive, frisches ML-KEM je DH-Schritt).
                    VStack(alignment: .leading, spacing: 8) {
                        HStack(spacing: 10) {
                            Image(systemName: "arrow.triangle.2.circlepath")
                                .foregroundColor(LadonTheme.greenInk)
                            Text("Key Rotation")
                                .font(isDark ? .callout : .manrope(15.5, .bold))
                            Spacer()
                            Text("Continuous")
                                .font(isDark ? .callout : .manrope(15, .extrabold))
                                .foregroundColor(LadonTheme.greenInk)
                                .fontWeight(.semibold)
                        }

                        Text("Every message gets a fresh key. Each time the conversation turns around, the whole key chain is renewed — and every 32nd turn adds a new post-quantum key on top. Nothing here needs your attention.")
                            .font(.caption)
                            .foregroundColor(LadonTheme.textSecondary)
                    }
                    }
                    .padding(16)
                }

                glassSection(header: "Advanced Security") {
                    // `.padding(16)` on each row reproduces what the former
                    // `Group { … }.padding(16)` did per child, so dark is unchanged;
                    // light adds 1 pt hairlines between the rows.
                    VStack(alignment: .leading, spacing: 0) {
                    // FIX CRIT-7: Accurately describe feature — uses Ed25519 signatures,
                    // not zero-knowledge proofs. Honesty prevents false security claims.
                    protectionRow("checkmark.seal.fill", "Message Authenticity", "Ed25519 digital signatures")
                        .padding(16)
                    if !isDark { CardDivider() }
                    protectionRow("eye.slash.fill", "Sealed Sender", "Server cannot see who sends messages")
                        .padding(16)
                    if !isDark { CardDivider() }
                    protectionRow("waveform.path", "Cover Traffic", "Hides real communication patterns")
                        .padding(16)
                    if !isDark { CardDivider() }
                    protectionRow("atom", "Post-Quantum Cryptography", "Kyber768 + Dilithium3 (NIST)")
                        .padding(16)
                    if !isDark { CardDivider() }
                    protectionRow("network", "Tor Routing", "All traffic routed through Tor network")
                        .padding(16)

                    HStack(alignment: .top, spacing: 8) {
                        Image(systemName: "info.circle")
                            .foregroundColor(LadonTheme.greenInk)
                        Text("These protections add extra layers beyond end-to-end encryption. Ed25519 signatures verify authenticity, sealed sender hides the sender from the server, cover traffic masks communication patterns, post-quantum cryptography protects against future quantum computers, and Tor routing anonymizes network traffic.")
                            .font(.footnote)
                            .foregroundColor(LadonTheme.textSecondary)
                    }
                    .padding(isDark ? 8 : 12)
                    .background(LadonTheme.paper2)
                    .cornerRadius(isDark ? 8 : 14)
                    .padding(16)
                    }
                }

                glassSection(header: "About") {
                    Group {
                    HStack {
                        Text("App Version")
                        Spacer()
                            // L3 FIX: Dynamic version from Bundle instead of hardcoded
                            // Test builds made outside Xcode set LADON_TEST_BUILD
                            // ("<commit count>-<short hash>") so the installed stand is
                            // visible; empty for normal builds. The real build number
                            // (CFBundleVersion, App Store lineage) is never touched.
                            Text("\(Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "2.0") (\(Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "1"))" + ((Bundle.main.infoDictionary?["LadonTestBuild"] as? String).flatMap { $0.isEmpty ? nil : " · Test \($0)" } ?? ""))
                            .foregroundColor(LadonTheme.textSecondary)
                    }
                    
                    VStack(alignment: .leading, spacing: 0) {
                        Button(action: { withAnimation { showEncryptionDetails.toggle() } }) {
                            HStack {
                                Text("Encryption Details")
                                Spacer()
                                Image(systemName: showEncryptionDetails ? "chevron.down" : "chevron.right")
                                    .foregroundColor(LadonTheme.textSecondary)
                            }
                            .foregroundColor(LadonTheme.textPrimary)
                        }
                        
                        if showEncryptionDetails {
                            FadingSeparator()
                                .padding(.vertical, 8)
                            
                            VStack(alignment: .leading, spacing: 10) {
                                HStack(alignment: .top, spacing: 12) {
                                    Image(systemName: "lock.fill")
                                        .frame(width: 24, alignment: .leading)
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text("Message Encryption").fontWeight(.semibold)
                                        Text("Signal Protocol with Double Ratchet algorithm. Every message uses a unique encryption key that is automatically deleted after use, ensuring perfect forward secrecy.").font(.caption).foregroundColor(LadonTheme.textSecondary)
                                    }
                                    Spacer()
                                }
                                
                                HStack(alignment: .top, spacing: 12) {
                                    Image(systemName: "key.fill")
                                        .frame(width: 24, alignment: .leading)
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text("Key Exchange").fontWeight(.semibold)
                                        Text("X3DH (Extended Triple Diffie-Hellman) combined with Kyber768 post-quantum key encapsulation. Protects your keys even against future quantum computers.").font(.caption).foregroundColor(LadonTheme.textSecondary)
                                    }
                                    Spacer()
                                }
                                
                                HStack(alignment: .top, spacing: 12) {
                                    Image(systemName: "shield.fill")
                                        .frame(width: 24, alignment: .leading)
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text("Digital Signatures").fontWeight(.semibold)
                                        Text("Dilithium3 post-quantum signatures verify message authenticity. Each message is cryptographically signed to prevent tampering and impersonation.").font(.caption).foregroundColor(LadonTheme.textSecondary)
                                    }
                                    Spacer()
                                }
                                
                                HStack(alignment: .top, spacing: 12) {
                                    Image(systemName: "link.circle.fill")
                                        .frame(width: 24, alignment: .leading)
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text("Symmetric Encryption").fontWeight(.semibold)
                                        Text("ChaCha20-Poly1305 AEAD cipher provides authenticated encryption. Military-grade 256-bit security with built-in message authentication to detect tampering.").font(.caption).foregroundColor(LadonTheme.textSecondary)
                                    }
                                    Spacer()
                                }
                                
                                HStack(alignment: .top, spacing: 12) {
                                    Image(systemName: "arrow.2.circlepath")
                                        .frame(width: 24, alignment: .leading)
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text("Key Derivation").fontWeight(.semibold)
                                        Text("HKDF (HMAC-based Key Derivation Function) generates cryptographically strong keys from shared secrets. Each conversation derives unique encryption keys.").font(.caption).foregroundColor(LadonTheme.textSecondary)
                                    }
                                    Spacer()
                                }
                                
                                HStack(alignment: .top, spacing: 12) {
                                    Image(systemName: "bolt.fill")
                                        .frame(width: 24, alignment: .leading)
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text("Forward Secrecy").fontWeight(.semibold)
                                        Text("Double Ratchet continuously generates new keys. Even if your device is compromised, past messages stay encrypted — the keys that could open them no longer exist.").font(.caption).foregroundColor(LadonTheme.textSecondary)
                                    }
                                    Spacer()
                                }
                                
                                HStack(alignment: .top, spacing: 12) {
                                    Image(systemName: "globe")
                                        .frame(width: 24, alignment: .leading)
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text("Quantum Protection").fontWeight(.semibold)
                                        Text("Kyber768 and Dilithium3 are NIST-standardized post-quantum algorithms. Your messages are protected against both current and future quantum computer attacks.").font(.caption).foregroundColor(LadonTheme.textSecondary)
                                    }
                                    Spacer()
                                }
                            }
                            .padding(.vertical, 8)
                        }
                    }
                    
                    HStack {
                        Text("Security Level")
                        Spacer()
                        Text("Production")
                            .foregroundColor(LadonTheme.greenInk)
                            .fontWeight(.semibold)
                    }
                    }
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
            }
            }
        }
    }

}
