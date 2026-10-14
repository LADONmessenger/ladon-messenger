import SwiftUI

struct ContentView: View {
    // Creates the dependency that makes this view repaint when the
    // appearance changes. LadonTheme's colours are static reads, so
    // without it SwiftUI sees no reason to call body again and the view
    // keeps the previous mode's colours. Unused on purpose.
    @Environment(\.colorScheme) private var ladonAppearanceTick
    @EnvironmentObject var appState: AppState
    @State private var isScreenCaptured = false
    @StateObject private var inactivityManager = InactivityManager.shared
    @State private var showScreenshotBlockedAlert = false
    @Environment(\.scenePhase) private var scenePhase
    /// Measured height of the light tab pill (incl. its bottom padding).
    @State private var tabPillHeight: CGFloat = 0

    /// Light: room for the tab pill at the bottom of every tab screen — the
    /// pill's measured height while it is shown, none while a chat is open
    /// (the pill is hidden there) and none in dark (system tab bar).
    private var pillClearance: CGFloat {
        guard !AppearanceManager.isDarkStored,
              !(appState.selectedTab == 0 && appState.isChatOpen) else { return 0 }
        return tabPillHeight
    }

    /// Light: our pill replaces the system tab bar; dark: unchanged.
    private var tabBarVisibility: Visibility {
        AppearanceManager.isDarkStored ? .automatic : .hidden
    }

    var body: some View {
        ZStack {
            LadonTheme.background.ignoresSafeArea()
            Group {
                if appState.isAuthenticated {
                    // LADON messenger is free (decision 29.09.2026): no subscription
                    // gate — the app opens straight into the tabs after onboarding.
                    TabView(selection: $appState.selectedTab) {
                        ConversationListView()
                            .tabEntrance(tag: 0, selection: appState.selectedTab)
                            .tabItem {
                                Label("Messages", systemImage: "message.fill")
                            }
                            .tag(0)
                            .toolbar(tabBarVisibility, for: .tabBar)
                            .background(TabPillClearance(bottom: pillClearance))

                        SecurityView()
                            .tabEntrance(tag: 1, selection: appState.selectedTab)
                            .tabItem {
                                Label("Security", systemImage: "lock.shield.fill")
                            }
                            .tag(1)
                            .toolbar(tabBarVisibility, for: .tabBar)
                            .background(TabPillClearance(bottom: pillClearance))

                        SettingsView()
                            .tabEntrance(tag: 2, selection: appState.selectedTab)
                            .tabItem {
                                Label("Settings", systemImage: "gear")
                            }
                            .tag(2)
                            .toolbar(tabBarVisibility, for: .tabBar)
                            .background(TabPillClearance(bottom: pillClearance))
                    }
                    .tint(LadonTheme.accent)
                    // Light (ladon.app): our own glass pill replaces the system
                    // tab bar. As a safe-area inset, content keeps clear of it
                    // and scrolls beneath it. Dark: system tab bar, unchanged.
                    .safeAreaInset(edge: .bottom, spacing: 0) {
                        if !AppearanceManager.isDarkStored,
                           !(appState.selectedTab == 0 && appState.isChatOpen) {
                            LadonTabPill(selection: $appState.selectedTab)
                                .padding(.horizontal, 16)
                                .padding(.bottom, 4)
                                .onGeometryChange(for: CGFloat.self) { $0.size.height } action: { tabPillHeight = $0 }
                        }
                    }
                } else {
                    OnboardingView()
                }
            }
            // Show inactivity warning if triggered
            if inactivityManager.showInactivityWarning {
                InactivityWarningView()
                    .environmentObject(inactivityManager)
            }
            
            // Blur overlay when screen is being captured/recorded
            if isScreenCaptured {
                if !AppearanceManager.isDarkStored {
                    LadonContentHiddenView(title: "Screen Recording Detected",
                                           lead: "For security, content is hidden during screen recording or mirroring")
                        .transition(.opacity)
                } else {
                ZStack {
                    MeshBackground()
                    VStack(spacing: 20) {
                        Image(systemName: "eye.slash.fill")
                            .font(.system(size: 60))
                            .foregroundColor(LadonTheme.coral)
                            .shadow(color: LadonTheme.coral.opacity(0.5), radius: 16)

                        Text("Screen Recording Detected")
                            .font(.manrope(22, .bold))
                            .foregroundColor(LadonTheme.textPrimary)

                        Text("For security, content is hidden during screen recording or mirroring")
                            .font(.subheadline)
                            .foregroundColor(LadonTheme.textSecondary)
                            .multilineTextAlignment(.center)
                            .padding(.horizontal)
                    }
                }
                .transition(.opacity)
                }
            }
        }
        .onAppear {
            // SM-M9 FIX: Use onReceive instead of addObserver to avoid observer leak
            // FIX R21-A9-1: Only reset inactivity timer if NO warning is active.
            // Previously, .onAppear fired before biometric auth, silently resetting
            // the Dead Man's Switch — an attacker could repeatedly open/close the app
            // to prevent the switch from ever triggering.
            if !inactivityManager.showInactivityWarning {
                inactivityManager.resetInactivityTimer()
            }
            // Check initial state
            isScreenCaptured = UIScreen.main.isCaptured
        }
        .onReceive(NotificationCenter.default.publisher(for: UIScreen.capturedDidChangeNotification)) { _ in
            withAnimation {
                isScreenCaptured = UIScreen.main.isCaptured
            }
            #if DEBUG
            print("[Security] Screen capture status: \(UIScreen.main.isCaptured)")
            #endif
        }
        .onReceive(NotificationCenter.default.publisher(for: UIApplication.userDidTakeScreenshotNotification)) { _ in
            withAnimation(.easeInOut(duration: 0.25)) {
                showScreenshotBlockedAlert = true
            }
        }
        .overlay {
            if showScreenshotBlockedAlert && !AppearanceManager.isDarkStored {
                screenshotBlockedLight
            } else if showScreenshotBlockedAlert {
                ZStack {
                    Color.black.opacity(0.5)
                        .ignoresSafeArea()
                    
                    VStack(spacing: 16) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .font(.system(size: 36))
                            .foregroundColor(LadonTheme.coral)

                        Text("Screenshot blocked")
                            .font(.manrope(18, .bold))
                            .foregroundColor(LadonTheme.coral)

                        Text("For security reasons, screenshots of chat conversations and sensitive information are not possible.")
                            .font(.subheadline)
                            .foregroundColor(LadonTheme.textSecondary)
                            .multilineTextAlignment(.center)
                            .padding(.horizontal, 8)

                        Button {
                            withAnimation(.easeInOut(duration: 0.3)) {
                                showScreenshotBlockedAlert = false
                            }
                        } label: {
                            Text("OK")
                                .fontWeight(.semibold)
                                .foregroundColor(LadonTheme.background)
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, 12)
                                .background(LadonTheme.coralGradient)
                                .clipShape(Capsule())
                                .overlay(Capsule().strokeBorder(LadonTheme.onSurface(0.3), lineWidth: 1))
                        }
                        .buttonStyle(.plain)
                        .padding(.top, 4)
                    }
                    .padding(24)
                    .background(
                        RoundedRectangle(cornerRadius: 16)
                            .fill(.ultraThinMaterial)
                            .opacity(0.65)
                            .overlay(
                                RoundedRectangle(cornerRadius: 16)
                                    .strokeBorder(LadonTheme.coral.opacity(0.35), lineWidth: 1)
                            )
                    )
                    .padding(.horizontal, 40)
                    .transition(.scale.combined(with: .opacity))
                }
                .transition(.opacity)
            }
        }
        .onChange(of: scenePhase) { _, newPhase in
            inactivityManager.handleScenePhaseChange(newPhase)
        }
    }

    /// Light (ladon.app): ink dim, white 28 pt card, coral badge, green "OK" pill.
    private var screenshotBlockedLight: some View {
        ZStack {
            LadonTheme.onSurface(0.38)
                .ignoresSafeArea()
            VStack(spacing: 0) {
                LadonStatusBadge(systemImage: "exclamationmark.triangle", tint: .coral, size: 64)
                Text("Screenshot blocked")
                    .font(.manrope(21, .extrabold, relativeTo: .title2))
                    .tracking(LadonTheme.titleTracking(21) * 0.6)
                    .foregroundColor(LadonTheme.textPrimary)
                    .padding(.top, 14)
                Text("For security reasons, screenshots of chat conversations and sensitive information are not possible.")
                    .font(.manrope(15, relativeTo: .subheadline))
                    .foregroundColor(LadonTheme.textSecondary)
                    .lineSpacing(3)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.top, 8)
                Button {
                    withAnimation(.easeInOut(duration: 0.3)) {
                        showScreenshotBlockedAlert = false
                    }
                } label: {
                    Text("OK")
                        .font(.manrope(15.2, .bold, relativeTo: .headline))
                        .foregroundColor(LadonTheme.textPrimary)
                        .frame(maxWidth: .infinity)
                        .padding(14)
                        .background(PrimaryPillBackground())
                }
                .buttonStyle(.plain)
                .padding(.top, 18)
            }
            .padding(24)
            .background(LadonCardBackground(cornerRadius: 28, elevated: true))
            .padding(.horizontal, 32)
            .transition(.scale.combined(with: .opacity))
        }
        .transition(.opacity)
    }
    
}

struct OnboardingView: View {
    // Creates the dependency that makes this view repaint when the
    // appearance changes. LadonTheme's colours are static reads, so
    // without it SwiftUI sees no reason to call body again and the view
    // keeps the previous mode's colours. Unused on purpose.
    @Environment(\.colorScheme) private var ladonAppearanceTick
    @EnvironmentObject var appState: AppState
    @State private var isGeneratingKeys = false
    @State private var keygenError: String?
    @State private var currentPage = 0
    @State private var introTextVisible = false
    private var isDark: Bool { AppearanceManager.isDarkStored }
    #if DEBUG
    /// DEBUG-only onboarding preview (Settings): "Get started" calls this and
    /// returns — no identity keys are generated. Never compiled into Release.
    var debugPreviewDismiss: (() -> Void)? = nil
    #endif
    
    private let totalPages = 7
    
    var body: some View {
        ZStack {
            MeshBackground()

            TabView(selection: $currentPage) {
                // ── Screen 1: Welcome ──
                // Light: the design's welcome screen, no intro animation
                // (maintainer, 01.10.2026). Dark: unchanged, with the ASCII intro.
                if isDark {
                    onboardingPage(0) {
                        VStack(spacing: 20) {
                            // The ASCII rain renders FULL-SCREEN (overlay below) so bytes
                            // can fall in from beyond the top edge; this empty slot only
                            // reserves the 64pt logo space and anchors where the logo
                            // assembles + comes to rest. The morphed white logo (in the
                            // overlay) is the resting logo — no separate pulsing logo.
                            Color.clear
                                .frame(width: 64, height: 64)
                                .anchorPreference(key: LogoSlotAnchorKey.self, value: .center) { $0 }

                            Text("LADON messenger")
                                .font(.custom("Manrope-ExtraBold", size: 24))
                                .tracking(0.5)
                                .foregroundColor(LadonTheme.textPrimary)
                                .opacity(introTextVisible ? 1 : 0)

                            Text("Architectural Security for Confidential Communication.")
                                .font(isDark ? .subheadline : .manrope(16, relativeTo: .subheadline))
                                .foregroundColor(LadonTheme.textSecondary)
                                .multilineTextAlignment(.center)
                                .padding(.horizontal, 24)
                                .opacity(introTextVisible ? 1 : 0)

                            Text("Swipe to learn more →")
                                .font(.caption2)
                                .foregroundColor(LadonTheme.textSecondary.opacity(0.5))
                                .italic()
                                .padding(.top, 4)
                                .opacity(introTextVisible ? 1 : 0)
                        }
                    }
                    .overlayPreferenceValue(LogoSlotAnchorKey.self) { anchor in
                        // Full-screen rain overlay (ignores safe area) so the bytes fall in
                        // from beyond the physical top edge; the logo assembles at the slot.
                        GeometryReader { proxy in
                            if let anchor = anchor {
                                LogoAsciiIntro(logoCenter: proxy[anchor]) {
                                    withAnimation(.easeInOut(duration: 0.45).delay(0.05)) {
                                        introTextVisible = true
                                    }
                                }
                            }
                        }
                        .ignoresSafeArea()
                    }
                } else {
                    lightWelcomePage
                        .tag(0)
                }

                // Screens 2-7. Dark: unchanged. Light: the approved preview
                // (artifact "LADON messenger Onboarding", 01.10.2026).
                if isDark {
                    // ── Screen 2: Free, open source, paid out of pocket ──
                    onboardingPage(1) {
                        ViewThatFits(in: .vertical) {
                            noticeCard
                            ScrollView { noticeCard }
                        }
                    }

                    // ── Screen 3: E2E Encryption ──
                    onboardingPage(2) {
                        VStack(spacing: 16) {
                            onboardingIcon("🔐")
                        
                            Text("E2E Encryption")
                                .font(isDark ? .title2.weight(.heavy) : .manrope(26, .extrabold, relativeTo: .title2))
                                .tracking(isDark ? 0 : LadonTheme.titleTracking(26))
                                .foregroundColor(LadonTheme.textPrimary)
                        
                            Text("Your messages are encrypted on your device and can only be read by the recipient.")
                                .font(isDark ? .subheadline : .manrope(16, relativeTo: .subheadline))
                                .foregroundColor(LadonTheme.textSecondary)
                                .multilineTextAlignment(.center)
                                .padding(.horizontal, 24)
                        
                            // Encryption visual
                            HStack(spacing: 8) {
                                encryptionNode("📱")
                                encryptionArrow()
                                encryptionNode("🔐", isLock: true)
                                encryptionArrow()
                                encryptionNode("📱")
                            }
                            .padding(.top, 8)
                            .saturation(0)
                            .brightness(AppearanceManager.isDarkStored ? 0.3 : -0.15)
                            .opacity(0.55)
                        
                            Text("Not even our servers can access your messages.")
                                .font(.caption)
                                .foregroundColor(LadonTheme.textSecondary.opacity(0.7))
                                .multilineTextAlignment(.center)
                                .padding(.horizontal, 32)
                                .padding(.top, 4)
                        }
                    }
                
                    // ── Screen 4: Tor Integration ──
                    onboardingPage(3) {
                        VStack(spacing: 16) {
                            onboardingIcon("🧅")
                        
                            Text("Tor Integration")
                                .font(isDark ? .title2.weight(.heavy) : .manrope(26, .extrabold, relativeTo: .title2))
                                .tracking(isDark ? 0 : LadonTheme.titleTracking(26))
                                .foregroundColor(LadonTheme.textPrimary)
                        
                            Text("All app traffic is routed through the Tor network. Our servers and the people you write to never see your IP address.")
                                .font(isDark ? .subheadline : .manrope(16, relativeTo: .subheadline))
                                .foregroundColor(LadonTheme.textSecondary)
                                .multilineTextAlignment(.center)
                                .padding(.horizontal, 24)
                        
                            // Tor visual
                            HStack(spacing: 4) {
                                torHop("📱", active: false)
                                torLine()
                                torHop("🧅", active: true)
                                torLine()
                                torHop("🧅", active: true)
                                torLine()
                                torHop("🧅", active: true)
                                torLine()
                                torHop("🌍", active: false)
                            }
                            .padding(.top, 8)
                            .saturation(0)
                            .brightness(AppearanceManager.isDarkStored ? 0.3 : -0.15)
                            .opacity(0.55)
                        
                            Text("Connection setup takes a few seconds.\nThis is normal and ensures maximum privacy.")
                                .font(.caption)
                                .foregroundColor(LadonTheme.textSecondary.opacity(0.7))
                                .multilineTextAlignment(.center)
                                .padding(.horizontal, 32)
                                .padding(.top, 4)
                        }
                    }
                
                    // ── Screen 5: Safety Numbers ──
                    onboardingPage(4) {
                        VStack(spacing: 16) {
                            onboardingIcon("📲")
                        
                            Text("Verify Your Contacts")
                                .font(isDark ? .title2.weight(.heavy) : .manrope(26, .extrabold, relativeTo: .title2))
                                .tracking(isDark ? 0 : LadonTheme.titleTracking(26))
                                .foregroundColor(LadonTheme.textPrimary)
                        
                            Text("Compare Safety Numbers to ensure no one is intercepting your messages.")
                                .font(isDark ? .subheadline : .manrope(16, relativeTo: .subheadline))
                                .foregroundColor(LadonTheme.textSecondary)
                                .multilineTextAlignment(.center)
                                .padding(.horizontal, 24)
                        
                            // Safety number grid
                            LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 4), count: 4), spacing: 4) {
                                ForEach(["38274", "91053", "47182", "63920", "15847", "29361", "50483", "72916"], id: \.self) { num in
                                    Text(num)
                                        .font(.system(size: 12, design: .monospaced))
                                        .foregroundColor(LadonTheme.textSecondary.opacity(0.6))
                                        .padding(.vertical, 4)
                                        .padding(.horizontal, 6)
                                        .background(LadonTheme.onSurface(0.04))
                                        .cornerRadius(4)
                                        .overlay(
                                            RoundedRectangle(cornerRadius: 4)
                                                .stroke(LadonTheme.onSurface(0.08), lineWidth: 1)
                                        )
                                }
                            }
                            .frame(maxWidth: 200)
                            .padding(.top, 8)
                        
                            HStack(spacing: 0) {
                                Text("Tap the ")
                                    .font(.caption)
                                    .foregroundColor(LadonTheme.textSecondary.opacity(0.7))
                                Image("LadonLogo")
                                    .resizable()
                                    .scaledToFit()
                                    .frame(width: 12, height: 12)
                                    .padding(.horizontal, 3)
                                Text(" icon in any chat to verify.")
                                    .font(.caption)
                                    .foregroundColor(LadonTheme.textSecondary.opacity(0.7))
                            }
                            .padding(.top, 4)
                        }
                    }
                
                    // ── Screen 6: Security Features ──
                    onboardingPage(5) {
                        VStack(spacing: 16) {
                            onboardingIcon("🛡")
                        
                            Text("You're in Control")
                                .font(isDark ? .title2.weight(.heavy) : .manrope(26, .extrabold, relativeTo: .title2))
                                .tracking(isDark ? 0 : LadonTheme.titleTracking(26))
                                .foregroundColor(LadonTheme.textPrimary)
                        
                            Text("Advanced security features protect your conversations at every level.")
                                .font(isDark ? .subheadline : .manrope(16, relativeTo: .subheadline))
                                .foregroundColor(LadonTheme.textSecondary)
                                .multilineTextAlignment(.center)
                                .padding(.horizontal, 24)
                        
                            // Feature pills
                            let features = ["👆 Face ID", "🚫 No Tracking", "⏱ Disappearing", "🚨 Panic Mode", "📡 Cover Traffic", "🛡 Post-Quantum"]
                            FlowLayout(spacing: 6) {
                                ForEach(features, id: \.self) { feature in
                                    Text(feature)
                                        .font(.system(size: 11, weight: .semibold))
                                        .foregroundColor(Color.green.opacity(0.7))
                                        .padding(.vertical, 5)
                                        .padding(.horizontal, 12)
                                        .background(Color.green.opacity(0.08))
                                        .cornerRadius(20)
                                        .overlay(
                                            RoundedRectangle(cornerRadius: 20)
                                                .stroke(Color.green.opacity(0.2), lineWidth: 1)
                                        )
                                }
                            }
                            .saturation(0)
                            .brightness(AppearanceManager.isDarkStored ? 0.3 : -0.15)
                            .opacity(0.55)
                            .frame(maxWidth: 240)
                            .padding(.top, 8)
                        }
                    }
                
                    // ── Screen 7: Setup ──
                    onboardingPage(6) {
                        VStack(spacing: 20) {
                            PulsingLogo(size: 64)
                        
                            Text("Ready to Start")
                                .font(isDark ? .title2.weight(.heavy) : .manrope(26, .extrabold, relativeTo: .title2))
                                .tracking(isDark ? 0 : LadonTheme.titleTracking(26))
                                .foregroundColor(LadonTheme.textPrimary)
                        
                            Text("No phone number. No email. No tracking.\nJust secure communication.")
                                .font(isDark ? .subheadline : .manrope(16, relativeTo: .subheadline))
                                .foregroundColor(LadonTheme.textSecondary)
                                .multilineTextAlignment(.center)
                                .padding(.horizontal, 24)
                        }
                    }
                } else {
                    lightPages
                }
            }
            .tabViewStyle(.page(indexDisplayMode: .never))
            .animation(.easeInOut(duration: 0.3), value: currentPage)
            // Fill the physical screen so screen-0's full-screen rain overlay can
            // render bytes falling in from beyond the top edge (the page would
            // otherwise clip the overlay at the safe-area inset). Content stays
            // centered → negligible (~6pt) shift on the other screens.
            .ignoresSafeArea()
            
            // Skip button (screens 2-6) — jumps to the last page. The notice
            // (screen 2) comes right after the welcome, so every new user
            // has seen it before Skip appears.
            if currentPage > 1 && currentPage < totalPages - 1 {
                VStack {
                    HStack {
                        Spacer()
                        Button("Skip") {
                            withAnimation { currentPage = totalPages - 1 }
                        }
                        .font(isDark ? .system(size: 14, weight: .semibold) : .jbMono(11.5, relativeTo: .caption2))
                        .tracking(isDark ? 0 : 1.15)
                        .textCase(isDark ? nil : .uppercase)
                        .foregroundColor(isDark ? LadonTheme.textSecondary.opacity(0.6) : LadonTheme.inkMuted)
                        .padding(.trailing, 24)
                        .padding(.top, 8)
                    }
                    Spacer()
                }
            }
            
            // Bottom area: dots + button
            VStack {
                Spacer()

                if !isDark {
                    lightBottomControls
                } else {
                    // Page dots
                    pageDots
                        .padding(.bottom, 12)

                    // Action button
                    if currentPage < totalPages - 1 {
                        Button {
                            withAnimation { currentPage += 1 }
                        } label: {
                            Text("Next")
                                .font(isDark ? .system(size: 16, weight: .bold) : .manrope(15.2, .bold, relativeTo: .headline))
                                .foregroundColor(isDark ? LadonTheme.background : LadonTheme.textPrimary)
                                .frame(maxWidth: 200)
                                .padding(.vertical, 14)
                                .background(isDark ? Color.white : LadonTheme.brandGreen)
                                .cornerRadius(isDark ? 14 : 26)
                                .shadow(color: isDark ? .clear : LadonTheme.brandGreen.opacity(0.45), radius: 15, y: 10)
                        }
                        .padding(.bottom, 32)
                    } else {
                        if isGeneratingKeys {
                            ProgressView("Generating encryption keys...")
                                .padding(.bottom, 32)
                        } else {
                            VStack(spacing: 8) {
                                Button(action: setupAccount) {
                                    Text("Get started")
                                        .font(isDark ? .system(size: 16, weight: .bold) : .manrope(15.2, .bold, relativeTo: .headline))
                                        .foregroundColor(isDark ? Color(red: 0.1, green: 0.1, blue: 0.12) : LadonTheme.textPrimary)
                                        .frame(maxWidth: 200)
                                        .padding(.vertical, 14)
                                        .background(
                                            isDark
                                            ? AnyShapeStyle(LinearGradient(colors: [Color(red: 0.29, green: 0.87, blue: 0.5), Color(red: 0.13, green: 0.77, blue: 0.37)], startPoint: .topLeading, endPoint: .bottomTrailing))
                                            : AnyShapeStyle(LadonTheme.brandGreen)
                                        )
                                        .cornerRadius(isDark ? 14 : 26)
                                        .shadow(color: isDark ? Color.green.opacity(0.25) : LadonTheme.brandGreen.opacity(0.45),
                                                radius: isDark ? 10 : 15, y: isDark ? 4 : 10)
                                }
                            
                                Text("Your identity keys will be generated\nlocally on this device.")
                                    .font(.system(size: 10))
                                    .foregroundColor(LadonTheme.textSecondary.opacity(0.4))
                                    .multilineTextAlignment(.center)
                            }
                            .padding(.bottom, 32)
                        }
                    }
                }
            }
        }
        .alert("Error", isPresented: Binding(get: { keygenError != nil }, set: { if !$0 { keygenError = nil } })) {
            Button("Try Again") { setupAccount() }
            Button("OK", role: .cancel) { }
        } message: {
            Text(keygenError ?? "")
        }
    }
    

    // MARK: - Light onboarding (screens 2-7, approved preview 01.10.2026)

    /// Room the light bottom controls take: the row with dots + Next, and the
    /// taller "Get started" block on the last page.
    private static let lightRowRoom: CGFloat = 76
    private static let lightReadyRoom: CGFloat = 150

    @ViewBuilder private var lightPages: some View {
        // ── Screen 2: Free, open source, paid out of pocket ──
        lightPage(1) {
            ViewThatFits(in: .vertical) {
                FreeOpenSourceNotice(large: true)
                ScrollView(showsIndicators: false) { FreeOpenSourceNotice(large: true) }
            }
        }

        // ── Screen 3: E2E Encryption ──
        lightPage(2) {
            lightHeader(eyebrow: "End-to-end", title: "E2E Encryption",
                        lead: "Your messages are encrypted on your device and can only be read by the recipient.")
            lightCard {
                HStack(spacing: 6) {
                    flowNode(label: "You")
                    DashedLine()
                    HStack(spacing: 8) {
                        Image(systemName: "lock")
                            .font(.system(size: 13, weight: .medium))
                        Text("Sealed")
                            .font(.jbMono(10, relativeTo: .caption2))
                            .tracking(0.8)
                            .textCase(.uppercase)
                    }
                    .foregroundColor(LadonTheme.brandGreen)
                    .padding(.vertical, 9)
                    .padding(.horizontal, 12)
                    .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(LadonTheme.packet))
                    DashedLine()
                    flowNode(label: "Recipient")
                }
                lightNote("Not even our servers can access your messages.")
            }
        }

        // ── Screen 4: Tor Integration ──
        lightPage(3) {
            lightHeader(eyebrow: "Network", title: "Tor Integration",
                        lead: "All app traffic is routed through the Tor network. Our servers and the people you write to never see your IP address.")
            lightCard {
                HStack(alignment: .top, spacing: 0) {
                    torNode(icon: "iphone", label: "You")
                    torSegment
                    torNode(icon: nil, label: "Guard")
                    torSegment
                    torNode(icon: nil, label: "Middle")
                    torSegment
                    torNode(icon: nil, label: "Exit")
                    torSegment
                    torNode(icon: "server.rack", label: "Relay")
                }
                lightNote("Connection setup takes a few seconds. This is normal and ensures maximum privacy.")
            }
        }

        // ── Screen 5: Safety Numbers ──
        lightPage(4) {
            lightHeader(eyebrow: "Safety Number", title: "Verify Your Contacts",
                        lead: "Compare Safety Numbers to ensure no one is intercepting your messages.")
            lightCard {
                // Example only — the real format: 60 digits in 12 groups of 5
                // (SafetyNumbersView.swift:62).
                LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 14), count: 3), spacing: 10) {
                    ForEach(["38274", "91053", "47182", "63920", "15847", "29361",
                             "50483", "72916", "06158", "84430", "31907", "55642"], id: \.self) { group in
                        Text(verbatim: group)
                            .font(.jbMono(17, relativeTo: .body))
                            .foregroundColor(LadonTheme.textPrimary)
                    }
                }
                .accessibilityHidden(true)
                lightNote("Open the safety number with the \(Image(systemName: "checkmark.shield")) at the top right of any chat.")
            }
        }

        // ── Screen 6: Security Features ──
        lightPage(5) {
            lightHeader(eyebrow: "Features", title: "You're in Control",
                        lead: "Advanced security features protect your conversations at every level.")
            lightCard {
                FlowLayout(spacing: 8) {
                    featureChip("faceid", "Face ID")
                    featureChip("nosign", "No Tracking")
                    featureChip("timer", "Disappearing")
                    featureChip("exclamationmark.octagon", "Panic Mode")
                    featureChip("waveform.path", "Cover Traffic")
                    featureChip("shield", "Post-Quantum")
                }
            }
        }

        // ── Screen 7: Setup ──
        lightPage(6, bottomRoom: Self.lightReadyRoom) {
            Image("LadonLogo")
                .renderingMode(.template)
                .resizable()
                .scaledToFit()
                .frame(width: 56, height: 56)
                .foregroundColor(LadonTheme.greenInk)
                .accessibilityHidden(true)
            Text("Ready to Start")
                .font(.manrope(44, .extrabold, relativeTo: .largeTitle))
                .tracking(LadonTheme.titleTracking(44))
                .foregroundColor(LadonTheme.textPrimary)
                .padding(.top, 22)
            VStack(alignment: .leading, spacing: 0) {
                Text("No phone number. No email. No tracking.")
                    .foregroundColor(LadonTheme.textSecondary)
                Text("Just secure communication.")
                    .fontWeight(.bold)
                    .foregroundColor(LadonTheme.textPrimary)
            }
            .font(.manrope(18, relativeTo: .body))
            .padding(.top, 14)
        }
    }

    /// Light page frame: content in the vertical middle, left-aligned; the
    /// page is full-screen (the TabView ignores the safe area), so the window
    /// insets are added by hand, plus room for Skip on top and the controls
    /// at the bottom.
    private func lightPage<Content: View>(_ index: Int, bottomRoom: CGFloat = OnboardingView.lightRowRoom,
                                          @ViewBuilder content: () -> Content) -> some View {
        let insets = Self.windowInsets
        return VStack(alignment: .leading, spacing: 0) {
            Spacer(minLength: 0)
            content()
            Spacer(minLength: 0)
        }
        .padding(.top, insets.top + 40)
        .padding(.bottom, insets.bottom + bottomRoom)
        .padding(.horizontal, 24)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .leading)
        .tag(index)
    }

    private func lightHeader(eyebrow: LocalizedStringKey, title: LocalizedStringKey,
                             lead: LocalizedStringKey) -> some View {
        VStack(alignment: .leading, spacing: 14) {
            LadonEyebrow(text: eyebrow)
            Text(title)
                .font(.manrope(38, .extrabold, relativeTo: .largeTitle))
                .tracking(LadonTheme.titleTracking(38))
                .foregroundColor(LadonTheme.textPrimary)
                .fixedSize(horizontal: false, vertical: true)
            Text(lead)
                .font(.manrope(17, relativeTo: .body))
                .foregroundColor(LadonTheme.textSecondary)
                .lineSpacing(3)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private func lightCard<Content: View>(@ViewBuilder _ content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 0) { content() }
            .padding(20)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(LadonCardBackground())
            .padding(.top, 26)
    }

    private func lightNote(_ text: LocalizedStringKey) -> some View {
        Text(text)
            .font(.manrope(14, relativeTo: .footnote))
            .foregroundColor(LadonTheme.textSecondary)
            .lineSpacing(2)
            .fixedSize(horizontal: false, vertical: true)
            .padding(.top, 14)
    }

    private func flowNode(label: LocalizedStringKey) -> some View {
        VStack(spacing: 6) {
            Image(systemName: "iphone")
                .font(.system(size: 20, weight: .regular))
                .foregroundColor(LadonTheme.textSecondary)
                .frame(width: 46, height: 46)
                .background(RoundedRectangle(cornerRadius: 16, style: .continuous).fill(LadonTheme.paper2))
            monoCaption(label)
        }
    }

    private func torNode(icon: String?, label: LocalizedStringKey) -> some View {
        VStack(spacing: 6) {
            ZStack {
                if let icon {
                    Circle().fill(Color.white)
                        .overlay(Circle().strokeBorder(LadonTheme.onSurface(0.14), lineWidth: 1))
                    Image(systemName: icon)
                        .font(.system(size: 15, weight: .regular))
                        .foregroundColor(LadonTheme.textSecondary)
                } else {
                    Circle().fill(LadonTheme.brandGreenSoft)
                    Circle().fill(LadonTheme.greenInk).frame(width: 10, height: 10)
                }
            }
            .frame(width: 40, height: 40)
            monoCaption(label)
        }
        .frame(width: 52)
    }

    private var torSegment: some View {
        Rectangle()
            .fill(LadonTheme.onSurface(0.14))
            .frame(height: 1.5)
            .padding(.top, 19.25)
    }

    private func monoCaption(_ text: LocalizedStringKey) -> some View {
        Text(text)
            .font(.jbMono(10.5, relativeTo: .caption2))
            .tracking(1.26)
            .textCase(.uppercase)
            .foregroundColor(LadonTheme.inkMuted)
            .lineLimit(1)
            .fixedSize()
    }

    private func featureChip(_ icon: String, _ label: LocalizedStringKey) -> some View {
        HStack(spacing: 8) {
            Image(systemName: icon)
                .font(.system(size: 12, weight: .semibold))
            Text(label)
                .font(.jbMono(11.5, .medium, relativeTo: .caption))
                .tracking(1.15)
                .textCase(.uppercase)
        }
        .foregroundColor(LadonTheme.greenDeep)
        .padding(.vertical, 8)
        .padding(.leading, 10)
        .padding(.trailing, 14)
        .background(Capsule().fill(LadonTheme.brandGreenSoft))
    }

    /// Light bottom controls: welcome row (dots + swipe hint), then dots +
    /// compact Next, then the full-width "Get started" block.
    @ViewBuilder private var lightBottomControls: some View {
        if currentPage == 0 {
            HStack {
                pageDots
                Spacer()
                Button {
                    withAnimation { currentPage = 1 }
                } label: {
                    Text("Swipe to learn more →")
                        .font(.jbMono(11.5, relativeTo: .caption2))
                        .tracking(1.15)
                        .textCase(.uppercase)
                        .foregroundColor(LadonTheme.inkMuted)
                }
                .buttonStyle(.plain)
            }
            .padding(.horizontal, 24)
            .padding(.bottom, 14)
        } else if currentPage < totalPages - 1 {
            HStack {
                pageDots
                Spacer()
                Button {
                    withAnimation { currentPage += 1 }
                } label: {
                    HStack(spacing: 8) {
                        Text("Next")
                        Image(systemName: "arrow.right")
                    }
                    .font(.manrope(15.2, .bold, relativeTo: .headline))
                    .foregroundColor(LadonTheme.textPrimary)
                    .padding(.vertical, 12)
                    .padding(.horizontal, 22)
                    .background(Capsule().fill(LadonTheme.brandGreen))
                    .shadow(color: LadonTheme.brandGreen.opacity(0.45), radius: 15, y: 10)
                }
                .buttonStyle(.plain)
            }
            .padding(.horizontal, 24)
            .padding(.bottom, 14)
        } else {
            VStack(spacing: 12) {
                if isGeneratingKeys {
                    ProgressView("Generating encryption keys...")
                        .frame(height: 50)
                } else {
                    Button(action: setupAccount) {
                        HStack(spacing: 9.6) {
                            Text("Get started")
                            Image(systemName: "arrow.right")
                        }
                        .font(.manrope(15.2, .bold, relativeTo: .headline))
                        .foregroundColor(LadonTheme.textPrimary)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 15)
                        .background(Capsule().fill(LadonTheme.brandGreen))
                        .shadow(color: LadonTheme.brandGreen.opacity(0.45), radius: 15, y: 10)
                    }
                    .buttonStyle(.plain)
                }
                pageDots
                Text("Your identity keys will be generated\nlocally on this device.")
                    .font(.manrope(12.5, relativeTo: .caption))
                    .foregroundColor(LadonTheme.inkMuted)
                    .multilineTextAlignment(.center)
            }
            .padding(.horizontal, 24)
            .padding(.bottom, 14)
        }
    }

    // MARK: - Helpers

    private var pageDots: some View {
        HStack(spacing: isDark ? 8 : 6) {
            ForEach(0..<totalPages, id: \.self) { index in
                Capsule()
                    .fill(index == currentPage
                          ? (isDark ? Color.white : LadonTheme.brandGreen)
                          : LadonTheme.onSurface(isDark ? 0.2 : 0.14))
                    .frame(width: index == currentPage ? (isDark ? 20 : 22) : (isDark ? 8 : 7),
                           height: isDark ? 8 : 7)
                    .shadow(color: isDark && index == currentPage ? LadonTheme.onSurface(0.3) : .clear, radius: 4)
                    .animation(.easeInOut(duration: 0.25), value: currentPage)
            }
        }
    }

    private static var windowInsets: UIEdgeInsets {
        UIApplication.shared.connectedScenes
            .compactMap { ($0 as? UIWindowScene)?.keyWindow }
            .first?.safeAreaInsets ?? .zero
    }

    /// Light (ladon.app design, "Welcome"): tag, faint watermark mark, green
    /// mark, 58 pt title, lead with the second half in ink. The page is
    /// full-screen (the TabView ignores the safe area), so the window insets
    /// are added by hand; the bottom leaves room for the dots row.
    private var lightWelcomePage: some View {
        let insets = Self.windowInsets
        return VStack(alignment: .leading, spacing: 0) {
            LadonTagPill(text: "Beta · 2026", dot: true)
            Spacer(minLength: 0)
            VStack(alignment: .leading, spacing: 22) {
                Image("LadonLogo")
                    .renderingMode(.template)
                    .resizable()
                    .scaledToFit()
                    .frame(width: 56, height: 56)
                    .foregroundColor(LadonTheme.greenInk)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 0) {
                    Text(verbatim: "LADON")
                        .font(.custom("Manrope-ExtraBold", fixedSize: 58))
                        .tracking(-0.045 * 58)
                        .frame(height: 56, alignment: .leading)
                    Text(verbatim: "messenger")
                        .font(.custom("Manrope-Medium", fixedSize: 58))
                        .tracking(-0.03 * 58)
                        .modifier(ObliqueEffect())
                        .frame(height: 56, alignment: .leading)
                }
                .foregroundColor(LadonTheme.textPrimary)
                .accessibilityElement(children: .combine)
                Text("Architectural Security for \(Text("Confidential Communication.").font(.manrope(19, .bold, relativeTo: .title3)).foregroundColor(LadonTheme.textPrimary))")
                    .font(.manrope(19, relativeTo: .title3))
                    .foregroundColor(LadonTheme.textSecondary)
                    .lineSpacing(4)
                    .frame(maxWidth: 310, alignment: .leading)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(.top, insets.top + 10)
        .padding(.bottom, insets.bottom + 14 + 7 + 44)
        .padding(.horizontal, 24)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .leading)
        .background(alignment: .topTrailing) {
            Image("LadonLogo")
                .renderingMode(.template)
                .resizable()
                .scaledToFit()
                .frame(width: 360, height: 360)
                .foregroundColor(LadonTheme.onSurface(0.03))
                .offset(x: 90, y: 70)
                .accessibilityHidden(true)
        }
    }

    /// The free / open-source notice as an onboarding card.
    private var noticeCard: some View {
        FreeOpenSourceNotice()
            .padding(20)
            .background {
                if isDark {
                    RoundedRectangle(cornerRadius: 20, style: .continuous)
                        .fill(.ultraThinMaterial)
                        .opacity(0.55)
                        .overlay(
                            RoundedRectangle(cornerRadius: 20, style: .continuous)
                                .strokeBorder(LadonTheme.glassStroke, lineWidth: 1)
                        )
                } else {
                    LadonCardBackground()
                }
            }
            .padding(.horizontal, 20)
    }
    
    @ViewBuilder
    private func onboardingPage(_ index: Int, @ViewBuilder content: () -> some View) -> some View {
        VStack {
            Spacer()
            content()
            Spacer()
            // Spacer for bottom controls
            Color.clear.frame(height: 120)
        }
        .tag(index)
    }
    
    private func onboardingIcon(_ emoji: String) -> some View {
        Text(emoji)
            .font(.system(size: 42))
            .frame(width: 72, height: 72)
            .background(LadonTheme.onSurface(0.04))
            .overlay(
                RoundedRectangle(cornerRadius: 18)
                    .stroke(LadonTheme.onSurface(0.08), lineWidth: 1)
            )
            .cornerRadius(18)
            .saturation(0)
            .brightness(AppearanceManager.isDarkStored ? 0.3 : -0.15)
            .opacity(0.55)
    }
    
    private func encryptionNode(_ emoji: String, isLock: Bool = false) -> some View {
        Text(emoji)
            .font(.system(size: 14))
            .frame(width: 32, height: 32)
            .background(isLock ? Color.green.opacity(0.1) : LadonTheme.onSurface(0.08))
            .overlay(
                RoundedRectangle(cornerRadius: 8)
                    .stroke(isLock ? Color.green.opacity(0.3) : LadonTheme.onSurface(0.15), lineWidth: 1)
            )
            .cornerRadius(8)
    }
    
    private func encryptionArrow() -> some View {
        Text("───")
            .font(.system(size: 10))
            .foregroundColor(Color.green.opacity(0.6))
    }
    
    private func torHop(_ emoji: String, active: Bool) -> some View {
        Text(emoji)
            .font(.system(size: 11))
            .frame(width: 28, height: 28)
            .background(active ? Color.purple.opacity(0.1) : LadonTheme.onSurface(0.06))
            .overlay(
                Circle()
                    .stroke(active ? Color.purple.opacity(0.4) : LadonTheme.onSurface(0.12), lineWidth: 1)
            )
            .clipShape(Circle())
    }
    
    private func torLine() -> some View {
        Rectangle()
            .fill(LadonTheme.onSurface(0.15))
            .frame(width: 12, height: 1)
    }
    
    private func setupAccount() {
        #if DEBUG
        if let debugPreviewDismiss {
            debugPreviewDismiss()
            return
        }
        #endif
        isGeneratingKeys = true
        
        Task {
            do {
                try await KeyManager.shared.generateIdentityKeys()
                await MainActor.run {
                    appState.isAuthenticated = true
                    isGeneratingKeys = false
                    // FIX FRESH-PROVISION:
                    // 1) Mark KeyManager unlocked. After fresh onboarding the
                    //    user never went through Face ID, so _isAppLocked
                    //    defaults to true and blocks every loadSigningPrivateKey()
                    //    read. That made provisionAuthSecret fail silently
                    //    (signMessage \u2192 nil \u2192 completion(false)) and the
                    //    relay auth secret was never stored \u2192 \u201cA:\u274c\u201d in the
                    //    pre-send diagnostic. The keys were just generated
                    //    by an explicit user action on this device, so it is
                    //    safe to release the app-level lock now. The lock
                    //    re-engages automatically when the app backgrounds,
                    //    so the next foreground transition still requires
                    //    Face ID as designed.
                    KeyManager.shared.setAppLocked(false)
                    // 2) Drive the existing post-auth pipeline (provision \u2192
                    //    UAK registration \u2192 push) without waiting for the
                    //    first background\u2192foreground cycle.
                    NotificationCenter.default.post(name: .biometricAuthSuccess, object: nil)
                }
            } catch {
                #if DEBUG
                print("Error generating keys: \(error)")
                #endif
                await MainActor.run {
                    // FIX LOW-18: Show error to user instead of silently failing
                    keygenError = "Key generation failed. Please try again."
                    isGeneratingKeys = false
                }
            }
        }
    }
}

// MARK: - Flow Layout for Feature Pills

struct FlowLayout: Layout {
    var spacing: CGFloat = 6
    
    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let result = arrangeSubviews(proposal: proposal, subviews: subviews)
        return result.size
    }
    
    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        let result = arrangeSubviews(proposal: proposal, subviews: subviews)
        for (index, position) in result.positions.enumerated() {
            subviews[index].place(at: CGPoint(x: bounds.minX + position.x, y: bounds.minY + position.y), proposal: .unspecified)
        }
    }
    
    private func arrangeSubviews(proposal: ProposedViewSize, subviews: Subviews) -> (positions: [CGPoint], size: CGSize) {
        let maxWidth = proposal.width ?? .infinity
        var positions: [CGPoint] = []
        var x: CGFloat = 0
        var y: CGFloat = 0
        var rowHeight: CGFloat = 0
        
        for subview in subviews {
            let size = subview.sizeThatFits(.unspecified)
            if x + size.width > maxWidth && x > 0 {
                x = 0
                y += rowHeight + spacing
                rowHeight = 0
            }
            positions.append(CGPoint(x: x, y: y))
            rowHeight = max(rowHeight, size.height)
            x += size.width + spacing
        }
        
        return (positions, CGSize(width: maxWidth, height: y + rowHeight))
    }
}

#Preview {
    ContentView()
        .environmentObject(AppState())
}

/// Gives every tab screen room for the light tab pill. SwiftUI safe-area
/// modifiers on a tab do not reach into its NavigationStack — measured on the
/// 17 Pro: the Settings content kept a 34 pt bottom inset with a 72 pt pill
/// over it. The inset is therefore set in UIKit, which hands it down to the
/// tab's NavigationStack and every pushed screen: `additionalSafeAreaInsets`
/// of the tab's root controller (the direct child of the tab bar controller,
/// `TabHostingController`). NOT on the tab bar controller itself — measured on
/// the 12 Pro (iOS 26.5): that left the whole app white; iOS 27 tolerated it.
/// The pill sits outside the tabs and is unaffected.
struct TabPillClearance: UIViewControllerRepresentable {
    let bottom: CGFloat

    func makeUIViewController(context: Context) -> Controller { Controller() }

    func updateUIViewController(_ controller: Controller, context: Context) {
        controller.bottom = bottom
        controller.apply()
    }

    final class Controller: UIViewController {
        var bottom: CGFloat = 0

        override func didMove(toParent parent: UIViewController?) {
            super.didMove(toParent: parent)
            apply()
        }

        override func viewWillAppear(_ animated: Bool) {
            super.viewWillAppear(animated)
            apply()
        }

        func apply() {
            guard let tab = tabRoot, tab.additionalSafeAreaInsets.bottom != bottom else { return }
            tab.additionalSafeAreaInsets.bottom = bottom
        }

        /// This tab's root controller: the ancestor that is a direct child of
        /// the tab bar controller.
        private var tabRoot: UIViewController? {
            var current: UIViewController = self
            while let parent = current.parent {
                if parent is UITabBarController { return current }
                current = parent
            }
            return nil
        }
    }
}

/// A horizontal dashed rule (onboarding E2E flow).
struct DashedLine: View {
    var body: some View {
        GeometryReader { geo in
            Path { p in
                p.move(to: CGPoint(x: 0, y: geo.size.height / 2))
                p.addLine(to: CGPoint(x: geo.size.width, y: geo.size.height / 2))
            }
            .stroke(LadonTheme.onSurface(0.14), style: StrokeStyle(lineWidth: 1.5, dash: [4, 3]))
        }
        .frame(height: 2)
        .frame(maxWidth: .infinity)
        .padding(.bottom, 22)
    }
}

/// Synthetic oblique for Manrope, which ships no italic face — the same
/// slant (tan ≈ 0.25) browsers apply to ladon.app's italic "messenger".
struct ObliqueEffect: GeometryEffect {
    var slant: CGFloat = 0.25
    func effectValue(size: CGSize) -> ProjectionTransform {
        ProjectionTransform(CGAffineTransform(a: 1, b: 0, c: -slant, d: 1, tx: slant * size.height / 2, ty: 0))
    }
}

/// The maintainer's notice (DE 29.09.2026, EN approved 01.10.2026 — both verbatim):
/// free, open source, servers paid out of pocket. Shown once in onboarding and
/// in Settings → Info. "Its code is public" is only true once the repository
/// is public — this must not ship before that.
struct FreeOpenSourceNotice: View {
    @Environment(\.colorScheme) private var ladonAppearanceTick
    /// Onboarding page (light): large title, no card around it.
    var large: Bool = false
    var body: some View {
        let dark = AppearanceManager.isDarkStored
        VStack(alignment: .leading, spacing: large ? 14 : 12) {
            Text("Free. Open source. Paid out of my own pocket.")
                .font(dark ? .headline : .manrope(large ? 32 : 19, .extrabold, relativeTo: .headline))
                .tracking(dark ? 0 : (large ? LadonTheme.titleTracking(32) : -0.38))
                .foregroundColor(LadonTheme.textPrimary)
            Group {
                Text("LADON messenger is free, and its code is public. Anyone can check what the app does. The servers your messages travel through cost money every month, and right now I pay for them myself. If LADON messenger helps you, a tip keeps it running.")
                Text("If LADON messenger grows and the servers need a real upgrade, the app may one day cost CHF 2 to 5 per month. If it comes to that, you'll hear it here first, with the reasons. What won't change: no ads, no trackers, no selling of data. **You are never the product.**")
            }
            .font(dark ? .subheadline : .manrope(large ? 15.5 : 15, relativeTo: .subheadline))
            .foregroundColor(LadonTheme.textSecondary)
            .lineSpacing(2)
        }
        .fixedSize(horizontal: false, vertical: true)
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

/// The light-mode tab bar (ladon.app nav pill): frosted white capsule,
/// icon over label, the active tab on a soft green chip.
struct LadonTabPill: View {
    @Environment(\.colorScheme) private var ladonAppearanceTick
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Binding var selection: Int

    private struct Item {
        let tag: Int
        let title: LocalizedStringKey
        let icon: String
    }
    private let items = [
        Item(tag: 0, title: "Messages", icon: "bubble.left"),
        Item(tag: 1, title: "Security", icon: "lock.shield"),
        Item(tag: 2, title: "Settings", icon: "gearshape"),
    ]
    private static let spacing: CGFloat = 4

    /// Edges of the green indicator in the row's coordinate space. One
    /// indicator travels between the tabs (instead of one background per tab)
    /// so it can stretch like a rubber band — the maintainer's choice "Gummi",
    /// 02.10.2026, values from the approved motion preview.
    @State private var lead: CGFloat = 0
    @State private var trail: CGFloat = 0
    @State private var rowWidth: CGFloat = 0
    /// Bumped on every switch; a superseded sequence stops at its next step.
    @State private var motion = 0

    private func edges(_ tag: Int, width: CGFloat) -> (lead: CGFloat, trail: CGFloat) {
        let w = max(0, (width - CGFloat(items.count - 1) * Self.spacing) / CGFloat(items.count))
        let l = CGFloat(tag) * (w + Self.spacing)
        return (l, l + w)
    }

    var body: some View {
        HStack(spacing: Self.spacing) {
            ForEach(items, id: \.tag) { item in
                let active = selection == item.tag
                Button { selection = item.tag } label: {
                    VStack(spacing: 3) {
                        Image(systemName: item.icon)
                            .font(.system(size: 20, weight: .regular))
                            .frame(height: 22)
                        Text(item.title)
                            .font(.manrope(11, active ? .bold : .semibold))
                    }
                    .foregroundColor(active ? LadonTheme.greenDeep : LadonTheme.inkMuted)
                    .animation(reduceMotion ? nil : .easeOut(duration: 0.3), value: active)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 8)
                    .contentShape(Capsule())
                }
                .buttonStyle(.plain)
                .accessibilityAddTraits(active ? .isSelected : [])
            }
        }
        .background(alignment: .leading) {
            Capsule()
                .fill(LadonTheme.brandGreenSoft)
                .frame(width: max(0, trail - lead))
                .offset(x: lead)
        }
        .onGeometryChange(for: CGFloat.self) { $0.size.width } action: { width in
            rowWidth = width
            (lead, trail) = edges(selection, width: width)
        }
        .onChange(of: selection) { old, new in stretch(from: old, to: new) }
        .padding(6)
        .background(
            Capsule()
                .fill(.ultraThinMaterial)
                .overlay(Capsule().fill(Color.white.opacity(0.75)))
                .overlay(Capsule().strokeBorder(Color.white.opacity(0.7), lineWidth: 1))
                .shadow(color: LadonTheme.onSurface(0.05), radius: 1, y: 1)
                .shadow(color: LadonTheme.onSurface(0.14), radius: 20, y: 12)
        )
    }

    /// The rubber band: the front edge runs ahead to the target, then the
    /// trailing edge snaps after it, overshoots by 12 pt and swings back
    /// (−6, +2) before it rests. 0.9 s in all. Reduce Motion: no animation.
    private func stretch(from old: Int, to new: Int) {
        let target = edges(new, width: rowWidth)
        motion &+= 1
        let gen = motion
        guard !reduceMotion, old != new else { (lead, trail) = target; return }
        let right = new > old
        // Trailing edge position at `d` pt past the target (inward = positive).
        func trailing(_ d: CGFloat) { if right { lead = target.lead + d } else { trail = target.trail - d } }
        let steps: [(Animation, CGFloat)] = [
            (.timingCurve(0.3, 0, 0.4, 1, duration: 0.198), 12),
            (.easeInOut(duration: 0.162), -6),
            (.easeInOut(duration: 0.135), 2),
            (.easeInOut(duration: 0.135), 0),
        ]
        func run(_ i: Int) {
            guard i < steps.count, gen == motion else { return }
            withAnimation(steps[i].0) { trailing(steps[i].1) } completion: { run(i + 1) }
        }
        withAnimation(.timingCurve(0.65, 0, 0.35, 1, duration: 0.27)) {
            if right { trail = target.trail } else { lead = target.lead }
        } completion: { run(0) }
    }
}

