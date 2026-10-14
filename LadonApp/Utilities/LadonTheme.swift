import SwiftUI
import UIKit
import CryptoKit

// MARK: - LADON Design System
// Consistent with ladon.app website (Manrope font, dark theme, card-style UI)

enum LadonTheme {
    // MARK: - Colors (from ladon.app CSS)
    //
    // LIGHT / DARK
    //
    // Dark is the original design and every dark value below is byte-identical
    // to what it was before light mode existed. Light mirrors it in brightness
    // only: same layout, same radii, same spacing, same motion, same glass.
    //
    // Brand colours (green, coral, their gradients and the semantic aliases
    // built on them) do NOT mirror — they are the identity.
    //
    // A view that reads these has no SwiftUI dependency on them. Every view
    // therefore also reads `\.colorScheme` (the `ladonAppearanceTick`
    // properties), which `.preferredColorScheme` flips on switch — that
    // invalidates each view in place, so it re-reads these colours while
    // keeping navigation and scroll position.
    //
    // LIGHT PALETTE, in one sentence: the same anthracite (#2F2F33) that IS
    // the dark ground becomes the ink, the edge and the shade; the ground turns
    // to a cool light grey; glass stays glass (material + white wash + 1 px
    // edge + soft shadow); the mesh keeps its full colour, which on a light
    // ground reads as pastel.

    /// True when dark is selected. Read from UserDefaults so these stay usable
    /// off the main actor.
    private static var dark: Bool { AppearanceManager.isDarkStored }

    /// The colour that reads ON the current surface: white on dark, near-black
    /// on light. Every `Color.white.opacity(x)` that was meant as "a subtle
    /// lift on a dark surface" becomes `onSurface(x)` — on a light surface the
    /// same intent is a subtle *shade*, not a lift.
    static func onSurface(_ o: Double) -> Color {
        dark ? Color.white.opacity(o)
             : Color(red: 23/255, green: 25/255, blue: 27/255).opacity(o)      // ink #17191b (ladon.app)
    }

    /// UIKit counterpart of `textPrimary`, for the UITextField-backed input
    /// bars. Those sit on `.ultraThinMaterial`, which follows the appearance —
    /// a fixed white ink disappears on it in light mode.
    static var uiInk: UIColor {
        dark ? UIColor(red: 245/255, green: 246/255, blue: 247/255, alpha: 1)
             : UIColor(red: 23/255, green: 25/255, blue: 27/255, alpha: 1)     // #17191b
    }

    /// Primary background: #2F2F33 dark / #f7f9f8 light (ladon.app --paper).
    static var background: Color {
        dark ? Color(red: 47/255, green: 47/255, blue: 51/255)
             : Color(red: 247/255, green: 249/255, blue: 248/255)
    }

    /// Primary text: #F5F6F7 dark / #17191b light (ladon.app --ink)
    static var textPrimary: Color {
        dark ? Color(red: 245/255, green: 246/255, blue: 247/255)
             : Color(red: 23/255, green: 25/255, blue: 27/255)
    }

    /// Secondary text — light: #4b5054 (ladon.app --ink-2)
    static var textSecondary: Color {
        dark ? onSurface(0.45) : Color(red: 75/255, green: 80/255, blue: 84/255)
    }

    /// Tertiary text
    static var textTertiary: Color { onSurface(dark ? 0.78 : 0.78) }

    /// Card background — translucent wash over the backdrop in both modes.
    static var cardBackground: Color {
        dark ? Color.white.opacity(0.04) : Color.white      // light: solid white card (ladon.app --card)
    }

    /// Opaque card background for Form sections.
    /// Used for .listRowBackground() in Forms where transparent colors would composite
    /// over the system cell background instead of our app background.
    static var cardBackgroundSolid: Color {
        dark ? Color(red: 63/255, green: 63/255, blue: 67/255) : Color.white
    }

    /// Card border
    static var cardBorder: Color { onSurface(dark ? 0.08 : 0.08) }

    /// Elevated card
    static var cardElevated: Color {
        dark ? Color.white.opacity(0.06) : Color.white.opacity(0.80)
    }

    /// Ghost border
    static var ghostBorder: Color { onSurface(dark ? 0.30 : 0.24) }

    /// Subtle separator
    static var separator: Color { onSurface(dark ? 0.06 : 0.10) }

    /// Glow color
    static var glow: Color { onSurface(dark ? 0.07 : 0.06) }

    /// Outgoing message bubble — the high-contrast counterpoint in both modes.
    static var bubbleOutgoing: Color {
        dark ? Color(red: 245/255, green: 246/255, blue: 247/255)
             : Color(red: 47/255, green: 47/255, blue: 51/255)
    }

    /// Outgoing message text
    static var bubbleOutgoingText: Color {
        dark ? Color(red: 47/255, green: 47/255, blue: 51/255)
             : Color(red: 245/255, green: 246/255, blue: 247/255)
    }

    /// Incoming message bubble
    static var bubbleIncoming: Color {
        dark ? Color(red: 28/255, green: 28/255, blue: 30/255) : Color.white
    }

    /// Incoming message text
    static var bubbleIncomingText: Color {
        dark ? Color(red: 245/255, green: 246/255, blue: 247/255)
             : Color(red: 23/255, green: 25/255, blue: 27/255)
    }
    
    /// Accent / Unread badge
    static let accent = brandGreen   // P1: was white #F5F6F7 → brand green #34d399
    
    /// Danger/destructive
    static let danger = coral        // P1: → brand coral #ec7464
    
    /// Warning
    static let warning = coral       // P1: → brand coral #ec7464
    
    /// Success
    static let success = brandGreen  // P1: → brand green #34d399
    
    /// UIKit counterpart of `background`, for the appearance proxies.
    static var uiBackground: UIColor {
        dark ? UIColor(red: 47/255, green: 47/255, blue: 51/255, alpha: 1)
             : UIColor(red: 247/255, green: 249/255, blue: 248/255, alpha: 1)
    }

    // MARK: - Light-mode brand tokens (ladon.app light.css, sha 95f318f1)
    // In dark they resolve to exactly what the call sites used before, so a
    // call site can switch to them without touching dark mode.

    /// Green as TEXT: #0f8a5a in light (#34d399 is too pale on white); dark = brandGreen.
    static var greenInk: Color {
        dark ? brandGreen : Color(red: 15/255, green: 138/255, blue: 90/255)
    }
    /// Deep green for text on green tints: #0b6b46 in light; dark = brandGreen.
    static var greenDeep: Color {
        dark ? brandGreen : Color(red: 11/255, green: 107/255, blue: 70/255)
    }
    /// Coral as TEXT: #c94d3c in light; dark = coral.
    static var coralInk: Color {
        dark ? coral : Color(red: 201/255, green: 77/255, blue: 60/255)
    }
    /// Tertiary/meta text in light: #8b9195 (ladon.app --ink-3); dark = textSecondary.
    static var inkMuted: Color {
        dark ? textSecondary : Color(red: 139/255, green: 145/255, blue: 149/255)
    }
    /// Soft paper for inset panels: #eef2f0 (ladon.app --paper-2); dark = cardBackground.
    static var paper2: Color {
        dark ? cardBackground : Color(red: 238/255, green: 242/255, blue: 240/255)
    }
    /// The only dark surface in light mode — for encrypted things: #1f2124.
    static let packet = Color(red: 31/255, green: 33/255, blue: 36/255)
    /// Title tracking of the website (-0.035em) in points for a given size.
    static func titleTracking(_ size: CGFloat) -> CGFloat { -0.035 * size }

    /// Global UIKit appearance (navigation bar, tab bar, table backgrounds).
    ///
    /// Used to live inline in the App's `init()` with hard-coded dark values,
    /// which had two consequences in light mode: white tab icons on a light
    /// bar (invisible), and no way to change any of it at runtime because
    /// `init()` runs once. Now derived from the theme and re-applied by
    /// `AppearanceManager` on every switch. Appearance proxies only affect
    /// views created afterwards, so the last step re-attaches the existing
    /// window subviews to force the live tab bar to pick the new values up.
    @MainActor
    static func applyUIKitAppearance() {
        let bg = uiBackground
        let ink = uiInk
        let muted = ink.withAlphaComponent(dark ? 0.45 : 0.50)

        let nav = UINavigationBarAppearance()
        nav.configureWithOpaqueBackground()
        nav.backgroundColor = bg
        nav.titleTextAttributes = [.foregroundColor: ink]
        nav.largeTitleTextAttributes = [.foregroundColor: ink]
        nav.shadowColor = .clear
        UINavigationBar.appearance().standardAppearance = nav
        UINavigationBar.appearance().compactAppearance = nav
        UINavigationBar.appearance().scrollEdgeAppearance = nav
        UINavigationBar.appearance().tintColor = ink

        let tab = UITabBarAppearance()
        tab.configureWithOpaqueBackground()
        tab.backgroundColor = bg
        tab.stackedLayoutAppearance.normal.iconColor = muted
        tab.stackedLayoutAppearance.normal.titleTextAttributes = [.foregroundColor: muted]
        tab.stackedLayoutAppearance.selected.iconColor = ink
        tab.stackedLayoutAppearance.selected.titleTextAttributes = [.foregroundColor: ink]
        tab.shadowColor = .clear
        UITabBar.appearance().standardAppearance = tab
        UITabBar.appearance().scrollEdgeAppearance = tab

        UITableView.appearance().backgroundColor = bg
        UICollectionView.appearance().backgroundColor = bg

        // Appearance proxies only affect bars created afterwards. Update the
        // ones already on screen in place. (An earlier version detached and
        // re-attached the window's subviews to force this — on a SwiftUI
        // window that tears down the hosting view and leaves the screen
        // black. Never do that.)
        for case let scene as UIWindowScene in UIApplication.shared.connectedScenes {
            for window in scene.windows {
                for bar in window.descendants(ofType: UITabBar.self) {
                    bar.standardAppearance = tab
                    bar.scrollEdgeAppearance = tab
                    bar.setNeedsLayout()
                }
                for bar in window.descendants(ofType: UINavigationBar.self) {
                    bar.standardAppearance = nav
                    bar.compactAppearance = nav
                    bar.scrollEdgeAppearance = nav
                    bar.tintColor = ink
                    bar.setNeedsLayout()
                }
            }
        }
    }

    // MARK: - Corner Radii (from website: 16-20px)
    static let cornerRadiusSmall: CGFloat = 12
    static let cornerRadiusMedium: CGFloat = 16
    static let cornerRadiusLarge: CGFloat = 20
    static let cornerRadiusPill: CGFloat = 999
    
    // MARK: - Spacing
    static let spacingXS: CGFloat = 4
    static let spacingSM: CGFloat = 8
    static let spacingMD: CGFloat = 16
    static let spacingLG: CGFloat = 24
    static let spacingXL: CGFloat = 36
    static let spacingXXL: CGFloat = 48

    // MARK: - Brand (glass-morph) — additive, NOT yet wired in (rolls out from P1)
    // Source: ladon.app live site CSS tokens (:root). See docs / design mockups.
    /// Brand accent #34d399 (website green). Replaces the white `accent` in P1.
    static let brandGreen     = Color(red: 52/255,  green: 211/255, blue: 153/255)
    static let brandGreenSoft = Color(red: 52/255,  green: 211/255, blue: 153/255).opacity(0.16)
    /// Lighter green for liquid-glass gradients (#56e0b2).
    static let brandGreenLight = Color(red: 86/255, green: 224/255, blue: 178/255)
    /// Signature green gradient (light → brand) for buttons / checks / badges.
    static let greenGradient = LinearGradient(colors: [brandGreenLight, brandGreen],
                                              startPoint: .topLeading, endPoint: .bottomTrailing)
    /// Lighter coral + coral gradient (mirror of the green gradient, for destructive circle buttons).
    static let coralLight = Color(red: 242/255, green: 150/255, blue: 138/255)
    static let coralGradient = LinearGradient(colors: [coralLight, coral],
                                             startPoint: .topLeading, endPoint: .bottomTrailing)
    /// Warm / destructive #ec7464 (website coral). Replaces raw .red/.orange in P1.
    static let coral          = Color(red: 236/255, green: 116/255, blue: 100/255)
    static let coralSoft      = Color(red: 236/255, green: 116/255, blue: 100/255).opacity(0.16)
    /// Layered surfaces (for sections / sheets / mesh base).
    static var backgroundSoft: Color {
        dark ? Color(red: 42/255, green: 42/255, blue: 46/255)     // #2a2a2e
             : Color(red: 236/255, green: 236/255, blue: 239/255)  // #ececef
    }
    static var backgroundDeep: Color {
        dark ? Color(red: 35/255, green: 35/255, blue: 39/255)     // #232327
             : Color(red: 227/255, green: 227/255, blue: 231/255)  // #e3e3e7
    }
    /// Glass inner edge. White in dark mode (the classic glass highlight);
    /// in light mode the edges carry the dark mode's background grey #2F2F33
    /// instead — explicit design direction, it frames the cards the way the
    /// dark ground did.
    static var glassStroke: Color {
        dark ? Color.white.opacity(0.16)
             : Color(red: 23/255, green: 25/255, blue: 27/255).opacity(0.08)   // ladon.app --line
    }
    static var borderHi: Color { onSurface(dark ? 0.12 : 0.16) }

    /// Card shadow. Dark keeps the original tinted shadow (the ground colour
    /// at 50 %); light needs a genuinely dark, soft shadow — the tinted one
    /// would be near-white on near-white and vanish.
    static var shadow: Color {
        dark ? background.opacity(0.5) : Color.black.opacity(0.08)
    }

    // MARK: - Motion (website signature easings)
    enum Motion {
        /// Soft settle — cubic-bezier(0.16, 1, 0.3, 1).
        static let easeOut  = Animation.timingCurve(0.16, 1, 0.3, 1, duration: 0.5)
        /// Standard — cubic-bezier(0.65, 0, 0.35, 1).
        static let standard = Animation.timingCurve(0.65, 0, 0.35, 1, duration: 0.4)
    }

    // MARK: - Master switch (instant rollback; made permanent / removed in P7)
    /// false = classic look, true = glass-morph. Kept `true` during rollout.
    static let glassMorph = true
}

// MARK: - Identicon Generator
// Deterministic avatar from a public key string — no image upload needed

struct IdenticonView: View {
    // Creates the dependency that makes this view repaint when the
    // appearance changes. LadonTheme's colours are static reads, so
    // without it SwiftUI sees no reason to call body again and the view
    // keeps the previous mode's colours. Unused on purpose.
    @Environment(\.colorScheme) private var ladonAppearanceTick
    let publicKey: String
    let size: CGFloat
    
    /// Derive a stable hash from the key string
    /// FIX MED-NEW-02: Use SHA-256 instead of weak byte-summing hash.
    /// Prevents trivially crafted collisions in identicon generation.
    private var keyHash: [UInt8] {
        let data = Data(publicKey.utf8)
        let digest = SHA256.hash(data: data)
        return Array(digest.prefix(16))
    }
    
    /// Two gradient colors derived from key bytes
    private var gradientColors: (Color, Color) {
        let h = keyHash
        let hue1 = Double(h[0]) / 255.0
        let hue2 = Double(h[1]) / 255.0
        let sat1 = 0.4 + Double(h[2]) / 255.0 * 0.4 // 0.4–0.8
        let sat2 = 0.4 + Double(h[3]) / 255.0 * 0.4
        
        let c1 = Color(hue: hue1, saturation: sat1, brightness: 0.75)
        let c2 = Color(hue: hue2, saturation: sat2, brightness: 0.55)
        return (c1, c2)
    }
    
    /// Initials from key (first 2 hex chars)
    private var initials: String {
        let hex = publicKey.prefix(2).uppercased()
        return hex.isEmpty ? "??" : hex
    }
    
    var body: some View {
        ZStack {
            // Gradient circle
            Circle()
                .fill(
                    LinearGradient(
                        colors: [gradientColors.0, gradientColors.1],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    )
                )
                .frame(width: size, height: size)
            
            // Initials overlay
            Text(initials)
                .font(.system(size: size * 0.36, weight: .bold, design: .rounded))
                .foregroundColor(.white.opacity(0.9))
        }
        .overlay(
            Circle()
                .stroke(LadonTheme.cardBorder, lineWidth: 1)
        )
    }
}

// MARK: - Chat Bubble Shape with Tail

struct BubbleShape: Shape {
    let isOutgoing: Bool
    let tailSize: CGFloat
    
    init(isOutgoing: Bool, tailSize: CGFloat = 8) {
        self.isOutgoing = isOutgoing
        self.tailSize = tailSize
    }
    
    func path(in rect: CGRect) -> Path {
        let radius: CGFloat = 16
        let tail = tailSize
        
        var path = Path()
        
        if isOutgoing {
            // Rounded rect with tail on bottom-right
            path.move(to: CGPoint(x: rect.minX + radius, y: rect.minY))
            path.addLine(to: CGPoint(x: rect.maxX - radius, y: rect.minY))
            path.addArc(center: CGPoint(x: rect.maxX - radius, y: rect.minY + radius),
                       radius: radius, startAngle: .degrees(-90), endAngle: .degrees(0), clockwise: false)
            path.addLine(to: CGPoint(x: rect.maxX, y: rect.maxY - radius - tail))
            // Tail curve
            path.addCurve(
                to: CGPoint(x: rect.maxX + tail, y: rect.maxY),
                control1: CGPoint(x: rect.maxX, y: rect.maxY - tail * 0.3),
                control2: CGPoint(x: rect.maxX + tail * 0.6, y: rect.maxY)
            )
            path.addCurve(
                to: CGPoint(x: rect.maxX - radius * 0.5, y: rect.maxY),
                control1: CGPoint(x: rect.maxX + tail * 0.2, y: rect.maxY),
                control2: CGPoint(x: rect.maxX, y: rect.maxY)
            )
            path.addLine(to: CGPoint(x: rect.minX + radius, y: rect.maxY))
            path.addArc(center: CGPoint(x: rect.minX + radius, y: rect.maxY - radius),
                       radius: radius, startAngle: .degrees(90), endAngle: .degrees(180), clockwise: false)
            path.addLine(to: CGPoint(x: rect.minX, y: rect.minY + radius))
            path.addArc(center: CGPoint(x: rect.minX + radius, y: rect.minY + radius),
                       radius: radius, startAngle: .degrees(180), endAngle: .degrees(270), clockwise: false)
        } else {
            // Rounded rect with tail on bottom-left
            path.move(to: CGPoint(x: rect.minX + radius, y: rect.minY))
            path.addLine(to: CGPoint(x: rect.maxX - radius, y: rect.minY))
            path.addArc(center: CGPoint(x: rect.maxX - radius, y: rect.minY + radius),
                       radius: radius, startAngle: .degrees(-90), endAngle: .degrees(0), clockwise: false)
            path.addLine(to: CGPoint(x: rect.maxX, y: rect.maxY - radius))
            path.addArc(center: CGPoint(x: rect.maxX - radius, y: rect.maxY - radius),
                       radius: radius, startAngle: .degrees(0), endAngle: .degrees(90), clockwise: false)
            path.addLine(to: CGPoint(x: rect.minX + radius * 0.5, y: rect.maxY))
            // Tail curve
            path.addCurve(
                to: CGPoint(x: rect.minX - tail, y: rect.maxY),
                control1: CGPoint(x: rect.minX, y: rect.maxY),
                control2: CGPoint(x: rect.minX - tail * 0.2, y: rect.maxY)
            )
            path.addCurve(
                to: CGPoint(x: rect.minX, y: rect.maxY - radius - tail),
                control1: CGPoint(x: rect.minX - tail * 0.6, y: rect.maxY),
                control2: CGPoint(x: rect.minX, y: rect.maxY - tail * 0.3)
            )
            path.addLine(to: CGPoint(x: rect.minX, y: rect.minY + radius))
            path.addArc(center: CGPoint(x: rect.minX + radius, y: rect.minY + radius),
                       radius: radius, startAngle: .degrees(180), endAngle: .degrees(270), clockwise: false)
        }
        
        path.closeSubpath()
        return path
    }
}

// MARK: - Capsule Input Bar

struct CapsuleInputBar: UIViewRepresentable {
    @Binding var text: String
    var placeholder: String
    var onCommit: () -> Void
    
    static func dismantleUIView(_ uiView: UITextField, coordinator: Coordinator) {
        // FIX L-03 + M-12: Secure wipe text buffer on deallocation to prevent memory forensics.
        // Parity with QuickPathTextField in ChatView.swift.
        // FIX M-12: Overwrite with spaces BEFORE clearing — UITextField's internal buffer
        // retains the last-set string in heap memory. Setting to spaces first overwrites
        // the plaintext, then clearing removes the spaces.
        let len = (uiView.text ?? "").count
        if len > 0 {
            uiView.text = String(repeating: " ", count: len)
        }
        uiView.text = ""
        uiView.resignFirstResponder()
    }
    
    func makeUIView(context: Context) -> UITextField {
        let tf = UITextField()
        tf.attributedPlaceholder = NSAttributedString(
            string: placeholder,
            attributes: [.foregroundColor: LadonTheme.uiInk.withAlphaComponent(0.35)]
        )
        tf.borderStyle = .none
        tf.backgroundColor = .clear
        tf.font = .systemFont(ofSize: 16, weight: .regular)
        tf.textColor = LadonTheme.uiInk
        tf.returnKeyType = .send
        tf.autocorrectionType = .no
        tf.autocapitalizationType = .sentences
        tf.spellCheckingType = .no
        // FIX AUDIT-MAR-2026-15: Prevent iOS Autofill content type inference
        tf.textContentType = .none
        tf.smartQuotesType = .no
        tf.smartDashesType = .no
        tf.smartInsertDeleteType = .no
        tf.delegate = context.coordinator
        tf.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        tf.setContentHuggingPriority(.defaultLow, for: .horizontal)
        tf.tintColor = LadonTheme.uiInk
        return tf
    }
    
    func updateUIView(_ uiView: UITextField, context: Context) {
        if uiView.text != text {
            uiView.text = text
        }
    }
    
    func makeCoordinator() -> Coordinator {
        Coordinator(self)
    }
    
    class Coordinator: NSObject, UITextFieldDelegate {
        var parent: CapsuleInputBar
        
        init(_ parent: CapsuleInputBar) {
            self.parent = parent
        }
        
        func textFieldDidChangeSelection(_ textField: UITextField) {
            DispatchQueue.main.async {
                self.parent.text = textField.text ?? ""
            }
        }
        
        func textFieldShouldReturn(_ textField: UITextField) -> Bool {
            if !(textField.text ?? "").isEmpty {
                parent.onCommit()
            }
            return false
        }
    }
}

// MARK: - Pulsing Logo Animation (matches website keyframe)

struct PulsingLogo: View {
    // Creates the dependency that makes this view repaint when the
    // appearance changes. LadonTheme's colours are static reads, so
    // without it SwiftUI sees no reason to call body again and the view
    // keeps the previous mode's colours. Unused on purpose.
    @Environment(\.colorScheme) private var ladonAppearanceTick
    let size: CGFloat
    @State private var isPulsing = false
    
    /// Light: the logo is green (#0f8a5a, as in the approved design and on
    /// ladon.app) with a green glow; dark: unchanged.
    private var isDark: Bool { AppearanceManager.isDarkStored }

    var body: some View {
        Image("LadonLogo")
            .renderingMode(.template)
            .resizable()
            .scaledToFit()
            .foregroundColor(isDark ? LadonTheme.textPrimary : LadonTheme.greenInk)
            .frame(width: size, height: size)
            .scaleEffect(isPulsing ? 1.18 : 1.0)
            .shadow(color: isDark ? LadonTheme.onSurface(isPulsing ? 0.5 : 0)
                                  : LadonTheme.brandGreen.opacity(isPulsing ? 0.55 : 0),
                    radius: isPulsing ? 20 : 0)
            .frame(width: size * 1.2, height: size * 1.2) // Fixed outer frame prevents layout shift
            .onAppear {
                withAnimation(.easeInOut(duration: 1.5).repeatForever(autoreverses: true)) {
                    isPulsing = true
                }
            }
    }
}

// MARK: - Bubble Tail Shape (iMessage-style tail)

struct BubbleTailShape: Shape {
    let isOutgoing: Bool
    
    func path(in rect: CGRect) -> Path {
        let radius: CGFloat = 16
        let tailWidth: CGFloat = 8
        let tailHeight: CGFloat = 12
        var path = Path()
        
        if isOutgoing {
            // Rounded rect without bottom-right corner
            path.move(to: CGPoint(x: rect.minX + radius, y: rect.minY))
            path.addLine(to: CGPoint(x: rect.maxX - radius, y: rect.minY))
            path.addArc(center: CGPoint(x: rect.maxX - radius, y: rect.minY + radius), radius: radius, startAngle: .degrees(-90), endAngle: .degrees(0), clockwise: false)
            path.addLine(to: CGPoint(x: rect.maxX, y: rect.maxY - tailHeight))
            // Tail
            path.addCurve(
                to: CGPoint(x: rect.maxX + tailWidth, y: rect.maxY),
                control1: CGPoint(x: rect.maxX, y: rect.maxY - tailHeight * 0.3),
                control2: CGPoint(x: rect.maxX + tailWidth * 0.5, y: rect.maxY)
            )
            path.addCurve(
                to: CGPoint(x: rect.maxX - 4, y: rect.maxY - 2),
                control1: CGPoint(x: rect.maxX + tailWidth * 0.2, y: rect.maxY),
                control2: CGPoint(x: rect.maxX, y: rect.maxY)
            )
            path.addLine(to: CGPoint(x: rect.minX + radius, y: rect.maxY))
            path.addArc(center: CGPoint(x: rect.minX + radius, y: rect.maxY - radius), radius: radius, startAngle: .degrees(90), endAngle: .degrees(180), clockwise: false)
            path.addLine(to: CGPoint(x: rect.minX, y: rect.minY + radius))
            path.addArc(center: CGPoint(x: rect.minX + radius, y: rect.minY + radius), radius: radius, startAngle: .degrees(180), endAngle: .degrees(270), clockwise: false)
        } else {
            // Rounded rect without bottom-left corner
            path.move(to: CGPoint(x: rect.minX + radius, y: rect.minY))
            path.addLine(to: CGPoint(x: rect.maxX - radius, y: rect.minY))
            path.addArc(center: CGPoint(x: rect.maxX - radius, y: rect.minY + radius), radius: radius, startAngle: .degrees(-90), endAngle: .degrees(0), clockwise: false)
            path.addLine(to: CGPoint(x: rect.maxX, y: rect.maxY - radius))
            path.addArc(center: CGPoint(x: rect.maxX - radius, y: rect.maxY - radius), radius: radius, startAngle: .degrees(0), endAngle: .degrees(90), clockwise: false)
            path.addLine(to: CGPoint(x: rect.minX + 4, y: rect.maxY))
            // Tail
            path.addCurve(
                to: CGPoint(x: rect.minX - tailWidth, y: rect.maxY),
                control1: CGPoint(x: rect.minX, y: rect.maxY),
                control2: CGPoint(x: rect.minX - tailWidth * 0.2, y: rect.maxY)
            )
            path.addCurve(
                to: CGPoint(x: rect.minX, y: rect.maxY - tailHeight),
                control1: CGPoint(x: rect.minX - tailWidth * 0.5, y: rect.maxY),
                control2: CGPoint(x: rect.minX, y: rect.maxY - tailHeight * 0.3)
            )
            path.addLine(to: CGPoint(x: rect.minX, y: rect.minY + radius))
            path.addArc(center: CGPoint(x: rect.minX + radius, y: rect.minY + radius), radius: radius, startAngle: .degrees(180), endAngle: .degrees(270), clockwise: false)
        }
        
        path.closeSubpath()
        return path
    }
}

// MARK: - Fading Separator (fade-out on both ends)

struct FadingSeparator: View {
    // Creates the dependency that makes this view repaint when the
    // appearance changes. LadonTheme's colours are static reads, so
    // without it SwiftUI sees no reason to call body again and the view
    // keeps the previous mode's colours. Unused on purpose.
    @Environment(\.colorScheme) private var ladonAppearanceTick
    var color: Color = LadonTheme.cardBorder
    var height: CGFloat = 0.5
    private let fadeLength: CGFloat = 24
    
    var body: some View {
        GeometryReader { geo in
            let total = geo.size.width
            let fadeFraction = min(fadeLength / total, 0.25)
            Rectangle()
                .fill(color)
                .mask(
                    LinearGradient(
                        gradient: Gradient(stops: [
                            .init(color: .clear, location: 0),
                            .init(color: .white, location: fadeFraction),
                            .init(color: .white, location: 1.0 - fadeFraction),
                            .init(color: .clear, location: 1.0)
                        ]),
                        startPoint: .leading,
                        endPoint: .trailing
                    )
                )
        }
        .frame(height: height)
    }
}

// MARK: - Glow Background (matches website radial gradient)

struct GlowBackground: View {
    // Creates the dependency that makes this view repaint when the
    // appearance changes. LadonTheme's colours are static reads, so
    // without it SwiftUI sees no reason to call body again and the view
    // keeps the previous mode's colours. Unused on purpose.
    @Environment(\.colorScheme) private var ladonAppearanceTick
    var body: some View {
        ZStack {
            LadonTheme.background
                .ignoresSafeArea()
            
            // Top-left glow
            RadialGradient(
                gradient: Gradient(colors: [LadonTheme.brandGreen.opacity(0.16), Color.clear]),
                center: UnitPoint(x: 0.3, y: 0.2),
                startRadius: 0,
                endRadius: 400
            )
            .ignoresSafeArea()
            
            // Bottom-right glow
            RadialGradient(
                gradient: Gradient(colors: [LadonTheme.coral.opacity(0.10), Color.clear]),
                center: UnitPoint(x: 0.7, y: 0.8),
                startRadius: 0,
                endRadius: 400
            )
            .ignoresSafeArea()
        }
    }
}

// MARK: - Website-style Primary Button

struct LadonPrimaryButton: View {
    // Creates the dependency that makes this view repaint when the
    // appearance changes. LadonTheme's colours are static reads, so
    // without it SwiftUI sees no reason to call body again and the view
    // keeps the previous mode's colours. Unused on purpose.
    @Environment(\.colorScheme) private var ladonAppearanceTick
    let title: String
    let action: () -> Void
    
    var body: some View {
        let dark = AppearanceManager.isDarkStored
        Button(action: action) {
            Text(title)
                .font(dark ? .system(size: 16, weight: .bold, design: .rounded) : .manrope(16, .bold))
                .foregroundColor(dark ? LadonTheme.bubbleOutgoingText : LadonTheme.textPrimary)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 16)
                .background(dark ? LadonTheme.textPrimary : LadonTheme.brandGreen)
                .clipShape(RoundedRectangle(cornerRadius: dark ? LadonTheme.cornerRadiusMedium : LadonTheme.cornerRadiusPill))
                .shadow(color: dark ? .clear : LadonTheme.brandGreen.opacity(0.45), radius: dark ? 0 : 15, y: dark ? 0 : 10)
        }
    }
}

// MARK: - Website-style Ghost Button

struct LadonGhostButton: View {
    // Creates the dependency that makes this view repaint when the
    // appearance changes. LadonTheme's colours are static reads, so
    // without it SwiftUI sees no reason to call body again and the view
    // keeps the previous mode's colours. Unused on purpose.
    @Environment(\.colorScheme) private var ladonAppearanceTick
    let title: String
    let action: () -> Void
    
    var body: some View {
        Button(action: action) {
            Text(title)
                .font(.system(size: 16, weight: .semibold, design: .rounded))
                .foregroundColor(LadonTheme.textPrimary)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 16)
                .background(Color.clear)
                .overlay(
                    RoundedRectangle(cornerRadius: LadonTheme.cornerRadiusMedium)
                        .stroke(LadonTheme.ghostBorder, lineWidth: 1)
                )
        }
    }
}

// MARK: - Badge (like website hero badges)

struct LadonBadge: View {
    // Creates the dependency that makes this view repaint when the
    // appearance changes. LadonTheme's colours are static reads, so
    // without it SwiftUI sees no reason to call body again and the view
    // keeps the previous mode's colours. Unused on purpose.
    @Environment(\.colorScheme) private var ladonAppearanceTick
    let text: String
    
    var body: some View {
        Text(text)
            .font(.system(size: 12, weight: .semibold, design: .rounded))
            .foregroundColor(AppearanceManager.isDarkStored ? .white.opacity(0.7) : LadonTheme.textSecondary)
            .padding(.horizontal, 14)
            .padding(.vertical, 6)
            .overlay(
                RoundedRectangle(cornerRadius: LadonTheme.cornerRadiusPill)
                    .stroke(AppearanceManager.isDarkStored ? Color.white.opacity(0.2) : LadonTheme.onSurface(0.14), lineWidth: 1)
            )
    }
}

// MARK: - Typography (Dynamic-Type aware) — additive, not yet wired (P2)
// NOTE: the .custom(...) strings must match the embedded fonts' PostScript names.
// Verify with Font Book after adding the .ttf files (P0 prerequisite). If a name
// is wrong SwiftUI silently falls back to the system font — no crash.

extension Font {
    enum ManropeWeight: String {
        case regular   = "Manrope-Regular"
        case medium    = "Manrope-Medium"
        case semibold  = "Manrope-SemiBold"
        case bold      = "Manrope-Bold"
        case extrabold = "Manrope-ExtraBold"
    }
    /// Manrope with Dynamic-Type scaling (relativeTo).
    static func manrope(_ size: CGFloat, _ weight: ManropeWeight = .regular,
                        relativeTo style: Font.TextStyle = .body) -> Font {
        .custom(weight.rawValue, size: size, relativeTo: style)
    }

    enum MonoWeight: String {
        case regular = "JetBrainsMono-Regular"
        case medium  = "JetBrainsMono-Medium"
    }
    /// JetBrains Mono for data (IDs, safety numbers, timers).
    static func jbMono(_ size: CGFloat, _ weight: MonoWeight = .regular,
                       relativeTo style: Font.TextStyle = .body) -> Font {
        .custom(weight.rawValue, size: size, relativeTo: style)
    }
}

// MARK: - Glass surface (with mandatory Reduce-Transparency fallback) — additive (P3)

struct GlassSurface: ViewModifier {
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency
    var cornerRadius: CGFloat = LadonTheme.cornerRadiusLarge
    var tint: Color = Color.white.opacity(0.06)

    @Environment(\.colorScheme) private var ladonAppearanceTick

    func body(content: Content) -> some View {
        // The background swaps per mode; `content` keeps one identity.
        content.background { surface }
    }

    @ViewBuilder
    private var surface: some View {
        if AppearanceManager.isDarkStored {
            let shape = RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
            Group {
                if reduceTransparency {
                    shape.fill(LadonTheme.cardBackgroundSolid)        // opaque fallback (a11y)
                } else {
                    shape.fill(.ultraThinMaterial)
                    shape.fill(tint)                                  // brand tint
                }
            }
            .overlay(shape.strokeBorder(LadonTheme.glassStroke, lineWidth: 1))    // 1px inner edge
            .shadow(color: LadonTheme.shadow, radius: 16, y: 10)
        } else {
            // Light = ladon.app card. The default radius becomes the site's 24;
            // explicitly passed radii are kept.
            LadonCardBackground(cornerRadius: cornerRadius == LadonTheme.cornerRadiusLarge ? 24 : cornerRadius)
        }
    }
}

/// The ladon.app card surface for light mode: white, 1 pt ink @ 8 % edge and
/// the two stacked soft shadows of --shadow-sm (0 1 2 @ 4 %, 0 4 12 −4 @ 6 %).
/// `elevated` approximates --shadow-lg (0 2 4 @ 4 %, 0 30 80 −24 @ 22 %).
struct LadonCardBackground: View {
    @Environment(\.colorScheme) private var ladonAppearanceTick
    var cornerRadius: CGFloat = 24
    var elevated: Bool = false
    var body: some View {
        let shape = RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
        shape.fill(Color.white)
            .overlay(shape.strokeBorder(LadonTheme.onSurface(0.08), lineWidth: 1))
            .shadow(color: LadonTheme.onSurface(0.04), radius: elevated ? 2 : 1, y: elevated ? 2 : 1)
            .shadow(color: LadonTheme.onSurface(elevated ? 0.18 : 0.06), radius: elevated ? 28 : 6, y: elevated ? 26 : 4)
    }
}

/// ladon.app eyebrow: uppercase JetBrains Mono 11.5, tracking 0.14 em, green
/// ink, preceded by a 24 × 1 line at 70 %.
struct LadonEyebrow: View {
    @Environment(\.colorScheme) private var ladonAppearanceTick
    let text: LocalizedStringKey
    var color: Color? = nil
    var body: some View {
        let c = color ?? LadonTheme.greenInk
        HStack(spacing: 9.6) {
            Rectangle().fill(c.opacity(0.7)).frame(width: 24, height: 1)
            Text(text)
                .font(.jbMono(11.5, .medium, relativeTo: .caption))
                .tracking(1.61)
                .textCase(.uppercase)
                .foregroundColor(c)
        }
    }
}

/// Light (ladon.app): round tinted badge with a symbol — green for neutral or
/// positive states, coral for warnings. Used by the status screens (lock,
/// screen recording, panic, key error), as on the design's "Safety Number".
struct LadonStatusBadge: View {
    enum Tint { case green, coral }
    let systemImage: String
    var tint: Tint = .green
    var size: CGFloat = 88
    var body: some View {
        Image(systemName: systemImage)
            .font(.system(size: size * 0.4, weight: .medium))
            .foregroundColor(tint == .green ? LadonTheme.greenInk : LadonTheme.coralInk)
            .frame(width: size, height: size)
            .background(Circle().fill(tint == .green ? LadonTheme.brandGreenSoft : LadonTheme.coral.opacity(0.14)))
            .accessibilityHidden(true)
    }
}

/// Light (ladon.app) status-screen text: title (Manrope ExtraBold) and lead.
struct LadonStatusText: View {
    let title: LocalizedStringKey
    var lead: LocalizedStringKey? = nil
    var titleSize: CGFloat = 34
    var body: some View {
        VStack(spacing: 10) {
            Text(title)
                .font(.manrope(titleSize, .extrabold, relativeTo: .largeTitle))
                .tracking(LadonTheme.titleTracking(titleSize))
                .foregroundColor(LadonTheme.textPrimary)
            if let lead {
                Text(lead)
                    .font(.manrope(16.5, relativeTo: .body))
                    .foregroundColor(LadonTheme.textSecondary)
                    .lineSpacing(3)
            }
        }
        .multilineTextAlignment(.center)
        .fixedSize(horizontal: false, vertical: true)
    }
}

/// Light (ladon.app): full-screen cover while content is hidden — coral
/// eye-slash badge, coral "Content hidden" eyebrow, title and optional lead.
/// Used for screen recording (ContentView) and the chat shield (ChatView).
struct LadonContentHiddenView: View {
    @Environment(\.colorScheme) private var ladonAppearanceTick
    let title: LocalizedStringKey
    var lead: LocalizedStringKey? = nil
    /// Off where the title already says "Content hidden" (chat shield).
    var showsEyebrow = true
    var body: some View {
        ZStack {
            MeshBackground()
            VStack(spacing: 0) {
                LadonStatusBadge(systemImage: "eye.slash", tint: .coral)
                if showsEyebrow {
                    LadonEyebrow(text: "Content hidden", color: LadonTheme.coralInk)
                        .padding(.top, 24)
                }
                LadonStatusText(title: title, lead: lead, titleSize: 30)
                    .padding(.top, showsEyebrow ? 12 : 22)
            }
            .padding(.horizontal, 24)
        }
    }
}

/// ladon.app status check: 22 pt green-tinted circle with a green-ink check.
struct LadonCheckCircle: View {
    @Environment(\.colorScheme) private var ladonAppearanceTick
    var size: CGFloat = 22
    var body: some View {
        ZStack {
            Circle().fill(LadonTheme.brandGreenSoft)
            Image(systemName: "checkmark")
                .font(.system(size: size * 0.5, weight: .bold))
                .foregroundColor(LadonTheme.greenInk)
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }
}

/// ladon.app tag pill ("BETA · 2026", "RECOMMENDED"): mono, green-soft fill, deep-green text.
struct LadonTagPill: View {
    @Environment(\.colorScheme) private var ladonAppearanceTick
    let text: LocalizedStringKey
    var dot: Bool = false
    var body: some View {
        HStack(spacing: 7) {
            if dot { Circle().fill(LadonTheme.greenInk).frame(width: 7, height: 7) }
            Text(text)
                .font(.jbMono(11, .medium, relativeTo: .caption2))
                .tracking(1.5)
                .textCase(.uppercase)
        }
        .foregroundColor(LadonTheme.greenDeep)
        .padding(.vertical, 5)
        .padding(.leading, dot ? 9 : 12)
        .padding(.trailing, 12)
        .background(Capsule().fill(LadonTheme.brandGreenSoft))
    }
}

extension View {
    /// Frosted glass surface, brand-tinted, with opaque Reduce-Transparency fallback.
    func glassSurface(cornerRadius: CGFloat = LadonTheme.cornerRadiusLarge,
                      tint: Color = Color.white.opacity(0.06)) -> some View {
        modifier(GlassSurface(cornerRadius: cornerRadius, tint: tint))
    }
}

// MARK: - Glass section (Settings-style card with optional header/footer) — global
// Use anywhere you want the same card look as Settings:
//
//   GlassSection(header: "Identity", footer: "Optional helper") { ... }
//
// Includes the 1px outer glass border that traces ALL FOUR corners (which a
// Form/insetGrouped clip would cut off — that's exactly why we replaced Form
// with ScrollView in Settings).

struct GlassSection<Content: View>: View {
    @Environment(\.colorScheme) private var ladonAppearanceTick
    let header: LocalizedStringKey?
    let footer: LocalizedStringKey?
    let content: () -> Content

    init(
        header: LocalizedStringKey? = nil,
        footer: LocalizedStringKey? = nil,
        @ViewBuilder content: @escaping () -> Content
    ) {
        self.header = header
        self.footer = footer
        self.content = content
    }

    var body: some View {
        let dark = AppearanceManager.isDarkStored
        VStack(alignment: .leading, spacing: dark ? 6 : 10) {
            if let header {
                if dark {
                    Text(header)
                        .font(.caption)
                        .fontWeight(.semibold)
                        .tracking(1.5)
                        .textCase(.uppercase)
                        .foregroundColor(LadonTheme.textSecondary)
                        .padding(.horizontal, 16)
                } else {
                    LadonEyebrow(text: header)
                        .padding(.horizontal, 4)
                }
            }
            // `content()` keeps one identity in both modes — only its background
            // changes — so state inside a section survives an appearance switch.
            VStack(alignment: .leading, spacing: 0) {
                content()
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .background { sectionBackground(dark) }
            if let footer {
                Text(footer)
                    .font(dark ? .caption : .manrope(13.4, relativeTo: .caption))
                    .foregroundColor(dark ? LadonTheme.textSecondary : LadonTheme.inkMuted)
                    .lineSpacing(dark ? 0 : 2)
                    .padding(.horizontal, dark ? 16 : 6)
                    .padding(.top, 2)
            }
        }
    }

    @ViewBuilder
    private func sectionBackground(_ dark: Bool) -> some View {
        if dark {
            RoundedRectangle(cornerRadius: 14, style: .continuous)
                .fill(.ultraThinMaterial)
                .opacity(0.55)
                .overlay(
                    RoundedRectangle(cornerRadius: 14, style: .continuous)
                        .strokeBorder(LadonTheme.glassStroke, lineWidth: 1)
                )
        } else {
            LadonCardBackground(cornerRadius: 24)
        }
    }
}

/// Full-width hairline divider, intended for rows inside a `GlassSection`.
struct CardDivider: View {
    // Creates the dependency that makes this view repaint when the
    // appearance changes. LadonTheme's colours are static reads, so
    // without it SwiftUI sees no reason to call body again and the view
    // keeps the previous mode's colours. Unused on purpose.
    @Environment(\.colorScheme) private var ladonAppearanceTick
    var body: some View {
        Rectangle().fill(LadonTheme.glassStroke).frame(height: AppearanceManager.isDarkStored ? 0.5 : 1)
    }
}

// MARK: - Ambient mesh background — additive (P5)
// Intended ONLY for onboarding / paywall / lock / empty screens — NOT behind
// long scrolling lists. Animation is gated by Reduce-Motion and Low-Power-Mode.

struct MeshBackground: View {
    // Creates the dependency that makes this view repaint when the
    // appearance changes. LadonTheme's colours are static reads, so
    // without it SwiftUI sees no reason to call body again and the view
    // keeps the previous mode's colours. Unused on purpose.
    @Environment(\.colorScheme) private var ladonAppearanceTick
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var drift = false
    private var animates: Bool { !reduceMotion && !ProcessInfo.processInfo.isLowPowerModeEnabled }
    /// Mesh base: #20201f dark / #F7F7F6 light.
    private var baseColor: Color {
        AppearanceManager.isDarkStored
            ? Color(red: 32/255, green: 32/255, blue: 31/255)
            : Color(red: 247/255, green: 249/255, blue: 248/255)      // ladon.app --paper
    }

    /// The radial alphas below are tuned for a near-black ground, where they
    /// read as a faint shimmer. Over a light ground the identical values are
    /// solid colour — 42 % green would cover a third of the screen. Light
    /// therefore scales them to keep the *perceived* intensity. Positions,
    /// radii and drift are untouched: same mesh, same quietness.
    private func meshAlpha(_ a: Double) -> Double {
        AppearanceManager.isDarkStored ? a : a * 1.0
    }

    var body: some View {
        GeometryReader { geo in
            let w = geo.size.width
            let h = geo.size.height
            ZStack {
                baseColor
                if AppearanceManager.isDarkStored {
                    // Matches mockup .mesh: 4 radials (green/coral) over #20201f.
                    radial(LadonTheme.brandGreen, meshAlpha(0.42), x: drift ? 0.22 : 0.18, y: 0.14, r: w * 0.58)
                    radial(LadonTheme.brandGreen, meshAlpha(0.28), x: 0.86, y: drift ? 0.24 : 0.20, r: w * 0.66)
                    radial(LadonTheme.coral,      meshAlpha(0.30), x: 0.74, y: drift ? 0.88 : 0.92, r: w * 0.72)
                    radial(LadonTheme.brandGreen, meshAlpha(0.20), x: 0.10, y: drift ? 0.82 : 0.86, r: w * 0.66)
                } else {
                    // ladon.app .ambient — ellipse 60%×40% at 30% −5% green .16 ·
                    // 40%×35% at 100% 55% coral .07 · 60%×40% at 0% 100% green .07,
                    // each fading out at 65 % of its radius. Static, like the site.
                    siteEllipse(LadonTheme.brandGreen, 0.16, cx: 0.30, cy: -0.05, rx: 0.60, ry: 0.40, w: w, h: h)
                    siteEllipse(LadonTheme.coral,      0.07, cx: 1.00, cy: 0.55,  rx: 0.40, ry: 0.35, w: w, h: h)
                    siteEllipse(LadonTheme.brandGreen, 0.07, cx: 0.00, cy: 1.00,  rx: 0.60, ry: 0.40, w: w, h: h)
                }
            }
        }
        .ignoresSafeArea()
        .onAppear {
            guard animates else { return }
            withAnimation(.easeInOut(duration: 16).repeatForever(autoreverses: true)) { drift = true }
        }
    }

    private func radial(_ color: Color, _ a: Double, x: Double, y: Double, r: CGFloat) -> some View {
        RadialGradient(colors: [color.opacity(a), .clear],
                       center: UnitPoint(x: x, y: y), startRadius: 0, endRadius: r)
    }

    /// CSS `radial-gradient(ellipse rx ry at cx cy, color a, transparent 65%)`.
    private func siteEllipse(_ color: Color, _ a: Double, cx: CGFloat, cy: CGFloat,
                             rx: CGFloat, ry: CGFloat, w: CGFloat, h: CGFloat) -> some View {
        Rectangle()
            .fill(EllipticalGradient(stops: [.init(color: color.opacity(a), location: 0),
                                             .init(color: color.opacity(0), location: 0.65)],
                                     center: .center, startRadiusFraction: 0, endRadiusFraction: 0.5))
            .frame(width: 2 * rx * w, height: 2 * ry * h)
            .position(x: cx * w, y: cy * h)
            .allowsHitTesting(false)
    }
}



/// In-app appearance selection.
///
/// Light is the default. Dark is the original design, unchanged, available in
/// settings. Like `LanguageManager`, the choice is local only — never sent
/// anywhere, never part of a network request.
@MainActor
final class AppearanceManager: ObservableObject {
    static let shared = AppearanceManager()

    enum Mode: String, CaseIterable, Hashable {
        case light
        case dark
    }

    nonisolated private static let storageKey = "app.ladon.appearance"

    @Published var mode: Mode {
        didSet {
            UserDefaults.standard.set(mode.rawValue, forKey: Self.storageKey)
            LadonTheme.applyUIKitAppearance()
        }
    }

    /// Drives `.preferredColorScheme` so system chrome (keyboard, sheets, list
    /// backgrounds, the status bar) follows the in-app choice.
    var colorScheme: ColorScheme { mode == .dark ? .dark : .light }

    /// Read by `LadonTheme`'s colours. `nonisolated` so they stay usable off
    /// the main actor, and UserDefaults-backed so a colour resolves correctly
    /// even before the manager is first constructed.
    nonisolated static var isDarkStored: Bool {
        UserDefaults.standard.string(forKey: storageKey) == Mode.dark.rawValue
    }

    private init() {
        let stored = UserDefaults.standard.string(forKey: Self.storageKey)
        mode = Mode(rawValue: stored ?? "") ?? .light
    }
}

private extension UIView {
    /// Depth-first collection of all descendants of a given type.
    func descendants<T: UIView>(ofType type: T.Type) -> [T] {
        var out: [T] = []
        for v in subviews {
            if let t = v as? T { out.append(t) }
            out.append(contentsOf: v.descendants(ofType: type))
        }
        return out
    }
}

// MARK: - Tab entrance motion (light, ladon.app reveal)
//
// The maintainer's choice 02.10.2026 (motion preview): when a tab is entered, its
// screen fades in and rises 12 pt (0.35 s, ease-out 0.16,1,0.3,1) and its
// cards follow one after another, each rising 14 pt (0.5 s). Light mode only
// (dark stays unchanged); nothing moves with Reduce Motion.

private struct TabEntranceTickKey: EnvironmentKey {
    static let defaultValue = 0
}

extension EnvironmentValues {
    /// Changes each time the enclosing tab is entered; `staggerIn()` children
    /// replay their rise on it.
    var tabEntranceTick: Int {
        get { self[TabEntranceTickKey.self] }
        set { self[TabEntranceTickKey.self] = newValue }
    }
}

/// Website reveal curve (`--ease-out`).
private let ladonRevealCurve = Animation.timingCurve(0.16, 1, 0.3, 1, duration: 0.35)

private struct TabEntrance: ViewModifier {
    let tag: Int
    let selection: Int
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var shown = true
    @State private var tick = 0

    func body(content: Content) -> some View {
        content
            .opacity(shown ? 1 : 0)
            .offset(y: shown ? 0 : 12)
            .environment(\.tabEntranceTick, tick)
            .onChange(of: selection) { _, new in
                guard new == tag, !reduceMotion, !AppearanceManager.isDarkStored else { return }
                var still = Transaction()
                still.disablesAnimations = true
                withTransaction(still) { shown = false }
                tick &+= 1
                DispatchQueue.main.async {
                    withAnimation(ladonRevealCurve) { shown = true }
                }
            }
    }
}

private struct StaggerIn: ViewModifier {
    @Environment(\.tabEntranceTick) private var tick
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var shown = true
    /// Top edge on screen; lower cards start later (≈ 0.05 s per card).
    @State private var minY: CGFloat = 0

    func body(content: Content) -> some View {
        content
            .opacity(shown ? 1 : 0)
            .offset(y: shown ? 0 : 14)
            .onGeometryChange(for: CGFloat.self) { $0.frame(in: .global).minY } action: { minY = $0 }
            .onChange(of: tick) { _, _ in
                guard !reduceMotion, !AppearanceManager.isDarkStored else { return }
                var still = Transaction()
                still.disablesAnimations = true
                withTransaction(still) { shown = false }
                let delay = 0.06 + min(0.3, max(0, Double(minY - 140) / 160 * 0.05))
                DispatchQueue.main.async {
                    withAnimation(.timingCurve(0.16, 1, 0.3, 1, duration: 0.5).delay(delay)) { shown = true }
                }
            }
    }
}

extension View {
    /// Fade-and-rise of a tab screen when the tab `tag` becomes `selection`.
    func tabEntrance(tag: Int, selection: Int) -> some View {
        modifier(TabEntrance(tag: tag, selection: selection))
    }
    /// A card that rises in after the cards above it when its tab is entered.
    func staggerIn() -> some View {
        modifier(StaggerIn())
    }
}

// MARK: - Chat bubble spring-in (light)
//
// The maintainer's choice "Federn" (02.10.2026): a new bubble springs out of its tail
// corner — scale 0.35 → 1 with the website's spring (0.34, 1.56, 0.64, 1),
// 0.56 s. Only for messages that arrive or are sent while the chat is open.
// Light mode only; nothing moves with Reduce Motion.

private struct SpringIn: ViewModifier {
    let active: Bool
    let outgoing: Bool
    let onAppeared: () -> Void
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var settled: Bool

    init(active: Bool, outgoing: Bool, onAppeared: @escaping () -> Void) {
        self.active = active
        self.outgoing = outgoing
        self.onAppeared = onAppeared
        _settled = State(initialValue: !active)
    }

    func body(content: Content) -> some View {
        // Dark and Reduce Motion never show the start state, not even for a frame.
        let atRest = settled || reduceMotion || AppearanceManager.isDarkStored
        return content
            .scaleEffect(atRest ? 1 : 0.35, anchor: outgoing ? .bottomTrailing : .bottomLeading)
            .opacity(atRest ? 1 : 0)
            .onAppear {
                guard !settled else { return }
                if reduceMotion || AppearanceManager.isDarkStored {
                    settled = true
                } else {
                    withAnimation(.timingCurve(0.34, 1.56, 0.64, 1, duration: 0.56)) { settled = true }
                }
                DispatchQueue.main.async { onAppeared() }
            }
    }
}

extension View {
    /// Spring a chat bubble in from its tail corner (once, when `active`).
    func springIn(active: Bool, outgoing: Bool, onAppeared: @escaping () -> Void) -> some View {
        modifier(SpringIn(active: active, outgoing: outgoing, onAppeared: onAppeared))
    }
}
