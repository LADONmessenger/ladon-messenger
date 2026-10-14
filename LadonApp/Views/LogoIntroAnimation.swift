import SwiftUI
import CoreGraphics
import UIKit

// MARK: - Logo-slot anchor (so the full-screen rain can target the onboarding slot)

/// Carries the onboarding logo slot's center so a full-screen rain overlay can
/// assemble the logo at exactly that point (resolved via a GeometryReader proxy).
struct LogoSlotAnchorKey: PreferenceKey {
    static var defaultValue: Anchor<CGPoint>? = nil
    static func reduce(value: inout Anchor<CGPoint>?, nextValue: () -> Anchor<CGPoint>?) {
        value = value ?? nextValue()
    }
}

// MARK: - ASCII byte-rain logo intro (onboarding screen 0)
//
// Native SwiftUI port of the approved animation (~/Desktop/logo-ascii-onboarding-preview.html):
// cipher bytes rain straight down from BEYOND the top edge of the screen and assemble the LADON
// logo at a CONSTANT 64pt at the final onboarding logo position (no zoom), the logo Y-rotates
// back→front, chars scramble then lock ("decrypt"), then the ascii fades as the solid logo morphs
// green→white with a green glow flash, and stays as the resting logo.
//
// It renders FULL-SCREEN (ignoring safe areas, via the caller's overlay) so the rain originates
// off-screen above the physical top edge — not at a canvas/safe-area line partway down. The logo
// assembles at `logoCenter` (the onboarding slot's center, passed in via a layout anchor).
//
// The character cloud AND the morph logo are both built from the SAME `LadonLogo` asset the final
// `PulsingLogo` shows — identical shape, completeness, size and position.

struct LogoAsciiIntro: View {
    // Creates the dependency that makes this view repaint when the
    // appearance changes. LadonTheme's colours are static reads, so
    // without it SwiftUI sees no reason to call body again and the view
    // keeps the previous mode's colours. Unused on purpose.
    @Environment(\.colorScheme) private var ladonAppearanceTick
    let logoCenter: CGPoint
    let onComplete: () -> Void

    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    // ── geometry (logo is a constant 64pt) ──
    private static let logoPt: CGFloat = 64
    private static let rasterS = 96                          // source raster the cloud is sampled from
    private static let scale: CGFloat = logoPt / CGFloat(rasterS)   // raster → 64pt (matches PulsingLogo .scaledToFit)
    private static let glyphPt: CGFloat = 2.6                // proportional to the 64pt logo
    private static let fallAboveTop: CGFloat = 120           // chars start this far ABOVE the physical top edge
    private static let introDur: Double = 3.2
    static let green = Color(red: 52/255, green: 211/255, blue: 153/255)   // #34d399

    // small fixed glyph alphabet → bounded text resolves per frame (perf)
    private static let bytePool: [String] = {
        let hex = Array("0123456789abcdef")
        return (0..<40).map { _ in String([hex.randomElement()!, hex.randomElement()!]) }
    }()

    struct CloudPoint { let x, y, z, delay: Double; let index: Int; let finalGlyph: String }

    @State private var cloud: [CloudPoint]
    @State private var startDate = Date()

    // morph / handoff state
    @State private var asciiOpacity: Double = 1
    @State private var asciiBlur: CGFloat = 0
    @State private var canvasHidden = false
    @State private var morphAppeared = false
    @State private var morphWhite = false
    @State private var glowOpacity: Double = 0
    @State private var glowScale: CGFloat = 0.6
    @State private var didComplete = false

    init(logoCenter: CGPoint, onComplete: @escaping () -> Void) {
        self.logoCenter = logoCenter
        self.onComplete = onComplete
        _cloud = State(initialValue: Self.buildCloud(stride: 4))
    }

    var body: some View {
        ZStack {
            if !reduceMotion && !canvasHidden {
                canvasLayer
                    .opacity(asciiOpacity)
                    .blur(radius: asciiBlur)
            }
            morphLayer.position(logoCenter)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)   // full-screen (caller ignores safe area)
        .allowsHitTesting(false)
        .onAppear {
            startDate = Date()
            if reduceMotion { startReducedMotion() }
            else { DispatchQueue.main.asyncAfter(deadline: .now() + Self.introDur * 0.94) { startMorph() } }
        }
    }

    // ── full-screen falling-byte canvas; chars target `logoCenter`, starting above the top edge ──
    private var canvasLayer: some View {
        TimelineView(.animation) { timeline in
            Canvas { ctx, _ in
                draw(&ctx, t: timeline.date.timeIntervalSince(startDate))
            }
        }
    }

    private func draw(_ ctx: inout GraphicsContext, t: Double) {
        guard !cloud.isEmpty else { return }
        let originX = logoCenter.x
        let originY = logoCenter.y
        let fall = originY + Self.fallAboveTop            // start ~fallAboveTop px above the physical top edge
        let introT = min(1, t / Self.introDur)
        let rotY = Double.pi + easeInOut(introT) * Double.pi
        let cosY = cos(rotY), sinY = sin(rotY)
        let scrambling = introT < 1.0
        let bucket = Int(t * 60) / 3

        var resolvedCache: [String: GraphicsContext.ResolvedText] = [:]
        func resolved(_ g: String) -> GraphicsContext.ResolvedText {
            if let r = resolvedCache[g] { return r }
            let r = ctx.resolve(Text(g)
                .font(.system(size: Self.glyphPt, design: .monospaced))
                .foregroundColor(Self.green))
            resolvedCache[g] = r
            return r
        }

        for c in cloud {
            let settle = easeOutCubic(min(1, max(0, (introT - c.delay) / 0.45)))
            let glyph: String
            if settle >= 0.96 { glyph = c.finalGlyph }
            else if scrambling {
                glyph = Self.bytePool[abs(c.index &* 131 &+ bucket &* 977) % Self.bytePool.count]
            } else { glyph = c.finalGlyph }

            let x1 = c.x * cosY + c.z * sinY
            let px = originX + CGFloat(x1) * Self.scale
            let py = originY + CGFloat(c.y) * Self.scale - fall * CGFloat(1 - settle)
            // No per-char fade-in: each byte falls in at full opacity from beyond the
            // top edge (py < 0 is above the screen → clipped), scrambling as it drops,
            // then locking once settled.
            ctx.draw(resolved(glyph), at: CGPoint(x: px, y: py), anchor: .center)
        }
    }

    // ── solid logo morph + glow flash (the SAME asset PulsingLogo uses, at 64pt) ──
    private var morphLayer: some View {
        ZStack {
            Circle()
                .fill(RadialGradient(
                    gradient: Gradient(colors: [Self.green.opacity(0.55), Self.green.opacity(0.12), .clear]),
                    center: .center, startRadius: 0, endRadius: 75))
                .frame(width: 150, height: 150)
                .scaleEffect(glowScale)
                .opacity(glowOpacity)
                .allowsHitTesting(false)

            Image("LadonLogo")
                .renderingMode(.template)
                .resizable()
                .scaledToFit()
                .frame(width: 64, height: 64)
                .foregroundColor(morphWhite ? LadonTheme.textPrimary : Self.green)
                .scaleEffect(morphAppeared ? 1.0 : 0.9)
                .opacity(morphAppeared ? 1 : 0)
                .shadow(color: morphWhite ? LadonTheme.onSurface(0.6) : .clear, radius: 9)
        }
        .frame(width: 150, height: 150)
    }

    // ── timeline ──
    private func startMorph() {
        withAnimation(.easeInOut(duration: 0.4)) { asciiOpacity = 0; asciiBlur = 3 }
        withAnimation(.spring(response: 0.5, dampingFraction: 0.6)) { morphAppeared = true }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.05) {
            withAnimation(.easeInOut(duration: 0.42)) { morphWhite = true }
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.22) { flashGlow() }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { canvasHidden = true }   // stop the timeline
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.55) { complete() }            // fade in the texts
    }

    private func flashGlow() {
        withAnimation(.easeOut(duration: 0.25)) { glowOpacity = 1; glowScale = 1.05 }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.25) {
            withAnimation(.easeIn(duration: 0.6)) { glowOpacity = 0; glowScale = 1.6 }
        }
    }

    private func startReducedMotion() {
        withAnimation(.easeInOut(duration: 0.4)) { morphAppeared = true }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.35) {
            withAnimation(.easeInOut(duration: 0.4)) { morphWhite = true }
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.75) { complete() }
    }

    private func complete() {
        guard !didComplete else { return }
        didComplete = true
        onComplete()
    }

    // ── point cloud: sample the LadonLogo alpha mask (same asset as PulsingLogo) ──
    private static func buildCloud(stride: Int) -> [CloudPoint] {
        guard let cg = UIImage(named: "LadonLogo")?.cgImage else { return [] }
        let s = rasterS
        let bytesPerRow = s * 4
        var px = [UInt8](repeating: 0, count: s * bytesPerRow)
        var points: [CloudPoint] = []
        px.withUnsafeMutableBytes { raw in
            guard let base = raw.baseAddress,
                  let ctx = CGContext(data: base, width: s, height: s, bitsPerComponent: 8,
                                      bytesPerRow: bytesPerRow, space: CGColorSpaceCreateDeviceRGB(),
                                      bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) else { return }
            // CGContext.draw places the image upright in the buffer (row 0 = top),
            // which is the orientation we sample → matches the upright PNG/PulsingLogo.
            // Aspect-fit the logo into s×s centred (same as `.scaledToFit()`).
            let iw = CGFloat(cg.width), ih = CGFloat(cg.height)
            let fit = min(CGFloat(s) / iw, CGFloat(s) / ih)
            let dw = iw * fit, dh = ih * fit
            ctx.draw(cg, in: CGRect(x: (CGFloat(s) - dw) / 2, y: (CGFloat(s) - dh) / 2, width: dw, height: dh))
            var idx = 0
            var y = 0
            while y < s {
                var x = 0
                while x < s {
                    if raw[(y * s + x) * 4 + 3] > 60 {
                        points.append(CloudPoint(
                            x: Double(x - s / 2), y: Double(y - s / 2),
                            z: Double.random(in: -11...11), delay: Double.random(in: 0...0.4),
                            index: idx, finalGlyph: bytePool.randomElement() ?? "0a"))
                        idx += 1
                    }
                    x += stride
                }
                y += stride
            }
        }
        return points
    }
}

// MARK: - easings (match the preview)
private func easeOutCubic(_ t: Double) -> Double { 1 - pow(1 - t, 3) }
private func easeInOut(_ t: Double) -> Double { t < 0.5 ? 4 * t * t * t : 1 - pow(-2 * t + 2, 3) / 2 }
