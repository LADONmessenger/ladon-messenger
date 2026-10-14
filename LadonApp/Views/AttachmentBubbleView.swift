// AttachmentBubbleView.swift — Phase 8
//
// SwiftUI bubble that renders an attachment message. On first appearance
// it parses the wire payload (cheap) and shows a type-appropriate
// placeholder. On tap it triggers the download/unseal via
// ``AttachmentDownloadCache`` and presents the full content: image
// preview, video playback, or audio playback.

import SwiftUI
import AVKit
import UniformTypeIdentifiers

@available(iOS 17.0, *)
struct AttachmentBubbleView: View {
    // Creates the dependency that makes this view repaint when the
    // appearance changes. LadonTheme's colours are static reads, so
    // without it SwiftUI sees no reason to call body again and the view
    // keeps the previous mode's colours. Unused on purpose.
    @Environment(\.colorScheme) private var ladonAppearanceTick
    let message: Message
    let isOutgoing: Bool
    private var isDark: Bool { AppearanceManager.isDarkStored }

    /// Dark: 18 pt rounded tile (unchanged). Light: the text bubbles' shape —
    /// 18 pt corners with a 4 pt tail corner on the sender's side.
    private var bubbleShape: AnyShape {
        if isDark { return AnyShape(RoundedRectangle(cornerRadius: 18, style: .continuous)) }
        return AnyShape(UnevenRoundedRectangle(topLeadingRadius: 18,
                                               bottomLeadingRadius: isOutgoing ? 18 : 4,
                                               bottomTrailingRadius: isOutgoing ? 4 : 18,
                                               topTrailingRadius: 18,
                                               style: .continuous))
    }

    /// Light bubble fill, as for text messages: green outgoing, paper incoming.
    private var lightBubbleFill: Color { isOutgoing ? LadonTheme.brandGreen : LadonTheme.paper2 }

    @State private var payload: AttachmentMessagePayload?
    @State private var parseError: String?
    @State private var opened: AttachmentReceiveService.Opened?
    @State private var isLoading = false
    @State private var downloadProgress: Double = 0
    @State private var downloadError: String?
    @State private var showingFullscreen = false

    // Inline voice playback state
    @State private var voicePlayer: AVAudioPlayer?
    @State private var voiceIsPlaying = false
    @State private var voiceProgress: Double = 0
    @State private var voiceTimer: Timer?
    /// User-visible playback error (e.g. "Format not supported"). Shown
    /// inside the bubble so the user sees WHY a tap did nothing.
    @State private var voiceError: String?

    /// Sender-side preview image (own outgoing media). Populated on appear
    /// from `SenderAttachmentCache` so the outgoing bubble shows the actual
    /// photo / video poster immediately, without re-downloading from the
    /// relay. RAM-only; nil after app restart for media we no longer hold.
    @State private var senderPreviewImage: UIImage?
    @State private var senderPreviewFullContent: Data?
    @State private var senderPreviewThumbnail: Data?

    var body: some View {
        Group {
            if let payload = payload {
                bubble(for: payload)
            } else if let err = parseError {
                Text("Attachment error: \(err)")
                    .font(.caption)
                    .foregroundColor(.red)
                    .padding(12)
                    .background(LadonTheme.bubbleIncoming)
                    .cornerRadius(12)
            } else {
                ProgressView()
                    .frame(width: 60, height: 60)
            }
        }
        .onAppear {
            if payload == nil && parseError == nil {
                do {
                    payload = try AttachmentReceiveService.parse(messageContent: message.contentString)
                } catch {
                    parseError = String(describing: error)
                }
            }
            // Outgoing bubbles: try to fill the preview from the
            // sender-side RAM cache so the user sees their own photo/video
            // immediately, no shimmer.
            if isOutgoing, senderPreviewImage == nil, let p = payload {
                Task { await loadSenderPreview(payload: p) }
            }
        }
        .onDisappear {
            voicePlayer?.stop()
            voiceTimer?.invalidate()
            voiceTimer = nil
            voiceIsPlaying = false
            // Release the AVAudioSession so subsequent recorder views
            // can switch the category (.playback → .playAndRecord).
            // Without this, the session stays in `.playback` and the
            // VoiceRecorder's setCategory(.playAndRecord) silently fails
            // on some devices (observed: iPhone 13 Pro).
            try? AVAudioSession.sharedInstance().setActive(
                false, options: .notifyOthersOnDeactivation
            )
        }
        .sheet(isPresented: $showingFullscreen) {
            if let opened = opened {
                AttachmentViewer(opened: opened)
            }
        }
    }

    @ViewBuilder
    private func bubble(for payload: AttachmentMessagePayload) -> some View {
        VStack(alignment: isOutgoing ? .trailing : .leading, spacing: 6) {
            Button(action: tap) {
                placeholder(for: payload)
            }
            .buttonStyle(.plain)
            .sensoryFeedback(.impact(flexibility: .soft, intensity: 0.6), trigger: showingFullscreen)

            if let captionText = captionText(for: payload) {
                if isDark {
                Text(captionText)
                    .font(.callout)
                    .foregroundColor(isOutgoing ? LadonTheme.bubbleOutgoingText : LadonTheme.bubbleIncomingText)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 7)
                    .background(
                        (isOutgoing ? LadonTheme.bubbleOutgoing : LadonTheme.bubbleIncoming)
                            .opacity(0.92)
                    )
                    .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
                } else {
                    Text(captionText)
                        .font(.manrope(15.5, isOutgoing ? .medium : .regular, relativeTo: .body))
                        .foregroundColor(LadonTheme.textPrimary)
                        .padding(.horizontal, 15)
                        .padding(.vertical, 11)
                        .background(bubbleShape.fill(lightBubbleFill))
                }
            }

            if let err = downloadError {
                HStack(spacing: 6) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .font(.caption2)
                    Text(err)
                        .font(.caption2)
                    Button("Retry") { downloadError = nil; tap() }
                        .font(.caption2.weight(.semibold))
                }
                .foregroundColor(LadonTheme.danger)
            }
        }
    }

    private func captionText(for payload: AttachmentMessagePayload) -> String? {
        if let caption = opened?.caption,
           let s = String(data: caption, encoding: .utf8),
           !s.isEmpty {
            return s
        }
        return nil
    }

    @ViewBuilder
    private func placeholder(for payload: AttachmentMessagePayload) -> some View {
        let mime = payload.descriptor.mime
        let w = CGFloat(max(payload.descriptor.dimensions.width, 1))
        let h = CGFloat(max(payload.descriptor.dimensions.height, 1))
        let aspect: CGFloat = (w > 0 && h > 0) ? max(0.55, min(w / h, 2.0)) : 1.0

        switch mime {
        case .jpeg, .png, .webp:
            mediaTile(aspect: aspect, mime: mime, payload: payload, isVideo: false)
        case .mp4h264:
            mediaTile(aspect: aspect, mime: mime, payload: payload, isVideo: true)
        case .opus, .aac:
            voiceTile(payload: payload, mime: mime)
        }
    }

    @ViewBuilder
    private func mediaTile(
        aspect: CGFloat,
        mime: AttachmentMimeType,
        payload: AttachmentMessagePayload,
        isVideo: Bool
    ) -> some View {
        let tileW: CGFloat = 240
        let tileH: CGFloat = min(320, max(150, tileW / max(aspect, 0.55)))
        let hasImage = openedImage != nil

        ZStack {
            // Base: placeholder (always present, crossfaded out when image arrives)
            ShimmerGradient(icon: isVideo ? "play.rectangle.fill" : "photo")
                .frame(width: tileW, height: tileH)
                .opacity(hasImage ? 0 : 1)

            // Opened image (crossfades in)
            if let img = openedImage {
                Image(uiImage: img)
                    .resizable()
                    .scaledToFill()
                    .frame(width: tileW, height: tileH)
                    .clipped()
                    .transition(.opacity)
            }

            // Video play-icon overlay (only over actual image or when idle)
            if isVideo && !isLoading {
                Circle()
                    .fill(.ultraThinMaterial)
                    .frame(width: 60, height: 60)
                    .overlay(
                        Image(systemName: "play.fill")
                            .font(.system(size: 22, weight: .bold))
                            .foregroundColor(.white)
                            .offset(x: 2)
                    )
                    .shadow(color: .black.opacity(0.35), radius: 8, y: 2)
            }

            // Duration badge (video)
            if isVideo, payload.descriptor.dimensions.durationMs > 0 {
                VStack {
                    Spacer()
                    HStack {
                        Spacer()
                        Text(formatDuration(ms: payload.descriptor.dimensions.durationMs))
                            .font(.caption2.weight(.semibold).monospacedDigit())
                            .foregroundColor(.white)
                            .padding(.horizontal, 8)
                            .padding(.vertical, 3)
                            .background(Capsule().fill(Color.black.opacity(0.55)))
                            .padding(8)
                    }
                }
            }

            // Unopened idle state: "Tap to download" hint + size badge (only
            // when no image yet and not currently loading)
            if !hasImage && !isLoading {
                VStack(spacing: 8) {
                    Image(systemName: isVideo ? "arrow.down.circle.fill" : "arrow.down.circle.fill")
                        .font(.system(size: 38, weight: .regular))
                        .foregroundColor(LadonTheme.onSurface(0.9))
                        .shadow(color: .black.opacity(0.4), radius: 6, y: 1)
                    Text(sizeLabel(for: payload))
                        .font(.caption2.weight(.semibold).monospacedDigit())
                        .foregroundColor(LadonTheme.onSurface(0.85))
                        .padding(.horizontal, 10)
                        .padding(.vertical, 3)
                        .background(Capsule().fill(Color.black.opacity(0.45)))
                }
            }

            // Download progress overlay
            if isLoading {
                Rectangle().fill(Color.black.opacity(0.5))
                VStack(spacing: 8) {
                    ProgressRing(progress: downloadProgress)
                        .frame(width: 58, height: 58)
                    Text("Downloading…")
                        .font(.caption2.weight(.semibold))
                        .foregroundColor(LadonTheme.onSurface(0.85))
                }
            }
        }
        .frame(width: tileW, height: tileH)
        .clipShape(bubbleShape)
        .overlay(
            bubbleShape
                .stroke(LadonTheme.onSurface(0.08), lineWidth: 1)
        )
        .shadow(color: isDark ? .black.opacity(0.25) : .clear, radius: 6, y: 2)
        .animation(.easeInOut(duration: 0.35), value: hasImage)
    }

    /// Human-readable size hint derived from the bucket (public, padded size
    /// — reveals nothing about the real plaintext length).
    private func sizeLabel(for payload: AttachmentMessagePayload) -> String {
        let bytes = payload.descriptor.bucket.byteSize
        let mb = Double(bytes) / (1024.0 * 1024.0)
        if mb >= 1.0 {
            return String(format: "%.0f MB", mb)
        } else {
            let kb = Double(bytes) / 1024.0
            return String(format: "%.0f KB", kb)
        }
    }

    @ViewBuilder
    private func voiceTile(payload: AttachmentMessagePayload, mime: AttachmentMimeType) -> some View {
        let totalSecs = Int(payload.descriptor.dimensions.durationMs / 1000)
        let totalText = totalSecs > 0 ? String(format: "%d:%02d", totalSecs / 60, totalSecs % 60) : "—:—"
        let currentSecs = Int((voicePlayer?.currentTime ?? 0))
        let displayedText: String = {
            if voiceIsPlaying || voiceProgress > 0 {
                return String(format: "%d:%02d", currentSecs / 60, currentSecs % 60)
            } else {
                return totalText
            }
        }()
        // Light: ink on the green / paper bubble, like text messages.
        let primaryColor = !isDark ? LadonTheme.textPrimary
            : (isOutgoing ? LadonTheme.bubbleOutgoingText : LadonTheme.bubbleIncomingText)
        let secondaryColor = primaryColor.opacity(isDark ? 0.35 : 0.25)

        HStack(spacing: 12) {
            // Play / pause / loading indicator
            ZStack {
                Circle()
                    .fill(!isDark ? LadonTheme.onSurface(0.12)
                          : (isOutgoing
                          ? Color.black.opacity(0.08)
                          : LadonTheme.onSurface(0.12)))
                    .frame(width: 40, height: 40)
                if isLoading {
                    ProgressRing(progress: downloadProgress, tint: primaryColor)
                        .frame(width: 40, height: 40)
                } else if opened == nil {
                    // Not downloaded yet — show a download/play glyph
                    Image(systemName: "arrow.down")
                        .font(.system(size: 14, weight: .bold))
                        .foregroundColor(primaryColor)
                } else {
                    Image(systemName: voiceIsPlaying ? "pause.fill" : "play.fill")
                        .font(.system(size: 16, weight: .bold))
                        .foregroundColor(primaryColor)
                        .offset(x: voiceIsPlaying ? 0 : 1.5)
                }
            }

            // Waveform — fills left-to-right with playback progress
            WaveformBars(
                seed: voiceSeed(payload: payload),
                progress: voiceProgress,
                fillColor: primaryColor,
                backgroundColor: secondaryColor
            )
            .frame(height: 28)
            .frame(maxWidth: .infinity)

            Text(displayedText)
                .font(isDark ? .caption.weight(.semibold).monospacedDigit() : .jbMono(11, .medium, relativeTo: .caption))
                .monospacedDigit()
                .foregroundColor(primaryColor.opacity(isDark ? 0.7 : 0.85))
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
        .frame(width: 240)
        .background(
            bubbleShape
                .fill(!isDark ? lightBubbleFill
                      : (isOutgoing ? LadonTheme.bubbleOutgoing : LadonTheme.bubbleIncoming))
                .shadow(color: !isDark && isOutgoing ? LadonTheme.brandGreen.opacity(0.35) : .clear,
                        radius: 12, y: 8)
        )
        .overlay(
            bubbleShape
                .stroke(LadonTheme.onSurface(isDark ? 0.06 : 0), lineWidth: 1)
        )
        .overlay(alignment: .bottom) {
            if let err = voiceError {
                // Render the full error inline below the bubble. No
                // hard `.offset` (would push it off-screen on the 13
                // Pro's shorter chat view); use a real layout block.
                VStack { Spacer().frame(height: 4); Text(err) }
                    .font(.caption2.monospaced())
                    .foregroundColor(.white)
                    .multilineTextAlignment(.leading)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 6)
                    .frame(maxWidth: 240, alignment: .leading)
                    .background(
                        RoundedRectangle(cornerRadius: 10, style: .continuous)
                            .fill(Color.red.opacity(0.92))
                    )
                    .offset(y: 80)
                    .onTapGesture {
                        UIPasteboard.general.setItems(
                            [[UIPasteboard.typeAutomatic: err]],
                            // L4: 10 s expiry, matching the rest of the app.
                            options: [.localOnly: true, .expirationDate: Date().addingTimeInterval(10)]
                        )
                    }
            }
        }
    }

    private func formatDuration(ms: UInt32) -> String {
        let s = Int(ms / 1000)
        return String(format: "%d:%02d", s / 60, s % 60)
    }

    // Deterministic seed so every rendering of the same voice message
    // shows the same waveform (feels stable, not jittery across re-renders).
    private func voiceSeed(payload: AttachmentMessagePayload) -> UInt64 {
        let raw = payload.descriptor.dimensions.durationMs
        return UInt64(raw) &* 2654435761 ^ 0xC0FFEE
    }

    private var openedImage: UIImage? {
        if let opened = opened {
            switch opened.mime {
            case .jpeg, .png, .webp: return UIImage(data: opened.content)
            default: return UIImage(data: opened.thumbnail)
            }
        }
        // Fallback: sender-side preview (own outgoing media), populated
        // from SenderAttachmentCache on appear.
        return senderPreviewImage
    }

    /// Look up the outgoing-media preview from the in-memory sender cache.
    /// Prefers full content for photos; falls back to the 4 KB thumbnail
    /// for videos (= poster frame). Runs once on appear.
    @MainActor
    private func loadSenderPreview(payload: AttachmentMessagePayload) async {
        let entry = await SenderAttachmentCache.shared.entry(for: payload.descriptor.blobID)
        guard let entry = entry else { return }
        // Stash the raw bytes for the synthesized Opened later.
        self.senderPreviewFullContent = entry.fullContent
        self.senderPreviewThumbnail = entry.thumbnail
        // Decide what to display in the bubble: full content if we have it
        // (sharp), otherwise the 4 KB thumbnail (soft fallback).
        let imageBytes: Data? = {
            switch entry.mime {
            case .jpeg, .png, .webp:
                return entry.fullContent ?? entry.thumbnail
            case .mp4h264:
                // Videos: the 4 KB on-wire thumbnail is only 256 px on the
                // longest edge and looks blurry when rendered at 240 pt on
                // a Retina display. If we still hold the full sanitised
                // MP4 in the sender cache, extract a sharp poster frame
                // asynchronously below. Use the small thumbnail only as a
                // transient fallback while the poster is being decoded.
                return entry.thumbnail
            case .opus, .aac:
                return nil
            }
        }()
        if let bytes = imageBytes, let img = UIImage(data: bytes) {
            withAnimation(.easeInOut(duration: 0.25)) {
                self.senderPreviewImage = img
            }
        }

        // Upgrade path: for videos where the full MP4 is cached locally,
        // decode a high-resolution poster frame off the main actor and
        // swap it in once ready. Stays in RAM only for this view; the
        // cache already holds the MP4 bytes.
        if entry.mime == .mp4h264, let mp4 = entry.fullContent {
            let sharp = await Self.extractVideoPoster(mp4: mp4)
            if let sharp {
                await MainActor.run {
                    withAnimation(.easeInOut(duration: 0.2)) {
                        self.senderPreviewImage = sharp
                    }
                }
            }
        }
    }

    /// Decode a high-resolution poster frame from an in-memory MP4. Runs
    /// off the main actor. Returns nil if the asset has no decodable
    /// frame in the first second (very short / codec-quirky videos).
    nonisolated private static func extractVideoPoster(mp4: Data) async -> UIImage? {
        let tempDir = FileManager.default.temporaryDirectory
        let url = tempDir.appendingPathComponent("ladon-bubble-poster-\(UUID().uuidString).mp4")
        // P8-AUDIT8-IOS-26: plaintext video — strongest protection class.
        do { try mp4.write(to: url, options: [.atomic, .completeFileProtection]) } catch { return nil }
        defer { try? FileManager.default.removeItem(at: url) }

        let asset = AVURLAsset(url: url)
        let gen = AVAssetImageGenerator(asset: asset)
        gen.appliesPreferredTrackTransform = true
        gen.requestedTimeToleranceBefore = .positiveInfinity
        gen.requestedTimeToleranceAfter = .positiveInfinity
        // Target ~3x the tile width so the bubble stays crisp on Retina.
        gen.maximumSize = CGSize(width: 1024, height: 1024)

        let candidates: [CMTime] = [
            CMTime(seconds: 0, preferredTimescale: 600),
            CMTime(seconds: 0.1, preferredTimescale: 600),
            CMTime(seconds: 0.5, preferredTimescale: 600),
            CMTime(seconds: 1.0, preferredTimescale: 600),
        ]
        for t in candidates {
            if let cg = try? await gen.image(at: t).image {
                return UIImage(cgImage: cg)
            }
        }
        return nil
    }

    // MARK: - Actions

    private var isVoiceOrAudio: Bool {
        guard let payload = payload else { return false }
        switch payload.descriptor.mime {
        case .opus, .aac: return true
        default: return false
        }
    }

    private func tap() {
        guard let payload = payload else { return }
        if opened != nil {
            if isVoiceOrAudio {
                toggleVoicePlayback()
            } else {
                showingFullscreen = true
            }
            return
        }
        // Outgoing bubbles cannot use the recipient download path \u2014 the
        // sender does not hold the recipient's Kyber secret key. Either we
        // have the original cached locally, or the original is gone (cache
        // evicted / app restarted) and we surface a clean message.
        if isOutgoing {
            if let full = senderPreviewFullContent, !full.isEmpty {
                let synthesized = AttachmentReceiveService.Opened(
                    content: full,
                    thumbnail: senderPreviewThumbnail ?? Data(),
                    caption: nil,
                    mime: payload.descriptor.mime,
                    dimensions: payload.descriptor.dimensions
                )
                self.opened = synthesized
                self.showingFullscreen = true
            } else {
                self.downloadError = "Original no longer available on this device"
            }
            return
        }
        guard !isLoading else { return }
        isLoading = true
        downloadProgress = 0
        downloadError = nil
        Task {
            do {
                let result = try await AttachmentDownloadCache.shared.fetch(
                    payload: payload,
                    contactID: message.conversationID,
                    progress: { p in
                        Task { @MainActor in
                            // Monotonic — never jump backwards, and animate
                            // smoothly towards the new value.
                            withAnimation(.easeInOut(duration: 0.25)) {
                                if p > self.downloadProgress {
                                    self.downloadProgress = p
                                }
                            }
                        }
                    }
                )
                await MainActor.run {
                    withAnimation(.easeInOut(duration: 0.2)) {
                        self.downloadProgress = 1.0
                    }
                    self.opened = result
                    self.isLoading = false
                    // Voice/audio: auto-start inline playback.
                    // Photo/Video: open fullscreen.
                    if self.isVoiceOrAudio {
                        self.startVoicePlayback()
                    } else {
                        self.showingFullscreen = true
                    }
                }
            } catch {
                await MainActor.run {
                    self.isLoading = false
                    self.downloadProgress = 0
                    self.downloadError = "Download failed"
                    #if DEBUG
                    self.downloadError = "DL: \(error)"
                    #endif
                }
            }
        }
    }

    // MARK: - Inline voice playback

    private func toggleVoicePlayback() {
        if voiceIsPlaying {
            pauseVoicePlayback()
        } else {
            startVoicePlayback()
        }
    }

    private func startVoicePlayback() {
        guard let opened = opened else { return }
        // Haptic
        let gen = UIImpactFeedbackGenerator(style: .soft)
        gen.impactOccurred(intensity: 0.7)

        do {
            if voicePlayer == nil {
                // Always reset the AVAudioSession to a clean .playback
                // state before building the player. Skipping this on a
                // session left in `.playAndRecord` (recorder just used)
                // is what causes AVAudioPlayer(data:) to throw
                // "Audio not playable" intermittently — the decoder
                // refuses to init while the session is still tied to
                // the recorder route.
                let session = AVAudioSession.sharedInstance()
                try? session.setActive(false, options: .notifyOthersOnDeactivation)
                try session.setCategory(.playback, mode: .default)
                try session.setActive(true)
                let player = try Self.makeAudioPlayer(from: opened.content)
                player.prepareToPlay()
                voicePlayer = player
                voiceError = nil
            }
            guard let player = voicePlayer else { return }
            player.play()
            voiceIsPlaying = true
            voiceTimer?.invalidate()
            voiceTimer = Timer.scheduledTimer(withTimeInterval: 0.05, repeats: true) { _ in
                Task { @MainActor in
                    guard let p = self.voicePlayer else { return }
                    if p.duration > 0 {
                        self.voiceProgress = min(1.0, p.currentTime / p.duration)
                    }
                    if !p.isPlaying {
                        self.voiceIsPlaying = false
                        self.voiceTimer?.invalidate()
                        self.voiceTimer = nil
                        // Reset to beginning when finished so next tap restarts.
                        if p.currentTime >= max(0, p.duration - 0.1) {
                            p.currentTime = 0
                            self.voiceProgress = 0
                        }
                    }
                }
            }
        } catch {
            let ns = error as NSError
            // L1 (security audit): never put decrypted bytes in the user-facing
            // string or the pasteboard — on a decrypt/corruption failure the
            // "magic" bytes are arbitrary plaintext, not container magic. The
            // first 16 bytes stay in the DEBUG-only log below.
            let bytes = opened.content.count
            let msg = "Audio not playable\n\(ns.domain) \(ns.code)\n\(error.localizedDescription)\nbytes=\(bytes)"
            voiceError = msg
            // Push the (plaintext-free) message to the pasteboard so the user
            // can paste it back to us — the bubble has limited vertical space.
            // L4: 10 s expiry, matching the rest of the app.
            UIPasteboard.general.setItems(
                [[UIPasteboard.typeAutomatic: msg]],
                options: [.localOnly: true, .expirationDate: Date().addingTimeInterval(10)]
            )
            #if DEBUG
            let hex = opened.content.prefix(16).map { String(format: "%02x", $0) }.joined(separator: " ")
            print("[AttachmentBubble] voice playback failed: \(error)")
            print("[AttachmentBubble]   domain=\(ns.domain) code=\(ns.code) bytes=\(bytes) firstHex=\(hex)")
            #endif
        }
    }

    /// AVAudioPlayer factory — **RAM only**, never writes plaintext to
    /// disk. Two attempts:
    /// 1) `AVAudioPlayer(data:fileTypeHint:)` with `.m4a` hint.
    /// 2) Same with `.mp4` hint (some iOS builds prefer this for AAC).
    /// If both fail the error is surfaced to the user via `voiceError`
    /// so the bug can be diagnosed without leaking the bytes to disk.
    fileprivate static func makeAudioPlayer(from data: Data) throws -> AVAudioPlayer {
        // Path 1: in-memory with explicit M4A hint.
        if let p = try? AVAudioPlayer(data: data, fileTypeHint: AVFileType.m4a.rawValue) {
            return p
        }
        // Path 2: in-memory with MP4 hint.
        return try AVAudioPlayer(data: data, fileTypeHint: AVFileType.mp4.rawValue)
    }

    private func pauseVoicePlayback() {
        voicePlayer?.pause()
        voiceIsPlaying = false
        voiceTimer?.invalidate()
        voiceTimer = nil
    }
}

// MARK: - Progress ring (filling circle)

@available(iOS 17.0, *)
private struct ProgressRing: View {
    // Creates the dependency that makes this view repaint when the
    // appearance changes. LadonTheme's colours are static reads, so
    // without it SwiftUI sees no reason to call body again and the view
    // keeps the previous mode's colours. Unused on purpose.
    @Environment(\.colorScheme) private var ladonAppearanceTick
    let progress: Double
    /// The ring has two callsites with opposite backdrops: over the black
    /// scrim on a media tile (white is right in both modes) and inside a voice
    /// bubble (must follow the bubble's text colour, or an incoming download
    /// shows white-on-white in light mode).
    var tint: Color = .white

    var body: some View {
        let p = CGFloat(max(0, min(progress, 1)))
        ZStack {
            Circle()
                .stroke(tint.opacity(0.22), lineWidth: 4)
            Circle()
                .trim(from: 0, to: p)
                .stroke(
                    AngularGradient(
                        gradient: Gradient(colors: [tint.opacity(0.6), tint]),
                        center: .center
                    ),
                    style: StrokeStyle(lineWidth: 4, lineCap: .round)
                )
                .rotationEffect(.degrees(-90))
            Text("\(Int(p * 100))%")
                .font(.system(size: 11, weight: .semibold, design: .rounded))
                .foregroundColor(tint)
                .monospacedDigit()
        }
    }
}

// MARK: - Shimmer gradient placeholder (used while loading media thumb)

@available(iOS 17.0, *)
private struct ShimmerGradient: View {
    // Creates the dependency that makes this view repaint when the
    // appearance changes. LadonTheme's colours are static reads, so
    // without it SwiftUI sees no reason to call body again and the view
    // keeps the previous mode's colours. Unused on purpose.
    @Environment(\.colorScheme) private var ladonAppearanceTick
    let icon: String
    @State private var phase: CGFloat = -1

    var body: some View {
        ZStack {
            LinearGradient(
                colors: [
                    LadonTheme.onSurface(0.06),
                    LadonTheme.onSurface(0.02),
                    LadonTheme.onSurface(0.06),
                ],
                startPoint: .topLeading, endPoint: .bottomTrailing
            )
            .background(LadonTheme.bubbleIncoming)

            // Shimmer band
            GeometryReader { geo in
                LinearGradient(
                    gradient: Gradient(stops: [
                        .init(color: .clear, location: 0),
                        .init(color: LadonTheme.onSurface(0.10), location: 0.5),
                        .init(color: .clear, location: 1),
                    ]),
                    startPoint: .leading, endPoint: .trailing
                )
                .frame(width: geo.size.width * 0.6)
                .offset(x: geo.size.width * phase)
                .blendMode(.plusLighter)
            }
            .allowsHitTesting(false)

            Image(systemName: icon)
                .font(.system(size: 30, weight: .semibold))
                .foregroundColor(LadonTheme.onSurface(0.6))
        }
        .onAppear {
            withAnimation(.linear(duration: 1.6).repeatForever(autoreverses: false)) {
                phase = 1.6
            }
        }
    }
}

// MARK: - Waveform bars (deterministic from seed)

@available(iOS 17.0, *)
private struct WaveformBars: View {
    // Creates the dependency that makes this view repaint when the
    // appearance changes. LadonTheme's colours are static reads, so
    // without it SwiftUI sees no reason to call body again and the view
    // keeps the previous mode's colours. Unused on purpose.
    @Environment(\.colorScheme) private var ladonAppearanceTick
    let seed: UInt64
    /// 0…1 — how much of the waveform is "played" (filled from left).
    var progress: Double = 0
    var fillColor: Color = .white
    var backgroundColor: Color = LadonTheme.onSurface(0.45)

    private static let barCount = 34

    var body: some View {
        GeometryReader { geo in
            let fillWidth = geo.size.width * CGFloat(max(0, min(1, progress)))
            HStack(alignment: .center, spacing: 2) {
                ForEach(0..<Self.barCount, id: \.self) { i in
                    Capsule()
                        .fill(backgroundColor)
                        .frame(width: 2, height: barHeight(index: i, max: geo.size.height))
                }
            }
            .frame(width: geo.size.width, height: geo.size.height, alignment: .leading)
            .overlay(
                // Filled (played) portion — same bars, clipped to progress width.
                HStack(alignment: .center, spacing: 2) {
                    ForEach(0..<Self.barCount, id: \.self) { i in
                        Capsule()
                            .fill(fillColor)
                            .frame(width: 2, height: barHeight(index: i, max: geo.size.height))
                    }
                }
                .frame(width: geo.size.width, height: geo.size.height, alignment: .leading)
                .mask(
                    HStack(spacing: 0) {
                        Rectangle().frame(width: fillWidth)
                        Spacer(minLength: 0)
                    }
                )
                .animation(.linear(duration: 0.1), value: progress)
            )
        }
    }

    private func barHeight(index: Int, max: CGFloat) -> CGFloat {
        // Deterministic pseudo-random between 0.2 and 1.0 — looks like a waveform
        // without revealing any actual audio content (purely visual).
        let x = seed &+ UInt64(index &* 2654435761)
        let v = Double((x >> 16) & 0xFFFF) / Double(0xFFFF)   // 0…1
        let normalized = 0.22 + 0.78 * (0.5 + 0.5 * sin(Double(index) * 0.9 + v * 6.28))
        return CGFloat(normalized) * max
    }
}

// MARK: - Fullscreen viewer

@available(iOS 17.0, *)
struct AttachmentViewer: View {
    // Creates the dependency that makes this view repaint when the
    // appearance changes. LadonTheme's colours are static reads, so
    // without it SwiftUI sees no reason to call body again and the view
    // keeps the previous mode's colours. Unused on purpose.
    @Environment(\.colorScheme) private var ladonAppearanceTick
    let opened: AttachmentReceiveService.Opened
    @Environment(\.dismiss) private var dismiss
    @State private var audioPlayer: AVAudioPlayer?
    @State private var isPlaying = false
    @State private var audioProgress: Double = 0
    @State private var audioTimer: Timer?
    @State private var dismissOffset: CGFloat = 0

    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()

            content
                .offset(y: dismissOffset)
                .opacity(1.0 - min(Double(abs(dismissOffset)) / 400.0, 0.5))

            // Top bar
            VStack {
                HStack {
                    Button(action: { dismiss() }) {
                        ZStack {
                            Circle()
                                .fill(.ultraThinMaterial)
                                .frame(width: 36, height: 36)
                            Image(systemName: "xmark")
                                .font(.system(size: 14, weight: .bold))
                                .foregroundColor(.white)
                        }
                    }
                    Spacer()
                    Text(title)
                        .font(.subheadline.weight(.semibold))
                        .foregroundColor(LadonTheme.onSurface(0.9))
                    Spacer()
                    Color.clear.frame(width: 36, height: 36)
                }
                .padding(.horizontal, 16)
                .padding(.top, 12)
                Spacer()
            }
        }
        // Swipe-to-dismiss is only wired up for audio, because images have
        // their own pan-while-zoomed gesture and video has its own player
        // controls; a competing parent DragGesture would hijack those.
        .simultaneousGesture(
            DragGesture(minimumDistance: 20)
                .onChanged { v in
                    guard swipeDismissAllowed else { return }
                    if v.translation.height > 0 { dismissOffset = v.translation.height }
                }
                .onEnded { v in
                    guard swipeDismissAllowed else { return }
                    if v.translation.height > 140 {
                        dismiss()
                    } else {
                        withAnimation(.spring(response: 0.3, dampingFraction: 0.8)) {
                            dismissOffset = 0
                        }
                    }
                }
        )
        .onDisappear {
            audioPlayer?.stop()
            audioTimer?.invalidate()
            audioTimer = nil
        }
    }

    private var title: String {
        switch opened.mime {
        case .jpeg, .png, .webp: return "Photo"
        case .mp4h264: return "Video"
        case .opus: return "Voice"
        case .aac: return "Audio"
        }
    }

    /// Only allow swipe-to-dismiss on audio views. Images and videos have
    /// their own internal gestures (pan/zoom for images, scrubber + play
    /// controls for video) that must not be overridden.
    private var swipeDismissAllowed: Bool {
        switch opened.mime {
        case .opus, .aac: return true
        default: return false
        }
    }

    @ViewBuilder
    private var content: some View {
        switch opened.mime {
        case .jpeg, .png, .webp:
            if let img = UIImage(data: opened.content) {
                ZoomableImage(image: img)
            } else {
                Text("Cannot decode image").foregroundColor(.red)
            }
        case .mp4h264:
            VideoContentView(data: opened.content)
        case .opus, .aac:
            audioControls
        }
    }

    private var audioControls: some View {
        VStack(spacing: 28) {
            // Large waveform placeholder (visual only; content is in memory)
            RoundedRectangle(cornerRadius: 20, style: .continuous)
                .fill(LadonTheme.onSurface(0.04))
                .overlay(
                    WaveformBars(
                        seed: UInt64(opened.content.count) &* 2654435761,
                        progress: audioProgress,
                        fillColor: .white,
                        backgroundColor: LadonTheme.onSurface(0.3)
                    )
                    .padding(.horizontal, 24)
                )
                .frame(height: 120)
                .padding(.horizontal, 24)

            // Progress bar
            VStack(spacing: 6) {
                ProgressView(value: audioProgress)
                    .tint(.white)
                HStack {
                    Text(formatTime(audioPlayer?.currentTime ?? 0))
                    Spacer()
                    Text(formatTime(audioPlayer?.duration ?? 0))
                }
                .font(.caption2.monospacedDigit())
                .foregroundColor(LadonTheme.onSurface(0.6))
            }
            .padding(.horizontal, 40)

            // Play button
            Button(action: togglePlay) {
                ZStack {
                    Circle()
                        .fill(.ultraThinMaterial)
                        .frame(width: 76, height: 76)
                    Image(systemName: isPlaying ? "pause.fill" : "play.fill")
                        .font(.system(size: 30, weight: .bold))
                        .foregroundColor(.white)
                        .offset(x: isPlaying ? 0 : 2)
                }
            }
            .buttonStyle(.plain)
            .sensoryFeedback(.impact(flexibility: .soft, intensity: 0.7), trigger: isPlaying)
        }
        .padding()
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .onAppear { prepareAudio() }
    }

    private func formatTime(_ t: TimeInterval) -> String {
        if !t.isFinite || t < 0 { return "0:00" }
        let s = Int(t)
        return String(format: "%d:%02d", s / 60, s % 60)
    }

    private func prepareAudio() {
        do {
            try AVAudioSession.sharedInstance().setCategory(.playback, mode: .default)
            try AVAudioSession.sharedInstance().setActive(true)
            let player = try AttachmentBubbleView.makeAudioPlayer(from: opened.content)
            player.prepareToPlay()
            audioPlayer = player
        } catch {
            #if DEBUG
            print("[AttachmentViewer] audio init failed: \(error)")
            print("[AttachmentViewer]   bytes=\(opened.content.count) firstHex=\(opened.content.prefix(16).map { String(format: "%02x", $0) }.joined())")
            #endif
        }
    }

    private func togglePlay() {
        guard let player = audioPlayer else { return }
        if player.isPlaying {
            player.pause()
            isPlaying = false
            audioTimer?.invalidate()
            audioTimer = nil
        } else {
            player.play()
            isPlaying = true
            audioTimer = Timer.scheduledTimer(withTimeInterval: 0.1, repeats: true) { _ in
                guard let p = audioPlayer else { return }
                if p.duration > 0 {
                    audioProgress = min(1.0, p.currentTime / p.duration)
                }
                if !p.isPlaying {
                    isPlaying = false
                    audioTimer?.invalidate()
                    audioTimer = nil
                }
            }
        }
    }
}

@available(iOS 17.0, *)
private struct ZoomableImage: View {
    // Creates the dependency that makes this view repaint when the
    // appearance changes. LadonTheme's colours are static reads, so
    // without it SwiftUI sees no reason to call body again and the view
    // keeps the previous mode's colours. Unused on purpose.
    @Environment(\.colorScheme) private var ladonAppearanceTick
    let image: UIImage

    @State private var scale: CGFloat = 1.0
    @State private var lastScale: CGFloat = 1.0
    @State private var offset: CGSize = .zero
    @State private var lastOffset: CGSize = .zero

    private let minScale: CGFloat = 1.0
    private let maxScale: CGFloat = 6.0

    var body: some View {
        GeometryReader { geo in
            Image(uiImage: image)
                .resizable()
                .scaledToFit()
                .frame(width: geo.size.width, height: geo.size.height)
                .scaleEffect(scale)
                .offset(offset)
                .gesture(
                    SimultaneousGesture(
                        MagnificationGesture()
                            .onChanged { value in
                                scale = min(max(lastScale * value, 0.8), maxScale)
                            }
                            .onEnded { _ in
                                if scale < minScale {
                                    withAnimation(.spring(response: 0.35, dampingFraction: 0.8)) {
                                        scale = minScale
                                        offset = .zero
                                    }
                                }
                                lastScale = scale
                                lastOffset = offset
                            },
                        DragGesture()
                            .onChanged { v in
                                guard scale > 1.01 else { return }
                                offset = CGSize(
                                    width: lastOffset.width + v.translation.width,
                                    height: lastOffset.height + v.translation.height
                                )
                            }
                            .onEnded { _ in
                                // Clamp offset so the image stays visible.
                                let imgW = geo.size.width * scale
                                let imgH = geo.size.height * scale
                                let maxX = max(0, (imgW - geo.size.width) / 2)
                                let maxY = max(0, (imgH - geo.size.height) / 2)
                                withAnimation(.spring(response: 0.3, dampingFraction: 0.85)) {
                                    offset = CGSize(
                                        width: min(maxX, max(-maxX, offset.width)),
                                        height: min(maxY, max(-maxY, offset.height))
                                    )
                                }
                                lastOffset = offset
                            }
                    )
                )
                .onTapGesture(count: 2) {
                    withAnimation(.spring(response: 0.35, dampingFraction: 0.8)) {
                        if scale > 1.01 {
                            scale = 1.0
                            lastScale = 1.0
                            offset = .zero
                            lastOffset = .zero
                        } else {
                            scale = 2.5
                            lastScale = 2.5
                        }
                    }
                }
        }
        .background(Color.black)
    }
}

@available(iOS 17.0, *)
private struct VideoContentView: View {
    // Creates the dependency that makes this view repaint when the
    // appearance changes. LadonTheme's colours are static reads, so
    // without it SwiftUI sees no reason to call body again and the view
    // keeps the previous mode's colours. Unused on purpose.
    @Environment(\.colorScheme) private var ladonAppearanceTick
    @Environment(\.scenePhase) private var scenePhase
    let data: Data
    @State private var url: URL?

    var body: some View {
        Group {
            if let url = url {
                VideoPlayer(player: AVPlayer(url: url))
            } else {
                ProgressView()
            }
        }
        .onAppear { writeTempIfNeeded() }
        .onDisappear { removeTemp() }
        // The decrypted MP4 is a plaintext file in tmp/. Removed only on
        // disappear, it outlived a viewer left open when the app was
        // backgrounded and then killed (scan F44). Remove it in the
        // background; write it again from memory on return.
        .onChange(of: scenePhase) { _, phase in
            switch phase {
            case .background: removeTemp()
            case .active: writeTempIfNeeded()
            default: break
            }
        }
    }

    private func removeTemp() {
        if let url = url { try? FileManager.default.removeItem(at: url) }
        url = nil
    }

    private func writeTempIfNeeded() {
        guard url == nil else { return }
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("ladon-att-\(UUID().uuidString).mp4")
        do {
            try data.write(to: tmp, options: [.atomic, .completeFileProtection])
            url = tmp
        } catch {
            #if DEBUG
            print("[VideoContentView] write failed: \(error)")
            #endif
        }
    }
}

// MARK: - Attachment picker sheet (replaces confirmationDialog)

@available(iOS 17.0, *)
struct AttachmentPickerSheet: View {
    // Creates the dependency that makes this view repaint when the
    // appearance changes. LadonTheme's colours are static reads, so
    // without it SwiftUI sees no reason to call body again and the view
    // keeps the previous mode's colours. Unused on purpose.
    @Environment(\.colorScheme) private var ladonAppearanceTick
    let onPhoto: () -> Void
    let onVideo: () -> Void
    let onVoice: () -> Void
    let onAudio: () -> Void
    let onCancel: () -> Void

    var body: some View {
        if AppearanceManager.isDarkStored {
            darkBody
        } else {
            lightBody
        }
    }

    /// Light (ladon.app): built like New Chat — Cancel in the glass bar,
    /// eyebrow, title, the "Encrypted · via Tor" tag, one green card and
    /// white cards.
    private var lightBody: some View {
        NavigationStack {
            ZStack {
                MeshBackground()
                ScrollView {
                    VStack(spacing: 12) {
                        PairingHeader(eyebrow: "Attach media", title: Text("Send"), titleSize: 34)
                        HStack {
                            LadonTagPill(text: "Encrypted · via Tor", dot: true)
                            Spacer()
                        }
                        .padding(.horizontal, 24)
                        .padding(.bottom, 10)
                        choiceCard(icon: "photo", title: "Photo", subtitle: "From your library",
                                   prominent: true, action: onPhoto)
                        choiceCard(icon: "video", title: "Video", subtitle: "From your library", action: onVideo)
                        choiceCard(icon: "mic", title: "Voice", subtitle: "Record a voice message", action: onVoice)
                        choiceCard(icon: "music.note", title: "Audio", subtitle: "From Files", action: onAudio)
                    }
                    .padding(.bottom, 24)
                }
                .scrollContentBackground(.hidden)
            }
            .toolbarBackground(.hidden, for: .navigationBar)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel", action: onCancel)
                        .foregroundColor(LadonTheme.brandGreen)
                }
            }
        }
        .tint(LadonTheme.brandGreen)
        .presentationDetents([.large])
        .presentationBackground { MeshBackground() }
    }

    /// Light card, same values as New Chat's cards: green (prominent) or
    /// white, 24 pt corners, 48 pt icon tile, chevron.
    private func choiceCard(icon: String, title: LocalizedStringKey, subtitle: LocalizedStringKey,
                            prominent: Bool = false, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(spacing: 14) {
                Image(systemName: icon)
                    .font(.system(size: 22, weight: .medium))
                    .foregroundColor(prominent ? LadonTheme.textPrimary : LadonTheme.greenInk)
                    .frame(width: 48, height: 48)
                    .background(
                        RoundedRectangle(cornerRadius: 16, style: .continuous)
                            .fill(prominent ? Color.white.opacity(0.35) : LadonTheme.brandGreenSoft)
                    )
                VStack(alignment: .leading, spacing: 2) {
                    Text(title)
                        .font(.manrope(17, .extrabold, relativeTo: .headline))
                        .tracking(-0.34)
                        .foregroundColor(LadonTheme.textPrimary)
                    Text(subtitle)
                        .font(.manrope(13, prominent ? .semibold : .regular, relativeTo: .caption))
                        .foregroundColor(prominent ? LadonTheme.greenDeep : LadonTheme.textSecondary)
                }
                Spacer()
                Image(systemName: "chevron.right")
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundColor(prominent ? LadonTheme.textPrimary : LadonTheme.inkMuted)
            }
            .padding(18)
            .background(
                Group {
                    if prominent {
                        RoundedRectangle(cornerRadius: 24, style: .continuous)
                            .fill(LadonTheme.brandGreen)
                            .shadow(color: LadonTheme.brandGreen.opacity(0.45), radius: 15, y: 10)
                    } else {
                        LadonCardBackground()
                    }
                }
            )
        }
        .buttonStyle(.plain)
        .padding(.horizontal)
    }

    private var darkBody: some View {
        VStack(spacing: 18) {
            // Grabber
            Capsule()
                .fill(LadonTheme.onSurface(0.25))
                .frame(width: 38, height: 4)
                .padding(.top, 10)

            Text("Send")
                .font(.headline)
                .foregroundColor(LadonTheme.textPrimary)

            HStack(spacing: 14) {
                PickerTile(icon: "photo.fill", label: "Photo", action: onPhoto)
                PickerTile(icon: "video.fill", label: "Video", action: onVideo)
                PickerTile(icon: "waveform", label: "Voice", action: onVoice)
                PickerTile(icon: "music.note", label: "Audio", action: onAudio)
            }
            .padding(.horizontal, 20)

            Button(action: onCancel) {
                Text("Cancel")
                    .font(.body.weight(.semibold))
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 14)
                    .background(
                        Capsule()
                            .fill(.ultraThinMaterial).opacity(0.55)
                            .overlay(Capsule().strokeBorder(LadonTheme.glassStroke, lineWidth: 1))
                    )
                    .foregroundColor(LadonTheme.textPrimary)
            }
            .buttonStyle(.plain)
            .padding(.horizontal, 20)
            .padding(.bottom, 20)
        }
        .frame(maxWidth: .infinity)
        .presentationDetents([.height(260)])
        .presentationDragIndicator(.hidden)
        .presentationBackground { MeshBackground() }
        .presentationCornerRadius(24)
    }

    private struct PickerTile: View {
        // Creates the dependency that makes this view repaint when the
        // appearance changes. LadonTheme's colours are static reads, so
        // without it SwiftUI sees no reason to call body again and the view
        // keeps the previous mode's colours. Unused on purpose.
        @Environment(\.colorScheme) private var ladonAppearanceTick
        let icon: String
        let label: String
        let action: () -> Void

        var body: some View {
            Button(action: action) {
                VStack(spacing: 10) {
                    ZStack {
                        RoundedRectangle(cornerRadius: 18, style: .continuous)
                            .fill(LadonTheme.onSurface(0.08))
                            .frame(width: 64, height: 64)
                            .overlay(
                                RoundedRectangle(cornerRadius: 18, style: .continuous)
                                    .stroke(LadonTheme.onSurface(0.12), lineWidth: 1)
                            )
                        Image(systemName: icon)
                            .font(.system(size: 24, weight: .semibold))
                            .foregroundColor(LadonTheme.textPrimary)
                    }
                    Text(label)
                        .font(.caption.weight(.medium))
                        .foregroundColor(LadonTheme.textTertiary)
                }
                .frame(maxWidth: .infinity)
            }
            .buttonStyle(.plain)
            .sensoryFeedback(.impact(flexibility: .soft, intensity: 0.6), trigger: false)
        }
    }
}
