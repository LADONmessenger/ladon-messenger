// VoiceRecorderOverlay.swift — Phase 8
//
// Press-and-hold voice recorder. Writes an AAC/M4A file in the temporary
// directory and hands the raw bytes back to the caller on release. The
// AudioSanitizer is run inside AttachmentSendService before upload — this
// view is strictly the capture stage.

import SwiftUI
import AVFoundation

@available(iOS 17.0, *)
struct VoiceRecorderOverlay: View {
    // Creates the dependency that makes this view repaint when the
    // appearance changes. LadonTheme's colours are static reads, so
    // without it SwiftUI sees no reason to call body again and the view
    // keeps the previous mode's colours. Unused on purpose.
    @Environment(\.colorScheme) private var ladonAppearanceTick

    /// Called with raw recorded bytes when the user finishes.
    let onFinish: (Data) -> Void
    /// Called when the user cancels (slide to cancel, permission denial, etc).
    let onCancel: () -> Void

    @Environment(\.scenePhase) private var scenePhase
    @State private var recorder: AVAudioRecorder?
    @State private var fileURL: URL?
    @State private var elapsed: TimeInterval = 0
    @State private var timer: Timer?
    @State private var denied = false
    @State private var pulse = false
    @State private var levels: [CGFloat] = Array(repeating: 0.15, count: 36)

    var body: some View {
        Group {
            if AppearanceManager.isDarkStored {
                darkBody
            } else {
                lightBody
            }
        }
        .onAppear {
            begin()
            withAnimation(.easeOut(duration: 1.0).repeatForever(autoreverses: false)) {
                pulse = true
            }
        }
        // The recording is a plaintext file in tmp/ until finish() or cancel()
        // removes it. A swipe-dismissed sheet reaches neither, so the file
        // stayed behind (scan F43): discard whatever is still open here.
        .onDisappear { discardIfStillOpen() }
        // Leaving the app locks it, and iOS does not record in the background
        // (no audio background mode): drop the take instead of keeping a
        // half-written plaintext file behind the lock screen.
        .onChange(of: scenePhase) { _, phase in
            if phase == .background { cancel() }
        }
    }

    /// Light (ladon.app): built like Safety Number — badge, eyebrow, title,
    /// lead, a white data card (REC, timer in JetBrains Mono, live
    /// waveform), green Send pill; Cancel in the glass bar.
    private var lightBody: some View {
        NavigationStack {
            ZStack {
                MeshBackground()
                VStack(spacing: 0) {
                    if denied {
                        Spacer()
                        LadonStatusBadge(systemImage: "mic.slash", size: 64)
                        LadonStatusText(title: "Voice", lead: "Microphone access is required for voice messages.",
                                        titleSize: 28)
                            .padding(.top, 18)
                        Spacer()
                        Button(action: onCancel) {
                            PairingGhostLabel(title: "Close", systemImage: "xmark")
                        }
                        .buttonStyle(.plain)
                        .padding(.horizontal, 16)
                    } else {
                        PairingHeader(badge: AnyView(LadonStatusBadge(systemImage: "mic", size: 48)),
                                      eyebrow: "Attach media", title: Text("Voice"), titleSize: 28,
                                      lead: Text("Tap Send when you're done"))
                        recordingCard
                            .padding(.horizontal, 16)
                            .padding(.top, 10)
                        Spacer()
                        PairingPrimaryButton(title: "Send", systemImage: "arrow.up", action: finish)
                            .sensoryFeedback(.impact(flexibility: .solid, intensity: 0.8), trigger: elapsed)
                            .padding(.horizontal, 16)
                    }
                }
                .padding(.bottom, 12)
            }
            .toolbarBackground(.hidden, for: .navigationBar)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel", action: cancel)
                        .foregroundColor(LadonTheme.brandGreen)
                }
            }
        }
        .tint(LadonTheme.brandGreen)
        .presentationDetents([.large])
        .presentationBackground { MeshBackground() }
    }

    /// White data card: REC marker, elapsed time, live waveform.
    private var recordingCard: some View {
        VStack(spacing: 14) {
            HStack(spacing: 8) {
                Circle()
                    .fill(LadonTheme.coral)
                    .frame(width: 7, height: 7)
                    .background(Circle().fill(LadonTheme.coral.opacity(0.18)).frame(width: 15, height: 15))
                Text(verbatim: "REC")
                    .font(.jbMono(10.5, .medium, relativeTo: .caption2))
                    .tracking(1.47)
                    .foregroundColor(LadonTheme.coralInk)
            }
            Text(formatted(elapsed))
                .font(.jbMono(48, .medium))
                .monospacedDigit()
                .foregroundColor(LadonTheme.textPrimary)
            HStack(alignment: .center, spacing: 3) {
                ForEach(0..<levels.count, id: \.self) { i in
                    Capsule()
                        .fill(LadonTheme.brandGreen.opacity(0.55 + 0.45 * Double(levels[i])))
                        .frame(width: 3, height: 6 + 34 * levels[i])
                }
            }
            .frame(height: 40)
            .animation(.easeOut(duration: 0.08), value: levels)
        }
        .padding(.vertical, 22)
        .padding(.horizontal, 20)
        .frame(maxWidth: .infinity)
        .background(LadonCardBackground(elevated: true))
    }

    private var darkBody: some View {
        VStack(spacing: 20) {
            Capsule()
                .fill(LadonTheme.onSurface(0.25))
                .frame(width: 38, height: 4)
                .padding(.top, 10)

            if denied {
                VStack(spacing: 16) {
                    Image(systemName: "mic.slash.fill")
                        .font(.system(size: 48))
                        .foregroundColor(LadonTheme.textSecondary)
                    Text("Microphone access is required for voice messages.")
                        .multilineTextAlignment(.center)
                        .font(.callout)
                        .foregroundColor(LadonTheme.textPrimary)
                    Button(action: onCancel) {
                        Text("Close")
                            .font(.body.weight(.semibold))
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 12)
                            .background(
                                Capsule()
                                    .fill(.ultraThinMaterial).opacity(0.55)
                                    .overlay(Capsule().strokeBorder(LadonTheme.glassStroke, lineWidth: 1))
                            )
                            .foregroundColor(LadonTheme.textPrimary)
                    }
                    .buttonStyle(.plain)
                    .padding(.horizontal, 20)
                }
                .padding(24)
            } else {
                // Pulsing rec dot + timer
                HStack(spacing: 10) {
                    ZStack {
                        Circle()
                            .fill(LadonTheme.coral.opacity(0.30))
                            .frame(width: 24, height: 24)
                            .scaleEffect(pulse ? 1.8 : 1.0)
                            .opacity(pulse ? 0 : 0.8)
                        Circle()
                            .fill(LadonTheme.coral)
                            .frame(width: 12, height: 12)
                    }
                    Text(formatted(elapsed))
                        .font(.jbMono(20, .medium))
                        .foregroundColor(LadonTheme.textPrimary)
                }
                .padding(.top, 8)

                // Live waveform — brand green gradient
                HStack(alignment: .center, spacing: 3) {
                    ForEach(0..<levels.count, id: \.self) { i in
                        Capsule()
                            .fill(LadonTheme.greenGradient)
                            .frame(width: 3, height: 6 + 60 * levels[i])
                    }
                }
                .frame(height: 72)
                .padding(.horizontal, 24)
                .animation(.easeOut(duration: 0.08), value: levels)

                Text("Tap Send when you're done")
                    .font(.caption)
                    .foregroundColor(LadonTheme.textSecondary)

                HStack(spacing: 14) {
                    Button(action: cancel) {
                        HStack(spacing: 8) {
                            Image(systemName: "xmark")
                            Text("Cancel")
                        }
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

                    Button(action: finish) {
                        HStack(spacing: 8) {
                            Image(systemName: "paperplane.fill")
                            Text("Send")
                        }
                        .font(.body.weight(.semibold))
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 14)
                        .background(LadonTheme.greenGradient)
                        .clipShape(Capsule())
                        .overlay(Capsule().strokeBorder(LadonTheme.onSurface(0.3), lineWidth: 1))
                        .foregroundColor(LadonTheme.background)
                    }
                    .buttonStyle(.plain)
                    .sensoryFeedback(.impact(flexibility: .solid, intensity: 0.8), trigger: elapsed)
                }
                .padding(.horizontal, 20)
                .padding(.bottom, 20)
            }
        }
        .frame(maxWidth: .infinity)
        .presentationDetents([.height(340)])
        .presentationDragIndicator(.hidden)
        .presentationBackground { MeshBackground() }
        .presentationCornerRadius(24)
    }

    private func formatted(_ secs: TimeInterval) -> String {
        let total = Int(secs)
        return String(format: "%d:%02d", total / 60, total % 60)
    }

    private func begin() {
        let session = AVAudioSession.sharedInstance()
        // Belt-and-braces: deactivate any leftover playback session from
        // the bubble's voicememo player. Switching categories while the
        // session is still `.playback`-active fails silently on some
        // devices (observed on iPhone 13 Pro) and would otherwise show
        // the "Microphone access required" denial UI.
        try? session.setActive(false, options: .notifyOthersOnDeactivation)
        do {
            try session.setCategory(.playAndRecord, mode: .spokenAudio, options: [.defaultToSpeaker])
            try session.setActive(true)
        } catch {
            denied = true
            return
        }
        AVAudioApplication.requestRecordPermission { granted in
            DispatchQueue.main.async {
                guard granted else {
                    denied = true
                    return
                }
                startRecording()
            }
        }
    }

    private func startRecording() {
        // The sheet appears twice when it opens (onAppear, onDisappear,
        // onAppear in the same instant — measured on the 12 Pro, 13.10.2026),
        // so begin() runs twice and both permission callbacks land here. A
        // second recorder replaced the first, whose plaintext take was then
        // left in tmp/ with no reference. One take per sheet.
        guard recorder == nil else { return }
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("ladon-voice-\(UUID().uuidString).m4a")
        let settings: [String: Any] = [
            AVFormatIDKey: Int(kAudioFormatMPEG4AAC),
            AVSampleRateKey: 44_100,
            AVNumberOfChannelsKey: 1,
            AVEncoderAudioQualityKey: AVAudioQuality.medium.rawValue,
            AVEncoderBitRateKey: 48_000
        ]
        do {
            let rec = try AVAudioRecorder(url: url, settings: settings)
            rec.isMeteringEnabled = true
            rec.prepareToRecord()
            // P8-AUDIT8-IOS-26: the take is plaintext voice; prepareToRecord
            // created the file — give it the strongest protection class
            // before any audio is written (default was the tmp class).
            try? FileManager.default.setAttributes(
                [.protectionKey: FileProtectionType.complete], ofItemAtPath: url.path)
            if !rec.record() {
                denied = true
                return
            }
            recorder = rec
            fileURL = url
            elapsed = 0
            timer = Timer.scheduledTimer(withTimeInterval: 0.08, repeats: true) { _ in
                rec.updateMeters()
                elapsed = rec.currentTime
                // averagePower is in dB, -160 (silence) … 0 (max).
                let db = rec.averagePower(forChannel: 0)
                let normalized = CGFloat(max(0, min(1, (db + 55) / 55)))
                // Shift the buffer left, append latest sample at the end.
                var next = levels
                next.removeFirst()
                next.append(max(0.08, normalized))
                levels = next
                if elapsed >= 180 { // hard cap 3 min
                    finish()
                }
            }
        } catch {
            denied = true
        }
    }

    private func finish() {
        guard let rec = recorder, let url = fileURL else { onCancel(); return }
        rec.stop()
        cleanupTimerOnly()
        // Release the .playAndRecord session so a subsequent voicememo
        // playback (auto-start after receive) can switch to .playback
        // cleanly. Without this the AVAudioPlayer(data:) factory can
        // fail with OSStatus 1685348671 ('typ?') / 56 because the
        // session is still locked to the recorder route.
        try? AVAudioSession.sharedInstance().setActive(
            false, options: .notifyOthersOnDeactivation
        )
        guard let data = try? Data(contentsOf: url) else {
            try? FileManager.default.removeItem(at: url)
            onCancel()
            return
        }
        try? FileManager.default.removeItem(at: url)
        recorder = nil
        fileURL = nil
        onFinish(data)
    }

    private func cancel() {
        recorder?.stop()
        if let url = fileURL { try? FileManager.default.removeItem(at: url) }
        recorder = nil
        fileURL = nil
        cleanupTimerOnly()
        // Same reasoning as `finish()`: release the recorder session.
        try? AVAudioSession.sharedInstance().setActive(
            false, options: .notifyOthersOnDeactivation
        )
        onCancel()
    }

    /// Stop and delete a recording that neither finish() nor cancel() ended,
    /// without calling back into the presenter (the sheet is already gone).
    /// No-op after finish()/cancel(): both clear `recorder` and `fileURL`.
    private func discardIfStillOpen() {
        cleanupTimerOnly()
        guard recorder != nil || fileURL != nil else { return }
        recorder?.stop()
        if let url = fileURL { try? FileManager.default.removeItem(at: url) }
        recorder = nil
        fileURL = nil
        try? AVAudioSession.sharedInstance().setActive(
            false, options: .notifyOthersOnDeactivation
        )
    }

    private func cleanupTimerOnly() {
        timer?.invalidate()
        timer = nil
    }
}
