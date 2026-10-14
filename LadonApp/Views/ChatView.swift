import SwiftUI
import UIKit
import AudioToolbox
import PhotosUI
import UniformTypeIdentifiers
import AVFoundation
import CryptoKit

// MARK: - UIKit TextField wrapper for reliable QuickPath/SwipeTyping support
struct QuickPathTextField: UIViewRepresentable {
    @Binding var text: String
    var placeholder: String
    var onCommit: () -> Void
    
    static func dismantleUIView(_ uiView: UITextField, coordinator: Coordinator) {
        uiView.resignFirstResponder()
        // FIX R21-A5-2: Wipe UITextField's native NSString buffer before deallocation.
        // SwiftUI may not call updateUIView during teardown, leaving plaintext in heap.
        let len = (uiView.text ?? "").count
        uiView.text = String(repeating: " ", count: len)
        uiView.text = ""
    }
    
    func makeUIView(context: Context) -> UITextField {
        let tf = UITextField()
        tf.placeholder = placeholder
        tf.borderStyle = .none
        if !AppearanceManager.isDarkStored, let manrope = UIFont(name: "Manrope-Regular", size: 15.5) {
            // Light (ladon.app): Manrope, still scaling with Dynamic Type.
            tf.font = UIFontMetrics(forTextStyle: .body).scaledFont(for: manrope)
        } else {
            tf.font = .preferredFont(forTextStyle: .body)
        }
        tf.adjustsFontForContentSizeCategory = true
        tf.returnKeyType = .send
        // FIX M-8: Disable keyboard caching — prevents iOS from storing
        // sensitive message text in keyboard prediction/autocorrect databases.
        tf.autocorrectionType = .no
        tf.autocapitalizationType = .sentences
        tf.spellCheckingType = .no
        // FIX AUDIT-MAR-2026-15: Prevent iOS Autofill content type inference
        tf.textContentType = .none
        tf.smartQuotesType = .yes
        tf.smartDashesType = .yes
        tf.smartInsertDeleteType = .yes
        tf.delegate = context.coordinator
        tf.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        tf.setContentHuggingPriority(.defaultLow, for: .horizontal)
        // Ladon Theme Styling
        // 2026-08-11: Hintergrund und Rahmen liefert die Glas-Kapsel der Eingabe-
        // leiste (Capsule().fill(.ultraThinMaterial) + strokeBorder, siehe unten).
        // Ein zusaetzlicher opaker Hintergrund hier legte beide Flaechen
        // uebereinander — sichtbar als "doppeltes Grau" hinter dem Textfeld.
        tf.backgroundColor = .clear
        tf.textColor = LadonTheme.uiInk
        tf.attributedPlaceholder = NSAttributedString(
            string: placeholder,
            attributes: [.foregroundColor: AppearanceManager.isDarkStored
                ? LadonTheme.uiInk.withAlphaComponent(0.45)
                : UIColor(red: 183/255, green: 188/255, blue: 191/255, alpha: 1)]   // #b7bcbf
        )
        tf.layer.cornerRadius = 18
        tf.layer.borderWidth = 0
        tf.clipsToBounds = true
        // Padding inside text field
        tf.leftView = UIView(frame: CGRect(x: 0, y: 0, width: 12, height: 0))
        tf.leftViewMode = .always
        tf.rightView = UIView(frame: CGRect(x: 0, y: 0, width: 12, height: 0))
        tf.rightViewMode = .always
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
        var parent: QuickPathTextField
        
        init(_ parent: QuickPathTextField) {
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

struct ChatView: View {
    // Creates the dependency that makes this view repaint when the
    // appearance changes. LadonTheme's colours are static reads, so
    // without it SwiftUI sees no reason to call body again and the view
    // keeps the previous mode's colours. Unused on purpose.
    @Environment(\.colorScheme) private var ladonAppearanceTick
    // FIX VW-9: @State private var for proper access control
    @State private var conversation: Conversation
    @StateObject private var viewModel: ChatViewModel
    @State private var messageText = ""
    @State private var isCaptured = UIScreen.main.isCaptured
    @State private var isShielded = false
    @State private var lastMessageCount = 0
    @State private var sendHapticTrigger = false
    @State private var inputBarID = UUID()
    @State private var showRenameAlert = false
    @State private var renameText = ""
    @State private var logoPulse = false
    // Phase 8: attachment UI state
    @State private var showAttachmentDialog = false
    @State private var photoPickerItem: PhotosPickerItem?
    @State private var videoPickerItem: PhotosPickerItem?
    @State private var showPhotoPicker = false
    @State private var showVideoPicker = false
    @State private var showVoiceRecorder = false
    @State private var showFileImporter = false
    @State private var attachmentSending = false
    @State private var attachmentUploadProgress: Double = 0
    @State private var attachmentSendPhase: String = ""
    @State private var attachmentAlert: String?
    @ObservedObject private var torManager = TorManager.shared
    @Environment(\.scenePhase) private var scenePhase
    // Mutual-scan gate: true once we hold the peer's identity (PeerStoreV2).
    // false for a received-only "unverified" contact → input is replaced by a
    // "scan their code to reply" prompt. Pure contact-layer, no crypto change.
    @State private var canReply = false
    /// The user blocked this contact (A1 §7): "Unblock" above the input bar;
    /// sending and attaching are refused until then.
    @State private var isBlocked = false
    @State private var showReplyScanner = false
    @State private var replyScanKey = ""
    @State private var showReplyNaming = false
    @State private var replyName = ""
    @State private var replyScanError: String?
    /// In-chat code exchange: choose who shows and who scans.
    @State private var showCodeExchangeChoice = false
    @State private var showMyCodeSheet = false

    init(conversation: Conversation) {
        self.conversation = conversation
        self._viewModel = StateObject(wrappedValue: ChatViewModel(conversation: conversation))
    }

    private var isDark: Bool { AppearanceManager.isDarkStored }
    
    var body: some View {
        ZStack {
            MeshBackground()
            chatContent

            if !isDark {
                ChatHeaderPillBackdrop()
            }

            if (isCaptured || isShielded) && !isDark {
                LadonContentHiddenView(title: "Content hidden", showsEyebrow: false)
            } else if isCaptured || isShielded {
                LadonTheme.background
                    .ignoresSafeArea()
                    .overlay(
                        Text("Content hidden")
                            .multilineTextAlignment(.center)
                            .foregroundColor(LadonTheme.textPrimary)
                            .font(.headline)
                    )
            }
        }
        .navigationTitle(conversation.contactName)
        .navigationBarTitleDisplayMode(.inline)
        // Light: the glass tab pill (ContentView) stays; keep the system tab
        // bar from coming back on push. Dark: unchanged.
        .toolbar(AppearanceManager.isDarkStored ? .automatic : .hidden, for: .tabBar)
        .toolbarBackground(.hidden, for: .navigationBar)
        .toolbar {
            ToolbarItem(placement: .principal) {
                Button(action: {
                    renameText = conversation.contactName
                    showRenameAlert = true
                }) {
                    if isDark {
                        Text(conversation.contactName)
                            .font(.headline)
                            .foregroundColor(LadonTheme.textPrimary)
                    } else {
                        VStack(spacing: 1) {
                            Text(conversation.contactName)
                                .font(.manrope(16, .bold, relativeTo: .headline))
                                .foregroundColor(LadonTheme.textPrimary)
                                .lineLimit(1)
                            HStack(spacing: 5) {
                                Circle().fill(LadonTheme.brandGreen).frame(width: 5, height: 5)
                                Text("Encrypted · via Tor")
                                    .font(.jbMono(10, relativeTo: .caption2))
                                    .tracking(1)
                                    .textCase(.uppercase)
                            }
                            .foregroundColor(LadonTheme.greenInk)
                        }
                    }
                }
            }
            // Light: our own 44 pt circles sit in the header pill, so the
            // shared iOS glass capsule around them is switched off (iOS 26+).
            if isDark {
                ToolbarItem(placement: .topBarTrailing) { trailingButtons }
            } else {
                if #available(iOS 26.0, *) {
                    ToolbarItem(placement: .topBarTrailing) { trailingButtons }
                        .sharedBackgroundVisibility(.hidden)
                } else {
                    ToolbarItem(placement: .topBarTrailing) { trailingButtons }
                }
            }
        }
        .task {
            await viewModel.loadMessages()
        }
        .onAppear {
            NotificationCenter.default.post(name: .chatViewActive, object: nil)
            // #1 (receive-consolidation): posting .chatViewActive switches the
            // single V2 receive loop to its faster (1.5 s) cadence and
            // suppresses the list screen's foreground notification while this
            // chat is open. The chat's own poll loop was removed — incoming
            // messages now arrive via the NewMessagesReceived observer.
            // Force re-create text input after returning from pushed views (e.g. SafetyNumbers)
            inputBarID = UUID()
            // Mutual-scan gate: do we already hold this peer's identity? If not,
            // the input bar is replaced by a "scan their code to reply" prompt.
            canReply = PeerStoreV2.exists(forContactId: conversation.recipientID)
            isBlocked = ConversationListView.contactRid(conversation).map(BlockListV2.contains) ?? false
            // Mark messages as read when the user opens the chat (sees the messages)
            let candidateIDs = Set([conversation.recipientID, conversation.id, conversation.relayRecipientID].compactMap { $0 })
            InMemoryMessageStore.shared.markAsRead(forAnyOf: candidateIDs)
        }
        .onDisappear {
            NotificationCenter.default.post(name: .chatViewInactive, object: nil)
            // #1: posting .chatViewInactive returns the V2 receive loop to its
            // idle (5 s) cadence and re-enables the list foreground notification.
            // FIX AUDIT-R18-F5: Wipe unsent message text from memory on navigation away
            // FIX R20-A5: Overwrite buffer before clearing (parity with sendMessage())
            messageText = String(repeating: " ", count: messageText.count)
            messageText = ""
        }
        .alert("Rename Contact", isPresented: $showRenameAlert) {
            TextField("Name", text: $renameText)
                .autocorrectionDisabled(true)  // P8-AUDIT8-IOS-17: contact names stay out of the keyboard dictionary
            Button("Cancel", role: .cancel) { }
            Button("Save") {
                renameContact(renameText)
            }
        } message: {
            Text("Enter a new name for this contact.")
        }
        .onReceive(NotificationCenter.default.publisher(for: UIScreen.capturedDidChangeNotification)) { _ in
            isCaptured = UIScreen.main.isCaptured
        }
        .onReceive(NotificationCenter.default.publisher(for: UIApplication.userDidTakeScreenshotNotification)) { _ in
            // H7 FIX: Do NOT purge all messages on screenshot — this is a DoS vector
            // An attacker with physical access could force screenshots to destroy evidence.
            // Instead, shield the content temporarily.
            // Extended shield duration to discourage rapid successive screenshots.
            isShielded = true
            DispatchQueue.main.asyncAfter(deadline: .now() + 5.0) {
                isShielded = false
            }
        }
        .onChange(of: scenePhase) { _, newPhase in
            switch newPhase {
            case .active:
                isShielded = false
            case .inactive, .background:
                isShielded = true
            @unknown default:
                isShielded = true
            }
        }
    }

    private var chatContent: some View {
        VStack(spacing: 0) {
            FadingSeparator()
                .opacity(isDark ? 1 : 0)
            
            // FIX #3: Key-Change Warning Banner
            if viewModel.showKeyChangeWarning && !isDark {
                lightBanner(coral: true) {
                    Image(systemName: "exclamationmark.shield")
                        .font(.system(size: 16, weight: .semibold))
                        .foregroundColor(LadonTheme.coralInk)
                        .padding(.top, 2)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Safety Number Changed")
                            .font(.manrope(14.5, .bold, relativeTo: .subheadline))
                            .foregroundColor(LadonTheme.textPrimary)
                        Text(viewModel.keyChangeWasVerified
                             ? "This contact was verified but their identity key changed. Verify again."
                             : "This contact's identity key has changed. This may indicate a new device.")
                            .font(.manrope(14, relativeTo: .footnote))
                            .foregroundColor(LadonTheme.textPrimary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    Spacer(minLength: 0)
                    lightBannerClose { viewModel.showKeyChangeWarning = false }
                }
                .padding(.top, 8)
            } else if viewModel.showKeyChangeWarning {
                HStack(spacing: 8) {
                    Image(systemName: "exclamationmark.shield.fill")
                        .foregroundColor(.white)
                        .font(.title3)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Safety Number Changed")
                            .font(.subheadline.bold())
                            .foregroundColor(.white)
                        Text(viewModel.keyChangeWasVerified
                             ? "This contact was verified but their identity key changed. Verify again."
                             : "This contact's identity key has changed. This may indicate a new device.")
                            .font(.caption)
                            .foregroundColor(LadonTheme.onSurface(0.9))
                    }
                    Spacer()
                    Button(action: { viewModel.showKeyChangeWarning = false }) {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundColor(LadonTheme.onSurface(0.7))
                    }
                }
                .padding(10)
                .background(viewModel.keyChangeWasVerified ? Color.red : Color.orange)
                .cornerRadius(0)
            }
            
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(spacing: 12) {
                        ForEach(viewModel.messages) { message in
                            VStack(alignment: .trailing, spacing: 4) {
                                MessageBubble(message: message, disappearingTimer: conversation.disappearingTimer)
                                    .springIn(active: viewModel.springInIDs.contains(message.id),
                                              outgoing: message.isOutgoing) {
                                        viewModel.springInIDs.remove(message.id)
                                    }
                                if message.isOutgoing && message.deliveryStatus == .failed {
                                    resendButton(for: message)
                                }
                            }
                            .id(message.id)
                        }

                        if viewModel.messages.isEmpty && !isDark {
                            VStack(spacing: 0) {
                                PairingBadge(systemImage: "bubble.left")
                                Text("No messages yet")
                                    .font(.manrope(19, .extrabold, relativeTo: .headline))
                                    .foregroundColor(LadonTheme.textPrimary)
                                    .padding(.top, 12)
                                Text("Send a message to start the conversation")
                                    .font(.manrope(14, relativeTo: .subheadline))
                                    .foregroundColor(LadonTheme.inkMuted)
                                    .multilineTextAlignment(.center)
                                    .padding(.top, 4)
                            }
                            .frame(maxWidth: .infinity)
                            .containerRelativeFrame(.vertical)
                        } else if viewModel.messages.isEmpty {
                            VStack(spacing: 16) {
                                Image(systemName: "bubble.left.and.bubble.right")
                                    .font(.system(size: 60))
                                    .foregroundColor(LadonTheme.textSecondary)
                                Text("No messages yet")
                                    .font(.headline)
                                    .foregroundColor(LadonTheme.textSecondary)
                                Text("Send a message to start the conversation")
                                    .font(.caption)
                                    .foregroundColor(LadonTheme.textSecondary)
                            }
                            .frame(maxWidth: .infinity, maxHeight: .infinity)
                            .padding()
                        }
                    }
                    .padding()
                }
                .onChange(of: viewModel.messages.count) { _, newCount in
                    guard newCount > lastMessageCount else {
                        lastMessageCount = newCount
                        return
                    }

                    if let lastMessage = viewModel.messages.last {
                        withAnimation {
                            proxy.scrollTo(lastMessage.id, anchor: .bottom)
                        }
                    }

                    lastMessageCount = newCount
                }
                .scrollDismissesKeyboard(.interactively)
                .scrollContentBackground(.hidden)
                .refreshable {
                    await viewModel.loadMessages()
                }
            }

            #if DEBUG
            // Persistent debug info bar — always visible in DEBUG builds
            let sessionID = viewModel.conversation.recipientID
            let relayTarget = viewModel.currentRelayRecipientID ?? viewModel.conversation.relayRecipientID ?? viewModel.conversation.recipientID
            Text("SID:\(sessionID.prefix(8)) → RID:\(relayTarget.prefix(8))")
                .font(.system(size: 9, design: .monospaced))
                .foregroundColor(.secondary)
                .padding(.horizontal)
            #endif

            // FIX TOR-RACE: Show Tor status banner while Tor is not yet connected.
            // Tor is mandatory (no enforcement toggle), so this always applies.
            if !torManager.isTorReady && !isDark {
                lightBanner(coral: false, alignment: .center) {
                    if torManager.isOffline {
                        Image(systemName: "wifi.slash")
                            .font(.system(size: 14, weight: .semibold))
                            .foregroundColor(LadonTheme.coralInk)
                        Text("No internet connection")
                            .font(.manrope(13.5, relativeTo: .footnote))
                            .foregroundColor(LadonTheme.textSecondary)
                    } else if torManager.controlLost {
                        Image(systemName: "arrow.clockwise")
                            .font(.system(size: 14, weight: .semibold))
                            .foregroundColor(LadonTheme.coralInk)
                        Text("Secure connection needs a restart — please close and reopen LADON messenger")
                            .font(.manrope(13.5, relativeTo: .footnote))
                            .foregroundColor(LadonTheme.textSecondary)
                    } else if torManager.isBootstrapping {
                        ProgressView()
                            .tint(LadonTheme.greenInk)
                            .scaleEffect(0.75)
                            .frame(width: 16, height: 16)
                        let pct = Int(torManager.progress * 100)
                        Text("Establishing secure connection… \(pct)%")
                            .font(.manrope(13.5, relativeTo: .footnote))
                            .foregroundColor(LadonTheme.textSecondary)
                    } else {
                        Image(systemName: "exclamationmark.triangle")
                            .font(.system(size: 14, weight: .semibold))
                            .foregroundColor(LadonTheme.coralInk)
                        Text("Secure connection inactive — messages are held back")
                            .font(.manrope(13.5, relativeTo: .footnote))
                            .foregroundColor(LadonTheme.textSecondary)
                    }
                    Spacer(minLength: 0)
                }
                .padding(.bottom, 8)
                .transition(.move(edge: .top).combined(with: .opacity))
                .animation(.easeInOut(duration: 0.3), value: torManager.isTorReady)
            } else if !torManager.isTorReady {
                HStack(spacing: 10) {
                    if torManager.isOffline {
                        Image(systemName: "wifi.slash")
                            .font(.system(size: 11))
                            .foregroundColor(.orange)
                        Text("No internet connection")
                            .font(.system(size: 11, weight: .medium))
                            .foregroundColor(.orange)
                    } else if torManager.controlLost {
                        Image(systemName: "arrow.clockwise")
                            .font(.system(size: 11))
                            .foregroundColor(.orange)
                        Text("Secure connection needs a restart — please close and reopen LADON messenger")
                            .font(.system(size: 11, weight: .medium))
                            .foregroundColor(.orange)
                    } else if torManager.isBootstrapping {
                        ProgressView()
                            .scaleEffect(0.65)
                            .tint(.orange)
                        let pct = Int(torManager.progress * 100)
                        Text("Establishing secure connection… \(pct)%")
                            .font(.system(size: 11, weight: .medium))
                            .foregroundColor(.orange)
                    } else {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .font(.system(size: 11))
                            .foregroundColor(.orange)
                        Text("Secure connection inactive — messages are held back")
                            .font(.system(size: 11, weight: .medium))
                            .foregroundColor(.orange)
                    }
                    Spacer()
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
                .background(Color.black.opacity(0.3))
                .overlay(
                    RoundedRectangle(cornerRadius: LadonTheme.cornerRadiusSmall)
                        .stroke(LadonTheme.cardBorder, lineWidth: 0.5)
                )
                .cornerRadius(LadonTheme.cornerRadiusSmall)
                .padding(.horizontal)
                .transition(.move(edge: .top).combined(with: .opacity))
                .animation(.easeInOut(duration: 0.3), value: torManager.isTorReady)
            }

            if let error = viewModel.errorMessage, !isDark {
                lightBanner(coral: true) {
                    Image(systemName: "exclamationmark.triangle")
                        .font(.system(size: 16, weight: .semibold))
                        .foregroundColor(LadonTheme.coralInk)
                        .padding(.top, 2)
                    // Tap copies the full message (see the dark branch below).
                    Text(error)
                        .font(.manrope(14, relativeTo: .footnote))
                        .foregroundColor(LadonTheme.textPrimary)
                        .lineLimit(2)
                        .truncationMode(.tail)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .contentShape(Rectangle())
                        .onTapGesture {
                            UIPasteboard.general.setItems(
                                [[UIPasteboard.typeAutomatic: error]],
                                options: [.localOnly: true, .expirationDate: Date().addingTimeInterval(10)]  // P8-AUDIT8-IOS-17: 10 s like every other copy
                            )
                        }
                    lightBannerClose { viewModel.clearError() }
                }
                .padding(.bottom, 8)
                .transition(.move(edge: .top).combined(with: .opacity))
            } else if let error = viewModel.errorMessage {
                HStack(alignment: .top) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundColor(.orange)
                    // Tap on the text → copy full message to clipboard so the
                    // user can paste it into a bug report. UI shows max ~2 lines;
                    // long V2 error chains (RelayClientV2Error.directory(...))
                    // are truncated visually but the FULL string is copied on tap.
                    Text(error)
                        .font(.caption2)
                        .foregroundColor(LadonTheme.textPrimary)
                        .lineLimit(2)
                        .truncationMode(.tail)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .contentShape(Rectangle())
                        .onTapGesture {
                            UIPasteboard.general.setItems(
                                [[UIPasteboard.typeAutomatic: error]],
                                options: [.localOnly: true, .expirationDate: Date().addingTimeInterval(10)]  // P8-AUDIT8-IOS-17: 10 s like every other copy
                            )
                        }
                    Spacer(minLength: 0)
                    Button(action: { viewModel.clearError() }) {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundColor(LadonTheme.textSecondary)
                    }
                }
                .padding(8)
                .background(Color.orange.opacity(0.15))
                .cornerRadius(8)
                .padding(.horizontal)
                .transition(.move(edge: .top).combined(with: .opacity))
            }

            // Inline upload-progress card (photo / video / voice / audio).
            // Slides up between the message list and the input bar while
            // a sealed attachment is being chunked + uploaded to the relay.
            if attachmentSending {
                AttachmentSendProgressCard(
                    phase: attachmentSendPhase,
                    progress: attachmentUploadProgress
                )
                .padding(.horizontal)
                .padding(.bottom, 6)
                .transition(.move(edge: .bottom).combined(with: .opacity))
            }

            FadingSeparator()
                .opacity(isDark ? 1 : 0)

            if isBlocked {
                // Blocked contact: nothing can be sent until unblocked.
                Button(action: unblockContact) {
                    Label("Unblock", systemImage: "hand.raised.slash")
                        .font(.subheadline.weight(.semibold))
                        .foregroundColor(LadonTheme.textPrimary)
                        .frame(maxWidth: .infinity)
                        .padding(10)
                        .background(RoundedRectangle(cornerRadius: LadonTheme.cornerRadiusMedium, style: .continuous).fill(LadonTheme.cardBackgroundSolid))
                }
                .buttonStyle(.plain)
                .padding(.horizontal)
            } else if canReply && viewModel.needsFreshCode {
                // One of the two shows a code, the other scans it — ask which.
                Button(action: { showCodeExchangeChoice = true }) {
                    Label("Exchange a fresh code", systemImage: "qrcode.viewfinder")
                        .font(.subheadline.weight(.semibold))
                        .foregroundColor(LadonTheme.textPrimary)
                        .frame(maxWidth: .infinity)
                        .padding(10)
                        .background(RoundedRectangle(cornerRadius: LadonTheme.cornerRadiusMedium, style: .continuous).fill(LadonTheme.cardBackgroundSolid))
                }
                .buttonStyle(.plain)
                .padding(.horizontal)
                .confirmationDialog("Exchange a fresh code", isPresented: $showCodeExchangeChoice, titleVisibility: .visible) {
                    Button("Show my code") { showMyCodeSheet = true }
                    Button("Scan their code") { showReplyScanner = true }
                    Button("Cancel", role: .cancel) {}
                } message: {
                    Text("One of you shows the code, the other scans it.")
                }
                .sheet(isPresented: $showMyCodeSheet) { ShowMyCodeSheet() }
            }

            HStack(spacing: isDark ? 12 : 8) {
                if canReply {
                    if FeatureFlags.attachmentsEnabled {
                        Button(action: {
                            if isBlocked {
                                viewModel.setError(LanguageManager.localized("You blocked this contact."))
                            } else {
                                showAttachmentDialog = true
                            }
                        }) {
                            if isDark {
                                Image(systemName: "plus.circle.fill")
                                    .font(.system(size: 28))
                                    .foregroundColor(attachmentSending ? LadonTheme.textSecondary : LadonTheme.accent)
                            } else {
                                Image(systemName: "plus")
                                    .font(.system(size: 17, weight: .medium))
                                    .foregroundColor(LadonTheme.textSecondary)
                                    .frame(width: 38, height: 38)
                                    .background(Circle().fill(LadonTheme.background))
                                    .opacity(attachmentSending ? 0.45 : 1)
                            }
                        }
                        .disabled(attachmentSending)
                        .accessibilityLabel("Attach media")
                    }
                    // UIKit placeholder: a plain String is not reached by the in-app locale.
                    QuickPathTextField(text: $messageText, placeholder: LanguageManager.localized("Message"), onCommit: sendMessage)
                        .frame(height: 36)
                        .padding(.horizontal, isDark ? 14 : 2)
                        .background(messageFieldBackground)

                    Button(action: sendMessage) {
                        ZStack {
                            Circle().fill(sendButtonFill)
                            Image(systemName: "arrow.up")
                                .font(.system(size: 16, weight: .bold))
                                .foregroundColor(isDark
                                                 ? (messageText.isEmpty ? LadonTheme.textSecondary : LadonTheme.background)
                                                 : LadonTheme.textPrimary)
                        }
                        .frame(width: isDark ? 36 : 40, height: isDark ? 36 : 40)
                        .shadow(color: isDark || messageText.isEmpty ? .clear : LadonTheme.brandGreen.opacity(0.45),
                                radius: 8, y: 6)
                    }
                    .disabled(messageText.isEmpty)
                    .sensoryFeedback(.impact(flexibility: .solid, intensity: 0.8), trigger: sendHapticTrigger)
                } else {
                    replyLockedView
                }
            }
            .padding(isDark || !canReply ? 0 : 6)
            .background(inputPillBackground)
            .padding()
            .id(inputBarID)
            .sheet(isPresented: $showReplyScanner, onDismiss: { handleReplyScanResult() }) {
                QRScannerView(scannedPublicKey: $replyScanKey)
            }
            .alert("Name this contact", isPresented: $showReplyNaming) {
                TextField("Contact name", text: $replyName)
                    .autocorrectionDisabled(true)  // P8-AUDIT8-IOS-17: contact names stay out of the keyboard dictionary
                Button("Save") { finishReplyAdd(name: replyName) }
                Button("Skip", role: .cancel) { finishReplyAdd(name: "") }
            } message: {
                Text("Add a name so you can recognise this contact.")
            }
            .alert("Couldn't add contact", isPresented: Binding(
                get: { replyScanError != nil },
                set: { if !$0 { replyScanError = nil } }
            )) {
                Button("OK", role: .cancel) { replyScanError = nil }
            } message: {
                Text(replyScanError ?? "")
            }
            .sheet(isPresented: $showAttachmentDialog) {
                AttachmentPickerSheet(
                    onPhoto: { showAttachmentDialog = false
                        DispatchQueue.main.asyncAfter(deadline: .now() + 0.25) { showPhotoPicker = true } },
                    onVideo: { showAttachmentDialog = false
                        DispatchQueue.main.asyncAfter(deadline: .now() + 0.25) { showVideoPicker = true } },
                    onVoice: { showAttachmentDialog = false
                        DispatchQueue.main.asyncAfter(deadline: .now() + 0.25) { showVoiceRecorder = true } },
                    onAudio: { showAttachmentDialog = false
                        DispatchQueue.main.asyncAfter(deadline: .now() + 0.25) { showFileImporter = true } },
                    onCancel: { showAttachmentDialog = false }
                )
            }
            .photosPicker(isPresented: $showPhotoPicker, selection: $photoPickerItem, matching: .images)
            .photosPicker(isPresented: $showVideoPicker, selection: $videoPickerItem, matching: .videos)
            .onChange(of: photoPickerItem) { _, newItem in
                guard let item = newItem else { return }
                Task { await loadAndSendPhotoItem(item); photoPickerItem = nil }
            }
            .onChange(of: videoPickerItem) { _, newItem in
                guard let item = newItem else { return }
                Task { await loadAndSendVideoItem(item); videoPickerItem = nil }
            }
            .sheet(isPresented: $showVoiceRecorder) {
                VoiceRecorderOverlay(
                    onFinish: { data in
                        showVoiceRecorder = false
                        Task { await sendAttachment(kind: .voice(data)) }
                    },
                    onCancel: { showVoiceRecorder = false }
                )
            }
            .fileImporter(
                isPresented: $showFileImporter,
                allowedContentTypes: [.audio, .mpeg4Audio, .mp3],
                allowsMultipleSelection: false
            ) { result in
                guard case .success(let urls) = result, let url = urls.first else { return }
                Task { await loadAndSendAudioURL(url) }
            }
            .alert(
                "Attachment error",
                isPresented: Binding(
                    get: { attachmentAlert != nil },
                    set: { if !$0 { attachmentAlert = nil } }
                ),
                presenting: attachmentAlert
            ) { _ in
                Button("OK", role: .cancel) { attachmentAlert = nil }
            } message: { text in
                Text(text)
            }
        }
    }
    
    /// Disappearing-timer menu and safety-number link of the chat header.
    @ViewBuilder private var trailingButtons: some View {
        // Light: iOS pads each of the two controls by 10 pt on both sides
        // (measured on the 17 Pro, iOS 27: circles 26 pt apart at spacing 6,
        // the right one 26 pt from the edge vs. 16 pt for the back button).
        // Spacing −14 brings the gap to 6 pt; the 10 pt offset lines the
        // right circle up with the back button's edge distance.
        HStack(spacing: isDark ? 12 : -14) {
            // FIX #5: Disappearing message timer picker
            Menu {
                ForEach(DisappearingTimer.allCases, id: \.self) { timer in
                    Button(action: {
                        updateDisappearingTimer(timer)
                    }) {
                        HStack {
                            Text(timer.displayName)
                            if conversation.disappearingTimer == timer {
                                Image(systemName: "checkmark")
                            }
                        }
                    }
                }
            } label: {
                if isDark {
                    HStack(spacing: 2) {
                        Image(systemName: conversation.disappearingTimer == .off ? "timer" : "timer.circle.fill")
                            .foregroundColor(conversation.disappearingTimer == .off ? .gray : .orange)
                        if conversation.disappearingTimer != .off {
                            Text(conversation.disappearingTimer.shortName)
                                .font(.caption2)
                                .foregroundColor(.orange)
                        }
                    }
                } else {
                    Group {
                        if conversation.disappearingTimer == .off {
                            Image(systemName: "timer")
                                .font(.system(size: 16, weight: .medium))
                                .foregroundColor(LadonTheme.textSecondary)
                        } else {
                            Text(conversation.disappearingTimer.shortName)
                                .font(.jbMono(11, .medium, relativeTo: .caption2))
                                .foregroundColor(LadonTheme.coralInk)
                        }
                    }
                    .modifier(HeaderCircle())
                }
            }
            
            NavigationLink(destination: SafetyNumbersView(conversation: conversation)) {
                if !isDark {
                    Image(systemName: "checkmark.shield")
                        .font(.system(size: 16, weight: .medium))
                        .foregroundColor(LadonTheme.greenInk)
                        .modifier(HeaderCircle())
                } else {
                Image("LadonLogo")
                    .resizable()
                    .renderingMode(.template)
                    .scaledToFit()
                    .frame(width: 22, height: 22)
                    .foregroundColor(LadonTheme.accent)
                    .scaleEffect(logoPulse ? 1.18 : 1.0)
                    .shadow(color: LadonTheme.accent.opacity(logoPulse ? 0.5 : 0), radius: logoPulse ? 8 : 0)
                    .animation(.easeInOut(duration: 1.5).repeatForever(autoreverses: true), value: logoPulse)
                    .onAppear { logoPulse = true }
                }
            }
        }
        .offset(x: isDark ? 0 : 10)
    }

    /// Dark: the glass capsule behind the text field (unchanged). Light: none —
    /// the whole row sits in one white pill (`inputPillBackground`).
    @ViewBuilder private var messageFieldBackground: some View {
        if isDark {
            Capsule().fill(.ultraThinMaterial)
                .overlay(Capsule().strokeBorder(LadonTheme.glassStroke, lineWidth: 1))
        } else {
            Color.clear
        }
    }

    private var sendButtonFill: AnyShapeStyle {
        if isDark {
            return messageText.isEmpty ? AnyShapeStyle(LadonTheme.cardBackground) : AnyShapeStyle(LadonTheme.greenGradient)
        }
        return AnyShapeStyle(LadonTheme.brandGreen.opacity(messageText.isEmpty ? 0.45 : 1))
    }

    /// Light (ladon.app): the input row as one white pill — ink-14% hairline,
    /// soft drop shadow and an 8 pt green-8% ring (the waitlist field of the site).
    @ViewBuilder private var inputPillBackground: some View {
        if !isDark && canReply {
            ZStack {
                Capsule().stroke(LadonTheme.brandGreen.opacity(0.08), lineWidth: 16)
                Capsule().fill(Color.white)
                    .shadow(color: LadonTheme.onSurface(0.04), radius: 2, y: 2)
                    .shadow(color: LadonTheme.onSurface(0.10), radius: 24, y: 16)
                Capsule().strokeBorder(LadonTheme.onSurface(0.14), lineWidth: 1)
            }
        }
    }

    // MARK: - Mutual-scan gate (received-only "unverified" contact)

    /// Shown in place of the input bar when we don't yet hold this peer's
    /// identity. Tapping opens the scanner so the user can scan the peer's QR
    /// back — restoring the two-way, out-of-band-verified pairing.
    @ViewBuilder private var replyLockedView: some View {
        if !isDark {
            // Light (ladon.app): white card with a green icon tile.
            Button(action: { showReplyScanner = true }) {
                HStack(spacing: 12) {
                    Image(systemName: "qrcode.viewfinder")
                        .font(.system(size: 20, weight: .medium))
                        .foregroundColor(LadonTheme.greenInk)
                        .frame(width: 44, height: 44)
                        .background(RoundedRectangle(cornerRadius: 14, style: .continuous)
                            .fill(LadonTheme.brandGreenSoft))
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Scan their code to reply")
                            .font(.manrope(15.5, .extrabold, relativeTo: .subheadline))
                            .foregroundColor(LadonTheme.textPrimary)
                        Text("You both confirm each other — scan their QR code to reply.")
                            .font(.manrope(13, relativeTo: .caption))
                            .foregroundColor(LadonTheme.textSecondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    Spacer(minLength: 0)
                }
                .padding(.vertical, 14)
                .padding(.horizontal, 16)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(LadonCardBackground())
            }
            .buttonStyle(.plain)
            .accessibilityLabel("Scan their code to reply")
        } else {
        Button(action: { showReplyScanner = true }) {
            HStack(spacing: 12) {
                Image(systemName: "qrcode.viewfinder")
                    .font(.system(size: 26, weight: .semibold))
                    .foregroundColor(LadonTheme.accent)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Scan their code to reply")
                        .font(.subheadline.weight(.semibold))
                        .foregroundColor(LadonTheme.textPrimary)
                    Text("You both confirm each other — scan their QR code to reply.")
                        .font(.caption)
                        .foregroundColor(LadonTheme.textSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 0)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(12)
            .background(
                RoundedRectangle(cornerRadius: LadonTheme.cornerRadiusMedium, style: .continuous)
                    .fill(LadonTheme.cardBackgroundSolid)
            )
        }
        .buttonStyle(.plain)
        .accessibilityLabel("Scan their code to reply")
        }
    }

    /// Under a failed outgoing message: send the same content again through
    /// the normal send path. The failed copy is removed first, so a second
    /// tap finds nothing and cannot send twice.
    private func resendButton(for message: Message) -> some View {
        Button {
            let content = message.contentString
            guard viewModel.discardFailedMessage(id: message.id) else { return }
            Task { await viewModel.sendMessage(content) }
        } label: {
            Label("Resend", systemImage: "arrow.clockwise")
                .font(isDark ? .caption.weight(.semibold) : .manrope(12.5, .bold, relativeTo: .caption))
                .foregroundColor(isDark ? .red : LadonTheme.coralInk)
                .padding(.vertical, 4)
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .padding(.trailing, 8)
    }

    /// Light (ladon.app) banner: coral tint for warnings, paper for status.
    private func lightBanner<Content: View>(coral: Bool, alignment: VerticalAlignment = .top,
                                            @ViewBuilder content: () -> Content) -> some View {
        HStack(alignment: alignment, spacing: 12) { content() }
            .padding(.vertical, 12)
            .padding(.horizontal, 14)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(RoundedRectangle(cornerRadius: 18, style: .continuous)
                .fill(coral ? LadonTheme.coral.opacity(0.14) : LadonTheme.paper2))
            .padding(.horizontal, 16)
    }

    private func lightBannerClose(_ action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Image(systemName: "xmark")
                .font(.system(size: 12, weight: .bold))
                .foregroundColor(LadonTheme.textSecondary)
                .frame(width: 28, height: 28)
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel("Close")
    }

    /// Called when the reply-scanner sheet dismisses. A non-empty key is
    /// validated + matched against THIS conversation's peer + stored via the
    /// shared add-path. On success we ask for a display name; on failure we
    /// surface the reason. Pure contact-layer — no crypto change.
    /// Unblock this chat's contact: off the list, our key goes to it (A1 §7).
    private func unblockContact() {
        guard let rid = ConversationListView.contactRid(conversation) else { return }
        do {
            try DeliveryRotationV2.unblock(rid)
            isBlocked = false
        } catch {
            SecureLogger.error("[ChatView] unblock failed: \(error)")
            viewModel.setError(LanguageManager.localized("Could not unblock this contact. Please try again."))
        }
    }

    private func handleReplyScanResult() {
        let k = replyScanKey.trimmingCharacters(in: .whitespacesAndNewlines)
        replyScanKey = ""
        guard !k.isEmpty else { return }
        // Known contact (fresh-code rescan) vs. received-only contact (first add).
        let wasKnown = canReply
        do {
            try V2ContactAdder.addPeer(fromScannedKey: k, expectedRecipientId: conversation.recipientID)
            // Build the session now (skipped inside if one exists already).
            PairingStartV2.send(toContactId: conversation.recipientID)
            if wasKnown {
                viewModel.needsFreshCode = false   // new code on file; the start message builds the session
            } else {
                replyName = ""
                showReplyNaming = true
            }
        } catch let e as V2ContactAddError {
            replyScanError = e.userMessage
        } catch {
            replyScanError = LanguageManager.localized("Could not add this contact. Please try again.")
        }
    }

    /// Finalise the reply-scan add: optionally rename, then unlock the input bar.
    private func finishReplyAdd(name: String) {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmed.isEmpty { renameContact(trimmed) }
        canReply = PeerStoreV2.exists(forContactId: conversation.recipientID)
        inputBarID = UUID()
    }

    private func sendMessage() {
        guard !messageText.isEmpty else { return }

        sendHapticTrigger.toggle()
        
        // Capture text and clear input field IMMEDIATELY (before async send)
        let textToSend = messageText
        // FIX UI-14: Secure wipe message text before clearing
        messageText = String(repeating: " ", count: messageText.count)
        messageText = ""
        
        Task {
            await viewModel.sendMessage(textToSend)
        }
    }

    // MARK: - Phase 8: Attachment send helpers

    private func loadAndSendPhotoItem(_ item: PhotosPickerItem) async {
        guard let data = try? await item.loadTransferable(type: Data.self) else {
            presentAttachmentError(LanguageManager.localized("Could not load photo from library"))
            return
        }
        await sendAttachment(kind: .image(data))
    }

    private func loadAndSendVideoItem(_ item: PhotosPickerItem) async {
        guard let data = try? await item.loadTransferable(type: Data.self) else {
            presentAttachmentError(LanguageManager.localized("Could not load video from library"))
            return
        }
        await sendAttachment(kind: .video(data))
    }

    private func loadAndSendAudioURL(_ url: URL) async {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        guard let data = try? Data(contentsOf: url) else {
            presentAttachmentError(LanguageManager.localized("Could not read audio file"))
            return
        }
        await sendAttachment(kind: .audio(data))
    }

    private func sendAttachment(kind: AttachmentSendService.Kind) async {
        guard FeatureFlags.attachmentsEnabled else {
            presentAttachmentError(LanguageManager.localized("Attachments are disabled"))
            return
        }
        let kindLabel: String = {
            switch kind {
            case .image: return "image"
            case .video: return "video"
            case .voice: return "voice"
            case .audio: return "audio"
            }
        }()
        await MainActor.run {
            withAnimation(.spring(response: 0.35, dampingFraction: 0.8)) {
                attachmentSending = true
            }
            attachmentUploadProgress = 0
            attachmentSendPhase = "Preparing \(kindLabel)…"
        }
        defer {
            Task { @MainActor in
                withAnimation(.easeInOut(duration: 0.25)) {
                    attachmentSending = false
                }
                attachmentUploadProgress = 0
                attachmentSendPhase = ""
            }
        }

        // Recipient X25519 public key resolution.
        //
        // Two paths, mirroring the messaging layer:
        //   • V2 contact (PeerStoreV2 has an entry) → fetch the V2 HKEM
        //     public key (X25519 || Kyber768) via RelayClientV2 and split
        //     out the X25519 / Kyber halves. No `KeyManager` session lookup.
        //   • No V2 entry → legacy/unreachable contact; attachment send is
        //     rejected (the V1 attachment path was retired with the V1 store).
        let payloadString: String
        if let peerV2 = try? PeerStoreV2.load(forContactId: conversation.recipientID),
           let v2Client = await V2SessionManager.shared.client {
            let hkemPk: Data
            do {
                hkemPk = try await v2Client.recipientHkemPublicKey(for: peerV2)
            } catch {
                SecureLogger.error("[ChatView] Attachment \(kindLabel): recipient HKEM key unresolved: \(describeAttachmentError(error))")
                presentAttachmentError(userFacingAttachmentError(error), detail: describeAttachmentError(error))
                return
            }
            guard hkemPk.count == LadonV2.hkemPkLen else {
                SecureLogger.error("[ChatView] Attachment \(kindLabel): recipient HKEM key length \(hkemPk.count) B, expected \(LadonV2.hkemPkLen)")
                presentAttachmentError(LanguageManager.localized("Attachment not sent. Please try again."))
                return
            }
            let xPubBytes = Data(hkemPk.prefix(LadonV2.x25519PkLen))
            let kyPubBytes = Data(hkemPk.suffix(from: LadonV2.x25519PkLen))
            let xPub: Curve25519.KeyAgreement.PublicKey
            do {
                xPub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: xPubBytes)
            } catch {
                SecureLogger.error("[ChatView] Attachment \(kindLabel): recipient X25519 key invalid: \(error)")
                presentAttachmentError(LanguageManager.localized("Attachment not sent. Please try again."))
                return
            }
            do {
                payloadString = try await AttachmentSendService.buildAttachmentMessageV2(
                    kind: kind,
                    caption: nil,
                    recipientX25519PublicKey: xPub,
                    recipientKyberPublicKey: kyPubBytes,
                    progress: { p in
                        Task { @MainActor in
                            if p > self.attachmentUploadProgress {
                                withAnimation(.easeInOut(duration: 0.25)) {
                                    self.attachmentUploadProgress = p
                                }
                            }
                            let pct = Int((p * 100).rounded())
                            self.attachmentSendPhase = "Uploading \(kindLabel) · \(pct)%"
                        }
                    }
                )
            } catch {
                let detail = describeAttachmentError(error)
                SecureLogger.error("[ChatView] Attachment \(kindLabel) (V2) failed: \(detail)")
                presentAttachmentError(userFacingAttachmentError(error), detail: describeAttachmentError(error))
                return
            }
        } else {
            // No usable V2 session. Mirror the text-send reject (FIX #7/M2) and
            // distinguish: a THROWN load error (transient keychain lock / corrupt
            // blob) → ask to retry rather than pushing the user to delete a valid
            // contact; a nil handle → genuine legacy V1 contact; a present handle
            // → the V2 client just wasn't ready yet. The V1 attachment path was
            // retired with the V1 session store.
            do {
                if try PeerStoreV2.load(forContactId: conversation.recipientID) != nil {
                    presentAttachmentError(LanguageManager.localized("Still preparing the secure session. Please try again in a moment."))
                } else {
                    presentAttachmentError(LanguageManager.localized("Not mutually verified yet — scan their QR code to message this contact."))
                }
            } catch {
                presentAttachmentError(LanguageManager.localized("Couldn't read this contact right now. Please try again."))
            }
            return
        }

        SecureLogger.debug("[ChatView] Attachment \(kindLabel) built, \(payloadString.utf8.count)B payload — sending")
        await viewModel.sendMessage(payloadString)
    }

    @MainActor
    private func presentAttachmentError(_ message: String, detail: String? = nil) {
        // Shown once, as the alert. Test builds add the technical detail on a
        // second line (as for text sends) and write it to the diagnostics log;
        // Release shows the plain message only.
        #if DEBUG
        if let detail {
            SecureLogger.torDiag("[ATTACH] failed: \(detail)")
            attachmentAlert = "\(message)\n\(detail)"
            return
        }
        #endif
        attachmentAlert = message
    }

    /// What the user reads when an attachment fails: the size message when
    /// it was too large (they can act on it), otherwise a plain "not sent".
    private func userFacingAttachmentError(_ error: Error) -> String {
        if let e = error as? VideoSanitizer.Error {
            switch e {
            case .inputTooLarge(let bytes), .outputTooLarge(let bytes):
                return attachmentTooLargeMessage(bytes)
            default: break
            }
        }
        if let e = error as? BucketPadding.Error, case .exceedsLargestBucket(let bytes) = e {
            return attachmentTooLargeMessage(bytes)
        }
        if let e = error as? ImageSanitizer.Error, case .inputTooLarge(let bytes) = e {
            return attachmentTooLargeMessage(bytes)
        }
        return LanguageManager.localized("Attachment not sent. Please try again.")
    }

    private func describeAttachmentError(_ error: Error) -> String {
        if let e = error as? AttachmentSendService.AttachmentSendError {
            switch e {
            case .featureDisabled: return "feature flag disabled"
            case .recipientKyberKeyMissing:
                return "Recipient has no Kyber public key in the active session. Rescan the QR code to rebuild the session."
            case .recipientX25519KeyMissing:
                return "Recipient X25519 key missing on conversation."
            case .prepareFailed(let why): return "prepare: \(why)"
            case .sealFailed(let why): return "seal: \(why)"
            case .uploadFailed(let why): return "upload: \(why)"
            case .payloadEncodeFailed: return "payload encode failed"
            case .payloadTooLarge(let bytes): return "payload too large (\(bytes) B, max 15000)"
            }
        }
        // Groessenfehler in Klartext uebersetzen. Ohne diese Faelle landete hier
        // die rohe Swift-Beschreibung ("outputTooLarge(bytes: 24117248)"), aus
        // der niemand ablesen kann, was zu tun waere.
        if let e = error as? VideoSanitizer.Error {
            switch e {
            case .inputTooLarge(let bytes), .outputTooLarge(let bytes):
                return attachmentTooLargeMessage(bytes)
            default: break
            }
        }
        if let e = error as? BucketPadding.Error, case .exceedsLargestBucket(let bytes) = e {
            return attachmentTooLargeMessage(bytes)
        }
        if let e = error as? ImageSanitizer.Error, case .inputTooLarge(let bytes) = e {
            return attachmentTooLargeMessage(bytes)
        }
        return String(describing: error)
    }

    /// Groessenangabe in Megabyte, gerundet auf eine Nachkommastelle.
    private func megabytes(_ bytes: Int) -> String {
        String(format: "%.1f MB", Double(bytes) / (1024 * 1024))
    }

    private func attachmentTooLargeMessage(_ bytes: Int) -> String {
        String(
            format: LanguageManager.localized("Too large to send: %@ after compression. The limit is %@."),
            megabytes(bytes),
            megabytes(AttachmentLimits.plaintextHardCapBytes)
        )
    }
    
    // FIX #5: Update disappearing timer and persist
    // FIX CV-TIMER1: Auch ViewModel-Kopie aktualisieren, damit Polling den neuen Timer nutzt.
    private func renameContact(_ newName: String) {
        let trimmed = newName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        // Same sanitization as new contact creation
        let bidiOverrides: Set<Unicode.Scalar> = [
            "\u{200E}", "\u{200F}",
            "\u{202A}", "\u{202B}", "\u{202C}", "\u{202D}", "\u{202E}",
            "\u{2066}", "\u{2067}", "\u{2068}", "\u{2069}"
        ]
        let sanitized = String(trimmed
            .unicodeScalars
            .filter { !$0.properties.isDefaultIgnorableCodePoint && $0.value >= 0x20 && !bidiOverrides.contains($0) }
            .prefix(64)
            .map { Character($0) })
        guard !sanitized.isEmpty else { return }
        conversation.contactName = sanitized
        viewModel.conversation.contactName = sanitized
        do {
            try EncryptedDatabase.shared.storeConversation(conversation)
            // Notify ConversationListView to update its in-memory copy
            NotificationCenter.default.post(
                name: .contactRenamed,
                object: nil,
                userInfo: ["conversationID": conversation.id, "newName": sanitized]
            )
        } catch {
            #if DEBUG
            SecureLogger.debug("[ChatView] ❌ Failed to persist renamed contact: \(error)")
            #endif
        }
    }
    
    private func updateDisappearingTimer(_ timer: DisappearingTimer) {
        conversation.disappearingTimer = timer
        viewModel.conversation.disappearingTimer = timer
        do {
            try EncryptedDatabase.shared.storeConversation(conversation)
        } catch {
            #if DEBUG
            SecureLogger.debug("[ChatView] ❌ Failed to persist disappearing timer: \(error)")
            #endif
        }
    }
    
    
}

/// Light (ladon.app): the frosted header pill of the design, drawn BEHIND the
/// system navigation bar. The bar itself stays (transparent), so the system
/// back button and its swipe-back gesture keep working — only this capsule
/// sits beneath the bar's items. The bar height is measured, not assumed:
/// this screen's top inset minus the window's status-bar inset. The bar's
/// items do not sit in its middle: measured on iOS 27 (17 Pro) the bar is
/// 54 pt and back button, title and trailing items fill its TOP 44 pt — so
/// the pill is centred on that 44 pt row, 6 pt larger on every side.
struct ChatHeaderPillBackdrop: View {
    var body: some View {
        GeometryReader { geo in
            let statusInset = UIApplication.shared.connectedScenes
                .compactMap { ($0 as? UIWindowScene)?.keyWindow }
                .first?.safeAreaInsets.top ?? 0
            let bar = max(0, geo.safeAreaInsets.top - statusInset)
            let row = min(bar, 44)
            let height = row + 12
            Capsule()
                .fill(.ultraThinMaterial)
                .overlay(Capsule().fill(Color.white.opacity(0.55)))
                .overlay(Capsule().strokeBorder(Color.white.opacity(0.7), lineWidth: 1))
                .shadow(color: LadonTheme.onSurface(0.12), radius: 15, y: 8)
                .frame(width: max(0, geo.size.width - 20), height: height)
                .position(x: geo.size.width / 2, y: -bar + row / 2)
                .opacity(bar > 0 ? 1 : 0)
        }
        .allowsHitTesting(false)
        .accessibilityHidden(true)
    }
}

/// Light (ladon.app): header button circle — white 60 %, ink-14 % hairline.
/// 44 pt, the size of the system back button beside it (the design's 38 pt
/// would make the two trailing circles visibly smaller than the back button).
struct HeaderCircle: ViewModifier {
    func body(content: Content) -> some View {
        content
            .frame(width: 44, height: 44)
            .background(Circle().fill(Color.white.opacity(0.6)))
            .overlay(Circle().strokeBorder(LadonTheme.onSurface(0.14), lineWidth: 1))
            .contentShape(Circle())
    }
}

struct MessageBubble: View {
    // Creates the dependency that makes this view repaint when the
    // appearance changes. LadonTheme's colours are static reads, so
    // without it SwiftUI sees no reason to call body again and the view
    // keeps the previous mode's colours. Unused on purpose.
    @Environment(\.colorScheme) private var ladonAppearanceTick
    let message: Message
    let disappearingTimer: DisappearingTimer  // FIX #5: Configurable timer
    @State private var timeRemaining: Int = 0
    @State private var displayTimer: Timer?
    @State private var isDisplaying: Bool = true
    @State private var expiryDate: Date

    private var isDark: Bool { AppearanceManager.isDarkStored }

    init(message: Message, disappearingTimer: DisappearingTimer = .fiveMinutes) {
        self.message = message
        self.disappearingTimer = disappearingTimer
        let interval = TimeInterval(disappearingTimer.rawValue)
        // FIX: Base expiryDate on message.timestamp (not Date()) so returning to chat
        // shows messages with correct remaining time instead of resetting the timer.
        let baseTime = message.timestamp
        let expiry = baseTime.addingTimeInterval(interval > 0 ? interval : 30)
        _expiryDate = State(initialValue: expiry)
        // FIX: If message is already expired at init time, set isDisplaying=false immediately
        // to prevent a 1-frame flash of expired messages when re-entering the chat.
        _isDisplaying = State(initialValue: disappearingTimer == .off || expiry > Date())
    }
    
    var body: some View {
        if !isDisplaying {
            EmptyView()
        } else {
            HStack {
                if message.isOutgoing {
                    Spacer()
                }
                
                VStack(alignment: message.isOutgoing ? .trailing : .leading, spacing: 4) {
                    HStack(alignment: .top, spacing: 8) {
                        if FeatureFlags.attachmentsEnabled,
                           AttachmentMessagePayload.isAttachmentContent(message.contentString) {
                            AttachmentBubbleView(message: message, isOutgoing: message.isOutgoing)
                                .padding(message.isOutgoing ? .trailing : .leading, 8)
                                .accessibilityLabel("Attachment")
                                .accessibilityHint(message.isOutgoing ? "Sent" : "Received")
                        } else {
                            Text(message.contentString)
                            .font(isDark ? nil : .manrope(15.5, message.isOutgoing ? .medium : .regular, relativeTo: .body))
                            .padding(.vertical, isDark ? 12 : 11)
                            .padding(.horizontal, isDark ? 12 : 15)
                            .foregroundColor(message.isOutgoing
                                             ? (isDark ? LadonTheme.bubbleOutgoingText : LadonTheme.textPrimary)
                                             : LadonTheme.bubbleIncomingText)
                            .background(textBubbleBackground)
                            .frame(maxWidth: isDark ? nil : 272, alignment: message.isOutgoing ? .trailing : .leading)
                            .padding(message.isOutgoing ? .trailing : .leading, isDark ? 8 : 0)
                            .textSelection(.disabled) // FIX MED-183: Prevent copy via text selection
                            // FIX MED: Prevent VoiceOver from reading message content aloud
                            // Nearby eavesdroppers could hear message content through accessibility
                            // FIX M-26 AUDIT-MAR-2026: Neutral label — "Encrypted message" reveals messenger type
                            .accessibilityLabel("Message")
                            .accessibilityHint(message.isOutgoing ? "Sent" : "Received")
                        }
                        
                        // FIX #5: Only show timer when disappearing is enabled
                        if disappearingTimer != .off && !message.isOutgoing {
                            Text(formatTimeRemaining(timeRemaining))
                                .font(.caption)
                                .fontWeight(.bold)
                                .foregroundColor(.red)
                                .padding(6)
                                .background(LadonTheme.background.opacity(0.85))
                                .cornerRadius(8)
                        }
                    }
                    
                    HStack(spacing: 4) {
                        // FIX UI-11: No seconds precision — prevents timing correlation attacks
                        Text(message.timestamp, format: .dateTime.hour().minute())
                            .font(isDark ? .caption2 : .jbMono(10.5, relativeTo: .caption2))
                            .foregroundColor(LadonTheme.inkMuted)
                        
                        if disappearingTimer != .off {
                            Image(systemName: "timer")
                                .font(.caption2)
                                .foregroundColor(LadonTheme.inkMuted)
                        }
                        
                        if message.isOutgoing {
                            // Delivery status checkmarks
                        if message.deliveryStatus == .delivered {
                            // Double checkmark = delivered to recipient
                            HStack(spacing: -4) {
                                Image(systemName: "checkmark")
                                Image(systemName: "checkmark")
                            }
                            .font(.caption2)
                            .foregroundColor(LadonTheme.greenInk)
                        } else if message.deliveryStatus == .failed {
                            // FIX AUDIT-21APR-HIGH2: Show error indicator for failed sends.
                            Image(systemName: "exclamationmark.circle")
                                .font(.caption2)
                                .foregroundColor(.red)
                        } else {
                            // Single checkmark = sent to relay (or .sending / .sent)
                            Image(systemName: "checkmark")
                                .font(.caption2)
                                .foregroundColor(LadonTheme.inkMuted)
                        }
                        }
                    }
                    .padding(.horizontal, isDark ? 0 : 6)
                }
                
                if !message.isOutgoing {
                    Spacer()
                }
            }
            .onAppear {
                startCountdown()
            }
            .onDisappear {
                displayTimer?.invalidate()
            }
        }
    }
    
    /// Dark: the tailed glass bubble (unchanged). Light (ladon.app): 18 pt
    /// corners with a 4 pt corner on the sender's side — paper-2 incoming,
    /// brand green with a soft green shadow outgoing.
    @ViewBuilder private var textBubbleBackground: some View {
        if isDark {
            BubbleTailShape(isOutgoing: message.isOutgoing)
                .fill(message.isOutgoing ? AnyShapeStyle(LadonTheme.greenGradient) : AnyShapeStyle(.ultraThinMaterial))
                .overlay(
                    BubbleTailShape(isOutgoing: message.isOutgoing)
                        .stroke(Color.white.opacity(message.isOutgoing ? 0.28 : 0.12), lineWidth: 1)
                )
        } else {
            UnevenRoundedRectangle(topLeadingRadius: 18,
                                   bottomLeadingRadius: message.isOutgoing ? 18 : 4,
                                   bottomTrailingRadius: message.isOutgoing ? 4 : 18,
                                   topTrailingRadius: 18,
                                   style: .continuous)
                .fill(message.isOutgoing ? LadonTheme.brandGreen : LadonTheme.paper2)
                .shadow(color: message.isOutgoing ? LadonTheme.brandGreen.opacity(0.35) : .clear, radius: 12, y: 8)
        }
    }

    private func startCountdown() {
        let messageID = message.id
        let interval = TimeInterval(disappearingTimer.rawValue)
        
        // FIX #5: If disappearing is off, don't start countdown
        guard disappearingTimer != .off else {
            timeRemaining = 0
            return
        }
        
        // H2 FIX: Base expiry on message.timestamp (receive time), NOT on view-appear time.
        // This prevents bypassing the timer by keeping the chat closed.
        // FIX SM-M8: Guard against clock-manipulation attacks where the sender sets
        // a timestamp far in the FUTURE so the message never expires.
        // FIX (countdown-reset bug 2026): Only clamp FUTURE-skewed timestamps.
        // Earlier code used `abs(...)` which also clamped legitimately aging
        // messages: as soon as a message was older than 60 s and the bubble's
        // `.onAppear` fired again (scroll / messages-array update / re-render),
        // `expiryDate` was reset to `now + interval` → countdown restarted from
        // the top. With a 30 s timer this was never observable because the
        // message expired before reaching the 60 s threshold; with 5 min it
        // looped forever.
        // Past timestamps are not an attack vector — they only cause the
        // message to expire earlier, which is the desired behaviour for
        // disappearing messages opened long after receipt.
        let now = Date()
        let maxClockDrift: TimeInterval = 60 // 1 minute future skew tolerated
        let clampedTimestamp: Date
        if message.timestamp.timeIntervalSince(now) > maxClockDrift {
            // Sender timestamp >60 s in the future → clamp to now (anti-attack)
            clampedTimestamp = now
        } else {
            clampedTimestamp = message.timestamp
        }
        expiryDate = clampedTimestamp.addingTimeInterval(interval)
        let remaining = Int(expiryDate.timeIntervalSinceNow)
        
        // If already expired, delete immediately
        guard remaining > 0 else {
            isDisplaying = false
            NotificationCenter.default.post(
                name: NSNotification.Name("DeleteMessage"),
                object: nil,
                userInfo: ["messageID": messageID, "authToken": ChatViewModel.deleteAuthToken]
            )
            return
        }
        
        timeRemaining = remaining
        displayTimer?.invalidate()
        // Capture main-actor-isolated static before entering the Sendable Timer closure.
        let authToken = ChatViewModel.deleteAuthToken
        displayTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { _ in
            let remaining = Int(self.expiryDate.timeIntervalSinceNow)
            if remaining > 0 {
                self.timeRemaining = remaining
            } else {
                self.displayTimer?.invalidate()
                self.displayTimer = nil

                withAnimation {
                    self.isDisplaying = false
                }

                // C9 FIX: Post delete notification — the ViewModel wipes the original content.
                // Do NOT wipe a local copy (Swift value-type semantics mean it only wipes the copy).
                NotificationCenter.default.post(
                    name: NSNotification.Name("DeleteMessage"),
                    object: nil,
                    userInfo: ["messageID": messageID, "authToken": authToken]
                )
            }
        }
    }
    
    /// FIX #5: Format remaining time for display (30s, 4m30s, 1h23m, 6d12h)
    private func formatTimeRemaining(_ seconds: Int) -> String {
        if seconds < 60 {
            return "\(seconds)s"
        } else if seconds < 3600 {
            let m = seconds / 60
            let s = seconds % 60
            return s > 0 ? "\(m)m\(s)s" : "\(m)m"
        } else if seconds < 86400 {
            let h = seconds / 3600
            let m = (seconds % 3600) / 60
            return m > 0 ? "\(h)h\(m)m" : "\(h)h"
        } else {
            let d = seconds / 86400
            let h = (seconds % 86400) / 3600
            return h > 0 ? "\(d)d\(h)h" : "\(d)d"
        }
    }
}

// String.securelyWipe() is defined in MemoryProtector.swift

@MainActor
class ChatViewModel: ObservableObject {
    @Published var messages: [Message] = []
    /// Ids of messages that arrived or were sent while this chat is open —
    /// only these spring in (the maintainer's choice "Federn", 02.10.2026); the
    /// history loaded on open stays still. An id is removed once its bubble
    /// has appeared.
    @Published var springInIDs = Set<String>()
    @Published var errorMessage: String?
    /// Set when a send failed for lack of a session and an unused code of this
    /// contact: the chat then offers scanning a fresh code right there (no
    /// second chat via +).
    @Published var needsFreshCode = false
    /// True when `errorMessage` was set with `sticky: true` and must not be
    /// silently overwritten by routine polling status updates.
    @Published var errorIsSticky: Bool = false
    @Published var showKeyChangeWarning = false
    @Published var keyChangeWasVerified = false

    var conversation: Conversation
    private var deleteObserver: NSObjectProtocol?
    private var pushObserver: NSObjectProtocol?
    private var keyChangeObserver: NSObjectProtocol?
    private var receiptObserver: NSObjectProtocol?
    private var emergencyWipeObserver: NSObjectProtocol?
    private(set) var currentRelayRecipientID: String?

    // FIX ORD-2: Reentrance guard prevents concurrent syncFromMessageStore() calls
    // from push observer + poll cycle racing and producing inconsistent message arrays.
    private var isSyncing = false

    // FIX ORD-3 (2026-05-05): Serialize outgoing sends per conversation.
    // Each tap creates `Task { await viewModel.sendMessage(...) }`. Without
    // serialization those tasks run concurrently on the MainActor: one suspends
    // at `await client.sendMessage(...)`, the next jumps in and starts its own
    // network send, and both races finish in non-deterministic order — the
    // recipient observed messages 1, 3, 2. Chaining each send onto the previous
    // task forces strict FIFO over the network.
    private var lastSendTask: Task<Void, Never>?

    // FIX CV-04 (ADVERSARIAL): Per-launch random token prevents Frida/Cycript
    // from injecting DeleteMessage notifications without knowing the secret.
    // FIX VW-12: nonisolated(unsafe) removed — static let with closure initializer
    // is thread-safe by definition (dispatch_once semantics in Swift)
    // FIX LO-02: Token is regenerated on every app launch via SecRandomCopyBytes (CSPRNG).
    // While theoretically extractable via Frida on jailbroken devices, the per-launch
    // regeneration ensures a new 128-bit random value is used for each session,
    // preventing attackers from crafting valid delete notifications across app restarts.
    // Storage in static memory is a deliberate trade-off: Keychain operations are too
    // slow for per-notification authentication, while per-launch regeneration provides
    // sufficient entropy for the threat model (opportunistic Frida injection is unlikely
    // to target rapidly-regenerated tokens without app source code access).
    static let deleteAuthToken: String = {
        var bytes = [UInt8](repeating: 0, count: 16)
        // FIX AUDIT3-IOS-01: CSPRNG failure is catastrophic — fatalError instead of
        // arc4random_uniform fallback (which uses the same kernel entropy and would
        // most likely fail too). Same fail-closed CSPRNG handling as
        // TorController.swift.
        let status = SecRandomCopyBytes(kSecRandomDefault, 16, &bytes)
        guard status == errSecSuccess else {
            SecureLogger.error("SecRandomCopyBytes failed with status \(status)")
            fatalError("CSPRNG failure — cannot generate secure delete auth token (status=\(status))")
        }
        return bytes.map { String(format: "%02x", $0) }.joined()
    }()

    init(conversation: Conversation) {
        self.conversation = conversation
        self.currentRelayRecipientID = conversation.relayRecipientID

        // FIX #3: Listen for identity key changes
        // Capture conversation values up-front so the Sendable observer closure
        // doesn't need to reach back into main-actor-isolated `self.conversation`.
        let capturedConvoIDs = Set([conversation.recipientID, conversation.id, conversation.relayRecipientID].compactMap { $0 })
        keyChangeObserver = NotificationCenter.default.addObserver(
            forName: .identityKeyChanged,
            object: nil,
            queue: .main
        ) { [weak self] notification in
            guard let contactID = notification.userInfo?["contactID"] as? String else { return }
            let wasVerified = notification.userInfo?["wasVerified"] as? Bool ?? false
            // Check if this key change is for our conversation
            guard capturedConvoIDs.contains(contactID) else { return }
            Task { @MainActor in
                guard let self = self else { return }
                self.keyChangeWasVerified = wasVerified
                self.showKeyChangeWarning = true
            }
        }

        // ... rest of init ...
        setupObservers()

    }

    private func setupObservers() {
        // All four observers are registered with `queue: .main`, so they
        // already run on the main thread. `MainActor.assumeIsolated` asserts
        // that at runtime while letting the closure body access main-actor-
        // isolated state without the strict-concurrency Sendable-closure
        // warnings.
        deleteObserver = NotificationCenter.default.addObserver(
            forName: NSNotification.Name("DeleteMessage"),
            object: nil,
            queue: .main
        ) { [weak self] notification in
            MainActor.assumeIsolated {
                guard let self = self,
                      let messageID = notification.userInfo?["messageID"] as? String,
                      // FIX CV-04: Validate per-launch auth token to prevent Frida injection
                      let token = notification.userInfo?["authToken"] as? String,
                      token == ChatViewModel.deleteAuthToken else { return }

                if let index = self.messages.firstIndex(where: { $0.id == messageID }) {
                    // FIX R21-A5-1: Wipe original in-place, not a struct copy.
                    // `var message = self.messages[index]` created a copy — securelyWipe()
                    // would only zero the copy while the original remained in heap.
                    self.messages[index].content.securelyWipe()
                    self.messages.remove(at: index)

                    // FIX: Also remove from InMemoryMessageStore so the message
                    // doesn't reappear when navigating back into the chat.
                    Task { @MainActor in
                        InMemoryMessageStore.shared.removeMessage(id: messageID)
                    }

                    #if DEBUG
                    print("[ChatView] 🔥 Message auto-deleted: \(messageID)")
                    #endif
                }
            }
        }

        // Listen for push-fetched messages
        // FIX ORD-1: Instead of inserting messages directly (which caused race conditions
        // with syncFromMessageStore running in parallel → duplicate sorts, wrong order after
        // background return), delegate to syncFromMessageStore as the SINGLE entry point.
        pushObserver = NotificationCenter.default.addObserver(
            forName: NSNotification.Name("NewMessagesReceived"),
            object: nil,
            queue: .main
        ) { [weak self] notification in
            MainActor.assumeIsolated {
                guard let self = self,
                      let newMessages = notification.userInfo?["messages"] as? [Message] else { return }

                // Check if any message belongs to this conversation before triggering sync
                let convoIDs = Set([self.conversation.recipientID, self.conversation.id, self.conversation.relayRecipientID].compactMap { $0 })
                let hasRelevant = newMessages.contains { message in
                    let candidateIDs = Set([message.conversationID, message.senderStableID, message.senderCurrentID].compactMap { $0 })
                    return !candidateIDs.isDisjoint(with: convoIDs)
                }

                if hasRelevant {
                    // #1: markAsRead-on-arrival. The removed ChatView poll loop
                    // used to reset the unread counter for messages that arrived
                    // WHILE the chat stayed open (onAppear only covers opening).
                    // The single V2 receive loop now delivers via this
                    // notification, so the reset must happen here.
                    InMemoryMessageStore.shared.markAsRead(forAnyOf: convoIDs)
                    Task { [weak self] in
                        await self?.syncFromMessageStore()
                    }
                }
            }
        }

        // FIX CV-OB1: Store observer token so it can be removed in deinit.
        // Previously the return value was discarded → observer never removed → memory leak.
        emergencyWipeObserver = NotificationCenter.default.addObserver(
            forName: .emergencyMemoryWipe,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self = self else { return }

                // FIX VM-3: Securely zero message content before removal
                for i in 0..<self.messages.count {
                    self.messages[i].content.securelyWipe()
                }
                self.messages.removeAll()

                #if DEBUG
                print("[ChatView] 🔥🔥🔥 Emergency memory wipe: all messages deleted")
                #endif
            }
        }
        // Listen for delivery receipts
        receiptObserver = NotificationCenter.default.addObserver(
            forName: .messageDelivered,
            object: nil,
            queue: .main
        ) { [weak self] notification in
            MainActor.assumeIsolated {
                guard let self = self,
                      let messageID = notification.userInfo?["messageID"] as? String else { return }
                if let idx = self.messages.firstIndex(where: { $0.id == messageID && $0.isOutgoing }) {
                    self.messages[idx].deliveryStatus = .delivered
                    #if DEBUG
                    // FIX M-23: Delivery banner with internal messageID was shown in Release builds.
                    // setError() displays visible UI text — must not leak internal IDs to users.
                    self.setError("✅✅ DELIVERED: \(messageID.prefix(8))")
                    print("[ChatView] ✅✅ Message \(messageID.prefix(8)) marked as DELIVERED")
                    #endif
                } else {
                    #if DEBUG
                    print("[ChatView] ⚠️ Receipt for unknown/non-outgoing msg: \(messageID.prefix(8))")
                    self.setError("⚠️ Receipt no match: \(messageID.prefix(8))")
                    #endif
                }
            }
        }
    }
    
    deinit {
        // P7-IOS-BUG-14: cancel the FIFO send chain too. Without this,
        // the tail of the chain keeps running after the view-model is
        // gone (each .send() awaited `previous?.value`, so cancellation
        // only propagates if the head is cancelled). The
        // `if Task.isCancelled` guard inside the chain then short-
        // circuits subsequent links.
        lastSendTask?.cancel()
        if let observer = deleteObserver {
            NotificationCenter.default.removeObserver(observer)
        }
        if let observer = pushObserver {
            NotificationCenter.default.removeObserver(observer)
        }
        if let observer = keyChangeObserver {
            NotificationCenter.default.removeObserver(observer)
        }
        if let observer = receiptObserver {
            NotificationCenter.default.removeObserver(observer)
        }
        // FIX CV-OB1: Use token-based removal (matches block-based addObserver).
        // Previously used removeObserver(self, ...) which is the selector-based API — no-op.
        if let observer = emergencyWipeObserver {
            NotificationCenter.default.removeObserver(observer)
        }
    }
    
    func loadMessages() async {
        // Load any messages already decrypted by ConversationListView from RAM store
        let candidateIDs = Set([conversation.recipientID, conversation.id, conversation.relayRecipientID].compactMap { $0 })
        let stored = InMemoryMessageStore.shared.messages(forAnyOf: candidateIDs)
        
        // FIX: Filter out already-expired disappearing messages to prevent flash on re-entry
        // and proactively clean them from the InMemoryMessageStore
        let timer = conversation.disappearingTimer
        if timer != .off {
            let interval = TimeInterval(timer.rawValue)
            let now = Date()
            var validMessages: [Message] = []
            for msg in stored {
                if msg.timestamp.addingTimeInterval(interval) > now {
                    validMessages.append(msg)
                } else {
                    // Remove expired message from store
                    InMemoryMessageStore.shared.removeMessage(id: msg.id)
                    #if DEBUG
                    SecureLogger.debug("[ChatView] 🔥 Removed expired message at load: \(msg.id)")
                    #endif
                }
            }
            // FIX ORD-2: Wrap messages assignment in MainActor.run for thread safety.
            // ChatViewModel is not @MainActor — direct assignment from async context is a data race.
            await MainActor.run { messages = validMessages }
        } else {
            await MainActor.run { messages = stored }
        }
        
        #if DEBUG
        SecureLogger.debug("[ChatView] 📦 Loaded \(messages.count) messages from InMemoryMessageStore")
        #endif
        // #1: no startPolling() — incoming messages arrive via the single V2
        // receive loop + the NewMessagesReceived observer. loadMessages just
        // hydrates the view from the store on open.
    }

    func clearError() {
        withAnimation {
            errorMessage = nil
            errorIsSticky = false
        }
    }

    /// Removes a failed outgoing message before it is sent again (wiped in
    /// the store like any other removal). Returns false when it is no longer
    /// there or no longer failed — the caller then does not resend.
    @discardableResult
    func discardFailedMessage(id: String) -> Bool {
        guard let idx = messages.firstIndex(where: { $0.id == id && $0.isOutgoing && $0.deliveryStatus == .failed }) else {
            return false
        }
        messages.remove(at: idx)
        InMemoryMessageStore.shared.removeMessage(id: id)
        clearError()
        return true
    }
    
    /// Sticky errors survive polling-cycle status updates. Use for any
    /// failure the user must read in full (V2 send errors, attachment
    /// failures). Cleared only by `clearError()` or another sticky setError.
    func setError(_ message: String, sticky: Bool = false) {
        // Non-sticky updates (polling status "📥 N msg received", etc.)
        // must not overwrite a sticky error — the user has not read it yet.
        if errorIsSticky && !sticky { return }
        withAnimation {
            errorMessage = message
            errorIsSticky = sticky
        }
    }
    
    private func syncFromMessageStore() async {
        // FIX ORD-2: Check and set guard on MainActor to prevent TOCTOU race
        let shouldProceed = await MainActor.run {
            guard !isSyncing else { return false }
            isSyncing = true
            return true
        }
        guard shouldProceed else { return }
        defer { Task { @MainActor in isSyncing = false } }

        let candidateIDs = Set([conversation.recipientID, conversation.id, conversation.relayRecipientID].compactMap { $0 })
        let storedMessages = InMemoryMessageStore.shared.messages(forAnyOf: candidateIDs)
        
        // FIX: Update currentRelayRecipientID from stored messages too.
        // When the constant-rate loop processes messages (before ChatView gets them),
        // messages are stored in InMemoryMessageStore but currentRelayRecipientID
        // isn't updated. Sync it from the most recent incoming message.
        for storedMsg in storedMessages where !storedMsg.isOutgoing {
            if let senderCurrentID = storedMsg.senderCurrentID {
                currentRelayRecipientID = senderCurrentID
            }
        }
        
        // FIX: Filter out expired disappearing messages during polling sync
        let syncTimer = conversation.disappearingTimer
        let syncInterval = TimeInterval(syncTimer.rawValue)
        let syncNow = Date()
        
        var addedCount = 0
        var addedIncomingCount = 0
        var expiredCount = 0
        
        await MainActor.run {
            for storedMsg in storedMessages {
                // Skip expired disappearing messages and remove from store
                if syncTimer != .off && storedMsg.timestamp.addingTimeInterval(syncInterval) <= syncNow {
                    let age = Int(syncNow.timeIntervalSince(storedMsg.timestamp))
                    #if DEBUG
                    print("[ChatView] 🗑️ Expired: age=\(age)s timer=\(Int(syncInterval))s id=\(storedMsg.id.prefix(8))")
                    #endif
                    InMemoryMessageStore.shared.removeMessage(id: storedMsg.id)
                    expiredCount += 1
                    continue
                }
                
                // FIX iOS-F10: De-dup by message ID statt content+timestamp
                if let existingIdx = messages.firstIndex(where: { $0.id == storedMsg.id }) {
                    // FIX RECEIPT-SYNC + FIX AUDIT-21APR-HIGH2: Sync ALL delivery status
                    // transitions from store to local array (not only .delivered).
                    // Without .failed sync, a message marked failed by the retry loop
                    // would still show as .sending in UI after a store reload.
                    if let storeStatus = storedMsg.deliveryStatus,
                       storeStatus != messages[existingIdx].deliveryStatus {
                        messages[existingIdx].deliveryStatus = storeStatus
                        #if DEBUG
                        print("[ChatView] ✅ Synced \(storeStatus) status from store: \(storedMsg.id.prefix(8))")
                        #endif
                    }
                } else {
                    messages.append(storedMsg)
                    springInIDs.insert(storedMsg.id)
                    addedCount += 1
                    if !storedMsg.isOutgoing {
                        addedIncomingCount += 1
                    }
                }
            }
            if addedCount > 0 {
                // FIX ORD-2: Deterministic sort with tie-breaker by message ID
                // Prevents unstable ordering for same-timestamp messages across syncs.
                messages.sort {
                    if $0.timestamp != $1.timestamp { return $0.timestamp < $1.timestamp }
                    return $0.id < $1.id
                }
                // FIX PUSH-14: Restore haptic for REAL incoming messages only.
                // PUSH-11 removed ALL haptic, but the user needs tactile feedback
                // when messages arrive while actively viewing the chat.
                // Safe: only fires for non-outgoing messages that just appeared.
                // Cover traffic can't be decrypted, receipts are filtered in processEnvelopes.
                if addedIncomingCount > 0 {
                    // FIX PUSH-14b: Use real vibration (like notification) instead of
                    // subtle haptic tap. kSystemSoundID_Vibrate = 4095.
                    AudioServicesPlaySystemSound(kSystemSoundID_Vibrate)
                }
            }
            
            // Also remove any messages from the view that have since expired
            if syncTimer != .off {
                messages.removeAll { msg in
                    msg.timestamp.addingTimeInterval(syncInterval) <= syncNow
                }
            }
            
            // FIX UI-C01: Receipt counters are diagnostic data — DEBUG only
            #if DEBUG
            // DIAGNOSTIC: Always show receipt counters
            let totalNow = messages.count
            let storeCount = storedMessages.count
            setError("📊 s=\(storeCount) n=\(totalNow)")
            #endif
        }
    }
    
    func sendMessage(_ content: String) async {
        // FIX R19-V10: Client-side message length limit. The real ceiling is what
        // one 16 KB envelope can carry after all headers and signatures
        // (V2RatchetPayload.maxPlaintextLen, derived from the wire constants).
        // The former 15,000 B figure was looser than that and let oversized
        // messages reach the ratchet.
        let maxBytes = V2RatchetPayload.maxPlaintextLen
        guard content.utf8.count <= maxBytes else {
            await MainActor.run { setError(LanguageManager.localized("This message is too long.")) }
            return
        }
        // A1 §7: nothing goes to a blocked contact (the relay client refuses
        // too); say so before a bubble is created.
        if let rid = ConversationListView.contactRid(conversation), BlockListV2.contains(rid) {
            await MainActor.run { setError(LanguageManager.localized("You blocked this contact.")) }
            return
        }

        // V2-only send path (P8-V1REMOVAL-IOS-08): the legacy V1 RelayClient
        // fallback was removed — the V1 relay is decommissioned (disabled.invalid).
        // FIX #7/M2: distinguish a THROWN load error (transient keychain lock /
        // corrupt blob) from a genuine nil (no V2 handle). Collapsing both into
        // the "retired V1" message could push the user to delete a valid contact.
        let peer: PeerHandleV2?
        do {
            peer = try PeerStoreV2.load(forContactId: conversation.recipientID)
        } catch {
            await MainActor.run {
                setError(LanguageManager.localized("Couldn't read this contact right now. Please try again."))
            }
            return
        }
        guard let peer else {
            // No V2 handle → legacy V1 contact that can no longer be reached.
            await MainActor.run {
                setError(LanguageManager.localized("Not mutually verified yet — scan their QR code to message this contact."))
            }
            return
        }
        guard let v2Client = await V2SessionManager.shared.client else {
            // V2 contact, but the session manager hasn't finished initialising yet
            // (e.g. Send pressed right after auth). Transient — ask the user to retry.
            await MainActor.run {
                setError(LanguageManager.localized("Still connecting to the network — please send again in a moment."))
            }
            return
        }
        await sendMessageV2(content: content, peer: peer, client: v2Client)
    }

    // MARK: - Phase 3: V2 Send Path

    /// Send `content` over the V2 protocol path.
    /// Called when `PeerStoreV2` has an entry for `conversation.recipientID`.
    private func sendMessageV2(content: String, peer: PeerHandleV2, client: RelayClientV2) async {
        // FIX SELF-SEND: Defense-in-depth — abort if the resolved peer is our own
        // identity. Catches legacy contacts that were stored before the SELF-ADD
        // guard in ConversationListView was introduced.
        if peer.recipientId == client.identity.recipientId {
            await MainActor.run {
                setError(LanguageManager.localized("This contact is your own identity. Re-add the peer using their QR code."))
            }
            return
        }

        // Progress and success banners are diagnostics: the bubble's tick
        // already shows the state, so Release builds show no banner.
        #if DEBUG
        await MainActor.run { setError("📤 Sending (V2)…") }
        #endif

        // Build a Message for the local UI (same shape as V1 outgoing messages).
        let now = Date()
        let messageTimestamp: Date = await MainActor.run {
            let lastTimestamp = messages.last?.timestamp ?? Date.distantPast
            return max(now, lastTimestamp.addingTimeInterval(0.001))
        }
        let message = Message(
            id: UUID().uuidString,
            content: content,
            timestamp: messageTimestamp,
            isOutgoing: true,
            conversationID: conversation.recipientID,
            deliveryStatus: .sending
        )

        await MainActor.run {
            messages.append(message)
            springInIDs.insert(message.id)
            messages.sort {
                if $0.timestamp != $1.timestamp { return $0.timestamp < $1.timestamp }
                return $0.id < $1.id
            }
        }
        InMemoryMessageStore.shared.addMessages([message])

        // FIX ORD-3 (2026-05-05): Serialize ONLY the network send — the local
        // UI append above must remain synchronous so the sender's bubble shows
        // up immediately. Chaining each network call onto the previous send's
        // task forces FIFO order on the relay so the receiver sees 1, 2, 3.
        let previous = lastSendTask
        let networkTask = Task { [weak self] in
            await previous?.value
            // P7-IOS-BUG-14: bail out if the chain was cancelled (the
            // ChatViewModel was torn down via deinit while we were
            // waiting on `previous`). Without this guard, up to N
            // chained sends would keep running after the user left the
            // chat, burning Tor circuits + battery for invisible
            // payloads. The local message has already landed in
            // InMemoryMessageStore so dropping the network half is a
            // pure no-op from the receiver's perspective (next fetch
            // re-orders correctly).
            if Task.isCancelled { return }
            await self?.sendMessageV2Network(
                message: message,
                content: content,
                peer: peer,
                client: client
            )
        }
        lastSendTask = networkTask
        await networkTask.value
    }

    /// Network portion of the V2 send path. Runs inside the serialized
    /// `lastSendTask` chain so concurrent taps hit the relay in tap order.
    private func sendMessageV2Network(
        message: Message,
        content: String,
        peer: PeerHandleV2,
        client: RelayClientV2
    ) async {
        let bodyData = Data(content.utf8)
        let maxRetries = 3
        var lastError: Error?
        // Exits we've already tried in this send attempt — drives rotation
        // when an entry-relay returns transient 502 (upstream pool stall) or
        // similar. Tracked by exit-id hex string.
        var triedExits: Set<String> = []

        retryLoop: for attempt in 0..<maxRetries {
            if attempt > 0 {
                let delay = UInt64(3_000_000_000) * UInt64(attempt)
                #if DEBUG
                await MainActor.run { setError("🔄 V2 retry \(attempt)/\(maxRetries - 1)…") }
                #endif
                try? await Task.sleep(nanoseconds: delay)
            }
            // Pick the exit that this attempt will use, so we can record it
            // as "tried" if it fails. Exits already in `triedExits` are excluded.
            let plannedExitHex: String?
            if let preview = await client.previewNextExit(excluding: triedExits) {
                plannedExitHex = preview.exitIdHex
            } else if !triedExits.isEmpty,
                      let preview = await client.previewNextExit(excluding: []) {
                // Every known exit is marked tried, but exits DO exist — so this
                // is a transient failure, not a missing configuration.
                //
                // Exit rotation is built for the target topology with several
                // relays. With a single exit, one hiccup exhausts the list on
                // the first retry and the user sees "no exits configured",
                // which points at the wrong thing entirely. Observed on the
                // 17 Pro on 2026-08-24 while Tor was still settling: the exit
                // was never gone and worked again a minute later.
                //
                // Clear the marks and give the same exit another chance. The
                // attempt budget still bounds this, so a genuinely dead exit
                // still ends the loop — just with an honest error.
                triedExits.removeAll()
                plannedExitHex = preview.exitIdHex
            } else {
                // No untried exits remain. FIX #5: record a failure so the
                // message is marked .failed below — it never reached a relay.
                // Without this, lastError stayed nil on attempt 0 and the send
                // fell through to .sent, falsely showing "delivered" for a
                // message that never left the device.
                plannedExitHex = nil
                if lastError == nil { lastError = RelayClientV2Error.noExitsConfigured }
                #if DEBUG
                NSLog("[ChatView] all exits exhausted after %d attempts", attempt)
                #endif
                break retryLoop
            }
            do {
                // Issue #38: pass the message id so the sealed frame can be
                // held in RAM for possible re-submission (PendingSendCache).
                try await client.sendMessage(to: peer, messageBody: bodyData, excludingExits: triedExits, messageID: message.id)
                lastError = nil
                break retryLoop
            } catch {
                lastError = error
                // Mark this attempt's exit as tried so the next retry rotates.
                if let hex = plannedExitHex { triedExits.insert(hex) }
                // Permanent V2 errors — no point retrying.
                switch error {
                case RelayClientV2Error.enqueue(.http(let code)) where code == 400 || code == 413:
                    break retryLoop
                case RelayClientV2Error.ratchet(.noPeerPrekey),
                     RelayClientV2Error.missingDeliveryKey,
                     RelayClientV2Error.deliveryKeyOutdated,
                     RelayClientV2Error.contactBlocked:
                    // No session and no unused code of the contact, or no
                    // current delivery key of it — retrying cannot help; a
                    // fresh code is needed.
                    break retryLoop
                default:
                    break
                }
            }
        }

        if let error = lastError {
            await MainActor.run {
                if let idx = self.messages.firstIndex(where: { $0.id == message.id }) {
                    self.messages[idx].deliveryStatus = .failed
                }
                // Use String(describing:) so RelayClientV2Error.description (CustomStringConvertible)
                // surfaces the actual reason ("relayv2: enqueue — http(503)", "noExitsConfigured", …)
                // instead of Swift's default "The operation couldn't be completed."
                let detail = String(describing: error)
                #if DEBUG
                NSLog("[ChatView] ❌ V2 send failed: %@", detail)
                #endif
                // While Tor is still coming up every request fails with a
                // transport error, and the raw reason reads like a broken app.
                // Measured on the 12 Pro on 2026-08-24: ~60 s from cold start
                // to the first successful request. Say what is actually going
                // on instead — the technical detail stays in the DEBUG log.
                if case RelayClientV2Error.ratchet(.noPeerPrekey) = error {
                    // Raised before any network step, so Tor state is irrelevant.
                    needsFreshCode = true
                    setError(LanguageManager.localized("No session with this contact yet — exchange a fresh code to start."), sticky: true)
                } else if case RelayClientV2Error.missingDeliveryKey = error {
                    // Raised before any network step (A1: no delivery key on file).
                    needsFreshCode = true
                    setError(LanguageManager.localized("Exchange a fresh code with this contact once to keep messaging."), sticky: true)
                } else if case RelayClientV2Error.contactBlocked = error {
                    setError(LanguageManager.localized("You blocked this contact."), sticky: true)
                } else if case RelayClientV2Error.deliveryKeyOutdated = error {
                    // The contact's published key no longer matches ours.
                    needsFreshCode = true
                    setError(LanguageManager.localized("Exchange a fresh code with this contact once to keep messaging."), sticky: true)
                } else if !TorController.shared.circuitEstablished {
                    setError(LanguageManager.localized("Still connecting to the network — please send again in a moment."), sticky: true)
                } else {
                    // The directory doesn't know them: the relay holds nothing
                    // current from their device.
                    let unreachable: Bool = {
                        switch error {
                        case RelayClientV2Error.directory(.unknownRecipient): return true
                        default: return false
                        }
                    }()
                    let text = unreachable
                        ? LanguageManager.localized("Message not sent — your contact hasn't been reachable recently. Please try again later.")
                        : LanguageManager.localized("Message not sent. Tap Resend to try again.")
                    #if DEBUG
                    setError("\(text)\n\(detail)", sticky: true)
                    #else
                    setError(text, sticky: true)
                    #endif
                }
            }
            InMemoryMessageStore.shared.updateDeliveryStatus(messageID: message.id, status: .failed)
            return
        }

        await MainActor.run {
            if let idx = self.messages.firstIndex(where: { $0.id == message.id }) {
                self.messages[idx].deliveryStatus = .sent
            }
            self.needsFreshCode = false        // a session exists now
            #if DEBUG
            setError("✅ V2 sent")
            #endif
        }
        InMemoryMessageStore.shared.updateDeliveryStatus(messageID: message.id, status: .sent)
    }

    // FIX LOW-27: Removed dead code purgeAllMessages() — was never called from any code path
}

// MARK: - Attachment send progress card

/// Compact card pinned above the input bar while an attachment is being
/// sealed and uploaded. Visual language matches `AttachmentBubbleView`'s
/// download UI (filling ring + monospaced %) but in accent color, with an
/// indeterminate breathing pulse during the prepare phase before the first
/// progress callback fires.
@available(iOS 17.0, *)
struct AttachmentSendProgressCard: View {
    // Creates the dependency that makes this view repaint when the
    // appearance changes. LadonTheme's colours are static reads, so
    // without it SwiftUI sees no reason to call body again and the view
    // keeps the previous mode's colours. Unused on purpose.
    @Environment(\.colorScheme) private var ladonAppearanceTick
    let phase: String
    let progress: Double

    @State private var pulse: Bool = false

    var body: some View {
        let p = max(0.0, min(progress, 1.0))
        let kindIcon: String = {
            let lower = phase.lowercased()
            if lower.contains("video") { return "film.fill" }
            if lower.contains("voice") { return "mic.fill" }
            if lower.contains("audio") { return "music.note" }
            return "photo.fill"
        }()
        let isPreparing = p < 0.001

        if !AppearanceManager.isDarkStored {
            lightCard(p: p, isPreparing: isPreparing)
        } else {
        HStack(spacing: 14) {
            ZStack {
                Circle()
                    .stroke(LadonTheme.accent.opacity(0.18), lineWidth: 3)
                    .frame(width: 36, height: 36)
                Circle()
                    .trim(from: 0, to: isPreparing ? 0.18 : CGFloat(p))
                    .stroke(
                        AngularGradient(
                            gradient: Gradient(colors: [
                                LadonTheme.accent.opacity(0.55),
                                LadonTheme.accent
                            ]),
                            center: .center
                        ),
                        style: StrokeStyle(lineWidth: 3, lineCap: .round)
                    )
                    .frame(width: 36, height: 36)
                    .rotationEffect(.degrees(isPreparing ? (pulse ? 360 : 0) : -90))
                    .animation(
                        isPreparing
                            ? .linear(duration: 1.0).repeatForever(autoreverses: false)
                            : .easeInOut(duration: 0.25),
                        value: isPreparing ? pulse : (p > 0.001)
                    )
                Image(systemName: kindIcon)
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundColor(LadonTheme.accent)
            }
            .onAppear { pulse = true }

            VStack(alignment: .leading, spacing: 2) {
                Text(phase.isEmpty ? "Sending…" : phase)
                    .font(.system(size: 13, weight: .semibold, design: .rounded))
                    .foregroundColor(LadonTheme.textPrimary)
                    .lineLimit(1)
                Text("Encrypted · via Tor")
                    .font(.system(size: 10.5, weight: .medium))
                    .foregroundColor(LadonTheme.textSecondary)
            }

            Spacer(minLength: 8)

            if !isPreparing {
                Text("\(Int((p * 100).rounded()))%")
                    .font(.system(size: 13, weight: .semibold, design: .rounded))
                    .monospacedDigit()
                    .foregroundColor(LadonTheme.textPrimary.opacity(0.85))
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .background(
            RoundedRectangle(cornerRadius: 14, style: .continuous)
                .fill(.ultraThinMaterial)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 14, style: .continuous)
                .stroke(LadonTheme.accent.opacity(0.25), lineWidth: 0.75)
        )
        .shadow(color: .black.opacity(0.18), radius: 8, y: 3)
        .accessibilityElement(children: .combine)
        .accessibilityLabel(phase.isEmpty ? "Sending attachment" : phase)
        }
    }

    /// Light (ladon.app): white card — "Encrypted · via Tor" in mono, the
    /// percentage, and a 6 pt green bar. Before the first progress callback
    /// a short segment slides back and forth.
    private func lightCard(p: Double, isPreparing: Bool) -> some View {
        VStack(spacing: 10) {
            HStack {
                HStack(spacing: 7) {
                    Circle().fill(LadonTheme.greenInk).frame(width: 6, height: 6)
                    Text("Encrypted · via Tor")
                        .font(.jbMono(10.5, .medium, relativeTo: .caption2))
                        .tracking(1.05)
                        .textCase(.uppercase)
                }
                .foregroundColor(LadonTheme.greenInk)
                Spacer(minLength: 8)
                if !isPreparing {
                    Text("\(Int((p * 100).rounded()))%")
                        .font(.jbMono(12, relativeTo: .caption))
                        .monospacedDigit()
                        .foregroundColor(LadonTheme.textPrimary)
                }
            }
            GeometryReader { geo in
                ZStack(alignment: .leading) {
                    Capsule().fill(LadonTheme.paper2)
                    Capsule().fill(LadonTheme.brandGreen)
                        .frame(width: geo.size.width * (isPreparing ? 0.18 : CGFloat(p)))
                        .offset(x: isPreparing && pulse ? geo.size.width * 0.82 : 0)
                        .animation(
                            isPreparing
                                ? .easeInOut(duration: 0.9).repeatForever(autoreverses: true)
                                : .easeInOut(duration: 0.25),
                            value: isPreparing ? pulse : (p > 0.001)
                        )
                }
            }
            .frame(height: 6)
            .clipShape(Capsule())
        }
        .padding(.vertical, 14)
        .padding(.horizontal, 16)
        .background(LadonCardBackground())
        .onAppear { pulse = true }
        .accessibilityElement(children: .combine)
        .accessibilityLabel(phase.isEmpty ? "Sending attachment" : phase)
    }
}

#Preview {
    NavigationStack {
        ChatView(conversation: Conversation(
            id: "1",
            recipientID: "test-recipient",
            recipientPublicKey: Data(count: 32),
            contactName: "Alice",
            lastMessage: nil
        ))
    }
}
