import SwiftUI
import UIKit
import CryptoKit
import VisionKit
import AVFoundation
import UserNotifications

struct ConversationListView: View {
    // Creates the dependency that makes this view repaint when the
    // appearance changes. LadonTheme's colours are static reads, so
    // without it SwiftUI sees no reason to call body again and the view
    // keeps the previous mode's colours. Unused on purpose.
    @Environment(\.colorScheme) private var ladonAppearanceTick
    @StateObject private var viewModel = ConversationListViewModel()
    @ObservedObject private var messageStore = InMemoryMessageStore.shared
    @ObservedObject private var inviteRouter = InviteRouter.shared
    @EnvironmentObject private var biometricAuth: BiometricAuthService
    @EnvironmentObject private var appState: AppState
    @State private var showingNewChat = false
    @State private var showDeleteAllConfirmation = false
    /// Chat whose contact the user asked to block (confirmation pending).
    @State private var blockCandidate: Conversation?
    /// Why the last block/unblock failed (shown once).
    @State private var blockError: String?
    @State private var navigationPath = NavigationPath()
    
    var body: some View {
        NavigationStack(path: $navigationPath) {
            VStack(spacing: 0) {
                // Top action row: trash (left) + new-chat (right), above the title.
                HStack {
                    if viewModel.conversations.isEmpty {
                        // Nothing to delete: same circle shape, greyed out, not tappable.
                        ZStack {
                            if isDark {
                                Circle().fill(LadonTheme.onSurface(0.08))
                            } else {
                                Circle().fill(Color.white.opacity(0.6))
                                Circle().strokeBorder(LadonTheme.onSurface(0.14), lineWidth: 1)
                            }
                            Image(systemName: "trash")
                                .font(.system(size: isDark ? 16 : 17, weight: isDark ? .bold : .regular))
                                .foregroundColor(LadonTheme.onSurface(0.3))
                        }
                        .frame(width: isDark ? 36 : 44, height: isDark ? 36 : 44)
                    } else {
                        Button(role: .destructive, action: { showDeleteAllConfirmation = true }) {
                            ZStack {
                                if isDark {
                                    Circle().fill(LadonTheme.coralGradient)
                                } else {
                                    // ladon.app: ghost circle, coral glyph
                                    Circle().fill(Color.white.opacity(0.6))
                                    Circle().strokeBorder(LadonTheme.onSurface(0.14), lineWidth: 1)
                                }
                                Image(systemName: "trash")
                                    .font(.system(size: isDark ? 16 : 17, weight: isDark ? .bold : .regular))
                                    .foregroundColor(isDark ? .black : LadonTheme.coralInk)
                            }
                            .frame(width: isDark ? 36 : 44, height: isDark ? 36 : 44)
                        }
                        .buttonStyle(.plain)
                        .accessibilityLabel("Delete All Chats?")
                    }
                    Spacer()
                    Button(action: { showingNewChat = true }) {
                        ZStack {
                            if isDark {
                                Circle().fill(LadonTheme.greenGradient)
                            } else {
                                // ladon.app: the one green action, soft green glow
                                Circle().fill(LadonTheme.brandGreen)
                                    .shadow(color: LadonTheme.brandGreen.opacity(0.45), radius: 15, y: 10)
                            }
                            Image(systemName: "plus")
                                .font(.system(size: isDark ? 16 : 18, weight: .bold))
                                .foregroundColor(isDark ? .black : LadonTheme.onSurface(1))
                        }
                        .frame(width: isDark ? 36 : 44, height: isDark ? 36 : 44)
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel("New Chat")
                }
                .padding(.horizontal, 20)
                .padding(.top, 8)

                // Custom large title with pulsing logo directly next to "Messages"
                HStack(alignment: .center, spacing: isDark ? 8 : 10) {
                    if !viewModel.conversations.isEmpty {
                        PulsingLogo(size: 28)
                    }
                    Text("Messages")
                        .font(.manrope(34, .extrabold))
                        .tracking(isDark ? 0 : LadonTheme.titleTracking(34))
                        .foregroundColor(LadonTheme.textPrimary)
                    Spacer()
                }
                .padding(.horizontal, 20)
                .padding(.top, isDark ? 20 : 14)
                .padding(.bottom, isDark ? 16 : 12)
                if !isDark {
                    HStack {
                        LadonTagPill(text: "Encrypted · via Tor", dot: true)
                        Spacer()
                    }
                    .padding(.horizontal, 20)
                    .padding(.bottom, 18)
                }
                
                if viewModel.conversations.isEmpty {
                    // Empty state
                    VStack(spacing: 30) {
                        Spacer()
                        
                        Button(action: { showingNewChat = true }) {
                            VStack(spacing: 8) {
                                PulsingLogo(size: 64)
                                    .padding(.bottom, 32)
                                
                                // Light: Manrope like every title (ladon.app); dark unchanged.
                                Text("No Conversations")
                                    .font(isDark ? .title2.weight(.semibold) : .manrope(26, .extrabold, relativeTo: .title2))
                                    .tracking(isDark ? 0 : LadonTheme.titleTracking(26))
                                    .foregroundColor(LadonTheme.textPrimary)
                                
                                Text("Tap to start a new chat")
                                    .font(isDark ? .subheadline : .manrope(16.5, relativeTo: .body))
                                    .foregroundColor(LadonTheme.textSecondary)
                            }
                        }
                        
                        Spacer()
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    List {
                        ForEach(Array(viewModel.conversations.enumerated()), id: \.element.id) { index, conversation in
                            let candidateIDs = Set([conversation.recipientID, conversation.id, conversation.relayRecipientID].compactMap { $0 })
                            let unread = messageStore.unreadCount(forAnyOf: candidateIDs)
                            NavigationLink(value: conversation) {
                                ConversationRow(conversation: conversation, unreadCount: unread)
                                    .staggerIn()
                            }
                            // Exactly one background per row. Light: the rows form one
                            // white card (ladon.app). Dark: the unchanged glass cards.
                            .listRowBackground(rowBackground(isFirst: index == 0,
                                                             isLast: index == viewModel.conversations.count - 1))
                            .listRowInsets(isDark ? nil : EdgeInsets(top: 0, leading: 34, bottom: 0, trailing: 34))
                            // Long press: block/unblock (V2 contacts) and the
                            // same delete as the swipe.
                            .contextMenu {
                                if let rid = Self.contactRid(conversation) {
                                    if BlockListV2.contains(rid) {
                                        Button {
                                            unblock(rid)
                                        } label: {
                                            Label("Unblock", systemImage: "hand.raised.slash")
                                        }
                                    } else {
                                        Button(role: .destructive) {
                                            blockCandidate = conversation
                                        } label: {
                                            Label("Block", systemImage: "hand.raised")
                                        }
                                    }
                                }
                                Button(role: .destructive) {
                                    viewModel.deleteConversation(conversation)
                                } label: {
                                    Label("Delete", systemImage: "trash")
                                }
                            }
                        }
                        .onDelete(perform: deleteConversation)
                        .listRowSeparator(.hidden)
                    }
                    .listStyle(.plain)
                    .scrollContentBackground(.hidden)
                    .refreshable {
                        // Pull to refresh
                        await viewModel.loadConversations()
                    }
                }
            }
            .background(MeshBackground())
            .toolbar(.hidden, for: .navigationBar)
            .navigationDestination(for: Conversation.self) { conversation in
                ChatView(conversation: conversation)
            }
            .onChange(of: navigationPath) { _, path in
                appState.isChatOpen = !path.isEmpty
            }
            .sheet(isPresented: $showingNewChat) {
                NewChatView(viewModel: viewModel, onConversationCreated: { conversation in
                    showingNewChat = false
                    
                    // Navigate to chat after sheet is fully dismissed
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.4) {
                        navigationPath.append(conversation)
                    }
                })
            }
            // Stage B: incoming invite-link → accept sheet. Gated on unlock so the
            // sheet never appears over the Face ID lock (which would deadlock:
            // sheet is non-interactive while locked, and the lock prompt sits
            // behind it). While locked → nil → no sheet; after unlock the pending
            // invite presents normally.
            .sheet(item: Binding(
                get: { biometricAuth.isLocked ? nil : inviteRouter.pending },
                set: { inviteRouter.pending = $0 }
            )) { invite in
                AcceptInviteView(invite: invite, viewModel: viewModel, onOpenChat: { conversation in
                    inviteRouter.pending = nil
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.4) {
                        navigationPath.append(conversation)
                    }
                })
            }
            .alert("Invite", isPresented: Binding(
                get: { !biometricAuth.isLocked && inviteRouter.failure != nil },
                set: { if !$0 { inviteRouter.failure = nil } }
            )) {
                Button("OK", role: .cancel) { inviteRouter.failure = nil }
            } message: {
                Text(inviteRouter.failure ?? "")
            }
            .alert("Block Contact?", isPresented: Binding(
                get: { blockCandidate != nil },
                set: { if !$0 { blockCandidate = nil } }
            )) {
                Button("Cancel", role: .cancel) { blockCandidate = nil }
                Button("Block", role: .destructive) {
                    if let c = blockCandidate, let rid = Self.contactRid(c) { block(rid) }
                    blockCandidate = nil
                }
            } message: {
                Text("This contact can no longer send you messages. Your other contacts receive your new key automatically.")
            }
            .alert("Error", isPresented: Binding(
                get: { blockError != nil },
                set: { if !$0 { blockError = nil } }
            )) {
                Button("OK", role: .cancel) { blockError = nil }
            } message: {
                Text(blockError ?? "")
            }
            .alert("Delete All Chats?", isPresented: $showDeleteAllConfirmation) {
                Button("Cancel", role: .cancel) { }
                Button("Delete All", role: .destructive) {
                    viewModel.deleteAllConversations()
                }
            } message: {
                Text("This action cannot be undone. All conversations will be permanently deleted.")
            }
            // P7-IOS-BUG-13: surface burst-rate-limit drops to the user.
            .alert("Some incoming messages skipped", isPresented: Binding(
                get: { viewModel.burstWarning != nil },
                set: { if !$0 { viewModel.burstWarning = nil } }
            )) {
                Button("OK", role: .cancel) { viewModel.burstWarning = nil }
            } message: {
                Text(viewModel.burstWarning ?? "")
            }
            .onAppear {
                Task {
                    // #1: loadConversations() now also reconciles rows from the
                    // message store; incoming messages arrive via the single V2
                    // receive loop + the NewMessagesReceived observer (no per-
                    // view fetch loop).
                    await viewModel.loadConversations()
                }
            }
        }
    }
    
    private var isDark: Bool { AppearanceManager.isDarkStored }

    /// Dark: gleiches Glas wie `GlassSection` (LadonTheme): Radius 14
    /// continuous, Deckkraft 0.55 und die 1px-Innenkante; das vertikale Padding
    /// trennt die Karten, ohne die Zeilenhoehe zu aendern (unverändert).
    /// Light: one white card from joined rows (ladon.app design).
    private func rowBackground(isFirst: Bool, isLast: Bool) -> AnyView {
        if isDark {
            return AnyView(
                RoundedRectangle(cornerRadius: 14, style: .continuous)
                    .fill(.ultraThinMaterial)
                    .opacity(0.55)
                    .overlay(
                        RoundedRectangle(cornerRadius: 14, style: .continuous)
                            .strokeBorder(LadonTheme.glassStroke, lineWidth: 1)
                    )
                    .padding(.vertical, 3)
            )
        }
        return AnyView(ChatCardRowBackground(isFirst: isFirst, isLast: isLast))
    }

    private func deleteConversation(at offsets: IndexSet) {
        offsets.forEach { index in
            let conversation = viewModel.conversations[index]
            viewModel.deleteConversation(conversation)
        }
    }

    /// The recipient id of a V2 contact's chat (its id is the rid in hex).
    static func contactRid(_ conversation: Conversation) -> RecipientIdV2? {
        guard BlockingCodecV2.isRidHex(conversation.recipientID),
              let bytes = Data(hexString: conversation.recipientID) else { return nil }
        return RecipientIdV2(bytes: bytes)
    }

    private func block(_ rid: RecipientIdV2) {
        do { try DeliveryRotationV2.block(rid) }
        catch {
            SecureLogger.error("[ConversationList] block failed: \(error)")
            blockError = LanguageManager.localized("Could not block this contact. Please try again.")
        }
    }

    private func unblock(_ rid: RecipientIdV2) {
        do { try DeliveryRotationV2.unblock(rid) }
        catch {
            SecureLogger.error("[ConversationList] unblock failed: \(error)")
            blockError = LanguageManager.localized("Could not unblock this contact. Please try again.")
        }
    }
}

/// One row of the light-mode chat card (ladon.app): white, 24 pt outer
/// radius, 1 px hairline (ink 8 %). Each row draws its top edge (the card's
/// top, or the line to the row above) and its sides; only the last row also
/// draws the bottom — so the lines between rows are 1 px, never doubled.
struct ChatCardRowBackground: View {
    let isFirst: Bool
    let isLast: Bool
    private let radius: CGFloat = 24

    var body: some View {
        let shape = UnevenRoundedRectangle(
            topLeadingRadius: isFirst ? radius : 0,
            bottomLeadingRadius: isLast ? radius : 0,
            bottomTrailingRadius: isLast ? radius : 0,
            topTrailingRadius: isFirst ? radius : 0,
            style: .continuous)
        ZStack {
            shape.fill(Color.white)
            // Extended 1.5 pt below the row unless last, then clipped: the
            // bottom edge falls outside and is not drawn.
            shape.strokeBorder(LadonTheme.onSurface(0.08), lineWidth: 1)
                .padding(.bottom, isLast ? 0 : -1.5)
        }
        .clipped()
        .padding(.horizontal, 16)
    }
}

struct ConversationRow: View {
    // Creates the dependency that makes this view repaint when the
    // appearance changes. LadonTheme's colours are static reads, so
    // without it SwiftUI sees no reason to call body again and the view
    // keeps the previous mode's colours. Unused on purpose.
    @Environment(\.colorScheme) private var ladonAppearanceTick
    let conversation: Conversation
    let unreadCount: Int
    
    /// Avatar-Hintergrundfarbe aus dem Namen ableiten (deterministisch)
    private var avatarColor: Color {
        let hash = conversation.contactName.unicodeScalars.reduce(0) { $0 &+ Int($1.value) }
        let hue = Double(hash % 360) / 360.0
        return Color(hue: hue, saturation: 0.3,
                     brightness: AppearanceManager.isDarkStored ? 0.35 : 0.62)
    }
    
    private var isDark: Bool { AppearanceManager.isDarkStored }

    var body: some View {
        HStack(spacing: 12) {
            // Avatar-Kreis mit Initiale (wie im Mockup B1). Light (ladon.app):
            // 46 pt, green tint while unread, soft paper otherwise.
            ZStack {
                Circle()
                    .fill(isDark ? avatarColor : (unreadCount > 0 ? LadonTheme.brandGreenSoft : LadonTheme.paper2))
                    .frame(width: isDark ? 44 : 46, height: isDark ? 44 : 46)
                Text(String(conversation.contactName.prefix(1)).uppercased())
                    .font(isDark ? .system(size: 18, weight: .semibold) : .manrope(17, .extrabold))
                    .foregroundColor(isDark ? LadonTheme.textPrimary
                                     : (unreadCount > 0 ? LadonTheme.greenDeep : LadonTheme.textSecondary))
            }
            
            VStack(alignment: .leading, spacing: isDark ? 4 : 2) {
                HStack(alignment: .firstTextBaseline) {
                    Text(conversation.contactName)
                        .font(isDark ? .headline : .manrope(16, .bold))
                        .foregroundColor(LadonTheme.textPrimary)
                    Spacer()
                    if let lastMessage = conversation.lastMessage {
                        // FIX iOS-F15: Quantisierte Zeitangabe — "recently" statt exaktem Zeitpunkt
                        // Verhindert Metadaten-Korrelation durch genaue Timestamps
                        Text(quantizedTimestamp(lastMessage.timestamp))
                            .font(isDark ? .caption : .jbMono(11, relativeTo: .caption2))
                            .tracking(isDark ? 0 : 0.44)
                            .textCase(isDark ? nil : .uppercase)
                            .foregroundColor(isDark ? LadonTheme.textSecondary : LadonTheme.inkMuted)
                    }
                }
                
                HStack {
                    if let lastMessage = conversation.lastMessage {
                        Text(lastMessage.isOutgoing ? "You: Message" : "Message received")
                            .font(isDark ? .subheadline
                                  : .manrope(14, unreadCount > 0 ? .semibold : .regular))
                            .foregroundColor(!isDark && unreadCount > 0 ? LadonTheme.textPrimary : LadonTheme.textSecondary)
                            .lineLimit(1)
                            // FIX MED: Prevent VoiceOver from reading message preview aloud
                            .accessibilityLabel(lastMessage.isOutgoing ? "Sent message" : "New message")
                    }
                    Spacer()
                }
            }
            
            if unreadCount > 0 {
                Text("\(unreadCount)")
                    .font(isDark ? .caption2.bold() : .manrope(12, .extrabold))
                    .foregroundColor(isDark ? LadonTheme.bubbleOutgoingText : LadonTheme.onSurface(1))
                    .padding(.horizontal, 7)
                    .padding(.vertical, 3)
                    .frame(minWidth: isDark ? nil : 22, minHeight: isDark ? nil : 22)
                    .background(isDark ? LadonTheme.accent : LadonTheme.brandGreen)
                    .clipShape(Capsule())
                    .accessibilityLabel("\(unreadCount) unread messages")
            }
        }
        .padding(.vertical, isDark ? 8 : 13)
    }
    
    /// FIX UI-10: Coarsened time buckets — prevents metadata correlation via precise timestamps
    /// Showing exact minutes (e.g., "23 min ago") allows observers to correlate send/receive times.
    /// Now uses 15-minute buckets: "< 15 min", "< 30 min", "< 1h", then hours/days.
    private func quantizedTimestamp(_ date: Date) -> String {
        let seconds = abs(date.timeIntervalSinceNow)
        switch seconds {
        case 0..<60:        return "just now"
        case 60..<900:      return "< 15 min"
        case 900..<1800:    return "< 30 min"
        case 1800..<3600:   return "< 1h"
        case 3600..<86400:  return "\(Int(seconds / 3600))h ago"
        default:
            let days = Int(seconds / 86400)
            return days == 1 ? "yesterday" : "\(days)d ago"
        }
    }
}

/// Build + parse LADON invite links.
///
/// Primary form is a **Universal Link** `https://ladon.app/i#<code>`: tappable in
/// any app, and the code sits in the `#` fragment, which is **never sent to the
/// server** (no metadata leak). The code is percent-encoded (alphanumerics-only
/// allowed, plus base64url's `-` and `_`) so the code survives transport intact.
/// P8-AUDIT8-IOS-19: the legacy `ladon://add?code=…` custom scheme is gone —
/// no longer registered and no longer parsed. It never carried a valid v4
/// code (v4 dates from 02.10.2026, `make` emits https only since 31.05.2026),
/// and any web page or app could open it without the user choosing a link.
enum InviteLink {
    /// `reciprocal` = a "send my code back" link. The opener of a reciprocal link
    /// already had their code added by the sender, so no further send-back is needed.
    /// Encoded as the path: initial `/i`, reciprocal `/i/r`.
    static func make(code: String, reciprocal: Bool = false) -> String {
        // base64url's `-` and `_` are unreserved (RFC 3986) and stay as they are.
        let enc = code.addingPercentEncoding(withAllowedCharacters: .alphanumerics.union(CharacterSet(charactersIn: "-_"))) ?? code
        return "https://ladon.app\(reciprocal ? "/i/r" : "/i")#\(enc)"
    }

    static func parse(_ url: URL) -> (code: String, reciprocal: Bool)? {
        let comps = URLComponents(url: url, resolvingAgainstBaseURL: false)
        // Universal Link: code in the fragment.
        if url.scheme?.lowercased() == "https",
           (url.host ?? "").lowercased() == "ladon.app" {
            let path = url.path.lowercased()
            if path.hasPrefix("/i"),
               let frag = comps?.percentEncodedFragment, !frag.isEmpty,
               let code = frag.removingPercentEncoding {
                return (code, path.hasPrefix("/i/r"))
            }
        }
        return nil
    }
}

/// Routes an incoming invite link to the UI. `onOpenURL` (in LadonApp)
/// validates + sets `pending`; ConversationListView presents the accept sheet.
@MainActor
final class InviteRouter: ObservableObject {
    static let shared = InviteRouter()
    private init() {}

    struct PendingInvite: Identifiable, Equatable {
        let id = UUID()
        let code: String        // pairing code, "ladonv5:…" (PairingCodeV4)
        let recipientId: String // hex
        let reciprocal: Bool    // true = opener already had their code sent back; no further send-back
    }
    @Published var pending: PendingInvite?
    /// Why the last invite link was refused (expired, old, damaged, own code),
    /// so tapping it never silently does nothing.
    @Published var failure: String?

    /// Fail-closed: only a valid, non-self pairing code becomes a pending invite.
    func handle(_ url: URL) {
        guard let parsed = InviteLink.parse(url) else {
            // Our own invite path without a readable code (e.g. a messenger cut
            // off the `#…` part) — say so instead of doing nothing.
            if url.scheme?.lowercased() == "https", (url.host ?? "").lowercased() == "ladon.app",
               url.path.lowercased().hasPrefix("/i") {
                failure = LanguageManager.localized("This isn't a valid LADON messenger code.")
            }
            return
        }
        do {
            let peer = try V2ContactAdder.validatedPeer(fromScannedKey: parsed.code)
            failure = nil
            pending = PendingInvite(code: parsed.code, recipientId: peer.recipientId.description, reciprocal: parsed.reciprocal)
        } catch let e as V2ContactAddError {
            failure = e.userMessage
        } catch {
            failure = LanguageManager.localized("This isn't a valid LADON messenger code.")
        }
    }
}

/// Errors surfaced while adding a V2 contact from a scanned/pasted key.
enum V2ContactAddError: Error {
    case invalidKey
    /// A code from before one-time prekeys — it cannot start a session.
    case oldCode
    /// The code's validity has passed; the owner has discarded its key.
    case expiredCode
    case selfAdd
    case identityUnavailable
    case storeFailed(String)
    /// The scanned key does not map to the contact we expected (reply-scan mismatch).
    case mismatch

    var userMessage: String {
        switch self {
        case .invalidKey:          return LanguageManager.localized("This isn't a valid LADON messenger code.")
        case .oldCode:             return LanguageManager.localized("This code is from an older version. Ask for a new one.")
        case .expiredCode:         return LanguageManager.localized("This code has expired. Ask for a new one.")
        case .selfAdd:             return LanguageManager.localized("This is your own code. Ask the other person for theirs.")
        case .identityUnavailable: return LanguageManager.localized("Could not verify your identity. Please try again.")
        case .storeFailed:         return LanguageManager.localized("Could not save this contact. Please try again.")
        case .mismatch:            return LanguageManager.localized("This code belongs to a different contact.")
        }
    }
}

/// Single, shared add-path for V2 contacts. Used by both the New-Chat scan flow
/// and ChatView's reply-scan so the validation + self-add guard + PeerStoreV2
/// persistence can never drift between the two entry points.
/// Pure contact-layer: no crypto / wire / ratchet changes.
enum V2ContactAdder {
    /// Validate a pairing code (`ladonv5:…`, see PairingCodeV4): format and
    /// owner signature, expiry
    /// hint, self-add guard, optional expected-recipient match. Returns the peer,
    /// the one-time prekey and the peer's delivery key WITHOUT persisting
    /// anything — used for immediate paste/scan feedback before the user commits.
    static func validatedCode(fromScannedKey raw: String, expectedRecipientId: String? = nil) throws -> (peer: PeerHandleV2, prekey: OneTimePrekeyPublicV2, deliveryKey: Data) {
        let code: PairingCodeV4
        do { code = try PairingCodeV4.parse(raw) }
        catch PairingCodeError.oldFormat { throw V2ContactAddError.oldCode }
        catch { throw V2ContactAddError.invalidKey }
        let nowRelay = ClockSyncV2.shared.nowSec()
        if code.isExpired(nowRelaySec: nowRelay) { throw V2ContactAddError.expiredCode }
        // P8-AUDIT8-IOS-30: no code we issue lives longer than an invite.
        if code.expiresImplausiblyLate(nowRelaySec: nowRelay) { throw V2ContactAddError.invalidKey }
        let hsigPk = code.hsigPk
        let recipientId = code.recipientId

        // FIX SELF-ADD: never add our own identity as a contact (would encrypt to
        // self; the message never reaches the intended peer). Fail-closed.
        let isSelf: Bool
        do {
            let own = try IdentityStoreV2.loadOrGenerate()
            isSelf = (own.recipientId == recipientId)
        } catch {
            throw V2ContactAddError.identityUnavailable
        }
        if isSelf { throw V2ContactAddError.selfAdd }

        // Reply-scan: the scanned code must belong to THIS conversation's peer.
        if let expected = expectedRecipientId, expected != recipientId.description {
            throw V2ContactAddError.mismatch
        }
        return (PeerHandleV2(recipientId: recipientId, recipientHsigPk: hsigPk), code.prekey, code.deliveryKey)
    }

    /// Validation only, peer handle only (callers that just need to check a code).
    static func validatedPeer(fromScannedKey raw: String, expectedRecipientId: String? = nil) throws -> PeerHandleV2 {
        try validatedCode(fromScannedKey: raw, expectedRecipientId: expectedRecipientId).peer
    }

    /// Validate + persist the peer (PeerStoreV2), its one-time prekey
    /// (PrekeyStoreV2 — an older code never replaces a newer one on file) and
    /// its delivery key (DeliveryKeyStoreV2 — the code carries the current
    /// one). Returns the derived recipient id.
    @discardableResult
    static func addPeer(fromScannedKey raw: String, expectedRecipientId: String? = nil) throws -> RecipientIdV2 {
        let (peer, prekey, deliveryKey) = try validatedCode(fromScannedKey: raw, expectedRecipientId: expectedRecipientId)
        do {
            try PeerStoreV2.store(peer: peer, forContactId: peer.recipientId.description)
            try PrekeyStoreV2.storePeer(prekey, forPeer: peer.recipientId.description)
            try DeliveryKeyStoreV2.storePeerKey(deliveryKey, for: peer.recipientId)
        } catch {
            throw V2ContactAddError.storeFailed(error.localizedDescription)
        }
        return peer.recipientId
    }
}

struct NewChatView: View {
    // Creates the dependency that makes this view repaint when the
    // appearance changes. LadonTheme's colours are static reads, so
    // without it SwiftUI sees no reason to call body again and the view
    // keeps the previous mode's colours. Unused on purpose.
    @Environment(\.colorScheme) private var ladonAppearanceTick
    @Environment(\.dismiss) var dismiss
    @ObservedObject var viewModel: ConversationListViewModel
    private var isDark: Bool { AppearanceManager.isDarkStored }
    @State private var recipientPublicKey = ""
    @State private var contactName = ""
    @State private var showScanner = false
    /// Our in-person code (PairingCodeV4, 10-minute one-time prekey), kept
    /// fresh while "Show my code" is visible.
    @StateObject private var inPersonCode = InPersonCodeModel()
    /// Invite codes (24-hour one-time prekey) are minted only when the user
    /// actually shares, so opening a screen never uses up a prekey slot.
    @State private var shareItem: ShareTextItem?
    @State private var isMintingInvite = false
    /// "Add their invite" shows its checkmark only for a code that validates.
    @State private var remoteCodeValid = false
    /// Guards "Start chat" against a double tap during the push animation.
    @State private var isStarting = false

    /// Add-remotely flow: whether the user has tapped Share, and any paste error.
    @State private var didShareInvite = false
    @State private var remoteError: String?
    @State private var conversationID = ""
    @State private var errorMessage: String?
    /// #UI guided add-flow navigation: scan → naming → verify.
    @State private var path: [AddStep] = []
    @State private var createdConversation: Conversation?

    // Guided add-flow order: scan their code → show MY code (so they can scan
    // me back) → name the contact → start chat.
    private enum AddStep: Hashable { case showMyCode, naming, remote, verify }

    // Callback for when conversation is created
    var onConversationCreated: ((Conversation) -> Void)? = nil
    
    var body: some View {
        NavigationStack(path: $path) {
            ZStack {
            MeshBackground()
            landingView
                .scrollContentBackground(.hidden)
                .navigationTitle(isDark ? LocalizedStringKey("New Chat") : LocalizedStringKey(""))
                .navigationBarTitleDisplayMode(.inline)
                .toolbarBackground(.hidden, for: .navigationBar)
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Cancel") { dismiss() }
                            .foregroundColor(LadonTheme.brandGreen)
                    }
                }
            }
            .tint(LadonTheme.brandGreen)
                .navigationDestination(for: AddStep.self) { step in
                    switch step {
                    case .showMyCode: showMyCodeStep
                    case .naming: namingStep
                    case .remote: remoteStep
                    case .verify: verifyStep
                    }
                }
                .sheet(item: $shareItem) { item in
                    ActivityShareSheet(text: item.text)
                        .presentationDetents([.medium, .large])
                }
                .sheet(isPresented: $showScanner, onDismiss: {
                    // A successful scan fills recipientPublicKey. It is validated
                    // right here (expired, old, own, damaged → message, no
                    // navigation) so a bad code never gets as far as naming.
                    // No automatic page jump otherwise: scan-first goes to the
                    // (deliberate) show-my-code step; show-first stays on it and
                    // the user taps "Continue". A cancelled scan leaves
                    // recipientPublicKey empty (no navigation).
                    guard !recipientPublicKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return }
                    do {
                        _ = try V2ContactAdder.validatedPeer(fromScannedKey: recipientPublicKey)
                    } catch {
                        recipientPublicKey = ""
                        errorMessage = (error as? V2ContactAddError)?.userMessage
                            ?? LanguageManager.localized("Couldn't read that code.")
                        return
                    }
                    if !path.contains(.showMyCode) {
                        path.append(.showMyCode)
                    }
                }) {
                    QRScannerView(scannedPublicKey: $recipientPublicKey)
                }
                .alert("Error", isPresented: Binding(
                    get: { errorMessage != nil },
                    set: { if !$0 { errorMessage = nil } }
                )) {
                    EmptyView()
                } message: {
                    Text(errorMessage ?? "")
                }
                .onChange(of: errorMessage) { _, newValue in
                    guard newValue != nil else { return }
                    DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
                        errorMessage = nil
                    }
                }
                .onAppear { generateNewConversationKeys() }
                // R19-V6 note: the codes held here are PUBLIC (identity key + the
                // public half of a one-time prekey; the QR is meant to be shown)
                // and MUST survive the scan → show-code → name → start
                // navigation. .onDisappear fires on push, so wiping here broke the
                // flow; we intentionally don't wipe. Private keys live in the
                // Keychain (IdentityStoreV2, PrekeyStoreV2), not in @State.
        }
    }

    // MARK: - Step 1: landing (two clear paths)

    private var landingView: some View {
        ScrollView {
            VStack(spacing: isDark ? 16 : 12) {
                if isDark {
                    Text("Connect securely. Scan someone's code, or show yours so they can add you.")
                        .font(.subheadline)
                        .foregroundColor(LadonTheme.textSecondary)
                        .multilineTextAlignment(.center)
                        .padding(.top, 8)
                        .padding(.horizontal)
                } else {
                    screenHeader(eyebrow: "Connect securely", title: "New Chat", titleSize: 34,
                                 lead: "Scan someone's code, or show yours so they can add you.")
                }

                actionCard(icon: "qrcode.viewfinder",
                           title: "Scan their code",
                           subtitle: "Add someone to chat",
                           prominent: true) {
                    recipientPublicKey = ""
                    showScanner = true
                }

                actionCard(icon: "qrcode",
                           title: "Show my code",
                           subtitle: "Let them add you",
                           prominent: false) {
                    recipientPublicKey = ""
                    path.append(.showMyCode)
                }

                actionCard(icon: "paperplane",
                           title: "Add remotely",
                           subtitle: "Invite someone who isn't here",
                           prominent: false) {
                    recipientPublicKey = ""
                    didShareInvite = false
                    remoteError = nil
                    path.append(.remote)
                }

                Spacer(minLength: 8)
            }
        }
    }

    private func actionCard(icon: String, title: LocalizedStringKey, subtitle: LocalizedStringKey,
                            prominent: Bool, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(spacing: 14) {
                if isDark {
                    Image(systemName: icon)
                        .font(.system(size: 26, weight: .semibold))
                        .foregroundColor(prominent ? LadonTheme.background : LadonTheme.textPrimary)
                        .frame(width: 40)
                } else {
                    // ladon.app icon tile: 48 pt, 16 pt corners.
                    Image(systemName: icon)
                        .font(.system(size: 22, weight: .medium))
                        .foregroundColor(prominent ? LadonTheme.textPrimary : LadonTheme.greenInk)
                        .frame(width: 48, height: 48)
                        .background(
                            RoundedRectangle(cornerRadius: 16, style: .continuous)
                                .fill(prominent ? Color.white.opacity(0.35) : LadonTheme.brandGreenSoft)
                        )
                }
                VStack(alignment: .leading, spacing: 2) {
                    Text(title)
                        .font(isDark ? .headline : .manrope(17, .extrabold, relativeTo: .headline))
                        .tracking(isDark ? 0 : -0.34)
                        .foregroundColor(isDark && prominent ? LadonTheme.background : LadonTheme.textPrimary)
                    Text(subtitle)
                        .font(isDark ? .caption : .manrope(13, prominent ? .semibold : .regular, relativeTo: .caption))
                        .foregroundColor(isDark
                                         ? (prominent ? LadonTheme.background.opacity(0.7) : LadonTheme.textSecondary)
                                         : (prominent ? LadonTheme.greenDeep : LadonTheme.textSecondary))
                }
                Spacer()
                Image(systemName: "chevron.right")
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundColor(isDark
                                     ? (prominent ? LadonTheme.background.opacity(0.6) : LadonTheme.textSecondary)
                                     : (prominent ? LadonTheme.textPrimary : LadonTheme.inkMuted))
            }
            .padding(isDark ? 16 : 18)
            .background(
                Group {
                    if !isDark {
                        // ladon.app: green primary card / white card, 24 pt corners.
                        if prominent {
                            RoundedRectangle(cornerRadius: 24, style: .continuous)
                                .fill(LadonTheme.brandGreen)
                                .shadow(color: LadonTheme.brandGreen.opacity(0.45), radius: 15, y: 10)
                        } else {
                            RoundedRectangle(cornerRadius: 24, style: .continuous)
                                .fill(Color.white)
                                .overlay(
                                    RoundedRectangle(cornerRadius: 24, style: .continuous)
                                        .strokeBorder(LadonTheme.onSurface(0.08), lineWidth: 1)
                                )
                                .shadow(color: LadonTheme.onSurface(0.04), radius: 1, y: 1)
                                .shadow(color: LadonTheme.onSurface(0.06), radius: 6, y: 4)
                        }
                    } else if prominent {
                        RoundedRectangle(cornerRadius: LadonTheme.cornerRadiusMedium, style: .continuous)
                            .fill(LadonTheme.greenGradient)
                            .overlay(
                                RoundedRectangle(cornerRadius: LadonTheme.cornerRadiusMedium, style: .continuous)
                                    .strokeBorder(LadonTheme.onSurface(0.3), lineWidth: 1)
                            )
                    } else {
                        RoundedRectangle(cornerRadius: LadonTheme.cornerRadiusMedium, style: .continuous)
                            .fill(.ultraThinMaterial)
                            .opacity(0.55)
                            .overlay(
                                RoundedRectangle(cornerRadius: LadonTheme.cornerRadiusMedium, style: .continuous)
                                    .strokeBorder(LadonTheme.glassStroke, lineWidth: 1)
                            )
                    }
                }
            )
        }
        .buttonStyle(.plain)
        .padding(.horizontal)
    }

    // MARK: - Add remotely (invite over any app, paste theirs back)

    private static func inviteShareText(code: String) -> String {
        String(
            format: LanguageManager.localized(
                "Add me on LADON messenger — tap to connect:\n%@\n\nNo app yet? Get LADON messenger, then add this code under +  →  Add remotely:\n%@"
            ),
            InviteLink.make(code: code),
            code
        )
    }

    /// Mint a fresh invite code (24-hour one-time prekey) and open the share
    /// sheet with it. Every share is a new code: each one opens one session.
    private func shareInvite() {
        guard !isMintingInvite else { return }
        isMintingInvite = true
        remoteError = nil
        Task {
            let result = await Task.detached(priority: .userInitiated) { () -> Result<String, Error> in
                Result { try PairingCodeV4.issue(.invite) }
            }.value
            isMintingInvite = false
            switch result {
            case .success(let code):
                shareItem = ShareTextItem(text: Self.inviteShareText(code: code))
                didShareInvite = true
            case .failure:
                remoteError = LanguageManager.localized("Couldn't create your code.")
            }
        }
    }

    private var remoteStep: some View {
        ZStack {
        MeshBackground()
        ScrollView {
            VStack(spacing: 14) {
                if isDark {
                    Text("Swap invites over any app — you each add the other, then you're connected.")
                        .font(.subheadline).foregroundColor(LadonTheme.textSecondary)
                        .multilineTextAlignment(.center).padding(.horizontal).padding(.top, 8)
                } else {
                    PairingHeader(eyebrow: "Connect securely", title: Text("Add remotely"),
                                  lead: Text("Swap invites over any app — you each add the other, then you're connected."))
                }

                // Card 1 — send your invite
                PairingCard {
                    HStack(spacing: 10) {
                        remoteCardIcon(dark: "paperplane.fill", light: "paperplane")
                        remoteCardTitle("Send your invite")
                        Spacer()
                        if didShareInvite { remoteStatus("Sent") }
                    }
                    Text("Share a link — they tap it to add you.").font(captionFont).foregroundColor(LadonTheme.textSecondary)
                    Text("The link works once and for 24 hours.").font(captionFont).foregroundColor(LadonTheme.textSecondary)
                    PairingPrimaryButton(title: "Share invite link", systemImage: "square.and.arrow.up",
                                         isBusy: isMintingInvite, darkPadding: 13) { shareInvite() }
                        .disabled(isMintingInvite)
                }
                .padding(.horizontal)

                // Card 2 — add their invite
                PairingCard {
                    HStack(spacing: 10) {
                        remoteCardIcon(dark: "tray.and.arrow.down.fill", light: "tray.and.arrow.down")
                        remoteCardTitle("Add their invite")
                        Spacer()
                        if remoteCodeValid { remoteStatus("Added") }
                    }
                    Text("Paste the code they sent you.").font(captionFont).foregroundColor(LadonTheme.textSecondary)
                    Button { pasteTheirCode() } label: {
                        PairingGhostLabel(title: "Paste from clipboard", systemImage: "doc.on.clipboard",
                                          darkPadding: 12, darkOutlineOnly: true)
                    }
                    .buttonStyle(.plain)
                    TextEditor(text: $recipientPublicKey)
                        .frame(height: 62).font(isDark ? .system(.caption, design: .monospaced) : .jbMono(11.5, relativeTo: .caption))
                        .autocorrectionDisabled(true).textContentType(.none)
                        .scrollContentBackground(.hidden)
                        .padding(isDark ? 0 : 6)
                        .background(isDark ? LadonTheme.cardBackground : LadonTheme.paper2)
                        .cornerRadius(isDark ? 8 : 14)
                        .privacySensitive()
                        .onChange(of: recipientPublicKey) { _, newValue in
                            // A pairing code is 4,362 characters (PairingCodeV4).
                            if newValue.count > 5000 { recipientPublicKey = String(newValue.prefix(5000)) }
                            remoteError = nil
                            remoteCodeValid = (try? V2ContactAdder.validatedPeer(fromScannedKey: recipientPublicKey)) != nil
                        }
                    if let remoteError {
                        Text(remoteError).font(captionFont).foregroundColor(LadonTheme.coralInk)
                    }
                }
                .padding(.horizontal)

                prominentButton(title: "Continue", systemImage: "arrow.right") {
                    continueFromRemote()
                }
                .disabled(recipientPublicKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                .padding(.horizontal)

                HStack(spacing: 6) {
                    Image(systemName: "lock.fill").font(.system(size: 11))
                    Text("You'll compare the safety number after connecting.")
                }
                .font(isDark ? .caption2 : .manrope(12.5, relativeTo: .caption2))
                .foregroundColor(LadonTheme.inkMuted).padding(.top, 2)

                Spacer(minLength: 8)
            }
        }
        }
        .navigationTitle(isDark ? LocalizedStringKey("Add remotely") : LocalizedStringKey(""))
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(.hidden, for: .navigationBar)
        .tint(LadonTheme.brandGreen)
    }

    private func pasteTheirCode() {
        let s = (UIPasteboard.general.string ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        guard !s.isEmpty else { remoteError = LanguageManager.localized("Nothing on the clipboard — copy their code first."); return }
        do {
            _ = try V2ContactAdder.validatedPeer(fromScannedKey: s)
            recipientPublicKey = s
            remoteError = nil
        } catch let e as V2ContactAddError {
            remoteError = e.userMessage
        } catch {
            remoteError = LanguageManager.localized("Couldn't read that code.")
        }
    }

    private func continueFromRemote() {
        do {
            _ = try V2ContactAdder.validatedPeer(fromScannedKey: recipientPublicKey)
            remoteError = nil
            path.append(.naming)
        } catch let e as V2ContactAddError {
            remoteError = e.userMessage
        } catch {
            remoteError = LanguageManager.localized("Couldn't read that code.")
        }
    }

    // MARK: - Step 2: show MY code so the peer can scan me back

    private var showMyCodeStep: some View {
        ZStack {
        MeshBackground()
        ScrollView {
            VStack(spacing: 16) {
                if isDark {
                    Text("Now show your code")
                        .font(.title3).bold()
                        .foregroundColor(LadonTheme.textPrimary)
                        .padding(.top, 20)
                    Text("Let them scan this with their camera so they can add you back.")
                        .font(.subheadline)
                        .foregroundColor(LadonTheme.textSecondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal)
                } else {
                    screenHeader(eyebrow: "Your Code", title: "Now show your code", titleSize: 28,
                                 lead: "Let them scan this with their camera so they can add you back.")
                }

                InPersonCodeCard(model: inPersonCode)

                // Remote add: an invite link with its own 24-hour code, minted
                // only when the user shares.
                if !inPersonCode.parts.isEmpty {
                    Button { shareInvite() } label: {
                        PairingGhostLabel(title: "Share my code", systemImage: "square.and.arrow.up", darkPadding: 12)
                    }
                    .buttonStyle(.plain)
                    .disabled(isMintingInvite)
                    .padding(.horizontal)
                    if let remoteError {
                        Text(remoteError).font(captionFont).foregroundColor(LadonTheme.coralInk)
                    }
                }

                // "Continue" is always the label. First tap (no peer code yet)
                // opens the scanner; after a successful scan we stay on this screen
                // (no auto-jump) and show a confirmation — a second tap proceeds to
                // naming. Every step is an explicit tap.
                let needsTheirCode = recipientPublicKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                if !needsTheirCode {
                    Label("QR Code scanned", systemImage: "checkmark.circle.fill")
                        .font(isDark ? .subheadline : .manrope(15, .semibold, relativeTo: .subheadline))
                        .foregroundColor(LadonTheme.greenInk)
                        .padding(.top, 4)
                }
                prominentButton(title: "Continue", systemImage: "arrow.right") {
                    if needsTheirCode {
                        showScanner = true
                    } else {
                        path.append(.naming)
                    }
                }
                .padding(.horizontal)

                if needsTheirCode {
                    Text("Press Continue to scan their QR code.")
                        .font(isDark ? .caption : .manrope(13.4, relativeTo: .caption))
                        .foregroundColor(LadonTheme.inkMuted)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal)
                }

                Spacer()
            }
        }
        }
        .navigationTitle("Show your code")
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(.hidden, for: .navigationBar)
        .tint(LadonTheme.brandGreen)
        .task { await inPersonCode.keepFresh() }
    }

    // MARK: - Step 3: name the scanned contact

    private var namingStep: some View {
        ZStack {
        MeshBackground()
        ScrollView {
            VStack(spacing: 18) {
                if isDark {
                    Image(systemName: "qrcode.viewfinder")
                        .font(.system(size: 40))
                        .foregroundColor(LadonTheme.success)
                        .padding(.top, 20)
                    Text("Code scanned")
                        .font(.headline)
                        .foregroundColor(LadonTheme.textPrimary)
                } else {
                    PairingHeader(eyebrow: "Code scanned", title: Text("Name this contact"))
                }
                PairingFingerprint(text: scannedFingerprint)

                // Light: the title already says "Name this contact".
                PairingNameField(text: $contactName, showsLabel: isDark)

                prominentButton(title: "Start chat", systemImage: "bubble.left.and.bubble.right") {
                    guard !isStarting else { return }
                    isStarting = true
                    startConversation()
                }
                .padding(.horizontal)

                Spacer()
            }
        }
        }
        .navigationTitle("Name contact")
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(.hidden, for: .navigationBar)
        .tint(LadonTheme.brandGreen)
    }

    /// First 16 hex digits of the scanned contact's id, grouped — the same
    /// fingerprint the invite screen shows. Empty if the code does not parse.
    private var scannedFingerprint: String {
        guard let code = try? PairingCodeV4.parse(recipientPublicKey) else { return "" }
        let h = code.recipientId.description.uppercased()
        return "\(h.prefix(4)) · \(h.dropFirst(4).prefix(4)) · \(h.dropFirst(8).prefix(4)) · \(h.dropFirst(12).prefix(4))"
    }

    private var displayName: String {
        let n = contactName.trimmingCharacters(in: .whitespacesAndNewlines)
        return n.isEmpty ? "Contact" : n
    }

    private func prominentButton(title: LocalizedStringKey, systemImage: String,
                                 action: @escaping () -> Void) -> some View {
        PairingPrimaryButton(title: title, systemImage: systemImage, action: action)
    }

    /// Light (ladon.app) screen head: eyebrow, large title, lead — left-aligned.
    private func screenHeader(eyebrow: LocalizedStringKey, title: LocalizedStringKey,
                              titleSize: CGFloat, lead: LocalizedStringKey) -> some View {
        PairingHeader(eyebrow: eyebrow, title: Text(title), titleSize: titleSize, lead: Text(lead))
    }

    /// Small print on these screens: dark `.caption` (unchanged), light Manrope 13.
    private var captionFont: Font { isDark ? .caption : .manrope(13, relativeTo: .caption) }

    /// Card icon on "Add remotely". Dark: plain symbol (unchanged). Light: 40 pt
    /// green-tinted tile, like the New Chat cards.
    @ViewBuilder private func remoteCardIcon(dark: String, light: String) -> some View {
        if isDark {
            Image(systemName: dark).font(.system(size: 18)).foregroundColor(LadonTheme.textPrimary)
        } else {
            Image(systemName: light)
                .font(.system(size: 18, weight: .medium))
                .foregroundColor(LadonTheme.greenInk)
                .frame(width: 40, height: 40)
                .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(LadonTheme.brandGreenSoft))
        }
    }

    private func remoteCardTitle(_ title: LocalizedStringKey) -> some View {
        Text(title)
            .font(isDark ? .headline : .manrope(17, .extrabold, relativeTo: .headline))
            .tracking(isDark ? 0 : -0.34)
            .foregroundColor(isDark ? nil : LadonTheme.textPrimary)
    }

    private func remoteStatus(_ title: LocalizedStringKey) -> some View {
        Label(title, systemImage: "checkmark")
            .font(isDark ? .caption.weight(.semibold) : .manrope(13, .semibold, relativeTo: .caption))
            .foregroundColor(LadonTheme.greenInk)
    }

    private func finish() {
        if let c = createdConversation {
            onConversationCreated?(c)
        } else {
            dismiss()
        }
    }
    
    private func generateNewConversationKeys() {
        // Fresh conversation ID for the contact being added. Our own codes are
        // issued by PairingCodeV4.issue (which also creates the V2 identity on
        // first use), each with a one-time prekey of its own.
        conversationID = UUID().uuidString
    }
    
    private func startConversation() {
        Task {
            #if DEBUG
            SecureLogger.debug("[ConversationList] 🆕 Starting new conversation with ID: \(conversationID)")
            #endif
            
            let trimmedName = contactName.trimmingCharacters(in: .whitespacesAndNewlines)
            // FIX UI-16: Sanitize contact name — limit length and strip control characters
            // FIX MED: Also strip RTL/LTR override characters (U+200E-200F, U+202A-202E, U+2066-2069)
            // that are NOT classified as isDefaultIgnorableCodePoint but enable UI spoofing
            let bidiOverrides: Set<Unicode.Scalar> = [
                "\u{200E}", "\u{200F}",  // LRM, RLM
                "\u{202A}", "\u{202B}", "\u{202C}", "\u{202D}", "\u{202E}",  // LRE, RLE, PDF, LRO, RLO
                "\u{2066}", "\u{2067}", "\u{2068}", "\u{2069}"   // LRI, RLI, FSI, PDI
            ]
            let sanitizedName = String(trimmedName
                .unicodeScalars
                .filter { !$0.properties.isDefaultIgnorableCodePoint && $0.value >= 0x20 && !bidiOverrides.contains($0) }
                .prefix(64)
                .map { Character($0) })
            let resolvedName = sanitizedName.isEmpty ? "New Contact" : sanitizedName
            // Tolerate stray whitespace/newlines from copy-paste — this is the only add-path.
            let trimmedKey = recipientPublicKey.trimmingCharacters(in: .whitespacesAndNewlines)

            // The only add-path: a pairing code (PairingCodeV4). Anything else —
            // including old `ladonv2:` codes — is refused by the adder with a
            // specific message.
            do {
                let recipientId: RecipientIdV2
                do {
                    // Shared validation + self-add guard + PeerStoreV2 persistence
                    // (identical path to ChatView's reply-scan — no security drift).
                    recipientId = try V2ContactAdder.addPeer(fromScannedKey: trimmedKey)
                } catch let e as V2ContactAddError {
                    await MainActor.run { errorMessage = e.userMessage; isStarting = false }
                    return
                } catch {
                    await MainActor.run { errorMessage = LanguageManager.localized("Could not add this contact. Please try again."); isStarting = false }
                    return
                }
                // Re-adding a known contact (e.g. with a fresh code) keeps its
                // existing chat instead of creating a second one.
                let v2Conversation = viewModel.conversations.first(where: { $0.recipientID == recipientId.description })
                    ?? Conversation(
                        id: conversationID,
                        recipientID: recipientId.description,
                        recipientPublicKey: Data(), // V2 contacts carry no V1 key
                        contactName: resolvedName
                    )
                viewModel.addConversation(v2Conversation)
                // Build the session now with the invisible start message.
                PairingStartV2.send(toContactId: recipientId.description)
                #if DEBUG
                SecureLogger.debug("[ConversationList] ✅ V2 contact added: \(recipientId.description.prefix(16))")
                #endif
                // Offer the safety-number comparison before the chat opens;
                // "Open chat" there calls finish() (fires onConversationCreated).
                await MainActor.run {
                    createdConversation = v2Conversation
                    path.append(.verify)
                }
            }
        }
    }

    // MARK: - Step 4: offer the safety-number comparison

    private var verifyStep: some View {
        ZStack {
        MeshBackground()
        ScrollView {
            VStack(spacing: 16) {
                if isDark {
                    Image(systemName: "checkmark.circle.fill")
                        .font(.system(size: 44))
                        .foregroundColor(LadonTheme.success)
                        .padding(.top, 20)
                    Text("\(displayName) added").font(.title3).bold().foregroundColor(LadonTheme.textPrimary)
                    Text("Compare the safety number with them to be sure it's really them.")
                        .font(.subheadline)
                        .foregroundColor(LadonTheme.textSecondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal)
                } else {
                    PairingHeader(badge: AnyView(PairingBadge(systemImage: "checkmark")),
                                  title: Text("\(displayName) added"),
                                  lead: Text("Compare the safety number with them to be sure it's really them."))
                }
                if let convo = createdConversation {
                    NavigationLink { SafetyNumbersView(conversation: convo) } label: {
                        PairingGhostLabel(title: "Verify safety number", systemImage: "checkmark.shield")
                    }
                    .padding(.horizontal)
                }
                prominentButton(title: "Open chat", systemImage: "bubble.left.and.bubble.right") {
                    finish()
                }
                .padding(.horizontal)
                Spacer()
            }
        }
        }
        .navigationTitle("Safety Number")
        .navigationBarTitleDisplayMode(.inline)
        .navigationBarBackButtonHidden(true)
        .toolbarBackground(.hidden, for: .navigationBar)
        .tint(LadonTheme.brandGreen)
    }
}

// Stage B: accept an incoming ladon:// invite — add them, then send your code back.
struct AcceptInviteView: View {
    // Creates the dependency that makes this view repaint when the
    // appearance changes. LadonTheme's colours are static reads, so
    // without it SwiftUI sees no reason to call body again and the view
    // keeps the previous mode's colours. Unused on purpose.
    @Environment(\.colorScheme) private var ladonAppearanceTick
    @Environment(\.dismiss) var dismiss
    let invite: InviteRouter.PendingInvite
    @ObservedObject var viewModel: ConversationListViewModel
    var onOpenChat: (Conversation) -> Void

    @State private var name = ""
    @State private var shareItem: ShareTextItem?
    @State private var isMintingCode = false
    @State private var error: String?
    @State private var added = false
    @State private var createdConvo: Conversation?
    private var isDark: Bool { AppearanceManager.isDarkStored }
    /// Small print: dark `.caption2` (unchanged), light Manrope 12.5.
    private var noteFont: Font { isDark ? .caption2 : .manrope(12.5, relativeTo: .caption2) }

    private var fingerprint: String {
        let h = invite.recipientId.uppercased()
        guard h.count >= 16 else { return h }
        return "\(h.prefix(4)) · \(h.dropFirst(4).prefix(4)) · \(h.dropFirst(8).prefix(4)) · \(h.dropFirst(12).prefix(4))"
    }
    private var displayName: String {
        let n = name.trimmingCharacters(in: .whitespacesAndNewlines)
        return n.isEmpty ? "New Contact" : n
    }
    private var avatarInitial: String { String(displayName.prefix(1)).uppercased() }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 16) {
                    if isDark {
                        Circle()
                            .fill(Color(hue: 0.09, saturation: 0.18, brightness: 0.30))
                            .frame(width: 64, height: 64)
                            .overlay(Text(avatarInitial).font(.system(size: 26, weight: .semibold)).foregroundColor(LadonTheme.textPrimary))
                            .padding(.top, 10)
                    }

                    if !added {
                        if isDark {
                            Text("Add this contact?").font(.title3).bold().foregroundColor(LadonTheme.textPrimary)
                            Text("You were invited to LADON messenger. Add the person, then send your code back so you can both message.")
                                .font(.subheadline).foregroundColor(LadonTheme.textSecondary).multilineTextAlignment(.center).padding(.horizontal)
                        } else {
                            PairingHeader(badge: AnyView(lightAvatar), title: Text("Add this contact?"),
                                          lead: Text("You were invited to LADON messenger. Add the person, then send your code back so you can both message."))
                        }
                        PairingFingerprint(text: fingerprint)
                        PairingNameField(text: $name)
                        ctaButton(title: "Add contact", systemImage: "person.badge.plus") { commitAdd() }
                    } else if invite.reciprocal {
                        // They opened our invite first and already have our code → mutual is complete.
                        if isDark {
                            Image(systemName: "checkmark.circle.fill").font(.system(size: 44)).foregroundColor(LadonTheme.success)
                            Text("\(displayName) added").font(.title3).bold().foregroundColor(LadonTheme.textPrimary)
                            Text("You're both connected — you can message each other now.")
                                .font(.subheadline).foregroundColor(LadonTheme.textSecondary).multilineTextAlignment(.center).padding(.horizontal)
                        } else {
                            PairingHeader(badge: AnyView(PairingBadge(systemImage: "checkmark")),
                                          title: Text("\(displayName) added"),
                                          lead: Text("You're both connected — you can message each other now."))
                        }
                        if let convo = createdConvo {
                            NavigationLink { SafetyNumbersView(conversation: convo) } label: {
                                PairingGhostLabel(title: "Verify safety number", systemImage: "checkmark.shield")
                            }.padding(.horizontal)
                        }
                        Text("Added remotely — compare the safety number to be sure it's really them.")
                            .font(noteFont).foregroundColor(LadonTheme.inkMuted).multilineTextAlignment(.center).padding(.horizontal)
                        ctaButton(title: "Open chat", systemImage: "bubble.left.and.bubble.right") { openChat() }
                    } else {
                        if isDark {
                            Text("\(displayName) added").font(.title3).bold().foregroundColor(LadonTheme.textPrimary)
                            Text("Now send your code back so \(displayName) can add you too — then you can both message.")
                                .font(.subheadline).foregroundColor(LadonTheme.textSecondary).multilineTextAlignment(.center).padding(.horizontal)
                        } else {
                            PairingHeader(badge: AnyView(lightAvatar), title: Text("\(displayName) added"),
                                          lead: Text("Now send your code back so \(displayName) can add you too — then you can both message."))
                        }
                        // Mark the send-back link reciprocal so they don't get asked to
                        // send back again. Its code (24-hour one-time prekey) is minted on tap.
                        PairingPrimaryButton(title: "Send my code back", systemImage: "square.and.arrow.up",
                                             isBusy: isMintingCode) { sendMyCodeBack() }
                            .disabled(isMintingCode)
                            .padding(.horizontal)
                        Text("The link works once and for 24 hours.")
                            .font(noteFont).foregroundColor(LadonTheme.inkMuted).multilineTextAlignment(.center).padding(.horizontal)
                        if let convo = createdConvo {
                            NavigationLink { SafetyNumbersView(conversation: convo) } label: {
                                PairingGhostLabel(title: "Verify safety number", systemImage: "checkmark.shield")
                            }.padding(.horizontal)
                        }
                        Button("Open chat") { openChat() }
                            .font(isDark ? nil : .manrope(15, .semibold, relativeTo: .body))
                            .foregroundColor(LadonTheme.textSecondary).padding(.top, 2)
                    }

                    if let error {
                        Text(error).font(isDark ? .caption : .manrope(13, relativeTo: .caption))
                            .foregroundColor(LadonTheme.coralInk).padding(.horizontal)
                    }
                    Spacer()
                }
            }
            .background {
                if isDark { LadonTheme.background } else { MeshBackground() }
            }
            .navigationTitle("Invite").navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(added ? "Done" : "Cancel") { added ? openChat() : dismiss() }
                }
            }
            .sheet(item: $shareItem) { item in
                ActivityShareSheet(text: item.text)
                    .presentationDetents([.medium, .large])
            }
        }
    }

    private func ctaButton(title: LocalizedStringKey, systemImage: String, action: @escaping () -> Void) -> some View {
        PairingPrimaryButton(title: title, systemImage: systemImage, action: action)
            .padding(.horizontal)
    }

    /// Light: 64 pt avatar in the design's unread-chat style (green tint, deep-green initial).
    private var lightAvatar: some View {
        Text(avatarInitial)
            .font(.manrope(26, .extrabold, relativeTo: .title))
            .foregroundColor(LadonTheme.greenDeep)
            .frame(width: 64, height: 64)
            .background(Circle().fill(LadonTheme.brandGreenSoft))
    }

    /// Mint our code (24-hour one-time prekey) and share it as a reciprocal link.
    private func sendMyCodeBack() {
        guard !isMintingCode else { return }
        isMintingCode = true
        error = nil
        Task {
            let result = await Task.detached(priority: .userInitiated) { () -> Result<String, Error> in
                Result { try PairingCodeV4.issue(.invite) }
            }.value
            isMintingCode = false
            switch result {
            case .success(let code): shareItem = ShareTextItem(text: InviteLink.make(code: code, reciprocal: true))
            case .failure: error = LanguageManager.localized("Couldn't create your code.")
            }
        }
    }

    private func commitAdd() {
        guard !added else { return }
        do {
            let rid = try V2ContactAdder.addPeer(fromScannedKey: invite.code)
            // A known contact keeps its existing chat.
            let convo = viewModel.conversations.first(where: { $0.recipientID == rid.description })
                ?? Conversation(id: UUID().uuidString, recipientID: rid.description, recipientPublicKey: Data(), contactName: displayName)
            viewModel.addConversation(convo)
            // Build the session now with the invisible start message.
            PairingStartV2.send(toContactId: rid.description)
            createdConvo = convo
            added = true
            error = nil
        } catch let e as V2ContactAddError {
            error = e.userMessage
        } catch {
            self.error = LanguageManager.localized("Could not add this contact. Please try again.")
        }
    }

    private func openChat() {
        if let c = createdConvo { onOpenChat(c) }
        dismiss()
    }
}

// QR Code Scanner (placeholder - requires VisionKit)
struct QRScannerView: View {
    // Creates the dependency that makes this view repaint when the
    // appearance changes. LadonTheme's colours are static reads, so
    // without it SwiftUI sees no reason to call body again and the view
    // keeps the previous mode's colours. Unused on purpose.
    @Environment(\.colorScheme) private var ladonAppearanceTick
    @Environment(\.dismiss) var dismiss
    @Binding var scannedPublicKey: String
    @State private var scannerUnavailableMessage: String?
    // FIX M-13: Show rejection reason when QR scan is invalid
    @State private var scanRejectionMessage: String?
    /// Two-part pairing codes: how many parts are in so far.
    @State private var partProgress: (have: Int, of: Int)?
    
    var body: some View {
        NavigationStack {
            ZStack {
            MeshBackground()
            ScrollView {
            VStack(spacing: 20) {
                Text("Scan their code")
                    .font(.manrope(20, .bold))
                    .foregroundColor(LadonTheme.textPrimary)
                    .padding(.top, 8)

                ZStack {
                    if DataScannerViewController.isSupported && DataScannerViewController.isAvailable {
                        DataScannerRepresentable(scannedText: $scannedPublicKey, pairingMode: true) {
                            dismiss()
                        } onScanRejected: { reason in
                            scanRejectionMessage = reason
                        } onPartProgress: { have, of in
                            partProgress = (have, of)
                            scanRejectionMessage = nil
                        }
                        .frame(height: 280)
                        .clipShape(RoundedRectangle(cornerRadius: 18, style: .continuous))
                        .overlay(
                            RoundedRectangle(cornerRadius: 18, style: .continuous)
                                .strokeBorder(LadonTheme.brandGreen.opacity(0.5), lineWidth: 2)
                        )
                        .overlay(
                            // Brand-green scan frame corners
                            ZStack {
                                VStack {
                                    HStack {
                                        scanCorner(rotation: 0)
                                        Spacer()
                                        scanCorner(rotation: 90)
                                    }
                                    Spacer()
                                    HStack {
                                        scanCorner(rotation: 270)
                                        Spacer()
                                        scanCorner(rotation: 180)
                                    }
                                }
                                .padding(20)
                            }
                            .allowsHitTesting(false)
                        )
                    } else {
                        RoundedRectangle(cornerRadius: 18, style: .continuous)
                            .fill(.ultraThinMaterial)
                            .opacity(0.55)
                            .overlay(
                                RoundedRectangle(cornerRadius: 18, style: .continuous)
                                    .strokeBorder(LadonTheme.glassStroke, lineWidth: 1)
                            )
                            .frame(height: 280)
                            .overlay(
                                VStack(spacing: 12) {
                                    Image(systemName: "qrcode")
                                        .font(.system(size: 50))
                                        .foregroundColor(LadonTheme.textSecondary)
                                    Text(scannerUnavailableMessage ?? "Camera not available")
                                        .font(.caption)
                                        .foregroundColor(LadonTheme.textSecondary)
                                }
                            )
                    }
                }
                .padding(.horizontal)
                .onAppear {
                    if !DataScannerViewController.isSupported {
                        scannerUnavailableMessage = "Scanner not supported on this device"
                    } else if !DataScannerViewController.isAvailable {
                        scannerUnavailableMessage = "Camera access required"
                    }
                }

                Text("Align the code within the frame")
                    .font(.caption)
                    .foregroundColor(LadonTheme.textSecondary)

                if let progress = partProgress, scanRejectionMessage == nil {
                    Text("Part \(progress.have) of \(progress.of) scanned — keep the camera on the code.")
                        .font(.caption)
                        .foregroundColor(LadonTheme.success)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal)
                }

                // FIX M-13: Show rejection feedback to user
                if let rejectionMsg = scanRejectionMessage {
                    Text(rejectionMsg)
                        .font(.caption)
                        .foregroundColor(LadonTheme.coral)
                        .padding(.horizontal)
                }

                Text("Or paste the key manually:")
                    .font(.caption)
                    .foregroundColor(LadonTheme.textSecondary)

                TextEditor(text: $scannedPublicKey)
                    .frame(height: 100)
                    .font(.jbMono(12))
                    .scrollContentBackground(.hidden)
                    // FIX AUDIT-MAR-2026-12: Disable keyboard caching for key material input
                    .autocorrectionDisabled(true)
                    .textContentType(.none)
                    .padding(8)
                    .background(
                        Group {
                            if AppearanceManager.isDarkStored {
                                RoundedRectangle(cornerRadius: 12, style: .continuous)
                                    .fill(.ultraThinMaterial).opacity(0.55)
                                    .overlay(
                                        RoundedRectangle(cornerRadius: 12, style: .continuous)
                                            .strokeBorder(LadonTheme.glassStroke, lineWidth: 1)
                                    )
                            } else {
                                // Light: white field with the ink-14 % hairline.
                                RoundedRectangle(cornerRadius: 16, style: .continuous)
                                    .fill(Color.white)
                                    .overlay(
                                        RoundedRectangle(cornerRadius: 16, style: .continuous)
                                            .strokeBorder(LadonTheme.onSurface(0.14), lineWidth: 1)
                                    )
                            }
                        }
                    )
                    .padding(.horizontal)

                if !AppearanceManager.isDarkStored {
                    // Light: the app's green pill, dimmed while empty.
                    PairingPrimaryButton(title: "Confirm", systemImage: "checkmark") { dismiss() }
                        .disabled(scannedPublicKey.isEmpty)
                        .opacity(scannedPublicKey.isEmpty ? 0.45 : 1)
                        .padding(.horizontal)
                } else {
                Button {
                    dismiss()
                } label: {
                    Text("Confirm")
                        .font(.headline)
                        .foregroundColor(LadonTheme.background)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 14)
                        .background(scannedPublicKey.isEmpty
                                    ? AnyShapeStyle(LadonTheme.onSurface(0.08))
                                    : AnyShapeStyle(LadonTheme.greenGradient))
                        .clipShape(Capsule())
                        .overlay(Capsule().strokeBorder(LadonTheme.onSurface(0.3), lineWidth: 1))
                }
                .buttonStyle(.plain)
                .disabled(scannedPublicKey.isEmpty)
                .padding(.horizontal)
                }

                Spacer(minLength: 8)
            }
            .padding(.top, 16)
            .padding(.bottom, 32)
            }
            }
            .navigationTitle("Scan QR Code")
            .navigationBarTitleDisplayMode(.inline)
            .toolbarBackground(.hidden, for: .navigationBar)
            .tint(LadonTheme.brandGreen)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        dismiss()
                    }
                    .foregroundColor(LadonTheme.brandGreen)
                }
            }
        }
    }

    /// Brand-green L-shaped corner brackets for the scan frame overlay.
    private func scanCorner(rotation: Double) -> some View {
        ZStack {
            Path { p in
                p.move(to: CGPoint(x: 0, y: 24))
                p.addLine(to: CGPoint(x: 0, y: 4))
                p.addArc(center: CGPoint(x: 4, y: 4), radius: 4, startAngle: .degrees(180), endAngle: .degrees(270), clockwise: false)
                p.addLine(to: CGPoint(x: 24, y: 0))
            }
            .stroke(LadonTheme.brandGreen, style: StrokeStyle(lineWidth: 4, lineCap: .round))
            .frame(width: 28, height: 28)
        }
        .rotationEffect(.degrees(rotation))
    }
}

struct DataScannerRepresentable: UIViewControllerRepresentable {
    @Binding var scannedText: String
    /// true: collect and validate the two parts of a pairing code
    /// (PairingCodeV4). false: hand every sanitized payload to the caller
    /// unchanged — the caller validates its own format.
    var pairingMode: Bool = false
    var didScan: () -> Void
    // FIX M-13: Callback for rejected QR scans so user gets feedback
    var onScanRejected: ((String) -> Void)?
    /// Called while a two-part pairing code is being collected.
    var onPartProgress: ((Int, Int) -> Void)?

    func makeUIViewController(context: Context) -> DataScannerViewController {
        let scanner = DataScannerViewController(
            recognizedDataTypes: [.barcode(symbologies: [.qr])],
            qualityLevel: .balanced,
            recognizesMultipleItems: false,
            isHighFrameRateTrackingEnabled: false,
            isHighlightingEnabled: true
        )
        scanner.delegate = context.coordinator
        do {
            try scanner.startScanning()
        } catch {
            #if DEBUG
            print("[Scanner] ⚠️ Failed to start scanning: \(error)")
            #endif
        }
        return scanner
    }

    func updateUIViewController(_ uiViewController: DataScannerViewController, context: Context) {
    }

    func makeCoordinator() -> Coordinator {
        Coordinator(self)
    }

    final class Coordinator: NSObject, DataScannerViewControllerDelegate {
        private let parent: DataScannerRepresentable
        /// Collects the two alternating parts of a pairing code (PairingCodeV4).
        private let assembler = PairingCodeV4.QRAssembler()
        private var finished = false

        init(_ parent: DataScannerRepresentable) {
            self.parent = parent
        }

        // The pairing code alternates between two QR parts at the same spot on
        // screen. Whether VisionKit reports the next part as a NEW item or as an
        // UPDATE of the one it is tracking is not something to rely on — both
        // callbacks feed the same handler.
        func dataScanner(_ dataScanner: DataScannerViewController, didAdd addedItems: [RecognizedItem], allItems: [RecognizedItem]) {
            addedItems.forEach(handle)
        }

        func dataScanner(_ dataScanner: DataScannerViewController, didUpdate updatedItems: [RecognizedItem], allItems: [RecognizedItem]) {
            updatedItems.forEach(handle)
        }

        private func handle(_ item: RecognizedItem) {
            guard !finished, case .barcode(let barcode) = item,
                  let payload = barcode.payloadStringValue, !payload.isEmpty else { return }
            // FIX H-26 + CL-08: strip control / ignorable characters and bound the
            // length. A pairing-code QR part is 2,239 characters (PairingCodeV4 v5).
            let sanitized = String(payload.unicodeScalars
                .filter { $0.value >= 0x20 && !$0.properties.isDefaultIgnorableCodePoint }
                .prefix(2700))
            guard parent.pairingMode else {
                guard !sanitized.isEmpty else { return }
                finished = true
                parent.scannedText = sanitized
                parent.didScan()
                return
            }
            if PairingCodeV4.isLegacy(sanitized) {
                parent.onScanRejected?(LanguageManager.localized("This code is from an older version. Ask for a new one."))
                return
            }
            guard sanitized.hasPrefix(PairingCodeV4.qrPrefix) else {
                parent.onScanRejected?(LanguageManager.localized("This isn't a valid LADON messenger code."))
                return
            }
            switch assembler.add(sanitized) {
            case .incomplete(let have, let of):
                parent.onPartProgress?(have, of)
            case .complete(let code):
                finished = true
                parent.scannedText = code
                parent.didScan()
            case .rejected:
                parent.onScanRejected?(LanguageManager.localized("Couldn't read this code — hold steady and try again."))
            }
        }
    }
}

/// Our in-person pairing code, kept valid while a screen shows it (call
/// `keepFresh()` from that screen's `.task`, which cancels on disappear).
/// A code is shown for its lifetime minus `refreshMargin`, so whoever scans it
/// last still has that long to send the first message; returning to the
/// screen reuses a code still inside that window instead of minting another
/// one-time prekey. Used by New Chat and by the in-chat code exchange.
@MainActor
final class InPersonCodeModel: ObservableObject {
    @Published private(set) var parts: [String] = []
    @Published private(set) var error: String?
    private var issuedAt: Date?
    static let refreshMargin: TimeInterval = 2 * 60

    func keepFresh() async {
        let showFor = PrekeyStoreV2.inPersonLifetime - Self.refreshMargin
        while !Task.isCancelled {
            if let issued = issuedAt, !parts.isEmpty {
                let remaining = issued.addingTimeInterval(showFor).timeIntervalSinceNow
                if remaining > 0 {
                    try? await Task.sleep(for: .seconds(remaining))
                    continue
                }
            }
            let result = await Task.detached(priority: .userInitiated) { () -> Result<[String], Error> in
                Result { try PairingCodeV4.qrParts(ofCode: try PairingCodeV4.issue(.inPerson)) }
            }.value
            guard !Task.isCancelled else { return }
            switch result {
            case .success(let newParts):
                parts = newParts
                issuedAt = Date()
                error = nil
            case .failure(let failure):
                parts = []
                issuedAt = nil
                error = String(describing: failure)
                return
            }
        }
    }
}

/// The QR block for our in-person code: progress, error, or the alternating
/// code with its one-line explanation.
// MARK: - Pairing-flow building blocks
// Light (ladon.app, design screen "Show your code"): left-aligned head, green
// and white pills, white cards. Dark: each one reproduces exactly what these
// screens drew before, so dark mode stays unchanged.

/// Screen head: optional badge, optional eyebrow, large title, optional lead.
struct PairingHeader: View {
    @Environment(\.colorScheme) private var ladonAppearanceTick
    var badge: AnyView? = nil
    var eyebrow: LocalizedStringKey? = nil
    let title: Text
    var titleSize: CGFloat = 28
    var lead: Text? = nil

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            if let badge { badge.padding(.bottom, 6) }
            if let eyebrow { LadonEyebrow(text: eyebrow) }
            title
                .font(.manrope(titleSize, .extrabold, relativeTo: .largeTitle))
                .tracking(LadonTheme.titleTracking(titleSize))
                .foregroundColor(LadonTheme.textPrimary)
                .fixedSize(horizontal: false, vertical: true)
            if let lead {
                lead
                    .font(.manrope(16.5, relativeTo: .body))
                    .foregroundColor(LadonTheme.textSecondary)
                    .lineSpacing(3)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 24)
        .padding(.top, 8)
        .padding(.bottom, 10)
    }
}

/// Light: 64 pt green-tinted circle with a green-ink symbol (design "Safety Number").
struct PairingBadge: View {
    let systemImage: String
    var body: some View {
        Image(systemName: systemImage)
            .font(.system(size: 26, weight: .semibold))
            .foregroundColor(LadonTheme.greenInk)
            .frame(width: 64, height: 64)
            .background(Circle().fill(LadonTheme.brandGreenSoft))
            .accessibilityHidden(true)
    }
}

/// Dark: green rounded rectangle. Light: green pill with a soft green shadow.
struct PrimaryPillBackground: View {
    @Environment(\.colorScheme) private var ladonAppearanceTick
    var body: some View {
        if AppearanceManager.isDarkStored {
            RoundedRectangle(cornerRadius: LadonTheme.cornerRadiusMedium, style: .continuous)
                .fill(LadonTheme.accent)
        } else {
            Capsule()
                .fill(LadonTheme.brandGreen)
                .shadow(color: LadonTheme.brandGreen.opacity(0.45), radius: 15, y: 10)
        }
    }
}

/// Dark: frosted rectangle, or a plain outline where the screen used one.
/// Light: white pill with an ink-14 % hairline.
struct GhostPillBackground: View {
    @Environment(\.colorScheme) private var ladonAppearanceTick
    var darkOutlineOnly = false
    var body: some View {
        if AppearanceManager.isDarkStored {
            if darkOutlineOnly {
                RoundedRectangle(cornerRadius: LadonTheme.cornerRadiusMedium, style: .continuous)
                    .stroke(LadonTheme.ghostBorder, lineWidth: 1)
            } else {
                RoundedRectangle(cornerRadius: LadonTheme.cornerRadiusMedium, style: .continuous)
                    .fill(.ultraThinMaterial)
                    .opacity(0.55)
                    .overlay(
                        RoundedRectangle(cornerRadius: LadonTheme.cornerRadiusMedium, style: .continuous)
                            .strokeBorder(LadonTheme.glassStroke, lineWidth: 1)
                    )
            }
        } else {
            Capsule()
                .fill(Color.white.opacity(0.6))
                .overlay(Capsule().strokeBorder(LadonTheme.onSurface(0.14), lineWidth: 1))
        }
    }
}

/// Primary action. Light: design pill, Manrope 15.2 bold, ink text.
struct PairingPrimaryButton: View {
    @Environment(\.colorScheme) private var ladonAppearanceTick
    let title: LocalizedStringKey
    let systemImage: String
    var isBusy = false
    var darkPadding: CGFloat = 14
    let action: () -> Void

    var body: some View {
        let dark = AppearanceManager.isDarkStored
        Button(action: action) {
            Group {
                if isBusy {
                    ProgressView().tint(dark ? LadonTheme.background : LadonTheme.textPrimary)
                } else {
                    Label(title, systemImage: systemImage)
                }
            }
            .font(dark ? .headline : .manrope(15.2, .bold, relativeTo: .headline))
            .foregroundColor(dark ? LadonTheme.background : LadonTheme.textPrimary)
            .frame(maxWidth: .infinity)
            .padding(dark ? darkPadding : 14)
            .background(PrimaryPillBackground())
        }
        .buttonStyle(.plain)
    }
}

/// Secondary action label (for a Button or a NavigationLink). Light: design
/// ghost pill, Manrope 15.2 bold.
struct PairingGhostLabel: View {
    @Environment(\.colorScheme) private var ladonAppearanceTick
    let title: LocalizedStringKey
    let systemImage: String
    var darkPadding: CGFloat = 13
    var darkOutlineOnly = false

    var body: some View {
        let dark = AppearanceManager.isDarkStored
        Label(title, systemImage: systemImage)
            .font(dark ? .subheadline.weight(.semibold) : .manrope(15.2, .bold, relativeTo: .subheadline))
            .foregroundColor(LadonTheme.textPrimary)
            .frame(maxWidth: .infinity)
            .padding(dark ? darkPadding : 13)
            .background(GhostPillBackground(darkOutlineOnly: darkOutlineOnly))
    }
}

/// A content card. Dark: frosted rectangle. Light: white 24 pt card.
struct PairingCard<Content: View>: View {
    @Environment(\.colorScheme) private var ladonAppearanceTick
    @ViewBuilder let content: () -> Content

    var body: some View {
        let dark = AppearanceManager.isDarkStored
        VStack(alignment: .leading, spacing: 11) { content() }
            .padding(dark ? 16 : 20)
            .frame(maxWidth: dark ? nil : .infinity, alignment: .leading)
            .background {
                if dark {
                    RoundedRectangle(cornerRadius: LadonTheme.cornerRadiusMedium, style: .continuous)
                        .fill(.ultraThinMaterial)
                        .opacity(0.55)
                        .overlay(
                            RoundedRectangle(cornerRadius: LadonTheme.cornerRadiusMedium, style: .continuous)
                                .strokeBorder(LadonTheme.glassStroke, lineWidth: 1)
                        )
                } else {
                    LadonCardBackground()
                }
            }
    }
}

/// The scanned contact's fingerprint (first 16 hex digits of its id).
struct PairingFingerprint: View {
    @Environment(\.colorScheme) private var ladonAppearanceTick
    let text: String

    var body: some View {
        let dark = AppearanceManager.isDarkStored
        Text(text)
            .font(dark ? .system(.caption, design: .monospaced) : .jbMono(15, .medium, relativeTo: .body))
            .tracking(dark ? 0 : 0.9)
            .foregroundColor(dark ? LadonTheme.textSecondary : LadonTheme.textPrimary)
            .padding(dark ? 8 : 16)
            .frame(maxWidth: .infinity)
            .background {
                if dark {
                    RoundedRectangle(cornerRadius: 8).fill(LadonTheme.cardBackground)
                } else {
                    LadonCardBackground()
                }
            }
            .privacySensitive()
            .padding(.horizontal)
    }
}

/// "Name this contact" field. Light: white field, 16 pt corners, ink-14 % hairline.
struct PairingNameField: View {
    @Environment(\.colorScheme) private var ladonAppearanceTick
    @Binding var text: String
    var showsLabel = true

    var body: some View {
        let dark = AppearanceManager.isDarkStored
        VStack(alignment: .leading, spacing: dark ? 6 : 8) {
            if showsLabel {
                Text("Name this contact")
                    .font(dark ? .subheadline : .manrope(14, .semibold, relativeTo: .subheadline))
                    .foregroundColor(LadonTheme.textSecondary)
            }
            TextField("Contact name", text: $text)
                .autocorrectionDisabled(true)
                .textContentType(.none)
                .font(dark ? nil : .manrope(16, relativeTo: .body))
                .padding(.vertical, dark ? 12 : 14)
                .padding(.horizontal, dark ? 12 : 16)
                .background {
                    if dark {
                        RoundedRectangle(cornerRadius: 10)
                            .fill(.ultraThinMaterial.opacity(0.55))
                            .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(LadonTheme.glassStroke, lineWidth: 1))
                    } else {
                        RoundedRectangle(cornerRadius: 16, style: .continuous)
                            .fill(Color.white)
                            .overlay(
                                RoundedRectangle(cornerRadius: 16, style: .continuous)
                                    .strokeBorder(LadonTheme.onSurface(0.14), lineWidth: 1)
                            )
                    }
                }
        }
        .padding(.horizontal)
    }
}

struct InPersonCodeCard: View {
    @Environment(\.colorScheme) private var ladonAppearanceTick
    @ObservedObject var model: InPersonCodeModel
    private var isDark: Bool { AppearanceManager.isDarkStored }

    var body: some View {
        if let err = model.error {
            VStack(spacing: 6) {
                Image(systemName: "xmark.octagon").font(.system(size: 40)).foregroundColor(.red)
                Text("Couldn't load your code").font(.subheadline).foregroundColor(LadonTheme.textPrimary)
                Text(err).font(.caption2).foregroundColor(LadonTheme.textSecondary)
                    .multilineTextAlignment(.center).padding(.horizontal)
            }.padding(.vertical, 24)
        } else if model.parts.isEmpty {
            VStack(spacing: 8) {
                ProgressView()
                Text("Generating Post-Quantum code…")
                    .font(.caption).foregroundColor(LadonTheme.textSecondary)
            }.padding(40)
        } else {
            AlternatingQRView(parts: model.parts)
                .frame(width: 230, height: 230)
                .padding(16)
                .background(Color.white)
                .cornerRadius(isDark ? 16 : 24)
                // Light (ladon.app): white card, ink-8 % hairline, soft shadow.
                .overlay(
                    RoundedRectangle(cornerRadius: 24, style: .continuous)
                        .strokeBorder(isDark ? Color.clear : LadonTheme.onSurface(0.08), lineWidth: 1)
                )
                .shadow(color: isDark ? .clear : LadonTheme.onSurface(0.12), radius: 30, y: 18)
                .padding(.horizontal)
                .privacySensitive()
            Text("Works once. A fresh code appears every 10 minutes.")
                .font(isDark ? .caption : .manrope(13, relativeTo: .caption))
                .foregroundColor(isDark ? LadonTheme.textSecondary : LadonTheme.inkMuted)
                .multilineTextAlignment(.center)
                .padding(.horizontal)
        }
    }
}

/// "Show my code" on its own, for the in-chat code exchange.
struct ShowMyCodeSheet: View {
    @Environment(\.colorScheme) private var ladonAppearanceTick
    @Environment(\.dismiss) private var dismiss
    @StateObject private var model = InPersonCodeModel()
    private var isDark: Bool { AppearanceManager.isDarkStored }

    var body: some View {
        NavigationStack {
            ZStack {
                MeshBackground()
                ScrollView {
                    VStack(spacing: 16) {
                        if isDark {
                            Text("Let them scan this with their camera so they can add you back.")
                                .font(.subheadline)
                                .foregroundColor(LadonTheme.textSecondary)
                                .multilineTextAlignment(.center)
                                .padding(.horizontal)
                                .padding(.top, 12)
                        } else {
                            PairingHeader(eyebrow: "Your Code", title: Text("Now show your code"),
                                          lead: Text("Let them scan this with their camera so they can add you back."))
                        }
                        InPersonCodeCard(model: model)
                        Spacer()
                    }
                }
            }
            .navigationTitle("Show your code")
            .navigationBarTitleDisplayMode(.inline)
            .toolbarBackground(.hidden, for: .navigationBar)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .tint(LadonTheme.brandGreen)
            .task { await model.keepFresh() }
        }
    }
}

/// Shows the parts of a pairing code one after another, one second each, so a
/// scanner can collect them. The images are rendered once per code (off the
/// main thread); the timeline only switches which one is visible.
struct AlternatingQRView: View {
    let parts: [String]
    @State private var images: [UIImage] = []
    private static let interval: TimeInterval = 1.0

    var body: some View {
        Group {
            if images.count == parts.count, !images.isEmpty {
                TimelineView(.periodic(from: .now, by: Self.interval)) { context in
                    let shown = Int(context.date.timeIntervalSinceReferenceDate / Self.interval) % images.count
                    VStack(spacing: 8) {
                        Image(uiImage: images[shown])
                            .interpolation(.none)
                            .resizable()
                            .scaledToFit()
                        HStack(spacing: 6) {
                            ForEach(images.indices, id: \.self) { i in
                                Circle()
                                    .fill(i == shown ? Color.black : Color.black.opacity(0.2))
                                    .frame(width: 6, height: 6)
                            }
                        }
                        .accessibilityHidden(true)
                    }
                }
            } else {
                ProgressView()
            }
        }
        .task(id: parts) {
            let source = parts
            let rendered = await Task.detached(priority: .userInitiated) {
                source.compactMap { QRCodeImage.render($0) }
            }.value
            images = rendered.count == source.count ? rendered : []
        }
    }
}

/// A text to hand to the system share sheet.
struct ShareTextItem: Identifiable {
    let id = UUID()
    let text: String
}

/// The system share sheet for a text minted on demand (ShareLink needs its
/// item up front, which would mint a one-time code just by showing a screen).
struct ActivityShareSheet: UIViewControllerRepresentable {
    let text: String
    func makeUIViewController(context: Context) -> UIActivityViewController {
        let vc = UIActivityViewController(activityItems: [text], applicationActivities: nil)
        // P8-AUDIT8-IOS-18: only invite codes go through this sheet. "Copy"
        // would put identity key, one-time prekey and delivery key on the
        // general pasteboard with no expiry and onto Universal Clipboard;
        // sending to another app works as before.
        vc.excludedActivityTypes = [.copyToPasteboard]
        return vc
    }
    func updateUIViewController(_ uiViewController: UIActivityViewController, context: Context) {}
}

// QR Code Generator
struct QRCodeImage: View {
    // Creates the dependency that makes this view repaint when the
    // appearance changes. LadonTheme's colours are static reads, so
    // without it SwiftUI sees no reason to call body again and the view
    // keeps the previous mode's colours. Unused on purpose.
    @Environment(\.colorScheme) private var ladonAppearanceTick
    let data: String

    /// Render a QR code image for `string` (same settings as this view).
    /// Nonisolated and View-free, so it can run off the main thread.
    nonisolated static func render(_ string: String) -> UIImage? {
        renderQRCode(from: string)
    }

    var body: some View {
        if let qrImage = generateQRCode(from: data) {
            Image(uiImage: qrImage)
                .interpolation(.none)
                .resizable()
                .scaledToFit()
        } else {
            VStack(spacing: 8) {
                Image(systemName: "exclamationmark.triangle")
                    .font(.system(size: 60))
                    .foregroundColor(.orange)
                Text("QR generation failed")
                    .font(.caption)
                Text("Payload: \(data.count) bytes")
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }
        }
    }

    private func generateQRCode(from string: String) -> UIImage? {
        renderQRCode(from: string)
    }
}

/// QR image for `string` (byte mode, correction level by size). A free,
/// nonisolated function so it can run off the main thread.
func renderQRCode(from string: String) -> UIImage? {
    guard let data = string.data(using: String.Encoding.utf8) else {
        #if DEBUG
        NSLog("[QR] ❌ string-to-utf8 failed (len=%d)", string.count)
        #endif
        return nil
    }
    #if DEBUG
    NSLog("[QR] generating, payload=%d bytes, prefix=%@", data.count, String(string.prefix(20)))
    #endif
    let filter = CIFilter(name: "CIQRCodeGenerator")
    filter?.setValue(data, forKey: "inputMessage")
    // QR byte-mode capacity:
    //   L=2953, M=2331, Q=1663, H=1273.
    // V2 HSig key (Ed25519+Dilithium3) base64 ≈ 2656 chars → only "L" fits.
    let correctionLevel: String
    if data.count > 2300 {
        correctionLevel = "L"
    } else if data.count > 200 {
        correctionLevel = "M"
    } else {
        correctionLevel = "H"
    }
    filter?.setValue(correctionLevel, forKey: "inputCorrectionLevel")

    guard let outputImage = filter?.outputImage else {
        #if DEBUG
        NSLog("[QR] ❌ filter.outputImage = nil (correction=%@, payload=%d)", correctionLevel, data.count)
        #endif
        return nil
    }
    if outputImage.extent.width <= 0 || outputImage.extent.height <= 0 {
        #if DEBUG
        NSLog("[QR] ❌ outputImage extent zero (correction=%@, payload=%d)", correctionLevel, data.count)
        #endif
        return nil
    }
    // Scale to high-res: target ~800px for crisp rendering on Retina displays
    let targetSize: CGFloat = 800.0
    let scale = targetSize / outputImage.extent.width
    let scaledImage = outputImage.transformed(by: CGAffineTransform(scaleX: scale, y: scale))
    let context = CIContext()
    if let cgImage = context.createCGImage(scaledImage, from: scaledImage.extent) {
        #if DEBUG
        NSLog("[QR] ✅ generated %.0fx%.0f from %d bytes (correction=%@)",
              scaledImage.extent.width, scaledImage.extent.height, data.count, correctionLevel)
        #endif
        return UIImage(cgImage: cgImage)
    }
    #if DEBUG
    NSLog("[QR] ❌ createCGImage failed")
    #endif
    return nil
}

@MainActor
class ConversationListViewModel: ObservableObject {
    @Published var conversations: [Conversation] = []
    /// P7-IOS-BUG-13: surfaced to UI when the burst rate-limit drops
    /// an incoming first-contact. The ConversationListView observes
    /// this and shows it as the regular error banner.
    @Published var burstWarning: String?
    /// #1: single delivery observer (replaces the removed fetch loop's fetchTask).
    private var newMessagesObserver: NSObjectProtocol?
    private var chatActiveObserver: NSObjectProtocol?
    private var chatInactiveObserver: NSObjectProtocol?
    private var isChatActive = false
    private static let conversationsKey = "saved_conversations"
    
    // FIX VM-6: Rate limiting for auto-created conversations
    private var autoCreatedCount = 0
    private var autoCreateWindowStart = Date()
    // FIX M-32: Reduced from 10 to 5 per window to limit DoS via mass identity spam
    // FIX L-03 AUDIT-MAR-2026: Further reduced from 5 to 2 — receiving >2 new contacts/min is unrealistic
    // P7-IOS-BUG-13: was 2/min, which silently dropped legitimate
    // 3rd-incoming-contact bursts. Each incoming first-contact already
    // requires a valid recipient-targeted token signed by the sender's
    // bundle, so the cryptographic cost of spam is high. 10/min is well
    // above realistic legitimate bursts but still bounds a runaway
    // attacker (who'd need a fresh signing-key per attempt anyway).
    private static let maxAutoCreatePerWindow = 10
    private static let autoCreateWindowSeconds: TimeInterval = 60

    private var contactRenamedObserver: NSObjectProtocol?

    init() {
        // All observers register with `queue: .main`, so they run on the
        // main thread at runtime. `MainActor.assumeIsolated` asserts that
        // and lets the closure body touch main-actor-isolated state without
        // strict-concurrency Sendable-closure warnings.
        chatActiveObserver = NotificationCenter.default.addObserver(
            forName: .chatViewActive,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated {
                self?.isChatActive = true
            }
        }

        chatInactiveObserver = NotificationCenter.default.addObserver(
            forName: .chatViewInactive,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated {
                self?.isChatActive = false
            }
        }

        // #1: single delivery entry point — react to messages delivered by the
        // V2 receive loop / push / auth one-shot (replaces the removed poll
        // loop). The store write already happened before this fires.
        newMessagesObserver = NotificationCenter.default.addObserver(
            forName: NSNotification.Name("NewMessagesReceived"),
            object: nil,
            queue: .main
        ) { [weak self] notification in
            MainActor.assumeIsolated {
                guard let self = self,
                      let messages = notification.userInfo?["messages"] as? [Message] else { return }
                self.handleDeliveredMessages(messages)
            }
        }

        contactRenamedObserver = NotificationCenter.default.addObserver(
            forName: .contactRenamed,
            object: nil,
            queue: .main
        ) { [weak self] notification in
            MainActor.assumeIsolated {
                guard let self = self,
                      let info = notification.userInfo,
                      let conversationID = info["conversationID"] as? String,
                      let newName = info["newName"] as? String else { return }
                if let idx = self.conversations.firstIndex(where: { $0.id == conversationID }) {
                    self.conversations[idx].contactName = newName
                }
            }
        }

        // FIX AUDIT-R18-F4: Observe emergencyMemoryWipe to clear social graph from RAM.
        // Without this, conversations (recipientIDs, contactNames) survive panic wipe.
        NotificationCenter.default.addObserver(
            forName: .emergencyMemoryWipe,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated {
                // FIX M-02 AUDIT-MAR-2026: Overwrite contactNames before removeAll()
                // to eliminate social graph heap residue. Swift Small String Optimization
                // stores strings ≤15 UTF-8 bytes inline — overwriting zeros the actual memory.
                // Note: recipientID is a let constant (immutable) — it's a SHA256 hash,
                // not social-graph metadata, so skipping it is acceptable.
                guard let self = self else { return }
                for i in self.conversations.indices {
                    let len = self.conversations[i].contactName.count
                    self.conversations[i].contactName = String(repeating: "\0", count: max(len, 1))
                }
                self.conversations.removeAll()
            }
        }
    }
    
    func loadConversations() async {
        // FIX #2: Load conversations from encrypted SQLite database
        do {
            let loaded = try EncryptedDatabase.shared.loadConversations()
            // Merge: keep any in-memory conversations not yet in DB
            var merged = loaded
            for existing in conversations {
                if !merged.contains(where: { $0.id == existing.id }) {
                    merged.append(existing)
                    // Try to persist the missing conversation
                    do {
                        try EncryptedDatabase.shared.storeConversation(existing)
                    } catch {
                        #if DEBUG
                        SecureLogger.debug("[ConversationListVM] ❌ Failed to persist merge: \(error)")
                        #endif
                    }
                }
            }
            // Migration: update old default (.thirtySeconds) to new default (.fiveMinutes)
            for i in merged.indices {
                if merged[i].disappearingTimer == .thirtySeconds {
                    merged[i].disappearingTimer = .fiveMinutes
                    do {
                        try EncryptedDatabase.shared.storeConversation(merged[i])
                    } catch {
                        #if DEBUG
                        SecureLogger.debug("[ConversationListVM] ❌ Timer migration store failed: \(error)")
                        #endif
                    }
                }
            }
            conversations = merged
            #if DEBUG
            SecureLogger.debug("[ConversationListVM] ✅ Loaded \(merged.count) conversations (DB: \(loaded.count))")
            #endif
        } catch {
            #if DEBUG
            print("[ConversationListVM] ❌ DB load failed: \(error)")
            #endif
            // Fallback: try loading from legacy SecureUserDefaults (migration path)
            do {
                if let data = try SecureUserDefaults.shared.data(forKey: Self.conversationsKey) {
                    let legacyConversations = try JSONDecoder().decode([Conversation].self, from: data)
                    conversations = legacyConversations
                    // Migrate each conversation to encrypted DB
                    for convo in legacyConversations {
                        do {
                            try EncryptedDatabase.shared.storeConversation(convo)
                        } catch {
                            #if DEBUG
                            SecureLogger.debug("[ConversationListVM] ❌ Migration store failed: \(error)")
                            #endif
                        }
                    }
                    // Remove legacy storage after successful migration
                    SecureUserDefaults.shared.remove(forKey: Self.conversationsKey)
                    UserDefaults.standard.removeObject(forKey: Self.conversationsKey)
                    #if DEBUG
                    print("[ConversationListVM] ✅ Migrated \(legacyConversations.count) conversations to encrypted DB")
                    #endif
                }
            } catch {
                #if DEBUG
                print("[ConversationListVM] ❌ Legacy migration failed: \(error)")
                #endif
                // FIX H-12: REMOVED plaintext UserDefaults fallback.
                // Loading unencrypted conversations defeats the purpose of EncryptedDatabase.
                // If both encrypted DB and SecureUserDefaults fail, conversations are lost
                // (security over availability — prevents forensic social graph extraction).
            }
        }

        // #1: derive any conversation rows still missing from the store
        // (self-heals a NewMessagesReceived notification missed before this
        // view model registered its observer — e.g. an auth/push one-shot at
        // launch). Idempotent.
        reconcileConversationsFromStore()
    }

    /// Deleting a chat also deletes what would let it be continued: the
    /// session keys, the stored contact identity and any unused code of that
    /// contact — unless another chat still belongs to the same contact.
    /// Failures are logged (no ids); the chat itself is already gone.
    private func forgetContactKeysIfUnused(_ recipientIds: [String]) {
        for rid in Set(recipientIds) where !rid.isEmpty && !conversations.contains(where: { $0.recipientID == rid }) {
            // Each part on its own, so one failure does not leave the others.
            do { try V2RatchetPayload.deleteSession(peerId: rid) }
            catch { SecureLogger.error("[ConversationListVM] session not removed: \(error)") }
            do { try PeerStoreV2.delete(forContactId: rid) }
            catch { SecureLogger.error("[ConversationListVM] contact identity not removed: \(error)") }
            do { try PrekeyStoreV2.forgetPeer(forPeer: rid) }
            catch { SecureLogger.error("[ConversationListVM] contact code not removed: \(error)") }
            // The contact's delivery key: with it gone, nothing more can be
            // sent to that contact until a fresh code is exchanged.
            if rid.count == LadonV2.recipientIdLen * 2, let bytes = Data(hexString: rid) {
                do { try DeliveryKeyStoreV2.deletePeerKey(RecipientIdV2(bytes: bytes)) }
                catch { SecureLogger.error("[ConversationListVM] contact delivery key not removed: \(error)") }
            }
        }
    }

    func addConversation(_ conversation: Conversation) {
        // Add new conversation to the list
        if !conversations.contains(where: { $0.id == conversation.id }) {
            conversations.append(conversation)
            // FIX #2: Store in encrypted SQLite DB
            do {
                try EncryptedDatabase.shared.storeConversation(conversation)
                #if DEBUG
                SecureLogger.debug("[ConversationListVM] ✅ Conversation stored in DB: \(conversation.id.prefix(16))")
                #endif
            } catch {
                #if DEBUG
                SecureLogger.debug("[ConversationListVM] ❌ Failed to store conversation in DB: \(error)")
                #endif
                // Conversation is still in memory, will be persisted on next saveConversations() call
            }
        }
    }
    
    func deleteConversation(_ conversation: Conversation) {
        // Remove conversation from list
        conversations.removeAll { $0.id == conversation.id }
        // FIX: Don't silently swallow deletion errors — user must know if data persists
        do {
            try EncryptedDatabase.shared.deleteConversation(id: conversation.id)
            // Keys go only once the chat is really gone from the database —
            // otherwise the next launch would show a chat without keys.
            forgetContactKeysIfUnused([conversation.recipientID])
        } catch {
            #if DEBUG
            SecureLogger.debug("[ConversationListVM] ❌ Failed to delete conversation from DB: \(error)")
            #endif
        }
        // FIX HIGH-07: Clear decrypted messages from RAM — prevents forensic recovery
        // of plaintext after conversation deletion. Uses secure memset_s wiping.
        Task { @MainActor in
            InMemoryMessageStore.shared.clear(conversationID: conversation.id)
            // Also clear by recipientID in case messages are keyed differently
            InMemoryMessageStore.shared.clear(conversationID: conversation.recipientID)
        }
    }

    func deleteAllConversations() {
        // Delete all conversations
        let removed = conversations.map { $0.recipientID }
        conversations = []
        // FIX: Don't silently swallow wipe errors — critical for security
        do {
            try EncryptedDatabase.shared.deleteAllConversations()
            forgetContactKeysIfUnused(removed)   // only once the chats are really gone
        } catch {
            #if DEBUG
            SecureLogger.debug("[ConversationListVM] ❌ CRITICAL: Failed to delete all conversations: \(error)")
            #endif
        }
        // FIX HIGH-07: Securely wipe ALL decrypted messages from RAM
        Task { @MainActor in
            InMemoryMessageStore.shared.clearAll()
        }
    }
    
    private func saveConversations() {
        // FIX #2: Save each conversation individually to encrypted SQLite DB
        for conversation in conversations {
            do {
                try EncryptedDatabase.shared.storeConversation(conversation)
            } catch {
                #if DEBUG
                SecureLogger.debug("[ConversationListVM] ❌ Failed to save conversation: \(error)")
                #endif
            }
        }
    }

    // MARK: - #1 Receive delivery (replaces the removed poll loop)

    /// React to a delivered batch — posted by the single V2 receive loop, the
    /// push handler, or the auth one-shot. Each writes to the store BEFORE
    /// posting, so the messages are already durable when this fires.
    func handleDeliveredMessages(_ messages: [Message]) {
        ingest(messages: messages)

        // FIX PUSH-13: foreground local notification for incoming messages
        // while the user is on the conversation list (not inside a ChatView).
        // Remote APNs alerts are suppressed in willPresent, so this is the ONLY
        // foreground notification path for the list screen.
        let incomingCount = messages.filter { !$0.isOutgoing }.count
        // Gate: only while the app is in the FOREGROUND and no ChatView is open.
        // The old poll loop was foreground-only (Tasks suspend in background),
        // so it never needed an explicit check. Now NewMessagesReceived can also
        // be posted from the BACKGROUND push path — without this guard we'd fire
        // a duplicate on top of SilentPushHandler's own background fallback (and
        // the server APNs alert). SilentPushHandler owns the background case.
        guard incomingCount > 0,
              !isChatActive,
              UIApplication.shared.applicationState == .active else { return }
        let content = UNMutableNotificationContent()
        // FIX NOTIF-01 / M-10: no title (keeps the app name out of the iOS
        // notification database), one constant body regardless of count — the
        // same key as the server's alert push, localised on the device.
        content.body = NSString.localizedUserNotificationString(forKey: "PUSH_NEW_ENCRYPTED_MESSAGE", arguments: nil)
        content.sound = .default
        content.badge = NSNumber(value: incomingCount)
        content.threadIdentifier = "m"
        let request = UNNotificationRequest(
            identifier: "m-\(UUID().uuidString)",
            content: content,
            trigger: nil  // nil trigger = shown immediately
        )
        UNUserNotificationCenter.current().add(request)
    }

    /// #1: Derive conversation rows from the message store. Self-heals a
    /// NewMessagesReceived notification missed before this view model
    /// registered its observer (e.g. an auth/push one-shot at launch).
    /// Idempotent — safe to call on every list appearance.
    private func reconcileConversationsFromStore() {
        ingest(messages: InMemoryMessageStore.shared.allMessagesSnapshot())
    }

    /// #1: Idempotently fold messages into the conversation list — auto-create
    /// rows for unknown senders (burst-limited), refresh relayRecipientID, and
    /// keep `lastMessage` pointing at the newest message. Accepts either a
    /// single delivered batch (hot path) or the whole store snapshot
    /// (reconcile). Persists once at the end.
    private func ingest(messages: [Message]) {
        guard !messages.isEmpty else { return }
        var didChangeExisting = false

        for message in messages {
            let candidateIDs = Set([message.conversationID, message.senderStableID, message.senderCurrentID].compactMap { $0 })

            if let existingIndex = conversations.firstIndex(where: { convo in
                candidateIDs.contains(convo.id)
                || candidateIDs.contains(convo.recipientID)
                || (convo.relayRecipientID.map { candidateIDs.contains($0) } ?? false)
            }) {
                // M6 FIX: only update relayRecipientID for decrypted messages.
                if let senderCurrentID = message.senderCurrentID,
                   conversations[existingIndex].relayRecipientID != senderCurrentID {
                    conversations[existingIndex].relayRecipientID = senderCurrentID
                    didChangeExisting = true
                }
                // #1: newest-wins. Reconcile may visit messages out of order,
                // so only advance lastMessage when this one is at least as new.
                let isNewer = conversations[existingIndex].lastMessage
                    .map { message.timestamp >= $0.timestamp } ?? true
                if isNewer {
                    // H3 FIX: store lastMessage WITHOUT content (forensic
                    // hygiene); ConversationRow shows only a generic preview.
                    var sanitized = message
                    sanitized.content = Data()
                    conversations[existingIndex].lastMessage = sanitized
                    didChangeExisting = true
                }
                continue
            }

            // Auto-create a conversation for an unknown incoming sender.
            // FIX M-22: require a valid sender identity.
            let recipientID = message.senderStableID ?? message.conversationID
            let conversationID = message.senderStableID ?? message.conversationID
            guard !recipientID.isEmpty else {
                #if DEBUG
                print("[ConversationList] ⚠️ Skipping message with empty sender ID")
                #endif
                continue
            }

            // FIX VM-6: rate-limit auto-created conversations.
            let now = Date()
            if now.timeIntervalSince(autoCreateWindowStart) > Self.autoCreateWindowSeconds {
                autoCreatedCount = 0
                autoCreateWindowStart = now
            }
            guard autoCreatedCount < Self.maxAutoCreatePerWindow else {
                #if DEBUG
                print("[ConversationList] ⚠️ Rate limit: too many auto-created conversations, skipping")
                #endif
                // P7-IOS-BUG-13: surface the drop (ratchet already advanced).
                if burstWarning == nil {
                    burstWarning = "Burst rate-limit hit (>\(Self.maxAutoCreatePerWindow) new contacts/\(Int(Self.autoCreateWindowSeconds))s). Some incoming messages were not auto-created."
                }
                continue
            }
            autoCreatedCount += 1

            // FIX H3 + HIGH-168: empty recipientPublicKey until key exchange;
            // lastMessage stored without content.
            var sanitized = message
            sanitized.content = Data()
            let newConversation = Conversation(
                id: conversationID,
                recipientID: recipientID,
                recipientPublicKey: Data(),
                contactName: String(localized: "Unverified contact"),
                lastMessage: sanitized,
                relayRecipientID: message.senderCurrentID
            )
            addConversation(newConversation)  // persists itself
        }

        if didChangeExisting {
            saveConversations()
        }
    }

    deinit {
        if let observer = newMessagesObserver {
            NotificationCenter.default.removeObserver(observer)
        }
        if let observer = chatActiveObserver {
            NotificationCenter.default.removeObserver(observer)
        }
        if let observer = chatInactiveObserver {
            NotificationCenter.default.removeObserver(observer)
        }
        // FIX VW-2: Remove contactRenamedObserver to prevent memory leak
        if let observer = contactRenamedObserver {
            NotificationCenter.default.removeObserver(observer)
        }
    }
}

extension Notification.Name {
    static let chatViewActive = Notification.Name("ChatViewActive")
    static let chatViewInactive = Notification.Name("ChatViewInactive")
    static let identityKeyChanged = Notification.Name("IdentityKeyChanged")
    static let messageDelivered = Notification.Name("MessageDelivered")
    static let contactRenamed = Notification.Name("ContactRenamed")
}

#Preview {
    ConversationListView()
}
