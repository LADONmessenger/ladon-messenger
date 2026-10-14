//
//  V2SessionManager.swift
//  Ladon — Production lifecycle manager for RelayClientV2.
//
//  Phase 2: Initialize after biometric auth.
//  Addendum A2 stage 2: run the two constant-rate lanes (LaneSchedulerV2) —
//  lane S sends, lane F fetches one envelope per tick; fetched envelopes
//  become Message → InMemoryMessageStore here.
//
//  Thread safety: all mutable state is actor-isolated.
//

import Foundation
import Security
import CryptoKit
import Network
#if canImport(UIKit)
import UIKit
#endif

/// Production manager for the V2 protocol stack.
/// Singleton per app session. All state is actor-isolated.
actor V2SessionManager {

    // MARK: - Singleton

    static let shared = V2SessionManager()
    private init() {}

    // MARK: - State

    /// The active V2 relay client. nil until initializeIfNeeded() completes.
    private(set) var client: RelayClientV2?

    /// True after a successful initialization. Guards against duplicate inits.
    private(set) var isInitialized: Bool = false

    /// Background task for geo-probe + lane start.
    private var publishTask: Task<Void, Never>?

    /// A2 stage 2: the two lanes. One scheduler for the app session; a Tor
    /// change swaps its connections, so queued sends survive it. Fetching
    /// runs only in lane F — the cadence is the same with and without an
    /// open chat (A2 §5, F3).
    let lanes = LaneSchedulerV2()

    /// The two connections of the current session (A2 stage 1): the
    /// identity connection carries lane F, the send connection lane S.
    private var identitySession: URLSession?
    private var sendSession: URLSession?

    /// Messages delivered while a catch-up burst runs, for the callers of
    /// `fetchPendingMessages()` (push wake, app start). nil = no burst waiting.
    private var burstCollector: [Message]?
    /// Control messages (START, KEY) handled while a burst caller waits.
    private var burstControlCount = 0
    private var burstCallers = 0
    private var foregroundObserverInstalled = false

    /// SOCKS endpoint (host, port) the current URLSession was built for.
    /// Rebuilt only when it changes or Tor dropped all connections.
    /// `TorStateChanged` fires on every Tor status change (28 call sites in
    /// TorController — progress, status text, verification steps). Rebuilding
    /// the session on each one cancelled the running fetch, publish and cover
    /// loops (`-999 cancelled`) although nothing had changed: measured on the
    /// 17 Pro 30.09.2026, 12 of 12 rebuilds with the same port. The session is
    /// now rebuilt only when the endpoint actually changes.
    private var sessionSocksEndpoint: String?
    /// `TorController.connectionEpoch` the session was built at: Tor dropping
    /// all connections also requires a fresh session (see there).
    private var sessionConnectionEpoch = 0
    /// True while a Tor session is built and its loops are (being) started.
    /// False after a reconfigure cancelled the loops but could not build a new
    /// session — then the next TorStateChanged rebuilds even if endpoint and
    /// epoch look unchanged (before, the loops stayed dead silently).
    private var sessionReady = false
    /// Observer for TorStateChanged installed once, also when init fails, so a
    /// later "Tor ready" can retry the initialisation.
    private var torObserverInstalled = false
    /// Coalesces concurrent initializeIfNeeded() calls (auth success, push,
    /// TorStateChanged) onto one run — the actor is re-entrant at awaits, so
    /// two calls could otherwise both pass the isInitialized guard.
    private var initTask: Task<Void, Never>?

    /// "host:port" of the SOCKS5 proxy Tor currently advertises, or nil.
    nonisolated private static func currentSocksEndpoint() -> String? {
        guard let data = TorController.loadSOCKS5ConfigFromKeychain(),
              let cfg = try? JSONDecoder().decode(SOCKS5Config.self, from: data),
              cfg.port > 0 else { return nil }
        return "\(cfg.host):\(cfg.port)"
    }

    // MARK: - Private Helpers

    /// ±20 % jitter for the local UI poll below (no network traffic).
    private static func jitteredInterval(_ baseInterval: Double) -> Double {
        let jitter = Double.random(in: 0.8...1.2)  // ±20% variance
        return baseInterval * jitter
    }

    /// Foreground UI poll cadence for the View-driven poll loops in ChatView /
    /// ConversationListView. Replaces the now-removed V1
    /// `RelayClient.currentPollingIntervalSeconds()` with no behavioural change
    /// to active-chat latency: 1.5 s base (matching the old
    /// `foregroundIntervalSeconds`), backing off to 30 s under Low Power Mode,
    /// with the same ±20% jitter the V2 loops use for timing-correlation
    /// resistance. (The legacy +2 s cellular penalty is intentionally dropped.)
    /// Local only: it re-reads the store, it sends nothing.
    static func uiPollIntervalSeconds() -> TimeInterval {
        let base: Double = ProcessInfo.processInfo.isLowPowerModeEnabled ? 30 : 1.5
        return jitteredInterval(base)
    }

    // MARK: - Public API
    /// available in Keychain (written by the Tor subsystem on connect).
    func initializeIfNeeded() async {
        guard !isInitialized else { return }
        // Install the Tor observer before any early return: if init fails
        // because Tor is not ready yet, the next TorStateChanged retries it.
        if !torObserverInstalled {
            torObserverInstalled = true
            observeTorStateChanges()
        }
        if let running = initTask {
            await running.value
            return
        }
        let task = Task { await self.performInitialization() }
        initTask = task
        await task.value
        initTask = nil
    }

    private func performInitialization() async {
        guard !isInitialized else { return }
        PrekeyStoreV2.purgeExpiredOwnNow()

        // Load exit registry from bundle with Tor-aware session for geoProbes.
        guard
            let url = Bundle.main.url(forResource: "exits-bootstrap", withExtension: "json"),
            let jsonData = try? Data(contentsOf: url),
            let registryTmp = try? ExitRegistryV2.load(from: jsonData)
        else {
            SecureLogger.error("[V2Session] exits-bootstrap.json missing or invalid — V2 stack not started")
            return
        }

        // Build Tor-aware session (will be used for probe geoProbes).
        // FIX F-V2-META-001 Teil 1: Tor fail-closed — abort init if Tor not available.
        guard let torSession = buildV2Session(requireTor: true) else {
            SecureLogger.error("[V2Session] Tor not available — V2 initialization blocked (F-V2-META-001)")
            return
        }
        sessionSocksEndpoint = Self.currentSocksEndpoint()
        sessionConnectionEpoch = TorController.connectionEpoch
        sessionReady = true

        // Recreate registry with Tor session so geoProbes go through Tor (FIX F-NET-002).
        let registry = try? await ExitRegistryV2(
            exits: registryTmp.exits,
            entries: registryTmp.entries,
            pushTarget: registryTmp.pushTarget,
            session: torSession  // F-NET-002: geoProbes now Tor-routed
        )

        // Load or generate the local V2 identity (persisted in Keychain).
        let identity: LocalIdentityV2
        do {
            identity = try IdentityStoreV2.loadOrGenerate()
        } catch {
            SecureLogger.error("[V2Session] V2 identity load/generate failed: \(error)")
            return
        }

        guard let registry = registry else {
            SecureLogger.error("[V2Session] registry init failed")
            return
        }

        RetiredTokenStateV2.remove()

        // A2 stage 1: the send connection is a second session with its own
        // Tor isolation credentials.
        guard let sendSession = buildV2Session(requireTor: true) else {
            SecureLogger.error("[V2Session] Tor not available for the send connection — V2 initialization blocked")
            sessionReady = false
            return
        }
        self.identitySession = torSession
        self.sendSession = sendSession
        let relayClient = RelayClientV2(identity: identity, registry: registry, lanes: lanes)
        self.client = relayClient
        self.isInitialized = true

        // Tor state changes are observed since the first init attempt
        // (torObserverInstalled) — subsequent requests use SOCKS5.

        // A2 §5: a catch-up burst on every return to the foreground.
        observeForeground()

        // Probe exits + start the loops in background (non-blocking).
        schedulePublish(client: relayClient)

        SecureLogger.info("[V2Session] Initialized.")
    }

    // MARK: - Startup

    /// Cancel any in-flight startup and run it again for `client`.
    private func schedulePublish(client: RelayClientV2) {
        publishTask?.cancel()
        publishTask = Task { [weak self] in
            guard !Task.isCancelled else { return }
            await self?.publishBundleOnBestExit(client: client)
        }
    }

    /// Probe all exits for latency, then start the lanes on the current
    /// connections and run a catch-up burst.
    ///
    /// No bundle is published here (Addendum A1 §4 rule 1): `published_at` is
    /// public, and publishing on every start and every 15 s exposed when the
    /// user was online. Lane F publishes on exactly those exits that
    /// report us unknown (first start, exit restart), and a rotation of the
    /// delivery key publishes everywhere.
    private func publishBundleOnBestExit(client: RelayClientV2) async {
        // P8-AUDIT5-IOS-LATENCY-2 (2026-05-22): start the loops
        // UNCONDITIONALLY, even if the probe failed (e.g. Tor circuit flake
        // during initial bootstrap) — otherwise the only recovery path was a
        // manual app relaunch.
        do {
            _ = try await client.bootstrapAndSelectExit()
        } catch {
            SecureLogger.error("[V2Session] geo-probe failed (continuing anyway): \(error)")
        }
        // Re-register the APNs token with the running client: the first upload
        // can race V2 startup. If the push relay does not know us, the
        // registration publishes our bundle and retries (registerPushTokenV2).
        await MainActor.run {
            SilentPushHandler.shared.retryPushRegistration()
        }

        // A superseded startup must not start the lanes: schedulePublish()
        // cancels this task only to run a newer one for a newer client, which
        // starts them itself (both phones, 01.10.2026: a stale client's first
        // fetch hung on the old session for the 60 s resource timeout).
        guard !Task.isCancelled else { return }
        await startLanes(client: client)
        // An unfinished block/unblock (KEY to contacts, publish) continues.
        DeliveryRotationV2.resume()
    }

    // MARK: - Lanes (Addendum A2 stage 2)

    /// Bind the lanes to `client` and the current connections and start
    /// them, then run a catch-up burst. Lane S defaults to cover, lane F to
    /// a fetch rotating over the exits (A2 §5).
    private func startLanes(client: RelayClientV2) async {
        guard let identitySession, let sendSession else { return }
        await lanes.setSources(
            cover: { await client.makeCoverJob() },
            fetch: { [weak self] in
                await client.makeFetchJob(deliver: { [weak self] envelopes, receipt in
                    await self?.deliverFetched(envelopes, receipt: receipt, client: client)
                })
            })
        await lanes.setTransports(send: SealedTransportV2(session: sendSession, clock: .sendLane),
                                  fetch: SealedTransportV2(session: identitySession, clock: .shared))
        await lanes.start()
        Task { await self.lanes.runBurst() }
    }

    /// Run a catch-up burst (A2 §5: exactly `SealedV2.catchUpBurst` fetch
    /// exchanges) and return what it delivered.
    ///
    /// Delivery (store write + `NewMessagesReceived`) happens centrally in
    /// `deliverFetched`, once per envelope. Callers MUST NOT store/post the
    /// returned messages themselves; the return value is informational only
    /// (e.g. the push `.noData` decision and the banner clean-up).
    func fetchPendingMessages() async -> [Message] {
        await fetchForWake().messages
    }

    /// `fetchPendingMessages()` plus whether the burst handled a control
    /// message — for the push handler's banner clean-up (A2 §7).
    func fetchForWake() async -> (messages: [Message], controlMessages: Int) {
        await initializeIfNeeded()
        // A push wake can come straight after Tor un-parked on a new SOCKS
        // port, before the TorStateChanged observer rebuilt the session.
        // Bring the session onto Tor's current port first (no-op if it already
        // is); while Tor has no route nothing is fetched (fail-closed — the
        // exit keeps the messages).
        await reconfigureForTorChange()
        guard sessionReady, client != nil else { return ([], 0) }
        if burstCallers == 0 { burstCollector = []; burstControlCount = 0 }
        burstCallers += 1
        await lanes.runBurst()
        burstCallers -= 1
        let delivered = (burstCollector ?? [], burstControlCount)
        if burstCallers == 0 { burstCollector = nil; burstControlCount = 0 }
        SecureLogger.torDiag("[V2] catch-up burst done: \(delivered.0.count) message(s), \(delivered.1) control")
        return delivered
    }

    /// One lane-F fetch result: convert to Message objects and deliver them to
    /// InMemoryMessageStore + UI. This is the SINGLE delivery point — the
    /// store write happens BEFORE the notification so a delivered message is
    /// durable even if a consumer fails. Then the batch is acknowledged: it
    /// goes out with the next fetch to that exit, and only then does the exit
    /// delete it. Runs inside the lane tick, so fetches never overlap.
    private func deliverFetched(_ envelopes: [OpenedInnerEnvelopeV2], receipt: FetchReceiptV2,
                                client: RelayClientV2) async {
        let (captured, controlCount, unreadable) = await messages(from: envelopes, client: client)
        if burstCollector != nil { burstControlCount += controlCount }
        if !captured.isEmpty {
            // Deliver on MainActor (InMemoryMessageStore is @MainActor).
            await MainActor.run {
                InMemoryMessageStore.shared.addMessages(captured)
                NotificationCenter.default.post(
                    name: NSNotification.Name("NewMessagesReceived"),
                    object: nil,
                    userInfo: ["messages": captured]
                )
            }
            burstCollector?.append(contentsOf: captured)
        }
        // P8-AUDIT8-IOS-01: an envelope that could not be opened because local
        // storage was unreadable must not be acknowledged — the exit would
        // delete it and the message would be gone. Without an ack the exit
        // hands the batch out again; envelopes of it that were opened are
        // dropped by the ratchet as replays. Bounded: while the device is
        // unlocked a storage error is not expected to clear by waiting, so
        // after `maxWithheldAcks` consecutive withheld fetches the batch is
        // acknowledged as before instead of blocking every later message.
        if unreadable > 0 {
            let protectedDataAvailable = await MainActor.run { UIApplication.shared.isProtectedDataAvailable }
            let withheld = (withheldAcks[receipt.exitHex] ?? 0) + 1
            if !protectedDataAvailable || withheld <= Self.maxWithheldAcks {
                withheldAcks[receipt.exitHex] = withheld
                SecureLogger.torDiag("[V2] \(unreadable) envelope(s) not opened (storage unreadable) — batch not acknowledged, exit re-delivers (\(withheld))")
                FetchAckLedgerV2.shared.commit(exitHex: receipt.exitHex, batchId: nil)
                return
            }
            SecureLogger.error("[V2] storage still unreadable after \(Self.maxWithheldAcks) re-deliveries while unlocked — \(unreadable) envelope(s) dropped")
        }
        withheldAcks[receipt.exitHex] = nil
        FetchAckLedgerV2.shared.commit(exitHex: receipt.exitHex, batchId: receipt.batchId)
    }

    /// Consecutive fetches per exit whose ack was withheld (see `deliverFetched`).
    private var withheldAcks: [String: Int] = [:]
    private static let maxWithheldAcks = 3

    /// Ratchet errors that come from local storage (Keychain), not from the
    /// frame: nothing was opened or consumed, so a later re-delivery can succeed.
    private static func isStorageError(_ error: RelayClientV2Error) -> Bool {
        switch error {
        case .ratchet(.keychain), .ratchet(.prekeyStore): return true
        default: return false
        }
    }

    /// The displayable messages among `envelopes`, how many control messages
    /// (START, KEY) were handled, and how many envelopes were left unopened
    /// because local storage was unreadable (they must not be acknowledged).
    private func messages(from envelopes: [OpenedInnerEnvelopeV2], client: RelayClientV2) async
        -> (messages: [Message], controlMessages: Int, unreadable: Int)
    {
        let realMessages = envelopes.filter { !$0.isCoverTraffic }
        guard !realMessages.isEmpty else { return ([], 0, 0) }
        var controlMessages = 0
        var unreadable = 0

        var appMessages: [Message] = []
        let now = Date()

        for envelope in realMessages {
            // Derive conversationID from sender's HSig public key.
            // SHA-256(senderHsigPk) == sender's RecipientIdV2, which is also the
            // hex string we stored as conversation.recipientID for V2 contacts.
            let senderIdBytes = Data(SHA256.hash(data: envelope.senderHsigPk))
            let conversationID = senderIdBytes.map { String(format: "%02x", $0) }.joined()

            // Clamp the sender-supplied timestamp to ±60 s of the relay-anchored
            // clock, expressed in this device's own time domain so it sorts next
            // to locally stamped messages even when this clock is off (ClockSyncV2).
            let rawTs = ClockSyncV2.shared.localDate(fromProtocolSec: envelope.timestamp)
            let clampedTs = abs(rawTs.timeIntervalSince(now)) <= 60 ? rawTs : now

            // The block list is read BEFORE opening: opening advances the
            // ratchet, so an envelope that was opened can never be re-delivered.
            // An unreadable list leaves the envelope unopened and unacknowledged
            // (P8-AUDIT8-IOS-01) instead of counting as "not blocked".
            let senderBlocked: Bool
            do {
                senderBlocked = try BlockListV2.containsStrict(RecipientIdV2.fromIdentityKey(envelope.senderHsigPk))
            } catch {
                SecureLogger.error("[V2] block list unreadable — envelope left for re-delivery: \(error)")
                unreadable += 1
                continue
            }

            let appPayload: Data
            do {
                let opened = try await client.openApplicationPayload(envelope)
                appPayload = opened.plaintext
                // A1 §7: a blocked contact's envelopes that still arrive are
                // discarded after decryption (the session stays consistent
                // for a later unblock) — no chat message, no notification,
                // no unread count. Acknowledged like everything fetched.
                if senderBlocked {
                    SecureLogger.torDiag("[V2] message from a blocked contact discarded")
                    continue
                }
                if opened.adoptedCrossing {
                    // Our own first chain to this peer was abandoned for its
                    // session; the peer never opens those frames. Send them
                    // again (new session, new frames — never a duplicate).
                    let peerId = conversationID
                    Task { await self.resendAbandonedFirstChain(peerId: peerId, client: client) }
                }
            } catch let e as RelayClientV2Error where Self.isStorageError(e) {
                SecureLogger.error("[V2] ratchet.open storage unreadable sender=\(conversationID.prefix(8)) err=\(e) — left for re-delivery")
                unreadable += 1
                continue
            } catch let e as RelayClientV2Error {
                // P8-AUDIT5-IOS-C2 (2026-05-21): unify swallow + escalate by class.
                // Previous single torDiag-line treated "malformed frame" and
                // "expected duplicate from parallel-fetch" identically and
                // dropped both messages silently. A malformed frame is either
                // a server bug or an active attack on the recipient — surface
                // it at .error so the redacted operator log shows it. Replay/
                // old stays at torDiag (expected steady-state noise).
                switch e {
                case .ratchet(.malformed),
                     .ratchet(.crypto),
                     .ratchet(.keychain),
                     .ratchet(.skippedKeyLimitExceeded),
                     .ratchet(.counterExhausted),
                     .ratchet(.prekeyUnavailable),
                     .ratchet(.prekeyStore):
                    SecureLogger.error("[V2] ratchet.open MALFORMED/CRYPTO sender=\(conversationID.prefix(8)) err=\(e)")
                    // Test builds: also in tor_diag.log (DEBUG-only), so a frame
                    // dropped on purpose — e.g. the losing side of a crossing
                    // start — is visible next to the delivery counts.
                    SecureLogger.torDiag("[V2] ratchet.open MALFORMED/CRYPTO sender=\(conversationID.prefix(8)) err=\(e)")
                case .ratchet(.replayOrTooOld):
                    SecureLogger.torDiag("[V2] ratchet.open replayOrTooOld sender=\(conversationID.prefix(8))")
                default:
                    SecureLogger.torDiag("[V2] ratchet.open FAILED sender=\(conversationID.prefix(8)) err=\(e)")
                }
                continue
            } catch {
                SecureLogger.error("[V2] ratchet.open UNEXPECTED sender=\(conversationID.prefix(8)) err=\(String(describing: error))")
                continue
            }

            guard let content = String(data: appPayload, encoding: .utf8),
                  !content.isEmpty else { continue }
            // Control messages (A1 §6) are never a chat message, never a
            // notification, never an unread count. open() above authenticated
            // the sender and its session, so START/KEY may set its delivery
            // key; anything malformed is dropped.
            if let control = ControlMessageV2.parse(content) {
                controlMessages += 1
                let senderRid = RecipientIdV2.fromIdentityKey(envelope.senderHsigPk)
                switch control {
                case .start(let k), .key(let k):
                    do {
                        try DeliveryKeyStoreV2.storePeerKey(k, for: senderRid)
                        SecureLogger.torDiag("[V2] control message received — contact's delivery key stored")
                    } catch {
                        SecureLogger.error("[V2] control message: storing the contact's delivery key failed: \(error)")
                    }
                case .malformed:
                    SecureLogger.error("[V2] malformed control message dropped sender=\(conversationID.prefix(8))")
                }
                continue
            }

            let message = Message(
                id: UUID().uuidString,
                content: content,
                timestamp: clampedTs,
                isOutgoing: false,
                conversationID: conversationID
            )
            appMessages.append(message)
        }

        guard !appMessages.isEmpty else { return ([], controlMessages, unreadable) }
        SecureLogger.torDiag("[V2] delivering \(appMessages.count) real messages convIDs=\(appMessages.map { $0.conversationID.prefix(8) }.joined(separator: ","))")
        return (appMessages, controlMessages, unreadable)
    }

    /// Crossing recovery (see `V2RatchetOpenedPayload.adoptedCrossing`): the
    /// application messages we sent in our abandoned first chain go out again
    /// in the adopted session. Only messages the user wrote are resent (they
    /// are in the store); control messages are not — their content (our
    /// delivery key) reached the peer with our pairing code. A message that
    /// cannot be sent now is marked failed, so the chat offers Resend.
    private func resendAbandonedFirstChain(peerId: String, client: RelayClientV2) async {
        let ids = V2RatchetPayload.takeFirstChainSends(peerId: peerId)
        guard !ids.isEmpty else { return }
        guard let peer = try? PeerStoreV2.load(forContactId: peerId) else {
            SecureLogger.error("[V2] crossing resend: contact not on file — \(ids.count) message(s) not resent")
            return
        }
        let outgoing: [Message] = await MainActor.run {
            let stored = InMemoryMessageStore.shared.messages(for: peerId)
            return ids.compactMap { id in stored.first { $0.id == id && $0.isOutgoing } }
        }
        SecureLogger.torDiag("[V2] crossing resolved for the peer — sending \(outgoing.count) of \(ids.count) first-chain message(s) again")
        for message in outgoing {
            do {
                _ = try await client.sendMessage(to: peer, messageBody: message.content, messageID: message.id)
            } catch {
                SecureLogger.error("[V2] crossing resend failed: \(error)")
                await MainActor.run {
                    _ = InMemoryMessageStore.shared.updateDeliveryStatus(messageID: message.id, status: .failed)
                }
            }
        }
    }

    // MARK: - Tor-Aware Session

    /// Build an ephemeral URLSession that routes through the Tor SOCKS5 proxy.
    /// This is required for sensitive V2 operations (Directory/Fetch/Enqueue).
    ///
    /// If requireTor is true, fails hard (nil) if SOCKS5 config is not available.
    /// If requireTor is false, falls back to direct connection (dev only).
    ///
    /// P8-AUDIT5-IOS-C1 (2026-05-21): default flipped to `true` (was `false`).
    /// All three production call sites already pass `true` explicitly, so this
    /// is purely a footgun-removal: a future caller that forgets the argument
    /// now fails closed instead of silently building a direct-connection
    /// session that bypasses Tor. The dev-fallback path is still reachable
    /// by passing `requireTor: false` explicitly.
    nonisolated private func buildV2Session(requireTor: Bool = true) -> URLSession? {
        var config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 30
        config.timeoutIntervalForResource = 60
        config.waitsForConnectivity = true
        config.tlsMinimumSupportedProtocolVersion = .TLSv13

        let majorV = "\(ProcessInfo.processInfo.operatingSystemVersion.majorVersion)"
        config.httpAdditionalHeaders = [
            "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS \(majorV)_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/\(majorV).0 Mobile/15E148 Safari/604.1",
            "Accept-Language": "en-US,en;q=0.9",
            "Cache-Control": "no-store",
        ]

        // Load SOCKS5 config from Keychain (set by Tor subsystem).
        guard let proxyData = TorController.loadSOCKS5ConfigFromKeychain(),
              let proxyConfig = try? JSONDecoder().decode(SOCKS5Config.self, from: proxyData),
              proxyConfig.port > 0 else {
            // Tor not available.
            if requireTor {
                // FIX F-V2-META-001: Fail-closed if Tor is required but not available.
                SecureLogger.error("[V2Session] Tor SOCKS5 config not available and Tor is required — session creation blocked")
                return nil
            }
            // L3 (security audit): the direct (non-Tor) fallback is a DEBUG-only
            // dev convenience. In a release build it must be physically
            // impossible to construct a clearnet session — fail closed even
            // when requireTor == false.
            #if DEBUG
            SecureLogger.debug("[V2Session] Tor SOCKS5 config not available — using direct connection (dev only)")
            return URLSession(
                configuration: config,
                delegate: CertificatePinningDelegate.shared,
                delegateQueue: nil
            )
            #else
            SecureLogger.error("[V2Session] Tor SOCKS5 config not available — session blocked (release fail-closed)")
            return nil
            #endif
        }

        // Tor is available — configure SOCKS5 proxy.
        //
        // Addendum A2 stage 1: every session gets its own random SOCKS
        // username and password. Tor isolates streams by SOCKS credentials by
        // default (ISO_SOCKSAUTH in ISO_DEFAULT, tor or.h; compared in
        // connection_edge.c), so each session built here runs on its own
        // circuit — the send connection never shares a circuit with the
        // identity connection that names our rid. The credentials are not a
        // secret; they only have to differ.
        //
        // Measured on macOS 2026-10-13 with this configuration against a local
        // SOCKS5 server: each session sends its own username/password, the
        // host name goes to the proxy (no local DNS), sessions never share a
        // connection or resume each other's TLS session, and with the proxy
        // unreachable the request fails instead of going direct.
        guard let socksPort = NWEndpoint.Port(rawValue: UInt16(clamping: proxyConfig.port)) else {
            SecureLogger.error("[V2Session] invalid SOCKS5 port — session blocked")
            return nil
        }
        var proxy = ProxyConfiguration(socksv5Proxy: .hostPort(host: NWEndpoint.Host(proxyConfig.host), port: socksPort))
        proxy.applyCredential(username: randomBytes(16).hexEncodedString,
                              password: randomBytes(16).hexEncodedString)
        // Failover is off by default (Network/proxy_config.h); set it anyway:
        // a session must never fall back to a direct connection.
        proxy.allowFailover = false
        config.proxyConfigurations = [proxy]

        return URLSession(
            configuration: config,
            delegate: CertificatePinningDelegate.shared,
            delegateQueue: nil
        )
    }

    /// Subscribe to `TorStateChanged` notifications. On each change, rebuild
    /// the URLSession and re-create the RelayClientV2 instance so upcoming
    /// requests use the correct (proxied or direct) transport.
    private func observeTorStateChanges() {
        NotificationCenter.default.addObserver(
            forName: .init("TorStateChanged"),
            object: nil,
            queue: nil
        ) { [weak self] _ in
            Task { await self?.reconfigureForTorChange() }
        }
    }

    /// A2 §5: lane F runs a catch-up burst on every return to the
    /// foreground. (If Tor re-binds on the way back, the rebuilt lanes run
    /// another one once the new connections stand.)
    private func observeForeground() {
        guard !foregroundObserverInstalled else { return }
        foregroundObserverInstalled = true
        #if canImport(UIKit)
        NotificationCenter.default.addObserver(
            forName: UIApplication.willEnterForegroundNotification,
            object: nil,
            queue: nil
        ) { [weak self] _ in
            PrekeyStoreV2.purgeExpiredOwnNow()
            Task { await self?.lanes.runBurst() }
        }
        #endif
    }

    private func reconfigureForTorChange() async {
        guard isInitialized, let existingClient = client else {
            // Not initialised yet (e.g. Tor was not ready at the first try):
            // a Tor change is the moment to retry.
            await initializeIfNeeded()
            return
        }
        let endpoint = Self.currentSocksEndpoint()
        let epoch = TorController.connectionEpoch
        if sessionReady, let endpoint, endpoint == sessionSocksEndpoint, epoch == sessionConnectionEpoch {
            // Same proxy as the running session: nothing to rebuild, and the
            // loops in flight stay alive.
            return
        }

        // Pause the lanes: nothing goes out on the old, dead connections.
        // Queued sends stay queued and go out on the new ones.
        await lanes.setTransports(send: nil, fetch: nil)

        // Build the new session only once Tor reports itself connected. The
        // recovery bumps the epoch at DisableNetwork=1 and posts progress while
        // the listeners are still down; a session built then sent its first
        // request into the closed port and waited out the 60 s resource
        // timeout before the receive loop restarted (17 Pro, 01.10.2026:
        // DisableNetwork=1 21:18:09 → bundle published 21:19:14). The loops are
        // cancelled above; markCircuitConnected() posts the next
        // TorStateChanged, which rebuilds here (sessionReady == false).
        let torConnected = await MainActor.run { TorController.shared.circuitEstablished }
        guard torConnected else {
            sessionReady = false
            SecureLogger.torDiag("[V2] reconfigure: Tor not connected yet — rebuild deferred until it is")
            return
        }

        // FIX F-V2-META-001: require Tor on reconfigure (fail-closed if Tor goes down).
        guard let newSession = buildV2Session(requireTor: true),
              let newSendSession = buildV2Session(requireTor: true) else {
            // The lanes above are paused; mark the session not ready so the
            // next TorStateChanged rebuilds it even with the same endpoint and
            // epoch (fail-closed: no request goes out without Tor meanwhile).
            sessionReady = false
            SecureLogger.error("[V2Session] Tor not available during reconfigure — loops stopped until Tor returns")
            SecureLogger.torDiag("[V2] reconfigure: no Tor session — loops stopped, will rebuild on next Tor change")
            return
        }
        // Keep the client (it holds no connection since A2 stage 2: the lanes
        // do); replace only the transport layer — the lanes' connections and
        // the registry's geo-probe session.
        await existingClient.registry.replaceSession(newSession)
        identitySession = newSession
        sendSession = newSendSession
        sessionSocksEndpoint = endpoint
        sessionConnectionEpoch = epoch
        sessionReady = true
        schedulePublish(client: existingClient)
    }

    // MARK: - Phase 4b: v2.1 Push Registration

    enum PushRegistrationV2Error: Error, CustomStringConvertible {
        case notInitialized
        case noExitsConfigured

        var description: String {
            switch self {
            case .notInitialized:    return "V2SessionManager not initialized"
            case .noExitsConfigured: return "no v2 exits configured"
            }
        }
    }

    /// Register the APNs device token with the push relay: a PUSH_REGISTER
    /// sealed to the push relay's key, in lane F (Addendum A2 §4.4). The
    /// entry sees a lane-F request to a target id; neither it nor an exit
    /// sees the token. Identity (rid + hsig keypair) is the running client's,
    /// so the rid signed here matches the rid of the published bundle.
    ///
    /// `PushRegistrationClientV2Error` is propagated unmodified so the caller
    /// can branch on `entryHasNoPushRelay` / `pushRelayRejected` etc.
    func registerPushTokenV2(_ apnsToken: Data, sandbox: Bool) async throws {
        guard let client = self.client, sessionReady else {
            throw PushRegistrationV2Error.notInitialized
        }
        do {
            try await client.registerPushToken(apnsToken: apnsToken, sandbox: sandbox)
        } catch PushRegistrationClientV2Error.unknownRecipient {
            // A1 §4 rule 1(c): the push relay has no copy of our identity key
            // (it restarted, or no exit holds our bundle yet). Publishing makes
            // the exits replicate it; then register once more. The replication
            // is asynchronous on the exit, hence the short pause.
            SecureLogger.torDiag("[V2] push relay does not know us — publishing bundle, then registering again")
            _ = await client.publishBundleOnAllExits()
            try await Task.sleep(nanoseconds: 3_000_000_000)
            try await client.registerPushToken(apnsToken: apnsToken, sandbox: sandbox)
        } catch RelayClientV2Error.noExitsConfigured {
            throw PushRegistrationV2Error.noExitsConfigured
        }
    }
}
