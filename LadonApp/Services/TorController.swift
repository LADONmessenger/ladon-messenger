//
//  TorController.swift
//  Ladon
//
//  Embedded Tor Controller using iCepa/Tor.framework
//

import Foundation
import Network
import CryptoKit
import UIKit

/// Controls embedded Tor instance using iCepa's Tor.framework
/// Provides full Tor network integration without external dependencies
@MainActor
class TorController: NSObject, ObservableObject {
    
    // MARK: - Tor Log Level
    // FIX AUDIT-MAR-2026-3: Use 'err' in production, 'notice' only in debug
    #if DEBUG
    private static let torLogLevel = "notice"
    /// DEBUG only: Tor's own notice log as a file, so a failed recovery can be
    /// diagnosed from Tor's side without a console attached. SafeLogging (on
    /// by default) scrubs connection addresses; bridge-configuration notices
    /// still name the configured (public, built-in) bridge address. Never in
    /// release builds.
    static let torNoticeLogFile: URL? = FileManager.default
        .urls(for: .documentDirectory, in: .userDomainMask).first?
        .appendingPathComponent("tor_notice.log")
    #else
    private static let torLogLevel = "err"
    #endif
    
    // MARK: - Published State
    
    @Published var isRunning = false
    @Published var bootstrapProgress = 0
    @Published var statusMessage = "Tor not started"
    @Published var circuitEstablished = false
    
    // MARK: - Properties
    
    static let shared = TorController()
    
    /// FIX H-8: SOCKS5 proxy port — randomized at launch to prevent local port hijacking on jailbroken devices
    /// Changes only in `moveSocksToFreshPort` (recovery), to another random
    /// loopback port; consumers read it from the persisted SOCKS5 config.
    private(set) var socksPort: UInt16 = UInt16.random(in: 49152...65500)
    
    /// FIX H-8: Control port (TCP) — used for legacy sendControlCommandWithResponse().
    /// Primary control communication now uses inProcessControlFD (socketpair from
    /// tor_main_configuration_setup_control_socket) which survives iOS suspension.
    lazy var controlPort: UInt16 = socksPort &+ 1

    /// In-process control file descriptor obtained from tor_main_configuration_setup_control_socket().
    /// This is a socketpair(AF_UNIX) FD that lives entirely within the process — NOT a TCP
    /// listen socket, NOT a filesystem Unix socket. iOS does NOT reclaim it during process
    /// suspension because it's not a kernel-level listener. Pre-authenticated: no cookie auth needed.
    /// After background return, we write "SIGNAL RELOAD\r\n" to this FD which triggers:
    ///   do_hup() → options_init_from_torrc() → set_options() → retry_all_listeners()
    /// → SOCKSPort + ControlPort TCP sockets are re-created by the kernel.
    private var inProcessControlFD: Int32 = -1
    
    /// H-24: Official Tor Project Snowflake bridge fingerprint.
    /// This is the publicly documented fingerprint from the Tor Project's Snowflake specification.
    /// It identifies the official Snowflake bridge operator's identity key.
    /// Hardcoded because: (1) value is public and version-pinned by Tor Project,
    /// (2) incorrect values would route traffic through untrusted bridges,
    /// (3) the Tor Project updates this only during major protocol changes.
    /// If the Tor Project rotates this fingerprint, update this constant.
    static let snowflakeFingerprint = "2B280B23E1107BB62ABFC40DDCC8824814F80A72"
    
    /// Tor data directory
    private var torDataDir: URL {
        // FIX CRIT-1: Use NSSearchPathForDirectoriesInDomains (always returns a path)
        // instead of urls()?[0] which can crash if array is empty.
        guard let appSupport = NSSearchPathForDirectoriesInDomains(
            .applicationSupportDirectory, .userDomainMask, true
        ).first else {
            // Fallback to tmp directory if app support is unavailable
            return FileManager.default.temporaryDirectory.appendingPathComponent("tor", isDirectory: true)
        }
        return URL(fileURLWithPath: appSupport).appendingPathComponent("tor", isDirectory: true)
    }
    
    /// Tor configuration
    private var torrcPath: URL {
        return torDataDir.appendingPathComponent("torrc")
    }
    
    /// Tor process/thread reference
    private var torThread: Thread?
    
    private var iptProxyBridge: IPtProxyBridge?
    private var obfs4Port: Int = 0
    private var snowflakePort: Int = 0
    /// Which ClientTransportPlugin lines the current torrc contains — the PT
    /// repair re-points exactly these, never adds one.
    private var torrcHasObfs4Plugin = false
    private var torrcHasSnowflakePlugin = false
    
    /// Health monitoring: detects Tor failures and triggers auto-reconnect
    private var healthMonitorTask: Task<Void, Never>?

    /// Counts the times Tor was told to drop all its connections
    /// (DisableNetwork toggle, RELOAD). Streams open at that moment are dead
    /// even though the SOCKS endpoint stays the same; V2SessionManager rebuilds
    /// its session when this changes (measured 30.09.2026 on the 12 Pro: without
    /// it, requests started before the toggle hung up to 60 s).
    private static let connectionEpochLock = NSLock()
    nonisolated(unsafe) private static var _connectionEpoch = 0
    nonisolated static var connectionEpoch: Int {
        connectionEpochLock.lock(); defer { connectionEpochLock.unlock() }
        return _connectionEpoch
    }
    private static func bumpConnectionEpoch() {
        connectionEpochLock.lock(); _connectionEpoch += 1; connectionEpochLock.unlock()
    }
    /// FIX TC-H1: Store circuit rotation task to allow cancellation in stopTor()
    private var circuitRotationTask: Task<Void, Never>?
    /// Prevent concurrent recovery paths (verifyCircuit + handleTorFailure) from racing each other.
    private var isVerifyingCircuit = false
    /// Network switched off on purpose for the background (prepareForBackground):
    /// no listener, no connection, transports stopped. Only a real wake —
    /// foreground return or push — brings it back (unparkNetwork).
    private(set) var isParked = false
    private var networkPathMonitor: NWPathMonitor?
    private var reconnectAttempts: Int = 0
    private var isReconnecting: Bool = false
    private static let maxReconnectAttempts = 3
    /// FIX K-5: Store monitorBootstrap() task handle to allow cancellation in stopTor()
    private var bootstrapTask: Task<Void, Never>?
    /// Timestamp when app last went to background — used to skip quick checks on long suspends
    var backgroundedAt: Date? = nil
    
    // MARK: - Initialization
    
    private override init() {
        super.init()
        setupTorDirectories()
        setupPluggableTransports()
        createTorrcConfig()
        
        // Observe external health check requests (e.g., client-reported proxy errors)
        NotificationCenter.default.addObserver(
            forName: .init("TorHealthCheckRequested"),
            object: nil,
            queue: nil
        ) { [weak self] _ in
            Task { @MainActor [weak self] in
                guard let self = self, self.isRunning, self.circuitEstablished else { return }
                let isHealthy = await self.checkSOCKSPortReady()
                if !isHealthy {
                    await self.handleTorFailure(reason: "Proxy error reported by client")
                }
            }
        }
    }
    
    // MARK: - Directory Setup
    
    private func setupTorDirectories() {
        let fm = FileManager.default
        
        // Create Tor data directory
        try? fm.createDirectory(at: torDataDir, withIntermediateDirectories: true)
        
        // FIX MED-80: Set iOS File Protection on Tor data directory
        try? fm.setAttributes(
            [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication],
            ofItemAtPath: torDataDir.path
        )
        
        // Create subdirectories
        let subdirs = ["hidden_service", "keys", "pt"]
        for subdir in subdirs {
            let path = torDataDir.appendingPathComponent(subdir)
            try? fm.createDirectory(at: path, withIntermediateDirectories: true)
            // FIX MED-80: Set iOS File Protection on each subdirectory
            try? fm.setAttributes(
                [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication],
                ofItemAtPath: path.path
            )
        }

        // Remove legacy cache directories that should be files
        let legacyCacheDirs = ["cached-certs", "cached-microdesc-consensus"]
        for name in legacyCacheDirs {
            let path = torDataDir.appendingPathComponent(name)
            var isDir: ObjCBool = false
            if fm.fileExists(atPath: path.path, isDirectory: &isDir), isDir.boolValue {
                try? fm.removeItem(at: path)
            }
        }
        
        #if DEBUG
        print("[TorController] 📁 Tor directories created at: \(torDataDir.path)")
        #endif

        notifyStateChanged()
    }
    
    // MARK: - Pluggable Transports Setup
    
    /// Initialize IPtProxy for censorship circumvention (obfs4 + Snowflake)
    private func setupPluggableTransports() {
        let fm = FileManager.default
        
        // Create PT directory for IPtProxy state
        let ptDir = torDataDir.appendingPathComponent("pt")
        try? fm.createDirectory(at: ptDir, withIntermediateDirectories: true)
        
        #if DEBUG
        print("[TorController] 🔌 IPtProxy directory ready at: \(ptDir.path)")
        #endif

        // FIX AUDIT-MAR-2026-2: Disable IPtProxy logging in production builds
        // INFO-level logs contain bridge connection attempts and Snowflake handshake details
        #if DEBUG
        let ptEnableLogging = true
        let ptLogLevel = "INFO"
        #else
        let ptEnableLogging = false
        let ptLogLevel = "ERROR"
        #endif
        iptProxyBridge = IPtProxyBridge(
            ptDir: ptDir.path,
            enableLogging: ptEnableLogging,
            unsafeLogging: false,
            logLevel: ptLogLevel
        )
        
        // Transport names come from IPtProxy itself — see IPtProxyBridge.h. The
        // previous literals "Obfs4"/"Snowflake" were the names of the framework's
        // constants, not their values, and a mismatch is invisible: start fails,
        // the port stays 0, and createTorrcConfig() then writes no bridge line.
        let obfs4Name = IPtProxyBridge.obfs4Name
        let snowflakeName = IPtProxyBridge.snowflakeName

        do { try iptProxyBridge?.startTransport(obfs4Name) } catch {
            #if DEBUG
            print("[TorController] ⚠️ obfs4 (\(obfs4Name)) failed to start: \(error)")
            #endif
        }
        obfs4Port = Int(iptProxyBridge?.port(forTransport: obfs4Name) ?? 0)

        do { try iptProxyBridge?.startTransport(snowflakeName) } catch {
            #if DEBUG
            print("[TorController] ⚠️ Snowflake (\(snowflakeName)) failed to start: \(error)")
            #endif
        }
        snowflakePort = Int(iptProxyBridge?.port(forTransport: snowflakeName) ?? 0)

        #if DEBUG
        // Tied to the port, never printed unconditionally: a success line that is
        // not conditioned on success is what hid this for months.
        print("[TorController] 🌉 obfs4 (\(obfs4Name)) port \(obfs4Port) — \(obfs4Port > 0 ? "running" : "NOT running")")
        print("[TorController] 🌉 Snowflake (\(snowflakeName)) port \(snowflakePort) — \(snowflakePort > 0 ? "running" : "NOT running")")
        #endif
    }
    
    /// FIX TOR-BG-RECONNECT: Restart pluggable transports if they were stopped
    /// by shutdownForBackground(). Must be called before createTorrcConfig().
    private func restartPluggableTransportsIfNeeded() {
        // Check if transports are still running by checking their ports
        let obfs4Name = IPtProxyBridge.obfs4Name
        let snowflakeName = IPtProxyBridge.snowflakeName

        let currentObfs4 = Int(iptProxyBridge?.port(forTransport: obfs4Name) ?? 0)
        let currentSnowflake = Int(iptProxyBridge?.port(forTransport: snowflakeName) ?? 0)

        if currentObfs4 == 0 && currentSnowflake == 0 {
            // Transports were stopped — restart them
            #if DEBUG
            print("[TorController] 🔌 Restarting pluggable transports after background shutdown...")
            #endif

            try? iptProxyBridge?.startTransport(obfs4Name)
            obfs4Port = Int(iptProxyBridge?.port(forTransport: obfs4Name) ?? 0)

            try? iptProxyBridge?.startTransport(snowflakeName)
            snowflakePort = Int(iptProxyBridge?.port(forTransport: snowflakeName) ?? 0)

            #if DEBUG
            print("[TorController] 🔌 after restart — obfs4 port \(obfs4Port), Snowflake port \(snowflakePort)")
            #endif
        }
    }
    
    // MARK: - Torrc Configuration
    
    private func createTorrcConfig() {
        // Determine if we should use bridges (if PT ports are available)
        let useBridges = (obfs4Port > 0 || snowflakePort > 0)
        torrcHasObfs4Plugin = false
        torrcHasSnowflakePlugin = false
        
        var torrc = """
        # Ladon Messenger - Tor Configuration
        
        # SOCKS5 Proxy (for app connections)
        SOCKSPort \(socksPort)
        
        # Control port (TCP loopback)
        ControlPort \(controlPort)
        CookieAuthentication 1
        
        # Data directory
        DataDirectory \(torDataDir.path)
        
        # Logging (only errors in production)
        # FIX AUDIT-MAR-2026-3: Use 'err' in production, 'notice' only in debug
        Log \(Self.torLogLevel) stdout
        \(Self.debugNoticeLogLine())
        
        # Client mode (not a relay/exit node)
        ClientOnly 1
        
        # Disable DNS on SOCKS (app handles DNS)
        DNSPort 0
        
        # Entry nodes (use fast guards)
        UseEntryGuards 1
        NumEntryGuards 3

        # Circuit preferences
        CircuitBuildTimeout 30
        LearnCircuitBuildTimeout 1
        
        # Hidden service (optional - for receiving messages)
        # HiddenServiceDir \(torDataDir.path)/hidden_service
        # HiddenServicePort 8080 127.0.0.1:8080
        
        """
        
        // Add bridge configuration if IPtProxy is available
        if useBridges {
            torrc += """
            
            # === CENSORSHIP CIRCUMVENTION ===
            # Pluggable Transports via IPtProxy (obfs4 + Snowflake)
            # UseBridges 1: bridges are the safe default (direct Tor connections may be throttled).
            # On background return, verifyCircuitAfterBackgroundReturn() temporarily overrides
            # to UseBridges=0 via SETCONF for fast direct reconnect, then re-enables if needed.
            
            UseBridges 1
            
            """
            
            // Add obfs4 configuration.
            // Only when bridge lines actually exist: declaring the transport
            // plugin without a single `Bridge obfs4 …` line gives Tor a plugin it
            // can never use. loadBridgeLines() prefers cached bridges and falls
            // back to the built-in set, so this is normally non-empty.
            let obfs4BridgeLines = Self.loadBridgeLines()
            if obfs4Port > 0 && !obfs4BridgeLines.isEmpty {
                torrcHasObfs4Plugin = true
                torrc += """
                
                # obfs4 (Lyrebird) - Deep Packet Inspection bypass
                # Works in: China, Iran, Egypt, UAE, Russia
                ClientTransportPlugin obfs4 socks5 127.0.0.1:\(obfs4Port)
                
                # Public obfs4 bridges (loaded securely)
                # Get fresh bridges from: https://bridges.torproject.org/
                \(obfs4BridgeLines.map { $0.replacingOccurrences(of: "\n", with: "").replacingOccurrences(of: "\r", with: "") }.joined(separator: "\n                "))
                
                """
            }
            
            // Add Snowflake configuration
            if snowflakePort > 0 {
                torrcHasSnowflakePlugin = true
                torrc += """
                
                # Snowflake - WebRTC NAT traversal (best for heavily censored networks)
                # Works when all bridge IPs are blocked
                ClientTransportPlugin snowflake socks5 127.0.0.1:\(snowflakePort)
                
                # Snowflake configuration (H-24: fingerprint from TorController.snowflakeFingerprint)
                # FIX AUDIT-H19: Removed stun.l.google.com — Google sees real IP (deanonymization risk)
                Bridge snowflake 192.0.2.3:80 \(Self.snowflakeFingerprint) fingerprint=\(Self.snowflakeFingerprint) url=https://snowflake-broker.torproject.net.global.prod.fastly.net/ fronts=foursquare.com,github.githubassets.com ice=stun:stun.antisip.com:3478,stun:stun.bluesip.net:3478,stun:stun.dus.net:3478,stun:stun.epygi.com:3478,stun:stun.sonetel.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.voys.nl:3478 utls-imitate=hellorandomizedalpn
                
                """
            }
            
            torrc += """
            
            # Prevent directory authority queries over clearnet
            FetchDirInfoEarly 1
            FetchDirInfoExtraEarly 1
            """
        } else {
            // Fallback: Direct connection (no bridges)
            torrc += """
            
            # Bridge support (for censored networks)
            # IPtProxy not available - using direct connection
            UseBridges 0
            
            # Prevent directory authority queries over clearnet
            FetchDirInfoEarly 1
            FetchDirInfoExtraEarly 1
            """
        }
        
        // FIX MED-71: Propagate torrc write errors instead of silently failing
        do {
            try torrc.write(to: torrcPath, atomically: true, encoding: .utf8)
        } catch {
            SecureLogger.error("Failed to write torrc: \(error.localizedDescription)")
            statusMessage = "Error: Failed to write Tor config"
            notifyStateChanged()
            return
        }
        
        // FIX L2: Set FileProtection for torrc file (contains bridge addresses)
        do {
            try FileManager.default.setAttributes(
                [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication],
                ofItemAtPath: torrcPath.path
            )
        } catch {
            SecureLogger.error("Failed to set torrc file protection: \(error.localizedDescription)")
        }
        
        #if DEBUG
        print("[TorController] 📝 Torrc created at: \(torrcPath.path)")
        print("[TorController] 🌉 Bridges enabled: \(useBridges)")
        #endif

        notifyStateChanged()
    }
    
    // MARK: - Start/Stop Tor
    
    /// Start embedded Tor instance
    func startTor() async throws {
        guard !isRunning else {
            #if DEBUG
            print("[TorController] ⚠️ Tor already running")
            #endif
            return
        }
        
        // FIX ZOMBIE-03: Guard against zombie thread from previous tor_main()
        // CRITICAL: tor_main() uses global C state (hs_circuitmap, etc.) that cannot
        // be re-initialized. Calling tor_main() a second time while the first is still
        // alive causes assert() → abort() in hs_circuitmap_init.
        // We MUST wait until the old thread is fully dead before launching a new one.
        if let oldThread = torThread, !oldThread.isFinished {
            #if DEBUG
            print("[TorController] ⚠️ Previous Tor thread still alive — sending SHUTDOWN + waiting...")
            #endif
            // Send SHUTDOWN signals to help the old thread exit — try in-process FD first
            let _ = await sendInProcessControlCommand("SIGNAL SHUTDOWN", timeoutSeconds: 3.0)
            await sendControlCommand("SIGNAL SHUTDOWN")
            
            // Wait up to 30s — on iOS, frozen threads may take time to unfreeze and exit.
            // This is long, but a crash is worse than a slow restart.
            let zombieDeadline = Date().addingTimeInterval(30.0)
            while !oldThread.isFinished && Date() < zombieDeadline {
                try? await Task.sleep(nanoseconds: 200_000_000) // 200ms
                // Send periodic SHUTDOWN signals in case the control port becomes responsive
                if Int(Date().timeIntervalSince1970) % 3 == 0 {
                    await sendControlCommand("SIGNAL SHUTDOWN")
                }
            }
            if !oldThread.isFinished {
                // Old thread STILL alive after 30s. We CANNOT start a new tor_main()
                // because it will abort() on hs_circuitmap_init (global C state clash).
                // Report failure — the user must restart the app.
                SecureLogger.error("[TorController] CANNOT restart Tor: previous tor_main() thread still alive after 30s — global C state prevents re-init")
                statusMessage = "Tor restart requires app restart"
                isRunning = false
                notifyStateChanged()
                throw TorError.controlPortUnavailable
            } else {
                // FIX WORKER-THREAD-CRASH: Wait for Tor's internal worker threads to drain.
                // tor_main() spawns worker threads (tor_pthread_helper_fn) not tracked by
                // torThread. Must wait after isFinished before starting new tor_main().
                try? await Task.sleep(nanoseconds: 2_000_000_000) // 2s worker-thread drain
                #if DEBUG
                print("[TorController] ✅ Previous Tor thread finished — safe to start new tor_main() (+ 2s worker drain)")
                #endif
            }
        }
        torThread = nil
        
        // Clean up lock file only after old thread is confirmed dead.
        cleanupTorLockFile()
        
        // FIX TOR-BG-RECONNECT: Restart pluggable transports if they were stopped
        // (shutdownForBackground stops them). They must be running before createTorrcConfig()
        // generates the torrc with bridge lines pointing to their ports.
        restartPluggableTransportsIfNeeded()
        
        // M5: Try to fetch fresh bridges from server before starting Tor
        await Self.refreshBridgesFromServer()
        // Regenerate torrc with potentially updated bridges
        createTorrcConfig()
        
        isRunning = true
        statusMessage = "Tor starting..."
        notifyStateChanged()
        
        // Start Tor in background thread using modern tor_run_main() API.
        // tor_run_main() + tor_main_configuration_setup_control_socket() creates
        // a pre-authenticated in-process control FD (socketpair) that survives
        // iOS process suspension — the ROOT CAUSE fix for background reconnect.
        let torrcPathStr = self.torrcPath.path
        let socksPortVal = self.socksPort
        
        // Build argv for tor_main_configuration_set_command_line
        let argv = [
            "tor",
            "-f", torrcPathStr,
            "--ignore-missing-torrc"
        ]
        
        // Create config, set up control socket, and get the FD — all on main thread
        // before launching the background thread, because the FD is needed immediately.
        guard let cfgRaw = tor_main_configuration_new() else {
            SecureLogger.error("[TorController] tor_main_configuration_new() returned nil")
            isRunning = false
            statusMessage = "Tor config creation failed"
            notifyStateChanged()
            throw TorError.controlPortUnavailable
        }
        // Umweg ueber cfgRaw, weil `nonisolated(unsafe)` an einem `guard let`
        // nicht erlaubt ist. Alle weiteren Verwendungen heissen unveraendert cfg.
        nonisolated(unsafe) let cfg = cfgRaw
        
        // nonisolated(unsafe): cArgs und cfg werden unten im Thread-Block
        // gefangen. Dieser Thread besitzt sie exklusiv — er ruft tor_run_main()
        // auf und gibt beide danach selbst frei; ausserhalb greift nach dem
        // Thread-Start niemand mehr darauf zu.
        nonisolated(unsafe) var cArgs = argv.map { strdup($0) }
        let argc = Int32(cArgs.count)
        tor_main_configuration_set_command_line(cfg, argc, &cArgs)
        
        // Setup in-process control socket — returns our end of the socketpair FD
        let controlFD = tor_main_configuration_setup_control_socket(cfg)
        if controlFD < 0 {
            SecureLogger.error("[TorController] tor_main_configuration_setup_control_socket() failed: \(controlFD)")
            cArgs.forEach { free($0) }
            tor_main_configuration_free(cfg)
            isRunning = false
            statusMessage = "Tor control socket setup failed"
            notifyStateChanged()
            throw TorError.controlPortUnavailable
        }
        self.inProcessControlFD = controlFD
        SecureLogger.torDiag("[START] In-process control FD = \(controlFD)")
        
        torThread = Thread {
            #if DEBUG
            print("[TorController] 🧅 Starting Tor with config: \(torrcPathStr)")
            print("[TorController] 📡 SOCKS5 will listen on: 127.0.0.1:\(socksPortVal)")
            print("[TorController] 🔌 In-process control FD: \(controlFD)")
            #endif
            
            // tor_run_main() blocks until Tor exits. The in-process control FD
            // is pre-authenticated — no cookie auth needed on our end.
            tor_run_main(cfg)
            
            // Cleanup after Tor exits
            tor_main_configuration_free(cfg)
            cArgs.forEach { free($0) }
        }
        
        torThread?.start()
        
        // Monitor bootstrap progress
        monitorBootstrap()
        
        // FIX M-64: Schedule periodic circuit rotation for unlinkability
        scheduleCircuitRotation()
    }
    
    /// Stop Tor instance
    func stopTor() async {
        guard isRunning else { return }
        
        // Stop health monitoring before tearing down Tor
        stopHealthMonitoring()
        // FIX TC-H1: Cancel circuit rotation task
        circuitRotationTask?.cancel()
        circuitRotationTask = nil
        // FIX K-5: Cancel bootstrap task to prevent setting circuitEstablished after stop
        bootstrapTask?.cancel()
        bootstrapTask = nil
        // FIX H-9: Reset reconnect state so next startTor gets a fresh counter
        // FIX TC-H3: Only reset reconnectAttempts when NOT called from handleTorFailure.
        // Previously, handleTorFailure incremented the counter, then called stopTor()
        // which reset it to 0 → the max-3 limit was never reached → infinite reconnect loop.
        // Now: only reset when isReconnecting is false (= manual stop, not failure-driven).
        if !isReconnecting {
            reconnectAttempts = 0
        }
        isReconnecting = false
        
        statusMessage = "Stopping Tor..."
        notifyStateChanged()
        
        // Send shutdown signal via in-process control FD first (survives any TCP issues)
        let _ = await sendInProcessControlCommand("SIGNAL SHUTDOWN", timeoutSeconds: 3.0)
        // Also try TCP control port as fallback
        await sendControlCommand("SIGNAL SHUTDOWN")
        
        // FIX MED-42 + FIX B + FIX ZOMBIE-01: Wait for Tor thread to finish.
        // CRITICAL: Do NOT set torThread = nil if the thread is still running!
        // Previously, setting torThread = nil here caused startTor() to bypass
        // the zombie-thread check → two tor_main() instances → crash.
        // Thread.cancel() only sets isCancelled flag — tor_main() (C code) ignores it.
        // The only reliable way to stop tor_main() is SIGNAL SHUTDOWN via control port
        // (already sent above) and then waiting for it to exit.
        if let thread = torThread {
            let deadline = Date().addingTimeInterval(3.0) // 3s — if SHUTDOWN works, tor exits in <2s
            while !thread.isFinished && Date() < deadline {
                // Task.sleep() is non-blocking — allows UI to continue rendering
                try? await Task.sleep(nanoseconds: 100_000_000) // 100ms
            }
            if !thread.isFinished {
                // FIX ZOMBIE-02: Do NOT set torThread = nil here!
                // Keep the reference so startTor() can detect the zombie thread.
                SecureLogger.error("[TorController] Tor thread did not stop within 3s — thread still alive (zombie)")
            } else {
                #if DEBUG
                print("[TorController] ✅ Tor thread stopped cleanly")
                #endif
                torThread = nil
            }
        }
        
        // Stop pluggable transports
        iptProxyBridge?.stopTransport(IPtProxyBridge.obfs4Name)
        iptProxyBridge?.stopTransport(IPtProxyBridge.snowflakeName)
        
        // FIX C-4: Clear bridge lines from torrc to prevent plaintext bridge exposure at rest.
        // Bridges are stored encrypted in Keychain; torrc is only written at Tor startup.
        clearBridgeLinesFromTorrc()
        
        // Close the in-process control FD (no longer needed after Tor exits)
        if inProcessControlFD >= 0 {
            Darwin.close(inProcessControlFD)
            inProcessControlFD = -1
        }
        
        isRunning = false
        circuitEstablished = false
        bootstrapProgress = 0
        statusMessage = "Tor stopped"

        // Clear SOCKS5 config from Keychain on stop — without a proxy, clients fail closed (Tor is mandatory)
        TorController.clearSOCKS5ConfigFromKeychain()
        notifyStateChanged()
        
        #if DEBUG
        print("[TorController] 🛑 Tor stopped")
        #endif
    }
    
    // MARK: - Background Shutdown (FIX TOR-BG-RECONNECT)
    
    /// Cleanly shut down Tor BEFORE iOS freezes the process.
    /// Called from the background handler with beginBackgroundTask().
    /// After this completes, torThread is nil and startTor() can launch a fresh tor_main().
    /// This is the key fix: instead of letting iOS freeze a running tor_main() (which
    /// leaves zombie sockets that take 10-30s to recover), we shut down cleanly so the
    /// next foreground return can start fresh — as fast as the very first app launch.
    func shutdownForBackground() async {
        guard isRunning else { return }
        
        #if DEBUG
        print("[TorController] 🌙 Background shutdown: stopping Tor cleanly before iOS freeze...")
        #endif
        
        // Stop monitoring tasks first
        stopHealthMonitoring()
        circuitRotationTask?.cancel()
        circuitRotationTask = nil
        bootstrapTask?.cancel()
        bootstrapTask = nil
        
        // Send SHUTDOWN via in-process control FD (survives TCP issues) + TCP fallback
        let _ = await sendInProcessControlCommand("SIGNAL SHUTDOWN", timeoutSeconds: 3.0)
        await sendControlCommand("SIGNAL SHUTDOWN")
        
        // Wait for tor_main() thread to exit (up to 5s — we have ~30s from beginBackgroundTask)
        if let thread = torThread {
            let deadline = Date().addingTimeInterval(5.0)
            while !thread.isFinished && Date() < deadline {
                try? await Task.sleep(nanoseconds: 100_000_000) // 100ms
            }
            if thread.isFinished {
                // FIX WORKER-THREAD-CRASH: tor_main() spawns internal worker threads
                // (tor_pthread_helper_fn → worker_thread_main) that are NOT tracked by
                // torThread. When torThread.isFinished == true, these workers may still
                // be alive. Starting a new tor_main() immediately re-initializes global
                // C state (mutexes, memory pools) → old workers crash with SIGABRT.
                // Wait 2s to let internal worker threads finish their cleanup.
                try? await Task.sleep(nanoseconds: 2_000_000_000) // 2s worker-thread drain
                torThread = nil
                #if DEBUG
                print("[TorController] ✅ Tor thread exited cleanly for background (+ 2s worker drain)")
                #endif
            } else {
                // Thread didn't exit in 5s — send another SHUTDOWN and wait 3s more
                let _ = await sendInProcessControlCommand("SIGNAL SHUTDOWN", timeoutSeconds: 2.0)
                await sendControlCommand("SIGNAL SHUTDOWN")
                let extendedDeadline = Date().addingTimeInterval(3.0)
                while !thread.isFinished && Date() < extendedDeadline {
                    try? await Task.sleep(nanoseconds: 100_000_000)
                }
                if thread.isFinished {
                    try? await Task.sleep(nanoseconds: 2_000_000_000) // 2s worker-thread drain
                    torThread = nil
                    #if DEBUG
                    print("[TorController] ✅ Tor thread exited on second SHUTDOWN attempt (+ 2s worker drain)")
                    #endif
                } else {
                    #if DEBUG
                    print("[TorController] ⚠️ Tor thread still alive after 8s — will be zombie on return")
                    #endif
                    // Don't nil torThread — startTor() needs to detect this zombie
                }
            }
        }
        
        // Stop pluggable transports
        iptProxyBridge?.stopTransport(IPtProxyBridge.obfs4Name)
        iptProxyBridge?.stopTransport(IPtProxyBridge.snowflakeName)
        
        // Clear bridge lines from torrc (security)
        clearBridgeLinesFromTorrc()
        
        // Close the in-process control FD
        if inProcessControlFD >= 0 {
            Darwin.close(inProcessControlFD)
            inProcessControlFD = -1
        }
        
        // Keep thread reference if it did not finish.
        // startTor() uses this to block unsafe re-init of tor_main() global C state.
        if let thread = torThread, !thread.isFinished {
            #if DEBUG
            print("[TorController] ⚠️ Tor thread still alive after 8s — keeping reference for zombie guard")
            #endif
        }
        
        let stoppedCleanly = (torThread == nil) || (torThread?.isFinished == true)

        if stoppedCleanly {
            // Reset state only when Tor thread really exited.
            isRunning = false
            circuitEstablished = false
            bootstrapProgress = 0
            reconnectAttempts = 0
            isReconnecting = false
            statusMessage = "Tor stopped (background)"

            // Clear SOCKS5 config
            TorController.clearSOCKS5ConfigFromKeychain()
            notifyStateChanged()

            #if DEBUG
            print("[TorController] 🌙 Background shutdown complete — ready for fresh start on return")
            #endif
        } else {
            // Thread did not exit; keep running state so foreground path verifies
            // existing Tor instead of forcing an unsafe restart attempt.
            circuitEstablished = false
            statusMessage = "Reconnecting..."
            notifyStateChanged()

            #if DEBUG
            print("[TorController] ⚠️ Background shutdown incomplete — keeping existing tor_main() for foreground recovery")
            #endif
        }
    }
    
    /// FIX C-4: Overwrite torrc with a minimal config (no bridge lines).
    /// Bridges are loaded from encrypted Keychain cache and written only at Tor startup.
    /// Clearing them on stop prevents plaintext bridge exposure if the device is seized.
    private func clearBridgeLinesFromTorrc() {
        let sanitizedTorrc = """
        # Ladon Messenger - Tor Configuration (stopped)
        # Bridge lines cleared for security (FIX C-4)
        SOCKSPort \(socksPort)
        ControlPort \(controlPort)
        CookieAuthentication 1
        DataDirectory \(torDataDir.path)
        ClientOnly 1
        DNSPort 0
        """
        do {
            try sanitizedTorrc.write(to: torrcPath, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes(
                [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication],
                ofItemAtPath: torrcPath.path
            )
        } catch {
            #if DEBUG
            print("[TorController] ⚠️ Failed to clear bridge lines from torrc: \(error)")
            #endif
        }
    }
    
    /// FIX B: Remove Tor's lock file from the data directory.
    /// tor_main() acquires an exclusive lock on DataDirectory/lock.
    /// If the old tor_main() thread didn't exit cleanly, this lock file
    /// prevents a new tor_main() from starting (EACCES/EAGAIN → crash).
    /// Removing it allows the next tor_main() to acquire a fresh lock.
    private func cleanupTorLockFile() {
        let lockFile = torDataDir.appendingPathComponent("lock")
        let fm = FileManager.default
        if fm.fileExists(atPath: lockFile.path) {
            do {
                try fm.removeItem(at: lockFile)
                #if DEBUG
                print("[TorController] 🗑️ Removed stale Tor lock file")
                #endif
            } catch {
                #if DEBUG
                print("[TorController] ⚠️ Failed to remove Tor lock file: \(error)")
                #endif
            }
        }
    }
    
    // MARK: - Bootstrap Monitoring
    
    
    /// Monitor Tor bootstrap by reading control port
    /// FIX: Added 120-second timeout to prevent infinite loop if Tor never connects.
    private func monitorBootstrap() {
        // FIX K-5: Cancel any existing bootstrap Task before starting a new one
        bootstrapTask?.cancel()
        bootstrapTask = Task {
            let maxWaitSeconds = 120
            var waitedSeconds = 0
            while !self.circuitEstablished && waitedSeconds < maxWaitSeconds {
                try? await Task.sleep(nanoseconds: 1_000_000_000) // 1s
                waitedSeconds += 1
                
                // Ready = SOCKS5 answers AND Tor does not report "no circuit /
                // network down" (isUsableNow). The greeting alone answered while
                // Tor had no route (17 Pro, 01.10.2026).
                let isReady = await self.isUsableNow(socksTimeout: 1.0)
                
                // FIX M-13: Query real bootstrap progress from Tor control port
                // instead of synthetic +10% per second
                var realProgress: Int?
                if !isReady {
                    realProgress = await self.queryBootstrapProgress()
                }
                
                await MainActor.run {
                    if isReady {
                        // FIX K-5: Guard against setting circuitEstablished after stopTor
                        guard self.isRunning else { return }
                        self.bootstrapProgress = 100
                        self.circuitEstablished = true
                        self.statusMessage = "Tor circuit established"
                        // Save SOCKS5 config to Keychain so clients route through Tor
                        TorController.saveSOCKS5ConfigToKeychain(host: "127.0.0.1", port: Int(self.socksPort))
                        self.notifyStateChanged()
                        // Start continuous health monitoring now that circuit is up
                        self.startHealthMonitoring()
                    } else {
                        // FIX M-13: Use real bootstrap progress from Tor control port
                        if let progress = realProgress {
                            // Cap at 99 — 100 is reserved for confirmed SOCKS5 readiness
                            self.bootstrapProgress = min(progress, 99)
                            self.statusMessage = "Bootstrapping Tor... \(self.bootstrapProgress)%"
                        } else if self.bootstrapProgress < 15 {
                            // Control port not ready yet — minimal progress indicator
                            self.bootstrapProgress = min(self.bootstrapProgress + 5, 15)
                            self.statusMessage = "Starting Tor..."
                        }
                        self.notifyStateChanged()
                    }
                }
            }
            
            // FIX: If timeout reached, update state
            if !self.circuitEstablished {
                await MainActor.run {
                    self.statusMessage = "Tor bootstrap timed out"
                    self.notifyStateChanged()
                }
                #if DEBUG
                SecureLogger.debug("[TorController] ⚠️ Bootstrap timed out after \(maxWaitSeconds)s")
                #endif
            }
        }
    }
    
    /// FIX D: Public SOCKS5 health check for use by clients before sending.
    /// Returns true if the SOCKS5 proxy is responding with a valid handshake.
    func isSOCKSHealthy() async -> Bool {
        return await checkSOCKSPortReady()
    }
    
    /// FIX M-13: Query real bootstrap progress from Tor control port.
    /// Sends GETINFO status/bootstrap-phase and parses PROGRESS=XX from response.
    /// Returns nil if control port is not yet available (early startup).
    private func queryBootstrapProgress() async -> Int? {
        let response: String
        do {
            response = try await sendControlCommandWithResponse("GETINFO status/bootstrap-phase")
        } catch {
            SecureLogger.error("Failed to query bootstrap progress: \(error)")
            return nil
        }
        // Tor response format: "250-status/bootstrap-phase=... PROGRESS=50 TAG=... SUMMARY=..."
        guard let range = response.range(of: "PROGRESS=") else { return nil }
        let afterProgress = response[range.upperBound...]
        let digits = afterProgress.prefix(while: { $0.isNumber })
        guard let progress = Int(digits), progress >= 0 && progress <= 100 else { return nil }
        return progress
    }
    
    /// Query bootstrap progress via in-process control FD instead of TCP ControlPort.
    /// Used during background recovery when TCP ControlPort may still be dead/rebuilding.
    private func queryBootstrapViaInProcessFD() async -> Int? {
        guard let response = await sendInProcessControlCommand("GETINFO status/bootstrap-phase", timeoutSeconds: 3.0) else {
            return nil
        }
        guard let range = response.range(of: "PROGRESS=") else { return nil }
        let afterProgress = response[range.upperBound...]
        let digits = afterProgress.prefix(while: { $0.isNumber })
        guard let progress = Int(digits), progress >= 0 && progress <= 100 else { return nil }
        return progress
    }

    /// Check if SOCKS5 port is listening and responds with valid SOCKS5 handshake
    /// FIX MED-40: Verify process identity by checking SOCKS5 protocol response.
    /// A SOCKS5 server must respond with version byte 0x05 — confirms it's actually
    /// our Tor instance and not a rogue process hijacking the port.
    private func checkSOCKSPortReady(timeoutSeconds: TimeInterval = 1.0, portOverride: Int? = nil) async -> Bool {
        let host = NWEndpoint.Host("127.0.0.1")
        // `portOverride` probes another local SOCKS5 listener (the pluggable
        // transports' — diagnostics only); default is Tor's own SOCKS port.
        let rawPort: UInt16
        if let o = portOverride {
            guard o > 0, o <= Int(UInt16.max) else { return false }
            rawPort = UInt16(o)
        } else {
            rawPort = socksPort
        }
        // FIX FORCEUNWRAP-01: Safe port creation — prevents crash if port is 0 (should never happen, defense in depth)
        guard let port = NWEndpoint.Port(rawValue: rawPort) else { return false }
        let connection = NWConnection(host: host, port: port, using: .tcp)
        
        return await withCheckedContinuation { continuation in
            let lock = NSLock()
            var didResume = false

            func resumeOnce(_ value: Bool) {
                lock.lock()
                defer { lock.unlock() }
                guard !didResume else { return }
                didResume = true
                connection.cancel()
                continuation.resume(returning: value)
            }

            nonisolated(unsafe) let timeoutWork = DispatchWorkItem {
                resumeOnce(false)
            }

            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    // FIX MED-40: Send SOCKS5 handshake probe: version 5, 1 method (no auth)
                    let socks5Hello = Data([0x05, 0x01, 0x00])
                    connection.send(content: socks5Hello, completion: .contentProcessed({ error in
                        if error != nil {
                            timeoutWork.cancel()
                            resumeOnce(false)
                            return
                        }
                        // Read 2-byte response: should be [0x05, method]
                        connection.receive(minimumIncompleteLength: 2, maximumLength: 2) { data, _, _, recvError in
                            timeoutWork.cancel()
                            if let data = data, data.count >= 2, data[0] == 0x05 {
                                resumeOnce(true)  // Valid SOCKS5 response
                            } else {
                                #if DEBUG
                                print("[TorController] ⚠️ SOCKS5 port responded with non-SOCKS5 data — possible hijack")
                                #endif
                                resumeOnce(false)
                            }
                        }
                    }))
                case .failed:
                    timeoutWork.cancel()
                    resumeOnce(false)
                case .waiting:
                    // IMPORTANT: Do not fail immediately on .waiting.
                    // During foreground resume, NWConnection can transiently report
                    // .waiting before becoming .ready. Returning false here creates
                    // false negatives and can leave UI stuck at 99%.
                    break
                default:
                    break
                }
            }

            connection.start(queue: .global())
            // Fast default timeout, but callers can request a more tolerant timeout during recovery.
            DispatchQueue.global().asyncAfter(deadline: .now() + timeoutSeconds, execute: timeoutWork)
        }
    }
    
    // MARK: - Control Port Commands
    
    /// Serial queue for the in-process control FD (see sendInProcessControlCommand).
    private static let inProcessControlQueue = DispatchQueue(label: "app.ladon.tor.control.inprocess", qos: .userInitiated)

    /// Send a command to Tor via the in-process control FD (socketpair).
    /// This FD is pre-authenticated — no cookie auth needed.
    /// Survives iOS process suspension because it's a process-internal socketpair,
    /// not a TCP listen socket that iOS kernel can reclaim.
    ///
    /// Returns the response string, or nil if the FD is invalid or write/read fails.
    private func sendInProcessControlCommand(_ command: String, timeoutSeconds: TimeInterval = 10.0) async -> String? {
        // An abandoned recovery must not reach Tor any more — a late
        // DisableNetwork=0 from it would undo the park that replaced it.
        if Task.isCancelled { return nil }
        let fd = self.inProcessControlFD
        guard fd >= 0 else {
            SecureLogger.torDiag("[IN-PROC] FD invalid (\(fd)) — cannot send: \(command)")
            return nil
        }
        
        let (response, gone) = await withCheckedContinuation { (continuation: CheckedContinuation<(String?, Bool), Never>) in
            // One command at a time: the socketpair is a single stream, so two
            // concurrent write+read pairs could each read the other's reply.
            Self.inProcessControlQueue.async {
                // Set recv timeout
                let sec = __darwin_time_t(timeoutSeconds)
                var tv = timeval(tv_sec: sec, tv_usec: 0)
                Darwin.setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
                
                // Write command
                let cmdStr = "\(command)\r\n"
                guard let cmdData = cmdStr.data(using: .utf8) else {
                    continuation.resume(returning: (nil, false))
                    return
                }
                let written = cmdData.withUnsafeBytes { ptr -> Int in
                    guard let base = ptr.baseAddress else { return -1 }
                    return Darwin.write(fd, base, cmdData.count)
                }
                guard written == cmdData.count else {
                    let err = Darwin.errno
                    SecureLogger.torDiag("[IN-PROC] write() failed for: \(command) — errno=\(err)")
                    continuation.resume(returning: (nil, Self.isConnectionGone(errno: err)))
                    return
                }
                
                // Read response (blocks up to timeoutSeconds)
                var buf = [UInt8](repeating: 0, count: 4096)
                let bytesRead = Darwin.read(fd, &buf, buf.count)
                guard bytesRead > 0 else {
                    let err = Darwin.errno
                    SecureLogger.torDiag("[IN-PROC] read() failed for: \(command) — errno=\(err) bytesRead=\(bytesRead)")
                    // 0 = end of stream: Tor's side is closed. -1 with a
                    // timeout errno is only a slow reply.
                    continuation.resume(returning: (nil, bytesRead == 0 || Self.isConnectionGone(errno: err)))
                    return
                }
                let response = String(bytes: buf.prefix(bytesRead), encoding: .utf8) ?? ""
                SecureLogger.torDiag("[IN-PROC] \(command) → \(String(response.prefix(60)))")
                continuation.resume(returning: (response, false))
            }
        }
        if gone { markControlLost() }
        return response
    }

    /// errno values that mean the control connection itself is gone — not a
    /// timeout (EAGAIN) or an interrupted call.
    nonisolated private static func isConnectionGone(errno err: Int32) -> Bool {
        err == EPIPE || err == EBADF || err == ECONNRESET || err == ENOTCONN
    }

    // MARK: - Lost control connection (03.10.2026)
    //
    // iOS can tear down the in-process control socketpair of a suspended app
    // (12 Pro, 03.10.2026: write() → EPIPE after ~75 s locked; the morning
    // stall at 1 % was the same). It is Tor's owning controller and exists
    // once per process, and tor_main() cannot run a second time — nothing can
    // steer Tor any more: no unpark, no re-bind. Only a new process helps.
    // Fail closed meanwhile: no SOCKS config, no route.

    /// True once the control connection is gone, for the rest of the process.
    @Published private(set) var controlLost = false

    private func markControlLost() {
        guard !controlLost else { return }
        controlLost = true
        SecureLogger.torDiag("[LOST] in-process control connection gone — Tor cannot be steered; a new process is needed")
        abandonRecovery(tag: "[LOST]")
        stopHealthMonitoring()
        TorController.clearSOCKS5ConfigFromKeychain()
        Self.bumpConnectionEpoch()
        circuitEstablished = false
        statusMessage = "Restart required"
        notifyStateChanged()
        quitIfControlLost(inBackground: UIApplication.shared.applicationState == .background)
    }

    /// With the control connection gone, end the process while the app is in
    /// the background, so the next open is a normal cold start. Never in the
    /// foreground (the app would vanish in front of the user — the banner asks
    /// for a reopen instead), and never while the device is locked: messages
    /// fetched while locked can only be persisted once it is unlocked (store
    /// key WhenUnlockedThisDeviceOnly) and would be lost. Everything in the
    /// message store is persisted first.
    private func quitIfControlLost(inBackground: Bool) {
        guard controlLost, inBackground else { return }
        guard UIApplication.shared.isProtectedDataAvailable else {
            SecureLogger.torDiag("[LOST] device locked — restart deferred until it is unlocked and backgrounded")
            return
        }
        InMemoryMessageStore.shared.forcePersist()
        SecureLogger.torDiag("[LOST] ending the process in the background — next open is a cold start")
        SecureLogger.flushTorDiag()
        exit(0)
    }
    
    /// DEBUG diagnostics only: like sendInProcessControlCommand, but for
    /// multi-line replies (GETINFO circuit-status / entry-guards). Reads until
    /// the final "250 OK" line so no remainder is left on the shared FD for the
    /// next command; capped at 256 KiB. Logs only the byte count — the reply
    /// holds relay fingerprints and addresses.
    private func sendInProcessMultilineDiagnostic(_ command: String, timeoutSeconds: TimeInterval = 3.0) async -> String? {
        #if DEBUG
        let fd = self.inProcessControlFD
        guard fd >= 0 else { return nil }
        return await withCheckedContinuation { continuation in
            Self.inProcessControlQueue.async {
                let sec = __darwin_time_t(timeoutSeconds)
                var tv = timeval(tv_sec: sec, tv_usec: 0)
                Darwin.setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
                guard let cmdData = "\(command)\r\n".data(using: .utf8) else {
                    continuation.resume(returning: nil); return
                }
                let written = cmdData.withUnsafeBytes { ptr -> Int in
                    guard let base = ptr.baseAddress else { return -1 }
                    return Darwin.write(fd, base, cmdData.count)
                }
                guard written == cmdData.count else { continuation.resume(returning: nil); return }
                var acc = [UInt8]()
                var buf = [UInt8](repeating: 0, count: 4096)
                let terminator = Array("\r\n250 OK\r\n".utf8)
                while acc.count < 262_144 {
                    let n = Darwin.read(fd, &buf, buf.count)
                    if n <= 0 { break }
                    acc.append(contentsOf: buf.prefix(n))
                    if acc.count >= terminator.count && Array(acc.suffix(terminator.count)) == terminator { break }
                    // A one-line error reply ("5xx ...\r\n") also ends the response.
                    if acc.count >= 4, acc[3] == 0x20, acc.suffix(2) == [0x0D, 0x0A] { break }
                }
                SecureLogger.torDiag("[IN-PROC] \(command) → \(acc.count) bytes (content not logged)")
                continuation.resume(returning: acc.isEmpty ? nil : String(decoding: acc, as: UTF8.self))
            }
        }
        #else
        return nil
        #endif
    }

    /// Send a command to Tor's control port and return the response
    private func sendControlCommand(_ command: String, timeoutSeconds: TimeInterval = 10.0) async {
        do {
            let response = try await sendControlCommandWithResponse(command, timeoutSeconds: timeoutSeconds)
            #if DEBUG
            print("[TorController] 📤 Control: \(command) → \(response.prefix(100))")
            #endif
        } catch {
            #if DEBUG
            print("[TorController] ❌ Control command failed: \(command) — \(error)")
            #endif
        }
    }
    
    /// Send a command to Tor's control port via Unix domain socket.
    ///
    /// Uses AF_UNIX (Unix domain socket) instead of TCP/NWConnection because:
    ///  - NWConnection (.waiting issue): after 10+ min iOS background, Network.framework
    ///    enters .waiting state on loopback and stays there 60-120s — all attempts time out.
    ///  - POSIX TCP (ECONNREFUSED issue): iOS reclaims TCP listen sockets of suspended
    ///    processes after 10+ min. POSIX connect() returns ECONNREFUSED immediately on ALL
    ///    20 attempts — proven by tor_diag.log 2026-04-14.
    ///  - Unix domain socket: filesystem-backed, NOT a network resource. iOS does NOT
    ///    reclaim Unix sockets during process suspension. connect() succeeds as soon as
    ///    tor_main()'s thread wakes from the iOS scheduler (typically ~2s on iPhone 17 Pro,
    ///    ~35s on iPhone 13 Pro). recv() blocks with SO_RCVTIMEO as safety net.
    ///
    /// Sends a command to Tor's control port (TCP 127.0.0.1) using POSIX sockets.
    /// Uses AF_INET with cookie authentication. POSIX sockets avoid NWConnection's
    /// .waiting state issue on loopback after iOS background suspension.
    private func sendControlCommandWithResponse(_ command: String, timeoutSeconds: TimeInterval = 10.0) async throws -> String {
        // Read cookie auth file
        let cookieFile = torDataDir.appendingPathComponent("control_auth_cookie")
        // FIX HIGH-21: Restrict cookie file permissions to owner-only (0600)
        try? FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: cookieFile.path
        )
        // FIX AUDIT3-IOS-10: cookie data must live ONLY inside the dispatch closure
        // so the wipe at end-of-closure actually zeroes the buffer (refcount == 1).
        // Previously the outer `let cookieData` retained a reference while the inner
        // `var mutableCookie = cookieData` wipe ran \u2192 CoW \u2192 only the detached copy was zeroed.
        let cookieFilePath = cookieFile.path

        let port = self.controlPort

        return try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .utility).async {
                // Read cookie INSIDE the closure as var so wipe targets the only buffer
                guard var cookieData = try? Data(contentsOf: URL(fileURLWithPath: cookieFilePath)) else {
                    continuation.resume(throwing: TorError.controlPortUnavailable)
                    return
                }
                defer {
                    cookieData.withUnsafeMutableBytes { ptr in
                        guard let base = ptr.baseAddress else { return }
                        memset_s(base, ptr.count, 0, ptr.count)
                    }
                }
                // Create TCP socket (AF_INET, loopback)
                let sockFd = Darwin.socket(AF_INET, SOCK_STREAM, 0)
                guard sockFd >= 0 else {
                    continuation.resume(throwing: TorError.controlPortUnavailable)
                    return
                }
                defer { Darwin.close(sockFd) }

                // SO_RCVTIMEO + SO_SNDTIMEO: unblock recv/send after timeoutSeconds.
                let sec = __darwin_time_t(timeoutSeconds)
                var tv = timeval(tv_sec: sec, tv_usec: 0)
                Darwin.setsockopt(sockFd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
                Darwin.setsockopt(sockFd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

                // Build sockaddr_in for 127.0.0.1:controlPort
                var addr = sockaddr_in()
                addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
                addr.sin_family = sa_family_t(AF_INET)
                addr.sin_port = port.bigEndian
                addr.sin_addr.s_addr = inet_addr("127.0.0.1")

                // connect() — TCP loopback, immediate success or ECONNREFUSED.
                let connectResult = withUnsafePointer(to: &addr) { ptr in
                    ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        Darwin.connect(sockFd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                    }
                }
                guard connectResult == 0 else {
                    let err = Darwin.errno
                    SecureLogger.torDiag("[CTRL] connect() failed errno=\(err) port=\(port)")
                    continuation.resume(throwing: TorError.controlPortUnavailable)
                    return
                }

                // Build AUTHENTICATE command as Data — FIX H-03: no String intermediary
                // for cookie hex (avoids heap strings that can't be wiped).
                var authData = Data("AUTHENTICATE ".utf8)
                let hexChars = Array("0123456789abcdef".utf8)
                for byte in cookieData {
                    authData.append(hexChars[Int(byte >> 4)])
                    authData.append(hexChars[Int(byte & 0x0F)])
                }
                authData.append(contentsOf: "\r\n".utf8)
                let authCount = authData.count

                // FIX AUDIT3-IOS-10: cookieData wipe handled by defer at top of closure

                // send() AUTHENTICATE
                let authSent = authData.withUnsafeBytes { ptr -> Int in
                    guard let base = ptr.baseAddress else { return -1 }
                    return Darwin.send(sockFd, base, authCount, 0)
                }
                // FIX H-03: Wipe authData after sending
                authData.withUnsafeMutableBytes { ptr in
                    guard let base = ptr.baseAddress else { return }
                    memset_s(base, ptr.count, 0, ptr.count)
                }
                guard authSent == authCount else {
                    continuation.resume(throwing: TorError.controlPortUnavailable)
                    return
                }

                // recv() AUTHENTICATE response — blocks until tor_main() wakes
                var authBuf = [UInt8](repeating: 0, count: 1024)
                let authRecvd = Darwin.recv(sockFd, &authBuf, authBuf.count, 0)
                guard authRecvd > 0,
                      let authStr = String(bytes: authBuf.prefix(authRecvd), encoding: .utf8),
                      authStr.hasPrefix("250") else {
                    continuation.resume(throwing: TorError.controlPortUnavailable)
                    return
                }

                // send() the actual command
                guard let cmdData = "\(command)\r\n".data(using: .utf8) else {
                    continuation.resume(throwing: TorError.controlPortUnavailable)
                    return
                }
                let cmdSent = cmdData.withUnsafeBytes { ptr -> Int in
                    guard let base = ptr.baseAddress else { return -1 }
                    return Darwin.send(sockFd, base, cmdData.count, 0)
                }
                guard cmdSent == cmdData.count else {
                    continuation.resume(throwing: TorError.controlPortUnavailable)
                    return
                }

                // recv() command response
                var respBuf = [UInt8](repeating: 0, count: 4096)
                let respRecvd = Darwin.recv(sockFd, &respBuf, respBuf.count, 0)
                guard respRecvd > 0 else {
                    continuation.resume(throwing: TorError.controlPortUnavailable)
                    return
                }
                let response = String(bytes: respBuf.prefix(respRecvd), encoding: .utf8) ?? ""
                continuation.resume(returning: response)
            }
        }
    }

    private func notifyStateChanged() {
        NotificationCenter.default.post(name: .init("TorStateChanged"), object: nil)
    }
    
    // MARK: - Circuit Management
    
    /// Ask Tor for new circuits (SIGNAL NEWNYM) over the in-process control FD
    /// — pre-authenticated and unaffected by iOS reclaiming the TCP control
    /// listener. Returns whether Tor accepted it ("250"); the status text only
    /// claims success when it did. (Before: the TCP path failed with
    /// controlPortUnavailable — 8 times in ~5 min on the 17 Pro, 30.09.2026 —
    /// and "New circuit created" was set regardless.)
    @discardableResult
    func newCircuit() async -> Bool {
        let response = await sendInProcessControlCommand("SIGNAL NEWNYM", timeoutSeconds: 5.0)
        let accepted = response?.hasPrefix("250") == true
        SecureLogger.torDiag("[CIRCUIT] NEWNYM \(accepted ? "accepted" : "not accepted")")
        guard accepted else { return false }
        statusMessage = "New circuit created"
        
        #if DEBUG
        print("[TorController] 🔄 New Tor circuit requested")
        #endif
        return true
    }
    
    /// FIX M-64: Periodically rotate Tor circuits to prevent long-lived circuit correlation.
    /// Default interval: 10 minutes (matches Tor's default MaxCircuitDirtiness).
    private func scheduleCircuitRotation() {
        // FIX TC-H1: Cancel existing task and store reference for cleanup in stopTor()
        circuitRotationTask?.cancel()
        circuitRotationTask = Task { [weak self] in
            while let self = self, self.isRunning {
                try? await Task.sleep(nanoseconds: 600_000_000_000) // 10 minutes
                guard self.isRunning, self.circuitEstablished else { continue }
                let rotated = await self.newCircuit()
                #if DEBUG
                print("[TorController] 🔄 Periodic circuit rotation \(rotated ? "done" : "NOT accepted") (M-64)")
                #endif
            }
        }
    }
    
    /// Get current circuit info
    func getCircuitInfo() async -> [String]? {
        // Query control port for circuit details
        // Returns list of nodes in circuit
        return nil
    }
    
    // MARK: - Background Return Recovery (FIX A)

    /// Called when the app enters the background (and after a push wake in the
    /// background) — BEFORE iOS freezes the process. Parks Tor's network.
    ///
    /// A suspended app's loopback listeners are taken away by iOS bit by bit:
    /// first the pluggable-transport listeners, after ~40 min Tor's SOCKS port
    /// as well (01./02.10.2026) — each found only in real use and repaired
    /// case by case on return. Parking closes them ourselves before iOS can:
    /// DisableNetwork=1 closes every listener and connection, the transports
    /// stop. The return (unparkNetwork) always starts from that same known
    /// state, however long the suspension was.
    ///
    /// Rejected in April 2026 because DisableNetwork=0 then went over the TCP
    /// ControlPort, which iOS reclaimed after 10+ min. It now goes over the
    /// in-process control socketpair, which answered after 43 min of
    /// suspension on both phones (02.10.2026). tor_main() keeps running —
    /// consensus and guards stay in memory; no C global state is touched.
    ///
    /// The persisted SOCKS5 config is cleared while parked: the old loopback
    /// port is free, and no consumer may build a session towards it (FIX H-8 —
    /// another local process could bind it). Consumers fail closed until
    /// markCircuitConnected() writes the new port.
    func prepareForBackground() async {
        guard isRunning else { return }
        backgroundedAt = Date()
        if controlLost {
            quitIfControlLost(inBackground: true)
            return
        }
        guard !isParked else {
            SecureLogger.torDiag("[PARK] skipped (already parked)")
            return
        }
        // A recovery still running is abandoned, not waited for: skipping the
        // park left Tor unparked through the suspension, iOS reclaimed the
        // transport listeners, and the frozen recovery resumed hours later
        // against them (17 Pro, 03.10.2026 12:39 → 15:31, stuck at 99 %).
        abandonRecovery(tag: "[PARK]")
        _ = await parkNetwork(tag: "[PARK]")
    }

    /// Network off, transports stopped, SOCKS config cleared. True if Tor
    /// accepted DisableNetwork=1.
    private func parkNetwork(tag: String) async -> Bool {
        stopHealthMonitoring()
        let reply = await sendInProcessControlCommand("SETCONF DisableNetwork=1", timeoutSeconds: 3.0)
        guard reply?.hasPrefix("250") == true else {
            SecureLogger.torDiag("\(tag) DisableNetwork=1 refused (\(reply?.prefix(40) ?? "nil")) — not parked")
            if circuitEstablished { startHealthMonitoring() }
            return false
        }
        Self.bumpConnectionEpoch()
        isParked = true
        iptProxyBridge?.stopTransport(IPtProxyBridge.obfs4Name)
        iptProxyBridge?.stopTransport(IPtProxyBridge.snowflakeName)
        TorController.clearSOCKS5ConfigFromKeychain()
        circuitEstablished = false
        statusMessage = "Paused"
        notifyStateChanged()
        SecureLogger.torDiag("\(tag) network off, transports stopped, SOCKS config cleared")
        return true
    }

    /// Soft network restart via Tor control port: DisableNetwork 1 → 0.
    ///
    /// After iOS suspends the app process, all TCP connections from tor_main() to the
    /// Tor relay network are dead (the remote side timed them out). Tor's internal state
    /// still thinks they are alive, so organic recovery is slow (~30–60s of retries).
    ///
    /// By toggling DisableNetwork via the control port we instruct Tor to:
    ///   1. DisableNetwork=1 → immediately close all existing (now-dead) connections
    ///   2. DisableNetwork=0 → start a fresh bootstrap sequence
    ///
    /// Because tor_main() is still running (NOT restarted), Tor retains its in-memory:
    ///   - Consensus document (no re-download if < 3h old)
    ///   - Guard node list and descriptor cache
    ///   - Previously built circuit parameters
    ///
    /// Result: circuit establishment takes ~3–6s — equivalent to a cold app start.
    ///
    /// The control port is a local TCP socket (127.0.0.1:controlPort). It responds as
    /// soon as tor_main()'s thread wakes from iOS suspension, WITHOUT needing a live
    /// Tor circuit — unlike SOCKS5 which only responds after circuits are built.
    ///
    /// Returns true if both SETCONF commands were accepted (250 OK).
    /// Returns false if the control port is not yet reachable (safe: caller falls back to Phase 1/2).
    private func trySoftNetworkRestart() async -> Bool {
        #if DEBUG
        print("[TorController] 🔄 trySoftNetworkRestart: DisableNetwork=1 → UseBridges=0 DisableNetwork=0")
        #endif
        do {
            let resp1 = try await sendControlCommandWithResponse("SETCONF DisableNetwork=1", timeoutSeconds: 4.0)
            guard resp1.hasPrefix("250") else { return false }
            Self.bumpConnectionEpoch()
            try? await Task.sleep(nanoseconds: 300_000_000)
            let resp2 = try await sendControlCommandWithResponse("SETCONF UseBridges=0 DisableNetwork=0", timeoutSeconds: 4.0)
            return resp2.hasPrefix("250")
        } catch {
            return false
        }
    }

    /// FIX ZOMBIE-04: Verify and recover Tor circuit after returning from background.
    ///
    /// ROOT CAUSE (proven by 3 diagnostic logs):
    ///   After 10+ min iOS background, iOS kernel reclaims ALL TCP listen sockets
    ///   (ControlPort + SOCKSPort). tor_main() thread is alive but deaf.
    ///   tor_main() CANNOT be restarted (global C state → SIGABRT).
    ///
    /// FIX: Use the in-process control FD (socketpair from tor_main_configuration_setup_control_socket)
    ///   to send SIGNAL RELOAD. This triggers:
    ///     do_hup() → options_init_from_torrc() → set_options() → retry_all_listeners()
    ///   → SOCKSPort + ControlPort TCP sockets are re-created.
    ///   Then send SIGNAL ACTIVE to wake Tor from dormant mode.
    ///   The in-process FD survives iOS suspension because it's a process-internal socketpair.
    func verifyCircuitAfterBackgroundReturn() async {
        guard isRunning else { return }
        // Every return to the foreground goes through the one recovery
        // coordinator — also when backgroundedAt is nil (Face ID prompt,
        // Notification Center), which used to skip recovery entirely.
        let backgroundDuration = backgroundedAt.map { Date().timeIntervalSince($0) }
        backgroundedAt = nil
        let trigger = backgroundDuration.map { "foreground bg=\(Int($0))s" } ?? "foreground bg=unknown"
        // Kept from the proven path: after a long suspension (> 30 s) always
        // re-bind — Tor's guard connections may be dead while it still reports
        // a circuit. A short one is checked first and keeps its NEWNYM nudge.
        let longBackground = (backgroundDuration ?? 0) > 30.0
        await ensureUsable(trigger: trigger,
                           forceRebind: longBackground,
                           nudgeIfHealthy: backgroundDuration != nil,
                           wake: true)
    }

    /// Re-create Tor's SOCKS/Control listeners through the in-process control
    /// FD while tor_main() itself is alive: SIGNAL ACTIVE → DisableNetwork=1
    /// (closes zombie listeners) → DisableNetwork=0 (fresh bind) → poll SOCKS5,
    /// with SIGNAL RELOAD as fallback. Moved unchanged out of
    /// verifyCircuitAfterBackgroundReturn() so handleTorFailure() can use the
    /// same proven sequence (`tag` keeps the [VERIFY] log lines identical).
    /// Returns true once SOCKS5 answers (circuit marked connected).

    #if DEBUG
    private static var noticeLogCleared = false
    #endif

    /// DEBUG only: torrc line that sends Tor's notice log to a file (empty in
    /// release). The previous session's file is removed once per launch — not
    /// when the torrc is rewritten during a recovery.
    private static func debugNoticeLogLine() -> String {
        #if DEBUG
        guard let url = torNoticeLogFile else { return "" }
        if !noticeLogCleared {
            SecureLogger.keepPreviousRun(of: url)
            noticeLogCleared = true
        }
        return "Log notice file \(url.path)"
        #else
        return ""
        #endif
    }

    /// Tor's own answer to "where is your SOCKS listener": the bound
    /// address(es), "" when Tor has none, nil when it could not be asked.
    /// Local, over the in-process control FD.
    private func socksListenerAddresses() async -> String? {
        guard let r = await sendInProcessControlCommand("GETINFO net/listeners/socks", timeoutSeconds: 3.0),
              r.hasPrefix("250"),
              let line = r.split(whereSeparator: \.isNewline).first,
              let eq = line.firstIndex(of: "=") else { return nil }
        return line[line.index(after: eq)...]
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: "\"", with: "")
    }

    /// Ask Tor to build a general circuit now (EXTENDCIRCUIT 0, Tor picks the
    /// path). After an hour without use Tor has no predicted ports and builds
    /// circuits only on demand, while we wait for a built circuit before
    /// sending anything — both sides waited (12 Pro, 02.10.2026 12:47: "idle
    /// for 3600 seconds", bootstrap 100 %, circ_building=0 for 30 s). A local
    /// control command: no stream, no destination, nothing reaches our relays.
    private func demandCircuit(tag: String) async {
        let r = await sendInProcessControlCommand("EXTENDCIRCUIT 0", timeoutSeconds: 3.0)
        SecureLogger.torDiag("\(tag) EXTENDCIRCUIT 0: \(r.map { String($0.prefix(24)) } ?? "nil")")
    }

    /// A random loopback port in the launch range that no listener of ours uses.
    private func freshSocksPortCandidate() -> UInt16 {
        var p: UInt16
        repeat {
            p = UInt16.random(in: 49152...65500)
        } while p == socksPort || p == controlPort
            || p == UInt16(clamping: obfs4Port) || p == UInt16(clamping: snowflakePort)
        return p
    }

    /// Stop and start one pluggable transport; its new port, or `current` if
    /// the start failed (Tor's plugin line then stays valid, that transport
    /// just has no route).
    private func restartTransport(_ name: String, current: Int) -> Int {
        guard let bridge = iptProxyBridge else { return current }
        bridge.stopTransport(name)
        do { try bridge.startTransport(name) } catch {
            SecureLogger.torDiag("[RECOVERY] PT restart failed")
            return current
        }
        let port = Int(bridge.port(forTransport: name))
        return port > 0 ? port : current
    }

    /// The ClientTransportPlugin lines the torrc has, with the current ports.
    /// SETCONF replaces the whole list, so all of them go into one command.
    private func transportPluginArguments() -> [String] {
        var plugins: [String] = []
        if torrcHasObfs4Plugin {
            plugins.append("ClientTransportPlugin=\"obfs4 socks5 127.0.0.1:\(obfs4Port)\"")
        }
        if torrcHasSnowflakePlugin {
            plugins.append("ClientTransportPlugin=\"snowflake socks5 127.0.0.1:\(snowflakePort)\"")
        }
        return plugins
    }

    /// Bring a parked Tor back: fresh transports, fresh SOCKS port (set while
    /// the network is still off, so Tor binds nothing early), then network on
    /// and wait for a usable route. The same state every time, independent of
    /// how long iOS kept the app suspended. Returns true once usable.
    private func unparkNetwork(trigger: String) async -> Bool {
        if Task.isCancelled { return false }
        SecureLogger.torDiag("[UNPARK] begin (\(trigger))")
        let started = Date()
        isParked = false
        circuitEstablished = false
        bootstrapProgress = 10
        statusMessage = "Reconnecting..."
        notifyStateChanged()

        if torrcHasObfs4Plugin { obfs4Port = restartTransport(IPtProxyBridge.obfs4Name, current: obfs4Port) }
        if torrcHasSnowflakePlugin { snowflakePort = restartTransport(IPtProxyBridge.snowflakeName, current: snowflakePort) }

        SecureLogger.torDiag("[UNPARK] transports restarted obfs4=\(obfs4Port > 0) snowflake=\(snowflakePort > 0) cancelled=\(Task.isCancelled)")
        let newPort = freshSocksPortCandidate()
        let args = transportPluginArguments() + ["SOCKSPort=127.0.0.1:\(newPort)"]
        let set = await sendInProcessControlCommand("SETCONF " + args.joined(separator: " "), timeoutSeconds: 5.0)
        guard set?.hasPrefix("250") == true else {
            SecureLogger.torDiag("[UNPARK] SETCONF refused: \(set?.prefix(60) ?? "nil")")
            return false
        }
        socksPort = newPort
        Self.bumpConnectionEpoch()

        var on = await sendInProcessControlCommand("SETCONF DisableNetwork=0", timeoutSeconds: 5.0)
        if on?.hasPrefix("250") != true, await moveSocksToFreshPort(tag: "[UNPARK]") {
            on = await sendInProcessControlCommand("SETCONF DisableNetwork=0", timeoutSeconds: 5.0)
        }
        guard on?.hasPrefix("250") == true else {
            SecureLogger.torDiag("[UNPARK] DisableNetwork=0 refused: \(on?.prefix(60) ?? "nil")")
            return false
        }
        bootstrapProgress = 20
        statusMessage = "Reconnecting... 20%"
        notifyStateChanged()

        for poll in 1...60 {
            try? await Task.sleep(nanoseconds: 500_000_000)
            if Task.isCancelled { return false }
            if await isUsableNow(socksTimeout: 2.0) {
                markCircuitConnected()
                SecureLogger.torDiag("[UNPARK] connected in \(Int(Date().timeIntervalSince(started)))s (\(trigger))")
                return true
            }
            if let p = await queryBootstrapViaInProcessFD() {
                bootstrapProgress = min(99, max(20, p))
            }
            statusMessage = "Reconnecting... \(bootstrapProgress)%"
            notifyStateChanged()
            // SOCKS answers but no circuit after ~2 s: ask for one (again at
            // ~10 s and ~20 s in case the first attempt failed).
            if poll == 4 || poll == 20 || poll == 40, await checkSOCKSPortReady(timeoutSeconds: 1.0) {
                await demandCircuit(tag: "[UNPARK]")
            }
        }
        SecureLogger.torDiag("[UNPARK] no usable route after 30s (\(trigger))")
        return false
    }

    /// Re-open Tor's SOCKS listener on a fresh random loopback port, when the
    /// DisableNetwork re-bind cannot bring the old port back. Seen on both
    /// phones on 02.10.2026 10:58 after ~43 min in the background: Tor
    /// accepted the re-enable, SOCKS stayed dead through re-bind and RELOAD,
    /// only a cold start helped (Tor's own log of that event was not
    /// captured). Reproduced on the 12 Pro: port still held → Tor answers
    /// "553 Failed to bind" (`Address already in use` in its log); port dead
    /// after re-enable → no SOCKS greeting. Both recovered on a fresh port in
    /// 6–7 s. Loopback only, same Tor, same isolation defaults; the new port
    /// reaches every consumer through the persisted SOCKS5 config written by
    /// markCircuitConnected(). Returns true if Tor accepted it.
    private func moveSocksToFreshPort(tag: String) async -> Bool {
        for _ in 1...3 {
            let newPort = freshSocksPortCandidate()
            let reply = await sendInProcessControlCommand("SETCONF SOCKSPort=127.0.0.1:\(newPort)", timeoutSeconds: 5.0)
            let ok = reply?.hasPrefix("250") == true
            SecureLogger.torDiag("\(tag) SOCKSPort move: \(ok ? "accepted" : String(reply?.prefix(80) ?? "nil"))")
            if ok {
                socksPort = newPort
                Self.bumpConnectionEpoch()
                let listeners = await socksListenerAddresses()
                SecureLogger.torDiag("\(tag) SOCKS listener after move: \(listeners.map { $0.isEmpty ? "none" : $0 } ?? "unknown")")
                return true
            }
        }
        return false
    }

    private func rebindListenersViaInProcessFD(tag: String) async -> Bool {
        // ── PRIMARY FIX: DisableNetwork toggle via in-process control FD ─────────
        // ROOT CAUSE: After iOS background suspension, TCP listen sockets are dead
        // BUT Tor's internal connection_t objects still exist with matching addr/port.
        // retry_all_listeners() sees the match and SKIPS re-binding (thinks they're alive).
        //
        // SOLUTION: DisableNetwork=1 calls connection_mark_all_noncontrol_connections()
        // which EXPLICITLY CLOSES all zombie listeners. Then DisableNetwork=0 triggers
        // retry_all_listeners() which finds NO existing listeners → creates fresh ones.
        //
        // SIGNAL RELOAD does NOT work because it calls retry_all_listeners() directly,
        // which matches zombie connection_t objects and skips rebinding.
        statusMessage = "Reconnecting..."
        circuitEstablished = false
        bootstrapProgress = 1
        // P8-AUDIT8-IOS-27 (audit F41): treat the listener release below like
        // parking. DisableNetwork=1 frees the loopback SOCKS port while the
        // persisted SOCKS5 config still pointed at it and the epoch was
        // unchanged — the lanes kept running and their next request could
        // connect to whatever process bound that port next (another app),
        // bypassing Tor. Clearing the config and bumping the epoch first makes
        // the session pause its lanes (no endpoint) until markCircuitConnected
        // writes the new one.
        TorController.clearSOCKS5ConfigFromKeychain()
        Self.bumpConnectionEpoch()
        notifyStateChanged()

        // Step 1: Wake Tor from dormant mode first (in case DormantClientTimeout triggered)
        let activeResp = await sendInProcessControlCommand("SIGNAL ACTIVE", timeoutSeconds: 5.0)
        SecureLogger.torDiag("\(tag) SIGNAL ACTIVE: \(activeResp?.prefix(40) ?? "nil")")

        // Step 2: DisableNetwork=1 — closes ALL non-control connections (zombie listeners!)
        // Note: 250 OK is returned IMMEDIATELY but actual processing is ASYNCHRONOUS
        // (libevent processes it in the next loop iteration). We MUST wait.
        let dn1 = await sendInProcessControlCommand("SETCONF DisableNetwork=1", timeoutSeconds: 5.0)
        let dn1OK = dn1?.hasPrefix("250") == true
        if dn1OK { Self.bumpConnectionEpoch() }
        SecureLogger.torDiag("\(tag) DisableNetwork=1: \(dn1?.prefix(40) ?? "nil") ok=\(dn1OK)")

        if dn1OK {
            // Wait 1.5s for libevent to process the DisableNetwork=1 command.
            // This gives Tor time to actually close zombie listener connections.
            try? await Task.sleep(nanoseconds: 1_500_000_000)

            // Tor must dial the transports where they listen now. Seen on the
            // 12 Pro (03.10.2026 15:44, push wake): the transports had been
            // restarted on new ports, Tor kept dialling the previous ones and
            // every bridge connection failed ("connection to the SOCKS5 proxy
            // … failed"). Re-applying the current ports is idempotent.
            let plugins = transportPluginArguments()
            if !plugins.isEmpty {
                let applied = await sendInProcessControlCommand("SETCONF " + plugins.joined(separator: " "), timeoutSeconds: 5.0)
                SecureLogger.torDiag("\(tag) transport ports re-applied: \(applied?.prefix(40) ?? "nil")")
            }
            bootstrapProgress = 10
            statusMessage = "Reconnecting... 10%"
            notifyStateChanged()

            // Step 3: DisableNetwork=0 — triggers retry_all_listeners() with NO existing
            // listeners → fresh bind()+listen() on SOCKSPort and ControlPort
            var dn0 = await sendInProcessControlCommand("SETCONF DisableNetwork=0", timeoutSeconds: 5.0)
            var dn0OK = dn0?.hasPrefix("250") == true
            SecureLogger.torDiag("\(tag) DisableNetwork=0: \(dn0?.prefix(40) ?? "nil") ok=\(dn0OK)")
            // Tor refuses DisableNetwork=0 when it cannot bind a listener port
            // and keeps the network disabled. Move SOCKS to a fresh port while
            // the network is still off, then enable again — once.
            var movedPort = false
            if !dn0OK, await moveSocksToFreshPort(tag: tag) {
                movedPort = true
                dn0 = await sendInProcessControlCommand("SETCONF DisableNetwork=0", timeoutSeconds: 5.0)
                dn0OK = dn0?.hasPrefix("250") == true
                SecureLogger.torDiag("\(tag) DisableNetwork=0 after port move: \(dn0?.prefix(40) ?? "nil") ok=\(dn0OK)")
            }

            if dn0OK {
                // Wait 1s for libevent to process and re-bind listeners
                try? await Task.sleep(nanoseconds: 1_000_000_000)
                bootstrapProgress = 20
                statusMessage = "Reconnecting... 20%"
                notifyStateChanged()
                let listeners = await socksListenerAddresses()
                SecureLogger.torDiag("\(tag) SOCKS listener after re-enable: \(listeners.map { $0.isEmpty ? "none" : $0 } ?? "unknown")")

                // Step 4: Poll SOCKS5 — listeners should be fresh, circuits rebuilding
                for poll in 1...60 {
                    try? await Task.sleep(nanoseconds: 500_000_000)
                    if Task.isCancelled { return false }
                    if await isUsableNow(socksTimeout: 2.0) {
                        markCircuitConnected()
                        SecureLogger.torDiag("\(tag) DisableNetwork toggle → connected at poll \(poll)\(movedPort ? " (fresh SOCKS port)" : "")")
                        return true
                    }
                    // Every successful re-bind so far answered SOCKS at poll 1.
                    // Still no SOCKS greeting after ~3 s: the port itself is the
                    // problem, not the circuit — move to a fresh one, once.
                    if poll == 6, !movedPort, !(await checkSOCKSPortReady(timeoutSeconds: 1.0)) {
                        movedPort = await moveSocksToFreshPort(tag: tag)
                        continue
                    }
                    if poll == 8 || poll == 30, await checkSOCKSPortReady(timeoutSeconds: 1.0) {
                        await demandCircuit(tag: tag)
                    }
                    // Query bootstrap via in-process FD (TCP ControlPort may still be rebuilding)
                    if let p = await queryBootstrapViaInProcessFD() {
                        bootstrapProgress = min(99, p)
                    } else {
                        bootstrapProgress = min(99, 20 + poll)
                    }
                    statusMessage = "Reconnecting... \(bootstrapProgress)%"
                    notifyStateChanged()

                    // At poll 20 (~10s), try NEWNYM to break stuck circuits
                    if poll == 20 {
                        let _ = await sendInProcessControlCommand("SIGNAL NEWNYM", timeoutSeconds: 2.0)
                        SecureLogger.torDiag("\(tag) NEWNYM at poll 20")
                    }
                }
                SecureLogger.torDiag("\(tag) DisableNetwork toggle OK but SOCKS5 not ready after 30s")
            }
        } else {
            SecureLogger.torDiag("\(tag) DisableNetwork=1 failed — in-process FD may be dead")
        }

        // ── FALLBACK: SIGNAL RELOAD ──────────────────────────────────────────────
        // If DisableNetwork toggle failed, try SIGNAL RELOAD as fallback
        if Task.isCancelled { return false }
        SecureLogger.torDiag("\(tag) FALLBACK: trying SIGNAL RELOAD")
        // RELOAD re-reads the torrc file. Its ports are the ones from launch;
        // after a transport restart or a SOCKS port move they are stale, and
        // RELOAD reverted both (12 Pro, 02.10.2026 12:48:29: "Closing
        // no-longer-configured Socks listener", transports "marked for
        // deletion"). Rewrite it with the current ports first.
        createTorrcConfig()
        let reloadResp = await sendInProcessControlCommand("SIGNAL RELOAD", timeoutSeconds: 10.0)
        let reloadOK = reloadResp?.hasPrefix("250") == true
        if reloadOK { Self.bumpConnectionEpoch() }
        SecureLogger.torDiag("\(tag) SIGNAL RELOAD: \(reloadResp?.prefix(40) ?? "nil") ok=\(reloadOK)")
        if reloadOK {
            try? await Task.sleep(nanoseconds: 2_000_000_000)
            for poll in 1...40 {
                try? await Task.sleep(nanoseconds: 500_000_000)
                if Task.isCancelled { return false }
                if await isUsableNow(socksTimeout: 2.0) {
                    markCircuitConnected()
                    SecureLogger.torDiag("\(tag) RELOAD fallback → connected at poll \(poll)")
                    return true
                }
                if let p = await queryBootstrapViaInProcessFD() {
                    bootstrapProgress = min(99, p)
                } else {
                    bootstrapProgress = min(99, 50 + poll)
                }
                statusMessage = "Reconnecting... \(bootstrapProgress)%"
                notifyStateChanged()
            }
        }

        return false
    }

    /// Mark circuit as fully connected and persist SOCKS5 config.
    private func markCircuitConnected() {
        // Without a control connection isUsableNow falls back to the SOCKS
        // greeting alone; an abandoned recovery, or the one that just lost the
        // control connection, must not declare a route from that.
        guard !Task.isCancelled, !controlLost else { return }
        circuitEstablished = true
        bootstrapProgress = 100
        statusMessage = "Connected"
        TorController.saveSOCKS5ConfigToKeychain(host: "127.0.0.1", port: Int(socksPort))
        notifyStateChanged()
        // Health monitoring must run whenever Tor is up; the verify path used
        // to mark "connected" without (re)starting it.
        if isRunning && healthMonitorTask == nil { startHealthMonitoring() }
    }

    // MARK: - Health Monitoring & Auto-Reconnect

    /// Start continuous health monitoring after successful bootstrap.
    /// Detects Tor failures via periodic SOCKS5 checks and network path changes.
    /// Consecutive health checks in which Tor reported no usable circuit.
    private var notUsableStreak = 0

    /// Tor's own view: `status/circuit-established` and `network-liveness`,
    /// asked over the in-process control FD. true/false only for a clear
    /// answer; nil when Tor could not be asked (then nothing is concluded).
    /// Measured 30.09.2026: 66 of 66 samples "=1"/"up" while traffic worked.
    private func torReportsUsableCircuit() async -> Bool? {
        guard let est = await sendInProcessControlCommand("GETINFO status/circuit-established", timeoutSeconds: 3.0),
              let live = await sendInProcessControlCommand("GETINFO network-liveness", timeoutSeconds: 3.0),
              est.hasPrefix("250"), live.hasPrefix("250") else { return nil }
        if est.contains("status/circuit-established=1"), live.contains("network-liveness=up") { return true }
        if est.contains("status/circuit-established=0") || live.contains("network-liveness=down") { return false }
        return nil
    }

    private func startHealthMonitoring() {
        stopHealthMonitoring()
        reconnectAttempts = 0
        notUsableStreak = 0

        // 1. Periodic check every 30 s while connected. It never exits on a
        // failure any more (that used to leave no monitor at all); it hands the
        // failure to the coordinator and keeps watching.
        healthMonitorTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 30_000_000_000) // 30s
                guard let self = self, !Task.isCancelled, self.isRunning else { continue }
                // Down: the down-retry owns recovery. Recovery running: wait.
                if !self.circuitEstablished || self.isVerifyingCircuit { continue }

                let isHealthy = await self.checkSOCKSPortReady()
                if !isHealthy {
                    #if DEBUG
                    SecureLogger.debug("[TorController] \u{26A0}\u{FE0F} Health check: SOCKS5 port unresponsive")
                    #endif
                    await self.ensureUsable(trigger: "health: SOCKS5 unresponsive")
                    continue
                }
                // The proxy can answer while Tor has no working circuit — on
                // the 12 Pro (30.09.2026) every request then failed (CFNetwork
                // 310) for 5+ minutes and nothing noticed. Ask Tor itself.
                // Act only on an explicit "no circuit" / "network down", twice
                // in a row (≥ 60 s) — this loop only acts while connected, so
                // never during bootstrap (cf. 7752afb).
                if let usable = await self.torReportsUsableCircuit() {
                    self.notUsableStreak = usable ? 0 : self.notUsableStreak + 1
                    SecureLogger.torDiag("[HEALTH] Tor circuit usable=\(usable) streak=\(self.notUsableStreak)")
                    if self.notUsableStreak >= 2 {
                        self.notUsableStreak = 0
                        await self.ensureUsable(trigger: "health: no usable circuit")
                    }
                }
            }
        }

        // 2. Network path change detection (instant on WiFi↔LTE switch)
        let monitor = NWPathMonitor()
        networkPathMonitor = monitor
        monitor.pathUpdateHandler = { [weak self] path in
            guard path.status == .satisfied else { return }
            Task { @MainActor [weak self] in
                guard let self = self, self.isRunning else { return }
                if self.isVerifyingCircuit { return }

                // FIX WIFI-RECONNECT: When network returns but circuit is already down
                // (e.g. WiFi lost for minutes), trigger reconnection instead of ignoring.
                if !self.circuitEstablished {
                    #if DEBUG
                    SecureLogger.debug("[TorController] 📡 Network returned while circuit down — triggering reconnection")
                    #endif
                    await self.ensureUsable(trigger: "network returned")
                    return
                }

                #if DEBUG
                SecureLogger.debug("[TorController] 📡 Network path changed — verifying Tor circuit")
                #endif
                let isHealthy = await self.checkSOCKSPortReady()
                if !isHealthy {
                    await self.ensureUsable(trigger: "network path changed")
                }
            }
        }
        monitor.start(queue: DispatchQueue.global(qos: .utility))
        
        #if DEBUG
        print("[TorController] \u{1FA7A} Health monitoring started (30s interval + network observer)")
        #endif
    }
    
    /// Stop health monitoring (called on Tor shutdown)
    private func stopHealthMonitoring() {
        healthMonitorTask?.cancel()
        healthMonitorTask = nil
        networkPathMonitor?.cancel()
        networkPathMonitor = nil
        downRetryTask?.cancel()
        downRetryTask = nil
    }

    /// Kept for its callers; all recovery now runs in ensureUsable().
    /// FIX ZOMBIE-04 still holds: NEVER stopTor() + startTor() — tor_main()
    /// can only run once per process; recovery uses control commands only.
    func handleTorFailure(reason: String) async {
        await ensureUsable(trigger: reason)
    }

    // MARK: - Recovery coordinator (01.10.2026)
    //
    // One serialised recovery for every trigger (foreground return, health
    // check, network path, push wake-up, down-retry). Before, three paths
    // could run at once and clear each other's isVerifyingCircuit; the
    // foreground path was skipped when backgroundedAt was nil; and "connected"
    // was declared on the local SOCKS greeting alone.
    //
    // Security: only commands the app already sent before (SIGNAL ACTIVE /
    // NEWNYM / RELOAD, SETCONF DisableNetwork) over the in-process FD, plus
    // local probes. UseBridges is never touched; nothing here can open a
    // connection outside Tor (every V2 session requires Tor, fail-closed).

    private var recoveryTask: Task<Bool, Never>?
    private var downRetryTask: Task<Void, Never>?
    /// Bumped when a recovery starts or is abandoned; a recovery whose number
    /// is no longer current must not touch the shared state when it ends.
    private var recoveryGeneration = 0
    /// The running recovery began while the app was in the background (push
    /// wake). iOS may have frozen it halfway, so a later wake never waits on it.
    private var recoveryStartedInBackground = false

    /// Cancel the running recovery. Cancelled, it can no longer reach Tor
    /// (sendInProcessControlCommand returns nil), restart a transport or
    /// declare a route (isUsableNow is false) — so it cannot undo a park.
    private func abandonRecovery(tag: String) {
        guard let running = recoveryTask else { return }
        running.cancel()
        recoveryTask = nil
        recoveryGeneration += 1
        downRetryTask?.cancel()
        downRetryTask = nil
        isVerifyingCircuit = false
        SecureLogger.torDiag("\(tag) running recovery abandoned (started in background=\(recoveryStartedInBackground))")
    }

    /// SOCKS5 greeting answers AND Tor does not report "no circuit / network
    /// down". If Tor cannot be asked (nil), the greeting decides — the old
    /// behaviour — so this check can never wedge the app by itself.
    private func isUsableNow(socksTimeout: TimeInterval) async -> Bool {
        if Task.isCancelled { return false }
        guard await checkSOCKSPortReady(timeoutSeconds: socksTimeout) else { return false }
        // P8-AUDIT8-IOS-27: a SOCKS greeting on the port does not prove it is
        // Tor — any process can answer 0x05. Tor itself must report that it is
        // bound there (in-process control FD; format measured on the 12 Pro:
        // `net/listeners/socks="127.0.0.1:<port>"`). Unknown → not usable.
        guard let listeners = await socksListenerAddresses(),
              listeners.split(separator: " ").contains(Substring("127.0.0.1:\(socksPort)")) else {
            SecureLogger.torDiag("[TOR] SOCKS port answers but Tor does not report it as its listener — not usable")
            return false
        }
        if Task.isCancelled { return false }
        return await torReportsUsableCircuit() != false
    }

    /// DEBUG diagnostics (torDiag is DEBUG-only): booleans, no identifiers.
    private func logRecoveryState(_ phase: String, trigger: String) async {
        #if DEBUG
        let socks = await checkSOCKSPortReady(timeoutSeconds: 1.5)
        let route = await torReportsUsableCircuit()
        var obfs4 = "off"
        if obfs4Port > 0 { obfs4 = await checkSOCKSPortReady(timeoutSeconds: 1.5, portOverride: obfs4Port) ? "alive" : "dead" }
        var snowflake = "off"
        if snowflakePort > 0 { snowflake = await checkSOCKSPortReady(timeoutSeconds: 1.5, portOverride: snowflakePort) ? "alive" : "dead" }
        let routeText = route.map { $0 ? "yes" : "no" } ?? "unknown"
        let tor = await torInternalCounts()
        let listener = await socksListenerAddresses().map { $0.isEmpty ? "none" : "bound" } ?? "unknown"
        SecureLogger.torDiag("[RECOVERY] \(phase) trigger=\(trigger) socks=\(socks) socks_listener=\(listener) route=\(routeText) pt_obfs4=\(obfs4) pt_snowflake=\(snowflake) \(tor)")
        #endif
    }

    /// DEBUG diagnostics: counts only (no fingerprints, no addresses) of
    /// Tor's built circuits and of its bridges/guards by state, asked over
    /// the in-process control FD. Local; no network traffic.
    private func torInternalCounts() async -> String {
        #if DEBUG
        var built = -1, launched = -1
        if let cs = await sendInProcessMultilineDiagnostic("GETINFO circuit-status"), cs.hasPrefix("250") {
            let lines = cs.split(whereSeparator: \.isNewline)
            built = lines.filter { $0.contains(" BUILT ") }.count
            launched = lines.filter { $0.contains(" LAUNCHED ") || $0.contains(" EXTENDED ") }.count
        }
        var up = -1, down = -1, never = -1
        if let eg = await sendInProcessMultilineDiagnostic("GETINFO entry-guards"), eg.hasPrefix("250") {
            let lines = eg.split(whereSeparator: \.isNewline)
            up = lines.filter { $0.hasSuffix(" up") || $0.contains(" up ") }.count
            down = lines.filter { $0.contains(" down") || $0.contains(" unusable") }.count
            never = lines.filter { $0.contains(" never-connected") }.count
        }
        return "circ_built=\(built) circ_building=\(launched) guards_up=\(up) guards_down=\(down) guards_never=\(never)"
        #else
        return ""
        #endif
    }

    /// Every recovery goes through here. Concurrent callers await the round
    /// already running — two repairs never overlap. Returns true when Tor is
    /// usable afterwards.
    @discardableResult
    func ensureUsable(trigger: String, forceRebind: Bool = false, nudgeIfHealthy: Bool = false, wake: Bool = false) async -> Bool {
        // A recovery begun in the background may have been frozen halfway by
        // iOS. Never wait on it: park, and start over from that known state.
        if wake, recoveryTask != nil, recoveryStartedInBackground, isRunning {
            abandonRecovery(tag: "[WAKE]")
            if !isParked { _ = await parkNetwork(tag: "[WAKE]") }
        }
        if let running = recoveryTask { return await running.value }
        guard isRunning, !controlLost else { return false }
        // Parked on purpose: only a real wake (foreground return, push) brings
        // the network back — not a health or network-path trigger.
        if isParked && !wake { return false }
        recoveryGeneration += 1
        let generation = recoveryGeneration
        recoveryStartedInBackground = UIApplication.shared.applicationState == .background
        let task = Task { @MainActor [weak self] () -> Bool in
            guard let self = self else { return false }
            return await self.runRecovery(trigger: trigger, forceRebind: forceRebind, nudgeIfHealthy: nudgeIfHealthy, generation: generation)
        }
        recoveryTask = task
        let ok = await task.value
        // Abandoned meanwhile: recoveryTask and the retry belong to whatever
        // replaced it.
        guard generation == recoveryGeneration else { return false }
        recoveryTask = nil
        if ok {
            downRetryTask?.cancel()
            downRetryTask = nil
        } else {
            scheduleDownRetry()
        }
        return ok
    }

    private func runRecovery(trigger: String, forceRebind: Bool, nudgeIfHealthy: Bool, generation: Int) async -> Bool {
        guard isRunning else { return false }
        isVerifyingCircuit = true
        defer { if generation == recoveryGeneration { isVerifyingCircuit = false } }
        let started = Date()
        var forceRebind = forceRebind
        if isParked {
            if await unparkNetwork(trigger: trigger) { return true }
            // Unpark did not get a route: the full repair below, as after a
            // long background.
            forceRebind = true
        }
        if Task.isCancelled { return false }
        await logRecoveryState("start", trigger: trigger)

        if !forceRebind, await isUsableNow(socksTimeout: 1.5) {
            if nudgeIfHealthy {
                _ = await sendInProcessControlCommand("SIGNAL NEWNYM", timeoutSeconds: 2.0)
            }
            markCircuitConnected()
            SecureLogger.torDiag("[RECOVERY] healthy — no repair (\(trigger))")
            return true
        }

        // Tor reaches the network only through the bridge listeners; with
        // them dead neither the nudge nor the re-bind below can help.
        await repairPluggableTransportsIfDead()
        if Task.isCancelled { return false }

        if !forceRebind {
            // Listeners answer but Tor reports no circuit / network down:
            // wake it and give it a short window before touching the network
            // configuration.
            if await checkSOCKSPortReady(timeoutSeconds: 1.5) {
                circuitEstablished = false
                bootstrapProgress = min(max(bootstrapProgress, 1), 95)
                statusMessage = "Reconnecting..."
                notifyStateChanged()
                _ = await sendInProcessControlCommand("SIGNAL ACTIVE", timeoutSeconds: 5.0)
                _ = await sendInProcessControlCommand("SIGNAL NEWNYM", timeoutSeconds: 2.0)
                await demandCircuit(tag: "[RECOVERY]")
                for _ in 1...15 {
                    try? await Task.sleep(nanoseconds: 1_000_000_000)
                    if Task.isCancelled { return false }
                    if await isUsableNow(socksTimeout: 1.5) {
                        markCircuitConnected()
                        SecureLogger.torDiag("[RECOVERY] route back after nudge in \(Int(Date().timeIntervalSince(started)))s (\(trigger))")
                        return true
                    }
                }
            }
        }

        if Task.isCancelled { return false }
        // Listeners dead, no route after the nudge, or a long background:
        // the proven re-bind (DisableNetwork 1 → 0 over the in-process FD,
        // RELOAD fallback). It marks connected only on isUsableNow.
        if await rebindListenersViaInProcessFD(tag: "[RECOVERY]") {
            SecureLogger.torDiag("[RECOVERY] connected after re-bind in \(Int(Date().timeIntervalSince(started)))s (\(trigger))")
            await logRecoveryState("after", trigger: trigger)
            return true
        }
        await logRecoveryState("failed", trigger: trigger)
        statusMessage = "Reconnecting..."
        notifyStateChanged()
        return false
    }

    /// iOS reclaims the IPtProxy listeners (obfs4 / Snowflake) of a suspended
    /// app just like Tor's own. Tor then gets SOCKS back after a re-bind but
    /// has no way to reach a bridge (12 Pro, 01.10.2026 22:08: pt_obfs4=dead
    /// pt_snowflake=dead, route=no through re-bind and RELOAD). Restart the
    /// dead transports and point Tor's existing plugin lines at their new
    /// loopback ports. Bridge lines and UseBridges are never touched; if a
    /// restart or the SETCONF fails, Tor simply keeps having no route
    /// (fail-closed) — nothing here can bypass the bridges.
    private func repairPluggableTransportsIfDead() async {
        guard iptProxyBridge != nil, torrcHasObfs4Plugin || torrcHasSnowflakePlugin else { return }
        let obfs4Dead = torrcHasObfs4Plugin && obfs4Port > 0
            ? !(await checkSOCKSPortReady(timeoutSeconds: 1.5, portOverride: obfs4Port)) : false
        let snowflakeDead = torrcHasSnowflakePlugin && snowflakePort > 0
            ? !(await checkSOCKSPortReady(timeoutSeconds: 1.5, portOverride: snowflakePort)) : false
        guard obfs4Dead || snowflakeDead, !Task.isCancelled else { return }

        if obfs4Dead { obfs4Port = restartTransport(IPtProxyBridge.obfs4Name, current: obfs4Port) }
        if snowflakeDead { snowflakePort = restartTransport(IPtProxyBridge.snowflakeName, current: snowflakePort) }
        let reply = await sendInProcessControlCommand("SETCONF " + transportPluginArguments().joined(separator: " "), timeoutSeconds: 5.0)
        let obfs4Alive = torrcHasObfs4Plugin ? await checkSOCKSPortReady(timeoutSeconds: 1.5, portOverride: obfs4Port) : false
        let snowflakeAlive = torrcHasSnowflakePlugin ? await checkSOCKSPortReady(timeoutSeconds: 1.5, portOverride: snowflakePort) : false
        SecureLogger.torDiag("[RECOVERY] PT restart obfs4=\(obfs4Dead ? (obfs4Alive ? "alive" : "dead") : "untouched") snowflake=\(snowflakeDead ? (snowflakeAlive ? "alive" : "dead") : "untouched") setconf=\(reply?.hasPrefix("250") == true ? "ok" : "failed")")
    }

    /// For a push wake-up: true at once if Tor is usable; otherwise start the
    /// coordinator (not awaited — it may outlast the window) and wait up to
    /// `timeoutSeconds` for it. Local probes only.
    func waitUntilUsable(timeoutSeconds: TimeInterval) async -> Bool {
        guard isRunning else { return false }
        if circuitEstablished, await isUsableNow(socksTimeout: 1.0) { return true }
        Task { @MainActor [weak self] in
            await self?.ensureUsable(trigger: "push wake", wake: true)
        }
        let deadline = Date().addingTimeInterval(timeoutSeconds)
        while Date() < deadline {
            try? await Task.sleep(nanoseconds: 500_000_000)
            if circuitEstablished && !isVerifyingCircuit { return true }
        }
        return circuitEstablished
    }

    /// While Tor stays unusable: notice an organic recovery within ~2 s
    /// (local probes only) and repeat the repair with backoff 30/60/120/300 s.
    /// Replaces the former endless NEWNYM loop.
    private func scheduleDownRetry() {
        guard isRunning, downRetryTask == nil else { return }
        downRetryTask = Task { [weak self] in
            let backoff: [TimeInterval] = [30, 60, 120, 300]
            var attempt = 0
            var nextRepair = Date().addingTimeInterval(backoff[0])
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 2_000_000_000)
                guard let self = self, !Task.isCancelled, self.isRunning else { return }
                // Recovered elsewhere (foreground return, network path): done.
                if self.circuitEstablished { break }
                if self.isVerifyingCircuit { continue }
                if await self.isUsableNow(socksTimeout: 1.5) {
                    self.markCircuitConnected()
                    SecureLogger.torDiag("[RECOVERY] recovered on its own (down-retry)")
                    break
                }
                if Date() >= nextRepair {
                    attempt += 1
                    nextRepair = Date().addingTimeInterval(backoff[min(attempt, backoff.count - 1)])
                    if await self.ensureUsable(trigger: "down-retry #\(attempt)") { break }
                }
            }
            self?.downRetryTask = nil
        }
    }

    // MARK: - Hidden Service
    
    /// Get onion address for this device (if hidden service enabled)
    func getOnionAddress() async -> String? {
        let hostnameFile = torDataDir.appendingPathComponent("hidden_service/hostname")
        
        guard FileManager.default.fileExists(atPath: hostnameFile.path),
              let onionAddress = try? String(contentsOf: hostnameFile, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines) else {
            return nil
        }
        
        return onionAddress
    }
    
    // MARK: - M5 FIX: Encrypted Bridge Management
    
    /// FIX CRIT-11: Derive bridge decryption key using HKDF from app-specific constants
    /// PLUS a per-device Keychain secret. Previously used only public inputs (bundle ID
    /// + static salt) which are extractable from the binary.
    private static func bridgeDecryptionKey() throws -> SymmetricKey {
        let bundleID = (Bundle.main.bundleIdentifier ?? "app.ladon.messenger").data(using: .utf8)!
        let staticSalt = Data("LadonBridgeKey-2026-v2".utf8)
        
        // FIX CRIT-11: Include per-device Keychain secret as additional entropy
        // FIX AUDIT-R7-09: Wipe deviceSecret + combinedInput after key derivation
        var deviceSecret = try loadOrCreateBridgeDeviceSecret()
        defer { deviceSecret.securelyWipe() }
        
        // Combine bundle ID + device secret as input key material
        var combinedInput = Data()
        combinedInput.append(bundleID)
        combinedInput.append(deviceSecret)
        defer { combinedInput.securelyWipe() }
        
        let inputKey = SymmetricKey(data: combinedInput)
        let derived = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: inputKey,
            salt: staticSalt,
            info: Data("tor-bridge-obfuscation".utf8),
            outputByteCount: 32
        )
        return derived
    }
    
    /// FIX CRIT-11: Load or create a per-device random secret stored in Keychain.
    /// This prevents binary-extraction attacks on the bridge decryption key.
    private static func loadOrCreateBridgeDeviceSecret() throws -> Data {
        let account = "ladon_bridge_device_secret"
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecAttrService as String: "app.ladon.messenger",
            kSecReturnData as String: true,
            kSecAttrSynchronizable as String: false
        ]
        var result: CFTypeRef?
        if SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
           let data = result as? Data, data.count == 32 {
            return data
        }
        // Generate new 32-byte random secret
        var secret = Data(count: 32)
        // FIX A7-RNG: Guard CSPRNG — zero secret compromises bridge device authentication
        let rngBridge = secret.withUnsafeMutableBytes { ptr in
            SecRandomCopyBytes(kSecRandomDefault, 32, ptr.baseAddress!)
        }
        if rngBridge != errSecSuccess {
            SecureLogger.error("[TorController] CSPRNG failure for bridge secret: \(rngBridge)")
            // FIX CSPRNG-01: Throw instead of fatalError. CSPRNG failure is catastrophic
            // but crashing the app on every launch is worse — Tor will simply start
            // without bridge authentication (reduced privacy, not zero security).
            throw TorError.controlPortUnavailable
        }
        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecAttrService as String: "app.ladon.messenger",
            kSecValueData as String: secret,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]
        let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
        if addStatus != errSecSuccess && addStatus != errSecDuplicateItem {
            SecureLogger.error("[TorController] Keychain write failed for bridge secret: \(addStatus)")
        }
        return secret
    }
    
    /// Encrypt a bridge line for embedding in the binary
    /// Call this once offline to generate the encrypted bridge data
    #if DEBUG
    static func encryptBridgeForEmbedding(_ bridgeLine: String) -> String? {
        guard let key = try? bridgeDecryptionKey() else { return nil }
        guard let plaintext = bridgeLine.data(using: .utf8) else { return nil }
        guard let sealed = try? ChaChaPoly.seal(plaintext, using: key) else { return nil }
        return sealed.combined.base64EncodedString()
    }
    #endif
    
    /// Decrypt an embedded bridge line at runtime
    private static func decryptBridge(_ encryptedBase64: String) -> String {
        guard let combined = Data(base64Encoded: encryptedBase64) else { return "" }
        guard let key = try? bridgeDecryptionKey() else { return "" }
        guard let sealedBox = try? ChaChaPoly.SealedBox(combined: combined),
              let plaintext = try? ChaChaPoly.open(sealedBox, using: key) else {
            return ""
        }
        return String(data: plaintext, encoding: .utf8) ?? ""
    }
    
    // FIX C3: Klartext-Bridges komplett entfernt aus Binary.
    // Bridges are ONLY loaded from server (HTTPS) or from Keychain cache.
    // No plaintext fallback — Tor connects without bridges if cache is empty.
    
    /// Key for caching bridges in Keychain
    private static let bridgeCacheKey = "ladon_cached_bridges"
    
    /// Load bridge lines: from Keychain cache only (fetched from server via HTTPS)
    /// FIX C3: No plaintext fallback — Bridges only from cached server fetch
    /// Built-in obfs4 bridges, obtained from bridges.torproject.org. These are
    /// meant for redistribution and are not secret.
    ///
    /// They exist because obfs4 had no source at all: `refreshBridgesFromServer()`
    /// has been empty since `/v1/bridges` was retired with V1, so the Keychain
    /// cache could only ever be empty and the transport ran into nothing.
    ///
    /// obfs4 is a plain TCP connection to a fixed address with an obfuscation
    /// layer — no broker, no rendezvous — so it connects far faster than
    /// Snowflake, which spent 80 of 84 measured seconds waiting for a proxy
    /// match. Both stay configured: whichever completes first carries the
    /// circuit, and Snowflake remains the way out when these addresses are
    /// blocked. Being public, they are also the first bridges a serious censor
    /// blocks; that is what Snowflake is for.
    private static let builtInObfs4Bridges: [String] = [
        "Bridge obfs4 92.5.79.231:8776 5B9DBF3FB7856D58F290CCE60902E257B52599A3 cert=xY1j9YM8E6uhGqEp0sGad6++hGHSx93t1+IpP+YZsk/QURcdxWIZuBrBo4yivPmFyBJZFQ iat-mode=0",
        "Bridge obfs4 45.39.190.102:4400 FB9DF60962E66929B4C6ABB564F94D038527219B cert=aLRXS6DO7zIhLBcpbZPRhBFpU9DztyQV4A+3svel+2Z2DZ5quoRnjZNtCyrAwQCjy4W3Qw iat-mode=0",
    ]

    /// FIX M-16: Validate bridge line format to prevent torrc injection.
    /// A compromised bridge server could inject Tor config directives.
    /// Only allow lines starting with "Bridge " and containing no control chars.
    /// Applied to the built-in list as well, so one malformed constant cannot
    /// smuggle a directive into the torrc either.
    private static func sanitiseBridgeLines(_ lines: [String]) -> [String] {
        lines.filter { line in
            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
            guard trimmed.hasPrefix("Bridge ") else { return false }
            // Reject any remaining control characters (besides space)
            let hasControlChars = trimmed.unicodeScalars.contains { $0.value < 0x20 }
            return !hasControlChars
        }
    }

    private static func loadBridgeLines() -> [String] {
        if let cached = loadCachedBridges(), !cached.isEmpty {
            let sanitised = sanitiseBridgeLines(cached)
            if !sanitised.isEmpty { return sanitised }
        }
        return sanitiseBridgeLines(builtInObfs4Bridges)
    }
    
    /// Fetch fresh bridges from relay server and cache them
    /// Called periodically or on Tor start
    static func refreshBridgesFromServer() async {
        // V1 `/v1/bridges` is retired. Use cached bridges if present; otherwise
        // Tor connects directly without fetching from the legacy relay.
    }
    
    /// Cache bridges in Keychain (encrypted at rest by iOS)
    /// FIX AUDIT3-IOS-08: Atomic Update-first / Add-on-NotFound pattern.
    /// Previous Delete+Add race: if Delete succeeded but Add failed (transient
    /// Keychain error such as errSecInteractionNotAllowed during background wake
    /// or errSecAuthFailed), the cache was wiped → next launch falls back to
    /// direct (no-bridge) Tor connection. In censored regions this means total
    /// Tor blackout. SecItemUpdate is atomic: previous value remains intact on
    /// failure.
    private static func cacheBridges(_ bridges: [String]) {
        guard let data = try? JSONEncoder().encode(bridges) else { return }
        let baseQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: bridgeCacheKey,
            kSecAttrService as String: "app.ladon.messenger"
        ]
        let updateAttrs: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]
        var status = SecItemUpdate(baseQuery as CFDictionary, updateAttrs as CFDictionary)
        if status == errSecItemNotFound {
            var addQuery = baseQuery
            addQuery[kSecValueData as String] = data
            addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            status = SecItemAdd(addQuery as CFDictionary, nil)
            // errSecDuplicateItem can happen on concurrent races — treat as success
            if status == errSecDuplicateItem {
                status = errSecSuccess
            }
        }
        if status != errSecSuccess {
            SecureLogger.error("[TorController] Keychain write failed for bridge cache: \(status)")
        }
    }
    
    /// Load cached bridges from Keychain
    private static func loadCachedBridges() -> [String]? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: bridgeCacheKey,
            kSecAttrService as String: "app.ladon.messenger",
            kSecReturnData as String: true,
            kSecAttrSynchronizable as String: false
        ]
        
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data,
              let bridges = try? JSONDecoder().decode([String].self, from: data) else {
            return nil
        }
        return bridges
    }
}

// MARK: - Errors

enum TorError: LocalizedError {
    case bootstrapTimeout
    case connectionFailed
    case controlPortUnavailable
    case configurationError
    
    var errorDescription: String? {
        switch self {
        case .bootstrapTimeout:
            return "Tor bootstrap is taking longer than expected"
        case .connectionFailed:
            return "Could not connect to Tor network"
        case .controlPortUnavailable:
            return "Tor control port not responding"
        case .configurationError:
            return "Invalid Tor configuration"
        }
    }
}

// MARK: - SOCKS5 Proxy Config (Keychain)
//
// P8-V1REMOVAL (2026-05-22): moved here from RelayClient. The Tor SOCKS5
// proxy config is V2-critical infrastructure — V2SessionManager and
// BlobRelayPinning both read it to build their Tor-routed URLSession, and
// TorController itself writes it on every bootstrap. It lives with
// TorController (its natural owner) so it can outlive the legacy V1
// RelayClient, which is being removed. Behaviour unchanged; only the
// owning type changed (RelayClient.* → TorController.*).

struct SOCKS5Config: Codable {
    let host: String
    let port: Int
}

extension TorController {
    /// Load SOCKS5 proxy config from Keychain (encrypted, not plaintext UserDefaults)
    nonisolated static func loadSOCKS5ConfigFromKeychain() -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: "app.ladon.messenger.socks5Config",
            kSecAttrService as String: "app.ladon.messenger",
            kSecReturnData as String: true,
            kSecAttrSynchronizable as String: false
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else { return nil }
        return data
    }

    /// Save SOCKS5 proxy config to Keychain.
    /// FIX MED-17: Validate hostname before saving to prevent injection or misconfiguration
    nonisolated static func saveSOCKS5ConfigToKeychain(host: String, port: Int) {
        // Validate host: must be IPv4, IPv6, or valid hostname (no spaces, no special chars)
        let validHostPattern = #"^[a-zA-Z0-9\.\-\:]+$"#
        guard host.range(of: validHostPattern, options: .regularExpression) != nil,
              !host.isEmpty,
              host.count <= 253,
              port > 0 && port <= 65535 else {
            #if DEBUG
            print("[TorController] ⚠️ Invalid SOCKS5 config rejected: host=\(host) port=\(port)")
            #endif
            return
        }
        let config = SOCKS5Config(host: host, port: port)
        guard let data = try? JSONEncoder().encode(config) else { return }
        // FIX A11-8: Delete query without kSecAttrAccessible — otherwise old entries
        // with different protection level won't be found, causing errSecDuplicateItem
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: "app.ladon.messenger.socks5Config",
            // FIX AUDIT-MAR-2026-22: Include kSecAttrService so emergency wipe catches this entry
            kSecAttrService as String: "app.ladon.messenger"
        ]
        SecItemDelete(deleteQuery as CFDictionary)
        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: "app.ladon.messenger.socks5Config",
            kSecAttrService as String: "app.ladon.messenger",
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
        if addStatus != errSecSuccess {
            SecureLogger.error("[TorController] Keychain write failed for SOCKS5 config: \(addStatus)")
        }
    }

    /// Clear SOCKS5 proxy config from Keychain (called when Tor disconnects)
    nonisolated static func clearSOCKS5ConfigFromKeychain() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: "app.ladon.messenger.socks5Config",
            kSecAttrService as String: "app.ladon.messenger"
        ]
        SecItemDelete(query as CFDictionary)
        #if DEBUG
        print("[TorController] 🧅 SOCKS5 config cleared from Keychain (Tor stopped)")
        #endif
    }
}

// MARK: - Tor Enforcement (mandatory, no toggle)
//
// P8-SEC-IOS-01 (2026-05-23): the `torEnforcementEnabled` toggle — briefly
// hosted here after the RelayClient migration in IOS-07 — has been RETIRED.
// Tor is now mandatory and unconditional: there is no opt-out, no "send
// directly" path. This realigns the app with security principle #1
// ("Maximalsicherheit ohne Toggles") and #3 (fail-closed). The former
// SecureUserDefaults key "torEnforcementEnabled" is no longer read.
//
// Callers that used to gate on the flag now treat Tor as always-required
// (BlobRelayClient.requireTorReady, ChatView Tor banner, LadonApp resume
// recovery). The V2 send path already enforced Tor fail-closed via the
// SOCKS5 session, so this only closes the inconsistent blob/UI opt-out gap.
