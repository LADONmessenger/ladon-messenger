//
//  TorManager.swift
//  Ladon
//
//  Embedded Tor.framework manager for network anonymity
//

import Foundation
import CFNetwork
import Network

/// Manages embedded Tor connection for anonymous network communication
/// High-level wrapper around TorController
@MainActor
class TorManager: ObservableObject {
    
    // MARK: - Published Properties
    
    @Published var isConnected = false
    @Published var isStarting = false
    @Published var progress: Double = 0.0
    @Published var statusMessage = "Tor not started"
    @Published var errorMessage: String?
    /// The device has no network path at all (Wi-Fi and mobile data down or
    /// switched off). Tor cannot reach a bridge then, however long it retries
    /// — the UI says so instead of showing a progress that never moves.
    @Published private(set) var isOffline = false
    /// Tor can no longer be steered in this process (TorController.controlLost);
    /// only reopening the app helps.
    @Published private(set) var controlLost = false
    
    // MARK: - Properties
    
    private let pathMonitor = NWPathMonitor()
    
    /// Singleton instance
    static let shared = TorManager()
    
    /// Embedded Tor controller
    private let torController = TorController.shared
    
    /// FIX CONN-ERR-RACE: Track in-progress circuit verification so sendMessage can await it.
    /// Without this, sendMessage races against verifyCircuit after background return:
    /// SOCKS5 health check passes (local loopback alive) but Tor circuits are stale → connection error.
    private var circuitVerificationTask: Task<Void, Never>?
    
    /// SOCKS proxy port (delegates to TorController)
    var socksPort: UInt16 {
        torController.socksPort
    }
    
    /// Control port (delegates to TorController)
    /// FIX AUDIT-H04: Removed hardcoded port 39051 — now uses TorController's randomized port
    var controlPort: UInt16 {
        torController.controlPort
    }
    
    // MARK: - Initialization
    
    private init() {
        pathMonitor.pathUpdateHandler = { [weak self] path in
            let offline = path.status != .satisfied
            Task { @MainActor [weak self] in
                guard let self, self.isOffline != offline else { return }
                self.isOffline = offline
            }
        }
        pathMonitor.start(queue: DispatchQueue(label: "app.ladon.netpath", qos: .utility))

        // Observe TorController state
        Task {
            await observeTorController()
        }

        Task {
            await syncStateFromController()
        }
    }
    
    // MARK: - State Observation
    
    private func observeTorController() async {
        // Sync state with TorController
        for await _ in NotificationCenter.default.notifications(named: .init("TorStateChanged")) {
            await syncStateFromController()
        }
    }

    private func syncStateFromController() async {
        await MainActor.run {
            self.isConnected = torController.isRunning && torController.circuitEstablished
            self.progress = Double(torController.bootstrapProgress) / 100.0
            self.statusMessage = torController.statusMessage
            self.controlLost = torController.controlLost
        }
    }
    
    // MARK: - Tor Control
    
    /// Start embedded Tor network connection
    func startTor() async {
        guard !isStarting else { return }
        
        isStarting = true
        statusMessage = "Starting Tor..."
        errorMessage = nil
        
        do {
            try await torController.startTor()
            
            isConnected = torController.isRunning && torController.circuitEstablished
            isStarting = false
            statusMessage = torController.statusMessage
            progress = Double(torController.bootstrapProgress) / 100.0
            
            #if DEBUG
            print("[TorManager] ✅ Tor started successfully")
            #endif
        } catch {
            isStarting = false
            isConnected = false
            // FIX LOW-19: Show generic error in production, detailed in DEBUG
            #if DEBUG
            errorMessage = error.localizedDescription
            #else
            errorMessage = "Tor could not be started. Please check your network connection."
            #endif
            statusMessage = "Failed to start Tor"
            
            #if DEBUG
            print("[TorManager] ❌ Tor start failed: \(error)")
            #endif
        }
    }
    
    /// Stop Tor connection
    func stopTor() async {
        await torController.stopTor()
        
        isConnected = false
        isStarting = false
        progress = 0.0
        statusMessage = "Tor stopped"
        
        #if DEBUG
        print("[TorManager] 🛑 Tor stopped")
        #endif
    }
    
    /// Restart Tor connection (new circuit)
    func restartTor() async {
        let accepted = await torController.newCircuit()
        statusMessage = accepted ? "New circuit established" : "New circuit could not be requested"
        
        #if DEBUG
        print("[TorManager] 🔄 Tor circuit renewal \(accepted ? "accepted" : "NOT accepted")")
        #endif
    }
    
    // MARK: - Status Checks
    
    /// Check if Tor is ready for use
    var isTorReady: Bool {
        isConnected && torController.circuitEstablished
    }
    
    /// FIX TOR-RACE: True while Tor process is running but circuit not yet established.
    /// Covers the gap where isStarting is already false but bootstrap is still in progress.
    /// Used by the send path to decide whether to wait (60s) or fail immediately.
    var isBootstrapping: Bool {
        isStarting || (torController.isRunning && !torController.circuitEstablished)
    }
    
    /// FIX D: Live SOCKS5 health check — verifies the proxy actually responds.
    /// Used before sending to avoid sending into a dead proxy.
    func isSOCKSHealthy() async -> Bool {
        return await torController.isSOCKSHealthy()
    }
    
    /// FIX A: Verify and restore Tor circuit after background return.
    /// Called when app transitions from .background to .active.
    /// FIX CONN-ERR-RACE: Now tracked via circuitVerificationTask so sendMessage can await completion.
    func verifyCircuitAfterBackgroundReturn() async {
        if let existingTask = circuitVerificationTask {
            #if DEBUG
            print("[TorManager] ⏳ Reusing in-flight circuit verification task")
            #endif
            await existingTask.value
            return
        }

        let task = Task {
            await torController.verifyCircuitAfterBackgroundReturn()
            await syncStateFromController()
        }
        circuitVerificationTask = task
        await task.value
        circuitVerificationTask = nil
    }
    
    /// FIX CONN-ERR-RACE: Wait for any in-progress circuit verification to complete.
    /// Called before sending to avoid racing against stale circuits.
    /// Returns immediately if no verification is in progress.
    func awaitCircuitVerificationIfNeeded() async {
        if let task = circuitVerificationTask {
            #if DEBUG
            print("[TorManager] ⏳ Waiting for circuit verification to complete before send...")
            #endif
            await task.value
            #if DEBUG
            print("[TorManager] ✅ Circuit verification completed — proceeding with send")
            #endif
        }
    }
    
    /// Get onion address for receiving messages
    func getOnionAddress() async -> String? {
        return await torController.getOnionAddress()
    }
}

// Note: TorError enum is defined in TorController.swift
