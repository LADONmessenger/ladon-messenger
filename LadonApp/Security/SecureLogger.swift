// SecureLogger.swift — Privacy-preserving logging (FIX: replaces all NSLog usage)
// In DEBUG: logs to os.log with .private redaction
// In RELEASE: completely disabled — ALL levels, zero data written to system logs
// FIX SL-1: os.log .private does NOT prevent forensic extraction (Cellebrite/GrayKey
// read raw log data from /var/db/diagnostics/ even after app deletion)
//
// Signal comparison: Signal uses OWSLogger with .private redaction
// Threema comparison: Threema uses LogManager with encryption
// Ladon: Exceeds Signal — zero logging in Release, not even .private redacted

import Foundation
import os.log

/// Secure logger that NEVER leaks data in production builds.
/// All sensitive parameters are redacted via os.log privacy annotations.
enum SecureLogger {
    
    // FIX LOW-39: Use Bundle identifier dynamically instead of hardcoded string
    private static let subsystem = Bundle.main.bundleIdentifier ?? "app.ladon.messenger"
    
    // Category-specific loggers
    static let crypto   = Logger(subsystem: subsystem, category: "crypto")
    static let network  = Logger(subsystem: subsystem, category: "network")
    static let ui       = Logger(subsystem: subsystem, category: "ui")
    static let security = Logger(subsystem: subsystem, category: "security")
    static let general  = Logger(subsystem: subsystem, category: "general")

    // Temporary diagnostic logger for Tor background recovery.
    // Writes to a file in the app's Documents directory so it can be read after testing.
    // REMOVE after background reconnect is fixed.
    private static let torDiagLogger = Logger(subsystem: subsystem, category: "TorDiag")
    private static let torDiagFile: URL = {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        return docs.appendingPathComponent("tor_diag.log")
    }()
    private static let torDiagQueue = DispatchQueue(label: "tordiag", qos: .utility)
    
    /// Log a debug message. In release builds, this is compiled out entirely.
    /// All dynamic values are automatically redacted by os.log in non-debug contexts.
    static func debug(_ message: String, category: Logger = SecureLogger.general) {
        #if DEBUG
        category.debug("\(message, privacy: .private)")
        #endif
    }
    
    /// Log an info message (non-sensitive operational events only).
    static func info(_ message: String, category: Logger = SecureLogger.general) {
        #if DEBUG
        category.info("\(message, privacy: .private)")
        #endif
    }
    
    /// Log an error. In release builds: NO output to system log.
    /// FIX SL-1: os.log .private does NOT prevent forensic extraction by Cellebrite/GrayKey.
    /// Logs in /var/db/diagnostics/ survive app deletion. Zero logging in Release.
    static func error(_ message: String, category: Logger = SecureLogger.general) {
        #if DEBUG
        category.error("\(message, privacy: .private)")
        #endif
    }
    
    /// Log a critical event. In release builds: NO output to system log.
    /// FIX SL-1: Same rationale — forensic tools extract raw log data regardless of .private.
    static func critical(_ message: String, category: Logger = SecureLogger.security) {
        #if DEBUG
        category.critical("\(message, privacy: .private)")
        #endif
    }

    /// Tor background recovery diagnostic. Writes to Documents/tor_diag.log.
    /// Only active in DEBUG. Remove once background reconnect is stable.
    static func torDiag(_ message: String) {
        #if DEBUG
        let ts = DateFormatter.localizedString(from: Date(), dateStyle: .none, timeStyle: .medium)
        let line = "[\(ts)] \(message)\n"
        torDiagQueue.async {
            if let data = line.data(using: .utf8) {
                if FileManager.default.fileExists(atPath: torDiagFile.path) {
                    if let fh = try? FileHandle(forWritingTo: torDiagFile) {
                        fh.seekToEndOfFile()
                        fh.write(data)
                        try? fh.close()
                    }
                } else {
                    try? data.write(to: torDiagFile)
                }
            }
        }
        #endif
    }

    /// Start a fresh tor_diag.log (call at app start). The previous run is
    /// kept as tor_diag.prev.log: a stall is often ended by quitting the app,
    /// and that cold launch must not erase the evidence of the stall.
    static func clearTorDiag() {
        #if DEBUG
        keepPreviousRun(of: torDiagFile)
        #endif
    }

    /// DEBUG: wait until every queued tor_diag line is written (before the
    /// process ends on purpose).
    static func flushTorDiag() {
        #if DEBUG
        torDiagQueue.sync {}
        #endif
    }

    /// DEBUG: move `url` to `<name>.prev.<ext>`, replacing an older copy.
    static func keepPreviousRun(of url: URL) {
        #if DEBUG
        let fm = FileManager.default
        let prev = url.deletingPathExtension().appendingPathExtension("prev." + url.pathExtension)
        try? fm.removeItem(at: prev)
        if (try? fm.moveItem(at: url, to: prev)) == nil {
            try? fm.removeItem(at: url)
        }
        #endif
    }
}
