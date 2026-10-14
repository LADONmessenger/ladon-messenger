//
//  ExitRegistryV2.swift
//  Ladon — list of v2 exit-relays + geo-probe latency tracking.
//
//  Spec §3.5: each Exit is identified by `BLAKE3(hkem_pk)[..16]`. The iOS
//  client maintains a registry of known exits (URL, region, HKEM public key)
//  and probes them periodically to pick the fastest one for outgoing messages.
//

import Foundation

/// Static descriptor for a single Exit-Relay.
/// Loaded at app start from a bundled config (or fetched from a trusted source).
struct ExitDescriptorV2: Codable, Hashable {
    /// 16-byte ExitId (hex-encoded for storage / URLs).
    let exitIdHex: String
    /// Base URL of the entry-relay that fronts this exit (e.g. "https://entry-ch1.ladon.app").
    /// All v2 client traffic goes through an Entry-Relay; the Entry forwards to the Exit by id.
    let entryUrl: URL
    /// Direct URL of the Exit-Relay (used for /v2/directory PUT during initial publish).
    /// The PUT is also proxied through the Entry today; this field is informational.
    let exitUrl: URL
    /// 1,216-byte HKEM public key of the Exit (for sealing outer envelopes).
    /// Stored hex-encoded so the descriptor remains plain JSON.
    let hkemPkHex: String
    /// Region tag (e.g. "ch1", "fi1", "pa1"). Free-form, used for UI grouping.
    let region: String

    /// Decoded HKEM public key (1,216 B).
    func hkemPublicKey() throws -> Data {
        guard let d = Data(hexString: hkemPkHex), d.count == LadonV2.hkemPkLen else {
            throw LadonV2Error.shortBuffer(expected: LadonV2.hkemPkLen, got: hkemPkHex.count / 2)
        }
        return d
    }

    /// Decoded ExitId (16 B).
    func exitId() throws -> ExitIdV2 {
        guard let d = Data(hexString: exitIdHex), d.count == LadonV2.exitIdLen else {
            throw LadonV2Error.shortBuffer(expected: LadonV2.exitIdLen, got: exitIdHex.count / 2)
        }
        return ExitIdV2(bytes: d)
    }

    /// Sanity check: `BLAKE3(hkem_pk)[..16] == exit_id`.
    func validateBinding() throws {
        let pk = try hkemPublicKey()
        let derived = ExitIdV2.fromHkemPk(pk)
        let claimed = try exitId()
        guard derived == claimed else {
            throw LadonV2Error.structuralInvariant(
                "ExitId(\(claimed)) does not match BLAKE3(hkem_pk) -> \(derived)")
        }
    }
}

/// Static descriptor for a single Entry-Relay (V2.1 split-topology, schema v2).
/// Entries front the relay graph: clients send every sealed request to
/// `POST /v2/relay` of the entry they pick (Addendum A2).
struct EntryDescriptorV2: Codable, Hashable {
    /// Region tag (e.g. "ch1", "fi1"). Free-form, used for UI grouping + diagnostics.
    let region: String
    /// Public base URL of the entry (e.g. `https://entry-ch.ladon.app`).
    let url: URL
}

/// The push relay as a sealed-request target (Addendum A2 §4.4): its HKEM
/// public key and 16-byte id `BLAKE3(hkem_pk)[..16]`, from the bootstrap
/// file like the exits' keys. PUSH_REGISTER is sealed to it, so neither the
/// entry nor an exit sees the APNs token.
struct PushTargetV2: Codable, Hashable {
    let targetIdHex: String
    let hkemPkHex: String

    func hkemPublicKey() throws -> Data {
        guard let d = Data(hexString: hkemPkHex), d.count == LadonV2.hkemPkLen else {
            throw LadonV2Error.shortBuffer(expected: LadonV2.hkemPkLen, got: hkemPkHex.count / 2)
        }
        return d
    }

    func targetId() throws -> Data {
        guard let d = Data(hexString: targetIdHex), d.count == LadonV2.exitIdLen else {
            throw LadonV2Error.shortBuffer(expected: LadonV2.exitIdLen, got: targetIdHex.count / 2)
        }
        return d
    }

    /// `BLAKE3(hkem_pk)[..16] == target_id`, as for an exit.
    func validateBinding() throws {
        guard ExitIdV2.fromHkemPk(try hkemPublicKey()).bytes == (try targetId()) else {
            throw LadonV2Error.structuralInvariant("push target id does not match BLAKE3(hkem_pk)")
        }
    }
}

/// Dynamic per-Exit health/latency snapshot, updated by `geoProbe()`.
struct ExitHealthV2: Equatable {
    let exitIdHex: String
    /// Round-trip latency in milliseconds for the most recent /v2/health probe.
    /// `nil` if probe failed or hasn't run yet.
    var lastLatencyMs: Double?
    /// Wall-clock time of the most recent probe.
    var lastProbedAt: Date?
    /// Number of consecutive probe failures (resets to 0 on success).
    var consecutiveFailures: Int
    /// Self-reported version byte from /v2/health (must equal 2).
    var reportedVersion: UInt8?
}

/// Thread-safe registry of known exits + their health.
actor ExitRegistryV2 {
    /// Static descriptors (immutable across registry lifetime).
    private(set) var exits: [ExitDescriptorV2]
    /// Schema-v2 entries[] (split-topology). Empty for legacy schema-v1 bootstraps.
    /// Currently informational; per-exit routing uses `ExitDescriptorV2.entryUrl`,
    /// which `load()` round-robin-assigns from this list when schemaVersion >= 2.
    private(set) var entries: [EntryDescriptorV2]
    /// The push relay as a sealed-request target (A2 §4.4). `nil` if the
    /// bootstrap names none — push registration then fails closed.
    private(set) var pushTarget: PushTargetV2?
    /// Per-exitId health snapshot.
    private var health: [String: ExitHealthV2] = [:]
    /// HTTP client for probes — uses Tor-aware session to prevent metadata leaks.
    /// Replaced on every Tor reconfigure (`replaceSession`) together with the
    /// relay client's session.
    private var session: URLSession

    init(
        exits: [ExitDescriptorV2],
        entries: [EntryDescriptorV2] = [],
        pushTarget: PushTargetV2? = nil,
        session: URLSession? = nil
    ) throws {
        for e in exits { try e.validateBinding() }
        try pushTarget?.validateBinding()
        self.exits = exits
        self.entries = entries
        self.pushTarget = pushTarget
        // Use provided Tor-aware session, or fall back to .shared if none provided (dev only).
        self.session = session ?? .shared
        for e in exits {
            health[e.exitIdHex] = ExitHealthV2(
                exitIdHex: e.exitIdHex,
                lastLatencyMs: nil,
                lastProbedAt: nil,
                consecutiveFailures: 0,
                reportedVersion: nil
            )
        }
    }

    /// Decode the registry from a JSON config blob (e.g. bundled in the app or fetched).
    ///
    /// Two schema versions are accepted:
    ///
    /// **Legacy (schemaVersion 1, default):** each exit carries its own `entryUrl`
    /// (because V2.0 colocated entry+exit on the same host).
    /// ```json
    /// { "exits": [
    ///   { "exitIdHex": "...", "entryUrl": "https://...", "exitUrl": "https://...",
    ///     "hkemPkHex": "...", "region": "ch1" }, ...
    /// ]}
    /// ```
    ///
    /// **Split-topology (schemaVersion 2, V2.1):** entries and exits are separate.
    /// Each exit is reached through one of the listed entries; this loader
    /// assigns entries to exits round-robin so a dead entry only takes down a
    /// proportional fraction of exits.
    /// ```json
    /// { "schemaVersion": 2,
    ///   "entries": [ { "region": "ch1", "url": "https://entry-ch.ladon.app" }, ... ],
    ///   "exits":   [ { "region": "is1", "exitIdHex": "...", "exitUrl": "...",
    ///                  "hkemPkHex": "..." }, ... ],
    ///   "push":    { "targetIdHex": "...", "hkemPkHex": "..." }
    /// }
    /// ```
    static func load(from json: Data) throws -> ExitRegistryV2 {
        // Peek at schemaVersion (default 1) to decide which decoder to use.
        struct VersionPeek: Codable { let schemaVersion: Int? }
        let version = (try? JSONDecoder().decode(VersionPeek.self, from: json))?.schemaVersion ?? 1

        if version >= 2 {
            struct ExitV2: Codable {
                let region: String
                let exitIdHex: String
                let exitUrl: URL
                let hkemPkHex: String
            }
            struct WrapperV2: Codable {
                let schemaVersion: Int
                let entries: [EntryDescriptorV2]
                let exits: [ExitV2]
                let push: PushTargetV2?
            }
            let w = try JSONDecoder().decode(WrapperV2.self, from: json)
            guard !w.entries.isEmpty else {
                throw LadonV2Error.structuralInvariant("schemaVersion 2 bootstrap has empty entries[]")
            }
            // #23: reject a tampered bootstrap pointing at a non-pinned host. SPKI
            // pinning already fail-closes the TLS handshake; this fails fast at load
            // (clear error) and refuses to even attempt a mutated bundle. Entries
            // are the client's only TLS targets (exits and the push relay are
            // reached through them).
            for ent in w.entries {
                guard let host = ent.url.host,
                      CertificatePinningDelegate.isPinnedHostname(host) else {
                    throw LadonV2Error.structuralInvariant("bootstrap entry host not pinned")
                }
            }
            // Round-robin-assign each exit to one entry. With 2 entries and 3
            // exits this yields ch1, fi1, ch1 — a single dead entry leaves at
            // least one exit reachable.
            let merged: [ExitDescriptorV2] = w.exits.enumerated().map { (idx, e) in
                let ent = w.entries[idx % w.entries.count]
                return ExitDescriptorV2(
                    exitIdHex: e.exitIdHex,
                    entryUrl: ent.url,
                    exitUrl: e.exitUrl,
                    hkemPkHex: e.hkemPkHex,
                    region: e.region
                )
            }
            return try ExitRegistryV2(exits: merged, entries: w.entries, pushTarget: w.push)
        }

        // Legacy schema-v1 path.
        struct WrapperV1: Codable { let exits: [ExitDescriptorV2] }
        let w = try JSONDecoder().decode(WrapperV1.self, from: json)
        return try ExitRegistryV2(exits: w.exits)
    }

    func descriptor(forExitId id: ExitIdV2) -> ExitDescriptorV2? {
        let hex = id.description
        return exits.first(where: { $0.exitIdHex == hex })
    }

    func descriptor(forExitIdHex hex: String) -> ExitDescriptorV2? {
        exits.first(where: { $0.exitIdHex == hex })
    }

    /// Return alternative entry URLs that can relay sealed requests for the
    /// same exit-id, excluding the currently used entry.
    func fallbackEntryUrls(excluding currentEntryUrl: URL) -> [URL] {
        entries
            .map { $0.url }
            .filter { $0 != currentEntryUrl }
    }

    func snapshotHealth() -> [ExitHealthV2] {
        health.values.sorted { ($0.lastLatencyMs ?? .infinity) < ($1.lastLatencyMs ?? .infinity) }
    }

    /// Returns the fastest exit (lowest probed latency, ignoring failed/unprobed).
    /// Falls back to the first descriptor if no probe data exists yet.
    func fastestExit() -> ExitDescriptorV2? {
        fastestExit(excluding: [])
    }

    /// Like `fastestExit()`, but skips any exit whose hex id is in `excluded`.
    /// Used by retry logic to rotate to a different exit when the previously
    /// chosen one fails (e.g. transient HTTP 502 from the entry-relay's
    /// upstream connection pool).
    func fastestExit(excluding excluded: Set<String>) -> ExitDescriptorV2? {
        let candidates = exits.filter { !excluded.contains($0.exitIdHex) }
        let healthy = candidates.compactMap { d -> (ExitDescriptorV2, Double)? in
            guard let h = health[d.exitIdHex],
                  let lat = h.lastLatencyMs,
                  h.consecutiveFailures == 0
            else { return nil }
            return (d, lat)
        }
        if let best = healthy.min(by: { $0.1 < $1.1 }) {
            return best.0
        }
        return candidates.first
    }

    /// Swap the probe session for the one the relay client was just rebuilt
    /// with. The registry outlives Tor reconfigures; keeping the init-time
    /// session made every probe after a re-bind wait out the 60 s resource
    /// timeout before the bundle was republished (17 Pro, 01.10.2026: probe
    /// 60.6 s vs. 0.7 s for the publish on the new session).
    func replaceSession(_ newSession: URLSession) {
        session = newSession
    }

    /// Probe every exit's `/v2/health` endpoint via its entry-URL once. Updates `health`.
    /// Each probe has its own timeout; failures don't block successful probes.
    func geoProbe(perProbeTimeoutSec: TimeInterval = 3.0) async {
        let probeSession = session
        await withTaskGroup(of: (String, ExitHealthV2).self) { group in
            for desc in exits {
                group.addTask { [probeSession] in
                    var snap = ExitHealthV2(
                        exitIdHex: desc.exitIdHex,
                        lastLatencyMs: nil,
                        lastProbedAt: Date(),
                        consecutiveFailures: 0,
                        reportedVersion: nil
                    )
                    let url = desc.entryUrl.appendingPathComponent("v2/health")
                    var req = URLRequest(url: url, timeoutInterval: perProbeTimeoutSec)
                    req.httpMethod = "GET"
                    let t0 = Date()
                    do {
                        let (data, resp) = try await probeSession.data(for: req)
                        let dt = Date().timeIntervalSince(t0) * 1000.0
                        guard let http = resp as? HTTPURLResponse else {
                            snap.consecutiveFailures = 1
                            return (desc.exitIdHex, snap)
                        }
                        // No clock sample here: the lanes' clocks learn only
                        // from sealed responses (A2 §4.3).
                        guard http.statusCode == 200 else {
                            snap.consecutiveFailures = 1
                            return (desc.exitIdHex, snap)
                        }
                        snap.lastLatencyMs = dt
                        // Try to extract reported version.
                        if let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                           let v = obj["version"] as? Int {
                            snap.reportedVersion = UInt8(v & 0xff)
                        }
                        return (desc.exitIdHex, snap)
                    } catch {
                        snap.consecutiveFailures = 1
                        return (desc.exitIdHex, snap)
                    }
                }
            }
            for await (hex, fresh) in group {
                let prevFails = health[hex]?.consecutiveFailures ?? 0
                var merged = fresh
                if fresh.lastLatencyMs == nil {
                    merged.consecutiveFailures = prevFails + 1
                }
                health[hex] = merged
            }
        }
    }
}

// `Data.init?(hexString:)` is already provided by Security/SecurityExtensions.swift.
// No additional Data extension needed here.
