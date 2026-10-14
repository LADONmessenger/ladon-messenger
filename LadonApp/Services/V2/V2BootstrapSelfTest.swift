//
//  V2BootstrapSelfTest.swift
//  Ladon — Phase-1 / Phase-2 verification helper.
//
//  Phase 1 (always): loads `exits-bootstrap.json` from the app bundle,
//    validates each ExitDescriptorV2, and probes `/v2/health` against every
//    pilot via the pinned URLSession.
//
//  Phase 2 (always after Phase 1): loads-or-generates the local V2 identity
//    from Keychain (IdentityStoreV2), picks the fastest pilot, and publishes
//    a freshly-signed delivery bundle (Addendum A1) to that pilot's
//    `/v2/directory/<rid>` endpoint.
//
//  Writes a plain-text report to Documents/v2-selftest.log so we can pull it
//  off-device with `xcrun devicectl device copy from`. Bypasses iOS log
//  redaction.
//
//  DEBUG-only.
//

#if DEBUG
import Foundation

enum V2BootstrapSelfTest {

    static func runOnce() {
        Task.detached(priority: .background) { await runInternal() }
    }

    private static func runInternal() async {
        var report = "=== V2 Bootstrap Self-Test ===\n"
        report += "started: \(Date())\n"

        guard let url = Bundle.main.url(forResource: "exits-bootstrap", withExtension: "json") else {
            report += "FAIL: exits-bootstrap.json missing from bundle\n"
            write(report); return
        }
        report += "bundle url: \(url.lastPathComponent)\n"

        let data: Data
        do { data = try Data(contentsOf: url) } catch {
            report += "FAIL: read JSON: \(error)\n"; write(report); return
        }
        report += "json bytes: \(data.count)\n"

        let registry: ExitRegistryV2
        do { registry = try ExitRegistryV2.load(from: data) } catch {
            report += "FAIL: decode/validate: \(error)\n"; write(report); return
        }
        let exits = await registry.exits
        report += "loaded \(exits.count) exits\n"
        write(report)  // Snapshot before network — survives crashes/timeouts.

        // ── Phase 1: TLS-pinned /v2/health probes ──────────────────────────
        let session = CertificatePinningDelegate.shared.pinnedURLSession
        var fastestRegion: String?
        var fastestMs: Int = .max
        var fastestDesc: ExitDescriptorV2?
        for desc in exits {
            let probe = desc.entryUrl.appendingPathComponent("v2/health")
            var req = URLRequest(url: probe, timeoutInterval: 6)
            req.httpMethod = "GET"
            let t0 = Date()
            do {
                let (body, response) = try await session.data(for: req)
                let ms = Int(Date().timeIntervalSince(t0) * 1000)
                let code = (response as? HTTPURLResponse)?.statusCode ?? -1
                let preview = String(data: body.prefix(96), encoding: .utf8)?
                    .replacingOccurrences(of: "\n", with: " ") ?? "?"
                report += "[\(desc.region)] HTTP \(code) in \(ms) ms — \(preview)\n"
                if code == 200 && ms < fastestMs {
                    fastestMs = ms
                    fastestRegion = desc.region
                    fastestDesc = desc
                }
            } catch {
                let ms = Int(Date().timeIntervalSince(t0) * 1000)
                report += "[\(desc.region)] ERROR after \(ms) ms — \(error)\n"
            }
            write(report)
        }

        // ── Phase 2: Identity-Bridge ───────────────────────────────────────
        report += "\n=== Phase 2: Identity-Bridge ===\n"
        write(report)

        let preExisted = IdentityStoreV2.exists()
        report += "identity in keychain (before): \(preExisted)\n"
        write(report)

        let identity: LocalIdentityV2
        do {
            identity = try IdentityStoreV2.loadOrGenerate()
        } catch {
            report += "FAIL: identity load/generate: \(error)\n"; write(report); return
        }
        report += "recipient_id: \(identity.recipientId.description)\n"
        report += "hsig_pk len: \(identity.senderHsigKp.publicKeyBytes().count)\n"
        report += "hkem_pk len: \(identity.recipientHkemKp.publicKeyBytes().count)\n"
        write(report)

        // Re-load to verify round-trip.
        do {
            if let reloaded = try IdentityStoreV2.load() {
                let same = reloaded.recipientId == identity.recipientId
                report += "identity reload check: \(same ? "OK (rid match)" : "FAIL (rid mismatch)")\n"
            } else {
                report += "identity reload check: FAIL (load returned nil after generate)\n"
            }
        } catch {
            report += "identity reload check: FAIL (\(error))\n"
        }
        write(report)

        // Bundle publish on fastest reachable exit.
        guard let target = fastestDesc, let region = fastestRegion else {
            report += "SKIP publish: no reachable exit\n"; write(report); return
        }
        report += "publish target: \(region) (\(fastestMs) ms)\n"
        write(report)

        // Publish only: nothing is sent, so one session for both lanes is
        // fine here (A2 stage 1 isolation applies to the running client). No
        // lane defaults: this scheduler carries the one DIR_PUT and stops.
        let lanes = LaneSchedulerV2()
        let transport = SealedTransportV2(session: session, clock: .shared)
        await lanes.setTransports(send: transport, fetch: transport)
        await lanes.start()
        let client = RelayClientV2(identity: identity, registry: registry, lanes: lanes)
        let started = Date()
        do {
            let exitId = try await client.publishBundle(on: target)
            let ms = Int(Date().timeIntervalSince(started) * 1000)
            report += "publish OK in \(ms) ms — exit_id: \(exitId.description)\n"
        } catch {
            let ms = Int(Date().timeIntervalSince(started) * 1000)
            report += "publish FAIL after \(ms) ms — \(error)\n"
        }
        await lanes.stop()

        report += "finished: \(Date())\n"
        write(report)
    }

    private static func write(_ text: String) {
        guard let docs = FileManager.default.urls(
            for: .documentDirectory, in: .userDomainMask).first else { return }
        let target = docs.appendingPathComponent("v2-selftest.log")
        try? text.data(using: .utf8)?.write(to: target, options: .atomic)
    }
}
#endif
