//
//  LadonV2SelfTest.swift
//  Ladon — runtime self-tests for the v2 crypto / wire-format layer.
//
//  Mirrors the Rust `relay-core-v2` test suite. Run from app launch (debug)
//  or on demand via Settings → Diagnostics. Each test returns a pass/fail
//  message; any failure indicates a serious crypto regression.
//

import Foundation
import CryptoKit

enum LadonV2SelfTest {

    struct Result {
        let name: String
        let passed: Bool
        let detail: String
    }

    /// Run all self-tests. Returns a list of (name, pass, detail).
    /// `requireSelfTestPassedFlag = false` allows running before PostQuantumService
    /// has been initialised; tests that need PQ will skip themselves cleanly.
    static func runAll() -> [Result] {
        var results: [Result] = []

        results.append(testWireSizes())
        results.append(testClockSyncHTTPDate())
        results.append(testClockSyncTargetTimeBounds())
        results.append(testPushRegisterBodyLayout())
        results.append(testBlake3KnownAnswerVectors())
        results.append(testHSigUsecaseDomains())
        results.append(testDeliveryBundleRoundtrip())
        results.append(testControlMessageFormat())
        results.append(testBlockingCodec())
        results.append(testDeliveryKeyChoice())
        results.append(testSealedLaneSizes())
        results.append(testAttachmentChunkCountBound())
        #if DEBUG
        results.append(testSealedKeychainSecureEnclave())
        #endif

        // PQ-dependent tests — require successful self-test of PostQuantumService.
        if PostQuantumService.shared.selfTestPassed {
            results.append(testHSigRoundtrip())
            results.append(testDeliveryBundleIssueVerify())
            results.append(testHKEMRoundtrip())
            results.append(testSealedRequestRealHKEM())
            results.append(testPushRegisterSignRoundtrip())
            #if DEBUG
            results.append(testV2RatchetRoundtrip())
            results.append(testV2RatchetOutOfOrder())
            results.append(testV2RatchetDHStepKDF())
            // #6 active DH-ratchet (Double Ratchet) desync matrix.
            results.append(testV2DRPingPong())
            results.append(testV2DRBurstIsOneTurn())
            results.append(testV2DROutOfOrderAcrossChains())
            results.append(testV2DRInterleaved())
            results.append(testV2DRSimultaneousInit())
            results.append(testV2DRCrossingAfterBurst())
            results.append(testV2CrossingRecoveryResendsBurst())
            results.append(testV2DRFreshKemEveryTurn())
            results.append(testV2DRKemKeysUsedOnce())
            results.append(testV2DRTamperReplayFailClosed())
            results.append(testV2RatchetSizeGate())
            // One-time prekey bootstrap + fail-closed guards.
            results.append(testV2BootPrekeyConsumed())
            results.append(testV2BootSecondUseRejected())
            results.append(testV2BootMissingUnknownExpired())
            results.append(testV2BootTamperKeepsPrekey())
            results.append(testV2DRGuardsFailClosed())
            results.append(testV2DRCrossingTamperFailClosed())
            results.append(testV2BootRootKDF())
            results.append(testV2BootRetargetedIdRejected())
            results.append(testV2BootRestart())
            results.append(testV2BootSaveFailure())
            results.append(testV2PrekeyStoreLimits())
            results.append(testV2ExpiredOwnPrekeysPurged())
            results.append(testV2SecretsWipedInPlace())
            results.append(testPairingCodeV4())
            results.append(testV2SessionResetEnablesRecovery())
            results.append(testControlMessageBootstraps())
            results.append(testPairingStartNeverAnswers())
            #endif
        } else {
            results.append(Result(
                name: "PQ-dependent tests (HSig / HKEM / OuterSealOpen)",
                passed: false,
                detail: "skipped — PostQuantumService.selfTestPassed == false"
            ))
        }

        // Cross-language byte-exact vectors (Rust relay-core-v2).
        results.append(contentsOf: LadonV2CrossLang.runAll())

        return results
    }

    // MARK: - Relay-anchored clock (ClockSyncV2)

    /// The clock correction rests entirely on parsing the relay's `Date`
    /// header. If that silently failed, the device would be back on its own
    /// clock — the exact outage of 2026-08-24 — with nothing in the logs.
    private static func testClockSyncHTTPDate() -> Result {
        var problems: [String] = []
        // RFC 9110 §5.6.7 example, all three accepted forms → same instant.
        let expected: TimeInterval = 784_111_777
        let forms = [
            "Sun, 06 Nov 1994 08:49:37 GMT",
            "Sunday, 06-Nov-94 08:49:37 GMT",
            "Sun Nov  6 08:49:37 1994",
        ]
        for f in forms {
            guard let d = ClockSyncV2.parseHTTPDate(f) else {
                problems.append("unparsed: \(f)")
                continue
            }
            if d.timeIntervalSince1970 != expected {
                problems.append("\(f) → \(d.timeIntervalSince1970), expected \(expected)")
            }
        }
        if ClockSyncV2.parseHTTPDate("") != nil { problems.append("empty string parsed") }
        if ClockSyncV2.parseHTTPDate("not a date") != nil { problems.append("garbage parsed") }
        // HTTP/2 delivers lower-case header names; the lookup must not care.
        if let http = HTTPURLResponse(
            url: URL(string: "https://entry-ch.ladon.app/v2/health")!,
            statusCode: 200, httpVersion: "HTTP/2",
            headerFields: ["date": forms[0]]
        ) {
            if http.value(forHTTPHeaderField: "Date") != forms[0] {
                problems.append("case-insensitive Date lookup failed")
            }
        } else {
            problems.append("could not build HTTPURLResponse")
        }
        return Result(
            name: "ClockSyncV2 HTTP-date parsing",
            passed: problems.isEmpty,
            detail: problems.isEmpty ? "3 RFC 9110 forms parsed, 2 rejects, header lookup OK"
                                     : problems.joined(separator: "; ")
        )
    }

    /// P8-AUDIT8-IOS-07: a relay-chosen `target_time` outside a plausible
    /// unix range is ignored instead of trapping in `Int64(Double)`.
    private static func testClockSyncTargetTimeBounds() -> Result {
        var problems: [String] = []
        let local: TimeInterval = 1_791_000_000
        for bad: UInt64 in [UInt64.max, UInt64(1) << 63, 4_102_444_800, 1_700_000_000, 0] {
            if let o = ClockSyncV2.offsetSample(targetTime: bad, localTime: local) {
                problems.append("\(bad) accepted as \(o)")
            }
        }
        if ClockSyncV2.offsetSample(targetTime: 1_791_000_030, localTime: local) != 30 {
            problems.append("+30 s not measured")
        }
        if ClockSyncV2.offsetSample(targetTime: 1_790_967_600, localTime: local) != -32_400 {
            problems.append("-9 h not measured")
        }
        return Result(
            name: "ClockSyncV2 target_time bounds",
            passed: problems.isEmpty,
            detail: problems.isEmpty ? "5 implausible values ignored, 2 offsets measured"
                                     : problems.joined(separator: "; ")
        )
    }

    // MARK: - Static layout assertions

    private static func testWireSizes() -> Result {
        var problems: [String] = []
        if LadonV2.relayProtocolVersion != 0x05 { problems.append("relayProtocolVersion=\(LadonV2.relayProtocolVersion) expected 0x05") }
        if LadonV2.hsigSigLen != 3_373 { problems.append("hsigSigLen=\(LadonV2.hsigSigLen) expected 3373") }
        if LadonV2.hkemPkLen != 1_216 { problems.append("hkemPkLen=\(LadonV2.hkemPkLen) expected 1216") }
        if LadonV2.hkemCtLen != 1_120 { problems.append("hkemCtLen=\(LadonV2.hkemCtLen) expected 1120") }
        if SealedV2.requestHeaderLen != 1_149 {
            problems.append("sealed requestHeaderLen=\(SealedV2.requestHeaderLen) expected 1149")
        }
        if SealedV2.innerEnvelopeLen != 15_128 {
            problems.append("sealed innerEnvelopeLen=\(SealedV2.innerEnvelopeLen) expected 15128")
        }
        // Addendum A1 layout (relay-core-v2 constants.rs tests pin the same).
        if LadonV2.bundleOffExitId != 3_257 { problems.append("bundleOffExitId=\(LadonV2.bundleOffExitId) expected 3257") }
        if LadonV2.bundleOffVerifier != 3_273 { problems.append("bundleOffVerifier=\(LadonV2.bundleOffVerifier) expected 3273") }
        if LadonV2.bundleBodyLen != 3_305 { problems.append("bundleBodyLen=\(LadonV2.bundleBodyLen) expected 3305") }
        if LadonV2.bundleLen != 6_678 { problems.append("bundleLen=\(LadonV2.bundleLen) expected 6678") }
        if SealedV2.enqueueHeaderLen != 88 { problems.append("enqueueHeaderLen=\(SealedV2.enqueueHeaderLen) expected 88") }
        return Result(
            name: "wire layout sizes",
            passed: problems.isEmpty,
            detail: problems.isEmpty ? "all sizes match Rust relay-core-v2" : problems.joined(separator: "; "))
    }

    /// Spec §4.9: PUSH_REGISTER_BODY_LEN must equal 3,414 and equal
    /// apns_token + sandbox + ts + hsig. Cross-checked against Rust
    /// `relay-core-v2::constants::PUSH_REGISTER_BODY_LEN`.
    private static func testPushRegisterBodyLayout() -> Result {
        var problems: [String] = []
        if LadonV2.apnsTokenLen != 32 { problems.append("apnsTokenLen=\(LadonV2.apnsTokenLen) expected 32") }
        let expected = LadonV2.apnsTokenLen + 1 + 8 + LadonV2.hsigSigLen
        if LadonV2.pushRegisterBodyLen != expected {
            problems.append("pushRegisterBodyLen=\(LadonV2.pushRegisterBodyLen) expected \(expected)")
        }
        if LadonV2.pushRegisterBodyLen != 3_414 {
            problems.append("pushRegisterBodyLen=\(LadonV2.pushRegisterBodyLen) expected 3414 (Rust)")
        }
        let domain = String(data: LadonV2.domainPushRegister, encoding: .utf8) ?? "<non-utf8>"
        if domain != "L1-PushRegister-v2.1" {
            problems.append("domainPushRegister=\"\(domain)\" expected \"L1-PushRegister-v2.1\"")
        }
        return Result(
            name: "push-register body layout (v2.1)",
            passed: problems.isEmpty,
            detail: problems.isEmpty ? "32 + 1 + 8 + 3,373 = 3,414, domain matches Rust" : problems.joined(separator: "; "))
    }

    // MARK: - BLAKE3 known-answer vectors (from BLAKE3 official test vectors)

    private static func testBlake3KnownAnswerVectors() -> Result {
        struct Kat { let input: Data; let hex32: String }
        let kats: [Kat] = [
            // Empty input
            Kat(input: Data(),
                hex32: "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"),
            // "abc"
            Kat(input: Data("abc".utf8),
                hex32: "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"),
            // 0x00..0xfa (251 bytes ascending) — BLAKE3 spec test vector input #1024
            // We use the documented vector for input length 0:
        ]
        for k in kats {
            let h = Blake3.hash(k.input, outputLength: 32)
            let got = h.map { String(format: "%02x", $0) }.joined()
            if got != k.hex32 {
                return Result(
                    name: "BLAKE3 known-answer vectors",
                    passed: false,
                    detail: "input.len=\(k.input.count) got=\(got) expected=\(k.hex32)")
            }
        }
        return Result(
            name: "BLAKE3 known-answer vectors",
            passed: true,
            detail: "\(kats.count) KATs match BLAKE3-team reference")
    }

    /// A1 §10: every usecase tag gives its own pre-hash domain, and none of
    /// them equals the retired untagged pre-hash `BLAKE3("L1-Sig-v1" || m)`.
    private static func testHSigUsecaseDomains() -> Result {
        let name = "HSig usecase tags: disjoint pre-hash domains"
        let m = Data("same message".utf8)
        let all: [HSigUsecaseV2] = [.bundle, .fetch, .pushRegister, .innerSender, .pairing]
        let hashes = all.map { HSigV2.prehash(m, usecase: $0) }
        let untagged: Data = {
            let h = Blake3.Hasher()
            h.update(LadonV2.domainSign)
            h.update(m)
            return h.finalize(outputLength: 32)
        }()
        guard Set(hashes).count == all.count, !hashes.contains(untagged) else {
            return Result(name: name, passed: false, detail: "two tags (or a tag and untagged) share a pre-hash")
        }
        return Result(name: name, passed: true, detail: "\(all.count) tags, pairwise distinct, none equals untagged")
    }

    /// A1 §7 support: the block list and the rotation job survive an encode/
    /// decode round trip exactly; malformed input never yields a job (so a
    /// damaged item cannot turn into "nothing to do" silently) and a list
    /// never carries anything but 64-hex recipient ids.
    private static func testBlockingCodec() -> Result {
        let name = "Blocking: block list + rotation job encoding"
        let a = String(repeating: "ab", count: 32), b = String(repeating: "0f", count: 32)
        var problems: [String] = []
        if BlockingCodecV2.decodeRids(BlockingCodecV2.encodeRids([a, b])) != [a, b] { problems.append("rid list round-trip") }
        if BlockingCodecV2.decodeRids(BlockingCodecV2.encodeRids([a, "XYZ", a.uppercased(), String(a.dropLast())])) != [a] {
            problems.append("invalid ids kept")
        }
        if !BlockingCodecV2.decodeRids(nil).isEmpty { problems.append("nil list not empty") }
        for job in [RotationJobV2(keyRecipients: [a, b], publishPending: true),
                    RotationJobV2(keyRecipients: [], publishPending: true),
                    RotationJobV2(keyRecipients: [b], publishPending: false)] {
            if BlockingCodecV2.decodeJob(BlockingCodecV2.encodeJob(job)) != job { problems.append("job round-trip") }
        }
        for bad in ["", "publish=2", "publish=1\nxyz", "x\n" + a] where BlockingCodecV2.decodeJob(Data(bad.utf8)) != nil {
            problems.append("malformed job accepted")
        }
        if !RotationJobV2(keyRecipients: [], publishPending: false).isDone { problems.append("isDone wrong") }
        guard problems.isEmpty else { return Result(name: name, passed: false, detail: problems.joined(separator: "; ")) }
        return Result(name: name, passed: true, detail: "lists + 3 jobs round-trip; 4 malformed jobs refused")
    }

    /// A1 §7 transition: a sender holding the contact's current and previous
    /// key uses exactly the one whose verifier the bundle carries — current
    /// first — and none if neither matches (stale key → precise error).
    private static func testDeliveryKeyChoice() -> Result {
        let name = "Delivery key choice: current or previous, by published verifier"
        do {
            let exit = ExitIdV2(bytes: Data(repeating: 0x21, count: 16))
            let current = Data(repeating: 0x01, count: 32), previous = Data(repeating: 0x02, count: 32)
            let other = Data(repeating: 0x03, count: 32)
            func v(_ k: Data) throws -> Data { DeliveryKeyV2.verifier(exitDeliveryKey: try DeliveryKeyV2.exitDeliveryKey(k, exitId: exit)) }
            let candidates = [current, previous]
            guard try RelayClientV2.keyMatching(verifier: v(current), candidates: candidates, exitId: exit) == current,
                  try RelayClientV2.keyMatching(verifier: v(previous), candidates: candidates, exitId: exit) == previous,
                  try RelayClientV2.keyMatching(verifier: v(other), candidates: candidates, exitId: exit) == nil,
                  try RelayClientV2.keyMatching(verifier: v(current), candidates: [], exitId: exit) == nil else {
                return Result(name: name, passed: false, detail: "wrong key chosen")
            }
            // Exit-bound: the verifier of another exit matches nothing here.
            let otherExit = ExitIdV2(bytes: Data(repeating: 0x22, count: 16))
            let foreign = DeliveryKeyV2.verifier(exitDeliveryKey: try DeliveryKeyV2.exitDeliveryKey(current, exitId: otherExit))
            guard try RelayClientV2.keyMatching(verifier: foreign, candidates: candidates, exitId: exit) == nil else {
                return Result(name: name, passed: false, detail: "verifier of another exit matched")
            }
            return Result(name: name, passed: true, detail: "current, previous, none, and other-exit cases correct")
        } catch { return Result(name: name, passed: false, detail: "\(error)") }
    }

    // MARK: - Wire-format round-trips

    /// Layout-only bundle (rid is not SHA-256 of the pk, as in the Rust vector).
    private static func dummyBundle() -> BundleV2 {
        BundleV2(
            version: LadonV2.relayProtocolVersion,
            recipientId: RecipientIdV2(bytes: Data(repeating: 0xAA, count: 32)),
            recipientHsigPk: Data(repeating: 0x22, count: LadonV2.hsigPkLen),
            recipientHkemPk: Data(repeating: 0x33, count: LadonV2.hkemPkLen),
            bundleId: BundleIdV2(bytes: Data(repeating: 0x44, count: 16)),
            publishedAt: 1_700_000_000,
            exitId: ExitIdV2(bytes: Data(repeating: 0xBB, count: 16)),
            verifier: Data(repeating: 0x66, count: LadonV2.deliveryVerifierLen),
            bundleHsig: Data(repeating: 0x55, count: LadonV2.hsigSigLen)
        )
    }

    /// A1 §3.2: fixed 6,678 B, exact parse, big-endian `published_at`, and
    /// refusal of any other length or version byte.
    private static func testDeliveryBundleRoundtrip() -> Result {
        let name = "Delivery bundle round-trip (A1)"
        let b = dummyBundle()
        let bytes = b.encode()
        guard bytes.count == LadonV2.bundleLen else {
            return Result(name: name, passed: false, detail: "size \(bytes.count) != \(LadonV2.bundleLen)")
        }
        do {
            guard try BundleV2.parse(bytes) == b else {
                return Result(name: name, passed: false, detail: "parsed != original")
            }
            guard b.signingInput() == bytes.prefix(LadonV2.bundleBodyLen),
                  bytes.subdata(in: LadonV2.bundleOffPublishedAt..<LadonV2.bundleOffExitId) == u64BE(1_700_000_000) else {
                return Result(name: name, passed: false, detail: "signing input or published_at layout wrong")
            }
        } catch {
            return Result(name: name, passed: false, detail: "\(error)")
        }
        var refusals: [String] = []
        if (try? BundleV2.parse(bytes + Data([0]))) != nil { refusals.append("trailing byte accepted") }
        if (try? BundleV2.parse(bytes.dropLast())) != nil { refusals.append("short bundle accepted") }
        var oldVersion = bytes
        oldVersion[0] = 0x02
        if (try? BundleV2.parse(oldVersion)) != nil { refusals.append("version 0x02 accepted") }
        // rid ≠ SHA-256(pk): structurally invalid even though it parses.
        if (try? b.validateStructure()) != nil { refusals.append("rid/pk binding not enforced") }
        guard refusals.isEmpty else { return Result(name: name, passed: false, detail: refusals.joined(separator: "; ")) }
        return Result(name: name, passed: true, detail: "6,678 B; exact parse; length/version/binding refused")
    }

    /// A1 §6: START/KEY encode and parse back exactly; anything else with the
    /// control prefix — including the retired V1 start — is malformed, never
    /// a chat message; ordinary texts are not control messages.
    private static func testControlMessageFormat() -> Result {
        let name = "Control messages START/KEY: format and parsing"
        let k = Data((0..<32).map { UInt8($0 + 1) })
        let start = ControlMessageV2.start(deliveryKey: k)
        let key = ControlMessageV2.key(deliveryKey: k)
        var problems: [String] = []
        if ControlMessageV2.parse(start) != .start(deliveryKey: k) { problems.append("START not parsed back") }
        if ControlMessageV2.parse(key) != .key(deliveryKey: k) { problems.append("KEY not parsed back") }
        let malformed = [
            "\u{E000}LADON-CTL-V1:start",                                        // retired V1
            ControlMessageV2.start(deliveryKey: Data(repeating: 0, count: 32)),  // all-zero K
            ControlMessageV2.start(deliveryKey: k.dropLast()),                   // 31 bytes
            start + "=",                                                         // non-canonical
            start + " ",
            "\u{E000}LADON-CTL-V2:other:" + PairingCodeV4.base64url(k),
        ]
        for m in malformed where ControlMessageV2.parse(m) != .malformed {
            problems.append("not refused: \(m.unicodeScalars.dropFirst().prefix(24))")
        }
        for text in ["hello", " " + start, "LADON-CTL-V2:start:" + PairingCodeV4.base64url(k)] where ControlMessageV2.parse(text) != nil {
            problems.append("ordinary text taken as control")
        }
        guard problems.isEmpty else { return Result(name: name, passed: false, detail: problems.joined(separator: "; ")) }
        return Result(name: name, passed: true, detail: "START/KEY round-trip; \(malformed.count) malformed refused; texts untouched")
    }

    /// A2 §5: lane sizes and body limits, and an answer of the wrong lane
    /// size is refused before any decryption.
    private static func testSealedLaneSizes() -> Result {
        let name = "Sealed lane sizes (A2 §5)"
        var problems: [String] = []
        if SealedLaneV2.send.requestLen != 16_384 || SealedLaneV2.send.responseLen != 8_192 { problems.append("lane S sizes") }
        if SealedLaneV2.fetch.requestLen != 8_192 || SealedLaneV2.fetch.responseLen != 16_384 { problems.append("lane F sizes") }
        if SealedLaneV2.send.maxRequestBody != SealedV2.enqueueHeaderLen + SealedV2.innerEnvelopeLen { problems.append("ENQUEUE does not fill lane S") }
        if SealedLaneV2.fetch.maxRequestBody < LadonV2.bundleLen { problems.append("DIR_PUT does not fit lane F") }
        if SealedLaneV2.send.maxResponseBody < LadonV2.bundleLen { problems.append("DIR_GET answer does not fit lane S") }
        if SealedLaneV2.fetch.maxResponseBody < 1 + LadonV2.fetchBatchIdLen + 1 + 4 + SealedV2.innerEnvelopeLen { problems.append("FETCH answer does not fit lane F") }
        let key = Data(repeating: 0x11, count: 32), target = Data(repeating: 0x42, count: 16)
        if (try? SealedCodecV2.openResponse(Data(count: SealedLaneV2.fetch.responseLen - 1), kResp: key, targetId: target, lane: .fetch)) != nil {
            problems.append("short answer accepted")
        }
        return Result(name: name, passed: problems.isEmpty, detail: problems.isEmpty ? "sizes and limits as specified" : problems.joined(separator: "; "))
    }

    /// Scan F30/F31: a peer-supplied chunkCount outside 1...128 must be
    /// refused by the descriptor before any buffer is sized from it.
    private static func testAttachmentChunkCountBound() -> Result {
        let name = "Attachment chunkCount bound (F30/F31)"
        func make(_ n: UInt32) throws -> AttachmentRemoteBlobDescriptor {
            try AttachmentRemoteBlobDescriptor(blobID: Data(count: 16), bucket: .b1KB,
                                               chunkCount: n, digest: Data(count: 32), blobHost: .ch)
        }
        for bad in [UInt32(0), 129, UInt32.max] {
            do {
                _ = try make(bad)
                return Result(name: name, passed: false, detail: "chunkCount \(bad) accepted")
            } catch AttachmentRemoteBlobDescriptor.ValidationError.chunkCountRange {
                continue
            } catch {
                return Result(name: name, passed: false, detail: "chunkCount \(bad): wrong error \(error)")
            }
        }
        for good in [UInt32(1), 128] {
            do { _ = try make(good) } catch {
                return Result(name: name, passed: false, detail: "chunkCount \(good) refused: \(error)")
            }
        }
        return Result(name: name, passed: true, detail: "0, 129, max refused; 1, 128 accepted")
    }

    // MARK: - Cryptographic round-trips (require PQ self-test)

    private static func testHSigRoundtrip() -> Result {
        do {
            let kp = try HSigKeyPairV2.generate()
            let pk = kp.publicKeyBytes()
            let msg = Data("the quick brown fox jumps over the lazy dog".utf8)
            let sig = try HSigV2.sign(msg, usecase: .bundle, with: kp)
            guard sig.count == LadonV2.hsigSigLen else {
                return Result(name: "HSig sign/verify", passed: false,
                              detail: "sig length \(sig.count) != \(LadonV2.hsigSigLen)")
            }
            guard HSigV2.verify(message: msg, usecase: .bundle, signature: sig, publicKey: pk) else {
                return Result(name: "HSig sign/verify", passed: false, detail: "verify rejected valid sig")
            }
            // A1 §10: the same signature must fail under every other tag.
            for other in [HSigUsecaseV2.fetch, .pushRegister, .innerSender]
            where HSigV2.verify(message: msg, usecase: other, signature: sig, publicKey: pk) {
                return Result(name: "HSig sign/verify", passed: false, detail: "accepted under another usecase tag")
            }
            // Tampered message must fail.
            let tampered = Data("tampered".utf8)
            guard !HSigV2.verify(message: tampered, usecase: .bundle, signature: sig, publicKey: pk) else {
                return Result(name: "HSig sign/verify", passed: false, detail: "verify accepted tampered msg")
            }
            // Flipped classical half must fail.
            var sigFlipEd = sig
            sigFlipEd[0] ^= 0x01
            guard !HSigV2.verify(message: msg, usecase: .bundle, signature: sigFlipEd, publicKey: pk) else {
                return Result(name: "HSig sign/verify", passed: false, detail: "accepted flipped Ed25519 half")
            }
            // Flipped PQ half must fail.
            var sigFlipDil = sig
            sigFlipDil[LadonV2.ed25519SigLen + 5] ^= 0x01
            guard !HSigV2.verify(message: msg, usecase: .bundle, signature: sigFlipDil, publicKey: pk) else {
                return Result(name: "HSig sign/verify", passed: false, detail: "accepted flipped ML-DSA half")
            }
            return Result(name: "HSig sign/verify", passed: true, detail: "sig=\(sig.count) B; tamper + cross-tag checks OK")
        } catch {
            return Result(name: "HSig sign/verify", passed: false, detail: "\(error)")
        }
    }

    /// End-to-end check that the push-register body produced by
    /// `PushRegistrationClientV2.buildBody` carries a valid hsig signature
    /// over the documented pre-image, and that any byte-level tamper is
    /// rejected by `HSigV2.verify` against the matching pre-image.
    private static func testPushRegisterSignRoundtrip() -> Result {
        do {
            let kp = try HSigKeyPairV2.generate()
            let pk = kp.publicKeyBytes()
            let rid = RecipientIdV2.fromIdentityKey(pk)
            // F-P6-IOS-CRYPTO-01 (2026-05-17): use the project's randomBytes()
            // helper which precondition-checks errSecSuccess, matching the
            // CSPRNG fail-closed convention used everywhere else in V2.
            let apns = randomBytes(LadonV2.apnsTokenLen)
            let ts: UInt64 = 1_715_000_000
            let body = try PushRegistrationClientV2.buildBody(
                rid: rid, apnsToken: apns, sandbox: true, timestamp: ts, hsigKp: kp
            )
            guard body.count == LadonV2.pushRegisterBodyLen else {
                return Result(name: "push-register sign roundtrip", passed: false,
                              detail: "body length \(body.count) != \(LadonV2.pushRegisterBodyLen)")
            }
            // Decompose body and reconstruct pre-image.
            let signedPayload = body.subdata(in: 0..<(LadonV2.apnsTokenLen + 1 + 8))
            let sig = body.subdata(in: signedPayload.count..<body.count)
            guard sig.count == LadonV2.hsigSigLen else {
                return Result(name: "push-register sign roundtrip", passed: false,
                              detail: "sig length \(sig.count) != \(LadonV2.hsigSigLen)")
            }
            // Sandbox byte must be exactly 1.
            guard signedPayload[LadonV2.apnsTokenLen] == 0x01 else {
                return Result(name: "push-register sign roundtrip", passed: false,
                              detail: "sandbox byte != 0x01")
            }
            // Timestamp must be big-endian.
            let tsBytes = signedPayload.subdata(in: (LadonV2.apnsTokenLen + 1)..<(LadonV2.apnsTokenLen + 1 + 8))
            let parsedTs = tsBytes.withUnsafeBytes { ptr -> UInt64 in
                var v: UInt64 = 0
                for b in ptr { v = (v << 8) | UInt64(b) }
                return v
            }
            guard parsedTs == ts else {
                return Result(name: "push-register sign roundtrip", passed: false,
                              detail: "ts not big-endian: parsed=\(parsedTs) expected=\(ts)")
            }
            var pre = Data()
            pre.append(LadonV2.domainPushRegister)
            pre.append(rid.bytes)
            pre.append(signedPayload)
            guard HSigV2.verify(message: pre, usecase: .pushRegister, signature: sig, publicKey: pk) else {
                return Result(name: "push-register sign roundtrip", passed: false,
                              detail: "verify rejected valid signature")
            }
            // Tamper: flip one bit of the apns token, re-derive pre-image,
            // verify must reject.
            var tampered = pre
            tampered[LadonV2.domainPushRegister.count + LadonV2.recipientIdLen] ^= 0x01
            guard !HSigV2.verify(message: tampered, usecase: .pushRegister, signature: sig, publicKey: pk) else {
                return Result(name: "push-register sign roundtrip", passed: false,
                              detail: "verify accepted tampered apns token")
            }
            // Wrong rid binding must fail.
            var otherRidBytes = rid.bytes
            otherRidBytes[0] ^= 0xFF
            var preWrongRid = Data()
            preWrongRid.append(LadonV2.domainPushRegister)
            preWrongRid.append(otherRidBytes)
            preWrongRid.append(signedPayload)
            guard !HSigV2.verify(message: preWrongRid, usecase: .pushRegister, signature: sig, publicKey: pk) else {
                return Result(name: "push-register sign roundtrip", passed: false,
                              detail: "verify accepted wrong rid binding")
            }
            return Result(name: "push-register sign roundtrip", passed: true,
                          detail: "body=\(body.count) B; sig=\(sig.count) B; tamper + rid checks OK")
        } catch {
            return Result(name: "push-register sign roundtrip", passed: false, detail: "\(error)")
        }
    }

    private static func testHKEMRoundtrip() -> Result {
        do {
            let kp = try HKEMKeyPairV2.generate()
            let pk = kp.publicKeyBytes()
            guard pk.count == LadonV2.hkemPkLen else {
                return Result(name: "HKEM encaps/decaps", passed: false,
                              detail: "pk length \(pk.count) != \(LadonV2.hkemPkLen)")
            }
            let r = try HKEMV2.encaps(publicKey: pk)
            guard r.ciphertext.count == LadonV2.hkemCtLen else {
                return Result(name: "HKEM encaps/decaps", passed: false,
                              detail: "ct length \(r.ciphertext.count) != \(LadonV2.hkemCtLen)")
            }
            guard r.sharedKey.count == 32 else {
                return Result(name: "HKEM encaps/decaps", passed: false,
                              detail: "K length \(r.sharedKey.count) != 32")
            }
            let kBack = try HKEMV2.decaps(keyPair: kp, ciphertext: r.ciphertext)
            guard kBack == r.sharedKey else {
                return Result(name: "HKEM encaps/decaps", passed: false,
                              detail: "decaps K != encaps K")
            }
            // Two encaps runs MUST produce different ct & K.
            let r2 = try HKEMV2.encaps(publicKey: pk)
            guard r2.ciphertext != r.ciphertext, r2.sharedKey != r.sharedKey else {
                return Result(name: "HKEM encaps/decaps", passed: false,
                              detail: "two encaps runs produced identical output")
            }
            return Result(name: "HKEM encaps/decaps", passed: true,
                          detail: "K matches; freshness OK")
        } catch {
            return Result(name: "HKEM encaps/decaps", passed: false, detail: "\(error)")
        }
    }

    /// A1 §4 / §3.2: a bundle issued with a delivery key verifies under the
    /// "L1-Bundle-v3" tag (and no other), carries V_X of exactly K_X for its
    /// exit, binds rid to the key, and changes verifier with the key.
    private static func testDeliveryBundleIssueVerify() -> Result {
        let name = "Delivery bundle issue/verify (A1)"
        do {
            let id = try makeIdentity()
            let exit = ExitIdV2(bytes: Data(repeating: 0x3C, count: 16))
            let k = randomBytes(LadonV2.deliveryKeyLen)
            let b = try BundleV2.issue(
                recipientId: id.recipientId,
                recipientHsigPk: id.senderHsigKp.publicKeyBytes(),
                recipientHkemPk: id.recipientHkemKp.publicKeyBytes(),
                publishedAt: 1_700_000_000, exitId: exit, deliveryKey: k,
                signWith: id.senderHsigKp)
            try b.validateStructure()
            let pk = id.senderHsigKp.publicKeyBytes()
            guard HSigV2.verify(message: b.signingInput(), usecase: .bundle, signature: b.bundleHsig, publicKey: pk),
                  !HSigV2.verify(message: b.signingInput(), usecase: .fetch, signature: b.bundleHsig, publicKey: pk) else {
                return Result(name: name, passed: false, detail: "bundle signature not bound to its tag")
            }
            let kx = try DeliveryKeyV2.exitDeliveryKey(k, exitId: exit)
            guard b.verifier == DeliveryKeyV2.verifier(exitDeliveryKey: kx), b.exitId == exit else {
                return Result(name: name, passed: false, detail: "verifier is not V_X of this exit's K_X")
            }
            let otherExitKx = try DeliveryKeyV2.exitDeliveryKey(k, exitId: ExitIdV2(bytes: Data(repeating: 0x3D, count: 16)))
            guard otherExitKx != kx else {
                return Result(name: name, passed: false, detail: "K_X not exit-bound")
            }
            let rotated = try BundleV2.issue(
                recipientId: id.recipientId,
                recipientHsigPk: pk,
                recipientHkemPk: id.recipientHkemKp.publicKeyBytes(),
                publishedAt: 1_700_000_001, exitId: exit, deliveryKey: randomBytes(LadonV2.deliveryKeyLen),
                signWith: id.senderHsigKp)
            guard rotated.verifier != b.verifier else {
                return Result(name: name, passed: false, detail: "verifier unchanged after key rotation")
            }
            guard try BundleV2.parse(b.encode()) == b else {
                return Result(name: name, passed: false, detail: "issued bundle does not round-trip")
            }
            return Result(name: name, passed: true, detail: "tag-bound signature; V_X matches K_X; exit-bound; rotates")
        } catch {
            return Result(name: name, passed: false, detail: "\(error)")
        }
    }

    private static func makeIdentity() throws -> LocalIdentityV2 {
        LocalIdentityV2.make(senderHsigKp: try HSigKeyPairV2.generate(),
                             recipientHkemKp: try HKEMKeyPairV2.generate())
    }

    /// A1 §3.3–3.4: the sealed envelope is exactly 16 KiB, opens under the v3
    /// AAD with the exit's HKEM key, and its plaintext is the 89-byte header
    /// (flags, rid, K_X, sent_at, envelope id) followed by the inner envelope.
    /// A2 §4.1 with the real hybrid HKEM: the app seals a request, and this
    /// test opens it the way the exit does — decapsulate, derive k_req, open
    /// the AEAD under the request AAD, then check kind, body length and the
    /// zero padding. The response key from the same secret opens an answer.
    private static func testSealedRequestRealHKEM() -> Result {
        let name = "Sealed request, real HKEM (A2 §4)"
        do {
            let exitKp = try HKEMKeyPairV2.generate()
            let pk = exitKp.publicKeyBytes()
            let target = ExitIdV2.fromHkemPk(pk).bytes
            let body = Data("ladon-selftest".utf8)
            let req = try SealedCodecV2.seal(targetHkemPk: pk, targetId: target, kind: .dirGet, body: body)
            let b = req.bytes
            guard b.count == SealedLaneV2.send.requestLen, b[0] == SealedV2.version,
                  b.subdata(in: SealedV2.offTargetId..<SealedV2.offHkemCt) == target else {
                return Result(name: name, passed: false, detail: "header or size wrong")
            }
            let ss = try HKEMV2.decaps(keyPair: exitKp, ciphertext: b.subdata(in: SealedV2.offHkemCt..<SealedV2.offNonce))
            let kReq = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: ss), salt: Data(),
                                              info: SealedV2.infoRequest, outputByteCount: 32)
            var aad = SealedV2.infoRequest
            aad.append(SealedV2.version)
            aad.append(target)
            let box = try ChaChaPoly.SealedBox(combined: b.subdata(in: SealedV2.offNonce..<b.count))
            let pt = try ChaChaPoly.open(box, using: kReq, authenticating: aad)
            let len = Int(readU16BE(pt, at: 1))
            guard pt[pt.startIndex] == SealedKindV2.dirGet.rawValue, len == body.count,
                  pt.subdata(in: 3..<(3 + len)) == body,
                  pt.suffix(from: pt.startIndex + 3 + len).allSatisfy({ $0 == 0 }) else {
                return Result(name: name, passed: false, detail: "plaintext kind/length/padding wrong")
            }
            #if DEBUG
            let kResp = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: ss), salt: Data(),
                                               info: SealedV2.infoResponse, outputByteCount: 32)
                .withUnsafeBytes { Data($0) }
            let answer = try SealedCodecV2.sealResponseForVectors(
                kResp: kResp, nonce: randomBytes(12), targetId: target, lane: .send,
                status: SealedStatusV2.unknownRecipient, targetTime: 1_700_000_001, body: Data())
            let opened = try SealedCodecV2.openResponse(answer, for: req)
            guard opened.status == SealedStatusV2.unknownRecipient, opened.targetTime == 1_700_000_001 else {
                return Result(name: name, passed: false, detail: "response did not open with the request's key")
            }
            #endif
            return Result(name: name, passed: true, detail: "exit-side open OK: kind, length, zero padding; response key matches")
        } catch {
            return Result(name: name, passed: false, detail: "\(error)")
        }
    }

    #if DEBUG
    // MARK: - V2 application-ratchet self-tests (P8-IOS-RATCHET-PCS-01)
    //
    // Regression net for `V2RatchetPayload`. Runs against an in-memory state
    // store (no Keychain side effects) via the DEBUG test seam. The round-trip /
    // out-of-order tests below are single-direction bursts that pin the opening
    // leg (the bootstrap chain); the desync matrix further down
    // pins the active DH-ratchet behaviour that provides post-compromise security.

    private static func makeTestIdentity() throws -> LocalIdentityV2 {
        LocalIdentityV2.make(
            senderHsigKp: try HSigKeyPairV2.generate(),
            recipientHkemKp: try HKEMKeyPairV2.generate()
        )
    }

    /// `owner` issues a fresh one-time prekey and `holder` stores it, exactly as
    /// scanning `owner`'s pairing code will. Returns the public half.
    @discardableResult
    private static func handPrekey(from owner: LocalIdentityV2, validFor: TimeInterval = 600) throws -> OneTimePrekeyPublicV2 {
        let pub = try PrekeyStoreV2.generateOwn(expiresAt: Date().addingTimeInterval(validFor))
        try PrekeyStoreV2.storePeer(pub, forPeer: owner.recipientId.description)
        return pub
    }

    private static func testV2RatchetRoundtrip() -> Result {
        let name = "V2 ratchet round-trip"
        V2RatchetPayload._installInMemoryStoreForTesting()
        defer { V2RatchetPayload._restoreKeychainStoreForTesting() }
        do {
            let alice = try makeTestIdentity()
            let bob = try makeTestIdentity()
            let bobPeer = PeerHandleV2(recipientId: bob.recipientId, recipientHsigPk: bob.senderHsigKp.publicKeyBytes())
            let bobHkemPk = bob.recipientHkemKp.publicKeyBytes()
            let aliceHsigPk = alice.senderHsigKp.publicKeyBytes()
            try handPrekey(from: bob)

            // Single-message round-trip.
            let m0 = Data("hello ratchet".utf8)
            let f0 = try V2RatchetPayload.seal(plaintext: m0, peer: bobPeer, recipientHkemPk: bobHkemPk, localIdentity: alice)
            guard V2RatchetPayload.isRatchetFrame(f0) else {
                return Result(name: name, passed: false, detail: "sealed frame not recognised as a ratchet frame")
            }
            let o0 = try V2RatchetPayload.open(frame: f0, senderHsigPk: aliceHsigPk, localIdentity: bob)
            guard o0.plaintext == m0, o0.messageNumber == 0 else {
                return Result(name: name, passed: false, detail: "round-trip mismatch (n=\(o0.messageNumber))")
            }

            // Multi-message in-order chain.
            for i in 1...4 {
                let m = Data("msg-\(i)".utf8)
                let f = try V2RatchetPayload.seal(plaintext: m, peer: bobPeer, recipientHkemPk: bobHkemPk, localIdentity: alice)
                let o = try V2RatchetPayload.open(frame: f, senderHsigPk: aliceHsigPk, localIdentity: bob)
                guard o.plaintext == m, o.messageNumber == UInt32(i) else {
                    return Result(name: name, passed: false, detail: "chain mismatch at i=\(i) (n=\(o.messageNumber))")
                }
            }

            // Tamper: flipping a ciphertext/tag byte must fail closed.
            let f5 = try V2RatchetPayload.seal(plaintext: Data("tamper target".utf8), peer: bobPeer, recipientHkemPk: bobHkemPk, localIdentity: alice)
            var bad = Data(f5)
            bad[bad.count - 1] ^= 0x01
            do {
                _ = try V2RatchetPayload.open(frame: bad, senderHsigPk: aliceHsigPk, localIdentity: bob)
                return Result(name: name, passed: false, detail: "tampered frame was accepted")
            } catch { /* expected */ }

            return Result(name: name, passed: true, detail: "single + 4-msg chain + tamper-reject OK")
        } catch {
            return Result(name: name, passed: false, detail: "\(error)")
        }
    }

    /// Size gate: (1) the limit is the one the wire constants imply, (2) a
    /// maximum-length plaintext produces a frame that fills the 16,384-byte
    /// envelope exactly, (3) one byte more is rejected BEFORE the ratchet moves
    /// — the next accepted message still gets the next consecutive number.
    private static func testV2RatchetSizeGate() -> Result {
        let name = "V2 ratchet size gate (no state change on oversize)"
        V2RatchetPayload._installInMemoryStoreForTesting()
        defer { V2RatchetPayload._restoreKeychainStoreForTesting() }
        do {
            // (1) Pin the derived numbers so any layout change is noticed.
            let maxBody = LadonV2.maxInnerMessageBodyLen
            guard maxBody == 8_610, V2RatchetPayload.maxPlaintextLen == 6_252 else {
                return Result(name: name, passed: false,
                              detail: "limits drifted: maxBody=\(maxBody) maxPlaintext=\(V2RatchetPayload.maxPlaintextLen)")
            }

            let alice = try makeTestIdentity()
            let bob = try makeTestIdentity()
            let bobPeer = PeerHandleV2(recipientId: bob.recipientId, recipientHsigPk: bob.senderHsigKp.publicKeyBytes())
            let bobHkemPk = bob.recipientHkemKp.publicKeyBytes()
            let aliceHsigPk = alice.senderHsigKp.publicKeyBytes()
            try handPrekey(from: bob)

            // Oversize on a FRESH session: must throw and must not bootstrap.
            let tooBig = Data(repeating: 0x41, count: V2RatchetPayload.maxPlaintextLen + 1)
            do {
                _ = try V2RatchetPayload.seal(plaintext: tooBig, peer: bobPeer, recipientHkemPk: bobHkemPk, localIdentity: alice)
                return Result(name: name, passed: false, detail: "oversize accepted on fresh session")
            } catch V2RatchetError.plaintextTooLarge { /* expected */ }

            // (2) Max-length plaintext: frame length must equal the body limit,
            // and the resulting Inner-Envelope must fill the bucket exactly.
            let maxPlain = Data(repeating: 0x42, count: V2RatchetPayload.maxPlaintextLen)
            let f0 = try V2RatchetPayload.seal(plaintext: maxPlain, peer: bobPeer, recipientHkemPk: bobHkemPk, localIdentity: alice)
            guard f0.count == maxBody else {
                return Result(name: name, passed: false, detail: "max frame \(f0.count) B != body limit \(maxBody) B")
            }
            let inner = try InnerEnvelopeV2.seal(recipientId: bob.recipientId, recipientHkemPk: bobHkemPk,
                                                 senderHsigKp: alice.senderHsigKp, timestamp: 0,
                                                 messageBody: f0, padLen: 0)
            // A2 §5: the ENQUEUE body (header + inner) fills lane S exactly.
            let envelope = SealedV2.requestHeaderLen + SealedV2.requestPrefixLen + SealedV2.enqueueHeaderLen
                + inner.count + LadonV2.aeadTagLen
            guard inner.count == SealedV2.innerEnvelopeLen, envelope == SealedLaneV2.send.requestLen else {
                return Result(name: name, passed: false, detail: "max message request \(envelope) B != \(SealedLaneV2.send.requestLen) B")
            }
            let o0 = try V2RatchetPayload.open(frame: f0, senderHsigPk: aliceHsigPk, localIdentity: bob)
            guard o0.plaintext == maxPlain, o0.messageNumber == 0 else {
                return Result(name: name, passed: false, detail: "max message round-trip failed (n=\(o0.messageNumber))")
            }

            // (3) Oversize on an ESTABLISHED session: rejected, counter untouched.
            do {
                _ = try V2RatchetPayload.seal(plaintext: tooBig, peer: bobPeer, recipientHkemPk: bobHkemPk, localIdentity: alice)
                return Result(name: name, passed: false, detail: "oversize accepted on established session")
            } catch V2RatchetError.plaintextTooLarge { /* expected */ }
            let m1 = Data("after oversize".utf8)
            let f1 = try V2RatchetPayload.seal(plaintext: m1, peer: bobPeer, recipientHkemPk: bobHkemPk, localIdentity: alice)
            let o1 = try V2RatchetPayload.open(frame: f1, senderHsigPk: aliceHsigPk, localIdentity: bob)
            guard o1.plaintext == m1, o1.messageNumber == 1 else {
                return Result(name: name, passed: false, detail: "counter moved on rejected send (next n=\(o1.messageNumber), expected 1)")
            }

            return Result(name: name, passed: true,
                          detail: "limit \(V2RatchetPayload.maxPlaintextLen) B; max fills \(envelope) B; oversize rejected twice, n stays consecutive")
        } catch {
            return Result(name: name, passed: false, detail: "\(error)")
        }
    }

    private static func testV2RatchetOutOfOrder() -> Result {
        let name = "V2 ratchet out-of-order + replay"
        V2RatchetPayload._installInMemoryStoreForTesting()
        defer { V2RatchetPayload._restoreKeychainStoreForTesting() }
        do {
            let alice = try makeTestIdentity()
            let bob = try makeTestIdentity()
            let bobPeer = PeerHandleV2(recipientId: bob.recipientId, recipientHsigPk: bob.senderHsigKp.publicKeyBytes())
            let bobHkemPk = bob.recipientHkemKp.publicKeyBytes()
            let aliceHsigPk = alice.senderHsigKp.publicKeyBytes()
            try handPrekey(from: bob)

            // Alice seals 4 messages; Bob receives them out of order: 3, 0, 1, 2.
            var frames: [Data] = []
            for i in 0..<4 {
                frames.append(try V2RatchetPayload.seal(plaintext: Data("ooo-\(i)".utf8), peer: bobPeer, recipientHkemPk: bobHkemPk, localIdentity: alice))
            }
            for idx in [3, 0, 1, 2] {
                let o = try V2RatchetPayload.open(frame: frames[idx], senderHsigPk: aliceHsigPk, localIdentity: bob)
                guard o.plaintext == Data("ooo-\(idx)".utf8), o.messageNumber == UInt32(idx) else {
                    return Result(name: name, passed: false, detail: "out-of-order mismatch at idx=\(idx) (n=\(o.messageNumber))")
                }
            }

            // Replay: re-opening an already-consumed message must fail closed.
            do {
                _ = try V2RatchetPayload.open(frame: frames[0], senderHsigPk: aliceHsigPk, localIdentity: bob)
                return Result(name: name, passed: false, detail: "replayed message was accepted")
            } catch { /* expected: replay / consumed skipped key */ }

            return Result(name: name, passed: true, detail: "skipped-key OOO [3,0,1,2] + replay-reject OK")
        } catch {
            return Result(name: name, passed: false, detail: "\(error)")
        }
    }

    /// Pins the DH-ratchet root KDF (ratchetRootStep): deterministic, advances
    /// the root key, 32+32 split, and sensitive to every input — both secrets
    /// (hybrid IKM) and each bound transcript field (ratchet key, KEM key
    /// encapsulated to, ciphertext, KEM key announced).
    private static func testV2RatchetDHStepKDF() -> Result {
        let name = "V2 ratchet DH-step KDF (hybrid, transcript-bound)"
        let rk = Data(repeating: 0x11, count: 32)
        let dh = Data(repeating: 0x22, count: 32)
        let kem = Data(repeating: 0x33, count: 32)
        let rpk = Data(repeating: 0x44, count: LadonV2.x25519PkLen)
        let toPk = Data(repeating: 0x55, count: LadonV2.kyber768PkLen)
        let ct = Data(repeating: 0x66, count: LadonV2.kyber768CtLen)
        let annPk = Data(repeating: 0x77, count: LadonV2.kyber768PkLen)
        func step(dh: Data = dh, kem: Data = kem, rpk: Data = rpk, toPk: Data = toPk, ct: Data = ct, annPk: Data = annPk) -> (rootKey: Data, chainKey: Data) {
            V2RatchetPayload._ratchetRootStepForTesting(rootKey: rk, dhOutput: dh, kemSharedSecret: kem,
                                                        ratchetPublicKey: rpk, encapsulatedToKemPk: toPk,
                                                        kemCt: ct, announcedKemPk: annPk)
        }
        func flipped(_ d: Data) -> Data { var x = Data(d); x[x.startIndex] ^= 0x01; return x }
        let a = step()
        let aAgain = step()
        var problems: [String] = []
        if a.rootKey.count != 32 || a.chainKey.count != 32 { problems.append("output not 32+32 B") }
        if a.rootKey != aAgain.rootKey || a.chainKey != aAgain.chainKey { problems.append("not deterministic") }
        if a.rootKey == a.chainKey { problems.append("root == chain (no KDF split separation)") }
        if a.rootKey == rk { problems.append("new root == old root (no advance)") }
        let variants: [(String, (rootKey: Data, chainKey: Data))] = [
            ("dh", step(dh: flipped(dh))), ("kem", step(kem: flipped(kem))),
            ("ratchetPk", step(rpk: flipped(rpk))), ("encapsulatedToKemPk", step(toPk: flipped(toPk))),
            ("kemCt", step(ct: flipped(ct))), ("announcedKemPk", step(annPk: flipped(annPk))),
        ]
        for (label, v) in variants where v.rootKey == a.rootKey || v.chainKey == a.chainKey {
            problems.append("\(label) change did not change the output")
        }
        return Result(name: name, passed: problems.isEmpty,
                      detail: problems.isEmpty ? "deterministic; 32+32; advances; sensitive to both secrets + 4 transcript fields" : problems.joined(separator: "; "))
    }

    // MARK: - V2 active DH-ratchet (Double Ratchet) desync matrix (#6 Step 3+)
    //
    // Exercises the merged ping-pong ratchet via the in-memory store seam. Two
    // distinct test identities → distinct `dr.<peerId>` accounts that coexist in
    // the shared store, so a single process drives both ends of the conversation.

    private struct DRPair {
        let alice: LocalIdentityV2
        let bob: LocalIdentityV2
        let alicePeer: PeerHandleV2
        let bobPeer: PeerHandleV2
        /// Alice's own prekey (held by Bob) and Bob's own prekey (held by Alice).
        let alicePrekey: OneTimePrekeyPublicV2
        let bobPrekey: OneTimePrekeyPublicV2
        var aliceHkemPk: Data { alice.recipientHkemKp.publicKeyBytes() }
        var bobHkemPk: Data { bob.recipientHkemKp.publicKeyBytes() }
        var aliceHsigPk: Data { alice.senderHsigKp.publicKeyBytes() }
        var bobHsigPk: Data { bob.senderHsigKp.publicKeyBytes() }
    }

    /// Two identities that have scanned each other's code: each holds one
    /// unused prekey of the other, so either side may start the session.
    private static func makeDRPair() throws -> DRPair {
        let alice = try makeTestIdentity()
        let bob = try makeTestIdentity()
        let alicePrekey = try handPrekey(from: alice)
        let bobPrekey = try handPrekey(from: bob)
        return DRPair(
            alice: alice, bob: bob,
            alicePeer: PeerHandleV2(recipientId: alice.recipientId, recipientHsigPk: alice.senderHsigKp.publicKeyBytes()),
            bobPeer: PeerHandleV2(recipientId: bob.recipientId, recipientHsigPk: bob.senderHsigKp.publicKeyBytes()),
            alicePrekey: alicePrekey, bobPrekey: bobPrekey
        )
    }

    // Alice→Bob / Bob→Alice convenience wrappers.
    private static func aSeal(_ p: DRPair, _ m: Data) throws -> Data {
        try V2RatchetPayload.seal(plaintext: m, peer: p.bobPeer, recipientHkemPk: p.bobHkemPk, localIdentity: p.alice)
    }
    private static func bOpen(_ p: DRPair, _ f: Data) throws -> V2RatchetOpenedPayload {
        try V2RatchetPayload.open(frame: f, senderHsigPk: p.aliceHsigPk, localIdentity: p.bob)
    }
    private static func bSeal(_ p: DRPair, _ m: Data) throws -> Data {
        try V2RatchetPayload.seal(plaintext: m, peer: p.alicePeer, recipientHkemPk: p.aliceHkemPk, localIdentity: p.bob)
    }
    private static func aOpen(_ p: DRPair, _ f: Data) throws -> V2RatchetOpenedPayload {
        try V2RatchetPayload.open(frame: f, senderHsigPk: p.bobHsigPk, localIdentity: p.alice)
    }

    /// Full bidirectional ping-pong: every reply folds a fresh DH into the root.
    private static func testV2DRPingPong() -> Result {
        let name = "V2 DR bidirectional ping-pong"
        V2RatchetPayload._installInMemoryStoreForTesting()
        defer { V2RatchetPayload._restoreKeychainStoreForTesting() }
        do {
            let p = try makeDRPair()
            for round in 0..<6 {
                let am = Data("a-\(round)".utf8)
                guard try bOpen(p, aSeal(p, am)).plaintext == am else {
                    return Result(name: name, passed: false, detail: "A→B mismatch round \(round)")
                }
                let bm = Data("b-\(round)".utf8)
                guard try aOpen(p, bSeal(p, bm)).plaintext == bm else {
                    return Result(name: name, passed: false, detail: "B→A mismatch round \(round)")
                }
            }
            return Result(name: name, passed: true, detail: "6 round trips both directions OK")
        } catch { return Result(name: name, passed: false, detail: "\(error)") }
    }

    /// A burst of consecutive sends is ONE DH turn: message numbers run 0,1,2…
    /// within a chain and reset to 0 only after a reply (a new sending chain).
    private static func testV2DRBurstIsOneTurn() -> Result {
        let name = "V2 DR burst = one DH turn"
        V2RatchetPayload._installInMemoryStoreForTesting()
        defer { V2RatchetPayload._restoreKeychainStoreForTesting() }
        do {
            let p = try makeDRPair()
            for i in 0..<3 {
                let o = try bOpen(p, aSeal(p, Data("x\(i)".utf8)))
                guard o.messageNumber == UInt32(i) else {
                    return Result(name: name, passed: false, detail: "burst1 expected n=\(i), got \(o.messageNumber)")
                }
            }
            _ = try aOpen(p, bSeal(p, Data("reply".utf8)))   // Bob replies → Alice DH-ratchets.
            let o0 = try bOpen(p, aSeal(p, Data("y0".utf8)))  // New sending chain → n resets to 0.
            let o1 = try bOpen(p, aSeal(p, Data("y1".utf8)))
            guard o0.messageNumber == 0, o1.messageNumber == 1 else {
                return Result(name: name, passed: false, detail: "post-reply chain expected n=0,1; got \(o0.messageNumber),\(o1.messageNumber)")
            }
            return Result(name: name, passed: true, detail: "chain0 [0,1,2] then reply then chain1 [0,1]")
        } catch { return Result(name: name, passed: false, detail: "\(error)") }
    }

    /// Out-of-order delivery ACROSS two sending DH chains: pins the archived-
    /// receiving-chain mechanism (the PN substitute) and the (dhr, n) skipped-key
    /// keying — the regression that the old message-number-only key would fail.
    private static func testV2DROutOfOrderAcrossChains() -> Result {
        let name = "V2 DR out-of-order across DH chains"
        V2RatchetPayload._installInMemoryStoreForTesting()
        defer { V2RatchetPayload._restoreKeychainStoreForTesting() }
        do {
            let p = try makeDRPair()
            let a0 = try aSeal(p, Data("c0-m0".utf8))   // chain 0, n0
            _ = try bOpen(p, a0)                         // Bob bootstraps + consumes c0-m0.
            let a0b = try aSeal(p, Data("c0-m1".utf8))  // chain 0, n1  (HOLD)
            _ = try aOpen(p, bSeal(p, Data("rb".utf8))) // Bob reply → Alice DH-ratchets → next Alice send is a new chain.
            let a1 = try aSeal(p, Data("c1-m0".utf8))   // chain 1, n0  (HOLD)
            let a1b = try aSeal(p, Data("c1-m1".utf8))  // chain 1, n1

            // Deliver c1-m1 first: forces a DH turn (archives chain 0 at nr=1) and
            // skips c1-m0 within the new chain.
            guard try bOpen(p, a1b).plaintext == Data("c1-m1".utf8) else {
                return Result(name: name, passed: false, detail: "c1-m1 mismatch")
            }
            // Late frame from the archived chain 0.
            guard try bOpen(p, a0b).plaintext == Data("c0-m1".utf8) else {
                return Result(name: name, passed: false, detail: "archived c0-m1 mismatch")
            }
            // The skipped key for c1-m0 (keyed by its own dhr).
            guard try bOpen(p, a1).plaintext == Data("c1-m0".utf8) else {
                return Result(name: name, passed: false, detail: "skipped c1-m0 mismatch")
            }
            // Replaying a consumed frame must fail closed.
            do { _ = try bOpen(p, a1b); return Result(name: name, passed: false, detail: "replay accepted") }
            catch { /* expected */ }
            return Result(name: name, passed: true, detail: "archived-chain + (dhr,n) skipped key + replay-reject OK")
        } catch { return Result(name: name, passed: false, detail: "\(error)") }
    }

    /// Interleaved in-flight messages both directions: independent send/receive
    /// chains, no counter cross-talk, survives state reload each call (the
    /// in-memory store decodes the full DR state on every seal/open).
    private static func testV2DRInterleaved() -> Result {
        let name = "V2 DR interleaved both directions"
        V2RatchetPayload._installInMemoryStoreForTesting()
        defer { V2RatchetPayload._restoreKeychainStoreForTesting() }
        do {
            let p = try makeDRPair()
            // Prime both directions.
            _ = try bOpen(p, aSeal(p, Data("a0".utf8)))
            _ = try aOpen(p, bSeal(p, Data("b0".utf8)))
            // Alice sends two before Bob replies; Bob sends two before Alice replies.
            let a1 = try aSeal(p, Data("a1".utf8))
            let a2 = try aSeal(p, Data("a2".utf8))
            let b1 = try bSeal(p, Data("b1".utf8))
            let b2 = try bSeal(p, Data("b2".utf8))
            guard try aOpen(p, b1).plaintext == Data("b1".utf8),
                  try bOpen(p, a1).plaintext == Data("a1".utf8),
                  try aOpen(p, b2).plaintext == Data("b2".utf8),
                  try bOpen(p, a2).plaintext == Data("a2".utf8) else {
                return Result(name: name, passed: false, detail: "interleaved mismatch")
            }
            return Result(name: name, passed: true, detail: "interleaved A/B in-flight OK")
        } catch { return Result(name: name, passed: false, detail: "\(error)") }
    }

    /// Simultaneous initiation (both bootstrap as initiator before receiving):
    /// the deterministic HSig tie-break makes the canonical responder (the SMALLER
    /// long-term HSig pk) yield and adopt the incoming session; the canonical
    /// initiator keeps its own and converges in ≤1 round trip. The cost is that the
    /// yielding side's already-sent messages in its abandoned initiator chain are
    /// dropped (see testV2DRCrossingAfterBurst for the >1-message case). This test
    /// pins WHICH side adopts (the direction of the tie-break), not just "one of".
    private static func testV2DRSimultaneousInit() -> Result {
        let name = "V2 DR simultaneous-init crossing"
        V2RatchetPayload._installInMemoryStoreForTesting()
        defer { V2RatchetPayload._restoreKeychainStoreForTesting() }
        do {
            let p = try makeDRPair()
            let af = try aSeal(p, Data("a-first".utf8))   // Alice initiator
            let bf = try bSeal(p, Data("b-first".utf8))   // Bob initiator (crossed)
            // Cross-deliver. The party with the SMALLER long-term HSig pk is the
            // canonical responder and is the one whose open() adopts + decrypts.
            let bobGotAlice = try? bOpen(p, af)
            let aliceGotBob = try? aOpen(p, bf)
            let aliceAdopts = p.aliceHsigPk.lexicographicallyPrecedes(p.bobHsigPk)
            if aliceAdopts {
                guard aliceGotBob?.plaintext == Data("b-first".utf8), bobGotAlice == nil else {
                    return Result(name: name, passed: false, detail: "expected Alice (smaller HSig) to adopt; alice=\(aliceGotBob != nil) bob=\(bobGotAlice != nil)")
                }
            } else {
                guard bobGotAlice?.plaintext == Data("a-first".utf8), aliceGotBob == nil else {
                    return Result(name: name, passed: false, detail: "expected Bob (smaller HSig) to adopt; alice=\(aliceGotBob != nil) bob=\(bobGotAlice != nil)")
                }
            }
            // Both codes are spent now: the adopter's by adoption, the other
            // side's by verify-and-burn — no copy of either code opens a session.
            guard try !ownPrekeyValid(p.alicePrekey), try !ownPrekeyValid(p.bobPrekey) else {
                return Result(name: name, passed: false, detail: "a crossing prekey stayed usable")
            }
            // Replaying the adopted frame must fail closed.
            do {
                _ = aliceAdopts ? try aOpen(p, bf) : try bOpen(p, af)
                return Result(name: name, passed: false, detail: "replayed crossing frame accepted")
            } catch { /* expected */ }
            // Convergence: subsequent round trips both directions must all succeed.
            for round in 0..<3 {
                let bm = Data("conv-b-\(round)".utf8)
                guard try aOpen(p, bSeal(p, bm)).plaintext == bm else {
                    return Result(name: name, passed: false, detail: "post-crossing B→A failed round \(round)")
                }
                let am = Data("conv-a-\(round)".utf8)
                guard try bOpen(p, aSeal(p, am)).plaintext == am else {
                    return Result(name: name, passed: false, detail: "post-crossing A→B failed round \(round)")
                }
            }
            return Result(name: name, passed: true, detail: "smaller-HSig side adopts deterministically + converges")
        } catch { return Result(name: name, passed: false, detail: "\(error)") }
    }

    /// Crossing where the yielding side already SENT a burst (ns>0) before the
    /// crossing frame arrives. The window guard keys on dhTurns/nr (not ns), so it
    /// still adopts — and the WHOLE abandoned burst is dropped, not a single
    /// message. Pins that the documented break is "one sending chain", and that
    /// both directions still converge afterwards.
    private static func testV2DRCrossingAfterBurst() -> Result {
        let name = "V2 DR crossing after a pre-crossing burst"
        V2RatchetPayload._installInMemoryStoreForTesting()
        defer { V2RatchetPayload._restoreKeychainStoreForTesting() }
        do {
            let p = try makeDRPair()
            // The canonical responder (smaller HSig pk) is the side that yields.
            // Have IT send a 3-message burst as initiator before the crossing frame.
            let aliceYields = p.aliceHsigPk.lexicographicallyPrecedes(p.bobHsigPk)
            let peerFirst = Data("peer-first".utf8)
            let adopted: V2RatchetOpenedPayload?
            if aliceYields {
                _ = try aSeal(p, Data("burst-0".utf8))
                _ = try aSeal(p, Data("burst-1".utf8))
                _ = try aSeal(p, Data("burst-2".utf8))     // ns = 3, abandoned on adopt
                adopted = try? aOpen(p, bSeal(p, peerFirst))
            } else {
                _ = try bSeal(p, Data("burst-0".utf8))
                _ = try bSeal(p, Data("burst-1".utf8))
                _ = try bSeal(p, Data("burst-2".utf8))
                adopted = try? bOpen(p, aSeal(p, peerFirst))
            }
            guard adopted?.plaintext == peerFirst else {
                return Result(name: name, passed: false, detail: "smaller-HSig side failed to adopt after a burst")
            }
            // Both directions converge despite the dropped burst.
            for round in 0..<3 {
                let bm = Data("cb-b-\(round)".utf8)
                guard try aOpen(p, bSeal(p, bm)).plaintext == bm else {
                    return Result(name: name, passed: false, detail: "post-burst B→A failed round \(round)")
                }
                let am = Data("cb-a-\(round)".utf8)
                guard try bOpen(p, aSeal(p, am)).plaintext == am else {
                    return Result(name: name, passed: false, detail: "post-burst A→B failed round \(round)")
                }
            }
            return Result(name: name, passed: true, detail: "adopts despite ns>0; whole burst dropped; converges")
        } catch { return Result(name: name, passed: false, detail: "\(error)") }
    }

    /// Crossing recovery (closes the gap pinned above): the yielding side's
    /// burst frames are BOOT frames and get recorded; its adoption is flagged
    /// (and only there — the keeping side never sees the flag); the recorded
    /// ids come back exactly once; the keeper never opens an abandoned frame
    /// (so a resend can never be a duplicate); and the same messages sealed
    /// again in the adopted session arrive, in order, with the chat converging.
    private static func testV2CrossingRecoveryResendsBurst() -> Result {
        let name = "V2 crossing recovery: abandoned burst resent, never duplicated"
        V2RatchetPayload._installInMemoryStoreForTesting()
        defer { V2RatchetPayload._restoreKeychainStoreForTesting() }
        do {
            let p = try makeDRPair()
            let aliceYields = p.aliceHsigPk.lexicographicallyPrecedes(p.bobHsigPk)
            // Yielder / keeper as closures, so one body covers both orders.
            let ySeal: (Data) throws -> Data = { aliceYields ? try aSeal(p, $0) : try bSeal(p, $0) }
            let yOpen: (Data) throws -> V2RatchetOpenedPayload = { aliceYields ? try aOpen(p, $0) : try bOpen(p, $0) }
            let kSeal: (Data) throws -> Data = { aliceYields ? try bSeal(p, $0) : try aSeal(p, $0) }
            let kOpen: (Data) throws -> V2RatchetOpenedPayload = { aliceYields ? try bOpen(p, $0) : try aOpen(p, $0) }
            // The yielder's peer id is the keeper's rid (records are per peer).
            let keeperId = (aliceYields ? p.bob : p.alice).recipientId.description

            let burst = (0..<3).map { Data("burst-\($0)".utf8) }
            let ids = (0..<3).map { _ in UUID().uuidString }
            var abandoned: [Data] = []
            for (m, id) in zip(burst, ids) {
                let f = try ySeal(m)
                guard V2RatchetPayload.isBootFrame(f) else {
                    return Result(name: name, passed: false, detail: "first-chain frame not marked BOOT")
                }
                V2RatchetPayload.recordFirstChainSend(peerId: keeperId, messageID: id)
                abandoned.append(f)
            }
            let peerFirst = Data("peer-first".utf8)
            let keeperFrame = try kSeal(peerFirst)
            let adopted = try yOpen(keeperFrame)
            guard adopted.plaintext == peerFirst, adopted.adoptedCrossing else {
                return Result(name: name, passed: false, detail: "adoption not flagged on the yielding side")
            }
            // Keeper: every abandoned frame is refused → a resend never duplicates.
            for f in abandoned where (try? kOpen(f)) != nil {
                return Result(name: name, passed: false, detail: "keeper opened an abandoned frame")
            }
            guard V2RatchetPayload.takeFirstChainSends(peerId: keeperId) == ids,
                  V2RatchetPayload.takeFirstChainSends(peerId: keeperId).isEmpty else {
                return Result(name: name, passed: false, detail: "recorded ids not handed out exactly once")
            }
            // Resend in the adopted session: not BOOT, all arrive in order.
            for m in burst {
                let f = try ySeal(m)
                guard !V2RatchetPayload.isBootFrame(f) else {
                    return Result(name: name, passed: false, detail: "resend still in a first chain")
                }
                let o = try kOpen(f)
                guard o.plaintext == m, !o.adoptedCrossing else {
                    return Result(name: name, passed: false, detail: "resent message lost or flagged")
                }
            }
            for round in 0..<2 {
                let km = Data("k-\(round)".utf8), ym = Data("y-\(round)".utf8)
                guard try yOpen(kSeal(km)).plaintext == km, try kOpen(ySeal(ym)).plaintext == ym else {
                    return Result(name: name, passed: false, detail: "no convergence after resend")
                }
            }
            return Result(name: name, passed: true, detail: "3 BOOT frames recorded; adoption flagged once; keeper refused all 3; resent 3/3 in order")
        } catch { return Result(name: name, passed: false, detail: "\(error)") }
    }

    /// Every DH turn carries a FRESH one-time ML-KEM key and ciphertext: across
    /// 40 round trips (the bootstrap chain plus 79 DH turns) no KEM public key or ciphertext ever repeats
    /// between chains, while all frames of one chain carry the same pair (so the
    /// turn works from whichever frame of the chain arrives first).
    private static func testV2DRFreshKemEveryTurn() -> Result {
        let name = "V2 DR fresh ML-KEM on every DH turn"
        V2RatchetPayload._installInMemoryStoreForTesting()
        defer { V2RatchetPayload._restoreKeychainStoreForTesting() }
        let pkOff = V2RatchetPayload._kemPkOffsetForTesting
        let ctOff = V2RatchetPayload._kemCtOffsetForTesting
        func kemPk(_ f: Data) -> Data { Data(f[(f.startIndex + pkOff)..<(f.startIndex + pkOff + LadonV2.kyber768PkLen)]) }
        func kemCt(_ f: Data) -> Data { Data(f[(f.startIndex + ctOff)..<(f.startIndex + ctOff + LadonV2.kyber768CtLen)]) }
        do {
            let p = try makeDRPair()
            var seenPk = Set<Data>()
            var seenCt = Set<Data>()
            for round in 0..<40 {
                // Two frames per chain: both must carry the chain's KEM pair.
                let a0 = try aSeal(p, Data("pq-a-\(round)-0".utf8))
                let a1 = try aSeal(p, Data("pq-a-\(round)-1".utf8))
                guard kemPk(a0) == kemPk(a1), kemCt(a0) == kemCt(a1) else {
                    return Result(name: name, passed: false, detail: "A chain \(round): KEM fields differ within one chain")
                }
                guard try bOpen(p, a0).plaintext == Data("pq-a-\(round)-0".utf8),
                      try bOpen(p, a1).plaintext == Data("pq-a-\(round)-1".utf8) else {
                    return Result(name: name, passed: false, detail: "A→B failed at round \(round)")
                }
                let b0 = try bSeal(p, Data("pq-b-\(round)".utf8))
                guard try aOpen(p, b0).plaintext == Data("pq-b-\(round)".utf8) else {
                    return Result(name: name, passed: false, detail: "B→A failed at round \(round)")
                }
                for f in [a0, b0] {
                    guard seenPk.insert(kemPk(f)).inserted else {
                        return Result(name: name, passed: false, detail: "KEM public key repeated at round \(round)")
                    }
                    guard seenCt.insert(kemCt(f)).inserted else {
                        return Result(name: name, passed: false, detail: "KEM ciphertext repeated at round \(round)")
                    }
                }
            }
            return Result(name: name, passed: true, detail: "40 round trips: \(seenPk.count) distinct KEM keys, \(seenCt.count) distinct ciphertexts; stable within each chain")
        } catch { return Result(name: name, passed: false, detail: "\(error)") }
    }

    /// One-time KEM keys are used once, then gone from the persisted state:
    /// the peer key is dropped by the send turn that encapsulates to it, our own
    /// secret is dropped by the receive turn that decapsulates with it.
    private static func testV2DRKemKeysUsedOnce() -> Result {
        let name = "V2 DR one-time KEM keys deleted after use"
        V2RatchetPayload._installInMemoryStoreForTesting()
        defer { V2RatchetPayload._restoreKeychainStoreForTesting() }
        typealias Slots = V2RatchetPayload.KemSlotsForTesting
        do {
            let p = try makeDRPair()
            let aliceSession = p.bob.recipientId.description   // Alice's state for Bob
            let bobSession = p.alice.recipientId.description   // Bob's state for Alice
            func slots(_ id: String) throws -> Slots? { try V2RatchetPayload._kemSlotsForTesting(peerId: id) }

            // Alice bootstraps: holds her announced key + the bootstrap ciphertext.
            let a0 = try aSeal(p, Data("a0".utf8))
            guard try slots(aliceSession) == Slots(hasOwnSecret: true, hasOwnPublic: true, hasOutgoingCt: true, hasPeerPublic: false) else {
                return Result(name: name, passed: false, detail: "after A bootstrap: \(String(describing: try slots(aliceSession)))")
            }
            // Bob receives: holds only Alice's announced key, nothing of his own yet.
            _ = try bOpen(p, a0)
            guard try slots(bobSession) == Slots(hasOwnSecret: false, hasOwnPublic: false, hasOutgoingCt: false, hasPeerPublic: true) else {
                return Result(name: name, passed: false, detail: "after B receive: \(String(describing: try slots(bobSession)))")
            }
            // Bob's send turn consumes Alice's key and announces his own.
            let b0 = try bSeal(p, Data("b0".utf8))
            guard try slots(bobSession) == Slots(hasOwnSecret: true, hasOwnPublic: true, hasOutgoingCt: true, hasPeerPublic: false) else {
                return Result(name: name, passed: false, detail: "after B send turn: \(String(describing: try slots(bobSession)))")
            }
            // Alice's receive turn uses her secret once and drops it.
            _ = try aOpen(p, b0)
            guard try slots(aliceSession) == Slots(hasOwnSecret: false, hasOwnPublic: false, hasOutgoingCt: false, hasPeerPublic: true) else {
                return Result(name: name, passed: false, detail: "after A receive turn: \(String(describing: try slots(aliceSession)))")
            }
            // A second frame of the same Bob chain still opens (no new turn needed)…
            let b1 = try bSeal(p, Data("b1".utf8))
            guard try aOpen(p, b1).plaintext == Data("b1".utf8) else {
                return Result(name: name, passed: false, detail: "second frame of the chain failed")
            }
            // …and does not bring any KEM secret back.
            guard try slots(aliceSession)?.hasOwnSecret == false else {
                return Result(name: name, passed: false, detail: "own KEM secret reappeared")
            }
            return Result(name: name, passed: true, detail: "peer key dropped on encaps, own secret dropped on decaps; chain continues")
        } catch { return Result(name: name, passed: false, detail: "\(error)") }
    }

    /// Under frame v0x04: tamper (ciphertext, flags, KEM key, KEM ciphertext,
    /// version) and replay must all fail closed — the whole header is AEAD AAD,
    /// and a tampered KEM ciphertext also yields a wrong turn secret.
    private static func testV2DRTamperReplayFailClosed() -> Result {
        let name = "V2 DR tamper/replay fail-closed (0x04)"
        V2RatchetPayload._installInMemoryStoreForTesting()
        defer { V2RatchetPayload._restoreKeychainStoreForTesting() }
        do {
            let p = try makeDRPair()
            _ = try bOpen(p, aSeal(p, Data("seed".utf8)))
            _ = try aOpen(p, bSeal(p, Data("reply".utf8)))     // establish a DH chain
            let frame = try aSeal(p, Data("victim".utf8))

            // Flip a ciphertext byte.
            var ct = Data(frame); ct[ct.count - 1] ^= 0x01
            // Flip the flags byte (offset 5): 0x03 with an all-zero prekey id is
            // refused by parse (the header is additionally AEAD AAD).
            var fl = Data(frame); fl[fl.startIndex + 5] ^= 0x02
            // Flip a byte of the announced KEM key and of the KEM ciphertext.
            var kp = Data(frame); kp[kp.startIndex + V2RatchetPayload._kemPkOffsetForTesting + 7] ^= 0x01
            var kc = Data(frame); kc[kc.startIndex + V2RatchetPayload._kemCtOffsetForTesting + 7] ^= 0x01
            // Downgrade the version to the previous 0x03 and the legacy 0x02.
            var v3 = Data(frame); v3[v3.startIndex + 4] = 0x03
            var v2 = Data(frame); v2[v2.startIndex + 4] = 0x02

            for (label, bad) in [("ciphertext", ct), ("flag", fl), ("kemPk", kp), ("kemCt", kc), ("version 0x03", v3), ("version 0x02", v2)] {
                do { _ = try bOpen(p, bad); return Result(name: name, passed: false, detail: "\(label) tamper accepted") }
                catch { /* expected */ }
            }
            // The genuine frame still opens (tamper attempts did not corrupt state).
            guard try bOpen(p, frame).plaintext == Data("victim".utf8) else {
                return Result(name: name, passed: false, detail: "genuine frame failed after tamper attempts")
            }
            // Replay of the now-consumed genuine frame must fail closed.
            do { _ = try bOpen(p, frame); return Result(name: name, passed: false, detail: "replay accepted") }
            catch { /* expected */ }
            return Result(name: name, passed: true, detail: "ciphertext/flag/kemPk/kemCt/version tamper + replay all rejected")
        } catch { return Result(name: name, passed: false, detail: "\(error)") }
    }

    // MARK: - One-time prekey bootstrap (P8-RCV2-IOS-08)

    private static func header(_ f: Data, _ offset: Int, _ len: Int) -> Data {
        Data(f[(f.startIndex + offset)..<(f.startIndex + offset + len)])
    }
    private static func flipped(_ f: Data, at offset: Int) -> Data {
        var x = Data(f); x[x.startIndex + offset] ^= 0x01; return x
    }
    private static func ownPrekeyValid(_ pk: OneTimePrekeyPublicV2) throws -> Bool {
        try PrekeyStoreV2.loadOwnValid(id: pk.id, now: Date()) != nil
    }

    /// The first chain is marked BOOT with the prekey id; the initiator forgets
    /// the contact's prekey after using it, the responder deletes its own after
    /// the first authenticated frame, and the rest of the chain needs neither.
    private static func testV2BootPrekeyConsumed() -> Result {
        let name = "V2 boot: prekey used once, then deleted on both sides"
        V2RatchetPayload._installInMemoryStoreForTesting()
        defer { V2RatchetPayload._restoreKeychainStoreForTesting() }
        do {
            let p = try makeDRPair()
            let a0 = try aSeal(p, Data("a0".utf8))
            let a1 = try aSeal(p, Data("a1".utf8))
            let idOff = V2RatchetPayload._otpkIdOffsetForTesting
            guard a0[a0.startIndex + 5] == 0x03, header(a0, idOff, PrekeyStoreV2.idLen) == p.bobPrekey.id,
                  header(a1, idOff, PrekeyStoreV2.idLen) == p.bobPrekey.id else {
                return Result(name: name, passed: false, detail: "first-chain frames not BOOT-marked with the prekey id")
            }
            guard try PrekeyStoreV2.loadPeer(forPeer: p.bob.recipientId.description) == nil else {
                return Result(name: name, passed: false, detail: "initiator kept the used peer prekey")
            }
            guard try ownPrekeyValid(p.bobPrekey) else {
                return Result(name: name, passed: false, detail: "responder prekey gone before any frame arrived")
            }
            guard try bOpen(p, a0).plaintext == Data("a0".utf8) else {
                return Result(name: name, passed: false, detail: "bootstrap frame did not open")
            }
            guard try !ownPrekeyValid(p.bobPrekey) else {
                return Result(name: name, passed: false, detail: "responder prekey still usable after bootstrap")
            }
            guard try bOpen(p, a1).plaintext == Data("a1".utf8) else {
                return Result(name: name, passed: false, detail: "second first-chain frame failed")
            }
            _ = try aOpen(p, bSeal(p, Data("b0".utf8)))
            let a2 = try aSeal(p, Data("a2".utf8))
            guard a2[a2.startIndex + 5] == 0x01, header(a2, idOff, PrekeyStoreV2.idLen) == Data(count: PrekeyStoreV2.idLen) else {
                return Result(name: name, passed: false, detail: "BOOT marking not cleared after the first DH turn")
            }
            guard try bOpen(p, a2).plaintext == Data("a2".utf8) else {
                return Result(name: name, passed: false, detail: "post-boot chain failed")
            }
            return Result(name: name, passed: true, detail: "BOOT chain marked; both prekey copies gone after use; session continues")
        } catch { return Result(name: name, passed: false, detail: "\(error)") }
    }

    /// A second session against an already used prekey is refused, even from a
    /// different, validly signed identity that got a copy of the same code.
    private static func testV2BootSecondUseRejected() -> Result {
        let name = "V2 boot: second use of a prekey rejected"
        V2RatchetPayload._installInMemoryStoreForTesting()
        defer { V2RatchetPayload._restoreKeychainStoreForTesting() }
        do {
            let p = try makeDRPair()
            let carol = try makeTestIdentity()
            _ = try bOpen(p, aSeal(p, Data("a0".utf8)))             // Bob's prekey is now spent.
            // Carol runs in this same process: drop Alice's session with Bob so
            // Carol's seal really bootstraps on its own, then hand her a copy.
            V2RatchetPayload._deleteStateForTesting(peerId: p.bob.recipientId.description)
            try PrekeyStoreV2.storePeer(p.bobPrekey, forPeer: p.bob.recipientId.description)
            let c0 = try V2RatchetPayload.seal(plaintext: Data("c0".utf8), peer: p.bobPeer, recipientHkemPk: p.bobHkemPk, localIdentity: carol)
            guard c0[c0.startIndex + 5] == 0x03,
                  header(c0, V2RatchetPayload._otpkIdOffsetForTesting, PrekeyStoreV2.idLen) == p.bobPrekey.id else {
                return Result(name: name, passed: false, detail: "Carol's frame is not a bootstrap against Bob's prekey")
            }
            let carolHsigPk = carol.senderHsigKp.publicKeyBytes()
            do {
                _ = try V2RatchetPayload.open(frame: c0, senderHsigPk: carolHsigPk, localIdentity: p.bob)
                return Result(name: name, passed: false, detail: "second use of a spent prekey was accepted")
            } catch V2RatchetError.prekeyUnavailable { /* expected */ }
            guard try V2RatchetPayload._rawStateForTesting(peerId: carol.recipientId.description) == nil else {
                return Result(name: name, passed: false, detail: "a session was stored for the rejected sender")
            }
            return Result(name: name, passed: true, detail: "spent prekey refused for a second identity; nothing stored")
        } catch { return Result(name: name, passed: false, detail: "\(error)") }
    }

    /// No prekey of the contact → no first message. Unknown or expired own
    /// prekey → frame refused, nothing stored, an expired prekey is removed.
    private static func testV2BootMissingUnknownExpired() -> Result {
        let name = "V2 boot: missing / unknown / expired prekey fail closed"
        V2RatchetPayload._installInMemoryStoreForTesting()
        defer { V2RatchetPayload._restoreKeychainStoreForTesting() }
        do {
            // (1) Initiator without a prekey of the contact.
            let alice = try makeTestIdentity()
            let bob = try makeTestIdentity()
            let bobPeer = PeerHandleV2(recipientId: bob.recipientId, recipientHsigPk: bob.senderHsigKp.publicKeyBytes())
            let bobHkemPk = bob.recipientHkemKp.publicKeyBytes()
            let aliceHsigPk = alice.senderHsigKp.publicKeyBytes()
            do {
                _ = try V2RatchetPayload.seal(plaintext: Data("x".utf8), peer: bobPeer, recipientHkemPk: bobHkemPk, localIdentity: alice)
                return Result(name: name, passed: false, detail: "sent without a peer prekey")
            } catch V2RatchetError.noPeerPrekey { /* expected */ }
            guard try V2RatchetPayload._rawStateForTesting(peerId: bob.recipientId.description) == nil else {
                return Result(name: name, passed: false, detail: "state created without a peer prekey")
            }

            // (2) Unknown prekey: issued, then gone before the frame arrives.
            let gone = try handPrekey(from: bob)
            try PrekeyStoreV2.consumeOwn(id: gone.id)
            let f = try V2RatchetPayload.seal(plaintext: Data("y".utf8), peer: bobPeer, recipientHkemPk: bobHkemPk, localIdentity: alice)
            do {
                _ = try V2RatchetPayload.open(frame: f, senderHsigPk: aliceHsigPk, localIdentity: bob)
                return Result(name: name, passed: false, detail: "unknown prekey accepted")
            } catch V2RatchetError.prekeyUnavailable { /* expected */ }
            guard try V2RatchetPayload._rawStateForTesting(peerId: alice.recipientId.description) == nil else {
                return Result(name: name, passed: false, detail: "state stored for an unknown prekey")
            }

            // (3) Expired prekey: refused and removed.
            let carol = try makeTestIdentity()
            let dave = try makeTestIdentity()
            let davePeer = PeerHandleV2(recipientId: dave.recipientId, recipientHsigPk: dave.senderHsigKp.publicKeyBytes())
            try handPrekey(from: dave, validFor: -1)
            let before = try PrekeyStoreV2.ownCount()
            let g = try V2RatchetPayload.seal(plaintext: Data("z".utf8), peer: davePeer, recipientHkemPk: dave.recipientHkemKp.publicKeyBytes(), localIdentity: carol)
            do {
                _ = try V2RatchetPayload.open(frame: g, senderHsigPk: carol.senderHsigKp.publicKeyBytes(), localIdentity: dave)
                return Result(name: name, passed: false, detail: "expired prekey accepted")
            } catch V2RatchetError.prekeyUnavailable { /* expected */ }
            guard try PrekeyStoreV2.ownCount() == before - 1 else {
                return Result(name: name, passed: false, detail: "expired prekey not removed")
            }
            return Result(name: name, passed: true, detail: "no peer prekey → no send; unknown/expired → refused, nothing stored")
        } catch { return Result(name: name, passed: false, detail: "\(error)") }
    }

    /// A tampered bootstrap frame (prekey id, ciphertext, flags) is refused and
    /// does NOT burn the prekey — the genuine frame still opens afterwards.
    private static func testV2BootTamperKeepsPrekey() -> Result {
        let name = "V2 boot: tampered bootstrap frame keeps the prekey"
        V2RatchetPayload._installInMemoryStoreForTesting()
        defer { V2RatchetPayload._restoreKeychainStoreForTesting() }
        do {
            let p = try makeDRPair()
            let a0 = try aSeal(p, Data("genuine".utf8))
            var flags01 = Data(a0); flags01[flags01.startIndex + 5] = 0x01
            let cases: [(String, Data)] = [
                ("otpkId", flipped(a0, at: V2RatchetPayload._otpkIdOffsetForTesting + 3)),
                ("kemCt", flipped(a0, at: V2RatchetPayload._kemCtOffsetForTesting + 3)),
                ("ciphertext", flipped(a0, at: a0.count - 1)),
                ("flags", flags01),
            ]
            for (label, bad) in cases {
                do { _ = try bOpen(p, bad); return Result(name: name, passed: false, detail: "\(label) tamper accepted") }
                catch { /* expected */ }
                guard try ownPrekeyValid(p.bobPrekey),
                      try V2RatchetPayload._rawStateForTesting(peerId: p.alice.recipientId.description) == nil else {
                    return Result(name: name, passed: false, detail: "\(label) tamper burned the prekey or stored state")
                }
            }
            guard try bOpen(p, a0).plaintext == Data("genuine".utf8), try !ownPrekeyValid(p.bobPrekey) else {
                return Result(name: name, passed: false, detail: "genuine frame failed after tamper attempts")
            }
            return Result(name: name, passed: true, detail: "otpkId/kemCt/ciphertext/flags tamper refused; prekey intact until the genuine frame")
        } catch { return Result(name: name, passed: false, detail: "\(error)") }
    }

    /// The two "no unused KEM key" guards fail closed and leave the stored
    /// session byte-for-byte unchanged. No legitimate sequence reaches them, so
    /// the state is broken on purpose through a DEBUG seam.
    private static func testV2DRGuardsFailClosed() -> Result {
        let name = "V2 DR guards: missing KEM key fails closed, state unchanged"
        V2RatchetPayload._installInMemoryStoreForTesting()
        defer { V2RatchetPayload._restoreKeychainStoreForTesting() }
        do {
            // Send side: Bob must reply (a DH turn) but the peer KEM key is gone.
            let p = try makeDRPair()
            _ = try bOpen(p, aSeal(p, Data("a0".utf8)))
            let bobSession = p.alice.recipientId.description
            try V2RatchetPayload._dropKemSlotsForTesting(peerId: bobSession, ownSecret: false, peerPublic: true)
            let bobBefore = try V2RatchetPayload._rawStateForTesting(peerId: bobSession)
            do {
                _ = try bSeal(p, Data("b0".utf8))
                return Result(name: name, passed: false, detail: "send turn without a peer KEM key succeeded")
            } catch V2RatchetError.crypto(let m) where m.hasPrefix("no unused peer KEM key") { /* expected */ }
            guard try V2RatchetPayload._rawStateForTesting(peerId: bobSession) == bobBefore else {
                return Result(name: name, passed: false, detail: "send guard changed the stored session")
            }

            // Receive side: Alice must run a turn but her own KEM secret is gone.
            let q = try makeDRPair()
            _ = try bOpen(q, aSeal(q, Data("a0".utf8)))
            let b0 = try bSeal(q, Data("b0".utf8))
            let aliceSession = q.bob.recipientId.description
            try V2RatchetPayload._dropKemSlotsForTesting(peerId: aliceSession, ownSecret: true, peerPublic: false)
            let aliceBefore = try V2RatchetPayload._rawStateForTesting(peerId: aliceSession)
            do {
                _ = try aOpen(q, b0)
                return Result(name: name, passed: false, detail: "receive turn without an own KEM secret succeeded")
            } catch V2RatchetError.crypto(let m) where m.hasPrefix("no unused own KEM key") { /* expected */ }
            guard try V2RatchetPayload._rawStateForTesting(peerId: aliceSession) == aliceBefore else {
                return Result(name: name, passed: false, detail: "receive guard changed the stored session")
            }
            return Result(name: name, passed: true, detail: "both guards throw; stored sessions byte-identical")
        } catch { return Result(name: name, passed: false, detail: "\(error)") }
    }

    /// Inside the crossing window a tampered crossing frame is refused without
    /// touching the adopter's session or burning its prekey; the genuine frame
    /// is then adopted and burns it.
    private static func testV2DRCrossingTamperFailClosed() -> Result {
        let name = "V2 DR crossing window: tamper fails closed"
        V2RatchetPayload._installInMemoryStoreForTesting()
        defer { V2RatchetPayload._restoreKeychainStoreForTesting() }
        do {
            let p = try makeDRPair()
            let af = try aSeal(p, Data("a-first".utf8))
            let bf = try bSeal(p, Data("b-first".utf8))
            let aliceAdopts = p.aliceHsigPk.lexicographicallyPrecedes(p.bobHsigPk)
            // The adopter receives the other side's first frame, built against the adopter's prekey.
            let incoming = aliceAdopts ? bf : af
            let adopterPrekey = aliceAdopts ? p.alicePrekey : p.bobPrekey
            let adopterSession = aliceAdopts ? p.bob.recipientId.description : p.alice.recipientId.description
            func adopterOpen(_ f: Data) throws -> V2RatchetOpenedPayload { aliceAdopts ? try aOpen(p, f) : try bOpen(p, f) }

            let before = try V2RatchetPayload._rawStateForTesting(peerId: adopterSession)
            do {
                _ = try adopterOpen(flipped(incoming, at: incoming.count - 1))
                return Result(name: name, passed: false, detail: "tampered crossing frame accepted")
            } catch { /* expected */ }
            guard try V2RatchetPayload._rawStateForTesting(peerId: adopterSession) == before,
                  try ownPrekeyValid(adopterPrekey) else {
                return Result(name: name, passed: false, detail: "tamper changed the session or burned the prekey")
            }
            let expected = aliceAdopts ? Data("b-first".utf8) : Data("a-first".utf8)
            guard try adopterOpen(incoming).plaintext == expected, try !ownPrekeyValid(adopterPrekey) else {
                return Result(name: name, passed: false, detail: "genuine crossing frame not adopted or prekey kept")
            }
            return Result(name: name, passed: true, detail: "tampered crossing refused, session + prekey intact; genuine adopted, prekey burned")
        } catch { return Result(name: name, passed: false, detail: "\(error)") }
    }

    /// The bootstrap root depends on every secret and every transcript field.
    private static func testV2BootRootKDF() -> Result {
        let name = "V2 boot root KDF (3 secrets + transcript-bound)"
        func d(_ b: UInt8, _ n: Int) -> Data { Data(repeating: b, count: n) }
        let pk = OneTimePrekeyPublicV2(id: d(0x01, PrekeyStoreV2.idLen), seq: 7, xPk: d(0x02, 32), kyPk: d(0x03, LadonV2.kyber768PkLen))
        let f: [String: Data] = [
            "dh1": d(0x11, 32), "dh2": d(0x12, 32), "kem": d(0x13, 32),
            "hsigI": d(0x21, LadonV2.hsigPkLen), "hsigR": d(0x22, LadonV2.hsigPkLen),
            "ek": d(0x23, 32), "ik": d(0x24, LadonV2.hkemPkLen),
            "ct": d(0x25, LadonV2.kyber768CtLen), "kemPk": d(0x26, LadonV2.kyber768PkLen),
        ]
        func root(_ f: [String: Data], _ pk: OneTimePrekeyPublicV2) -> Data {
            V2RatchetPayload._bootRootForTesting(dh1: f["dh1"]!, dh2: f["dh2"]!, kemSs: f["kem"]!,
                                                 initiatorHsigPk: f["hsigI"]!, responderHsigPk: f["hsigR"]!,
                                                 initiatorEphemeralPk: f["ek"]!, responderIdentityHkemPk: f["ik"]!,
                                                 prekey: pk, kemCt: f["ct"]!, initiatorKemPk: f["kemPk"]!)
        }
        func flip(_ x: Data) -> Data { var y = Data(x); y[y.startIndex] ^= 0x01; return y }
        let base = root(f, pk)
        var problems: [String] = []
        if base.count != 32 { problems.append("root not 32 B") }
        if root(f, pk) != base { problems.append("not deterministic") }
        for key in f.keys.sorted() {
            var g = f; g[key] = flip(f[key]!)
            if root(g, pk) == base { problems.append("\(key) not bound") }
        }
        for (label, q) in [("otpkId", OneTimePrekeyPublicV2(id: flip(pk.id), seq: pk.seq, xPk: pk.xPk, kyPk: pk.kyPk)),
                           ("otpkSeq", OneTimePrekeyPublicV2(id: pk.id, seq: pk.seq + 1, xPk: pk.xPk, kyPk: pk.kyPk)),
                           ("otpkX", OneTimePrekeyPublicV2(id: pk.id, seq: pk.seq, xPk: flip(pk.xPk), kyPk: pk.kyPk)),
                           ("otpkKy", OneTimePrekeyPublicV2(id: pk.id, seq: pk.seq, xPk: pk.xPk, kyPk: flip(pk.kyPk)))] where root(f, q) == base {
            problems.append("\(label) not bound")
        }
        return Result(name: name, passed: problems.isEmpty,
                      detail: problems.isEmpty ? "deterministic; all 3 secrets + 10 transcript fields change the root" : problems.joined(separator: "; "))
    }

    /// Pointing a bootstrap frame at ANOTHER valid prekey of the responder is
    /// refused by the key derivation itself (not just by an unknown id), and
    /// burns neither prekey.
    private static func testV2BootRetargetedIdRejected() -> Result {
        let name = "V2 boot: frame retargeted to another valid prekey rejected"
        V2RatchetPayload._installInMemoryStoreForTesting()
        defer { V2RatchetPayload._restoreKeychainStoreForTesting() }
        do {
            let p = try makeDRPair()
            let a0 = try aSeal(p, Data("genuine".utf8))
            // A second valid prekey of Bob's (the holder slot does not matter here).
            let other = try PrekeyStoreV2.generateOwn(expiresAt: Date().addingTimeInterval(600))
            var bad = Data(a0)
            bad.replaceSubrange((bad.startIndex + V2RatchetPayload._otpkIdOffsetForTesting)..<(bad.startIndex + V2RatchetPayload._otpkIdOffsetForTesting + PrekeyStoreV2.idLen), with: other.id)
            do {
                _ = try bOpen(p, bad)
                return Result(name: name, passed: false, detail: "retargeted frame accepted")
            } catch V2RatchetError.crypto { /* expected: wrong root → AEAD fails */ }
            guard try ownPrekeyValid(other), try ownPrekeyValid(p.bobPrekey) else {
                return Result(name: name, passed: false, detail: "a prekey was burned by the retargeted frame")
            }
            guard try bOpen(p, a0).plaintext == Data("genuine".utf8), try !ownPrekeyValid(p.bobPrekey), try ownPrekeyValid(other) else {
                return Result(name: name, passed: false, detail: "genuine frame did not burn exactly its own prekey")
            }
            return Result(name: name, passed: true, detail: "retarget refused by the KDF (AEAD), no prekey burned; genuine burns only its own")
        } catch { return Result(name: name, passed: false, detail: "\(error)") }
    }

    /// Recovery when the first message goes wrong: the initiator starts over
    /// against a fresh code; the responder adopts a restart only against a
    /// prekey issued later than its current one, burns an older one.
    private static func testV2BootRestart() -> Result {
        let name = "V2 boot: restart with a fresh code (lost / superseded first message)"
        V2RatchetPayload._installInMemoryStoreForTesting()
        defer { V2RatchetPayload._restoreKeychainStoreForTesting() }
        func converge(_ p: DRPair) throws -> Bool {
            for r in 0..<2 {
                let bm = Data("rb\(r)".utf8), am = Data("ra\(r)".utf8)
                guard try aOpen(p, bSeal(p, bm)).plaintext == bm, try bOpen(p, aSeal(p, am)).plaintext == am else { return false }
            }
            return true
        }
        do {
            // (a) First message lost: never delivered. Fresh code → restart → works.
            let p = try makeDRPair()
            _ = try aSeal(p, Data("lost".utf8))
            try handPrekey(from: p.bob)
            let a = try aSeal(p, Data("again".utf8))
            guard try bOpen(p, a).plaintext == Data("again".utf8), try converge(p) else {
                return Result(name: name, passed: false, detail: "(a) restart after a lost first message failed")
            }

            // (b) Bob holds an unconfirmed session from attempt 1; attempt 2 uses a
            //     newer code → Bob adopts it and the chat converges.
            let q = try makeDRPair()
            _ = try bOpen(q, aSeal(q, Data("attempt1".utf8)))
            let newer = try handPrekey(from: q.bob)
            let a2 = try aSeal(q, Data("attempt2".utf8))
            guard try bOpen(q, a2).plaintext == Data("attempt2".utf8), try !ownPrekeyValid(newer), try converge(q) else {
                return Result(name: name, passed: false, detail: "(b) newer restart not adopted")
            }

            // (c) Bob bootstrapped from attempt 2 first; a late attempt-1 frame
            //     (older, still unused code) is refused and its code burned.
            let r = try makeDRPair()
            let older = r.bobPrekey
            let late = try aSeal(r, Data("attempt1-late".utf8))
            try handPrekey(from: r.bob)
            let fresh = try aSeal(r, Data("attempt2".utf8))
            guard try bOpen(r, fresh).plaintext == Data("attempt2".utf8) else {
                return Result(name: name, passed: false, detail: "(c) newer attempt failed")
            }
            do {
                _ = try bOpen(r, late)
                return Result(name: name, passed: false, detail: "(c) older attempt displaced the newer session")
            } catch { /* expected */ }
            guard try !ownPrekeyValid(older), try converge(r) else {
                return Result(name: name, passed: false, detail: "(c) older code not burned or session broken")
            }

            // (d) Confirmed session + a fresh code: no restart, session kept.
            let t = try makeDRPair()
            _ = try bOpen(t, aSeal(t, Data("t0".utf8)))
            _ = try aOpen(t, bSeal(t, Data("t-reply".utf8)))          // Alice is confirmed now.
            let spare = try handPrekey(from: t.bob)
            let t1 = try aSeal(t, Data("t1".utf8))
            guard t1[t1.startIndex + 5] == 0x01, try bOpen(t, t1).plaintext == Data("t1".utf8),
                  try PrekeyStoreV2.loadPeer(forPeer: t.bob.recipientId.description) == spare else {
                return Result(name: name, passed: false, detail: "(d) confirmed session restarted by a fresh code")
            }

            // (e) Unanswered, but the code on file is OLDER than the one used:
            //     no restart (the responder would refuse it); the first chain goes on.
            let oldCode = try PrekeyStoreV2.generateOwn(expiresAt: Date().addingTimeInterval(600))
            let u = try makeDRPair()
            _ = try aSeal(u, Data("u0".utf8))                           // not delivered
            try PrekeyStoreV2.storePeer(oldCode, forPeer: u.bob.recipientId.description)
            let u1 = try aSeal(u, Data("u1".utf8))
            guard header(u1, V2RatchetPayload._otpkIdOffsetForTesting, PrekeyStoreV2.idLen) == u.bobPrekey.id,
                  try bOpen(u, u1).plaintext == Data("u1".utf8), try converge(u) else {
                return Result(name: name, passed: false, detail: "(e) an older code triggered a restart")
            }

            // (f) Bob already replied (reply lost), Alice restarts with a newer
            //     code: Bob's KEM turn fails the AEAD, he adopts, chat converges.
            let v = try makeDRPair()
            _ = try bOpen(v, aSeal(v, Data("v0".utf8)))
            _ = try bSeal(v, Data("v-reply-lost".utf8))                // Bob now holds his own KEM secret
            try handPrekey(from: v.bob)
            let v2 = try aSeal(v, Data("v-restart".utf8))
            guard try bOpen(v, v2).plaintext == Data("v-restart".utf8), try converge(v) else {
                return Result(name: name, passed: false, detail: "(f) restart after a lost reply not adopted")
            }

            // (g) The code on file never goes backwards.
            let w = try makeTestIdentity()
            let wOld = try PrekeyStoreV2.generateOwn(expiresAt: Date().addingTimeInterval(600))
            let wNew = try PrekeyStoreV2.generateOwn(expiresAt: Date().addingTimeInterval(600))
            let wId = w.recipientId.description
            guard try PrekeyStoreV2.storePeer(wNew, forPeer: wId), try !PrekeyStoreV2.storePeer(wOld, forPeer: wId),
                  try PrekeyStoreV2.loadPeer(forPeer: wId) == wNew else {
                return Result(name: name, passed: false, detail: "(g) an older code replaced a newer one")
            }
            return Result(name: name, passed: true, detail: "lost → restart; newer adopted; older refused + burned; confirmed kept; older code no restart; restart after lost reply; store never goes backwards")
        } catch { return Result(name: name, passed: false, detail: "\(error)") }
    }

    /// Prekey burned, then the session save fails: nothing is stored and the
    /// prekey stays burned (never usable twice); a fresh code recovers.
    private static func testV2BootSaveFailure() -> Result {
        let name = "V2 boot: save failure after burning the prekey fails closed"
        V2RatchetPayload._installInMemoryStoreForTesting()
        defer { V2RatchetPayload._restoreKeychainStoreForTesting() }
        do {
            let p = try makeDRPair()
            let a0 = try aSeal(p, Data("a0".utf8))
            V2RatchetPayload._failNextStateSaveForTesting()
            do {
                _ = try bOpen(p, a0)
                return Result(name: name, passed: false, detail: "open succeeded although the save failed")
            } catch V2RatchetError.keychain { /* expected */ }
            guard try !ownPrekeyValid(p.bobPrekey),
                  try V2RatchetPayload._rawStateForTesting(peerId: p.alice.recipientId.description) == nil else {
                return Result(name: name, passed: false, detail: "prekey still usable or partial session stored")
            }
            do {
                _ = try bOpen(p, a0)
                return Result(name: name, passed: false, detail: "burned prekey accepted on redelivery")
            } catch V2RatchetError.prekeyUnavailable { /* expected */ }
            try handPrekey(from: p.bob)
            let a1 = try aSeal(p, Data("recovered".utf8))
            guard try bOpen(p, a1).plaintext == Data("recovered".utf8) else {
                return Result(name: name, passed: false, detail: "fresh code did not recover the chat")
            }
            return Result(name: name, passed: true, detail: "burned + nothing stored; redelivery refused; fresh code recovers")
        } catch { return Result(name: name, passed: false, detail: "\(error)") }
    }

    /// Store limits and the real Keychain backend: at most `maxOwn` unused own
    /// prekeys (oldest dropped), `canSeal` reflects prekey/session presence,
    /// and the Keychain code path works (the other tests use memory).
    private static func testV2PrekeyStoreLimits() -> Result {
        let name = "V2 prekey store: cap, canSeal, real Keychain backend"
        V2RatchetPayload._installInMemoryStoreForTesting()
        defer { V2RatchetPayload._restoreKeychainStoreForTesting() }
        do {
            var issued: [OneTimePrekeyPublicV2] = []
            for _ in 0...PrekeyStoreV2.maxOwn {
                issued.append(try PrekeyStoreV2.generateOwn(expiresAt: Date().addingTimeInterval(600)))
            }
            guard try PrekeyStoreV2.ownCount() == PrekeyStoreV2.maxOwn,
                  try !ownPrekeyValid(issued[0]), try ownPrekeyValid(issued[PrekeyStoreV2.maxOwn]) else {
                return Result(name: name, passed: false, detail: "cap of \(PrekeyStoreV2.maxOwn) not enforced oldest-first")
            }
            let alice = try makeTestIdentity(), bob = try makeTestIdentity()
            let bobId = bob.recipientId.description
            guard try !V2RatchetPayload.canSeal(toPeer: bobId) else {
                return Result(name: name, passed: false, detail: "canSeal true without session or prekey")
            }
            try handPrekey(from: bob)
            guard try V2RatchetPayload.canSeal(toPeer: bobId) else {
                return Result(name: name, passed: false, detail: "canSeal false with a prekey on file")
            }
            _ = try V2RatchetPayload.seal(plaintext: Data("x".utf8), peer: PeerHandleV2(recipientId: bob.recipientId, recipientHsigPk: bob.senderHsigKp.publicKeyBytes()),
                                          recipientHkemPk: bob.recipientHkemKp.publicKeyBytes(), localIdentity: alice)
            guard try V2RatchetPayload.canSeal(toPeer: bobId) else {
                return Result(name: name, passed: false, detail: "canSeal false with a session")
            }
            if let failure = PrekeyStoreV2._keychainBackendSelfTest() {
                return Result(name: name, passed: false, detail: "Keychain backend: \(failure)")
            }
            return Result(name: name, passed: true, detail: "cap \(PrekeyStoreV2.maxOwn) oldest-first; canSeal correct; Keychain save/update/load/list/delete OK")
        } catch { return Result(name: name, passed: false, detail: "\(error)") }
    }

    #if DEBUG
    /// P8-AUDIT8-IOS-33 (audit F2): the Keychain secrets are sealed with the
    /// Secure Enclave — runs on the real chip (device only).
    private static func testSealedKeychainSecureEnclave() -> Result {
        let name = "SealedKeychainV2 (Secure Enclave, audit F2)"
        if let failure = SealedKeychainV2._selfTest() {
            return Result(name: name, passed: false, detail: failure)
        }
        return Result(name: name, passed: true,
                      detail: "stored value is ciphertext; opens via chip; tamper, account and service binding rejected; \(SealedKeychainV2.lastStoreCheckCount) store items all sealed")
    }
    #endif

    /// P8-AUDIT8-IOS-12: `purgeExpiredOwnNow` (run at V2 start and on every
    /// return to the foreground) removes expired own prekeys and keeps the
    /// valid ones — without waiting for the next code to be generated.
    private static func testV2ExpiredOwnPrekeysPurged() -> Result {
        let name = "V2 prekey store: expired own prekeys purged at start/foreground"
        V2RatchetPayload._installInMemoryStoreForTesting()
        defer { V2RatchetPayload._restoreKeychainStoreForTesting() }
        do {
            // generateOwn purges BEFORE storing, so an already-expired prekey
            // stays on file until the next purge — exactly the gap closed here.
            let valid = try PrekeyStoreV2.generateOwn(expiresAt: Date().addingTimeInterval(600))
            _ = try PrekeyStoreV2.generateOwn(expiresAt: Date().addingTimeInterval(-1))
            guard try PrekeyStoreV2.ownCount() == 2 else {
                return Result(name: name, passed: false, detail: "setup: expected 2 own prekeys")
            }
            PrekeyStoreV2.purgeExpiredOwnNow()
            guard try PrekeyStoreV2.ownCount() == 1, try ownPrekeyValid(valid) else {
                return Result(name: name, passed: false, detail: "expired prekey kept or valid one removed")
            }
            return Result(name: name, passed: true, detail: "1 expired removed, 1 valid kept")
        } catch { return Result(name: name, passed: false, detail: "\(error)") }
    }

    /// Point 1 (RAM hygiene): every secret the ratchet and the prekey store wipe
    /// is overwritten in the storage it actually lives in — never only in a
    /// copy-on-write copy while the original bytes survive elsewhere. Drives
    /// bootstrap, bursts, ping-pong, out-of-order across chains (skipped and
    /// archived keys) and a crossing, then checks the wipe audit.
    private static func testV2SecretsWipedInPlace() -> Result {
        let name = "V2 RAM hygiene: secrets wiped in their own storage"
        V2RatchetPayload._installInMemoryStoreForTesting()
        defer { V2RatchetPayload._restoreKeychainStoreForTesting() }
        SecretWipeAuditV2.reset()
        do {
            let p = try makeDRPair()
            let a0 = try aSeal(p, Data("c0-m0".utf8))
            _ = try bOpen(p, a0)
            let a0b = try aSeal(p, Data("c0-m1".utf8))                 // held back
            _ = try aOpen(p, bSeal(p, Data("rb".utf8)))
            let a1 = try aSeal(p, Data("c1-m0".utf8))                  // held back
            let a1b = try aSeal(p, Data("c1-m1".utf8))
            _ = try bOpen(p, a1b)                                       // skips c1-m0, archives chain 0
            _ = try bOpen(p, a0b)                                       // archived chain
            _ = try bOpen(p, a1)                                        // skipped key
            for r in 0..<4 {
                _ = try aOpen(p, bSeal(p, Data("pb\(r)".utf8)))
                _ = try bOpen(p, aSeal(p, Data("pa\(r)".utf8)))
            }
            let q = try makeDRPair()                                    // crossing
            let af = try aSeal(q, Data("a-first".utf8))
            let bf = try bSeal(q, Data("b-first".utf8))
            _ = try? bOpen(q, af)
            _ = try? aOpen(q, bf)
            _ = try aOpen(q, bSeal(q, Data("x".utf8)))
            _ = try bOpen(q, aSeal(q, Data("y".utf8)))
            let c = SecretWipeAuditV2.counts()
            guard c.shared == 0, c.inPlace > 0 else {
                return Result(name: name, passed: false, detail: "wipes in place \(c.inPlace), only a copy \(c.shared)")
            }
            return Result(name: name, passed: true, detail: "\(c.inPlace) secret wipes, all in their own storage")
        } catch { return Result(name: name, passed: false, detail: "\(error)") }
    }

    /// Step 4 core + A1 §5 + P8-AUDIT8-IOS-30: the signed pairing code
    /// (identity + one-time prekey + delivery key + owner signature)
    /// round-trips exactly, splits into four QR parts that fit a QR code at
    /// level M, reassembles in any order, never mixes parts of two codes,
    /// rejects tampering (any body byte, a foreign signer), old codes (v2, v3,
    /// v4), damaged input, an all-zero delivery key, expired and implausibly
    /// late hints, and refuses our own code.
    private static func testPairingCodeV4() -> Result {
        let name = "Pairing code v5: signature, format, QR parts, assembly, validation"
        V2RatchetPayload._installInMemoryStoreForTesting()
        defer { V2RatchetPayload._restoreKeychainStoreForTesting() }
        do {
            let owner = try makeTestIdentity()
            func makeCode(expiresIn: Int64, deliveryKey: Data = randomBytes(LadonV2.deliveryKeyLen)) throws -> PairingCodeV4 {
                let pk = try PrekeyStoreV2.generateOwn(expiresAt: Date().addingTimeInterval(600))
                let now = Int64(ClockSyncV2.shared.nowSec())
                return try PairingCodeV4.signed(by: owner.senderHsigKp, prekey: pk, expiresAt: UInt64(now + expiresIn),
                                                deliveryKey: deliveryKey)
            }
            // (1) Exact round-trip and length.
            let a = try makeCode(expiresIn: 600)
            let aText = PairingCodeV4.encode(a)
            guard aText.count == PairingCodeV4.textPrefix.count + (PairingCodeV4.payloadLen * 4 + 2) / 3,
                  try PairingCodeV4.parse(aText) == a, try PairingCodeV4.parse("  \(aText)\n") == a else {
                return Result(name: name, passed: false, detail: "text round-trip or length wrong (\(aText.count))")
            }
            // (2) Four QR parts, each within QR byte capacity at level M
            //     (2,331 B; renderQRCode picks M up to 2,300 B) and below the
            //     scanner's 2,700-character bound.
            let aParts = try PairingCodeV4.qrParts(ofCode: aText)
            let partBytes = aParts.map { $0.utf8.count }
            guard aParts.count == 4, partBytes.allSatisfy({ $0 <= 2_300 }) else {
                return Result(name: name, passed: false, detail: "QR parts \(partBytes)")
            }
            // (3) Assembly in any order; a repeated part is not progress.
            let asm = PairingCodeV4.QRAssembler()
            guard asm.add(aParts[2]) == .incomplete(have: 1, of: 4), asm.add(aParts[2]) == .incomplete(have: 1, of: 4),
                  asm.add(aParts[0]) == .incomplete(have: 2, of: 4), asm.add(aParts[3]) == .incomplete(have: 3, of: 4),
                  asm.add(aParts[1]) == .complete(aText),
                  asm.add(aParts[3]) == .incomplete(have: 1, of: 4), asm.add(aParts[1]) == .incomplete(have: 2, of: 4),
                  asm.add(aParts[0]) == .incomplete(have: 3, of: 4), asm.add(aParts[2]) == .complete(aText) else {
                return Result(name: name, passed: false, detail: "assembly order/duplicate handling wrong")
            }
            // (4) Parts of two different codes never mix.
            let b = try makeCode(expiresIn: 600)
            let bText = PairingCodeV4.encode(b)
            let bParts = try PairingCodeV4.qrParts(ofCode: bText)
            guard asm.add(aParts[0]) == .incomplete(have: 1, of: 4), asm.add(bParts[1]) == .incomplete(have: 1, of: 4),
                  asm.add(bParts[0]) == .incomplete(have: 2, of: 4), asm.add(bParts[2]) == .incomplete(have: 3, of: 4),
                  asm.add(bParts[3]) == .complete(bText) else {
                return Result(name: name, passed: false, detail: "parts of two codes were mixed")
            }
            // (5) A tampered part (valid characters, right length) is rejected.
            var chars = Array(aParts[1])
            let i = chars.count - 40
            chars[i] = chars[i] == "A" ? "B" : "A"
            guard asm.add(aParts[0]) == .incomplete(have: 1, of: 4), asm.add(aParts[2]) == .incomplete(have: 2, of: 4),
                  asm.add(aParts[3]) == .incomplete(have: 3, of: 4), asm.add(String(chars)) == .rejected else {
                return Result(name: name, passed: false, detail: "tampered QR part not rejected")
            }
            // (5b) Signature: every body byte is covered, and only the named
            //      identity can sign. Re-encoded with a fresh tag, so only the
            //      signature check can catch it.
            let aPayload = PairingCodeV4.fromBase64url(String(aText.dropFirst(PairingCodeV4.textPrefix.count)))!
            var sigErrors: [String] = []
            for off in [1, 1 + LadonV2.hsigPkLen + 3, PairingCodeV4.bodyLen - 1, PairingCodeV4.bodyLen + 10] {
                var t = aPayload
                t[t.startIndex + off] ^= 0x01
                do { _ = try PairingCodeV4.parse(PairingCodeV4.textPrefix + PairingCodeV4.base64url(t)); sigErrors.append("byte \(off) flip accepted") }
                catch PairingCodeError.malformed {} catch { sigErrors.append("byte \(off): \(error)") }
            }
            let mallory = try makeTestIdentity()
            let forged = try PairingCodeV4.signed(by: mallory.senderHsigKp, prekey: a.prekey, expiresAt: a.expiresAt, deliveryKey: a.deliveryKey)
            var forgedPayload = PairingCodeV4.fromBase64url(String(PairingCodeV4.encode(forged).dropFirst(PairingCodeV4.textPrefix.count)))!
            forgedPayload.replaceSubrange((forgedPayload.startIndex + 1)..<(forgedPayload.startIndex + 1 + LadonV2.hsigPkLen),
                                          with: owner.senderHsigKp.publicKeyBytes())
            do { _ = try PairingCodeV4.parse(PairingCodeV4.textPrefix + PairingCodeV4.base64url(forgedPayload)); sigErrors.append("foreign signer accepted") }
            catch PairingCodeError.malformed {} catch { sigErrors.append("foreign signer: \(error)") }
            guard sigErrors.isEmpty else { return Result(name: name, passed: false, detail: sigErrors.joined(separator: "; ")) }
            // (6) Old, damaged and foreign input.
            let old = "ladonv2:" + owner.senderHsigKp.publicKeyBytes().base64EncodedString()
            let v3 = "ladonv3:" + String(aText.dropFirst(PairingCodeV4.textPrefix.count))
            let v4 = "ladonv4:" + String(aText.dropFirst(PairingCodeV4.textPrefix.count))
            var errors: [String] = []
            for o in [old, v3, v4] {
                do { _ = try PairingCodeV4.parse(o); errors.append("old accepted") } catch PairingCodeError.oldFormat {} catch { errors.append("old: \(error)") }
            }
            let zeroKey = PairingCodeV4.encode(try makeCode(expiresIn: 600, deliveryKey: Data(count: LadonV2.deliveryKeyLen)))
            for bad in [String(aText.dropLast()), aText + "A", "ladonv5:", "hello", aText.replacingOccurrences(of: "ladonv5:", with: "ladonv5;"), zeroKey] {
                do { _ = try PairingCodeV4.parse(bad); errors.append("damaged accepted") } catch PairingCodeError.malformed {} catch { errors.append("\(error)") }
            }
            if PairingCodeV4.QRAssembler().add("ladonv5q:5/4:" + aParts[0].split(separator: ":").dropFirst(2).joined(separator: ":")) != .rejected {
                errors.append("bad part index accepted")
            }
            guard errors.isEmpty else { return Result(name: name, passed: false, detail: errors.joined(separator: "; ")) }
            // (7) Expiry hint with the relays' clock-skew tolerance.
            let now = ClockSyncV2.shared.nowSec()
            let tol = Int64(LadonV2.clockSkewToleranceSec)
            // ±30 s margin: makeCode reads the clock itself, a few ms later.
            guard try makeCode(expiresIn: -(tol + 30)).isExpired(nowRelaySec: now),
                  try !makeCode(expiresIn: -(tol - 30)).isExpired(nowRelaySec: now) else {
                return Result(name: name, passed: false, detail: "expiry tolerance wrong")
            }
            // (8) Contact-add validation: expired, old, and our own freshly issued code.
            var addErrors: [String] = []
            do { _ = try V2ContactAdder.validatedCode(fromScannedKey: PairingCodeV4.encode(try makeCode(expiresIn: -(tol + 60)))); addErrors.append("expired accepted") }
            catch V2ContactAddError.expiredCode {} catch { addErrors.append("expired: \(error)") }
            for o in [old, v3, v4] {
                do { _ = try V2ContactAdder.validatedCode(fromScannedKey: o); addErrors.append("old accepted") }
                catch V2ContactAddError.oldCode {} catch { addErrors.append("old: \(error)") }
            }
            let farFuture = Int64(PrekeyStoreV2.inviteLifetime) + tol + 600
            do { _ = try V2ContactAdder.validatedCode(fromScannedKey: PairingCodeV4.encode(try makeCode(expiresIn: farFuture))); addErrors.append("implausible expiry accepted") }
            catch V2ContactAddError.invalidKey {} catch { addErrors.append("implausible expiry: \(error)") }
            do { _ = try V2ContactAdder.validatedCode(fromScannedKey: try PairingCodeV4.issue(.inPerson)); addErrors.append("own code accepted") }
            catch V2ContactAddError.selfAdd {} catch { addErrors.append("own: \(error)") }
            let v = try V2ContactAdder.validatedCode(fromScannedKey: aText)
            if v.prekey != a.prekey || v.peer.recipientId != a.recipientId || v.deliveryKey != a.deliveryKey {
                addErrors.append("valid code misread")
            }
            guard addErrors.isEmpty else { return Result(name: name, passed: false, detail: addErrors.joined(separator: "; ")) }
            return Result(name: name, passed: true, detail: "text \(aText.count) chars; QR parts \(partBytes) B; any order; no mixing; tamper/byte-flip/foreign-signer/v2/v3/v4/damaged/zero-key/expired/too-late/self refused")
        } catch { return Result(name: name, passed: false, detail: "\(error)") }
    }

    /// Step 5 (B): a CONFIRMED session is never replaced by a bootstrap — so
    /// after one side lost its state, recovery needs the other side's explicit
    /// reset. Proves both halves: refused before the reset, accepted after it
    /// (same frame, same still-valid code), and the chat converges.
    private static func testV2SessionResetEnablesRecovery() -> Result {
        let name = "V2 session reset: confirmed session recoverable only after user reset"
        V2RatchetPayload._installInMemoryStoreForTesting()
        defer { V2RatchetPayload._restoreKeychainStoreForTesting() }
        do {
            let p = try makeDRPair()
            _ = try bOpen(p, aSeal(p, Data("a0".utf8)))
            _ = try aOpen(p, bSeal(p, Data("b0".utf8)))
            _ = try bOpen(p, aSeal(p, Data("a1".utf8)))                // both sides confirmed now
            let bobSession = p.alice.recipientId.description
            let aliceSession = p.bob.recipientId.description
            guard try V2RatchetPayload.hasSession(peerId: bobSession), try V2RatchetPayload.hasSession(peerId: aliceSession) else {
                return Result(name: name, passed: false, detail: "sessions missing after exchange")
            }
            // Alice loses her state; Bob hands her a fresh code; she restarts.
            V2RatchetPayload._deleteStateForTesting(peerId: aliceSession)
            let fresh = try handPrekey(from: p.bob)
            let restart = try aSeal(p, Data("after-loss".utf8))
            do {
                _ = try bOpen(p, restart)
                return Result(name: name, passed: false, detail: "confirmed session replaced without a reset")
            } catch { /* expected: confirmed sessions are never replaced */ }
            guard try ownPrekeyValid(fresh) else {
                return Result(name: name, passed: false, detail: "refused restart burned the fresh code")
            }
            // Bob resets on his own device; the same restart frame is accepted.
            try V2RatchetPayload.deleteSession(peerId: bobSession)
            guard try !V2RatchetPayload.hasSession(peerId: bobSession) else {
                return Result(name: name, passed: false, detail: "session still present after reset")
            }
            try V2RatchetPayload.deleteSession(peerId: bobSession)   // idempotent
            guard try bOpen(p, restart).plaintext == Data("after-loss".utf8), try !ownPrekeyValid(fresh) else {
                return Result(name: name, passed: false, detail: "restart not accepted after reset")
            }
            for r in 0..<2 {
                let bm = Data("rb\(r)".utf8), am = Data("ra\(r)".utf8)
                guard try aOpen(p, bSeal(p, bm)).plaintext == bm, try bOpen(p, aSeal(p, am)).plaintext == am else {
                    return Result(name: name, passed: false, detail: "chat did not converge after reset")
                }
            }
            return Result(name: name, passed: true, detail: "refused while confirmed; accepted after local reset; converges")
        } catch { return Result(name: name, passed: false, detail: "\(error)") }
    }

    /// Step 5 (A) + A1 §6: the START control message travels as an ordinary
    /// ratchet plaintext, bootstraps the session like any first message, and
    /// hands over the sender's delivery key intact.
    private static func testControlMessageBootstraps() -> Result {
        let name = "START control message: ordinary frame, bootstraps, carries K"
        V2RatchetPayload._installInMemoryStoreForTesting()
        defer { V2RatchetPayload._restoreKeychainStoreForTesting() }
        do {
            let k = randomBytes(LadonV2.deliveryKeyLen)
            let start = ControlMessageV2.start(deliveryKey: k)
            let p = try makeDRPair()
            let o = try bOpen(p, aSeal(p, Data(start.utf8)))
            guard o.messageNumber == 0,
                  let text = String(data: o.plaintext, encoding: .utf8),
                  ControlMessageV2.parse(text) == .start(deliveryKey: k),
                  try !ownPrekeyValid(p.bobPrekey), try V2RatchetPayload.hasSession(peerId: p.alice.recipientId.description) else {
                return Result(name: name, passed: false, detail: "START did not bootstrap the session or lost the key")
            }
            guard try aOpen(p, bSeal(p, Data("first real".utf8))).plaintext == Data("first real".utf8) else {
                return Result(name: name, passed: false, detail: "session after START unusable")
            }
            return Result(name: name, passed: true, detail: "bootstraps + burns the code; key arrives intact; session usable")
        } catch { return Result(name: name, passed: false, detail: "\(error)") }
    }

    /// Step 5 (A), review fix: a first-chain-only seal (the start message) goes
    /// out only into no session or our own unanswered first chain. Once the
    /// peer's frame has arrived — their start, or their reply — it refuses
    /// without sending or storing anything, so it can never answer.
    private static func testPairingStartNeverAnswers() -> Result {
        let name = "Pairing start: first-chain-only seal never answers"
        V2RatchetPayload._installInMemoryStoreForTesting()
        defer { V2RatchetPayload._restoreKeychainStoreForTesting() }
        func startSeal(_ from: LocalIdentityV2, to peer: PeerHandleV2, _ hkem: Data) throws -> Data {
            try V2RatchetPayload.seal(plaintext: Data(ControlMessageV2.start(deliveryKey: Data(repeating: 0x5A, count: 32)).utf8),
                                      peer: peer, recipientHkemPk: hkem,
                                      localIdentity: from, firstChainOnly: true)
        }
        do {
            let p = try makeDRPair()
            let s1 = try startSeal(p.alice, to: p.bobPeer, p.bobHkemPk)          // no session → allowed
            let s2 = try startSeal(p.alice, to: p.bobPeer, p.bobHkemPk)          // own unanswered first chain → allowed
            guard s1[s1.startIndex + 5] == 0x03, s2[s2.startIndex + 5] == 0x03 else {
                return Result(name: name, passed: false, detail: "start frames not in the first (BOOT) chain")
            }
            _ = try bOpen(p, s1)                                                   // Bob now holds the peer's session
            let bobBefore = try V2RatchetPayload._rawStateForTesting(peerId: p.alice.recipientId.description)
            do {
                _ = try startSeal(p.bob, to: p.alicePeer, p.aliceHkemPk)
                return Result(name: name, passed: false, detail: "responder's start message would have answered")
            } catch V2RatchetError.notFirstChain { /* expected */ }
            guard try V2RatchetPayload._rawStateForTesting(peerId: p.alice.recipientId.description) == bobBefore else {
                return Result(name: name, passed: false, detail: "refused start changed the responder's session")
            }
            _ = try aOpen(p, bSeal(p, Data("reply".utf8)))                       // Alice's first chain is answered
            do {
                _ = try startSeal(p.alice, to: p.bobPeer, p.bobHkemPk)
                return Result(name: name, passed: false, detail: "start message sent into an answered session")
            } catch V2RatchetError.notFirstChain { /* expected */ }
            return Result(name: name, passed: true, detail: "allowed: none / own first chain; refused: peer's session, answered session; nothing stored")
        } catch { return Result(name: name, passed: false, detail: "\(error)") }
    }
    #endif
}
