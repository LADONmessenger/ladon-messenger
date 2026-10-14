//
//  LadonV2CrossLangVectors.swift
//  Ladon — cross-language byte-level test vectors against `relay-core-v2`.
//
//  Source of truth: `relay-core-v2/src/bin/emit_test_vectors.rs` (format 2;
//  bundles under relay protocol 0x05 / Addendum A1, requests under 0x06 /
//  Addendum A2). Run that binary to refresh the
//  constants when the Rust crate changes wire layout — never edit them by
//  hand. A failure in any of these checks means Swift and Rust disagree on a
//  wire byte — DO NOT ship.
//

import Foundation

/// Fixed inputs — kept in sync with `emit_test_vectors.rs`.
enum LadonV2FixedInputs {
    static let recipientId  = RecipientIdV2(bytes: Data(repeating: 0xAA, count: 32))
    static let exitId       = ExitIdV2(bytes: Data(repeating: 0xBB, count: 16))
    static let publishedAt: UInt64 = 1_700_000_000
    static let deliveryKey  = Data(repeating: 0x5A, count: LadonV2.deliveryKeyLen)
    static let sentAt: UInt64 = 1_700_000_000
    static let envelopeId   = Data(repeating: 0xE1, count: LadonV2.envelopeIdLen)

    static let bundleRecipientHsigPk = Data(repeating: 0x22, count: LadonV2.hsigPkLen)
    static let bundleRecipientHkemPk = Data(repeating: 0x33, count: LadonV2.hkemPkLen)
    static let bundleId   = BundleIdV2(bytes: Data(repeating: 0x44, count: 16))
    static let bundleHsig = Data(repeating: 0x55, count: LadonV2.hsigSigLen)

    static let exitPkInput = Data(repeating: 0x77, count: LadonV2.hkemPkLen)
    static let fetchTs: UInt64 = 1_700_000_000
    static let fetchAck = Data(repeating: 0xEE, count: LadonV2.fetchBatchIdLen)
    static let taggedSigMessage = Data("ladon-vector".utf8)
}

/// Hex strings emitted by `relay-core-v2/src/bin/emit_test_vectors.rs` (format 2).
enum LadonV2RustVectors {
    static let relayProtocolVersion: UInt8 = 5
    static let blake3Empty             = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
    static let blake3Abc               = "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
    static let exitIdFromPk77          = "79a4c15344223b3a610abb5f12f95031"

    static let exitDeliveryKey         = "bf0bee7489101576b2b389e8b18a9b9847145ade3326b07d46b0eccfae079171"
    static let deliveryVerifier        = "e27f8107e5ef28a1a10d36b53fabd519ad25443b6e40d897ff288b4b5a896278"

    static let bundleLen               = 6678
    static let bundleBlake3            = "15588b0dc4b83f3a3ae6e1824e9c39191b537ce71a8cfa036ffb524ad56effb5"
    static let bundleSigningBlake3     = "0fd465a0ce2d1b72c045fa5459aec09208e6288cc2b8980eaeebd8c68a219225"

    /// A2 §4.1: sealed ENQUEUE body header (rid ‖ K_X ‖ sent_at ‖ envelope_id).
    static let enqueueBodyHeader       = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabf0bee7489101576b2b389e8b18a9b9847145ade3326b07d46b0eccfae079171000000006553f100e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1"
    static let enqueueBodyHeaderLen    = 88
    static let innerAad                = "4c312d496e6e65722d763102aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    static let innerAadLen             = 44

    static let fetchAckPreimage        = "4c312d466574636841636b2d7632bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa000000006553f100eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
    static let fetchAckPreimageLen     = 86

    static let prehashTaggedBundle       = "4bff06874733d0f412d90e45ffe29de7f03863d051a040fe58f4b710aaf6d7f6"
    static let prehashTaggedFetch        = "3e8462e100e8382f92d5d7355904d343dedef6582f8abc4e3c8f89b49d4bde54"
    static let prehashTaggedPushRegister = "6e8b1f2e518906085e631fe0a05c724d8701bcb202a8a9a5c5b9783aba429476"
    static let prehashTaggedInnerSender  = "b76fcc2702d43a36b310acf6b1a2a9792c3ef54198180129c1559093ef1ebcf1"
    static let prehashTaggedPairing      = "3f450bb1f5fc0b0bec375140a54ffa785be18507fe23d082e523ceab554220f1"

    /// A2 §4 sealed request/response. Inputs: ss 0x33×32, hkem_ct 0x77×1120,
    /// nonces 0x01×12 / 0x02×12, target 0x42×16, kind FETCH, body
    /// "ladon-sealed", status OK, target_time 1,700,000,000, body "ok".
    static let sealedKReq           = "7df7cf9f0de86599f32f762faf1ccdd4446ea2dfae084b51739d7c75dc51bee8"
    static let sealedKResp          = "992ca4c7c4081d33043566f97f913958c42bd46267d14e2dcf079b3049294b40"
    static let sealedRequestLen     = 8192
    static let sealedRequestBlake3  = "3bd068de74ce838b2c3621dedb021f7254349e00cfe84e0c843321d38ad2496f"
    static let sealedResponseLen    = 16384
    static let sealedResponseBlake3 = "4e84c4346f36bc1409188b2b7422d62aabde34aad198db631d8a34bcad478b3b"
}

/// Cross-language byte-vector tests. Used by `LadonV2SelfTest`.
enum LadonV2CrossLang {

    /// Run every cross-language assertion. Returns one Result per check.
    static func runAll() -> [LadonV2SelfTest.Result] {
        var out: [LadonV2SelfTest.Result] = []
        out.append(check("Relay protocol version matches Rust (0x05)") {
            LadonV2.relayProtocolVersion == LadonV2RustVectors.relayProtocolVersion
        })
        out.append(check("BLAKE3 empty matches Rust") {
            blake3Hex(Data()) == LadonV2RustVectors.blake3Empty
        })
        out.append(check("BLAKE3 'abc' matches Rust") {
            blake3Hex(Data("abc".utf8)) == LadonV2RustVectors.blake3Abc
        })
        out.append(check("ExitId(BLAKE3(0x77*1216)) matches Rust") {
            let id = ExitIdV2.fromHkemPk(LadonV2FixedInputs.exitPkInput)
            return id.bytes.hexEncodedString == LadonV2RustVectors.exitIdFromPk77
        })
        out.append(check("Exit delivery key K_X (HKDF) matches Rust") {
            (try? exitDeliveryKey())?.hexEncodedString == LadonV2RustVectors.exitDeliveryKey
        })
        out.append(check("Delivery verifier V_X matches Rust") {
            guard let kx = try? exitDeliveryKey() else { return false }
            return DeliveryKeyV2.verifier(exitDeliveryKey: kx).hexEncodedString == LadonV2RustVectors.deliveryVerifier
        })
        out.append(check("Bundle.encode length = 6678") {
            (try? makeFixedBundle())?.encode().count == LadonV2RustVectors.bundleLen
        })
        out.append(check("BLAKE3(Bundle.encode) matches Rust") {
            guard let b = try? makeFixedBundle() else { return false }
            return blake3Hex(b.encode()) == LadonV2RustVectors.bundleBlake3
        })
        out.append(check("BLAKE3(Bundle.signing_input) matches Rust") {
            guard let b = try? makeFixedBundle() else { return false }
            return blake3Hex(b.signingInput()) == LadonV2RustVectors.bundleSigningBlake3
        })
        out.append(check("Sealed ENQUEUE body header matches Rust (len=88)") {
            guard let kx = try? exitDeliveryKey() else { return false }
            let h = SealedV2.enqueueHeader(
                recipientId: LadonV2FixedInputs.recipientId,
                exitDeliveryKey: kx,
                sentAt: LadonV2FixedInputs.sentAt,
                envelopeId: LadonV2FixedInputs.envelopeId)
            return h.hexEncodedString == LadonV2RustVectors.enqueueBodyHeader
                && h.count == LadonV2RustVectors.enqueueBodyHeaderLen
        })
        out.append(check("Inner-AAD bytes match Rust (len=44)") {
            let aad = InnerEnvelopeV2.innerAAD(
                version: LadonV2.innerAadVersion,
                recipientId: LadonV2FixedInputs.recipientId)
            return aad.hexEncodedString == LadonV2RustVectors.innerAad
                && aad.count == LadonV2RustVectors.innerAadLen
        })
        out.append(check("Acknowledged-fetch pre-image bytes match Rust (len=86)") {
            let m = FetchClientV2.fetchAckSigningInput(
                exitId: LadonV2FixedInputs.exitId,
                recipientId: LadonV2FixedInputs.recipientId,
                timestamp: LadonV2FixedInputs.fetchTs,
                ack: LadonV2FixedInputs.fetchAck)
            return m.hexEncodedString == LadonV2RustVectors.fetchAckPreimage
                && m.count == LadonV2RustVectors.fetchAckPreimageLen
        })
        out.append(contentsOf: sealedChecks())
        let tagged: [(String, HSigUsecaseV2, String)] = [
            ("L1-Bundle-v3", .bundle, LadonV2RustVectors.prehashTaggedBundle),
            ("L1-Fetch-v2.1", .fetch, LadonV2RustVectors.prehashTaggedFetch),
            ("L1-PushRegister-v3", .pushRegister, LadonV2RustVectors.prehashTaggedPushRegister),
            ("L1-InnerSender-v3", .innerSender, LadonV2RustVectors.prehashTaggedInnerSender),
            ("L1-Pairing-v1", .pairing, LadonV2RustVectors.prehashTaggedPairing),
        ]
        for (name, usecase, want) in tagged {
            out.append(check("Tagged HSig pre-hash \(name) matches Rust") {
                HSigV2.prehash(LadonV2FixedInputs.taggedSigMessage, usecase: usecase).hexEncodedString == want
            })
        }
        return out
    }

    /// A2 §4: the sealed request and response bytes, the two keys, and the
    /// fixed inner-envelope length under relay protocol 0x06.
    private static func sealedChecks() -> [LadonV2SelfTest.Result] {
        var out: [LadonV2SelfTest.Result] = []
        let target = Data(repeating: 0x42, count: 16)
        let sealed = try? SealedCodecV2.seal(
            ss: Data(repeating: 0x33, count: 32),
            hkemCt: Data(repeating: 0x77, count: LadonV2.hkemCtLen),
            nonce: Data(repeating: 0x01, count: 12),
            targetId: target, kind: .fetch, body: Data("ladon-sealed".utf8))
        out.append(check("Sealed k_req / k_resp (HKDF) match Rust") {
            sealed?.kReq.hexEncodedString == LadonV2RustVectors.sealedKReq
                && sealed?.kResp.hexEncodedString == LadonV2RustVectors.sealedKResp
        })
        out.append(check("Sealed request bytes match Rust (lane F, 8,192 B)") {
            guard let r = sealed?.request else { return false }
            return r.count == LadonV2RustVectors.sealedRequestLen
                && blake3Hex(r) == LadonV2RustVectors.sealedRequestBlake3
        })
        #if DEBUG
        let response: Data? = sealed.flatMap {
            try? SealedCodecV2.sealResponseForVectors(
                kResp: $0.kResp, nonce: Data(repeating: 0x02, count: 12), targetId: target,
                lane: .fetch, status: SealedStatusV2.ok, targetTime: 1_700_000_000, body: Data("ok".utf8))
        }
        out.append(check("Sealed response bytes match Rust (lane F, 16,384 B)") {
            guard let r = response else { return false }
            return r.count == LadonV2RustVectors.sealedResponseLen
                && blake3Hex(r) == LadonV2RustVectors.sealedResponseBlake3
        })
        out.append(check("Sealed response opens: status, target_time, body") {
            guard let r = response, let k = sealed?.kResp,
                  let o = try? SealedCodecV2.openResponse(r, kResp: k, targetId: target, lane: .fetch) else { return false }
            return o.status == SealedStatusV2.ok && o.targetTime == 1_700_000_000 && o.body == Data("ok".utf8)
        })
        out.append(check("Sealed response with a flipped byte is refused") {
            guard var r = response, let k = sealed?.kResp else { return false }
            r[100] ^= 1
            return (try? SealedCodecV2.openResponse(r, kResp: k, targetId: target, lane: .fetch)) == nil
        })
        #endif
        out.append(check("Inner envelope under 0x06 = 15,128 B (matches Rust)") {
            SealedV2.innerEnvelopeLen == 15_128
        })
        return out
    }

    // MARK: - Helpers

    private static func check(_ name: String, _ predicate: () -> Bool) -> LadonV2SelfTest.Result {
        let ok = predicate()
        return LadonV2SelfTest.Result(
            name: name,
            passed: ok,
            detail: ok ? "byte-exact match" : "MISMATCH — Rust↔Swift disagree"
        )
    }

    private static func blake3Hex(_ d: Data) -> String {
        Blake3.hash(d, outputLength: 32).hexEncodedString
    }

    private static func exitDeliveryKey() throws -> Data {
        try DeliveryKeyV2.exitDeliveryKey(LadonV2FixedInputs.deliveryKey, exitId: LadonV2FixedInputs.exitId)
    }

    /// Layout vector only: rid is the fixed 0xAA input, not SHA-256 of the
    /// fixed pk, so this bundle would fail `validateStructure` (as in Rust).
    private static func makeFixedBundle() throws -> BundleV2 {
        let kx = try exitDeliveryKey()
        return BundleV2(
            version: LadonV2.relayProtocolVersion,
            recipientId: LadonV2FixedInputs.recipientId,
            recipientHsigPk: LadonV2FixedInputs.bundleRecipientHsigPk,
            recipientHkemPk: LadonV2FixedInputs.bundleRecipientHkemPk,
            bundleId: LadonV2FixedInputs.bundleId,
            publishedAt: LadonV2FixedInputs.publishedAt,
            exitId: LadonV2FixedInputs.exitId,
            verifier: DeliveryKeyV2.verifier(exitDeliveryKey: kx),
            bundleHsig: LadonV2FixedInputs.bundleHsig
        )
    }
}
