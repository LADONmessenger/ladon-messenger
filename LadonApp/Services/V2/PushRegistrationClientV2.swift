//
//  PushRegistrationClientV2.swift
//  Ladon — the signed push-token registration body.
//
//  Wire format mirrors `relay-core-v2`'s `PUSH_REGISTER_BODY_LEN`:
//
//      body (3,414 B) =
//        apns_token (32 B)
//        sandbox    (1 B; 0 = production APNs, 1 = sandbox)
//        timestamp  (8 B big-endian unix seconds)
//        hsig       (3,373 B Ed25519 || ML-DSA-65)
//
//  HSig pre-image (signed end-to-end by the recipient's hsig key):
//
//      DOMAIN_PUSH_REGISTER || rid (32) || apns_token || sandbox || ts_be
//
//  Transport (Addendum A2 §4.4): `rid || body` as a sealed PUSH_REGISTER to
//  the push relay's own HKEM key, in lane F (`RelayClientV2.
//  registerPushToken`). Neither the entry nor an exit sees the token. The
//  HTTP route `/v2/proxy-push-register/:rid` is gone (phase B).
//

import Foundation

/// Errors raised by the push-registration client.
enum PushRegistrationClientV2Error: Error, CustomStringConvertible {
    /// APNs device token is not exactly `LadonV2.apnsTokenLen` bytes.
    case apnsTokenSize(got: Int)
    /// Signing the pre-image failed (PostQuantumService unavailable or crypto error).
    case signFailed(String)
    /// No push relay target in the bootstrap file (A2 §4.4) — registration
    /// is not possible; fail closed.
    case entryHasNoPushRelay
    /// Push-relay rejected the registration (signature mismatch / unknown rid /
    /// stale timestamp / token storage exhausted).
    case pushRelayRejected(status: Int)
    /// Push-relay has no replicated identity key for this rid (403
    /// E-UNKNOWN-RECIPIENT): publishing the bundle replicates it (A1 §4).
    case unknownRecipient
    /// Entry-relay returned a non-2xx that isn't a 503-disabled marker.
    case entryHttp(status: Int)
    /// URLSession transport error.
    case transport(Error)

    var description: String {
        switch self {
        case .apnsTokenSize(let n):
            return "pushRegV2: apns token must be \(LadonV2.apnsTokenLen) bytes, got \(n)"
        case .signFailed(let m):
            return "pushRegV2: sign failed — \(m)"
        case .entryHasNoPushRelay:
            return "pushRegV2: entry-relay has no push-relay configured (E-PUSH-DISABLED)"
        case .pushRelayRejected(let s):
            return "pushRegV2: push-relay rejected (HTTP \(s))"
        case .unknownRecipient:
            return "pushRegV2: push-relay does not know this recipient"
        case .entryHttp(let s):
            return "pushRegV2: entry-relay HTTP \(s)"
        case .transport(let e):
            return "pushRegV2: transport — \(e)"
        }
    }
}

enum PushRegistrationClientV2 {

    /// Build the 3,414-byte register body. Pure / no I/O — exposed so
    /// callers and tests can construct + inspect the wire format without
    /// having to send anything.
    ///
    /// - Parameters:
    ///   - rid: 32-byte recipient id of the local user (= SHA-256(IK_R)).
    ///   - apnsToken: exactly 32 bytes from
    ///     `application(_:didRegisterForRemoteNotificationsWithDeviceToken:)`.
    ///   - sandbox: `true` if APNs sandbox environment, else `false`.
    ///   - timestamp: unix seconds. Defaults to "now". Push-relay enforces
    ///     ±`PUSH_REGISTER_SKEW_SEC` (= 120 s), so callers MUST supply a
    ///     close-to-current value.
    ///   - hsigKp: recipient's long-term hsig keypair.
    /// - Returns: exactly `LadonV2.pushRegisterBodyLen` bytes.
    static func buildBody(
        rid: RecipientIdV2,
        apnsToken: Data,
        sandbox: Bool,
        timestamp: UInt64 = ClockSyncV2.shared.nowSec(),
        hsigKp: HSigKeyPairV2
    ) throws -> Data {
        guard apnsToken.count == LadonV2.apnsTokenLen else {
            throw PushRegistrationClientV2Error.apnsTokenSize(got: apnsToken.count)
        }

        // Signed payload: apns_token (32) || sandbox (1) || ts_be (8)  → 41 B.
        var signedPayload = Data(capacity: LadonV2.apnsTokenLen + 1 + 8)
        signedPayload.append(apnsToken)
        signedPayload.append(sandbox ? 0x01 : 0x00)
        var tsBe = timestamp.bigEndian
        withUnsafeBytes(of: &tsBe) { signedPayload.append(contentsOf: $0) }
        precondition(signedPayload.count == LadonV2.apnsTokenLen + 1 + 8)

        // Pre-image: DOMAIN || rid || signedPayload  → 20 + 32 + 41 = 93 B.
        var pre = Data(capacity: LadonV2.domainPushRegister.count + LadonV2.recipientIdLen + signedPayload.count)
        pre.append(LadonV2.domainPushRegister)
        pre.append(rid.bytes)
        pre.append(signedPayload)

        let sig: Data
        do {
            // Usecase tag "L1-PushRegister-v3" (A1 §10); the push relay
            // accepts nothing else.
            sig = try HSigV2.sign(pre, usecase: .pushRegister, with: hsigKp)
        } catch {
            throw PushRegistrationClientV2Error.signFailed("\(error)")
        }
        guard sig.count == LadonV2.hsigSigLen else {
            throw PushRegistrationClientV2Error.signFailed("hsig length \(sig.count) != \(LadonV2.hsigSigLen)")
        }

        // Body: signedPayload || hsig.
        var body = Data(capacity: LadonV2.pushRegisterBodyLen)
        body.append(signedPayload)
        body.append(sig)
        precondition(body.count == LadonV2.pushRegisterBodyLen,
                     "PushRegister body must be exactly \(LadonV2.pushRegisterBodyLen) bytes, got \(body.count)")
        return body
    }
}
