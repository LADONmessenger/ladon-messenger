//
//  DirectoryClientV2.swift
//  Ladon — verification of a contact's delivery bundle (Addendum A1 §4).
//
//  Bundles travel as sealed requests since Addendum A2 stage 2: a contact's
//  bundle is a DIR_GET in lane S, the own bundle a DIR_PUT in lane F
//  (`RelayClientV2`). The HTTP routes `/v2/proxy-directory[-put]` are gone
//  (phase B). What stays is the check every fetched bundle must pass.
//

import Foundation

/// Errors raised by the directory client.
enum DirectoryClientV2Error: Error, CustomStringConvertible {
    case unknownRecipient
    case unknownExit
    case malformedResponse(String)
    case bundleSizeMismatch(got: Int)
    case bundleSignatureInvalid
    case http(status: Int)
    case transport(Error)

    var description: String {
        switch self {
        case .unknownRecipient: return "directory: unknown recipient"
        case .unknownExit: return "directory: unknown exit"
        case .malformedResponse(let m): return "directory: malformed response — \(m)"
        case .bundleSizeMismatch(let g): return "directory: bundle size \(g) != \(LadonV2.bundleLen)"
        case .bundleSignatureInvalid: return "directory: bundle hsig invalid"
        case .http(let s): return "directory: HTTP \(s)"
        case .transport(let e): return "directory: transport — \(e)"
        }
    }
}

enum DirectoryClientV2 {

    /// Parse and verify a bundle the directory handed out for `recipientId`
    /// on `exitId`: size and structure, recipient and exit binding, the
    /// caller-supplied identity key, not from the future, and its signature.
    /// Shared by the HTTP lookup and the sealed DIR_GET (A2 stage 2).
    static func verifiedBundle(
        _ body: Data,
        recipientId: RecipientIdV2,
        exitId: ExitIdV2,
        recipientHsigPk: Data,
        nowSec: UInt64
    ) throws -> BundleV2 {
        guard recipientHsigPk.count == LadonV2.hsigPkLen else {
            throw LadonV2Error.shortBuffer(expected: LadonV2.hsigPkLen, got: recipientHsigPk.count)
        }
        // Parse + structural validation.
        let bundle: BundleV2
        do {
            bundle = try BundleV2.parse(body)
        } catch {
            throw DirectoryClientV2Error.malformedResponse("parse: \(error)")
        }
        do {
            try bundle.validateStructure()
        } catch {
            throw DirectoryClientV2Error.malformedResponse("structure: \(error)")
        }
        // Recipient binding: bundle.recipient_id MUST match the GET parameter.
        guard bundle.recipientId == recipientId else {
            throw DirectoryClientV2Error.malformedResponse("recipient mismatch")
        }
        // Exit binding (A1 §4 rule 4): the verifier inside is for exactly the
        // exit we asked; a bundle for another exit is useless here.
        guard bundle.exitId == exitId else {
            throw DirectoryClientV2Error.malformedResponse("bundle is for another exit")
        }
        // Recipient pk binding: caller-supplied pk MUST equal the in-bundle pk.
        // (If the caller's source-of-truth disagrees with the bundle, treat it
        // as a key-rotation event handled at a higher layer — fail closed here.)
        guard bundle.recipientHsigPk == recipientHsigPk else {
            throw DirectoryClientV2Error.malformedResponse("hsig pk mismatch with caller-supplied pk")
        }
        
        // A1 §4 rule 4: refuse a bundle from the future (beyond 5 min of
        // clock drift). There is deliberately NO lower bound: bundles are not
        // republished periodically and the exit never expires them, so a
        // current bundle can be arbitrarily old — an age limit would make its
        // owner unreachable. A stale bundle gains an attacker nothing: its
        // HKEM key is the long-term identity key, the exit refuses rolled-back
        // bundles, and the exit enforces the current verifier at delivery.
        // Relay-anchored clock (ClockSyncV2): the check must not fail on a
        // device whose own clock is off — see the 2026-08-24 12 Pro outage.
        let now = nowSec
        let maxSkew: UInt64 = 300
        if bundle.publishedAt > now + maxSkew {
            throw DirectoryClientV2Error.malformedResponse("bundle published in the future")
        }

        // Verify bundle self-signature.
        let signingInput = bundle.signingInput()
        guard HSigV2.verify(message: signingInput,
                            usecase: .bundle,
                            signature: bundle.bundleHsig,
                            publicKey: recipientHsigPk)
        else {
            throw DirectoryClientV2Error.bundleSignatureInvalid
        }
        return bundle
    }
}
