//
//  EnqueueClientV2.swift
//  Ladon — errors of a sealed ENQUEUE (Addendum A2 §4.1).
//
//  The HTTP route `POST /v2/enqueue` and its client are gone (A2 stage 2,
//  phase B): an ENQUEUE is a sealed request in lane S (`RelayClientV2.
//  sendMessage`). The error type stays, because the send path and its callers
//  (ChatView's retry policy) branch on it. `.http(status:)` carries the
//  verdict the exit seals into its response, mapped to the HTTP status it
//  used to answer with (`RelayClientV2.enqueueError(forStatus:)`), or the
//  entry's own non-200.
//

import Foundation

/// Errors raised by the send path.
enum EnqueueClientV2Error: Error, CustomStringConvertible {
    case http(status: Int)
    case transport(Error)
    case malformed(String)

    var description: String {
        switch self {
        case .http(let s): return "enqueue: HTTP \(s)"
        case .transport(let e): return "enqueue: transport — \(e)"
        case .malformed(let m): return "enqueue: malformed — \(m)"
        }
    }
}
