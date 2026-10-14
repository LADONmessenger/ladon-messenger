//
//  SealedTransportV2.swift
//  Ladon — one sealed exchange: POST <entry>/v2/relay (Addendum A2 §4.5).
//
//  The entry sees a request of one of two lane sizes and a target id; it
//  forwards the body byte for byte and passes back a response of the lane's
//  response size. Every verdict about the request travels inside the sealed
//  response, so a refusal and an acceptance look the same on the path.
//
//  The lane's clock is fed from the opened response only (A2 §4.3); nothing
//  that did not open moves it.
//

import Foundation

enum SealedTransportV2Error: Error, CustomStringConvertible {
    case transport(Error)
    /// Non-200 from the entry: the request did not reach a target that could
    /// open it (400/401 passed through, 404 unknown target, 502 upstream).
    case http(status: Int)
    case malformed(String)

    var description: String {
        switch self {
        case .transport(let e): return "relay: transport — \(e)"
        case .http(let s): return "relay: HTTP \(s)"
        case .malformed(let m): return "relay: malformed — \(m)"
        }
    }
}

struct SealedTransportV2 {
    let session: URLSession
    /// The clock of the connection this transport belongs to (A2 stage 1:
    /// `.sendLane` for lane S, `.shared` for lane F).
    let clock: ClockSyncV2

    /// Send `request` through `entryUrl` and open the answer. The response
    /// key in `request` is not wiped here — the caller owns the request.
    func exchange(_ request: SealedRequestV2, entryUrl: URL) async throws -> OpenedSealedResponseV2 {
        var req = URLRequest(url: entryUrl.appendingPathComponent("v2/relay"), timeoutInterval: 20.0)
        req.httpMethod = "POST"
        req.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type")
        req.httpBody = request.bytes

        let body: Data
        let resp: URLResponse
        do {
            (body, resp) = try await session.data(for: req)
        } catch {
            throw SealedTransportV2Error.transport(error)
        }
        guard let http = resp as? HTTPURLResponse else {
            throw SealedTransportV2Error.malformed("not HTTP")
        }
        guard http.statusCode == 200 else {
            throw SealedTransportV2Error.http(status: http.statusCode)
        }
        guard body.count == request.lane.responseLen else {
            throw SealedTransportV2Error.malformed("response \(body.count) B, lane expects \(request.lane.responseLen)")
        }
        let opened: OpenedSealedResponseV2
        do {
            opened = try SealedCodecV2.openResponse(body, for: request)
        } catch {
            // Fail closed: an answer that does not open is a failure, and its
            // target_time is never used (A2 §8).
            throw SealedTransportV2Error.malformed("response did not open")
        }
        clock.record(targetTime: opened.targetTime)
        return opened
    }
}
