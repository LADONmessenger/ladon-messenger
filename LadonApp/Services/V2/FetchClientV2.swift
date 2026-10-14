//
//  FetchClientV2.swift
//  Ladon — acknowledged fetch: the signed pre-image, the ack ledger and the
//  record parser. The fetch itself is a sealed FETCH in lane F
//  (`RelayClientV2.makeFetchJob`, Addendum A2 §5); the HTTP route
//  `GET /v2/fetch-proxy` is gone (A2 stage 2, phase B).
//
//  Acknowledged fetch: the exit deletes nothing until the next fetch names
//  the batch in its ack, and the client names it only after the messages
//  are stored (`FetchAckLedgerV2`). A response lost on the way is re-delivered;
//  the ratchet rejects a second copy of a message it already opened.
//

import Foundation

enum FetchClientV2Error: Error, CustomStringConvertible {
    case truncated

    var description: String { "fetch: response body truncated" }
}

/// Batch ids still to be acknowledged, per exit (hex ExitId). RAM only: a
/// lost entry (app restart) only means the exit re-delivers that batch, and
/// the ratchet drops what was already opened. Outlives `RelayClientV2`
/// instances, which are replaced on every Tor reconfigure.
final class FetchAckLedgerV2: @unchecked Sendable {
    static let shared = FetchAckLedgerV2()

    private let lock = NSLock()
    private var pending: [String: Data] = [:]

    /// The ack to send with the next fetch to `exitHex`: the stored batch id,
    /// or all zero ("nothing to acknowledge").
    func ack(for exitHex: String) -> Data {
        lock.lock(); defer { lock.unlock() }
        return pending[exitHex] ?? Data(count: LadonV2.fetchBatchIdLen)
    }

    /// Record the result of a successful fetch AFTER its messages were stored:
    /// the batch it handed out becomes the next ack; nil (empty response)
    /// leaves nothing to acknowledge.
    func commit(exitHex: String, batchId: Data?) {
        lock.lock(); defer { lock.unlock() }
        pending[exitHex] = batchId
    }
}

enum FetchClientV2 {

    /// Acknowledged-fetch pre-image:
    /// `"L1-FetchAck-v2" || exit_id16 || rid || ts_be8 || ack16`.
    /// The ack is signed because it authorises deletion on the exit. The
    /// target exit's id is part of it (P8-AUDIT8-IOS-31, audit F12): a FETCH
    /// that one exit opened could otherwise be re-sealed to every other exit
    /// and serve, suppress push for and block this mailbox there.
    static func fetchAckSigningInput(exitId: ExitIdV2, recipientId: RecipientIdV2, timestamp: UInt64, ack: Data) -> Data {
        precondition(ack.count == LadonV2.fetchBatchIdLen, "fetch ack must be \(LadonV2.fetchBatchIdLen) bytes")
        var m = Data(capacity: LadonV2.domainFetchAck.count + LadonV2.exitIdLen + LadonV2.recipientIdLen + 8 + LadonV2.fetchBatchIdLen)
        m.append(LadonV2.domainFetchAck)
        m.append(exitId.bytes)
        m.append(recipientId.bytes)
        m.append(u64BE(timestamp))
        m.append(ack)
        return m
    }

    /// Sign the acknowledged-fetch pre-image with the recipient's own HSig
    /// keypair, under usecase tag "L1-Fetch-v2.1" (A1 §10).
    static func signFetchAck(
        exitId: ExitIdV2,
        recipientId: RecipientIdV2,
        timestamp: UInt64,
        ack: Data,
        with kp: HSigKeyPairV2
    ) throws -> Data {
        let m = fetchAckSigningInput(exitId: exitId, recipientId: recipientId, timestamp: timestamp, ack: ack)
        return try HSigV2.sign(m, usecase: .fetch, with: kp)
    }

    // MARK: - Helpers

    /// Parse `[ u32_be len || bytes ]+` records. Validates each record fits
    /// inside the buffer; throws `.truncated` if the buffer ends mid-record.
    static func parseLengthPrefixedRecords(_ buf: Data) throws -> [Data] {
        var out: [Data] = []
        var idx = buf.startIndex
        while idx < buf.endIndex {
            guard buf.distance(from: idx, to: buf.endIndex) >= 4 else {
                throw FetchClientV2Error.truncated
            }
            let lenRange = idx..<buf.index(idx, offsetBy: 4)
            let lenBytes = buf[lenRange]
            // Big-endian u32.
            var len: UInt32 = 0
            for b in lenBytes { len = (len << 8) | UInt32(b) }
            let payloadStart = buf.index(idx, offsetBy: 4)
            guard buf.distance(from: payloadStart, to: buf.endIndex) >= Int(len) else {
                throw FetchClientV2Error.truncated
            }
            let payloadEnd = buf.index(payloadStart, offsetBy: Int(len))
            out.append(Data(buf[payloadStart..<payloadEnd]))
            idx = payloadEnd
        }
        return out
    }
}
