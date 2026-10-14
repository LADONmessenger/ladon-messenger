//
//  ClockSyncV2.swift
//  Ladon — relay-anchored protocol clock.
//
//  Every protocol timestamp this client stamps (token issued_at, bundle
//  published_at, fetch and push-register signatures, blob-init auth, the
//  inner-envelope timestamp) and every freshness check it performs (token
//  expiry on admission, bundle age) has to agree with the relays' clocks,
//  not with the device's. The relay-side tolerances are small — the exit
//  rejects tokens issued more than TOKEN_FUTURE_SKEW_SEC = 30 s in the
//  future, fetch/push/S2S allow 120 s, the blob relay 300 s. A device whose
//  wall clock is further off is unreachable without any hint: its tokens
//  are rejected as expired or future-dated, so nobody can enqueue to it,
//  and its own fetch signatures fail. Measured 2026-08-24 on the 12 Pro
//  (clock 9 h behind): one-sided message loss, no error surfaced.
//
//  Source of truth is the `Date` response header (RFC 9110 §6.6.1) that
//  every relay response carries. offset = server time − local receive
//  time. The estimate is biased by the one-way transit time, so the
//  corrected clock lags the relay by at most one round trip — the safe
//  direction: stamped material looks slightly past, never future-dated.
//
//  Trust boundary. The relay operator is adversary #1. A relay that lies in
//  `Date` shifts this offset arbitrarily. What it gains: it can make the
//  client stamp material that an honest exit rejects (denial of service,
//  which any relay achieves by dropping traffic), and it can widen the
//  client-side bundle-freshness window for bundles that the very same
//  relay serves — old single-use tokens the exit's replay filter and its
//  own expiry check still reject, and long-term keys that do not change
//  between bundles. No plaintext, key or identity is exposed and no
//  cryptographic check is weakened; `clockSkewToleranceSec` and every
//  relay-side tolerance stay untouched. The offset is therefore applied
//  without a cap — a cap would only bring the outage back for honestly
//  wrong clocks.
//
//  Two independent clocks (Addendum A2 stage 1). `shared` is fed and read
//  by the identity connection (fetch, publish, push register, health
//  probes) and everything outside the V2 transport. `sendLane` is fed and
//  read only by the send connection (enqueue, contact bundle lookups) and
//  stamps the outer `sent_at` the exit reads. One clock for both would be a
//  marking channel: a relay that shifts `Date` on the connection where it
//  sees a user's own rid would find the same shift in `sent_at` on the send
//  connection, and link the two Tor circuits that are kept apart on purpose.
//
//  Never persisted: a stored offset is wrong the moment the user fixes the
//  clock. Until the first relay response arrives the raw device clock is
//  used, which is exactly the pre-fix behaviour. The first request of every
//  bootstrap is the health probe, so the offset is known before the first
//  bundle is published.
//

import Foundation

final class ClockSyncV2: @unchecked Sendable {

    static let shared = ClockSyncV2(label: "identity")
    /// The send connection's own clock — see the file header.
    static let sendLane = ClockSyncV2(label: "send")
    /// The blob relay's own clock: fed only by blob-relay responses, read only
    /// for the blob `expires_at`. Before, the blob relay's `Date` moved
    /// `shared`, which stamps the fetch on the identity connection — a blob
    /// relay could mark a downloader and read the mark next to its rid
    /// (scan F21).
    static let blob = ClockSyncV2(label: "blob")

    private let label: String
    private let lock = NSLock()
    private var offsetSec: Int64 = 0
    private var sampleCount: Int = 0

    private init(label: String) {
        self.label = label
    }

    // MARK: - Reading the clock

    /// Protocol "now" in unix seconds: device clock plus the relay offset.
    func nowSec() -> UInt64 {
        let corrected = Date().timeIntervalSince1970 + TimeInterval(currentOffsetSec())
        return corrected > 0 ? UInt64(corrected) : 0
    }

    /// Protocol "now" as a `Date`.
    func now() -> Date {
        Date(timeIntervalSince1970: Date().timeIntervalSince1970 + TimeInterval(currentOffsetSec()))
    }

    /// Current offset in seconds (relay minus device). 0 until the first sample.
    func currentOffsetSec() -> Int64 {
        lock.lock()
        defer { lock.unlock() }
        return offsetSec
    }

    /// Move a protocol timestamp (relay time domain) into the device's own
    /// time domain, so it sorts next to locally stamped messages.
    func localDate(fromProtocolSec sec: UInt64) -> Date {
        Date(timeIntervalSince1970: TimeInterval(sec) - TimeInterval(currentOffsetSec()))
    }

    // MARK: - Feeding samples

    /// Feed one relay response. Responses without a parsable `Date` header
    /// are ignored — the offset simply keeps its previous value.
    func observe(_ http: HTTPURLResponse) {
        guard let raw = http.value(forHTTPHeaderField: "Date"),
              let serverDate = Self.parseHTTPDate(raw)
        else { return }
        record(serverTime: serverDate.timeIntervalSince1970,
               localTime: Date().timeIntervalSince1970)
    }

    /// A2 §4.3: the relay lanes feed their clocks only from here — the
    /// `target_time` inside a sealed response that opened, i.e. the target's
    /// own clock, which neither the entry nor anyone on the path can change.
    /// HTTP `Date` headers no longer move `shared` or `sendLane`.
    ///
    /// The first sample sets the offset (there is no estimate to protect
    /// yet, and a device whose clock is hours off must work at once — the
    /// 12 Pro outage of 2026-08-24). After that one sample moves the offset
    /// by at most `clockSkewToleranceSec`, so a single response cannot jump
    /// the clock.
    func record(targetTime: UInt64, localTime: TimeInterval = Date().timeIntervalSince1970) {
        guard let measured = Self.offsetSample(targetTime: targetTime, localTime: localTime) else { return }
        lock.lock()
        let previous = offsetSec
        let first = sampleCount == 0
        let cap = Int64(LadonV2.clockSkewToleranceSec)
        let fresh = first ? measured : previous + max(-cap, min(cap, measured - previous))
        offsetSec = fresh
        sampleCount += 1
        lock.unlock()
        if first || abs(fresh - previous) > 5 {
            SecureLogger.torDiag("[V2] clock offset vs target (\(label)): \(fresh)s (was \(previous)s)")
        }
        if first && abs(fresh) > cap {
            SecureLogger.error("[V2] device clock is \(fresh)s off the relay (\(label)) — protocol timestamps are being corrected")
        }
    }

    /// Offset (target − device) for one sealed-response `target_time`, or nil
    /// when the value is not a plausible unix time.
    ///
    /// P8-AUDIT8-IOS-07 (audit F21): `target_time` is chosen by the target
    /// relay. It used to be checked only from below; `Int64(Double)` traps
    /// for values outside Int64, so a relay answering with e.g. u64::MAX
    /// crashed every client on each start. Upper bound 4_102_444_800 =
    /// 2100-01-01T00:00:00Z.
    static func offsetSample(targetTime: UInt64, localTime: TimeInterval) -> Int64? {
        guard targetTime > 1_700_000_000, targetTime < 4_102_444_800 else { return nil }
        let delta = (TimeInterval(targetTime) - localTime).rounded()
        guard delta.isFinite, abs(delta) < 1e15 else { return nil }
        return Int64(delta)
    }

    /// Testable core of `observe`.
    func record(serverTime: TimeInterval, localTime: TimeInterval) {
        // A server date before the protocol existed is garbage, not a sample.
        guard serverTime > 1_700_000_000 else { return }
        let fresh = Int64((serverTime - localTime).rounded())
        lock.lock()
        let previous = offsetSec
        let first = sampleCount == 0
        offsetSec = fresh
        sampleCount += 1
        lock.unlock()
        // The offset is not sensitive (it reveals nothing beyond how wrong
        // this device's clock is) and is the one number needed to diagnose
        // a silent receive outage — log it when it first appears or moves.
        if first || abs(fresh - previous) > 5 {
            SecureLogger.torDiag("[V2] clock offset vs relay (\(label)): \(fresh)s (was \(previous)s)")
        }
        if first && abs(fresh) > Int64(LadonV2.clockSkewToleranceSec) {
            SecureLogger.error("[V2] device clock is \(fresh)s off the relay (\(label)) — protocol timestamps are being corrected")
        }
    }

    // MARK: - HTTP-date parsing

    /// RFC 9110 §5.6.7: IMF-fixdate is what servers send; the two obsolete
    /// forms are still accepted, as the RFC requires of recipients.
    private static let httpDateFormats = [
        "EEE, dd MMM yyyy HH:mm:ss zzz",   // IMF-fixdate: Sun, 06 Nov 1994 08:49:37 GMT
        "EEEE, dd-MMM-yy HH:mm:ss zzz",    // RFC 850:     Sunday, 06-Nov-94 08:49:37 GMT
        "EEE MMM d HH:mm:ss yyyy",         // asctime:     Sun Nov  6 08:49:37 1994
    ]

    static func parseHTTPDate(_ raw: String) -> Date? {
        let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !s.isEmpty else { return nil }
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(secondsFromGMT: 0)
        for fmt in httpDateFormats {
            f.dateFormat = fmt
            if let d = f.date(from: s) { return d }
        }
        return nil
    }
}
