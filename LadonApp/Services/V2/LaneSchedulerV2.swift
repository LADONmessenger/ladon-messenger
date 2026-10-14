//
//  LaneSchedulerV2.swift
//  Ladon — the two constant-rate lanes of Addendum A2 §5.
//
//  While the session runs, each lane sends exactly one sealed request per
//  tick (T = 3 s, ±10 % uniform jitter that does not depend on content),
//  whatever the app is doing:
//
//    lane S (send connection):     real ENQUEUE > control ENQUEUE > DIR_GET > COVER
//    lane F (identity connection): DIR_PUT / PUSH_REGISTER > FETCH (rotating over the exits)
//
//  A real message waits for the next lane-S tick and takes the place of that
//  tick's cover; it is never sent in addition. Exchanges in a lane are
//  sequential: the next tick starts one interval after the previous one
//  started, or at once if the exchange took longer than that.
//
//  Catch-up burst: on return to the foreground and on a push wake, lane F
//  runs exactly `SealedV2.catchUpBurst` fetch exchanges back to back.
//
//  Fail-closed: a job whose request cannot be built is not sent in any other
//  form; that tick carries the lane's default request (cover or fetch)
//  instead, so the rate stays constant. With no transport (Tor down) the
//  lanes send nothing and queued jobs time out.
//

import Foundation

enum LaneSchedulerV2Error: Error, CustomStringConvertible {
    /// The job waited longer than `LaneSchedulerV2.maxQueueWait` for a tick.
    case timedOut

    var description: String {
        "lanes: no tick within \(Int(LaneSchedulerV2.maxQueueWait)) s"
    }
}

/// One unit of lane work: exactly one sealed exchange in one tick.
struct LaneJobV2: Sendable {
    let kind: SealedKindV2
    /// Called at the tick. Throwing means this job is not sent.
    let build: @Sendable () async throws -> (request: SealedRequestV2, entryUrl: URL)
    /// Receives the opened response, or the error.
    let complete: @Sendable (Result<OpenedSealedResponseV2, Error>) async -> Void
}

/// Lane-S priorities (A2 §5), highest first.
enum LaneSendPriorityV2: Int, CaseIterable, Sendable {
    case realMessage = 0
    case controlMessage = 1
    case directoryLookup = 2
}

actor LaneSchedulerV2 {

    /// How long a queued job may wait for its tick before it fails.
    static let maxQueueWait: TimeInterval = 90

    private struct Pending {
        let job: LaneJobV2
        let enqueuedAt: Date
    }

    private var sendQueues: [[Pending]] = Array(repeating: [], count: LaneSendPriorityV2.allCases.count)
    private var fetchQueue: [Pending] = []

    private var sendTransport: SealedTransportV2?
    private var fetchTransport: SealedTransportV2?
    /// Default work per tick when nothing is queued.
    private var coverSource: (@Sendable () async -> LaneJobV2?)?
    private var fetchSource: (@Sendable () async -> LaneJobV2?)?

    private var sendLoop: Task<Void, Never>?
    private var fetchLoop: Task<Void, Never>?
    /// The fetch lane's current wait between ticks; cancelled to start a burst.
    private var fetchSleep: Task<Void, Never>?

    private var burstRemaining = 0
    private var burstWaiters: [CheckedContinuation<Void, Never>] = []

    // MARK: - Configuration

    func setSources(cover: @escaping @Sendable () async -> LaneJobV2?,
                    fetch: @escaping @Sendable () async -> LaneJobV2?) {
        coverSource = cover
        fetchSource = fetch
    }

    /// Swap the connections (Tor change). nil pauses the lanes: no request
    /// goes out until transports are set again.
    func setTransports(send: SealedTransportV2?, fetch: SealedTransportV2?) {
        sendTransport = send
        fetchTransport = fetch
        if send == nil || fetch == nil { finishBurst() }
    }

    func start() {
        if sendLoop == nil {
            sendLoop = Task { [weak self] in
                guard let self else { return }
                await self.runLoop(.send)
            }
        }
        if fetchLoop == nil {
            fetchLoop = Task { [weak self] in
                guard let self else { return }
                await self.runLoop(.fetch)
            }
        }
    }

    /// End both loops (a scheduler built for a one-off, e.g. a self-test).
    /// Jobs still queued time out.
    func stop() {
        sendLoop?.cancel()
        fetchLoop?.cancel()
        fetchSleep?.cancel()
        sendLoop = nil
        fetchLoop = nil
        finishBurst()
    }

    // MARK: - Submitting work

    /// Queue a lane-S job.
    func submitSend(_ job: LaneJobV2, priority: LaneSendPriorityV2) {
        precondition(job.kind.lane == .send, "lane-S job of kind \(job.kind)")
        sendQueues[priority.rawValue].append(Pending(job: job, enqueuedAt: Date()))
    }

    /// Queue a lane-F job (DIR_PUT, PUSH_REGISTER).
    func submitFetchLane(_ job: LaneJobV2) {
        precondition(job.kind.lane == .fetch, "lane-F job of kind \(job.kind)")
        fetchQueue.append(Pending(job: job, enqueuedAt: Date()))
    }

    /// How long `runBurst` waits for the lanes to have connections. A push
    /// wake un-parks Tor and the lanes get their new connections a few
    /// seconds later; before, the burst found none, returned at once and the
    /// app went back to sleep with the messages still waiting (12 Pro,
    /// 13.10.2026). iOS gives a push wake about 30 s.
    static let burstReadyWait: TimeInterval = 15

    /// Run a catch-up burst on lane F and return when it is done. A burst
    /// already running is joined, not extended: the count is fixed (A2 §5).
    /// Waits up to `burstReadyWait` for the lanes to have connections.
    func runBurst() async {
        let deadline = Date().addingTimeInterval(Self.burstReadyWait)
        while fetchLoop == nil || sendTransport == nil || fetchTransport == nil {
            guard Date() < deadline, !Task.isCancelled else { return }
            try? await Task.sleep(for: .milliseconds(200))
        }
        if burstRemaining == 0 {
            burstRemaining = SealedV2.catchUpBurst
            fetchSleep?.cancel()
        }
        await withCheckedContinuation { burstWaiters.append($0) }
    }

    // MARK: - The loops

    private func runLoop(_ lane: SealedLaneV2) async {
        var lastStart = Date.distantPast
        while !Task.isCancelled {
            let inBurst = lane == .fetch && burstRemaining > 0
            if !inBurst {
                let interval = SealedV2.tickSec * Double.random(in: SealedV2.tickJitter)
                let wait = interval - Date().timeIntervalSince(lastStart)
                if wait > 0 {
                    let sleeper = Task<Void, Never> { try? await Task.sleep(for: .seconds(wait)) }
                    if lane == .fetch { fetchSleep = sleeper }
                    await sleeper.value
                    if lane == .fetch { fetchSleep = nil }
                }
            }
            guard !Task.isCancelled else { break }
            lastStart = Date()
            let burstTick = lane == .fetch && burstRemaining > 0
            if burstTick { burstRemaining -= 1 }
            await runTick(lane, burstTick: burstTick)
            if burstTick && burstRemaining == 0 { finishBurst() }
        }
    }

    private func finishBurst() {
        burstRemaining = 0
        let waiters = burstWaiters
        burstWaiters.removeAll()
        for w in waiters { w.resume() }
    }

    /// One tick of `lane`: exactly one exchange, or none while paused.
    private func runTick(_ lane: SealedLaneV2, burstTick: Bool) async {
        await expireStaleJobs()
        guard let transport = (lane == .send ? sendTransport : fetchTransport) else { return }

        let queued: LaneJobV2? = burstTick ? nil : dequeue(lane)
        let fallback: (@Sendable () async -> LaneJobV2?)? = lane == .send ? coverSource : fetchSource

        var job = queued
        var built: (request: SealedRequestV2, entryUrl: URL)?
        if let j = job {
            do { built = try await j.build() } catch {
                await j.complete(.failure(error))
                job = nil
            }
        }
        if built == nil {
            // Nothing queued, or the queued job could not be built: the
            // lane's default request keeps the rate.
            guard let make = fallback, let j = await make() else { return }
            do {
                built = try await j.build()
                job = j
            } catch {
                await j.complete(.failure(error))
                return
            }
        }
        guard let j = job, var b = built else { return }
        let result: Result<OpenedSealedResponseV2, Error>
        do {
            result = .success(try await transport.exchange(b.request, entryUrl: b.entryUrl))
        } catch {
            result = .failure(error)
        }
        b.request.wipe()
        await j.complete(result)
    }

    private func dequeue(_ lane: SealedLaneV2) -> LaneJobV2? {
        switch lane {
        case .send:
            for p in LaneSendPriorityV2.allCases where !sendQueues[p.rawValue].isEmpty {
                return sendQueues[p.rawValue].removeFirst().job
            }
            return nil
        case .fetch:
            return fetchQueue.isEmpty ? nil : fetchQueue.removeFirst().job
        }
    }

    private func expireStaleJobs() async {
        let cutoff = Date().addingTimeInterval(-Self.maxQueueWait)
        var expired: [LaneJobV2] = []
        for i in sendQueues.indices {
            expired += sendQueues[i].filter { $0.enqueuedAt < cutoff }.map(\.job)
            sendQueues[i].removeAll { $0.enqueuedAt < cutoff }
        }
        expired += fetchQueue.filter { $0.enqueuedAt < cutoff }.map(\.job)
        fetchQueue.removeAll { $0.enqueuedAt < cutoff }
        for j in expired { await j.complete(.failure(LaneSchedulerV2Error.timedOut)) }
    }
}

extension LaneSchedulerV2 {
    /// Submit a lane-S job and wait for its response.
    func sendLaneExchange(kind: SealedKindV2, priority: LaneSendPriorityV2,
                          build: @escaping @Sendable () async throws -> (request: SealedRequestV2, entryUrl: URL))
        async throws -> OpenedSealedResponseV2
    {
        try await withCheckedThrowingContinuation { cont in
            submitSend(LaneJobV2(kind: kind, build: build, complete: { cont.resume(with: $0) }), priority: priority)
        }
    }

    /// Submit a lane-F job (DIR_PUT, PUSH_REGISTER) and wait for its response.
    func fetchLaneExchange(kind: SealedKindV2,
                           build: @escaping @Sendable () async throws -> (request: SealedRequestV2, entryUrl: URL))
        async throws -> OpenedSealedResponseV2
    {
        try await withCheckedThrowingContinuation { cont in
            submitFetchLane(LaneJobV2(kind: kind, build: build, complete: { cont.resume(with: $0) }))
        }
    }
}
