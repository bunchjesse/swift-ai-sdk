/**
 Tests for MCPTransportAuthorization, the single-flight OAuth recovery shared
 by an MCP transport's 401 paths.

 Covers the behavior of `authorizeOnce()` from vercel/ai#15518.
 */

import Foundation
import Testing

@testable import SwiftAISDK

/// Counts operation runs and holds each run until the test releases it.
private actor GatedOperation {
    private(set) var runs = 0
    private var waiters: [CheckedContinuation<Void, Never>] = []
    private var released = false

    /// Records a run, then waits for ``release()``.
    func run() async {
        runs += 1
        if released { return }
        await withCheckedContinuation { waiters.append($0) }
    }

    /// Lets every waiting and future run finish.
    func release() {
        released = true
        waiters.forEach { $0.resume() }
        waiters.removeAll()
    }
}

private struct RecoveryFailure: Error, Equatable {}

@Suite("MCPTransportAuthorization")
struct MCPTransportAuthorizationTests {

    @Test("concurrent callers share a single recovery and its result")
    func concurrentCallersShareOneRecovery() async throws {
        let authorization = MCPTransportAuthorization()
        let gate = GatedOperation()

        async let first = authorization.authorize {
            await gate.run()
            return .authorized
        }
        try await waitForFirstRun(gate)
        async let second = authorization.authorize {
            await gate.run()
            return .redirect
        }
        // Give the second caller time to reach the actor and join the
        // in-flight recovery before the first one finishes.
        try await Task.sleep(nanoseconds: 100_000_000)
        await gate.release()

        let results = try await [first, second]
        #expect(results == [.authorized, .authorized])
        #expect(await gate.runs == 1)
    }

    @Test("a recovery after the previous one finished runs again")
    func sequentialCallersEachRun() async throws {
        let authorization = MCPTransportAuthorization()
        let gate = GatedOperation()
        await gate.release()

        let first = try await authorization.authorize {
            await gate.run()
            return .redirect
        }
        let second = try await authorization.authorize {
            await gate.run()
            return .authorized
        }

        #expect(first == .redirect)
        #expect(second == .authorized)
        #expect(await gate.runs == 2)
    }

    @Test("a failed recovery reaches every waiting caller and does not stick")
    func failureReachesEveryCaller() async throws {
        let authorization = MCPTransportAuthorization()
        let gate = GatedOperation()

        let first = Task {
            try await authorization.authorize {
                await gate.run()
                throw RecoveryFailure()
            }
        }
        try await waitForFirstRun(gate)
        let second = Task {
            try await authorization.authorize {
                await gate.run()
                return .authorized
            }
        }
        try await Task.sleep(nanoseconds: 100_000_000)
        await gate.release()

        await #expect(throws: RecoveryFailure.self) { try await first.value }
        await #expect(throws: RecoveryFailure.self) { try await second.value }
        #expect(await gate.runs == 1)

        let retry = try await authorization.authorize { .authorized }
        #expect(retry == .authorized)
    }

    @Test("cancel stops the recovery in flight and lets the next one run")
    func cancelStopsRecoveryInFlight() async throws {
        let authorization = MCPTransportAuthorization()
        let started = GatedOperation()
        await started.release()

        let waiter = Task {
            try await authorization.authorize {
                await started.run()
                try await Task.sleep(nanoseconds: 30_000_000_000)
                return .authorized
            }
        }
        try await waitForFirstRun(started)
        await authorization.cancel()

        await #expect(throws: CancellationError.self) { try await waiter.value }

        let next = try await authorization.authorize { .redirect }
        #expect(next == .redirect)
    }

    /// Waits up to a second for `gate` to record its first run.
    private func waitForFirstRun(_ gate: GatedOperation) async throws {
        for _ in 0..<1_000 {
            if await gate.runs > 0 { return }
            try await Task.sleep(nanoseconds: 1_000_000)
        }
        Issue.record("The recovery never started")
    }
}
