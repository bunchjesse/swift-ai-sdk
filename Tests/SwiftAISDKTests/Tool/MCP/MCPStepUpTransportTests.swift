/**
 Tests for 403 `insufficient_scope` step-up (SEP-2350) in the Streamable HTTP and legacy SSE transports.

 Port of the step-up cases of the MCP TypeScript SDK `streamableHttp.test.ts`.
 */

import Foundation
import Testing

@testable import SwiftAISDK
import AISDKProviderUtils

private let stepUpMetadataUrl = "https://resource.example.com/.well-known/oauth-protected-resource/custom"

/// One scripted answer from the fake MCP endpoint.
private struct MCPReply: Sendable {
    var status: Int
    var headers: [String: String] = [:]
    var body: ProviderHTTPResponseBody = .none

    /// A 200 with an empty body, enough for the transport to accept a notification.
    static let ok = MCPReply(status: 200)

    /// A 403 carrying a Bearer `insufficient_scope` challenge for `scope`.
    static func insufficientScope(_ scope: String? = "read write") -> MCPReply {
        var challenge = "Bearer error=\"insufficient_scope\", error_description=\"more scope needed\", resource_metadata=\"\(stepUpMetadataUrl)\""
        if let scope { challenge += ", scope=\"\(scope)\"" }
        return MCPReply(status: 403, headers: ["WWW-Authenticate": challenge])
    }

    /// A 401 carrying a Bearer challenge for `scope`.
    static func unauthorized(scope: String) -> MCPReply {
        MCPReply(status: 401, headers: ["WWW-Authenticate": "Bearer scope=\"\(scope)\""])
    }

    /// A 200 event stream that announces the legacy SSE message endpoint and never ends.
    ///
    /// Computed so every reply owns a fresh single-consumer stream.
    static var sseStream: MCPReply {
        MCPReply(
            status: 200,
            headers: ["content-type": "text/event-stream"],
            body: .stream(AsyncThrowingStream { continuation in
                continuation.yield(Data("event: endpoint\ndata: https://resource.example.com/messages\n\n".utf8))
            })
        )
    }
}

/// Records the requests the fake MCP endpoint received, in arrival order.
private actor MCPEndpointLog {
    private(set) var requests: [URLRequest] = []

    /// Appends `request` and returns its zero-based index among requests with the same method.
    func record(_ request: URLRequest) -> Int {
        let index = requests.filter { $0.httpMethod == request.httpMethod }.count
        requests.append(request)
        return index
    }

    /// The requests received with `method`.
    func requests(method: String) -> [URLRequest] { requests.filter { $0.httpMethod == method } }
}

/// Builds a fetch that answers MCP URLs from `reply` and everything else from the fake OAuth `server`.
private func makeStepUpFetch(
    server: OAuthServer,
    log: MCPEndpointLog,
    reply: @escaping @Sendable (URLRequest, Int) -> MCPReply
) -> FetchFunction {
    { request in
        let url = try #require(request.url)
        guard url.host == "resource.example.com", !url.path.contains(".well-known") else {
            let (data, response) = try await server.fetch(request)
            return FetchResponse(body: .data(data), urlResponse: response)
        }
        let answer = reply(request, await log.record(request))
        let response = try #require(HTTPURLResponse(url: url, statusCode: answer.status, httpVersion: nil, headerFields: answer.headers))
        return FetchResponse(body: answer.body, urlResponse: response)
    }
}

/// Thread-safe collector for errors reported through `onerror`.
private final class StepUpErrorBox: @unchecked Sendable {
    private let lock = NSLock()
    private var errors: [Error] = []

    /// Records `error`.
    func append(_ error: Error) { lock.withLock { errors.append(error) } }

    /// The errors recorded so far.
    var all: [Error] { lock.withLock { errors } }
}

/// Polls `predicate` until it holds or `timeout` seconds pass.
private func eventually(timeout: TimeInterval = 2, _ predicate: @escaping @Sendable () async -> Bool) async -> Bool {
    let start = Date()
    while Date().timeIntervalSince(start) < timeout {
        if await predicate() { return true }
        try? await Task.sleep(nanoseconds: 10_000_000)
    }
    return await predicate()
}

/// Reads one query item from an authorization URL, decoding `+` as a space.
private func stepUpQueryValue(_ url: URL, name: String) -> String? {
    var components = URLComponents(url: url, resolvingAgainstBaseURL: false)
    if let query = components?.percentEncodedQuery {
        components?.percentEncodedQuery = query.replacingOccurrences(of: "+", with: "%20")
    }
    return components?.queryItems?.first(where: { $0.name == name })?.value
}

/// A notification small enough that a 200 with no body completes the send.
private let stepUpMessage = JSONRPCMessage.notification(JSONRPCNotification(method: "notifications/initialized"))

@Suite("MCP step-up (Streamable HTTP)")
struct HttpStepUpTests {
    private let mcpUrl = "https://resource.example.com/mcp"

    /// Builds a transport over the fake endpoint; `provider` is `nil` for an unauthenticated transport.
    @available(macOS 12.0, iOS 15.0, watchOS 8.0, tvOS 15.0, *)
    private func makeTransport(
        provider: FlowProvider?,
        maxStepUpRetries: Int = 1,
        server: OAuthServer,
        log: MCPEndpointLog,
        reply: @escaping @Sendable (URLRequest, Int) -> MCPReply
    ) throws -> HttpMCPTransport {
        try HttpMCPTransport(config: MCPTransportConfig(
            type: "http", url: mcpUrl, authProvider: provider, maxStepUpRetries: maxStepUpRetries,
            fetch: makeStepUpFetch(server: server, log: log, reply: reply)
        ))
    }

    /// A store holding a token with `scope` and, optionally, a refresh token, pinned to the fake authorization server.
    private func makeStore(scope: String, refreshToken: String? = "stored-refresh") async -> OAuthStore {
        let store = OAuthStore(tokens: OAuthTokens(accessToken: "old-access", tokenType: "Bearer", scope: scope, refreshToken: refreshToken))
        await store.savePin(flowPin())
        return store
    }

    /// When the union stays within the granted scope, step-up refreshes the token and retries the POST once with the new bearer.
    @Test("403 insufficient_scope refreshes and retries the send")
    @available(macOS 12.0, iOS 15.0, watchOS 8.0, tvOS 15.0, *)
    func refreshesAndRetries() async throws {
        let store = await makeStore(scope: "read write")
        let server = OAuthServer()
        let log = MCPEndpointLog()
        let transport = try makeTransport(provider: FlowProvider(store: store), server: server, log: log) { _, index in
            index == 0 ? .insufficientScope("read") : .ok
        }

        try await transport.send(message: stepUpMessage)

        let posts = await log.requests(method: "POST")
        #expect(posts.count == 2)
        #expect(posts[0].value(forHTTPHeaderField: "Authorization") == "Bearer old-access")
        #expect(posts[1].value(forHTTPHeaderField: "Authorization") == "Bearer issued-access")
        let tokenRequests = await server.requests.filter { $0.url?.path == "/token" }
        #expect(tokenRequests.count == 1)
        #expect(String(data: try #require(tokenRequests.first?.httpBody), encoding: .utf8)?.contains("grant_type=refresh_token") == true)
        try await transport.close()
    }

    /// When the challenge widens the grant, step-up skips the refresh, starts a fresh authorization for the union, and surfaces `UnauthorizedError`.
    @Test("403 insufficient_scope beyond the granted scope forces reauthorization")
    @available(macOS 12.0, iOS 15.0, watchOS 8.0, tvOS 15.0, *)
    func forcesReauthorization() async throws {
        let store = await makeStore(scope: "read")
        let server = OAuthServer()
        let log = MCPEndpointLog()
        let transport = try makeTransport(provider: FlowProvider(store: store), server: server, log: log) { _, _ in
            .insufficientScope("write")
        }

        await #expect(throws: UnauthorizedError.self) {
            try await transport.send(message: stepUpMessage)
        }

        #expect(await server.requests.filter { $0.url?.path == "/token" }.isEmpty)
        let redirect = try #require(await store.redirect)
        #expect(stepUpQueryValue(redirect, name: "scope") == "read write")
        let metadataRequest = try #require(await server.requests.first { $0.url?.path.contains("oauth-protected-resource") == true })
        #expect(metadataRequest.url?.absoluteString == stepUpMetadataUrl)
        #expect(await log.requests(method: "POST").count == 1)
        try await transport.close()
    }

    /// A 403 `insufficient_scope` that survives one step-up retry fails with an HTTP error instead of looping.
    @Test("a second 403 insufficient_scope after the retry fails")
    @available(macOS 12.0, iOS 15.0, watchOS 8.0, tvOS 15.0, *)
    func secondForbiddenFails() async throws {
        let store = await makeStore(scope: "read write")
        let server = OAuthServer()
        let log = MCPEndpointLog()
        let transport = try makeTransport(provider: FlowProvider(store: store), server: server, log: log) { _, _ in
            .insufficientScope("read")
        }

        do {
            try await transport.send(message: stepUpMessage)
            Issue.record("Expected the step-up retry limit error")
        } catch let error as MCPClientError {
            #expect(error.statusCode == 403)
            #expect(error.message.contains("after step-up re-authorization"))
        }

        #expect(await log.requests(method: "POST").count == 2)
        #expect(await server.requests.filter { $0.url?.path == "/token" }.count == 1)
        try await transport.close()
    }

    /// `maxStepUpRetries: 0` disables step-up: the first 403 fails without contacting the authorization server.
    @Test("maxStepUpRetries of zero fails the first 403 insufficient_scope")
    @available(macOS 12.0, iOS 15.0, watchOS 8.0, tvOS 15.0, *)
    func zeroRetries() async throws {
        let store = await makeStore(scope: "read write")
        let server = OAuthServer()
        let log = MCPEndpointLog()
        let transport = try makeTransport(provider: FlowProvider(store: store), maxStepUpRetries: 0, server: server, log: log) { _, _ in
            .insufficientScope("read")
        }

        await #expect(throws: MCPClientError.self) {
            try await transport.send(message: stepUpMessage)
        }

        #expect(await log.requests(method: "POST").count == 1)
        #expect(await server.requests.isEmpty)
        try await transport.close()
    }

    /// Without an `authProvider` the challenge is surfaced as `InsufficientScopeError` carrying its parameters.
    @Test("403 insufficient_scope without a provider throws InsufficientScopeError")
    @available(macOS 12.0, iOS 15.0, watchOS 8.0, tvOS 15.0, *)
    func noProvider() async throws {
        let server = OAuthServer()
        let log = MCPEndpointLog()
        let transport = try makeTransport(provider: nil, server: server, log: log) { _, _ in .insufficientScope("read write") }

        do {
            try await transport.send(message: stepUpMessage)
            Issue.record("Expected InsufficientScopeError")
        } catch let error as InsufficientScopeError {
            #expect(error.requiredScope == "read write")
            #expect(error.resourceMetadataUrl?.absoluteString == stepUpMetadataUrl)
            #expect(error.errorDescription == "more scope needed")
        }

        #expect(await log.requests(method: "POST").count == 1)
        try await transport.close()
    }

    /// A 403 that is not an `insufficient_scope` challenge keeps the generic HTTP error and never starts OAuth.
    @Test(
        "other 403 responses keep the generic error",
        arguments: [nil, "Bearer error=\"invalid_token\"", "Basic error=\"insufficient_scope\""] as [String?]
    )
    @available(macOS 12.0, iOS 15.0, watchOS 8.0, tvOS 15.0, *)
    func otherForbidden(challenge: String?) async throws {
        let store = await makeStore(scope: "read write")
        let server = OAuthServer()
        let log = MCPEndpointLog()
        let transport = try makeTransport(provider: FlowProvider(store: store), server: server, log: log) { _, _ in
            MCPReply(status: 403, headers: challenge.map { ["WWW-Authenticate": $0] } ?? [:])
        }

        do {
            try await transport.send(message: stepUpMessage)
            Issue.record("Expected an HTTP error")
        } catch let error as MCPClientError {
            #expect(error.statusCode == 403)
            #expect(error.message.contains("HTTP 403"))
        }

        #expect(await server.requests.isEmpty)
        try await transport.close()
    }

    /// Without a step-up, a 401 authorizes with exactly the scope of its own challenge.
    @Test("401 uses the challenge scope when no step-up happened")
    @available(macOS 12.0, iOS 15.0, watchOS 8.0, tvOS 15.0, *)
    func unauthorizedUsesChallengeScope() async throws {
        let store = await makeStore(scope: "read", refreshToken: nil)
        let server = OAuthServer()
        let transport = try makeTransport(provider: FlowProvider(store: store), server: server, log: MCPEndpointLog()) { _, _ in
            .unauthorized(scope: "admin")
        }

        await #expect(throws: UnauthorizedError.self) {
            try await transport.send(message: stepUpMessage)
        }

        let redirect = try #require(await store.redirect)
        #expect(stepUpQueryValue(redirect, name: "scope") == "admin")
        try await transport.close()
    }

    /// A 401 after a step-up keeps the scope the step-up requested and adds the 401 challenge's scope.
    @Test("401 after a step-up keeps the remembered scope")
    @available(macOS 12.0, iOS 15.0, watchOS 8.0, tvOS 15.0, *)
    func unauthorizedKeepsSteppedUpScope() async throws {
        let store = await makeStore(scope: "read", refreshToken: nil)
        let server = OAuthServer()
        let transport = try makeTransport(provider: FlowProvider(store: store), server: server, log: MCPEndpointLog()) { _, index in
            index == 0 ? .insufficientScope("write") : .unauthorized(scope: "admin")
        }

        await #expect(throws: UnauthorizedError.self) {
            try await transport.send(message: stepUpMessage)
        }
        #expect(stepUpQueryValue(try #require(await store.redirect), name: "scope") == "read write")

        await #expect(throws: UnauthorizedError.self) {
            try await transport.send(message: stepUpMessage)
        }
        #expect(stepUpQueryValue(try #require(await store.redirect), name: "scope") == "read write admin")
        try await transport.close()
    }

    /// The standalone GET event stream reports `InsufficientScopeError` through `onerror` when there is no provider.
    @Test("GET stream 403 insufficient_scope without a provider reports InsufficientScopeError")
    @available(macOS 12.0, iOS 15.0, watchOS 8.0, tvOS 15.0, *)
    func getStreamNoProvider() async throws {
        let log = MCPEndpointLog()
        let transport = try makeTransport(provider: nil, server: OAuthServer(), log: log) { _, _ in .insufficientScope("read") }
        let errors = StepUpErrorBox()
        transport.onerror = { errors.append($0) }

        try await transport.start()

        #expect(await eventually { errors.all.contains { $0 is InsufficientScopeError } })
        #expect(await log.requests(method: "GET").count == 1)
        try await transport.close()
    }

    /// The standalone GET event stream step-up refreshes the token and reopens the stream with the new bearer.
    @Test("GET stream 403 insufficient_scope refreshes and reopens the stream")
    @available(macOS 12.0, iOS 15.0, watchOS 8.0, tvOS 15.0, *)
    func getStreamRefreshes() async throws {
        let store = await makeStore(scope: "read write")
        let server = OAuthServer()
        let log = MCPEndpointLog()
        let transport = try makeTransport(provider: FlowProvider(store: store), server: server, log: log) { _, index in
            index == 0 ? .insufficientScope("read") : MCPReply(status: 405)
        }

        try await transport.start()

        #expect(await eventually { await log.requests(method: "GET").count == 2 })
        let gets = await log.requests(method: "GET")
        #expect(gets.last?.value(forHTTPHeaderField: "Authorization") == "Bearer issued-access")
        #expect(await server.requests.filter { $0.url?.path == "/token" }.count == 1)
        try await transport.close()
    }
}

@Suite("MCP step-up (legacy SSE)")
struct SseStepUpTests {
    private let sseUrl = "https://resource.example.com/mcp"

    /// Builds a transport over the fake endpoint; `provider` is `nil` for an unauthenticated transport.
    @available(macOS 12.0, iOS 15.0, watchOS 8.0, tvOS 15.0, *)
    private func makeTransport(
        provider: FlowProvider?,
        server: OAuthServer,
        log: MCPEndpointLog,
        reply: @escaping @Sendable (URLRequest, Int) -> MCPReply
    ) throws -> SseMCPTransport {
        try SseMCPTransport(config: MCPTransportConfig(
            url: sseUrl, authProvider: provider, fetch: makeStepUpFetch(server: server, log: log, reply: reply)
        ))
    }

    /// Answers the SSE stream with the endpoint event and delegates POSTs to `post`.
    private func sseReply(post: @escaping @Sendable (Int) -> MCPReply) -> @Sendable (URLRequest, Int) -> MCPReply {
        { request, index in request.httpMethod == "POST" ? post(index) : .sseStream }
    }

    /// A POST that draws a 403 `insufficient_scope` is retried after a refresh and then succeeds.
    @Test("POST 403 insufficient_scope refreshes and retries")
    @available(macOS 12.0, iOS 15.0, watchOS 8.0, tvOS 15.0, *)
    func postRefreshesAndRetries() async throws {
        let store = OAuthStore(tokens: OAuthTokens(accessToken: "old-access", tokenType: "Bearer", scope: "read write", refreshToken: "stored-refresh"))
        await store.savePin(flowPin())
        let server = OAuthServer()
        let log = MCPEndpointLog()
        let transport = try makeTransport(provider: FlowProvider(store: store), server: server, log: log, reply: sseReply { index in
            index == 0 ? .insufficientScope("read") : MCPReply(status: 202)
        })

        try await transport.start()
        try await transport.send(message: stepUpMessage)

        let posts = await log.requests(method: "POST")
        #expect(posts.count == 2)
        #expect(posts[1].value(forHTTPHeaderField: "Authorization") == "Bearer issued-access")
        #expect(await server.requests.filter { $0.url?.path == "/token" }.count == 1)
        try await transport.close()
    }

    /// A second 403 `insufficient_scope` after the retry fails the send with an HTTP error.
    @Test("POST second 403 insufficient_scope fails")
    @available(macOS 12.0, iOS 15.0, watchOS 8.0, tvOS 15.0, *)
    func postSecondForbiddenFails() async throws {
        let store = OAuthStore(tokens: OAuthTokens(accessToken: "old-access", tokenType: "Bearer", scope: "read write", refreshToken: "stored-refresh"))
        await store.savePin(flowPin())
        let log = MCPEndpointLog()
        let transport = try makeTransport(provider: FlowProvider(store: store), server: OAuthServer(), log: log, reply: sseReply { _ in
            .insufficientScope("read")
        })

        try await transport.start()
        do {
            try await transport.send(message: stepUpMessage)
            Issue.record("Expected the step-up retry limit error")
        } catch let error as MCPClientError {
            #expect(error.message.contains("after step-up re-authorization"))
        }

        #expect(await log.requests(method: "POST").count == 2)
        try await transport.close()
    }

    /// Without an `authProvider`, a 403 `insufficient_scope` on a POST is surfaced as `InsufficientScopeError`.
    @Test("POST 403 insufficient_scope without a provider throws InsufficientScopeError")
    @available(macOS 12.0, iOS 15.0, watchOS 8.0, tvOS 15.0, *)
    func postNoProvider() async throws {
        let transport = try makeTransport(provider: nil, server: OAuthServer(), log: MCPEndpointLog(), reply: sseReply { _ in
            .insufficientScope("read write")
        })

        try await transport.start()
        do {
            try await transport.send(message: stepUpMessage)
            Issue.record("Expected InsufficientScopeError")
        } catch let error as InsufficientScopeError {
            #expect(error.requiredScope == "read write")
        }
        try await transport.close()
    }

    /// Opening the event stream with a 403 `insufficient_scope` and no provider fails `start()` with `InsufficientScopeError`.
    @Test("stream open 403 insufficient_scope without a provider fails start")
    @available(macOS 12.0, iOS 15.0, watchOS 8.0, tvOS 15.0, *)
    func streamNoProvider() async throws {
        let transport = try makeTransport(provider: nil, server: OAuthServer(), log: MCPEndpointLog()) { _, _ in
            .insufficientScope("read")
        }

        await #expect(throws: InsufficientScopeError.self) {
            try await transport.start()
        }
        try? await transport.close()
    }

    /// Opening the event stream retries after a refresh when the first attempt draws a 403 `insufficient_scope`.
    @Test("stream open 403 insufficient_scope refreshes and reconnects")
    @available(macOS 12.0, iOS 15.0, watchOS 8.0, tvOS 15.0, *)
    func streamRefreshes() async throws {
        let store = OAuthStore(tokens: OAuthTokens(accessToken: "old-access", tokenType: "Bearer", scope: "read write", refreshToken: "stored-refresh"))
        await store.savePin(flowPin())
        let log = MCPEndpointLog()
        let transport = try makeTransport(provider: FlowProvider(store: store), server: OAuthServer(), log: log) { _, index in
            index == 0 ? .insufficientScope("read") : .sseStream
        }

        try await transport.start()

        let gets = await log.requests(method: "GET")
        #expect(gets.count == 2)
        #expect(gets.last?.value(forHTTPHeaderField: "Authorization") == "Bearer issued-access")
        try await transport.close()
    }
}
