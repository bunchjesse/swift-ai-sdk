import Foundation
import AISDKProviderUtils

/// The parsed 403 `insufficient_scope` challenge (SEP-2350) handed to the step-up flow.
internal struct MCPStepUpChallenge: Sendable {
    let scope: String?
    let resourceMetadataUrl: URL?
    let errorDescription: String?
    let responseBody: String?
}

/// Returns the step-up challenge when `response` is a 403 whose `WWW-Authenticate` has `error="insufficient_scope"`.
///
/// Consumes `body` only on a match, so any other 403 keeps flowing through the caller's ordinary
/// error handling with its body intact.
internal func mcpInsufficientScopeChallenge(
    _ response: HTTPURLResponse,
    body: ProviderHTTPResponseBody
) async -> MCPStepUpChallenge? {
    guard response.statusCode == 403 else { return nil }
    let params = extractWWWAuthenticateParams(response)
    guard params.error == "insufficient_scope" else { return nil }
    let data = (try? await body.collectData()) ?? Data()
    return MCPStepUpChallenge(
        scope: params.scope,
        resourceMetadataUrl: params.resourceMetadataUrl,
        errorDescription: params.errorDescription,
        responseBody: String(data: data, encoding: .utf8)
    )
}

/// Owns one transport's OAuth state: the single in-flight authorization shared by concurrent
/// requests, plus the resource metadata URL and scope remembered from challenges.
internal actor MCPTransportAuthorization {
    /// Identifies what an in-flight authorization was started for; only identical flights are shared.
    private enum Flight: Hashable, Sendable {
        case unauthorized
        case stepUp(scope: String?, force: Bool)
    }

    private var pending: (id: UUID, flight: Flight, task: Task<AuthResult, Error>)?
    private var resourceMetadataUrl: URL?
    private var requestedScope: String?

    /// Joins an in-flight authorization of the same `flight`, or waits for a different one to finish and then starts its own.
    private func authorize(
        _ flight: Flight,
        _ operation: @escaping @Sendable () async throws -> AuthResult
    ) async throws -> AuthResult {
        while let current = pending {
            if current.flight == flight { return try await current.task.value }
            _ = try? await current.task.value
            if pending?.id == current.id { pending = nil }
        }
        let id = UUID()
        let task = Task { try await operation() }
        pending = (id, flight, task)
        defer { if pending?.id == id { pending = nil } }
        return try await task.value
    }

    /// Re-authorizes after a 401, remembering the challenge's resource metadata URL and folding its scope into the remembered scope.
    func authorizeAfterUnauthorized(
        provider: any OAuthClientProvider,
        serverUrl: URL,
        challenge: (resourceMetadataUrl: URL?, scope: String?),
        fetch: @escaping MCPFetchFunction
    ) async throws -> AuthResult {
        resourceMetadataUrl = challenge.resourceMetadataUrl
        requestedScope = computeScopeUnion(requestedScope, challenge.scope)
        let scope = requestedScope
        let metadataUrl = resourceMetadataUrl
        return try await authorize(.unauthorized) {
            try await auth(provider, serverUrl: serverUrl, scope: scope, resourceMetadataUrl: metadataUrl, fetchFn: fetch)
        }
    }

    /// Re-authorizes after a 403 `insufficient_scope` challenge (SEP-2350).
    ///
    /// Requests the union of the previously requested scope, the current token's scope, and the
    /// challenge's scope, so earlier grants are not lost. A fresh authorization is forced when the
    /// union exceeds the current token's scope, since a refresh cannot widen it.
    ///
    /// - Parameters:
    ///   - retries: Step-up attempts already made for this request.
    ///   - maxRetries: The step-up attempt limit per request.
    /// - Throws: `InsufficientScopeError` without a `provider`; `MCPClientError` once `retries` reached `maxRetries`.
    func stepUp(
        challenge: MCPStepUpChallenge,
        retries: Int,
        maxRetries: Int,
        provider: (any OAuthClientProvider)?,
        serverUrl: URL,
        fetch: @escaping MCPFetchFunction
    ) async throws -> AuthResult {
        guard let provider else {
            throw InsufficientScopeError(
                requiredScope: challenge.scope,
                resourceMetadataUrl: challenge.resourceMetadataUrl,
                errorDescription: challenge.errorDescription
            )
        }
        guard retries < maxRetries else {
            throw MCPClientError(
                message: "Server returned 403 insufficient_scope after step-up re-authorization (retry limit \(maxRetries) reached)",
                statusCode: 403,
                url: serverUrl.absoluteString,
                responseBody: challenge.responseBody
            )
        }
        if let challengeMetadataUrl = challenge.resourceMetadataUrl { resourceMetadataUrl = challengeMetadataUrl }

        let currentScope = try await provider.tokens()?.scope
        let union = computeScopeUnion(requestedScope, currentScope, challenge.scope)
        requestedScope = union
        let force = isStrictScopeSuperset(union, of: currentScope)
        let metadataUrl = resourceMetadataUrl
        return try await authorize(.stepUp(scope: union, force: force)) {
            try await auth(
                provider, serverUrl: serverUrl, scope: union, resourceMetadataUrl: metadataUrl,
                forceReauthorization: force, fetchFn: fetch
            )
        }
    }
}

internal final class MCPRedirectDelegate: NSObject, URLSessionTaskDelegate, Sendable {
    static let reject = MCPRedirectDelegate()

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping @Sendable (URLRequest?) -> Void
    ) { completionHandler(nil) }
}

internal func mcpSessionFetch(_ session: URLSession) -> FetchFunction {
    { request in
        let (bytes, response) = try await session.bytes(
            for: request,
            delegate: request.fetchRedirectMode == .follow ? nil : MCPRedirectDelegate.reject
        )
        return FetchResponse(body: .stream(mcpDataStream(from: bytes)), urlResponse: response)
    }
}

internal func fetchMCPResponse(_ request: URLRequest, fetch: FetchFunction, redirect: MCPRedirectMode) async throws -> (ProviderHTTPResponseBody, URLResponse) {
    var prepared = request
    prepared.fetchRedirectMode = redirect == .error ? .error : .follow
    try Task.checkCancellation()
    let response = try await fetch(prepared)
    if Task.isCancelled {
        if let url = request.url, let http = response.urlResponse as? HTTPURLResponse {
            await cancelResponseBody(.init(url: url, httpResponse: http, body: response.body))
        }
        throw CancellationError()
    }
    return (response.body, response.urlResponse)
}

internal func mcpOAuthFetch(_ fetch: @escaping FetchFunction) -> MCPFetchFunction {
    { request in
        let response = try await fetch(request)
        guard let http = response.urlResponse as? HTTPURLResponse else {
            throw MCPClientError(message: "Invalid OAuth HTTP response")
        }
        return (try await response.body.collectData(), http)
    }
}

// AsyncThrowingStream pulls this iterator from one consumer task.
private final class MCPByteReader: @unchecked Sendable {
    private var iterator: URLSession.AsyncBytes.Iterator

    init(_ bytes: URLSession.AsyncBytes) { iterator = bytes.makeAsyncIterator() }

    func next() async throws -> Data? {
        var buffer = Data()
        while let byte = try await iterator.next() {
            try Task.checkCancellation()
            buffer.append(byte)
            if buffer.count >= 1024 || byte == 10 { return buffer }
        }
        return buffer.isEmpty ? nil : buffer
    }
}

internal func mcpDataStream(from bytes: URLSession.AsyncBytes) -> AsyncThrowingStream<Data, Error> {
    let reader = MCPByteReader(bytes)
    return AsyncThrowingStream(unfolding: { try await reader.next() })
}
