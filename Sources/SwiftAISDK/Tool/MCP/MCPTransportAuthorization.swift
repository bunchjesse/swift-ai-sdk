import Foundation

/// Runs one OAuth recovery at a time for a transport, so a POST and the
/// inbound SSE stream that both get a 401 share one `auth()` call instead of
/// racing each other through discovery, client registration, and token
/// refresh. Callers that arrive while a recovery is running await its result;
/// the next 401 after it finishes starts a fresh one.
///
/// Port of `authorizeOnce()` from `packages/mcp/src/tool/mcp-http-transport.ts`
/// (vercel/ai#15518) and the matching SSE fix (vercel/ai#20943), named like
/// the upstream Swift port's `MCPTransportAuthorization`.
internal actor MCPTransportAuthorization {
    /// The recovery in flight, if any.
    private var pending: Task<AuthResult, Error>?

    /// Returns the in-flight recovery's result, or runs `operation` as the
    /// new recovery when none is running.
    func authorize(_ operation: @escaping @Sendable () async throws -> AuthResult) async throws -> AuthResult {
        if let pending { return try await pending.value }
        let task = Task { try await operation() }
        pending = task
        defer { if pending == task { pending = nil } }
        return try await task.value
    }

    /// Cancels the recovery in flight. The recovery runs in its own task, so
    /// cancelling a caller doesn't reach it; a transport calls this from
    /// `close()` so a closed transport stops discovering, registering, or
    /// redirecting to authorization.
    func cancel() {
        pending?.cancel()
        pending = nil
    }
}
