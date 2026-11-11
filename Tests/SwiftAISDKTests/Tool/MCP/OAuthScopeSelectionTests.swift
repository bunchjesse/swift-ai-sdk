/**
 Tests for MCP OAuth scope selection (SEP-2207), the scope-set helpers, and forced reauthorization.

 Port of the `determineScope`, `computeScopeUnion`, `isStrictScopeSuperset`, and
 `forceReauthorization` cases of the MCP TypeScript SDK `auth.ts` tests.
 */

import Foundation
import Testing

import SwiftAISDK
import AISDKProviderUtils

/// Reads one query item from an authorization URL, decoding `+` as a space.
private func redirectQueryValue(_ url: URL, name: String) -> String? {
    var components = URLComponents(url: url, resolvingAgainstBaseURL: false)
    if let query = components?.percentEncodedQuery {
        components?.percentEncodedQuery = query.replacingOccurrences(of: "+", with: "%20")
    }
    return components?.queryItems?.first(where: { $0.name == name })?.value
}

/// Decodes protected resource metadata advertising `scopes`.
private func makeResourceMetadata(scopes: [String]?) throws -> OAuthProtectedResourceMetadata {
    var json: [String: Any] = ["resource": "https://resource.example.com/mcp"]
    if let scopes { json["scopes_supported"] = scopes }
    return try JSONDecoder().decode(OAuthProtectedResourceMetadata.self, from: JSONSerialization.data(withJSONObject: json))
}

/// Builds authorization server metadata advertising `scopes`.
private func makeAuthServerMetadata(scopes: [String]?) throws -> AuthorizationServerMetadata {
    AuthorizationServerMetadata(
        issuer: "https://auth.example.com",
        authorizationEndpoint: try SafeURL(URL(string: "https://auth.example.com/authorize")!),
        tokenEndpoint: try SafeURL(URL(string: "https://auth.example.com/token")!),
        scopesSupported: scopes,
        responseTypesSupported: ["code"]
    )
}

/// Builds client metadata with the given default scope and grant types.
private func makeClientMetadata(scope: String? = nil, grantTypes: [String]? = nil) throws -> OAuthClientMetadata {
    OAuthClientMetadata(
        redirectUris: [try SafeURL(URL(string: "http://localhost:3000/callback")!)],
        grantTypes: grantTypes, scope: scope
    )
}

@Suite("MCP OAuth scope selection")
struct OAuthScopeSelectionTests {

    // MARK: - determineScope

    /// A non-empty challenge scope outranks protected-resource and client scopes.
    @Test("determineScope prefers the challenge scope")
    func challengeWins() throws {
        let scope = determineScope(
            requestedScope: "challenge.scope",
            resourceMetadata: try makeResourceMetadata(scopes: ["prm.read"]),
            clientMetadata: try makeClientMetadata(scope: "client.scope")
        )
        #expect(scope == "challenge.scope")
    }

    /// Without a challenge scope (or with an empty one), the protected resource's `scopes_supported` is used.
    @Test("determineScope falls back to protected resource scopes", arguments: [nil, ""] as [String?])
    func resourceFallback(requested: String?) throws {
        let scope = determineScope(
            requestedScope: requested,
            resourceMetadata: try makeResourceMetadata(scopes: ["prm.read", "prm.write"]),
            clientMetadata: try makeClientMetadata(scope: "client.scope")
        )
        #expect(scope == "prm.read prm.write")
    }

    /// With no challenge scope and no protected-resource scopes, the client's default scope is used.
    @Test("determineScope falls back to client metadata scope")
    func clientFallback() throws {
        let scope = determineScope(
            resourceMetadata: try makeResourceMetadata(scopes: []),
            clientMetadata: try makeClientMetadata(scope: "client.scope")
        )
        #expect(scope == "client.scope")
    }

    /// `offline_access` is appended only when the authorization server advertises it and the client supports `refresh_token`.
    @Test("determineScope appends offline_access when advertised and refresh_token is a grant type")
    func offlineAccessAppended() throws {
        let scope = determineScope(
            requestedScope: "read",
            authServerMetadata: try makeAuthServerMetadata(scopes: ["read", "offline_access"]),
            clientMetadata: try makeClientMetadata(grantTypes: ["authorization_code", "refresh_token"])
        )
        #expect(scope == "read offline_access")
    }

    /// Each missing precondition on its own suppresses the `offline_access` augmentation.
    @Test(
        "determineScope omits offline_access unless every condition holds",
        arguments: ["no AS advertisement", "AS metadata missing", "no refresh_token grant", "grant types missing"]
    )
    func offlineAccessNotAppended(missing: String) throws {
        let advertised = missing == "no AS advertisement" ? ["read"] : ["read", "offline_access"]
        let authServer = missing == "AS metadata missing" ? nil : try makeAuthServerMetadata(scopes: advertised)
        let grantTypes: [String]? = switch missing {
        case "no refresh_token grant": ["authorization_code"]
        case "grant types missing": nil
        default: ["authorization_code", "refresh_token"]
        }
        let scope = determineScope(
            requestedScope: "read", authServerMetadata: authServer,
            clientMetadata: try makeClientMetadata(grantTypes: grantTypes)
        )
        #expect(scope == "read")
    }

    /// An `offline_access` token already in the selection is not appended a second time.
    @Test("determineScope does not duplicate offline_access")
    func offlineAccessNotDuplicated() throws {
        let scope = determineScope(
            requestedScope: "offline_access read",
            authServerMetadata: try makeAuthServerMetadata(scopes: ["offline_access"]),
            clientMetadata: try makeClientMetadata(grantTypes: ["refresh_token"])
        )
        #expect(scope == "offline_access read")
    }

    /// With nothing to select, the result stays `nil` even if `offline_access` could be appended.
    @Test("determineScope keeps a nil selection nil")
    func nilStaysNil() throws {
        let scope = determineScope(
            authServerMetadata: try makeAuthServerMetadata(scopes: ["offline_access"]),
            clientMetadata: try makeClientMetadata(grantTypes: ["refresh_token"])
        )
        #expect(scope == nil)
    }

    // MARK: - computeScopeUnion / isStrictScopeSuperset

    /// The union keeps each token once, in first-seen order, and splits on any whitespace.
    @Test("computeScopeUnion deduplicates in first-seen order")
    func unionOrder() {
        #expect(computeScopeUnion("read write", nil, "write  admin", "", "read\tlist") == "read write admin list")
    }

    /// The union of nothing, or of only empty scopes, is `nil`.
    @Test("computeScopeUnion returns nil when every input is empty")
    func unionEmpty() {
        #expect(computeScopeUnion() == nil)
        #expect(computeScopeUnion(nil, "", "  ") == nil)
    }

    /// A union is a strict superset only when it holds a token the current scope lacks.
    @Test("isStrictScopeSuperset detects tokens missing from the current scope")
    func strictSuperset() {
        #expect(isStrictScopeSuperset("read write", of: "read"))
        #expect(!isStrictScopeSuperset("read", of: "read write"))
        #expect(!isStrictScopeSuperset("read write", of: "write read"))
    }

    /// An absent or empty current scope is the empty set; an absent or empty union is never a superset.
    @Test("isStrictScopeSuperset treats a missing current scope as empty")
    func strictSupersetEdges() {
        #expect(isStrictScopeSuperset("read", of: nil))
        #expect(isStrictScopeSuperset("read", of: ""))
        #expect(!isStrictScopeSuperset(nil, of: "read"))
        #expect(!isStrictScopeSuperset("", of: nil))
    }

    // MARK: - WWW-Authenticate

    /// `error` and `error_description` are extracted alongside the existing challenge fields, quoted or bare.
    @Test("extractWWWAuthenticateParams returns error and error_description")
    func challengeErrorFields() throws {
        let url = try #require(URL(string: "https://resource.example.com/mcp"))
        let quoted = try #require(HTTPURLResponse(url: url, statusCode: 403, httpVersion: nil, headerFields: [
            "WWW-Authenticate": "Bearer error=\"insufficient_scope\", error_description=\"needs more\", scope=\"read write\", resource_metadata=\"https://resource.example.com/prm\"",
        ]))
        let params = extractWWWAuthenticateParams(quoted)
        #expect(params.error == "insufficient_scope")
        #expect(params.errorDescription == "needs more")
        #expect(params.scope == "read write")
        #expect(params.resourceMetadataUrl?.absoluteString == "https://resource.example.com/prm")

        let bare = try #require(HTTPURLResponse(url: url, statusCode: 403, httpVersion: nil, headerFields: [
            "WWW-Authenticate": "Bearer error=insufficient_scope, scope=\"read\"",
        ]))
        #expect(extractWWWAuthenticateParams(bare).error == "insufficient_scope")
    }

    // MARK: - auth()

    /// `auth` uses the augmented scope for both dynamic registration and the authorization request, and adds `prompt=consent`.
    @Test("auth registers and authorizes with offline_access when the AS advertises it")
    func authAppendsOfflineAccess() async throws {
        let store = OAuthStore(client: nil)
        let provider = try FlowProvider(store: store, separatePin: false, grantTypes: ["authorization_code", "refresh_token"])
        let server = OAuthServer(scopes: ["resource.read"], authorizationServerScopes: ["offline_access"])
        let result = try await auth(provider, serverUrl: server.serverUrl, fetchFn: { try await server.fetch($0) })
        #expect(result == .redirect)
        let redirect = try #require(await store.redirect)
        #expect(redirectQueryValue(redirect, name: "scope") == "resource.read offline_access")
        #expect(redirectQueryValue(redirect, name: "prompt") == "consent")
        let registration = try #require(await server.requests.first { $0.url?.path == "/register" })
        let body = try #require(JSONSerialization.jsonObject(with: registration.httpBody!) as? [String: Any])
        #expect(body["scope"] as? String == "resource.read offline_access")
    }

    /// Without `refresh_token` in the client's grant types, `auth` neither adds `offline_access` nor asks for consent.
    @Test("auth does not add offline_access without the refresh_token grant")
    func authSkipsOfflineAccess() async throws {
        let store = OAuthStore(client: nil)
        let provider = try FlowProvider(store: store, separatePin: false)
        let server = OAuthServer(scopes: ["resource.read"], authorizationServerScopes: ["offline_access"])
        _ = try await auth(provider, serverUrl: server.serverUrl, fetchFn: { try await server.fetch($0) })
        let redirect = try #require(await store.redirect)
        #expect(redirectQueryValue(redirect, name: "scope") == "resource.read")
        #expect(redirectQueryValue(redirect, name: "prompt") == nil)
    }

    /// Control: a stored refresh token is used when reauthorization is not forced.
    @Test("auth refreshes with the stored refresh token by default")
    func authRefreshesByDefault() async throws {
        let store = OAuthStore(tokens: OAuthTokens(accessToken: "old", tokenType: "Bearer", refreshToken: "stored-refresh"))
        await store.savePin(flowPin())
        let server = OAuthServer()
        let result = try await auth(try FlowProvider(store: store), serverUrl: server.serverUrl, fetchFn: { try await server.fetch($0) })
        #expect(result == .authorized)
        let tokenRequests = await server.requests.filter { $0.url?.path == "/token" }
        #expect(tokenRequests.count == 1)
        #expect(await store.redirect == nil)
    }

    /// With `forceReauthorization`, the stored refresh token is never sent and a fresh authorization starts with the given scope.
    @Test("auth with forceReauthorization skips the refresh token")
    func authForceSkipsRefresh() async throws {
        let tokens = OAuthTokens(accessToken: "old", tokenType: "Bearer", scope: "read", refreshToken: "stored-refresh")
        let store = OAuthStore(tokens: tokens)
        await store.savePin(flowPin())
        let server = OAuthServer()
        let result = try await auth(
            try FlowProvider(store: store), serverUrl: server.serverUrl, scope: "read write",
            forceReauthorization: true, fetchFn: { try await server.fetch($0) }
        )
        #expect(result == .redirect)
        #expect(await server.requests.filter { $0.url?.path == "/token" }.isEmpty)
        let redirect = try #require(await store.redirect)
        #expect(redirectQueryValue(redirect, name: "scope") == "read write")
        #expect(await store.savedTokens == tokens)
    }
}
