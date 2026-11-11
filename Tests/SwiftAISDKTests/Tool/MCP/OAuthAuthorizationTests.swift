/**
 Tests for OAuth authorization helpers used by MCP transports.
 
 Port of selected cases from `packages/mcp/src/tool/oauth.test.ts`.
 */

import Foundation
import Testing

@testable import SwiftAISDK

private func queryValue(_ url: URL, name: String) -> String? {
    let components = URLComponents(url: url, resolvingAgainstBaseURL: false)
    return components?.queryItems?.first(where: { $0.name == name })?.value
}

@Suite("MCP OAuth Authorization")
struct OAuthAuthorizationTests {

    private func makeClientInfo() -> OAuthClientInformation {
        OAuthClientInformation(
            clientId: "client123",
            clientSecret: "secret123",
            clientIdIssuedAt: nil,
            clientSecretExpiresAt: nil
        )
    }

    private func makeMetadata(
        responseTypesSupported: [String] = ["code"],
        codeChallengeMethodsSupported: [String]? = ["S256"]
    ) throws -> AuthorizationServerMetadata {
        AuthorizationServerMetadata(
            issuer: "https://auth.example.com",
            authorizationEndpoint: try SafeURL(#require(URL(string: "https://auth.example.com/auth"))),
            tokenEndpoint: try SafeURL(#require(URL(string: "https://auth.example.com/tkn"))),
            registrationEndpoint: nil,
            scopesSupported: nil,
            responseTypesSupported: responseTypesSupported,
            grantTypesSupported: nil,
            codeChallengeMethodsSupported: codeChallengeMethodsSupported,
            tokenEndpointAuthMethodsSupported: nil,
            tokenEndpointAuthSigningAlgValuesSupported: nil
        )
    }

    // MARK: - startAuthorization

    @Test("startAuthorization generates authorization URL with PKCE challenge")
    func startAuthorizationGeneratesAuthorizationURL() throws {
        let authorizationServerUrl = try #require(URL(string: "https://auth.example.com"))
        let redirectUrl = try #require(URL(string: "http://localhost:3000/callback"))
        let resource = try #require(URL(string: "https://api.example.com/mcp-server"))

        let result = try startAuthorization(
            authorizationServerUrl: authorizationServerUrl,
            metadata: nil,
            clientInformation: makeClientInfo(),
            redirectUrl: redirectUrl,
            scope: nil,
            state: nil,
            resource: resource
        )

        #expect(result.authorizationUrl.absoluteString.hasPrefix("https://auth.example.com/authorize?"))
        #expect(queryValue(result.authorizationUrl, name: "response_type") == "code")
        #expect(queryValue(result.authorizationUrl, name: "client_id") == "client123")
        #expect(queryValue(result.authorizationUrl, name: "code_challenge_method") == "S256")
        #expect(queryValue(result.authorizationUrl, name: "redirect_uri") == "http://localhost:3000/callback")
        #expect(queryValue(result.authorizationUrl, name: "resource") == "https://api.example.com/mcp-server")

        let codeChallenge = queryValue(result.authorizationUrl, name: "code_challenge") ?? ""
        #expect(!codeChallenge.isEmpty)
        #expect(!result.codeVerifier.isEmpty)
    }

    @Test("startAuthorization includes scope parameter when provided")
    func startAuthorizationIncludesScope() throws {
        let result = try startAuthorization(
            authorizationServerUrl: #require(URL(string: "https://auth.example.com")),
            metadata: nil,
            clientInformation: makeClientInfo(),
            redirectUrl: #require(URL(string: "http://localhost:3000/callback")),
            scope: "read write profile",
            state: nil,
            resource: nil
        )

        #expect(queryValue(result.authorizationUrl, name: "scope") == "read write profile")
    }

    @Test("startAuthorization excludes scope parameter when not provided")
    func startAuthorizationExcludesScope() throws {
        let result = try startAuthorization(
            authorizationServerUrl: #require(URL(string: "https://auth.example.com")),
            metadata: nil,
            clientInformation: makeClientInfo(),
            redirectUrl: #require(URL(string: "http://localhost:3000/callback")),
            scope: nil,
            state: nil,
            resource: nil
        )

        #expect(queryValue(result.authorizationUrl, name: "scope") == nil)
    }

    @Test("startAuthorization includes state parameter when provided")
    func startAuthorizationIncludesState() throws {
        let result = try startAuthorization(
            authorizationServerUrl: #require(URL(string: "https://auth.example.com")),
            metadata: nil,
            clientInformation: makeClientInfo(),
            redirectUrl: #require(URL(string: "http://localhost:3000/callback")),
            scope: nil,
            state: "foobar",
            resource: nil
        )

        #expect(queryValue(result.authorizationUrl, name: "state") == "foobar")
    }

    @Test("startAuthorization excludes state parameter when not provided")
    func startAuthorizationExcludesState() throws {
        let result = try startAuthorization(
            authorizationServerUrl: #require(URL(string: "https://auth.example.com")),
            metadata: nil,
            clientInformation: makeClientInfo(),
            redirectUrl: #require(URL(string: "http://localhost:3000/callback")),
            scope: nil,
            state: nil,
            resource: nil
        )

        #expect(queryValue(result.authorizationUrl, name: "state") == nil)
    }

    @Test("startAuthorization includes consent prompt parameter if scope includes offline_access")
    func startAuthorizationOfflineAccessAddsPrompt() throws {
        let result = try startAuthorization(
            authorizationServerUrl: #require(URL(string: "https://auth.example.com")),
            metadata: nil,
            clientInformation: makeClientInfo(),
            redirectUrl: #require(URL(string: "http://localhost:3000/callback")),
            scope: "read write profile offline_access",
            state: nil,
            resource: nil
        )

        #expect(queryValue(result.authorizationUrl, name: "prompt") == "consent")
    }

    @Test("startAuthorization uses metadata authorization_endpoint when provided")
    func startAuthorizationUsesAuthorizationEndpointFromMetadata() throws {
        let metadata = try makeMetadata()

        let result = try startAuthorization(
            authorizationServerUrl: #require(URL(string: "https://auth.example.com")),
            metadata: metadata,
            clientInformation: makeClientInfo(),
            redirectUrl: #require(URL(string: "http://localhost:3000/callback")),
            scope: nil,
            state: nil,
            resource: nil
        )

        #expect(result.authorizationUrl.absoluteString.hasPrefix("https://auth.example.com/auth?"))
    }

    @Test("startAuthorization validates response type support")
    func startAuthorizationValidatesResponseType() throws {
        let metadata = try makeMetadata(responseTypesSupported: ["token"])

        do {
            _ = try startAuthorization(
                authorizationServerUrl: #require(URL(string: "https://auth.example.com")),
                metadata: metadata,
                clientInformation: makeClientInfo(),
                redirectUrl: #require(URL(string: "http://localhost:3000/callback")),
                scope: nil,
                state: nil,
                resource: nil
            )
            Issue.record("Expected error")
        } catch let error as MCPClientError {
            #expect(error.message.contains("does not support response type"))
        }
    }

    @Test("startAuthorization validates PKCE support")
    func startAuthorizationValidatesPKCE() throws {
        let metadata = try makeMetadata(
            responseTypesSupported: ["code"],
            codeChallengeMethodsSupported: ["plain"]
        )

        do {
            _ = try startAuthorization(
                authorizationServerUrl: #require(URL(string: "https://auth.example.com")),
                metadata: metadata,
                clientInformation: makeClientInfo(),
                redirectUrl: #require(URL(string: "http://localhost:3000/callback")),
                scope: nil,
                state: nil,
                resource: nil
            )
            Issue.record("Expected error")
        } catch let error as MCPClientError {
            #expect(error.message.contains("does not support code challenge method"))
        }
    }

    // MARK: - parseErrorResponse

    @Test("parseErrorResponse maps known OAuth error codes to MCPClientOAuthError types")
    func parseErrorResponseMapsKnownErrorCodes() throws {
        let body = """
        {"error":"invalid_client","error_description":"nope"}
        """

        let error = parseErrorResponse(statusCode: 400, body: body)
        #expect(error is InvalidClientError)

        let typed = try #require(error as? InvalidClientError)
        #expect(typed.message == "nope")
    }

    @Test("parseErrorResponse defaults to ServerError for unknown error codes")
    func parseErrorResponseUnknownErrorDefaultsToServerError() throws {
        let body = """
        {"error":"some_new_error","error_description":"wat"}
        """

        let error = parseErrorResponse(statusCode: 400, body: body)
        #expect(error is ServerError)

        let typed = try #require(error as? ServerError)
        #expect(typed.message == "wat")
    }

    @Test("parseErrorResponse returns ServerError on invalid JSON body with raw body included")
    func parseErrorResponseInvalidJSONBody() throws {
        let body = "not-json"

        let error = parseErrorResponse(statusCode: 400, body: body)
        let typed = try #require(error as? ServerError)

        #expect(typed.message.contains("HTTP 400: Invalid OAuth error response:"))
        #expect(typed.message.contains("Raw body: not-json"))
    }

    // MARK: - auth scope selection

    /// Runs `auth()` against a mock resource and authorization server, and
    /// returns the scope sent to dynamic client registration and the scope
    /// on the resulting authorization URL.
    private func runAuthScopeSelection(
        challengeScope: String?,
        resourceScopes: [String]?,
        clientScope: String?
    ) async throws -> (registeredScope: String?, authorizationScope: String?) {
        let serverUrl = try #require(URL(string: "https://resource.example.com/mcp"))
        let registeredScope = ScopeTestBox<String?>(nil)

        let fetchFn: MCPFetchFunction = { request in
            let url = try #require(request.url)
            let path = url.path
            func respond(_ status: Int, _ body: [String: Any]) throws -> (Data, HTTPURLResponse) {
                let response = try #require(HTTPURLResponse(url: url, statusCode: status, httpVersion: nil, headerFields: [
                    "Content-Type": "application/json",
                ]))
                return (try JSONSerialization.data(withJSONObject: body), response)
            }

            if path.hasPrefix("/.well-known/oauth-protected-resource") {
                var body: [String: Any] = [
                    "resource": "https://resource.example.com/mcp",
                    "authorization_servers": ["https://auth.example.com"],
                ]
                if let resourceScopes { body["scopes_supported"] = resourceScopes }
                return try respond(200, body)
            }
            if path.hasPrefix("/.well-known/oauth-authorization-server") {
                return try respond(200, [
                    "issuer": "https://auth.example.com",
                    "authorization_endpoint": "https://auth.example.com/authorize",
                    "token_endpoint": "https://auth.example.com/token",
                    "registration_endpoint": "https://auth.example.com/register",
                    "response_types_supported": ["code"],
                    "code_challenge_methods_supported": ["S256"],
                ])
            }
            if path == "/register" {
                let body = try #require(request.httpBody)
                let json = try #require(try JSONSerialization.jsonObject(with: body) as? [String: Any])
                registeredScope.set(json["scope"] as? String)
                return try respond(201, ["client_id": "registered-client", "redirect_uris": ["http://127.0.0.1:3000/callback"]])
            }
            return try respond(404, [:])
        }

        let provider = try ScopeTestProvider(clientScope: clientScope)
        let result = try await auth(
            provider,
            serverUrl: serverUrl,
            scope: challengeScope,
            fetchFn: fetchFn
        )
        #expect(result == .redirect)
        #expect(provider.savedClientId.get() == "registered-client")

        let authorizationUrl = try #require(provider.authorizationUrl.get())
        return (registeredScope.get(), queryValue(authorizationUrl, name: "scope"))
    }

    @Test("auth prefers the WWW-Authenticate challenge scope for registration and authorization")
    func authPrefersChallengeScope() async throws {
        let scopes = try await runAuthScopeSelection(
            challengeScope: "mcp.challenge",
            resourceScopes: ["mcp.read", "mcp.write"],
            clientScope: "client.scope"
        )
        #expect(scopes.registeredScope == "mcp.challenge")
        #expect(scopes.authorizationScope == "mcp.challenge")
    }

    @Test("auth falls back to protected resource scopes_supported")
    func authFallsBackToResourceScopes() async throws {
        let scopes = try await runAuthScopeSelection(
            challengeScope: nil,
            resourceScopes: ["mcp.read", "mcp.write"],
            clientScope: "client.scope"
        )
        #expect(scopes.registeredScope == "mcp.read mcp.write")
        #expect(scopes.authorizationScope == "mcp.read mcp.write")
    }

    @Test("auth falls back to client metadata scope when the server advertises none")
    func authFallsBackToClientScope() async throws {
        let scopes = try await runAuthScopeSelection(
            challengeScope: "",
            resourceScopes: [],
            clientScope: "client.scope"
        )
        #expect(scopes.registeredScope == "client.scope")
        #expect(scopes.authorizationScope == "client.scope")
    }

    @Test("auth omits scope when none is advertised or configured")
    func authOmitsScopeWhenNoneAvailable() async throws {
        let scopes = try await runAuthScopeSelection(
            challengeScope: nil,
            resourceScopes: nil,
            clientScope: nil
        )
        #expect(scopes.registeredScope == nil)
        #expect(scopes.authorizationScope == nil)
    }
}

/// A lock-guarded value the `@Sendable` fetch and provider closures can write.
private final class ScopeTestBox<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Value

    init(_ value: Value) {
        self.value = value
    }

    func get() -> Value { lock.withLock { value } }
    func set(_ newValue: Value) { lock.withLock { value = newValue } }
}

/// An in-memory OAuth provider with no stored client or tokens, so `auth()`
/// always registers dynamically and ends at the authorization redirect.
private final class ScopeTestProvider: OAuthClientProvider, @unchecked Sendable {
    let redirectUrl = URL(string: "http://127.0.0.1:3000/callback")!
    let clientMetadata: OAuthClientMetadata
    let savedClientId = ScopeTestBox<String?>(nil)
    let authorizationUrl = ScopeTestBox<URL?>(nil)
    private let verifier = ScopeTestBox<String>("")

    init(clientScope: String?) throws {
        var json: [String: Any] = [
            "redirect_uris": ["http://127.0.0.1:3000/callback"],
            "token_endpoint_auth_method": "none",
        ]
        if let clientScope { json["scope"] = clientScope }
        clientMetadata = try JSONDecoder().decode(
            OAuthClientMetadata.self,
            from: JSONSerialization.data(withJSONObject: json)
        )
    }

    func tokens() async throws -> OAuthTokens? { nil }
    func saveTokens(_ tokens: OAuthTokens) async throws {}
    func redirectToAuthorization(_ authorizationUrl: URL) async throws { self.authorizationUrl.set(authorizationUrl) }
    func saveCodeVerifier(_ codeVerifier: String) async throws { verifier.set(codeVerifier) }
    func codeVerifier() async throws -> String { verifier.get() }
    func clientInformation() async throws -> OAuthClientInformation? { nil }

    var saveClientInformation: OAuthSaveClientInformation? {
        { [savedClientId] information in savedClientId.set(information.clientId) }
    }
}

