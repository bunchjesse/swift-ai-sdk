import Foundation
import Testing
import AISDKProvider
import AISDKProviderUtils
import GoogleProvider

@Suite("Google API error contracts")
struct GoogleErrorHandlingTests {
    @Test("provider errors retain status, retry classification, and details")
    func providerError() async throws {
        let payload: JSONValue = .object(["error": .object(["code": .number(429), "message": .string("quota exhausted"), "status": .string("RESOURCE_EXHAUSTED"), "details": .array([.object(["retryDelay": .string("1s")])])])])
        let transport = GoogleTransport([.init(try googleData(payload), status: 429)])
        let model = try await transport.provider().embeddingModel(modelId: "gemini-embedding-2")
        do {
            _ = try await model.doEmbed(options: .init(values: ["hello"]))
            Issue.record("expected API error")
        } catch let error as APICallError {
            #expect(error.message == "quota exhausted")
            #expect(error.statusCode == 429)
            #expect(error.isRetryable)
            let data = try #require(error.data as? GoogleErrorData)
            #expect(data.error.details == [.object(["retryDelay": .string("1s")])])
        }
    }

    @Test("malformed API payloads produce typed API errors with validation causes")
    func malformedResponse() async throws {
        let transport = GoogleTransport([.init(Data("{\"candidates\":\"not-an-array\"}".utf8))])
        let model = await transport.provider().chat(modelId: "gemini-3.8-flash")
        do {
            _ = try await model.doGenerate(options: .init(prompt: googlePrompt))
            Issue.record("expected API error")
        } catch let error as APICallError {
            #expect(error.statusCode == 200)
            #expect(error.cause is TypeValidationError)
        }
    }

    // MARK: - Trailing stream error bodies

    /// A stream Google accepted with HTTP 200 that ends, after a thought
    /// chunk, with a bare multi-line error object and no `data:` prefix.
    private static let resourceExhaustedStreamBody = """
    data: {"candidates": [{"content": {"role": "model","parts": [{"text": "**Analyzing**\\n\\n","thought": true}]}}],"usageMetadata": {"trafficType": "ON_DEMAND"},"modelVersion": "gemini-3.8-flash","responseId": "resp-1"}

    {

      "error": {

        "code": 429,

        "message": "Resource exhausted. Please try again later.",

        "status": "RESOURCE_EXHAUSTED"

      }

    }


    """

    /// A chat model whose stream request is answered with `body` as SSE,
    /// split into `chunkSize`-byte chunks (one chunk when `chunkSize` is nil).
    private static func streamingModel(body: String, chunkSize: Int? = nil) -> any LanguageModelV4 {
        let bytes = Data(body.utf8)
        let chunks: [Data] = chunkSize.map { size in
            stride(from: 0, to: bytes.count, by: size).map { bytes.subdata(in: $0..<min($0 + size, bytes.count)) }
        } ?? [bytes]

        let fetch: FetchFunction = { request in
            let url = try #require(request.url)
            let response = try #require(HTTPURLResponse(
                url: url, statusCode: 200, httpVersion: "HTTP/1.1",
                headerFields: ["Content-Type": "text/event-stream"]
            ))
            let stream = AsyncThrowingStream<Data, Error> { continuation in
                for chunk in chunks { continuation.yield(chunk) }
                continuation.finish()
            }
            return FetchResponse(body: .stream(stream), urlResponse: response)
        }
        return createGoogle(settings: .init(
            baseURL: "https://provider.example/v1beta/", apiKey: "test-key",
            fetch: fetch, generateId: { "generated-id" }
        )).chat(modelId: "gemini-3.8-flash")
    }

    /// The finish reason `body` streams to, failing the test if it throws.
    private static func finishReason(streaming body: String) async throws -> LanguageModelV4FinishReason? {
        let result = try await streamingModel(body: body).doStream(options: .init(prompt: googlePrompt))
        var finishReason: LanguageModelV4FinishReason?
        for try await part in result.stream {
            if case .finish(let reason, _, _) = part { finishReason = reason }
        }
        return finishReason
    }

    @Test(
        "doStream fails with a retryable APICallError for a trailing error body",
        arguments: [nil, 1, 7] as [Int?]
    )
    func trailingErrorBodyThrowsAPICallError(chunkSize: Int?) async throws {
        let model = Self.streamingModel(body: Self.resourceExhaustedStreamBody, chunkSize: chunkSize)
        let result = try await model.doStream(options: .init(prompt: googlePrompt))

        var parts: [LanguageModelV4StreamPart] = []
        do {
            for try await part in result.stream { parts.append(part) }
            Issue.record("Expected the stream to throw APICallError")
        } catch let error as APICallError {
            #expect(error.statusCode == 429)
            #expect(error.isRetryable)
            #expect(error.message == "Resource exhausted. Please try again later.")
            #expect((error.data as? GoogleErrorData)?.error.status == "RESOURCE_EXHAUSTED")
        } catch {
            Issue.record("Expected APICallError, got: \(error)")
        }

        #expect(parts.contains { if case .reasoningDelta = $0 { true } else { false } })
        #expect(!parts.contains { if case .finish = $0 { true } else { false } })
    }

    @Test("doStream leaves statusCode nil when the trailing error code is not an integer")
    func trailingErrorBodyWithNonIntegralCode() async throws {
        let body = """
        data: {"candidates":[{"content":{"parts":[{"text":"Hello"}]}}]}

        {"error": {"code": 1e300, "message": "odd", "status": "UNKNOWN"}}

        """
        let result = try await Self.streamingModel(body: body).doStream(options: .init(prompt: googlePrompt))
        do {
            for try await _ in result.stream {}
            Issue.record("Expected the stream to throw APICallError")
        } catch let error as APICallError {
            #expect(error.statusCode == nil)
            #expect(error.message == "odd")
        } catch {
            Issue.record("Expected APICallError, got: \(error)")
        }
    }

    @Test("doStream ignores trailing unknown-field lines that are not a Google error body")
    func ignoresNonErrorTrailingLines() async throws {
        let body = """
        data: {"candidates":[{"content":{"parts":[{"text":"Hello"}]},"finishReason":"STOP"}]}

        not-an-sse-field
        {"unrelated": true}

        """
        #expect(try await Self.finishReason(streaming: body)?.unified == .stop)
    }

    @Test("doStream only treats lines after the last event as a trailing error body")
    func unknownLinesBeforeLaterEventsAreDiscarded() async throws {
        let body = """
        {"error": {"code": 429, "message": "stale", "status": "RESOURCE_EXHAUSTED"}}

        data: {"candidates":[{"content":{"parts":[{"text":"Hello"}]},"finishReason":"STOP"}]}


        """
        #expect(try await Self.finishReason(streaming: body)?.unified == .stop)
    }
}
