import Foundation
import Testing
import AISDKProvider
import AISDKProviderUtils
@testable import GoogleProvider

@Suite("GoogleProvider error handling")
struct GoogleErrorHandlingTests {
    @Test("Embedding model extracts message from Google error payload")
    func embeddingModel_extractsErrorMessage() async throws {
        let errorJSON: [String: Any] = [
            "error": [
                "code": 400,
                "message": "bad request from google",
                "status": "INVALID_ARGUMENT"
            ]
        ]
        let errorData = try JSONSerialization.data(withJSONObject: errorJSON)

        let fetch: FetchFunction = { request in
            let url = try #require(request.url)
            let response = try #require(HTTPURLResponse(
                url: url,
                statusCode: 400,
                httpVersion: nil,
                headerFields: ["Content-Type": "application/json"]
            ))
            return FetchResponse(body: .data(errorData), urlResponse: response)
        }

        let model = GoogleGenerativeAIEmbeddingModel(
            modelId: GoogleGenerativeAIEmbeddingModelId(rawValue: "text-embedding-004"),
            config: GoogleGenerativeAIEmbeddingConfig(
                provider: "google.generative-ai",
                baseURL: "https://api.example.com",
                headers: { [:] as [String: String?] },
                fetch: fetch
            )
        )

        do {
            _ = try await model.doEmbed(options: .init(values: ["hello"]))
            Issue.record("Expected APICallError")
        } catch let error as APICallError {
            #expect(error.message == "bad request from google")
            #expect(error.statusCode == 400)
        } catch {
            Issue.record("Expected APICallError, got: \(error)")
        }
    }

    @Test("Embedding model falls back to status text when error.code is missing")
    func embeddingModel_fallsBackWhenErrorCodeMissing() async throws {
        let errorJSON: [String: Any] = [
            "error": [
                "message": "bad request from google",
                "status": "INVALID_ARGUMENT"
            ]
        ]
        let errorData = try JSONSerialization.data(withJSONObject: errorJSON)

        let fetch: FetchFunction = { request in
            let url = try #require(request.url)
            let response = try #require(HTTPURLResponse(
                url: url,
                statusCode: 400,
                httpVersion: nil,
                headerFields: ["Content-Type": "application/json"]
            ))
            return FetchResponse(body: .data(errorData), urlResponse: response)
        }

        let model = GoogleGenerativeAIEmbeddingModel(
            modelId: GoogleGenerativeAIEmbeddingModelId(rawValue: "text-embedding-004"),
            config: GoogleGenerativeAIEmbeddingConfig(
                provider: "google.generative-ai",
                baseURL: "https://api.example.com",
                headers: { [:] as [String: String?] },
                fetch: fetch
            )
        )

        do {
            _ = try await model.doEmbed(options: .init(values: ["hello"]))
            Issue.record("Expected APICallError")
        } catch let error as APICallError {
            #expect(error.statusCode == 400)
            #expect(error.message != "bad request from google")
            #expect(error.data == nil)
        } catch {
            Issue.record("Expected APICallError, got: \(error)")
        }
    }

    // MARK: - Trailing stream errors

    /// Body captured from a real `streamGenerateContent` response: HTTP 200, one
    /// thought chunk, then a bare JSON error object without a `data:` prefix.
    private static let resourceExhaustedStreamBody = """
    data: {"candidates": [{"content": {"role": "model","parts": [{"text": "**Analyzing**\\n\\n","thought": true}]}}],"usageMetadata": {"trafficType": "ON_DEMAND"},"modelVersion": "gemini-3.8-flash","responseId": "resp-1"}

    {

      "error": {

        "code": 429,

        "message": "Resource exhausted. Please try again later. Please refer to https://cloud.google.com/vertex-ai/generative-ai/docs/error-code-429 for more details.",

        "status": "RESOURCE_EXHAUSTED"

      }

    }


    """

    /// Serves `body` as an SSE response, split into `chunkSize`-byte chunks
    /// (the whole body in one chunk when `chunkSize` is nil).
    private static func streamingModel(body: String, chunkSize: Int? = nil) -> GoogleGenerativeAILanguageModel {
        let bytes = Data(body.utf8)
        let chunks: [Data] = chunkSize.map { size in
            stride(from: 0, to: bytes.count, by: size).map { bytes.subdata(in: $0..<min($0 + size, bytes.count)) }
        } ?? [bytes]

        let fetch: FetchFunction = { request in
            let url = try #require(request.url)
            let response = try #require(HTTPURLResponse(
                url: url,
                statusCode: 200,
                httpVersion: "HTTP/1.1",
                headerFields: ["Content-Type": "text/event-stream"]
            ))
            let stream = AsyncThrowingStream<Data, Error> { continuation in
                for chunk in chunks {
                    continuation.yield(chunk)
                }
                continuation.finish()
            }
            return FetchResponse(body: .stream(stream), urlResponse: response)
        }

        return GoogleGenerativeAILanguageModel(
            modelId: GoogleGenerativeAIModelId(rawValue: "gemini-3.8-flash"),
            config: GoogleGenerativeAILanguageModel.Config(
                provider: "google.generative-ai",
                baseURL: "https://generativelanguage.googleapis.com/v1beta",
                headers: { ["x-goog-api-key": "test"] },
                fetch: fetch,
                generateId: { "id" },
                supportedUrls: { [:] }
            )
        )
    }

    private static let prompt: LanguageModelV3Prompt = [
        .user(content: [.text(.init(text: "Hello"))], providerOptions: nil)
    ]

    @Test(
        "doStream fails with APICallError when a 200 stream ends with a Google error body",
        arguments: [nil, 1, 7] as [Int?]
    )
    func doStream_trailingErrorBodyThrowsAPICallError(chunkSize: Int?) async throws {
        let model = Self.streamingModel(body: Self.resourceExhaustedStreamBody, chunkSize: chunkSize)
        let result = try await model.doStream(options: .init(prompt: Self.prompt))

        var parts: [LanguageModelV3StreamPart] = []
        do {
            for try await part in result.stream {
                parts.append(part)
            }
            Issue.record("Expected the stream to throw APICallError")
        } catch let error as APICallError {
            #expect(error.statusCode == 429)
            #expect(error.isRetryable)
            #expect(error.message.hasPrefix("Resource exhausted."))
            #expect((error.data as? GoogleErrorData)?.error.status == "RESOURCE_EXHAUSTED")
        } catch {
            Issue.record("Expected APICallError, got: \(error)")
        }

        #expect(parts.contains { if case .reasoningDelta = $0 { true } else { false } })
        #expect(!parts.contains { if case .finish = $0 { true } else { false } })
    }

    @Test("doStream leaves statusCode nil when the trailing error code is not an integer")
    func doStream_trailingErrorBodyWithNonIntegralCode() async throws {
        let body = """
        data: {"candidates":[{"content":{"parts":[{"text":"Hello"}]}}]}

        {"error": {"code": 1e300, "message": "odd", "status": "UNKNOWN"}}

        """
        let model = Self.streamingModel(body: body)
        let result = try await model.doStream(options: .init(prompt: Self.prompt))

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
    func doStream_ignoresNonErrorTrailingLines() async throws {
        let body = """
        data: {"candidates":[{"content":{"parts":[{"text":"Hello"}]},"finishReason":"STOP"}]}

        not-an-sse-field
        {"unrelated": true}

        """
        let model = Self.streamingModel(body: body)
        let result = try await model.doStream(options: .init(prompt: Self.prompt))

        var finishReason: LanguageModelV3FinishReason?
        for try await part in result.stream {
            if case .finish(let reason, _, _) = part {
                finishReason = reason
            }
        }

        #expect(finishReason?.unified == .stop)
    }

    @Test("doStream only treats lines after the last event as a trailing error body")
    func doStream_unknownLinesBeforeLaterEventsAreDiscarded() async throws {
        let body = """
        {"error": {"code": 429, "message": "stale", "status": "RESOURCE_EXHAUSTED"}}

        data: {"candidates":[{"content":{"parts":[{"text":"Hello"}]},"finishReason":"STOP"}]}


        """
        let model = Self.streamingModel(body: body)
        let result = try await model.doStream(options: .init(prompt: Self.prompt))

        var finishReason: LanguageModelV3FinishReason?
        for try await part in result.stream {
            if case .finish(let reason, _, _) = part {
                finishReason = reason
            }
        }

        #expect(finishReason?.unified == .stop)
    }
}
