import Foundation
import AISDKProvider
import AISDKProviderUtils
import EventSourceParser

/// SSE response handler for `streamGenerateContent` that surfaces a trailing
/// Google error body as an `APICallError`.
///
/// Swift-specific deviation from upstream:
/// Google can accept a stream with HTTP 200 and later end it with a bare JSON
/// error object that has no `data:` prefix, for example
/// `{"error": {"code": 429, "status": "RESOURCE_EXHAUSTED", ...}}`. The SSE
/// parser reports those lines as unknown fields, which upstream ignores, so
/// the stream ends without a finish reason and reads as a silent `other`
/// finish. This handler keeps the unknown-field lines that follow the last
/// event, and when they decode as a Google error body the stream fails with
/// an `APICallError` carrying the error's `code` as its status code, so
/// callers can retry it like a 429 returned before the stream started.
///
/// Otherwise it behaves like `createEventSourceResponseHandler`: `[DONE]`
/// events are skipped, and a failed body read becomes a "Failed to process
/// successful response" `APICallError` (abort errors pass through).
func createGoogleEventSourceResponseHandler<T>(
    chunkSchema: FlexibleSchema<T>
) -> ResponseHandler<AsyncThrowingStream<ParseJSONResult<T>, Error>> {
    { input in
        let response = input.response
        if case .none = response.body {
            throw EmptyResponseBodyError()
        }

        let headers = extractResponseHeaders(from: response.httpResponse)
        let body = response.body.makeStream()

        let stream = AsyncThrowingStream<ParseJSONResult<T>, Error> { continuation in
            let task = Task {
                // The parser calls back synchronously from `feed`, in body
                // order, so clearing `trailingLines` on each event leaves only
                // the lines that follow the last one.
                var eventData: [String] = []
                var trailingLines: [String] = []
                let parser = EventSourceParser(callbacks: ParserCallbacks(
                    onEvent: { event in
                        trailingLines.removeAll()
                        // Ignore the '[DONE]' event that e.g. OpenAI sends
                        if event.data != "[DONE]" {
                            eventData.append(event.data)
                        }
                    },
                    onError: { error in
                        if case .unknownField(_, _, let line) = error.kind {
                            trailingLines.append(line)
                        }
                    }
                ))

                /// Parses and yields the events the last `feed` produced.
                func yieldParsedEvents() async {
                    for data in eventData {
                        continuation.yield(await safeParseJSON(
                            ParseJSONWithSchemaOptions(text: data, schema: chunkSchema)
                        ))
                    }
                    eventData.removeAll()
                }

                do {
                    do {
                        for try await chunk in body {
                            parser.feed(chunk)
                            await yieldParsedEvents()
                        }
                    } catch {
                        throw bodyReadError(error, input: input, responseHeaders: headers)
                    }
                    parser.reset(consume: true)
                    await yieldParsedEvents()

                    if let error = await googleTrailingStreamError(
                        lines: trailingLines,
                        input: input,
                        responseHeaders: headers
                    ) {
                        continuation.finish(throwing: error)
                        return
                    }

                    continuation.finish()
                } catch {
                    continuation.finish(throwing: error)
                }
            }
            continuation.onTermination = { @Sendable _ in task.cancel() }
        }

        return ResponseHandlerResult(value: stream, responseHeaders: headers)
    }
}

/// Wraps a failed body read the way `createEventSourceResponseHandler` does:
/// abort errors pass through, anything else becomes a "Failed to process
/// successful response" `APICallError`, retryable when a network failure
/// caused it.
private func bodyReadError(
    _ error: Error,
    input: ResponseHandlerInput,
    responseHeaders: [String: String]
) -> Error {
    if isAbortError(error) {
        return error
    }
    return handleFetchError(
        error: APICallError(
            message: "Failed to process successful response",
            url: input.url,
            requestBodyValues: input.requestBodyValues,
            statusCode: input.response.statusCode,
            responseHeaders: responseHeaders,
            cause: error
        ),
        url: input.url,
        requestBodyValues: input.requestBodyValues
    )
}

/// Decodes the lines that followed the last SSE event as a Google error body,
/// or returns nil when they are empty or are not one. A non-integral `code`
/// leaves `statusCode` nil rather than trapping.
private func googleTrailingStreamError(
    lines: [String],
    input: ResponseHandlerInput,
    responseHeaders: [String: String]
) async -> APICallError? {
    let body = lines.joined(separator: "\n")
    guard !body.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
          case .success(let data, _) = await safeParseJSON(
              ParseJSONWithSchemaOptions(text: body, schema: googleErrorSchema)
          ) else {
        return nil
    }

    return APICallError(
        message: data.error.message,
        url: input.url,
        requestBodyValues: input.requestBodyValues,
        statusCode: data.error.code.flatMap { Int(exactly: $0) },
        responseHeaders: responseHeaders,
        responseBody: body,
        data: data
    )
}
