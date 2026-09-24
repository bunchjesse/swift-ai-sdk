import Foundation
import AISDKProvider
import AISDKProviderUtils
import EventSourceParser

/// SSE response handler for `streamGenerateContent` that surfaces a trailing
/// Google error body as an `APICallError`.
///
/// Swift-specific deviation from upstream (see `upstream/providers/google.md`):
/// Google can accept a stream with HTTP 200 and later end it with a bare JSON
/// error object that has no `data:` prefix, for example
/// `{"error": {"code": 429, "status": "RESOURCE_EXHAUSTED", ...}}`. The SSE
/// parser reports those lines as unknown fields, which upstream ignores, so
/// the stream ends without a finish reason and reads as a silent `other`
/// finish. This handler keeps the unknown-field lines that follow the last
/// event, and when they decode as a Google error body the stream fails with
/// an `APICallError` carrying the error's `code` as its status code.
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
            Task {
                // The parser calls back synchronously from `feed`, in body order,
                // so clearing `trailingLines` on each event leaves only the lines
                // that follow the last one.
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

                func yieldParsedEvents() async {
                    for data in eventData {
                        continuation.yield(await safeParseJSON(
                            ParseJSONWithSchemaOptions(text: data, schema: chunkSchema)
                        ))
                    }
                    eventData.removeAll()
                }

                do {
                    for try await chunk in body {
                        parser.feed(chunk)
                        await yieldParsedEvents()
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
        }

        return ResponseHandlerResult(value: stream, responseHeaders: headers)
    }
}

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
        statusCode: data.error.code.map { Int($0) },
        responseHeaders: responseHeaders,
        responseBody: body,
        data: data
    )
}
