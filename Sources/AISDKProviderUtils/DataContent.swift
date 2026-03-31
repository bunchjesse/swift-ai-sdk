import Foundation

/**
 Data content representation mirroring `@ai-sdk/provider-utils`.
 */
public enum DataContent: Sendable {
    /// Base64-encoded string
    case string(String)
    /// Raw binary data
    case data(Data)
}

/// Union type for data content or URL inputs (matches upstream usage across packages).
public enum DataContentOrURL: Sendable, Equatable, Codable {
    case data(Data)
    case string(String)
    case url(URL)

    private enum LegacyCodingKeys: String, CodingKey {
        case type
        case data
        case value
        case url
    }

    public init(from decoder: Decoder) throws {
        let singleValue = try decoder.singleValueContainer()

        // Upstream shape is a bare string (base64 or URL)
        if let string = try? singleValue.decode(String.self) {
            if let url = URL(string: string), url.scheme != nil {
                self = .url(url)
            } else {
                self = .string(string)
            }
            return
        }

        // Raw binary data
        if let data = try? singleValue.decode(Data.self) {
            self = .data(data)
            return
        }

        // Backward compat with the wrapper format we previously emitted
        if let keyed = try? decoder.container(keyedBy: LegacyCodingKeys.self),
           let type = try? keyed.decode(String.self, forKey: .type) {
            switch type {
            case "data":
                let base64 = try keyed.decode(String.self, forKey: .data)
                guard let decoded = Data(base64Encoded: base64) else {
                    throw DecodingError.dataCorruptedError(
                        forKey: .data,
                        in: keyed,
                        debugDescription: "Invalid base64 string"
                    )
                }
                self = .data(decoded)
                return
            case "string":
                let value = try keyed.decode(String.self, forKey: .value)
                self = .string(value)
                return
            case "url":
                let url = try keyed.decode(URL.self, forKey: .url)
                self = .url(url)
                return
            default:
                break
            }
        }

        throw DecodingError.dataCorrupted(
            DecodingError.Context(
                codingPath: decoder.codingPath,
                debugDescription: "Cannot decode DataContentOrURL"
            )
        )
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()

        switch self {
        case .string(let value):
            try container.encode(value)
        case .url(let url):
            try container.encode(url.absoluteString)
        case .data(let data):
            try container.encode(data.base64EncodedString())
        }
    }
}
