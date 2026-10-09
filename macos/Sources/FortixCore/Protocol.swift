import Foundation

/// CoreError reports fixed, secret-free failures at transport and configuration boundaries.
public enum CoreError: Error, Equatable, Sendable {
  /// Invalid or ambiguous JSON is never reflected into diagnostics.
  case invalidMessage
  /// The encoded record, including its newline, exceeds 64 KiB.
  case oversizedFrame
  /// The helper closed or the client explicitly disconnected.
  case disconnected
  /// A bounded operation did not complete before its deadline.
  case timeout
  /// A slow consumer would lose a helper notification.
  case eventOverflow
  /// The helper uses an unsupported protocol version.
  case incompatibleProtocol
  /// Configuration is invalid before any helper mutation.
  case invalidProfile
  /// A child failed without exposing its output or arguments.
  case commandFailed
  /// A requested tunnel did not stop cleanly or another start superseded it.
  case stopFailed
}

/// JSONValue retains operation-specific payloads without converting objects into JSON strings.
public enum JSONValue: Codable, Equatable, Sendable {
  /// Objects retain exact field spellings.
  case object([String: JSONValue])
  /// Arrays preserve helper ordering.
  case array([JSONValue])
  /// Strings are Unicode payloads, not diagnostic text.
  case string(String)
  /// Signed integers preserve exact values.
  case integer(Int64)
  /// Large attempt identifiers must not lose precision through floating point.
  case unsigned(UInt64)
  /// Booleans distinguish false from omitted fields.
  case bool(Bool)

  /// Decodes a non-null JSON value; malformed or unsupported values throw a decoding error.
  public init(from decoder: Decoder) throws {
    let value = try decoder.singleValueContainer()
    if let object = try? value.decode([String: JSONValue].self) {
      self = .object(object)
    } else if let array = try? value.decode([JSONValue].self) {
      self = .array(array)
    } else if let text = try? value.decode(String.self) {
      self = .string(text)
    } else if let flag = try? value.decode(Bool.self) {
      self = .bool(flag)
    } else if let integer = try? value.decode(Int64.self) {
      self = .integer(integer)
    } else if let integer = try? value.decode(UInt64.self) {
      self = .unsigned(integer)
    } else {
      throw CoreError.invalidMessage
    }
  }

  /// Encodes the underlying JSON type without a wrapper or a secret-bearing description.
  public func encode(to encoder: Encoder) throws {
    var value = encoder.singleValueContainer()
    switch self {
    case .object(let object): try value.encode(object)
    case .array(let array): try value.encode(array)
    case .string(let text): try value.encode(text)
    case .integer(let number): try value.encode(number)
    case .unsigned(let number): try value.encode(number)
    case .bool(let flag): try value.encode(flag)
    }
  }

  /// Converts a typed payload to its wire representation, propagating encoding failures.
  public static func make<T: Encodable>(_ value: T) throws -> JSONValue {
    try JSONDecoder().decode(JSONValue.self, from: JSONEncoder().encode(value))
  }

  /// Decodes an operation-specific payload and returns a fixed error on shape mismatch.
  public func decode<T: Decodable>(_ type: T.Type) throws -> T {
    do { return try JSONDecoder().decode(type, from: JSONEncoder().encode(self)) } catch {
      throw CoreError.invalidMessage
    }
  }
}

/// HelperRequest carries only inline fields recognized by the local helper.
public struct HelperRequest: Codable, Sendable {
  /// ID is replaced by the client with a unique correlation identifier for each call.
  public var id: String
  /// Operation is one of the helper's allowlisted names.
  public var op: String
  /// Version identifies the client during hello.
  public var version: String?
  /// Profile selects a helper-owned profile by safe identifier.
  public var profile: String?
  /// ProfileJSON is a configuration object, never a quoted JSON document.
  public var profileJSON: JSONValue?
  /// All selects every profile for down.
  public var all: Bool?
  /// ChallengeID binds an answer to a pending helper challenge.
  public var challengeID: String?
  /// Secret is transient and must never enter logs or persisted configuration.
  public var secret: String?
  /// Digest is the explicitly accepted certificate hash.
  public var digest: String?
  /// Lines bounds the returned log tail.
  public var lines: Int?
  /// Logs enables log notifications on this subscription.
  public var logs: Bool?

  /// CodingKeys spells the Go protocol fields exactly.
  enum CodingKeys: String, CodingKey {
    case id, op, version, profile, all, secret, digest, lines, logs
    case profileJSON = "profile_json"
    case challengeID = "challenge_id"
  }

  /// Creates an operation with optional inline arguments; encode validates its shape before I/O.
  public init(
    op: String, id: String = "", version: String? = nil, profile: String? = nil,
    profileJSON: JSONValue? = nil, all: Bool? = nil, challengeID: String? = nil,
    secret: String? = nil, digest: String? = nil, lines: Int? = nil, logs: Bool? = nil
  ) {
    self.id = id
    self.op = op
    self.version = version
    self.profile = profile
    self.profileJSON = profileJSON
    self.all = all
    self.challengeID = challengeID
    self.secret = secret
    self.digest = digest
    self.lines = lines
    self.logs = logs
  }

  /// Rejects cross-operation arguments and bounds escaped credentials before sending them.
  public func validate() throws {
    let allowed: [String: Set<String>] = [
      "hello": ["version"], "subscribe": ["logs"], "profile.list": [],
      "profile.get": ["profile"], "profile.put": ["profile_json"],
      "profile.delete": ["profile"], "up": ["profile"], "down": ["profile", "all"],
      "status": [], "answer": ["challenge_id", "secret"], "cancel": ["challenge_id"],
      "trust": ["profile", "digest"], "logs": ["profile", "lines"],
    ]
    guard !id.isEmpty, id.utf8.count <= 128, let fields = allowed[op] else {
      throw CoreError.invalidMessage
    }
    let values: [String: Bool] = [
      "version": !(version ?? "").isEmpty, "profile": !(profile ?? "").isEmpty,
      "profile_json": profileJSON != nil, "all": all == true, "logs": logs == true,
      "challenge_id": !(challengeID ?? "").isEmpty, "secret": !(secret ?? "").isEmpty,
      "digest": !(digest ?? "").isEmpty, "lines": (lines ?? 0) != 0,
    ]
    guard values.allSatisfy({ !$0.value || fields.contains($0.key) }) else {
      throw CoreError.invalidMessage
    }
    if fields.contains("profile"), (profile ?? "").isEmpty, !(op == "down" && all == true) {
      throw CoreError.invalidMessage
    }
    if op == "down", all == true, !(profile ?? "").isEmpty { throw CoreError.invalidMessage }
    if op == "profile.put", case .object = profileJSON {
    } else if op == "profile.put" {
      throw CoreError.invalidMessage
    }
    if fields.contains("challenge_id"), (challengeID ?? "").isEmpty {
      throw CoreError.invalidMessage
    }
    if op == "trust", digest?.utf8.count != 64 { throw CoreError.invalidMessage }
    if op == "logs", !(0...500).contains(lines ?? 0) { throw CoreError.invalidMessage }
    let bytes = Array((secret ?? "").utf8)
    let escapedCount = bytes.count + bytes.filter { [0, 10, 13, 37].contains($0) }.count * 2
    guard escapedCount <= 997 else { throw CoreError.invalidMessage }
  }
}

/// HelperFailure preserves stable error codes and the helper's public, redacted message.
public struct HelperFailure: Error, Codable, Equatable, Sendable {
  /// Code distinguishes invalid, conflict, busy, authorization, and transport-independent failures.
  public let code: String
  /// Message is already sanitized by the helper and is never a raw child output.
  public let message: String
}

/// HelperResult is the single correlated response to one request.
public struct HelperResult: Codable, Sendable {
  /// Type must equal result.
  public let type: String
  /// ID identifies the waiting caller.
  public let id: String
  /// OK distinguishes successful data from a failure.
  public let ok: Bool
  /// Error is present only on failure.
  public let error: HelperFailure?
  /// Data is an optional, operation-specific payload.
  public let data: JSONValue?
}

/// HelperEvent carries a state, challenge, certificate, or redacted log notification.
public struct HelperEvent: Codable, Sendable {
  /// Type chooses the event-specific required fields.
  public let type: String
  /// Profile identifies the affected stored profile.
  public let profile: String
  /// Attempt distinguishes consecutive tunnel generations.
  public let attempt: UInt64
  /// State is present on state transitions.
  public let state: String?
  /// Detail is the public transition explanation.
  public let detail: String?
  /// Code is an optional stable failure category.
  public let code: String?
  /// Wanted records desired connectivity on state transitions.
  public let wanted: Bool?
  /// Initiated says this connection initiated the attempt.
  public let initiated: Bool?
  /// CleanupPending prevents presenting a failed cleanup as disconnected.
  public let cleanupPending: Bool?
  /// ChallengeID identifies a live credential prompt.
  public let challengeID: String?
  /// Kind distinguishes password from second-factor prompts.
  public let kind: String?
  /// Prompt is bounded helper-provided presentation text.
  public let prompt: String?
  /// Digest is the rejected certificate's SHA-256 hash.
  public let digest: String?
  /// Subject is the certificate subject.
  public let subject: String?
  /// Issuer is the certificate issuer.
  public let issuer: String?
  /// Line is one already-redacted log record.
  public let line: String?

  /// CodingKeys retains exact snake_case protocol field names.
  enum CodingKeys: String, CodingKey {
    case type, profile, attempt, state, detail, code, wanted, initiated, kind, prompt
    case digest, subject, issuer, line
    case cleanupPending = "cleanup_pending"
    case challengeID = "challenge_id"
  }
}

/// HelperMessage separates correlated responses from asynchronous notifications.
public enum HelperMessage: Sendable {
  /// Result is delivered to its waiting request rather than the event stream.
  case result(HelperResult)
  /// Event is delivered in arrival order to the bounded notification stream.
  case event(HelperEvent)
}

/// HelperProtocol implements bounded, strict NDJSON independently of a socket transport.
public enum HelperProtocol {
  /// MaxLine includes the terminating newline.
  public static let maxLine = 64 * 1024
  /// Version is negotiated during hello.
  public static let version = 1

  /// Encodes one validated request; invalid or oversized messages never reach the socket.
  public static func encode(_ request: HelperRequest) throws -> Data {
    try request.validate()
    var data = try JSONEncoder().encode(request)
    data.append(10)
    guard data.count <= maxLine else { throw CoreError.oversizedFrame }
    return data
  }

  /// Decodes one complete frame, rejecting unknown fields, duplicates, nulls, and type mismatches.
  public static func decode(_ frame: Data) throws -> HelperMessage {
    guard frame.count <= maxLine else { throw CoreError.oversizedFrame }
    guard frame.last == 10 else { throw CoreError.invalidMessage }
    let object = try StrictJSON.object(frame)
    guard case .string(let type) = object["type"] else { throw CoreError.invalidMessage }
    if type == "result" {
      guard Set(object.keys).isSubset(of: ["type", "id", "ok", "error", "data"]) else {
        throw CoreError.invalidMessage
      }
      let result: HelperResult = try JSONValue.object(object).decode(HelperResult.self)
      guard !result.id.isEmpty, result.id.utf8.count <= 128,
        result.ok ? result.error == nil : result.error != nil && result.data == nil
      else {
        throw CoreError.invalidMessage
      }
      if case .object(let error) = object["error"], Set(error.keys) != ["code", "message"] {
        throw CoreError.invalidMessage
      }
      return .result(result)
    }
    let common: Set<String> = ["type", "profile", "attempt"]
    let required: [String: Set<String>] = [
      "state": ["state", "detail", "wanted", "initiated", "cleanup_pending"],
      "challenge": ["challenge_id", "kind", "prompt"],
      "cert": ["digest", "subject", "issuer"], "log": ["line"],
    ]
    guard let fields = required[type] else { throw CoreError.invalidMessage }
    let keys = Set(object.keys)
    let permitted = common.union(fields).union(type == "state" ? ["code"] : [])
    guard common.union(fields).isSubset(of: keys), keys.isSubset(of: permitted) else {
      throw CoreError.invalidMessage
    }
    return .event(try JSONValue.object(object).decode(HelperEvent.self))
  }
}

/// NDJSONFramer preserves partial records while limiting every frame, including its newline.
public struct NDJSONFramer: Sendable {
  /// Buffer retains only the incomplete record.
  private var buffer = Data()
  /// HasPartialRecord lets the reader bound assembly time without timing out idle subscriptions.
  public var hasPartialRecord: Bool { !buffer.isEmpty }

  /// Creates an empty framer without reading a transport.
  public init() {}

  /// Appends a bounded transport chunk and returns complete records in arrival order.
  public mutating func append(_ chunk: Data) throws -> [Data] {
    var records: [Data] = []
    for byte in chunk {
      guard buffer.count < HelperProtocol.maxLine else { throw CoreError.oversizedFrame }
      buffer.append(byte)
      if byte == 10 {
        records.append(buffer)
        buffer = Data()
      } else if buffer.count == HelperProtocol.maxLine {
        throw CoreError.oversizedFrame
      }
    }
    return records
  }

  /// Rejects EOF in a partially assembled record instead of accepting truncated JSON.
  public func finish() throws {
    guard buffer.isEmpty else { throw CoreError.invalidMessage }
  }
}

/// StrictJSON checks ambiguity before Foundation decoding, which otherwise accepts duplicate keys.
enum StrictJSON {
  /// Object returns an exact non-null object after bounded depth and duplicate-key checks.
  static func object(_ data: Data) throws -> [String: JSONValue] {
    let value = try decode(data)
    guard case .object(let object) = value else { throw CoreError.invalidMessage }
    return object
  }

  /// Decode rejects invalid UTF-8 and ambiguous JSON without including input in errors.
  static func decode(_ data: Data) throws -> JSONValue {
    guard String(data: data, encoding: .utf8) != nil else { throw CoreError.invalidMessage }
    do {
      var scanner = JSONScanner(bytes: Array(data))
      try scanner.value(depth: 0)
      scanner.whitespace()
      guard scanner.index == scanner.bytes.count else { throw CoreError.invalidMessage }
      return try JSONDecoder().decode(JSONValue.self, from: data)
    } catch { throw CoreError.invalidMessage }
  }
}

/// JSONScanner bounds nesting and tracks decoded object keys, including escaped spellings.
private struct JSONScanner {
  /// Bytes are the bounded input being checked.
  let bytes: [UInt8]
  /// Index is the next unread input byte.
  var index = 0

  /// Whitespace advances over only the four JSON whitespace bytes.
  mutating func whitespace() {
    while index < bytes.count, [9, 10, 13, 32].contains(bytes[index]) { index += 1 }
  }

  /// String reads one JSON string and decodes escaped keys for accurate duplicate detection.
  mutating func string() throws -> String {
    guard index < bytes.count, bytes[index] == 34 else { throw CoreError.invalidMessage }
    let start = index
    index += 1
    while index < bytes.count {
      if bytes[index] == 34 {
        index += 1
        return try JSONDecoder().decode(String.self, from: Data(bytes[start..<index]))
      }
      if bytes[index] == 92 { index += 1 }
      index += 1
    }
    throw CoreError.invalidMessage
  }

  /// Consume checks one punctuation byte after whitespace and fails without input disclosure.
  mutating func consume(_ byte: UInt8) throws {
    whitespace()
    guard index < bytes.count, bytes[index] == byte else { throw CoreError.invalidMessage }
    index += 1
  }

  /// Value checks one object, array, or primitive with at most 32 nesting levels.
  mutating func value(depth: Int) throws {
    whitespace()
    guard depth <= 32, index < bytes.count else { throw CoreError.invalidMessage }
    switch bytes[index] {
    case 123:
      index += 1
      var keys = Set<String>()
      whitespace()
      if index < bytes.count, bytes[index] == 125 {
        index += 1
        return
      }
      while true {
        whitespace()
        let key = try string()
        guard keys.insert(key).inserted else { throw CoreError.invalidMessage }
        try consume(58)
        try value(depth: depth + 1)
        whitespace()
        if index < bytes.count, bytes[index] == 125 {
          index += 1
          return
        }
        try consume(44)
      }
    case 91:
      index += 1
      whitespace()
      if index < bytes.count, bytes[index] == 93 {
        index += 1
        return
      }
      while true {
        try value(depth: depth + 1)
        whitespace()
        if index < bytes.count, bytes[index] == 93 {
          index += 1
          return
        }
        try consume(44)
      }
    case 34: _ = try string()
    default:
      let start = index
      while index < bytes.count, ![9, 10, 13, 32, 44, 93, 125].contains(bytes[index]) { index += 1 }
      guard index > start, bytes[start] != 110 else { throw CoreError.invalidMessage }
    }
  }
}
