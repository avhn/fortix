import Foundation

/// SharedJSON is an ordered JSON tree that keeps nulls and key order for the shared profile format.
/// Foundation's parser silently merges duplicate keys, so sharing uses this strict reader instead.
indirect enum SharedJSON: Equatable {
  /// Object retains members in document order so duplicates and export order stay observable.
  case object([Member])
  /// Array preserves element order.
  case array([SharedJSON])
  /// String is decoded Unicode text.
  case string(String)
  /// Number retains the exact literal so integer fields can reject fractions and exponents.
  case number(String)
  /// Bool distinguishes explicit false from omission.
  case bool(Bool)
  /// Null is parsed so it can be rejected with a stable error rather than a syntax error.
  case null

  /// Member is one object key and its value.
  struct Member: Equatable {
    /// Key is the exact decoded spelling.
    let key: String
    /// Value is the member's parsed value.
    let value: SharedJSON
  }

  /// Members returns object members, or nil for any other value.
  var members: [Member]? {
    if case .object(let members) = self { return members }
    return nil
  }

  /// Subscript returns the first member value for key in an object, or nil when absent.
  subscript(key: String) -> SharedJSON? { members?.first { $0.key == key }?.value }

  /// Encoded writes indented JSON with a final newline, escaping like the helper's encoder.
  func encoded() -> Data {
    var output = ""
    write(to: &output, indent: "")
    output += "\n"
    return Data(output.utf8)
  }

  /// Write appends this value using two-space indentation and stable member order.
  private func write(to output: inout String, indent: String) {
    let inner = indent + "  "
    switch self {
    case .object(let members):
      guard !members.isEmpty else {
        output += "{}"
        return
      }
      output += "{\n"
      for (index, member) in members.enumerated() {
        output += inner
        Self.writeString(member.key, to: &output)
        output += ": "
        member.value.write(to: &output, indent: inner)
        output += index == members.count - 1 ? "\n" : ",\n"
      }
      output += indent + "}"
    case .array(let values):
      guard !values.isEmpty else {
        output += "[]"
        return
      }
      output += "[\n"
      for (index, value) in values.enumerated() {
        output += inner
        value.write(to: &output, indent: inner)
        output += index == values.count - 1 ? "\n" : ",\n"
      }
      output += indent + "]"
    case .string(let text): Self.writeString(text, to: &output)
    case .number(let literal): output += literal
    case .bool(let flag): output += flag ? "true" : "false"
    case .null: output += "null"
    }
  }

  /// WriteString quotes text, escaping controls, HTML-sensitive characters, and line separators.
  private static func writeString(_ text: String, to output: inout String) {
    output += "\""
    for scalar in text.unicodeScalars {
      switch scalar {
      case "\"": output += "\\\""
      case "\\": output += "\\\\"
      case "\n": output += "\\n"
      case "\r": output += "\\r"
      case "\t": output += "\\t"
      case "\u{08}": output += "\\b"
      case "\u{0C}": output += "\\f"
      case "<", ">", "&", "\u{2028}", "\u{2029}":
        output += String(format: "\\u%04x", scalar.value)
      default:
        if scalar.value < 0x20 {
          output += String(format: "\\u%04x", scalar.value)
        } else {
          output.unicodeScalars.append(scalar)
        }
      }
    }
    output += "\""
  }
}

/// SharedJSONParser reads one strict JSON document and checks every key at every depth.
/// Forbidden secret keys fail immediately; duplicate keys and nulls are remembered so a later
/// secret key still takes precedence. Errors are fixed text and never contain document values.
struct SharedJSONParser {
  /// SecretKeys are rejected in any letter case wherever they appear as object keys.
  static let secretKeys: Set<String> = [
    "password", "passwd", "credential", "credentials", "secret", "token", "otp", "cookie",
    "svpncookie",
  ]
  /// MaxDepth bounds recursion far beyond the schema's three levels.
  private static let maxDepth = 128
  /// Bytes is the complete UTF-8 document.
  private let bytes: [UInt8]
  /// Index is the next unread byte.
  private var index = 0
  /// Problem is the first structural ambiguity, reported only if no secret key is found.
  private var problem: SharedProfileError?

  /// Creates a parser over an already size- and encoding-checked document.
  init(_ data: Data) { bytes = Array(data) }

  /// Parse returns the document tree or the highest-precedence fixed error.
  /// Precedence: syntax or secret errors as found, then trailing data, then nulls or duplicates.
  mutating func parse() throws -> SharedJSON {
    let value = try parseValue(depth: 0)
    skipWhitespace()
    guard index == bytes.count else {
      throw SharedProfileError.json("trailing data after document")
    }
    if let problem { throw problem }
    return value
  }

  /// ParseValue consumes one value of any type at the current position.
  private mutating func parseValue(depth: Int) throws -> SharedJSON {
    guard depth < Self.maxDepth else { throw SharedProfileError.json("invalid JSON") }
    skipWhitespace()
    guard let byte = peek() else { throw SharedProfileError.json("invalid JSON") }
    switch byte {
    case UInt8(ascii: "{"): return try parseObject(depth: depth)
    case UInt8(ascii: "["): return try parseArray(depth: depth)
    case UInt8(ascii: "\""): return .string(try parseString())
    case UInt8(ascii: "t"):
      try expect("true")
      return .bool(true)
    case UInt8(ascii: "f"):
      try expect("false")
      return .bool(false)
    case UInt8(ascii: "n"):
      try expect("null")
      if problem == nil {
        problem = SharedProfileError(kind: .field, field: "$", message: "null is not allowed")
      }
      return .null
    default:
      return .number(try parseNumber())
    }
  }

  /// ParseObject reads members, rejecting secret keys before their values are read.
  private mutating func parseObject(depth: Int) throws -> SharedJSON {
    index += 1
    var members: [SharedJSON.Member] = []
    var seen = Set<String>()
    skipWhitespace()
    if peek() == UInt8(ascii: "}") {
      index += 1
      return .object(members)
    }
    while true {
      skipWhitespace()
      guard peek() == UInt8(ascii: "\"") else {
        throw SharedProfileError.json("expected object key")
      }
      let key = try parseString()
      let lower = key.lowercased()
      if Self.secretKeys.contains(lower) {
        throw SharedProfileError(
          kind: .secret, field: lower, message: "secret fields are forbidden")
      }
      if seen.contains(key), problem == nil {
        problem = SharedProfileError(
          kind: .duplicateKey, field: "$", message: "duplicate object key")
      }
      seen.insert(key)
      skipWhitespace()
      guard next() == UInt8(ascii: ":") else { throw SharedProfileError.json("invalid JSON") }
      members.append(.init(key: key, value: try parseValue(depth: depth + 1)))
      skipWhitespace()
      switch next() {
      case UInt8(ascii: ","): continue
      case UInt8(ascii: "}"): return .object(members)
      default: throw SharedProfileError.json("invalid JSON")
      }
    }
  }

  /// ParseArray reads elements in order.
  private mutating func parseArray(depth: Int) throws -> SharedJSON {
    index += 1
    var values: [SharedJSON] = []
    skipWhitespace()
    if peek() == UInt8(ascii: "]") {
      index += 1
      return .array(values)
    }
    while true {
      values.append(try parseValue(depth: depth + 1))
      skipWhitespace()
      switch next() {
      case UInt8(ascii: ","): continue
      case UInt8(ascii: "]"): return .array(values)
      default: throw SharedProfileError.json("invalid JSON")
      }
    }
  }

  /// ParseString decodes escapes, including surrogate pairs; lone surrogates become U+FFFD.
  private mutating func parseString() throws -> String {
    index += 1
    var scalars = String.UnicodeScalarView()
    var raw: [UInt8] = []
    /// Flush moves pending raw UTF-8 bytes into the scalar buffer.
    func flush() {
      scalars.append(contentsOf: String(decoding: raw, as: UTF8.self).unicodeScalars)
      raw.removeAll(keepingCapacity: true)
    }
    while let byte = next() {
      switch byte {
      case UInt8(ascii: "\""):
        flush()
        return String(scalars)
      case UInt8(ascii: "\\"):
        flush()
        guard let escape = next() else { throw SharedProfileError.json("invalid JSON") }
        switch escape {
        case UInt8(ascii: "\""): scalars.append("\"")
        case UInt8(ascii: "\\"): scalars.append("\\")
        case UInt8(ascii: "/"): scalars.append("/")
        case UInt8(ascii: "b"): scalars.append("\u{08}")
        case UInt8(ascii: "f"): scalars.append("\u{0C}")
        case UInt8(ascii: "n"): scalars.append("\n")
        case UInt8(ascii: "r"): scalars.append("\r")
        case UInt8(ascii: "t"): scalars.append("\t")
        case UInt8(ascii: "u"): scalars.append(try parseUnicodeEscape())
        default: throw SharedProfileError.json("invalid JSON")
        }
      case 0..<0x20:
        throw SharedProfileError.json("invalid JSON")
      default:
        raw.append(byte)
      }
    }
    throw SharedProfileError.json("invalid JSON")
  }

  /// ParseUnicodeEscape reads `XXXX` after `\u`, combining a following low surrogate escape.
  private mutating func parseUnicodeEscape() throws -> Unicode.Scalar {
    let first = try parseHex4()
    if (0xD800...0xDBFF).contains(first), bytes.count >= index + 6,
      bytes[index] == UInt8(ascii: "\\"), bytes[index + 1] == UInt8(ascii: "u")
    {
      let saved = index
      index += 2
      let second = try parseHex4()
      if (0xDC00...0xDFFF).contains(second) {
        let value = 0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00)
        return Unicode.Scalar(value) ?? "\u{FFFD}"
      }
      index = saved
    }
    return Unicode.Scalar(first) ?? "\u{FFFD}"
  }

  /// ParseHex4 reads exactly four hexadecimal digits.
  private mutating func parseHex4() throws -> UInt32 {
    var value: UInt32 = 0
    for _ in 0..<4 {
      guard let byte = next(), let digit = Self.hexValue(byte) else {
        throw SharedProfileError.json("invalid JSON")
      }
      value = value << 4 | digit
    }
    return value
  }

  /// ParseNumber validates the JSON number grammar and returns the literal unchanged.
  private mutating func parseNumber() throws -> String {
    let start = index
    if peek() == UInt8(ascii: "-") { index += 1 }
    guard let lead = peek(), Self.isDigit(lead) else {
      throw SharedProfileError.json("invalid JSON")
    }
    index += 1
    if lead != UInt8(ascii: "0") { skipDigits() }
    if peek() == UInt8(ascii: ".") {
      index += 1
      guard try requireDigits() else { throw SharedProfileError.json("invalid JSON") }
    }
    if peek() == UInt8(ascii: "e") || peek() == UInt8(ascii: "E") {
      index += 1
      if peek() == UInt8(ascii: "+") || peek() == UInt8(ascii: "-") { index += 1 }
      guard try requireDigits() else { throw SharedProfileError.json("invalid JSON") }
    }
    return String(decoding: bytes[start..<index], as: UTF8.self)
  }

  /// RequireDigits consumes one or more digits and reports whether any were present.
  private mutating func requireDigits() throws -> Bool {
    guard let byte = peek(), Self.isDigit(byte) else { return false }
    skipDigits()
    return true
  }

  /// SkipDigits consumes consecutive ASCII digits.
  private mutating func skipDigits() {
    while let byte = peek(), Self.isDigit(byte) { index += 1 }
  }

  /// Expect consumes an exact literal keyword.
  private mutating func expect(_ literal: String) throws {
    for expected in literal.utf8 {
      guard next() == expected else { throw SharedProfileError.json("invalid JSON") }
    }
  }

  /// SkipWhitespace consumes the four JSON whitespace bytes only.
  private mutating func skipWhitespace() {
    while let byte = peek(), [0x20, 0x09, 0x0A, 0x0D].contains(byte) { index += 1 }
  }

  /// Peek returns the next byte without consuming it.
  private func peek() -> UInt8? { index < bytes.count ? bytes[index] : nil }

  /// Next consumes and returns one byte.
  private mutating func next() -> UInt8? {
    guard index < bytes.count else { return nil }
    defer { index += 1 }
    return bytes[index]
  }

  /// IsDigit accepts ASCII decimal digits.
  private static func isDigit(_ byte: UInt8) -> Bool { (48...57).contains(byte) }

  /// HexValue maps one ASCII hexadecimal digit to its value.
  private static func hexValue(_ byte: UInt8) -> UInt32? {
    switch byte {
    case 48...57: return UInt32(byte - 48)
    case 65...70: return UInt32(byte - 55)
    case 97...102: return UInt32(byte - 87)
    default: return nil
    }
  }
}
