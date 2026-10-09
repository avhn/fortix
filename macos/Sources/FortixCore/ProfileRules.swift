import Darwin
import Foundation

/// ProfileFieldProblem describes one invalid configuration field without echoing its value.
/// Field uses the helper's JSON path spelling, including list indexes such as `dns.domains[0]`.
public struct ProfileFieldProblem: Equatable, Sendable {
  /// Field is the JSON path of the rejected value.
  public let field: String
  /// Message is a fixed explanation that never contains supplied input.
  public let message: String

  /// Creates a problem from a schema path and a fixed explanation.
  public init(field: String, message: String) {
    self.field = field
    self.message = message
  }
}

/// ProfileRules mirrors the helper's full-profile validation so clients can explain failures locally.
/// The helper remains authoritative; these rules only report problems earlier and per field.
public enum ProfileRules {
  /// Problems returns every invalid field in helper order, or an empty list for a valid profile.
  /// Absent optional strings are treated as empty, and an omitted port as the default 443.
  /// It never normalizes input: callers normalize lists and certificate pins before validating.
  public static func problems(_ profile: VPNProfile) -> [ProfileFieldProblem] {
    var problems: [ProfileFieldProblem] = []
    let add = { (field: String, message: String) in
      problems.append(ProfileFieldProblem(field: field, message: message))
    }
    if profile.schemaVersion != 1 { add("schema_version", "must be 1") }
    if !validID(profile.id) { add("id", "must match ^[a-z0-9][a-z0-9-]{0,62}$") }
    if !validText(profile.name, min: 1, max: 64) {
      add("name", "must be 1..64 characters with no control characters")
    }
    if let backend = profile.backend, !["", "native", "openfortivpn"].contains(backend) {
      add("backend", "must be native or openfortivpn")
    }
    if profile.backend == "native" && profile.mfa.mode != "none" {
      add("backend", "native requires mfa.mode none; use openfortivpn for second factors")
    }
    if !validIPLiteral(profile.gateway.host) && !validDNSName(profile.gateway.host) {
      add("gateway.host", "must be a DNS hostname or an unscoped IP literal")
    }
    if !(1...65535).contains(profile.gateway.port ?? 443) {
      add("gateway.port", "must be 1..65535")
    }
    let realm = profile.realm ?? ""
    if realm.unicodeScalars.count > 64 || !realm.unicodeScalars.allSatisfy(isRealmScalar) {
      add(
        "realm",
        "must be at most 64 characters from A-Z, a-z, 0-9, dot, underscore, or hyphen")
    }
    if !validText(profile.username, min: 1, max: 256)
      || profile.username.trimmingCharacters(in: .whitespacesAndNewlines) != profile.username
    {
      add("username", "must be 1..256 characters without controls or whitespace at ends")
    }
    if let pin = profile.trustedCert, !pin.isEmpty, normalizedPin(pin) == nil {
      add("trusted_cert", "must be 64 lowercase hexadecimal characters")
    }
    mfaProblems(profile.mfa, add: add)
    routeModeProblems(profile.routes, add: add)
    for (index, message) in routeProblems(profile.routes.include ?? []) {
      add("routes.include[\(index)]", message)
    }
    dnsModeProblems(profile.dns, add: add)
    for (index, message) in domainProblems(profile.dns.domains ?? []) {
      add("dns.domains[\(index)]", message)
    }
    return problems
  }

  /// RouteProblems reports each malformed, non-canonical, too broad, duplicate, or overlapping prefix.
  /// Results pair a list index with its first-found messages in helper order; valid lists return none.
  public static func routeProblems(_ include: [String]) -> [(index: Int, message: String)] {
    var problems: [(index: Int, message: String)] = []
    var previous: [(address: UInt32, bits: Int)] = []
    for (index, text) in include.enumerated() {
      guard let prefix = parseIPv4Prefix(text) else {
        problems.append((index, "must be an IPv4 CIDR"))
        continue
      }
      if prefix.address != mask(prefix.address, bits: prefix.bits) {
        problems.append((index, "must be a canonical masked prefix"))
      }
      if prefix.bits < 8 { problems.append((index, "prefixes /0 through /7 are too broad")) }
      for earlier in previous {
        if earlier.address == prefix.address && earlier.bits == prefix.bits {
          problems.append((index, "duplicate prefix"))
          break
        }
        let shortest = min(earlier.bits, prefix.bits)
        if mask(earlier.address, bits: shortest) == mask(prefix.address, bits: shortest) {
          problems.append((index, "overlaps another included prefix"))
          break
        }
      }
      previous.append(prefix)
    }
    return problems
  }

  /// DomainProblems reports each invalid or duplicate split DNS domain by list index.
  /// Domains must already be normalized; wildcards and uppercase spellings are rejected.
  public static func domainProblems(_ domains: [String]) -> [(index: Int, message: String)] {
    var problems: [(index: Int, message: String)] = []
    var seen = Set<String>()
    for (index, domain) in domains.enumerated() {
      if !validDNSName(domain) || !domain.contains(".") || domain.lowercased() != domain {
        problems.append(
          (
            index,
            "must be a lowercase DNS name with at least two labels, without trailing dot or wildcard"
          ))
      }
      if seen.contains(domain) { problems.append((index, "duplicate domain")) }
      seen.insert(domain)
    }
    return problems
  }

  /// NormalizeDomain lowercases a domain and removes one leading wildcard label.
  /// Multiple wildcards stay invalid, and whitespace is not trimmed, matching the helper.
  public static func normalizeDomain(_ domain: String) -> String {
    let lower = domain.lowercased()
    if lower.hasPrefix("*."), !lower.dropFirst(2).contains("*") {
      return String(lower.dropFirst(2))
    }
    return lower
  }

  /// NormalizePrefix trims whitespace and masks host bits of a valid IPv4 prefix.
  /// Malformed text is only trimmed so validation still reports it.
  public static func normalizePrefix(_ text: String) -> String {
    let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
    guard let prefix = parseIPv4Prefix(trimmed) else { return trimmed }
    return format(mask(prefix.address, bits: prefix.bits), bits: prefix.bits)
  }

  /// NormalizedPin returns a valid certificate pin in lowercase without colons, or nil if invalid.
  public static func normalizedPin(_ pin: String) -> String? {
    let normalized = pin.replacingOccurrences(of: ":", with: "").lowercased()
    guard normalized.utf8.count == 64, normalized.utf8.allSatisfy(isLowerHex) else { return nil }
    return normalized
  }

  /// ValidID checks the helper's identifier alphabet without regular expression line anchors.
  static func validID(_ id: String) -> Bool {
    let bytes = Array(id.utf8)
    guard (1...63).contains(bytes.count), isLowerAlnum(bytes[0]) else { return false }
    return bytes.dropFirst().allSatisfy { isLowerAlnum($0) || $0 == UInt8(ascii: "-") }
  }

  /// MFAProblems reports mode and TOTP parameter errors; other modes forbid every parameter.
  private static func mfaProblems(_ mfa: VPNProfile.MFA, add: (String, String) -> Void) {
    switch mfa.mode {
    case "totp":
      if mfa.digits != 6 && mfa.digits != 8 { add("mfa.digits", "must be 6 or 8") }
      if !(15...120).contains(mfa.period ?? 0) { add("mfa.period", "must be 15..120") }
      if !["SHA1", "SHA256", "SHA512"].contains(mfa.algorithm ?? "") {
        add("mfa.algorithm", "must be SHA1, SHA256, or SHA512")
      }
    case "none", "push", "prompt", "static":
      break
    default:
      add("mfa.mode", "must be none, push, prompt, totp, or static")
    }
    if mfa.mode != "totp" {
      if mfa.digits != nil { add("mfa.digits", "only allowed for totp") }
      if mfa.period != nil { add("mfa.period", "only allowed for totp") }
      if mfa.algorithm != nil { add("mfa.algorithm", "only allowed for totp") }
    }
  }

  /// RouteModeProblems reports an unknown routing mode or a list incompatible with the mode.
  private static func routeModeProblems(_ routes: VPNProfile.Routes, add: (String, String) -> Void)
  {
    switch routes.mode {
    case "gateway", "full":
      if routes.include != nil { add("routes.include", "only allowed for custom") }
    case "custom":
      if (routes.include ?? []).isEmpty {
        add("routes.include", "custom requires a non-empty list")
      }
    default:
      add("routes.mode", "must be gateway, custom, or full")
    }
  }

  /// DNSModeProblems reports an unknown DNS mode or a domain count incompatible with the mode.
  private static func dnsModeProblems(_ dns: VPNProfile.DNS, add: (String, String) -> Void) {
    switch dns.mode {
    case "none":
      if dns.domains != nil { add("dns.domains", "only allowed for split") }
    case "split":
      if !(1...32).contains(dns.domains?.count ?? 0) {
        add("dns.domains", "split requires 1..32 domains")
      }
    default:
      add("dns.mode", "must be none or split")
    }
  }

  /// ValidText accepts min...max Unicode scalars and rejects control characters.
  private static func validText(_ text: String, min: Int, max: Int) -> Bool {
    (min...max).contains(text.unicodeScalars.count)
      && !text.unicodeScalars.contains { $0.properties.generalCategory == .control }
  }

  /// ValidDNSName checks an ASCII name's length and letter, digit, and hyphen label boundaries.
  /// It rejects schemes, ports, paths, empty labels, trailing dots, and wildcards.
  static func validDNSName(_ host: String) -> Bool {
    let bytes = Array(host.utf8)
    guard (1...253).contains(bytes.count) else { return false }
    let hyphen = UInt8(ascii: "-")
    for label in bytes.split(separator: UInt8(ascii: "."), omittingEmptySubsequences: false) {
      guard (1...63).contains(label.count), label.first != hyphen, label.last != hyphen else {
        return false
      }
      for byte in label where !isLowerAlnum(byte) && !isUpper(byte) && byte != hyphen {
        return false
      }
    }
    return true
  }

  /// ValidIPLiteral accepts IPv4 or IPv6 addresses without zones, ports, or brackets.
  private static func validIPLiteral(_ host: String) -> Bool {
    if parseIPv4(host) != nil { return true }
    guard !host.contains("%") else { return false }
    var address = in6_addr()
    return host.withCString { inet_pton(AF_INET6, $0, &address) } == 1
  }

  /// ParseIPv4Prefix accepts `a.b.c.d/n` with strict decimal octets and no leading zeros.
  private static func parseIPv4Prefix(_ text: String) -> (address: UInt32, bits: Int)? {
    let parts = text.split(separator: "/", omittingEmptySubsequences: false)
    guard parts.count == 2, let address = parseIPv4(String(parts[0])),
      let bits = strictDecimal(parts[1], max: 32)
    else { return nil }
    return (address, bits)
  }

  /// ParseIPv4 accepts exactly four decimal octets without leading zeros or signs.
  private static func parseIPv4(_ text: String) -> UInt32? {
    let parts = text.split(separator: ".", omittingEmptySubsequences: false)
    guard parts.count == 4 else { return nil }
    var address: UInt32 = 0
    for part in parts {
      guard let octet = strictDecimal(part, max: 255) else { return nil }
      address = address << 8 | UInt32(octet)
    }
    return address
  }

  /// StrictDecimal parses 1 to 3 ASCII digits without a leading zero, bounded by max.
  private static func strictDecimal(_ text: Substring, max: Int) -> Int? {
    let bytes = Array(text.utf8)
    guard (1...3).contains(bytes.count), bytes.allSatisfy(isDigit),
      bytes.count == 1 || bytes[0] != UInt8(ascii: "0")
    else { return nil }
    let value = bytes.reduce(0) { $0 * 10 + Int($1 - UInt8(ascii: "0")) }
    return value <= max ? value : nil
  }

  /// Mask clears host bits below a prefix length.
  private static func mask(_ address: UInt32, bits: Int) -> UInt32 {
    bits == 0 ? 0 : address & (UInt32.max << UInt32(32 - bits))
  }

  /// Format writes a canonical dotted-quad prefix.
  private static func format(_ address: UInt32, bits: Int) -> String {
    let octets = [24, 16, 8, 0].map { String((address >> UInt32($0)) & 0xff) }
    return octets.joined(separator: ".") + "/\(bits)"
  }

  /// IsRealmScalar accepts the realm alphabet: ASCII letters, digits, dot, underscore, hyphen.
  private static func isRealmScalar(_ scalar: Unicode.Scalar) -> Bool {
    scalar.isASCII
      && (isLowerAlnum(UInt8(scalar.value)) || isUpper(UInt8(scalar.value))
        || "._-".unicodeScalars.contains(scalar))
  }

  /// IsDigit accepts ASCII decimal digits.
  private static func isDigit(_ byte: UInt8) -> Bool { (48...57).contains(byte) }

  /// IsLowerAlnum accepts ASCII lowercase letters and digits.
  private static func isLowerAlnum(_ byte: UInt8) -> Bool {
    isDigit(byte) || (97...122).contains(byte)
  }

  /// IsUpper accepts ASCII uppercase letters.
  private static func isUpper(_ byte: UInt8) -> Bool { (65...90).contains(byte) }

  /// IsLowerHex accepts ASCII digits and lowercase hexadecimal letters.
  private static func isLowerHex(_ byte: UInt8) -> Bool {
    isDigit(byte) || (97...102).contains(byte)
  }
}
