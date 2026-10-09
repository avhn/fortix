import Foundation

/// SharedProfileError identifies a rejected shared document without including any input values.
/// Field names a schema field or a forbidden key; Message is a fixed explanation.
public struct SharedProfileError: Error, Equatable, Sendable {
  /// Kind groups failures so callers can react without parsing messages.
  public enum Kind: String, Sendable {
    /// JSON covers malformed syntax, invalid UTF-8, trailing data, and wrong value types.
    case json
    /// Size means the document exceeds 1 MiB.
    case size
    /// Format means the document is not marked as a Fortix profile file.
    case format
    /// Version means an unsupported document version.
    case version
    /// Count means fewer than 1 or more than 32 profiles.
    case count
    /// Field covers unknown keys, wrong object shapes, and nulls.
    case field
    /// DuplicateKey means an object repeats a key.
    case duplicateKey = "duplicate_key"
    /// DuplicateID means two profiles share an identifier.
    case duplicateID = "duplicate_id"
    /// Secret means a credential-like key appears anywhere in the document.
    case secret
    /// Invalid means supplied profile values break the profile rules; see Problems.
    case invalid
  }

  /// Kind is the stable failure category.
  public let kind: Kind
  /// Field is a schema path or forbidden key name, never a supplied value.
  public let field: String
  /// Message is a fixed explanation.
  public let message: String
  /// Problems lists every invalid supplied field for the invalid kind.
  public let problems: [ProfileFieldProblem]

  /// Creates a failure; problems are only meaningful for the invalid kind.
  public init(kind: Kind, field: String, message: String, problems: [ProfileFieldProblem] = []) {
    self.kind = kind
    self.field = field
    self.message = message
    self.problems = problems
  }

  /// JSON creates a document-level syntax or type failure.
  static func json(_ message: String) -> SharedProfileError {
    SharedProfileError(kind: .json, field: "$", message: message)
  }

  /// Invalid wraps validation problems, surfacing the first one as the summary.
  static func invalid(_ problems: [ProfileFieldProblem]) -> SharedProfileError {
    SharedProfileError(
      kind: .invalid, field: problems[0].field, message: problems[0].message, problems: problems)
  }
}

/// SharedProfileDraft holds optional shared fields; nil means the file did not supply the field.
/// There is no username: shared files cannot carry or overwrite personal identity.
public struct SharedProfileDraft: Equatable, Sendable {
  /// SchemaVersion is the per-profile schema version, independent of the document version.
  public var schemaVersion: Int?
  /// ID is the suggested profile identifier.
  public var id: String?
  /// Name is the suggested display label.
  public var name: String?
  /// Backend is an explicit backend choice; an empty value means automatic.
  public var backend: String?
  /// Gateway keeps host and port presence independent.
  public var gateway: Gateway?
  /// Realm is an optional authentication realm.
  public var realm: String?
  /// TrustedCert is a sender-supplied certificate pin, normalized when valid.
  public var trustedCert: String?
  /// MFA keeps mode and each TOTP parameter independent.
  public var mfa: MFA?
  /// Routes keeps mode, the complete prefix list, and LAN preservation independent.
  public var routes: Routes?
  /// DNS keeps mode and the complete domain list independent.
  public var dns: DNS?

  /// Gateway is a partial gateway; an absent host must be completed locally.
  public struct Gateway: Equatable, Sendable {
    /// Host is the gateway name or address.
    public var host: String?
    /// Port is the TLS port; omission means the default 443.
    public var port: Int?
    /// Creates a partial gateway.
    public init(host: String? = nil, port: Int? = nil) {
      self.host = host
      self.port = port
    }
  }

  /// MFA is partial second-factor configuration without any seed or response.
  public struct MFA: Equatable, Sendable {
    /// Mode selects the second-factor interaction.
    public var mode: String?
    /// Digits is the TOTP response length.
    public var digits: Int?
    /// Period is the TOTP interval in seconds.
    public var period: Int?
    /// Algorithm is the TOTP hash name.
    public var algorithm: String?
    /// Creates partial MFA settings.
    public init(
      mode: String? = nil, digits: Int? = nil, period: Int? = nil, algorithm: String? = nil
    ) {
      self.mode = mode
      self.digits = digits
      self.period = period
      self.algorithm = algorithm
    }
  }

  /// Routes is partial routing policy; a supplied Include replaces a base list entirely.
  public struct Routes: Equatable, Sendable {
    /// Mode selects gateway, custom, or full routing.
    public var mode: String?
    /// Include is the complete requested prefix list.
    public var include: [String]?
    /// PreserveLAN keeps explicit false distinct from omission.
    public var preserveLAN: Bool?
    /// Creates partial routing policy.
    public init(mode: String? = nil, include: [String]? = nil, preserveLAN: Bool? = nil) {
      self.mode = mode
      self.include = include
      self.preserveLAN = preserveLAN
    }
  }

  /// DNS is partial DNS policy; a supplied Domains replaces a base list entirely.
  public struct DNS: Equatable, Sendable {
    /// Mode selects none or split DNS.
    public var mode: String?
    /// Domains is the complete split DNS domain list.
    public var domains: [String]?
    /// Creates partial DNS policy.
    public init(mode: String? = nil, domains: [String]? = nil) {
      self.mode = mode
      self.domains = domains
    }
  }

  /// Creates a draft; every omitted argument stays absent.
  public init(
    schemaVersion: Int? = nil, id: String? = nil, name: String? = nil, backend: String? = nil,
    gateway: Gateway? = nil, realm: String? = nil, trustedCert: String? = nil, mfa: MFA? = nil,
    routes: Routes? = nil, dns: DNS? = nil
  ) {
    self.schemaVersion = schemaVersion
    self.id = id
    self.name = name
    self.backend = backend
    self.gateway = gateway
    self.realm = realm
    self.trustedCert = trustedCert
    self.mfa = mfa
    self.routes = routes
    self.dns = dns
  }

  /// Missing lists required fields the file did not supply, in schema order, always with username.
  /// Defaultable fields are excluded; custom or split modes also require their absent lists.
  public var missing: [String] {
    var fields: [String] = []
    if id == nil { fields.append("id") }
    if name == nil { fields.append("name") }
    if gateway?.host == nil { fields.append("gateway.host") }
    fields.append("username")
    if routes?.mode == "custom", routes?.include == nil { fields.append("routes.include") }
    if dns?.mode == "split", dns?.domains == nil { fields.append("dns.domains") }
    return fields
  }

  /// Apply overlays only supplied fields onto base and keeps base's username.
  /// Route and domain lists replace the base lists as a whole and are normalized; nothing
  /// is defaulted or validated, so callers validate the completed result before saving.
  public func apply(to base: VPNProfile) -> VPNProfile {
    var profile = base
    if let schemaVersion { profile.schemaVersion = schemaVersion }
    if let id { profile.id = id }
    if let name { profile.name = name }
    if let backend { profile.backend = backend.isEmpty ? nil : backend }
    if let host = gateway?.host { profile.gateway.host = host }
    if let port = gateway?.port { profile.gateway.port = port }
    if let realm { profile.realm = realm.isEmpty ? nil : realm }
    if let trustedCert { profile.trustedCert = trustedCert.isEmpty ? nil : trustedCert }
    if let mfa {
      if let mode = mfa.mode { profile.mfa.mode = mode }
      if let digits = mfa.digits { profile.mfa.digits = digits }
      if let period = mfa.period { profile.mfa.period = period }
      if let algorithm = mfa.algorithm { profile.mfa.algorithm = algorithm }
    }
    if let routes {
      if let mode = routes.mode { profile.routes.mode = mode }
      if let include = routes.include {
        profile.routes.include = include.map(ProfileRules.normalizePrefix)
      }
      if let preserveLAN = routes.preserveLAN { profile.routes.preserveLAN = preserveLAN }
    }
    if let dns {
      if let mode = dns.mode { profile.dns.mode = mode }
      if let domains = dns.domains {
        profile.dns.domains = domains.map(ProfileRules.normalizeDomain)
      }
    }
    return profile
  }

  /// Merge overlays supplied fields onto an existing profile while keeping its ID and username.
  /// Keeping the ID means a merge can only ever update the profile the user picked.
  public func merge(into existing: VPNProfile) -> VPNProfile {
    var profile = apply(to: existing)
    profile.id = existing.id
    profile.username = existing.username
    return profile
  }

  /// Has reports whether a validation path names a supplied field, including list elements.
  func has(field: String) -> Bool {
    switch field {
    case "schema_version": return schemaVersion != nil
    case "id": return id != nil
    case "name": return name != nil
    case "backend": return backend != nil
    case "gateway.host": return gateway?.host != nil
    case "gateway.port": return gateway?.port != nil
    case "realm": return realm != nil
    case "trusted_cert": return trustedCert != nil
    case "mfa.mode": return mfa?.mode != nil
    case "mfa.digits": return mfa?.digits != nil
    case "mfa.period": return mfa?.period != nil
    case "mfa.algorithm": return mfa?.algorithm != nil
    case "routes.mode": return routes?.mode != nil
    case "dns.mode": return dns?.mode != nil
    default: break
    }
    if field == "routes.include" || field.hasPrefix("routes.include[") {
      return routes?.include != nil
    }
    if field == "dns.domains" || field.hasPrefix("dns.domains[") { return dns?.domains != nil }
    return false
  }

  /// SuppliedProblems validates with full-profile rules and keeps errors only for supplied fields.
  /// Absent modes borrow a compatible temporary mode so supplied lists and parameters are checked.
  func suppliedProblems() -> [ProfileFieldProblem] {
    var profile = apply(to: SharedProfiles.zeroProfile)
    if let mfa, mfa.mode == nil, mfa.digits != nil || mfa.period != nil || mfa.algorithm != nil {
      profile.mfa.mode = "totp"
    }
    if let routes, routes.mode == nil, routes.include != nil { profile.routes.mode = "custom" }
    if let dns, dns.mode == nil, dns.domains != nil { profile.dns.mode = "split" }
    profile = apply(to: SharedProfiles.applyingDefaults(profile))
    return ProfileRules.problems(profile).filter { has(field: $0.field) }
  }

  /// Normalize canonicalizes supplied lists and valid pins without filling absent fields.
  mutating func normalize() {
    if let include = routes?.include { routes?.include = include.map(ProfileRules.normalizePrefix) }
    if let domains = dns?.domains { dns?.domains = domains.map(ProfileRules.normalizeDomain) }
    if let pin = trustedCert, let normalized = ProfileRules.normalizedPin(pin) {
      trustedCert = normalized
    }
  }
}

/// SharedProfiles reads and writes the secret-free `fortix-profile` exchange format, version 1.
/// Documents are at most 1 MiB with 1 to 32 profiles and never contain usernames or passwords.
public enum SharedProfiles {
  /// MaxBytes bounds the entire encoded document, including whitespace.
  public static let maxBytes = 1 << 20
  /// MaxProfiles bounds the number of profiles in one document.
  public static let maxProfiles = 32
  /// ProfileFields are the exact profile keys a shared file may use; username is excluded.
  static let profileFields: Set<String> = [
    "schema_version", "id", "name", "backend", "gateway", "realm", "trusted_cert", "mfa",
    "routes", "dns",
  ]
  /// NestedFields are the exact keys of each nested profile object.
  static let nestedFields: [String: Set<String>] = [
    "gateway": ["host", "port"], "mfa": ["mode", "digits", "period", "algorithm"],
    "routes": ["mode", "include", "preserve_lan"], "dns": ["mode", "domains"],
  ]
  /// ZeroProfile is the empty base used to validate partial drafts.
  static var zeroProfile: VPNProfile {
    VPNProfile(
      id: "", name: "", gateway: .init(host: "", port: nil), username: "", mfa: .init(mode: ""),
      routes: .init(mode: "", include: nil, preserveLAN: nil), dns: .init(mode: ""))
  }

  /// Read loads at most one byte beyond the size limit from url and parses it.
  /// Oversized files fail without being read completely.
  public static func read(contentsOf url: URL) throws -> [SharedProfileDraft] {
    let handle = try FileHandle(forReadingFrom: url)
    defer { try? handle.close() }
    let data = try handle.read(upToCount: maxBytes + 1) ?? Data()
    return try parse(data)
  }

  /// Parse validates a UTF-8 document and returns 1 to 32 normalized partial drafts.
  /// A raw pass rejects secret-like keys at any depth before schema checks and never echoes
  /// values. Unknown keys, nulls, duplicate keys or IDs, and invalid supplied fields fail.
  public static func parse(_ data: Data) throws -> [SharedProfileDraft] {
    guard data.count <= maxBytes else {
      throw SharedProfileError(kind: .size, field: "$", message: "exceeds 1 MiB limit")
    }
    guard String(decoding: data, as: UTF8.self).utf8.elementsEqual(data) else {
      throw SharedProfileError.json("invalid UTF-8")
    }
    var parser = SharedJSONParser(data)
    let document = try parser.parse()
    try checkObject(document, allowed: ["format", "version", "profiles"])
    guard case .string("fortix-profile")? = document["format"] else {
      throw SharedProfileError(kind: .format, field: "format", message: "must be fortix-profile")
    }
    guard let version = document["version"], (try? integer(version)) == 1 else {
      throw SharedProfileError(kind: .version, field: "version", message: "must be 1")
    }
    var entries: [SharedJSON] = []
    switch document["profiles"] {
    case .some(.array(let values)): entries = values
    case .none: break
    default: throw SharedProfileError.json("invalid document field type")
    }
    guard (1...maxProfiles).contains(entries.count) else {
      throw SharedProfileError(
        kind: .count, field: "profiles", message: "must contain 1..32 profiles")
    }
    var drafts: [SharedProfileDraft] = []
    var seen = Set<String>()
    for entry in entries {
      try checkObject(entry, allowed: profileFields)
      var draft = try decodeDraft(entry)
      draft.normalize()
      let problems = draft.suppliedProblems()
      guard problems.isEmpty else { throw SharedProfileError.invalid(problems) }
      if let id = draft.id {
        guard seen.insert(id).inserted else {
          throw SharedProfileError(
            kind: .duplicateID, field: "profiles.id", message: "duplicate profile id")
        }
      }
      drafts.append(draft)
    }
    return drafts
  }

  /// Export validates normalized copies and returns indented JSON with a final newline.
  /// It preserves order and never writes username; invalid profiles, duplicate IDs, and
  /// size or count limits fail. The certificate pin is exported when the profile has one.
  public static func export(_ profiles: [VPNProfile]) throws -> Data {
    guard (1...maxProfiles).contains(profiles.count) else {
      throw SharedProfileError(
        kind: .count, field: "profiles", message: "must contain 1..32 profiles")
    }
    var seen = Set<String>()
    var entries: [SharedJSON] = []
    for original in profiles {
      var profile = original
      profile.routes.include = profile.routes.include?.map(ProfileRules.normalizePrefix)
      profile.dns.domains = profile.dns.domains?.map(ProfileRules.normalizeDomain)
      let problems = ProfileRules.problems(profile)
      guard problems.isEmpty else { throw SharedProfileError.invalid(problems) }
      if let pin = profile.trustedCert { profile.trustedCert = ProfileRules.normalizedPin(pin) }
      guard seen.insert(profile.id).inserted else {
        throw SharedProfileError(
          kind: .duplicateID, field: "profiles.id", message: "duplicate profile id")
      }
      entries.append(encode(profile))
    }
    let document = SharedJSON.object([
      .init(key: "format", value: .string("fortix-profile")),
      .init(key: "version", value: .number("1")),
      .init(key: "profiles", value: .array(entries)),
    ])
    let data = document.encoded()
    guard data.count <= maxBytes else {
      throw SharedProfileError(kind: .size, field: "$", message: "exceeds 1 MiB limit")
    }
    return data
  }

  /// ApplyingDefaults fills omitted port, MFA, backend, TOTP, routing, and DNS settings.
  /// Explicit values, including invalid ones and explicit false, are preserved.
  static func applyingDefaults(_ base: VPNProfile) -> VPNProfile {
    var profile = base
    if profile.gateway.port == nil || profile.gateway.port == 0 { profile.gateway.port = 443 }
    if profile.mfa.mode.isEmpty { profile.mfa.mode = "none" }
    if profile.backend == nil || profile.backend == "" {
      profile.backend = profile.mfa.mode == "none" ? "native" : "openfortivpn"
    }
    if profile.mfa.mode == "totp" {
      profile.mfa.digits = profile.mfa.digits ?? 6
      profile.mfa.period = profile.mfa.period ?? 30
      profile.mfa.algorithm = profile.mfa.algorithm ?? "SHA1"
    }
    if profile.routes.mode.isEmpty { profile.routes.mode = "gateway" }
    if profile.routes.preserveLAN == nil { profile.routes.preserveLAN = true }
    if profile.dns.mode.isEmpty { profile.dns.mode = "none" }
    return profile
  }

  /// CheckObject requires an object whose keys are allowed, recursing into nested profile objects.
  private static func checkObject(_ value: SharedJSON, allowed: Set<String>) throws {
    guard let members = value.members else {
      throw SharedProfileError(kind: .field, field: "$", message: "must be an object")
    }
    for member in members {
      guard allowed.contains(member.key) else {
        throw SharedProfileError(
          kind: .field, field: "$", message: "unknown field in shared configuration")
      }
      if allowed == profileFields, let nested = nestedFields[member.key] {
        try checkObject(member.value, allowed: nested)
      }
    }
  }

  /// DecodeDraft converts a shape-checked profile object into typed optional fields.
  private static func decodeDraft(_ value: SharedJSON) throws -> SharedProfileDraft {
    var draft = SharedProfileDraft()
    draft.schemaVersion = try value["schema_version"].map(integer)
    draft.id = try value["id"].map(string)
    draft.name = try value["name"].map(string)
    draft.backend = try value["backend"].map(string)
    draft.realm = try value["realm"].map(string)
    draft.trustedCert = try value["trusted_cert"].map(string)
    if let gateway = value["gateway"] {
      draft.gateway = .init(
        host: try gateway["host"].map(string), port: try gateway["port"].map(integer))
    }
    if let mfa = value["mfa"] {
      draft.mfa = .init(
        mode: try mfa["mode"].map(string), digits: try mfa["digits"].map(integer),
        period: try mfa["period"].map(integer), algorithm: try mfa["algorithm"].map(string))
    }
    if let routes = value["routes"] {
      draft.routes = .init(
        mode: try routes["mode"].map(string), include: try routes["include"].map(strings),
        preserveLAN: try routes["preserve_lan"].map(bool))
    }
    if let dns = value["dns"] {
      draft.dns = .init(mode: try dns["mode"].map(string), domains: try dns["domains"].map(strings))
    }
    return draft
  }

  /// Encode writes one profile in schema order without username, omitting empty optionals.
  private static func encode(_ profile: VPNProfile) -> SharedJSON {
    var members: [SharedJSON.Member] = [
      .init(key: "schema_version", value: .number(String(profile.schemaVersion))),
      .init(key: "id", value: .string(profile.id)),
      .init(key: "name", value: .string(profile.name)),
    ]
    if let backend = profile.backend, !backend.isEmpty {
      members.append(.init(key: "backend", value: .string(backend)))
    }
    members.append(
      .init(
        key: "gateway",
        value: .object([
          .init(key: "host", value: .string(profile.gateway.host)),
          .init(key: "port", value: .number(String(profile.gateway.port ?? 443))),
        ])))
    if let realm = profile.realm, !realm.isEmpty {
      members.append(.init(key: "realm", value: .string(realm)))
    }
    if let pin = profile.trustedCert, !pin.isEmpty {
      members.append(.init(key: "trusted_cert", value: .string(pin)))
    }
    var mfa: [SharedJSON.Member] = [.init(key: "mode", value: .string(profile.mfa.mode))]
    if let digits = profile.mfa.digits {
      mfa.append(.init(key: "digits", value: .number("\(digits)")))
    }
    if let period = profile.mfa.period {
      mfa.append(.init(key: "period", value: .number("\(period)")))
    }
    if let algorithm = profile.mfa.algorithm {
      mfa.append(.init(key: "algorithm", value: .string(algorithm)))
    }
    members.append(.init(key: "mfa", value: .object(mfa)))
    var routes: [SharedJSON.Member] = [.init(key: "mode", value: .string(profile.routes.mode))]
    if let include = profile.routes.include {
      routes.append(.init(key: "include", value: .array(include.map(SharedJSON.string))))
    }
    if let preserveLAN = profile.routes.preserveLAN {
      routes.append(.init(key: "preserve_lan", value: .bool(preserveLAN)))
    }
    members.append(.init(key: "routes", value: .object(routes)))
    var dns: [SharedJSON.Member] = [.init(key: "mode", value: .string(profile.dns.mode))]
    if let domains = profile.dns.domains {
      dns.append(.init(key: "domains", value: .array(domains.map(SharedJSON.string))))
    }
    members.append(.init(key: "dns", value: .object(dns)))
    return .object(members)
  }

  /// String decodes a JSON string field.
  private static func string(_ value: SharedJSON) throws -> String {
    guard case .string(let text) = value else { throw fieldType }
    return text
  }

  /// Strings decodes an array of JSON strings.
  private static func strings(_ value: SharedJSON) throws -> [String] {
    guard case .array(let values) = value else { throw fieldType }
    return try values.map(string)
  }

  /// Bool decodes a JSON boolean field.
  private static func bool(_ value: SharedJSON) throws -> Bool {
    guard case .bool(let flag) = value else { throw fieldType }
    return flag
  }

  /// Integer accepts only integer literals that fit Int; fractions and exponents fail.
  private static func integer(_ value: SharedJSON) throws -> Int {
    guard case .number(let literal) = value, !literal.contains(where: { ".eE".contains($0) }),
      let number = Int(literal)
    else { throw fieldType }
    return number
  }

  /// FieldType is the fixed failure for a supplied value of the wrong JSON type.
  private static var fieldType: SharedProfileError {
    SharedProfileError.json("invalid profile field type")
  }
}
