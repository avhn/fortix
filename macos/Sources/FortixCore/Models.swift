import Foundation

/// VPNProfile is schema version 1 configuration without passwords, seeds, or executable options.
public struct VPNProfile: Codable, Equatable, Sendable, Identifiable {
  /// SchemaVersion must remain 1 for this additive configuration format.
  public var schemaVersion: Int
  /// ID is a safe helper-owned profile identifier.
  public var id: String
  /// Name is the human-readable profile label.
  public var name: String
  /// Backend preserves explicit choices; omission resolves according to the MFA mode.
  public var backend: String?
  /// Gateway identifies the remote TLS endpoint.
  public var gateway: Gateway
  /// Realm optionally selects a gateway authentication realm.
  public var realm: String?
  /// Username participates in credential identity and is not a password.
  public var username: String
  /// TrustedCert is helper-owned certificate trust, never imported or silently modified.
  public var trustedCert: String?
  /// MFA describes second-factor interaction without storing credential material.
  public var mfa: MFA
  /// Routes describes requested routing policy.
  public var routes: Routes
  /// DNS describes explicitly scoped split DNS policy.
  public var dns: DNS

  /// Gateway contains a host and TLS port; omitted ports resolve to 443.
  public struct Gateway: Codable, Equatable, Sendable {
    /// Host retains spelling because credential identity is case-sensitive.
    public var host: String
    /// Port is the explicit gateway port, or omitted for the default.
    public var port: Int?
    /// ResolvedPort supplies the same default as the helper.
    public var resolvedPort: Int { port == nil || port == 0 ? 443 : port! }
    /// Creates a gateway from an unnormalized host and optional port.
    public init(host: String, port: Int? = 443) {
      self.host = host
      self.port = port
    }
  }

  /// MFA records interaction settings without secret responses or TOTP seeds.
  public struct MFA: Codable, Equatable, Sendable {
    /// Mode selects none, push, code, totp, or static.
    public var mode: String
    /// Digits is an optional TOTP response length.
    public var digits: Int?
    /// Period is an optional TOTP interval in seconds.
    public var period: Int?
    /// Algorithm is an optional TOTP hash identifier.
    public var algorithm: String?
    /// Creates MFA configuration, preserving omitted TOTP settings for helper defaults.
    public init(
      mode: String = "none", digits: Int? = nil, period: Int? = nil, algorithm: String? = nil
    ) {
      self.mode = mode
      self.digits = digits
      self.period = period
      self.algorithm = algorithm
    }
  }

  /// Routes carries routing mode and optional IPv4 prefixes.
  public struct Routes: Codable, Equatable, Sendable {
    /// Mode selects gateway, custom, or full routing.
    public var mode: String
    /// Include contains only explicitly requested route prefixes.
    public var include: [String]?
    /// Exclude lists ranges removed from gateway-pushed routes, such as a range another VPN owns.
    public var exclude: [String]?
    /// PreserveLAN distinguishes omitted defaults from explicit false.
    public var preserveLAN: Bool?
    /// CodingKeys retains the helper's route field spelling.
    enum CodingKeys: String, CodingKey {
      case mode, include, exclude
      case preserveLAN = "preserve_lan"
    }
    /// Creates routing configuration, retaining explicit local-network preservation choices.
    public init(
      mode: String = "gateway", include: [String]? = nil, exclude: [String]? = nil,
      preserveLAN: Bool? = true
    ) {
      self.mode = mode
      self.include = include
      self.exclude = exclude
      self.preserveLAN = preserveLAN
    }
  }

  /// DNS carries unmanaged or domain-scoped DNS policy.
  public struct DNS: Codable, Equatable, Sendable {
    /// Mode selects none or split DNS.
    public var mode: String
    /// Domains contains explicitly scoped split DNS suffixes.
    public var domains: [String]?
    /// Creates DNS configuration without broadening the requested scope.
    public init(mode: String = "none", domains: [String]? = nil) {
      self.mode = mode
      self.domains = domains
    }
  }

  /// CodingKeys maps configuration keys exactly to the helper schema.
  enum CodingKeys: String, CodingKey {
    case id, name, backend, gateway, realm, username, mfa, routes, dns
    case schemaVersion = "schema_version"
    case trustedCert = "trusted_cert"
  }

  /// ResolvedBackend chooses native only for password-only profiles, without mutating stored choices.
  public var resolvedBackend: String { backend ?? (mfa.mode == "none" ? "native" : "openfortivpn") }

  /// Creates a secret-free profile; the helper remains authoritative for detailed field validation.
  public init(
    id: String, name: String, gateway: Gateway, username: String, backend: String? = nil,
    realm: String? = nil, trustedCert: String? = nil, mfa: MFA = MFA(),
    routes: Routes = Routes(), dns: DNS = DNS()
  ) {
    schemaVersion = 1
    self.id = id
    self.name = name
    self.gateway = gateway
    self.username = username
    self.backend = backend
    self.realm = realm
    self.trustedCert = trustedCert
    self.mfa = mfa
    self.routes = routes
    self.dns = dns
  }

  /// Decodes omitted top-level settings using the helper's defaults while retaining backend omission.
  public init(from decoder: Decoder) throws {
    let fields = try decoder.container(keyedBy: CodingKeys.self)
    schemaVersion = try fields.decode(Int.self, forKey: .schemaVersion)
    id = try fields.decode(String.self, forKey: .id)
    name = try fields.decode(String.self, forKey: .name)
    gateway = try fields.decode(Gateway.self, forKey: .gateway)
    username = try fields.decode(String.self, forKey: .username)
    backend = try fields.decodeIfPresent(String.self, forKey: .backend)
    realm = try fields.decodeIfPresent(String.self, forKey: .realm)
    trustedCert = try fields.decodeIfPresent(String.self, forKey: .trustedCert)
    mfa = try fields.decodeIfPresent(MFA.self, forKey: .mfa) ?? MFA()
    routes = try fields.decodeIfPresent(Routes.self, forKey: .routes) ?? Routes()
    dns = try fields.decodeIfPresent(DNS.self, forKey: .dns) ?? DNS()
  }

  /// ValidID recognizes the same ASCII identifier alphabet used by helper storage.
  public static func validID(_ id: String) -> Bool {
    id.range(of: "^[a-z0-9][a-z0-9-]{0,62}$", options: .regularExpression) != nil
  }

  /// Validate rejects unsafe IDs and incompatible backend selections before mutation.
  public func validate() throws {
    guard schemaVersion == 1, Self.validID(id), !name.isEmpty, !gateway.host.isEmpty,
      (1...65535).contains(gateway.resolvedPort), !username.isEmpty,
      ["native", "openfortivpn"].contains(resolvedBackend),
      resolvedBackend != "native" || mfa.mode == "none"
    else { throw CoreError.invalidProfile }
  }

  /// Decode rejects unknown or secret-bearing fields at every configuration object boundary.
  public static func decode(_ value: JSONValue) throws -> VPNProfile {
    guard case .object(let object) = value,
      Set(object.keys).isSubset(of: [
        "schema_version", "id", "name", "backend", "gateway", "realm",
        "username", "trusted_cert", "mfa", "routes", "dns",
      ])
    else {
      throw CoreError.invalidProfile
    }
    let nested: [String: Set<String>] = [
      "gateway": ["host", "port"], "mfa": ["mode", "digits", "period", "algorithm"],
      "routes": ["mode", "include", "exclude", "preserve_lan"], "dns": ["mode", "domains"],
    ]
    for (key, allowed) in nested {
      if let value = object[key] {
        guard case .object(let fields) = value, Set(fields.keys).isSubset(of: allowed) else {
          throw CoreError.invalidProfile
        }
      }
    }
    let profile: VPNProfile = try value.decode(VPNProfile.self)
    try profile.validate()
    return profile
  }
}

/// SessionStatus is a non-secret authoritative helper snapshot, including idle profiles.
public struct SessionStatus: Codable, Equatable, Sendable {
  /// Wanted records desired connectivity rather than merely current link state.
  public let wanted: Bool
  /// Initiated identifies attempts started by this client connection.
  public let initiated: Bool
  /// CleanupPending prevents treating dirty teardown as successful disconnect.
  public let cleanupPending: Bool
  /// Profile identifies the helper-owned configuration.
  public let profile: String
  /// State is the public session phase, retained as text for future phases.
  public let state: String
  /// Detail is a redacted state explanation.
  public let detail: String
  /// Attempt is the tunnel generation.
  public let attempt: UInt64
  /// Interface is the current link name, or empty before setup.
  public let interface: String
  /// LocalIP is the assigned IPv4 address, or empty before negotiation.
  public let localIP: String
  /// Since retains the helper's timestamp, including the zero timestamp for idle profiles.
  public let since: String

  /// CodingKeys preserves exact helper snapshot keys.
  enum CodingKeys: String, CodingKey {
    case wanted, initiated, profile, state, detail, attempt, interface, since
    case cleanupPending = "cleanup_pending"
    case localIP = "local_ip"
  }
}

/// ProfileState is the lightweight profile.list response, not a full session snapshot.
public struct ProfileState: Codable, Equatable, Sendable {
  /// Profile identifies one stored configuration.
  public let profile: String
  /// State identifies its current public phase.
  public let state: String
}

/// AggregateProfile is the presentation input shared by menu and window status rendering.
public struct AggregateProfile: Codable, Equatable, Sendable {
  /// ID identifies the profile independently of display labels.
  public var id: String
  /// State retains the helper's public phase.
  public var state: String
  /// Wanted indicates whether this profile contributes to wanted connection success.
  public var wanted: Bool
  /// PendingPassword distinguishes a human prompt from automatic keychain lookup.
  public var pendingPassword: Bool
  /// CleanupPending represents an unresolved network cleanup.
  public var cleanupPending: Bool

  /// CodingKeys matches the shared aggregate fixtures.
  enum CodingKeys: String, CodingKey {
    case id, state, wanted
    case pendingPassword = "pending_password"
    case cleanupPending = "cleanup_pending"
  }

  /// Creates presentation input without querying a helper or accessing credentials.
  public init(
    id: String, state: String, wanted: Bool, pendingPassword: Bool = false,
    cleanupPending: Bool = false
  ) {
    self.id = id
    self.state = state
    self.wanted = wanted
    self.pendingPassword = pendingPassword
    self.cleanupPending = cleanupPending
  }
}

/// AggregateStatus names connectivity independently of icon color, shape, or animation.
public enum AggregateStatus: String, Codable, Sendable {
  /// NotConnected also applies when the helper cannot verify stale snapshots.
  case notConnected = "NotConnected"
  /// Connecting represents transitional phases and automatic credential retrieval.
  case connecting = "Connecting"
  /// Connected means every wanted profile is connected and at least one is wanted.
  case connected = "Connected"
  /// Partial means some, but not all, wanted profiles are connected.
  case partial = "Partial"
  /// Attention represents failure, trust, or a human password prompt.
  case attention = "Attention"

  /// Build applies wanted connectivity before attention and progress, matching the menu model.
  public static func build(profiles: [AggregateProfile], reachable: Bool) -> AggregateStatus {
    guard reachable else { return .notConnected }
    let wanted = profiles.filter(\.wanted)
    let up = wanted.filter { $0.state == "connected" }.count
    if up > 0 && up < wanted.count { return .partial }
    if !wanted.isEmpty && up == wanted.count { return .connected }
    if profiles.contains(where: {
      $0.pendingPassword || $0.state == "failed" || $0.state == "waiting_trust"
    }) {
      return .attention
    }
    let progress: Set<String> = [
      "starting", "waiting_password", "waiting_code", "authenticating",
      "negotiating", "configuring", "stopping", "backoff",
    ]
    return profiles.contains(where: { progress.contains($0.state) }) ? .connecting : .notConnected
  }
}
