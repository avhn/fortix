import CryptoKit
import Foundation

/// CredentialKey binds one password to an exact profile ID, gateway tuple, and username.
public struct CredentialKey: Equatable, Sendable {
  /// Service matches the CLI's generic-password Keychain service.
  public static let service = "fortix"
  /// Account includes the bound tuple hash and password suffix used by the CLI.
  public let account: String
  /// TupleJSON retains canonical Go JSON for interoperability diagnostics using synthetic inputs.
  public let tupleJSON: String

  /// Creates the CLI-compatible key without normalization; invalid identity fails before Keychain access.
  public init(id: String, host: String, port: Int, username: String) throws {
    guard VPNProfile.validID(id), !host.isEmpty, (1...65535).contains(port), !username.isEmpty
    else {
      throw CoreError.invalidProfile
    }
    tupleJSON = "[\(Self.quote(host)),\(port),\(Self.quote(username))]"
    let digest = SHA256.hash(data: Data(tupleJSON.utf8)).map { String(format: "%02x", $0) }.joined()
    account = "\(id):\(digest):password"
  }

  /// Derives identity from an authoritative helper profile, applying the default TLS port.
  public init(profile: VPNProfile) throws {
    try self.init(
      id: profile.id, host: profile.gateway.host, port: profile.gateway.resolvedPort,
      username: profile.username)
  }

  /// Quote reproduces Go's UTF-8 JSON escaping, including HTML and Unicode line separators.
  private static func quote(_ text: String) -> String {
    var output = "\""
    for scalar in text.unicodeScalars {
      switch scalar.value {
      case 34: output += "\\\""
      case 92: output += "\\\\"
      case 8: output += "\\b"
      case 9: output += "\\t"
      case 10: output += "\\n"
      case 12: output += "\\f"
      case 13: output += "\\r"
      case 0..<32, 38, 60, 62, 0x2028, 0x2029: output += String(format: "\\u%04x", scalar.value)
      default: output.unicodeScalars.append(scalar)
      }
    }
    return output + "\""
  }
}
