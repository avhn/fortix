import Foundation
import Security

/// KeychainError distinguishes missing entries from secure-store access and encoding failures.
public enum KeychainError: Error, Equatable, Sendable {
  /// NotFound means the requested generic-password item is absent.
  case notFound
  /// Unavailable includes locked, denied, and malformed secure-store entries.
  case unavailable
  /// TooLong rejects passwords exceeding the CLI's compatible storage limit.
  case tooLong
}

/// KeychainProvider is an injectable generic-password boundary; it must not log query data.
public protocol KeychainProvider: Sendable {
  /// Read returns stored bytes or a typed missing/unavailable failure for the service and account.
  func read(service: String, account: String) throws -> Data
  /// Write replaces stored bytes without deleting the old credential first.
  func write(service: String, account: String, data: Data) throws
  /// Delete removes one item and reports notFound for an absent credential.
  func delete(service: String, account: String) throws
}

/// SecurityKeychainProvider uses the user's login Keychain without a disk or memory fallback.
public struct SecurityKeychainProvider: KeychainProvider {
  /// Creates a provider without prompting or accessing Keychain.
  public init() {}

  /// Query selects the same generic-password service and account used by the CLI.
  private func query(service: String, account: String) -> [String: Any] {
    [
      kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
      kSecAttrAccount as String: account,
    ]
  }

  /// Read retrieves stored data and maps all provider errors without exposing system diagnostics.
  public func read(service: String, account: String) throws -> Data {
    var query = query(service: service, account: account)
    query[kSecReturnData as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    try check(status)
    guard let data = item as? Data else { throw KeychainError.unavailable }
    return data
  }

  /// Write updates an existing entry atomically or adds a new compatible item when it is missing.
  public func write(service: String, account: String, data: Data) throws {
    let query = query(service: service, account: account)
    let attributes = [kSecValueData as String: data]
    let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
    if status != errSecItemNotFound {
      try check(status)
      return
    }
    var item = query
    item[kSecValueData as String] = data
    // The CLI creates ordinary login-Keychain generic passwords, not data-protection items.
    let added = SecItemAdd(item as CFDictionary, nil)
    if added == errSecDuplicateItem {
      try check(SecItemUpdate(query as CFDictionary, attributes as CFDictionary))
    } else {
      try check(added)
    }
  }

  /// Delete removes only the selected service/account item and retains typed missing errors.
  public func delete(service: String, account: String) throws {
    try check(SecItemDelete(query(service: service, account: account) as CFDictionary))
  }

  /// Check maps status values to fixed errors without returning sensitive Keychain diagnostics.
  private func check(_ status: OSStatus) throws {
    if status == errSecItemNotFound { throw KeychainError.notFound }
    guard status == errSecSuccess else { throw KeychainError.unavailable }
  }
}

/// KeychainStore encodes passwords exactly like go-keyring while serializing provider access.
public actor KeychainStore {
  /// Prefix marks go-keyring's base64-encoded password representation.
  public static let prefix = "go-keyring-base64:"
  /// Provider is the injected secure storage boundary; production uses Security.framework.
  private let provider: any KeychainProvider

  /// Creates a store without accessing Keychain; fakes never fall back to the real provider.
  public init(provider: any KeychainProvider = SecurityKeychainProvider()) {
    self.provider = provider
  }

  /// Get returns a decoded password; legacy unprefixed values remain compatible with go-keyring.
  public func get(_ key: CredentialKey) throws -> String {
    let data = try provider.read(service: CredentialKey.service, account: key.account)
    guard let stored = String(data: data, encoding: .utf8) else { throw KeychainError.unavailable }
    if !stored.hasPrefix(Self.prefix) { return stored }
    guard let decoded = Data(base64Encoded: String(stored.dropFirst(Self.prefix.count))),
      let password = String(data: decoded, encoding: .utf8)
    else { throw KeychainError.unavailable }
    return password
  }

  /// Set validates UTF-8 size, then stores the shared prefix and base64 representation.
  public func set(_ password: String, for key: CredentialKey) throws {
    guard password.utf8.count <= 2800 else { throw KeychainError.tooLong }
    let encoded = Self.prefix + Data(password.utf8).base64EncodedString()
    try provider.write(
      service: CredentialKey.service, account: key.account, data: Data(encoded.utf8))
  }

  /// Delete removes only this bound identity and propagates missing or inaccessible-store errors.
  public func delete(_ key: CredentialKey) throws {
    try provider.delete(service: CredentialKey.service, account: key.account)
  }
}
