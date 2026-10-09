import Foundation
import XCTest

@testable import FortixCore

/// MemoryKeychain stores synthetic provider bytes under a lock without using the real login Keychain.
private final class MemoryKeychain: KeychainProvider, @unchecked Sendable {
  /// Lock serializes access shared by independent store actors.
  private let lock = NSLock()
  /// Entries retain synthetic generic-password values indexed by service and account.
  private var entries: [String: Data] = [:]

  /// Read returns the exact stored bytes or the same typed missing error as Security.framework.
  func read(service: String, account: String) throws -> Data {
    lock.lock()
    defer { lock.unlock() }
    guard let value = entries[service + "/" + account] else { throw KeychainError.notFound }
    return value
  }
  /// Write replaces only the requested service/account entry.
  func write(service: String, account: String, data: Data) throws {
    lock.lock()
    defer { lock.unlock() }
    entries[service + "/" + account] = data
  }
  /// Delete removes the requested entry and preserves typed missing failures.
  func delete(service: String, account: String) throws {
    lock.lock()
    defer { lock.unlock() }
    guard entries.removeValue(forKey: service + "/" + account) != nil else {
      throw KeychainError.notFound
    }
  }
}

/// KeychainTests validates exact CLI credential identity and stored bytes using shared synthetic vectors.
final class KeychainTests: XCTestCase {
  /// Vector contains canonical Go tuple encoding, account hash, and provider password representation.
  private struct Vector: Decodable {
    /// Name identifies the synthetic edge case.
    let name: String
    /// ID is the safe profile identifier.
    let id: String
    /// Host retains case-sensitive identity.
    let host: String
    /// Port is the gateway TLS port.
    let port: Int
    /// Username includes synthetic Unicode or JSON escaping cases.
    let username: String
    /// TupleJSON is the canonical Go JSON encoded hash input.
    let tupleJSON: String
    /// Service is the shared generic-password service.
    let service: String
    /// Account is the bound hash and suffix expected by the CLI.
    let account: String
    /// Password is synthetic plaintext, including an empty value.
    let password: String
    /// StoredPassword is the go-keyring prefix and base64 encoding.
    let storedPassword: String

    /// CodingKeys maps fixture wire spellings to Swift property naming.
    enum CodingKeys: String, CodingKey {
      case name, id, host, port, username, service, account, password
      case tupleJSON = "tuple_json"
      case storedPassword = "stored_password"
    }
  }

  /// TestSharedVectors verifies every account hash and bidirectional CLI/app password encoding.
  func testSharedVectors() async throws {
    let vectors = try JSONDecoder().decode([Vector].self, from: Fixtures.data("keychain.json"))
    let provider = MemoryKeychain()
    let store = KeychainStore(provider: provider)
    for vector in vectors {
      let key = try CredentialKey(
        id: vector.id, host: vector.host, port: vector.port, username: vector.username)
      XCTAssertEqual(key.tupleJSON, vector.tupleJSON, vector.name)
      XCTAssertEqual(key.account, vector.account, vector.name)
      XCTAssertEqual(CredentialKey.service, vector.service)
      try provider.write(
        service: vector.service, account: key.account, data: Data(vector.storedPassword.utf8))
      let fetched = try await store.get(key)
      XCTAssertEqual(fetched, vector.password, vector.name)
      try await store.set(vector.password, for: key)
      XCTAssertEqual(
        try provider.read(service: vector.service, account: key.account),
        Data(vector.storedPassword.utf8))
      try await store.delete(key)
      do {
        _ = try await store.get(key)
        XCTFail("Expected missing credential")
      } catch { XCTAssertEqual(error as? KeychainError, .notFound) }
    }
  }

  /// TestMalformedLegacyAndBounds distinguishes missing, malformed, legacy, and oversized entries.
  func testMalformedLegacyAndBounds() async throws {
    let provider = MemoryKeychain()
    let store = KeychainStore(provider: provider)
    let key = try CredentialKey(id: "work", host: "vpn.example.com", port: 443, username: "user")
    try provider.write(
      service: CredentialKey.service, account: key.account, data: Data("legacy synthetic".utf8))
    let legacy = try await store.get(key)
    XCTAssertEqual(legacy, "legacy synthetic")
    try provider.write(
      service: CredentialKey.service, account: key.account, data: Data("go-keyring-base64:!".utf8))
    do {
      _ = try await store.get(key)
      XCTFail("Expected malformed encoding")
    } catch { XCTAssertEqual(error as? KeychainError, .unavailable) }
    do {
      try await store.set(String(repeating: "a", count: 2801), for: key)
      XCTFail("Expected bound")
    } catch { XCTAssertEqual(error as? KeychainError, .tooLong) }
    try await store.set(String(repeating: "a", count: 2800), for: key)
    XCTAssertThrowsError(
      try CredentialKey(id: "../work", host: "vpn.example.com", port: 443, username: "user"))
  }
}
