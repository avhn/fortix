import Foundation
import XCTest

@testable import FortixCore

/// ModelTests checks backend defaults, secret-free profile parsing, and aggregate status parity.
final class ModelTests: XCTestCase {
  /// AggregateVector decodes shared Go/Swift presentation expectations.
  private struct AggregateVector: Decodable {
    /// Name identifies the precedence scenario.
    let name: String
    /// Profiles contains presentation-only input snapshots.
    let profiles: [AggregateProfile]
    /// Reachable distinguishes verified data from stale snapshots.
    let reachable: Bool
    /// Status is the canonical status name expected by both clients.
    let status: AggregateStatus
  }

  /// TestAggregateFixtures verifies every shared precedence and progress scenario.
  func testAggregateFixtures() throws {
    let vectors = try JSONDecoder().decode(
      [AggregateVector].self, from: Fixtures.data("aggregate-status.json"))
    for vector in vectors {
      XCTAssertEqual(
        AggregateStatus.build(profiles: vector.profiles, reachable: vector.reachable),
        vector.status, vector.name)
    }
  }

  /// TestProfileFixtures verifies omitted and explicit backend choices survive typed round trips.
  func testProfileFixtures() throws {
    for frame in try Fixtures.lines("protocol.requests.ndjson") {
      let request = try JSONDecoder().decode(HelperRequest.self, from: frame)
      guard let payload = request.profileJSON else { continue }
      let profile = try VPNProfile.decode(payload)
      XCTAssertEqual(
        profile.backend,
        request.id == "put-omitted" ? nil : request.id == "put-native" ? "native" : "openfortivpn")
      XCTAssertEqual(
        profile.resolvedBackend, request.id == "put-external" ? "openfortivpn" : "native")
      XCTAssertEqual(try VPNProfile.decode(JSONValue.make(profile)), profile)
    }
  }

  /// TestInvalidProfiles rejects unsafe identifiers, invalid backend/MFA combinations, and secret fields.
  func testInvalidProfiles() throws {
    var profile = VPNProfile(
      id: "work", name: "Work", gateway: .init(host: "vpn.example.com"), username: "user")
    profile.id = "../work"
    XCTAssertThrowsError(try profile.validate())
    profile.id = "work"
    profile.backend = "native"
    profile.mfa = .init(mode: "push")
    XCTAssertThrowsError(try profile.validate())
    profile.backend = "openfortivpn"
    try profile.validate()
    guard case .object(var fields) = try JSONValue.make(profile) else {
      return XCTFail("Expected profile object")
    }
    fields["password"] = .string("synthetic")
    XCTAssertThrowsError(try VPNProfile.decode(.object(fields)))
    fields.removeValue(forKey: "password")
    fields["gateway"] = .object([
      "host": .string("vpn.example.com"), "command": .string("synthetic"),
    ])
    XCTAssertThrowsError(try VPNProfile.decode(.object(fields)))
  }
}
