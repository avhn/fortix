import Foundation
import XCTest

@testable import FortixCore

/// SharedProfilesTests checks the secret-free share format against the helper's documented rules.
final class SharedProfilesTests: XCTestCase {
  /// Example returns a complete profile with documentation-only names and addresses.
  private static var example: VPNProfile {
    VPNProfile(
      id: "example", name: "Example", gateway: .init(host: "vpn.example.com", port: 443),
      username: "example-user", backend: "native", realm: "example",
      trustedCert: String(repeating: "ab", count: 32),
      routes: .init(mode: "custom", include: ["192.0.2.0/24"], preserveLAN: false),
      dns: .init(mode: "split", domains: ["internal.example.com"]))
  }

  /// Wrap places raw profile objects in the supported envelope without changing their JSON.
  private static func wrap(_ profiles: String...) -> Data {
    Data(
      (#"{"format":"fortix-profile","version":1,"profiles":["#
        + profiles.joined(separator: ",") + "]}").utf8)
  }

  /// RequireKind asserts a typed rejection of the expected kind that never echoes a marker value.
  private func requireKind(
    _ data: Data, _ kind: SharedProfileError.Kind, file: StaticString = #filePath,
    line: UInt = #line
  ) {
    XCTAssertThrowsError(try SharedProfiles.parse(data), file: file, line: line) { error in
      guard let problem = error as? SharedProfileError else {
        return XCTFail("untyped error \(error)", file: file, line: line)
      }
      XCTAssertEqual(
        problem.kind, kind, String(decoding: data.prefix(200), as: UTF8.self), file: file,
        line: line)
      XCTAssertFalse("\(problem)".contains("do-not-echo"), file: file, line: line)
    }
  }

  /// TestRoundTrip exports stable indented JSON without username and parses it back losslessly.
  func testRoundTrip() throws {
    for mode in ["none", "totp", "push", "prompt", "static"] {
      var original = Self.example
      original.backend = mode == "none" ? "native" : nil
      original.mfa =
        mode == "totp"
        ? .init(mode: mode, digits: 8, period: 60, algorithm: "SHA256") : .init(mode: mode)
      let data = try SharedProfiles.export([original])
      let text = String(decoding: data, as: UTF8.self)
      XCTAssertFalse(text.contains("username"), mode)
      XCTAssertFalse(text.contains("example-user"), mode)
      XCTAssertTrue(text.hasPrefix("{\n  \"format\": \"fortix-profile\",\n  \"version\": 1,"), text)
      XCTAssertTrue(text.hasSuffix("}\n"))
      XCTAssertEqual(try SharedProfiles.export([original]), data)
      let drafts = try SharedProfiles.parse(data)
      XCTAssertEqual(drafts.count, 1)
      XCTAssertEqual(drafts[0].missing, ["username"])
      var completed = drafts[0].apply(to: SharedProfiles.zeroProfile)
      completed.username = original.username
      XCTAssertEqual(completed, original, mode)
    }
  }

  /// TestExcludeRoundTrip carries excluded ranges and applies the helper's mode and backend rules.
  func testExcludeRoundTrip() throws {
    var original = Self.example
    original.routes = .init(mode: "gateway", exclude: ["198.51.100.0/24"], preserveLAN: true)
    let data = try SharedProfiles.export([original])
    XCTAssertTrue(String(decoding: data, as: UTF8.self).contains("\"exclude\""))
    var completed = try SharedProfiles.parse(data)[0].apply(to: SharedProfiles.zeroProfile)
    completed.username = original.username
    XCTAssertEqual(completed, original)
    var custom = Self.example
    custom.routes.exclude = ["198.51.100.0/24"]
    XCTAssertTrue(ProfileRules.problems(custom).contains { $0.field == "routes.exclude" })
    var legacy = original
    legacy.backend = "openfortivpn"
    XCTAssertTrue(ProfileRules.problems(legacy).contains { $0.field == "routes.exclude" })
    var overlap = original
    overlap.routes.exclude = ["198.51.0.0/16", "198.51.100.0/24"]
    XCTAssertTrue(ProfileRules.problems(overlap).contains { $0.field == "routes.exclude[1]" })
  }

  /// TestExportIsCanonical normalizes wildcard domains, prefixes, and pins in the written copy.
  func testExportIsCanonical() throws {
    var original = Self.example
    original.dns.domains = ["*.Example2.com"]
    original.routes.include = [" 192.0.2.19/24 "]
    original.trustedCert = String(repeating: "AB:", count: 31) + "AB"
    let text = String(decoding: try SharedProfiles.export([original]), as: UTF8.self)
    XCTAssertFalse(text.contains("*."))
    XCTAssertTrue(text.contains("\"example2.com\""))
    XCTAssertTrue(text.contains("\"192.0.2.0/24\""))
    XCTAssertTrue(text.contains(String(repeating: "ab", count: 32)))
    XCTAssertEqual(original.dns.domains, ["*.Example2.com"])
  }

  /// TestSecretKeysRejectedAtDepth finds every forbidden key in any case at any depth first.
  func testSecretKeysRejectedAtDepth() {
    let keys = [
      "password", "passwd", "credential", "credentials", "secret", "token", "otp", "cookie",
      "svpncookie",
    ]
    for key in keys {
      for spelling in [key, key.uppercased()] {
        let value = "\"\(spelling)\":\"do-not-echo-this-value\""
        let inputs = [
          Data("{\(value)}".utf8),
          Self.wrap("{\(value)}"),
          Self.wrap(#"{"gateway":{"extra":{"# + value + "}}}"),
          Self.wrap(#"{"extra":[[{"nested":{"# + value + "}}]]}"),
          Self.wrap(#"{"id":"first","id":"second","extra":null,"nested":{"# + value + "}}"),
          Self.wrap(#"{"extra":{"# + value + #"},"extra":{}}"#),
        ]
        for input in inputs { requireKind(input, .secret) }
      }
    }
  }

  /// TestStructureRejected covers unknown keys, shapes, types, nulls, and ambiguous JSON.
  func testStructureRejected() {
    let cases: [(Data, SharedProfileError.Kind)] = [
      (Data(#"{"format":"other","version":1,"profiles":[{}]}"#.utf8), .format),
      (Data(#"{"version":1,"profiles":[{}]}"#.utf8), .format),
      (Data(#"{"format":"fortix-profile","version":2,"profiles":[{}]}"#.utf8), .version),
      (Data(#"{"format":"fortix-profile","version":1.0,"profiles":[{}]}"#.utf8), .version),
      (Data(#"{"format":"fortix-profile","version":"1","profiles":[{}]}"#.utf8), .version),
      (Data(#"{"format":"fortix-profile","version":1,"profiles":[{}],"extra":true}"#.utf8), .field),
      (Self.wrap(#"{"naem":"Example"}"#), .field),
      (Self.wrap(#"{"username":"example-user"}"#), .field),
      (Self.wrap(#"{"ID":"example"}"#), .field),
      (Self.wrap(#"{"gateway":{"HOST":"vpn.example.com"}}"#), .field),
      (Self.wrap(#"{"mfa":{"digit":6}}"#), .field),
      (Self.wrap(#"{"routes":{"includes":[]}}"#), .field),
      (Self.wrap(#"{"dns":{"domain":[]}}"#), .field),
      (Self.wrap(#"{"id":"example","id":"other"}"#), .duplicateKey),
      (Self.wrap(#"{"gateway":{"host":"a.example.com","host":"b.example.com"}}"#), .duplicateKey),
      (Self.wrap(#"{"routes":{"preserve_lan":null}}"#), .field),
      (Self.wrap(#"{"dns":{"domains":[null]}}"#), .field),
      (Self.wrap("[]"), .field),
      (Self.wrap(#"{"gateway":"vpn.example.com"}"#), .field),
      (Self.wrap(#"{"gateway":{"port":"443"}}"#), .json),
      (Self.wrap(#"{"gateway":{"port":4.43e2}}"#), .json),
      (Self.wrap(#"{"routes":{"include":"192.0.2.0/24"}}"#), .json),
      (Data(#"{"format":"fortix-profile","version":1,"profiles":{}}"#.utf8), .json),
      (Data("[]".utf8), .field),
      (Data(), .json),
      (Data(#"{"format":"#.utf8), .json),
      (Self.wrap("{}") + Data("{}".utf8), .json),
      (Self.wrap(#"{"name":""#) + Data([0xff]) + Data(#""}"#.utf8), .json),
    ]
    for (data, kind) in cases { requireKind(data, kind) }
  }

  /// TestSuppliedFieldValidation rejects invalid supplied values and accepts valid partial drafts.
  func testSuppliedFieldValidation() throws {
    let invalid: [(String, String)] = [
      (#"{"id":"../example"}"#, "id"), (#"{"name":""}"#, "name"),
      (#"{"backend":"other"}"#, "backend"),
      (#"{"gateway":{"host":"https://vpn.example.com"}}"#, "gateway.host"),
      (#"{"gateway":{"port":0}}"#, "gateway.port"), (#"{"realm":"not allowed"}"#, "realm"),
      (#"{"trusted_cert":"bad"}"#, "trusted_cert"), (#"{"mfa":{"digits":7}}"#, "mfa.digits"),
      (#"{"mfa":{"mode":"none","digits":6}}"#, "mfa.digits"),
      (#"{"backend":"native","mfa":{"mode":"push"}}"#, "backend"),
      (#"{"routes":{"include":[]}}"#, "routes.include"),
      (#"{"routes":{"include":["192.0.2.0/7"]}}"#, "routes.include[0]"),
      (#"{"routes":{"include":["2001:db8::/32"]}}"#, "routes.include[0]"),
      (#"{"routes":{"include":["192.0.2.0/024"]}}"#, "routes.include[0]"),
      (#"{"routes":{"include":["192.0.2.0/24","192.0.2.128/25"]}}"#, "routes.include[1]"),
      (#"{"dns":{"domains":["example"]}}"#, "dns.domains[0]"),
      (#"{"dns":{"domains":["*.*.example.com"]}}"#, "dns.domains[0]"),
      (#"{"dns":{"domains":["*.Example.com","example.com"]}}"#, "dns.domains[1]"),
    ]
    for (profile, field) in invalid {
      XCTAssertThrowsError(try SharedProfiles.parse(Self.wrap(profile)), profile) { error in
        let problem = error as? SharedProfileError
        XCTAssertEqual(problem?.kind, .invalid, profile)
        XCTAssertTrue(problem?.problems.contains { $0.field == field } == true, profile)
      }
    }
    for profile in [
      #"{"backend":"native"}"#, #"{"mfa":{"digits":8}}"#, #"{"routes":{"preserve_lan":false}}"#,
      #"{"realm":""}"#, #"{"trusted_cert":""}"#, #"{"gateway":{"host":"192.0.2.10"}}"#,
    ] {
      XCTAssertNoThrow(try SharedProfiles.parse(Self.wrap(profile)), profile)
    }
    let pin = try SharedProfiles.parse(
      Self.wrap(#"{"trusted_cert":""# + String(repeating: "AB:", count: 31) + #"AB"}"#))
    XCTAssertEqual(pin[0].trustedCert, String(repeating: "ab", count: 32))
  }

  /// TestWildcardNormalization strips one wildcard label and lowercases supplied domains.
  func testWildcardNormalization() throws {
    XCTAssertEqual(ProfileRules.normalizeDomain("*.Example2.com"), "example2.com")
    XCTAssertEqual(ProfileRules.normalizeDomain("*.*.example.com"), "*.*.example.com")
    XCTAssertEqual(ProfileRules.normalizePrefix(" \t192.0.2.19/24\n"), "192.0.2.0/24")
    let drafts = try SharedProfiles.parse(
      Self.wrap(
        #"{"routes":{"mode":"custom","include":[" 192.0.2.19/24 "]},"dns":{"mode":"split","domains":["*.Example2.com"]}}"#
      ))
    XCTAssertEqual(drafts[0].dns?.domains, ["example2.com"])
    XCTAssertEqual(drafts[0].routes?.include, ["192.0.2.0/24"])
    XCTAssertEqual(drafts[0].missing, ["id", "name", "gateway.host", "username"])
    let split = try SharedProfiles.parse(Self.wrap(#"{"dns":{"mode":"split"}}"#))
    XCTAssertEqual(split[0].missing, ["id", "name", "gateway.host", "username", "dns.domains"])
  }

  /// TestLimits checks the exact byte boundary, profile counts, and duplicate supplied IDs.
  func testLimits() throws {
    let minimal = Self.wrap("{}")
    let exact = minimal + Data(repeating: 0x20, count: SharedProfiles.maxBytes - minimal.count)
    XCTAssertEqual(try SharedProfiles.parse(exact).count, 1)
    requireKind(exact + Data([0x20]), .size)
    requireKind(Self.wrap(), .count)
    let inputs = (0..<32).map { #"{"id":"example-\#($0)"}"# }
    XCTAssertEqual(try SharedProfiles.parse(Self.wrap(inputs.joined(separator: ","))).count, 32)
    requireKind(Self.wrap((inputs + ["{}"]).joined(separator: ",")), .count)
    requireKind(Self.wrap(#"{"id":"example"}"#, #"{"id":"example"}"#), .duplicateID)
    XCTAssertEqual(try SharedProfiles.parse(Self.wrap("{}", "{}")).count, 2)
    let profiles = (0..<33).map { index -> VPNProfile in
      var profile = Self.example
      profile.id = "example-\(index)"
      return profile
    }
    XCTAssertNoThrow(try SharedProfiles.export(Array(profiles.prefix(32))))
    XCTAssertThrowsError(try SharedProfiles.export(profiles))
    XCTAssertThrowsError(try SharedProfiles.export([]))
    XCTAssertThrowsError(try SharedProfiles.export([Self.example, Self.example])) {
      XCTAssertEqual(($0 as? SharedProfileError)?.kind, .duplicateID)
    }
    var invalid = Self.example
    invalid.schemaVersion = 2
    XCTAssertThrowsError(try SharedProfiles.export([invalid])) {
      XCTAssertEqual(($0 as? SharedProfileError)?.field, "schema_version")
    }
  }

  /// TestReadBoundsFileSize parses a file and rejects one larger than the limit without loading it all.
  func testReadBoundsFileSize() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let small = directory.appendingPathComponent("example.fortix.json")
    try SharedProfiles.export([Self.example]).write(to: small)
    XCTAssertEqual(try SharedProfiles.read(contentsOf: small).first?.id, "example")
    let large = directory.appendingPathComponent("large.fortix.json")
    try (Self.wrap("{}") + Data(repeating: 0x20, count: SharedProfiles.maxBytes)).write(to: large)
    XCTAssertThrowsError(try SharedProfiles.read(contentsOf: large)) {
      XCTAssertEqual(($0 as? SharedProfileError)?.kind, .size)
    }
  }

  /// TestMergeSemantics overlays supplied fields only, keeps identity, and replaces lists whole.
  func testMergeSemantics() throws {
    var existing = Self.example
    existing.id = "existing"
    existing.username = "kept-user"
    existing.routes.include = ["192.0.2.0/25", "198.51.100.0/24"]
    existing.dns.domains = ["one.example.com", "two.example.com"]
    let drafts = try SharedProfiles.parse(
      Self.wrap(
        #"{"id":"other","gateway":{"port":8443},"routes":{"include":["203.0.113.0/24"]},"dns":{"domains":["*.Example2.com"]}}"#
      ))
    let merged = drafts[0].merge(into: existing)
    XCTAssertEqual(merged.id, "existing")
    XCTAssertEqual(merged.username, "kept-user")
    XCTAssertEqual(merged.name, existing.name)
    XCTAssertEqual(merged.gateway.host, existing.gateway.host)
    XCTAssertEqual(merged.gateway.port, 8443)
    XCTAssertEqual(merged.realm, existing.realm)
    XCTAssertEqual(merged.routes.mode, "custom")
    XCTAssertEqual(merged.routes.preserveLAN, false)
    XCTAssertEqual(merged.routes.include, ["203.0.113.0/24"])
    XCTAssertEqual(merged.dns.domains, ["example2.com"])
    XCTAssertEqual(drafts[0].apply(to: existing).id, "other")
  }

  /// TestEscaping writes HTML-sensitive characters as escapes that parse back unchanged.
  func testEscaping() throws {
    var profile = Self.example
    profile.name = "R&D <\"Example\"> \\ 2"
    let data = try SharedProfiles.export([profile])
    let text = String(decoding: data, as: UTF8.self)
    XCTAssertTrue(text.contains(#"R\u0026D \u003c\"Example\"\u003e \\ 2"#), text)
    XCTAssertEqual(try SharedProfiles.parse(data)[0].name, profile.name)
    let escaped = try SharedProfiles.parse(Self.wrap(#"{"name":"\u00e9\ud83d\ude00"}"#))
    XCTAssertEqual(escaped[0].name, "\u{e9}\u{1F600}")
  }
}
