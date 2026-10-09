import FortixCore
import Foundation
import XCTest

@testable import FortixApp

/// AppTests exercise presentation, challenge binding, secret retention, and explicit installer commands.
final class AppTests: XCTestCase {
  /// TestRingGeometry checks the distinct monochrome states against the CLI's design-grid rules.
  @MainActor func testRingGeometry() {
    XCTAssertEqual(RingRenderer.coverage(x: 0, y: 0, status: .notConnected, frame: 0), 0)
    XCTAssertEqual(RingRenderer.coverage(x: 0, y: 0, status: .connected, frame: 0), 1)
    XCTAssertEqual(RingRenderer.coverage(x: -2, y: 0, status: .partial, frame: 0), 1)
    XCTAssertEqual(RingRenderer.coverage(x: 2, y: 0, status: .partial, frame: 0), 0)
    XCTAssertEqual(RingRenderer.coverage(x: 8, y: 0, status: .attention, frame: 0), 1)
    XCTAssertEqual(RingRenderer.coverage(x: 8, y: 3, status: .attention, frame: 0), 0)
    XCTAssertEqual(RingRenderer.coverage(x: 0, y: -8, status: .connecting, frame: 0), 1)
    XCTAssertEqual(RingRenderer.coverage(x: 0, y: -8, status: .connecting, frame: 3), 0.35)
    XCTAssertTrue(RingRenderer.image(status: .connected, frame: 0).isTemplate)
  }

  /// TestAnimation verifies twelve one-second frames and a static reduced-motion substitution.
  func testAnimation() {
    for frame in 0..<12 {
      XCTAssertEqual(
        RingRenderer.frame(time: (Double(frame) + 0.25) / 12, animate: true, reduceMotion: false),
        frame)
    }
    XCTAssertEqual(RingRenderer.frame(time: 1, animate: true, reduceMotion: false), 0)
    XCTAssertEqual(RingRenderer.frame(time: 0.5, animate: false, reduceMotion: false), 0)
    XCTAssertEqual(RingRenderer.frame(time: 0.5, animate: true, reduceMotion: true), 0)
    XCTAssertEqual(RingRenderer.frame(time: .nan, animate: true, reduceMotion: false), 0)
  }

  /// TestDraftRoundTrip preserves omitted backend, realm, policy, and read-only certificate trust.
  func testDraftRoundTrip() throws {
    let profile = Fixture.profile
    XCTAssertEqual(try ProfileDraft(profile: profile).value(), profile)
    var draft = ProfileDraft(profile: profile)
    draft.port = "not-a-port"
    XCTAssertThrowsError(try draft.value())
    draft.port = "65536"
    XCTAssertThrowsError(try draft.value())
    draft.port = "443"
    draft.profile.routes.mode = "custom"
    draft.profile.dns.mode = "split"
    draft.routeRows = [.init(text: "10.0.0.0/8"), .init(text: " 192.0.2.0/24\n"), .init(text: "")]
    draft.domainRows = [
      .init(text: "corp.example"), .init(text: " "), .init(text: "internal.example"),
    ]
    let changed = try draft.value()
    XCTAssertNil(changed.backend)
    XCTAssertEqual(changed.routes.include, ["10.0.0.0/8", "192.0.2.0/24"])
    XCTAssertEqual(changed.dns.domains, ["corp.example", "internal.example"])
    draft.profile.backend = "native"
    draft.profile.mfa.mode = "prompt"
    XCTAssertThrowsError(try draft.value())
  }

  /// TestDraftListRows trims, drops empty rows, normalizes wildcards, and reports problems per row.
  func testDraftListRows() throws {
    var draft = ProfileDraft(profile: Fixture.profile)
    XCTAssertEqual(draft.routeRows.map(\.text), [""])
    draft.profile.routes.mode = "custom"
    draft.profile.dns.mode = "split"
    XCTAssertTrue(draft.routesEmpty)
    XCTAssertTrue(draft.domainCountInvalid)
    XCTAssertThrowsError(try draft.value())
    let bad = EntryRow(text: "192.0.2.1/24")
    let duplicate = EntryRow(text: "example2.com")
    draft.routeRows = [.init(text: "192.0.2.0/25"), bad]
    draft.domainRows = [.init(text: " *.Example2.com "), .init(text: ""), duplicate]
    XCTAssertEqual(draft.routeProblems, [bad.id: "Must be a canonical masked prefix"])
    XCTAssertEqual(draft.domainProblems, [duplicate.id: "Duplicate domain"])
    XCTAssertThrowsError(try draft.value())
    draft.routeRows.removeAll { $0.id == bad.id }
    draft.domainRows.removeAll { $0.id == duplicate.id }
    let result = try draft.value()
    XCTAssertEqual(result.routes.include, ["192.0.2.0/25"])
    XCTAssertEqual(result.dns.domains, ["example2.com"])
    draft.profile.dns.mode = "none"
    XCTAssertTrue(draft.domainProblems.isEmpty)
  }

  /// TestSharedDraftPrefill leaves absent fields empty, keeps pins out, and merges by overlay.
  func testSharedDraftPrefill() throws {
    let shared = try SharedProfiles.parse(
      Data(
        #"{"format":"fortix-profile","version":1,"profiles":[{"name":"Example","gateway":{"port":8443},"trusted_cert":"\#(String(repeating: "ab", count: 32))","routes":{"include":["192.0.2.0/24"]},"dns":{"mode":"split","domains":["*.example2.com"]}}]}"#
          .utf8))[0]
    XCTAssertEqual(shared.missing, ["id", "gateway.host", "username"])
    let created = ProfileDraft(shared: shared)
    XCTAssertEqual(created.profile.id, "")
    XCTAssertEqual(created.profile.username, "")
    XCTAssertEqual(created.profile.gateway.host, "")
    XCTAssertEqual(created.port, "8443")
    XCTAssertNil(created.profile.trustedCert)
    XCTAssertEqual(created.profile.routes.mode, "custom")
    XCTAssertEqual(created.routeRows.map(\.text), ["192.0.2.0/24"])
    XCTAssertEqual(created.domainRows.map(\.text), ["example2.com"])
    var existing = Fixture.profile
    existing.trustedCert = String(repeating: "cd", count: 32)
    existing.dns = .init(mode: "split", domains: ["corp.example", "internal.example"])
    let merged = ProfileDraft(shared: shared, merging: existing)
    XCTAssertEqual(merged.profile.id, existing.id)
    XCTAssertEqual(merged.profile.username, existing.username)
    XCTAssertEqual(merged.profile.gateway.host, existing.gateway.host)
    XCTAssertEqual(merged.profile.name, "Example")
    XCTAssertEqual(merged.profile.trustedCert, existing.trustedCert)
    XCTAssertEqual(try merged.value().dns.domains, ["example2.com"])
  }

  /// TestSharedFailureText names forbidden keys and schema paths but never supplied values.
  @MainActor func testSharedFailureText() {
    XCTAssertThrowsError(
      try SharedProfiles.parse(Data(#"{"profiles":[{"password":"do-not-echo"}]}"#.utf8))
    ) { error in
      let text = AppModel.failureText(error)
      XCTAssertTrue(text.contains("(password)"), text)
      XCTAssertFalse(text.contains("do-not-echo"), text)
    }
  }

  /// TestDraftModeChanges omit incompatible hidden fields and use the helper's prompt MFA spelling.
  func testDraftModeChanges() throws {
    var profile = Fixture.profile
    profile.mfa = .init(mode: "totp", digits: 6, period: 30, algorithm: "SHA1")
    profile.routes = .init(mode: "custom", include: ["10.0.0.0/8"])
    profile.dns = .init(mode: "split", domains: ["corp.example"])
    var draft = ProfileDraft(profile: profile)
    draft.profile.mfa.mode = "prompt"
    draft.profile.routes.mode = "gateway"
    draft.profile.dns.mode = "none"
    let result = try draft.value()
    XCTAssertEqual(result.mfa.mode, "prompt")
    XCTAssertEqual(result.resolvedBackend, "openfortivpn")
    XCTAssertNil(result.mfa.digits)
    XCTAssertNil(result.mfa.period)
    XCTAssertNil(result.mfa.algorithm)
    XCTAssertNil(result.routes.include)
    XCTAssertNil(result.dns.domains)
    draft.profile.mfa.mode = "code"
    XCTAssertThrowsError(try draft.value())
  }

  /// TestDraftExcludedRoutes saves excluded ranges for gateway mode and drops them for custom.
  func testDraftExcludedRoutes() throws {
    var profile = Fixture.profile
    profile.backend = "native"
    profile.mfa = .init(mode: "none")
    profile.routes = .init(mode: "gateway")
    var draft = ProfileDraft(profile: profile)
    draft.excludeRows = [.init(text: " 198.51.100.0/24 "), .init(text: "")]
    XCTAssertEqual(try draft.value().routes.exclude, ["198.51.100.0/24"])
    draft.excludeRows = [.init(text: "198.51.100.1/24")]
    XCTAssertFalse(draft.excludeProblems.isEmpty)
    XCTAssertThrowsError(try draft.value())
    draft.excludeRows = [.init(text: "")]
    XCTAssertNil(try draft.value().routes.exclude)
    draft.excludeRows = [.init(text: "198.51.100.0/24")]
    draft.profile.routes.mode = "custom"
    draft.routeRows = [.init(text: "192.0.2.0/24")]
    XCTAssertNil(try draft.value().routes.exclude)
  }

  /// TestFailureReportedOnce reports a failed attempt once and wraps its reason for the menu.
  @MainActor func testFailureReportedOnce() async throws {
    let model = AppModel(
      client: HelperClient(connector: { _ in AppTransport() }),
      keychain: KeychainStore(provider: MemoryKeychain()))
    var reports: [String] = []
    model.onFailure = { id, detail in reports.append("\(id) \(detail)") }
    let failed = try Fixture.event([
      "type": "state", "profile": "work", "attempt": 2, "state": "failed",
      "detail": "Other is already using 192.0.2.0/24. Disconnect Other to connect Work.",
      "wanted": false, "initiated": true, "cleanup_pending": false,
    ])
    await model.receive(failed)
    await model.receive(failed)
    await model.receive(try Fixture.state("connecting", attempt: 3))
    XCTAssertEqual(reports, ["work Other is already using 192.0.2.0/24. Disconnect Other to connect Work."])
    XCTAssertEqual(model.states["work"]?.state, "connecting")
    let lines = StatusController.wrap("Other is already using 192.0.2.0/24. Disconnect Other to connect Work.", width: 30)
    XCTAssertEqual(lines, ["Other is already using", "192.0.2.0/24. Disconnect Other", "to connect Work."])
    XCTAssertTrue(lines.allSatisfy { $0.count <= 30 })
  }

  /// TestHandshakeAndQuit verifies connecting or closing the app never starts or stops a tunnel.
  @MainActor func testHandshakeAndQuit() async throws {
    let transport = AppTransport()
    let client = HelperClient(connector: { _ in transport })
    let model = AppModel(client: client, keychain: KeychainStore(provider: MemoryKeychain()))
    try await model.connectHelper()
    XCTAssertTrue(model.reachable)
    XCTAssertEqual(model.profiles, [Fixture.profile])
    await model.stop()
    XCTAssertFalse(model.reachable)
    XCTAssertEqual(model.aggregate, .notConnected)
    let operations = await transport.operations()
    XCTAssertFalse(operations.contains("up"))
    XCTAssertFalse(operations.contains("down"))
  }

  /// TestNewDraftRejectsDuplicateID preserves every existing setting without sending the helper's upsert.
  @MainActor func testNewDraftRejectsDuplicateID() async throws {
    var original = Fixture.profile
    original.gateway = .init(host: "original.example", port: 8443)
    original.username = "original-user"
    original.routes = .init(mode: "custom", include: ["192.0.2.0/24"])
    original.dns = .init(mode: "split", domains: ["corp.example"])
    let transport = AppTransport(profiles: [original])
    let model = AppModel(client: HelperClient(connector: { _ in transport }))
    try await model.connectHelper()
    var draft = ProfileDraft(profile: ProfileDraft.newProfile)
    draft.profile = Fixture.profile
    do {
      try await model.save(draft.value(), existing: false)
      XCTFail("a new draft replaced an existing profile")
    } catch {
      XCTAssertEqual(error as? AppModel.SaveError, .duplicateID)
      XCTAssertEqual(
        AppModel.failureText(error),
        "This profile ID already exists. Edit the existing profile instead.")
    }
    XCTAssertEqual(model.profiles, [original])
    let stored = await transport.storedProfiles()
    XCTAssertEqual(stored, [original])
    let operations = await transport.operations()
    XCTAssertFalse(operations.contains("profile.put"))
    await model.stop()
  }

  /// TestNewDraftChecksFreshIDs rejects a duplicate created after the app's last configuration refresh.
  @MainActor func testNewDraftChecksFreshIDs() async throws {
    let transport = AppTransport()
    let model = AppModel(client: HelperClient(connector: { _ in transport }))
    try await model.connectHelper()
    var added = Fixture.profile
    added.id = "later"
    await transport.store(added)
    var draft = added
    draft.gateway.host = "replacement.example"
    do {
      try await model.save(draft, existing: false)
      XCTFail("a stale UI list permitted replacement")
    } catch {
      XCTAssertEqual(error as? AppModel.SaveError, .duplicateID)
    }
    XCTAssertEqual(model.profiles, [Fixture.profile])
    let stored = await transport.storedProfiles()
    XCTAssertTrue(stored.contains(added))
    let operations = await transport.operations()
    XCTAssertEqual(operations.last, "profile.list")
    XCTAssertFalse(operations.contains("profile.put"))
    await model.stop()
  }

  /// TestNewAndExistingDraftsSave permits a unique new profile and intentional edits to an existing ID.
  @MainActor func testNewAndExistingDraftsSave() async throws {
    let transport = AppTransport()
    let model = AppModel(client: HelperClient(connector: { _ in transport }))
    try await model.connectHelper()
    var added = Fixture.profile
    added.id = "new"
    try await model.save(added, existing: false)
    var edited = Fixture.profile
    edited.gateway.host = "updated.example"
    try await model.save(edited, existing: true)
    XCTAssertEqual(model.profiles, [added, edited])
    let stored = await transport.storedProfiles()
    XCTAssertEqual(stored, [added, edited])
    let operations = await transport.operations()
    XCTAssertEqual(operations.filter { $0 == "profile.put" }.count, 2)
    await model.stop()
  }

  /// TestReinstallRestartsConnection restores snapshots and profile controls after uninstall without relaunch.
  @MainActor func testReinstallRestartsConnection() async throws {
    let connections = AppConnections()
    let model = AppModel(client: HelperClient(connector: { _ in await connections.connect() }))
    let runner = RecordingRunner()
    let installation = AppInstallation(
      bundleURL: URL(fileURLWithPath: "/Applications/Fortix.app"), runner: runner)
    model.start()
    try await Fixture.waitUntil { model.reachable }
    try await model.disconnect()
    try await installation.uninstall()
    await model.stop()
    XCTAssertFalse(model.reachable)
    try await model.installHelper(installation)
    model.start()
    try await Fixture.waitUntil { model.reachable }
    XCTAssertEqual(model.profiles, [Fixture.profile])
    XCTAssertEqual(model.states["work"]?.state, "connected")
    let transports = await connections.transports
    XCTAssertEqual(transports.count, 2)
    let operations = await transports.last?.operations()
    XCTAssertEqual(operations, ["hello", "subscribe", "status", "profile.list", "profile.get"])
    let calls = await runner.calls
    XCTAssertEqual(calls.count, 2)
    XCTAssertTrue(calls[0].1.last!.contains("'uninstall'"))
    XCTAssertTrue(calls[1].1.last!.contains("'install' '--app-bundle'"))
    await model.stop()
  }

  /// TestFailedInstallDoesNotStartConnection leaves the app offline when its installer fails or is cancelled.
  @MainActor func testFailedInstallDoesNotStartConnection() async throws {
    let connections = AppConnections()
    let model = AppModel(client: HelperClient(connector: { _ in await connections.connect() }))
    let runner = RecordingRunner(failure: .commandFailed)
    let installation = AppInstallation(
      bundleURL: URL(fileURLWithPath: "/Applications/Fortix.app"), runner: runner)
    do {
      try await model.installHelper(installation)
      XCTFail("a failed installation was accepted")
    } catch {
      XCTAssertEqual(error as? CoreError, .commandFailed)
    }
    XCTAssertFalse(model.reachable)
    let transports = await connections.transports
    XCTAssertTrue(transports.isEmpty)
    await model.stop()
  }

  /// TestPasswordSavesOnlyAfterMatchingSuccess rejects stale prompts and never saves on answer success alone.
  @MainActor func testPasswordSavesOnlyAfterMatchingSuccess() async throws {
    let transport = AppTransport()
    let provider = MemoryKeychain()
    let model = AppModel(
      client: HelperClient(connector: { _ in transport }),
      keychain: KeychainStore(provider: provider))
    try await model.connectHelper()
    await model.receive(try Fixture.state("waiting_password", attempt: 1))
    await model.receive(try Fixture.challenge(attempt: 1))
    let prompt = try XCTUnwrap(model.prompts.first)
    try await model.answer(prompt, secret: "synthetic-password", remember: true)
    XCTAssertEqual(provider.count, 0)
    await model.receive(try Fixture.state("connected", attempt: 1))
    XCTAssertEqual(provider.count, 1)
    let key = try CredentialKey(profile: Fixture.profile)
    let stored = try provider.read(service: CredentialKey.service, account: key.account)
    XCTAssertEqual(
      String(data: stored, encoding: .utf8),
      KeychainStore.prefix + Data("synthetic-password".utf8).base64EncodedString())
    await model.receive(try Fixture.state("waiting_password", attempt: 2))
    await model.receive(try Fixture.challenge(attempt: 1))
    XCTAssertTrue(model.prompts.isEmpty)
  }

  /// TestFailedAttemptDiscardsPassword ensures a later successful generation cannot persist a failed candidate.
  @MainActor func testFailedAttemptDiscardsPassword() async throws {
    let transport = AppTransport()
    let provider = MemoryKeychain()
    let model = AppModel(
      client: HelperClient(connector: { _ in transport }),
      keychain: KeychainStore(provider: provider))
    try await model.connectHelper()
    await model.receive(try Fixture.state("waiting_password", attempt: 1))
    await model.receive(try Fixture.challenge(attempt: 1))
    try await model.answer(
      XCTUnwrap(model.prompts.first), secret: "failed-password", remember: true)
    await model.receive(try Fixture.state("failed", attempt: 1))
    await model.receive(try Fixture.state("connected", attempt: 2))
    XCTAssertEqual(provider.count, 0)
  }

  /// TestSecondFactorNeverPersists verifies codes do not enter the password secure store even if requested.
  @MainActor func testSecondFactorNeverPersists() async throws {
    let transport = AppTransport()
    let provider = MemoryKeychain()
    let model = AppModel(
      client: HelperClient(connector: { _ in transport }),
      keychain: KeychainStore(provider: provider))
    try await model.connectHelper()
    await model.receive(try Fixture.state("waiting_code", attempt: 1))
    await model.receive(try Fixture.challenge(attempt: 1, kind: "code"))
    try await model.answer(XCTUnwrap(model.prompts.first), secret: "123456", remember: true)
    await model.receive(try Fixture.state("connected", attempt: 1))
    XCTAssertEqual(provider.count, 0)
  }

  /// TestKeychainReuseAndForget uses the exact shared identity and removes it without a disk fallback.
  @MainActor func testKeychainReuseAndForget() async throws {
    let transport = AppTransport()
    let provider = MemoryKeychain()
    let keychain = KeychainStore(provider: provider)
    try await keychain.set("saved-synthetic-password", for: CredentialKey(profile: Fixture.profile))
    let model = AppModel(client: HelperClient(connector: { _ in transport }), keychain: keychain)
    try await model.connectHelper()
    await model.receive(try Fixture.state("waiting_password", attempt: 1))
    await model.receive(try Fixture.challenge(attempt: 1))
    XCTAssertTrue(model.prompts.isEmpty)
    let operations = await transport.operations()
    XCTAssertTrue(operations.contains("answer"))
    try await model.forget("work")
    XCTAssertEqual(provider.count, 0)
    try await model.forget("work")
  }

  /// TestAdvancingChallengeInvalidatesSheet prevents a password response after the helper requests a code.
  @MainActor func testAdvancingChallengeInvalidatesSheet() async throws {
    let transport = AppTransport()
    let model = AppModel(
      client: HelperClient(connector: { _ in transport }),
      keychain: KeychainStore(provider: MemoryKeychain()))
    try await model.connectHelper()
    await model.receive(try Fixture.state("waiting_password", attempt: 1))
    await model.receive(try Fixture.challenge(attempt: 1))
    let prompt = try XCTUnwrap(model.prompts.first)
    await model.receive(try Fixture.state("waiting_code", attempt: 1))
    XCTAssertFalse(model.isCurrent(prompt))
    XCTAssertTrue(model.prompts.isEmpty)
    do {
      try await model.answer(prompt, secret: "stale-password", remember: true)
      XCTFail("stale challenge was answered")
    } catch {}
    let operations = await transport.operations()
    XCTAssertFalse(operations.contains("answer"))
  }

  /// TestQueuedChallengesRemainIndependent keeps simultaneous code prompts instead of replacing another profile.
  @MainActor func testQueuedChallengesRemainIndependent() async throws {
    let transport = AppTransport()
    let model = AppModel(
      client: HelperClient(connector: { _ in transport }),
      keychain: KeychainStore(provider: MemoryKeychain()))
    try await model.connectHelper()
    await model.receive(try Fixture.state("waiting_code", attempt: 1))
    await model.receive(try Fixture.challenge(attempt: 1, kind: "code"))
    await model.receive(
      try Fixture.event([
        "type": "state", "profile": "other", "attempt": 1,
        "state": "waiting_code", "wanted": true, "initiated": true, "cleanup_pending": false,
        "detail": "",
      ]))
    await model.receive(
      try Fixture.event([
        "type": "challenge", "profile": "other", "attempt": 1,
        "challenge_id": "other-challenge", "kind": "code", "prompt": "Synthetic code request",
      ]))
    XCTAssertEqual(model.prompts.count, 2)
    await model.receive(try Fixture.state("connected", attempt: 1))
    XCTAssertEqual(model.currentPrompt?.event.profile, "other")
  }

  /// TestTransportLossDiscardsPassword ensures reconnect never carries a candidate or a stale prompt forward.
  @MainActor func testTransportLossDiscardsPassword() async throws {
    let transport = AppTransport()
    let provider = MemoryKeychain()
    let model = AppModel(
      client: HelperClient(connector: { _ in transport }),
      keychain: KeychainStore(provider: provider))
    try await model.connectHelper()
    await model.receive(try Fixture.state("waiting_password", attempt: 1))
    await model.receive(try Fixture.challenge(attempt: 1))
    try await model.answer(
      XCTUnwrap(model.prompts.first), secret: "unsaved-password", remember: true)
    await model.stop()
    await model.receive(try Fixture.state("connected", attempt: 1))
    XCTAssertEqual(provider.count, 0)
    XCTAssertFalse(model.reachable)
  }

  /// TestStaleTrustCannotWrite validates that the sheet's profile and attempt remain authoritative.
  @MainActor func testStaleTrustCannotWrite() async throws {
    let transport = AppTransport()
    let model = AppModel(
      client: HelperClient(connector: { _ in transport }),
      keychain: KeychainStore(provider: MemoryKeychain()))
    try await model.connectHelper()
    await model.receive(try Fixture.state("waiting_trust", attempt: 1))
    await model.receive(try Fixture.certificate(attempt: 1))
    let prompt = try XCTUnwrap(model.prompts.first)
    await model.receive(try Fixture.state("waiting_trust", attempt: 2))
    do {
      try await model.trust(prompt)
      XCTFail("stale trust was accepted")
    } catch {}
    let operations = await transport.operations()
    XCTAssertFalse(operations.contains("trust"))
  }

  /// TestDisconnectAndBoundedLogs checks clean all-profile down and five-hundred-line presentation limits.
  @MainActor func testDisconnectAndBoundedLogs() async throws {
    let transport = AppTransport()
    let model = AppModel(
      client: HelperClient(connector: { _ in transport }),
      keychain: KeychainStore(provider: MemoryKeychain()))
    try await model.connectHelper()
    try await model.disconnect()
    XCTAssertEqual(model.states["work"]?.state, "disconnected")
    try await model.loadLogs("work")
    XCTAssertEqual(model.logs, ["work: redacted diagnostic"])
    for index in 0..<510 { await model.receive(try Fixture.log("line-\(index)")) }
    XCTAssertEqual(model.logs.count, 500)
    XCTAssertEqual(model.logs.last, "work: line-509")
  }

  /// TestInstallCommands verifies one prompt, explicit user, fixed helper location, safe quoting, and no purge.
  func testInstallCommands() async throws {
    let runner = RecordingRunner()
    let installation = AppInstallation(
      bundleURL: URL(fileURLWithPath: "/Applications/Fortix.app"), runner: runner)
    XCTAssertTrue(installation.isInApplications)
    try await installation.install(user: "synthetic-user")
    try await installation.addMFASupport(
      binary: URL(fileURLWithPath: "/tmp/synthetic' path/openfortivpn"))
    try await installation.uninstall()
    let calls = await runner.calls
    XCTAssertEqual(calls.count, 3)
    XCTAssertTrue(calls.allSatisfy { $0.0.path == "/usr/bin/osascript" })
    XCTAssertTrue(calls[0].1.last!.contains("'install' '--app-bundle' '--user' 'synthetic-user'"))
    XCTAssertTrue(calls[1].1.last!.contains("'--add-openfortivpn'"))
    XCTAssertTrue(calls[1].1.last!.contains("synthetic'\\\\'' path"))
    XCTAssertTrue(calls[2].1.last!.contains("'uninstall'"))
    XCTAssertFalse(calls[2].1.last!.contains("--purge"))
    let outside = AppInstallation(
      bundleURL: URL(fileURLWithPath: "/Volumes/Fortix/Fortix.app"), runner: runner)
    XCTAssertFalse(outside.isInApplications)
    do {
      try await outside.install(user: "synthetic-user")
      XCTFail("installation outside Applications was accepted")
    } catch {}
    let after = await runner.calls
    XCTAssertEqual(after.count, 3)
  }
}

/// Fixture builds synthetic protocol objects without accessing a real helper or gateway.
private enum Fixture {
  /// Profile contains only synthetic configuration and preserves omitted backend selection.
  static let profile = VPNProfile(
    id: "work", name: "Work", gateway: .init(host: "vpn.example"), username: "user")

  /// WaitUntil permits five seconds of actor scheduling and fails instead of hanging on lifecycle regressions.
  @MainActor static func waitUntil(_ condition: @MainActor () -> Bool) async throws {
    for _ in 0..<500 {
      if condition() { return }
      try await Task.sleep(nanoseconds: 10_000_000)
    }
    XCTFail("the expected app lifecycle state was not reached within five seconds")
    throw CoreError.timeout
  }

  /// Event decodes an in-memory helper notification for presentation tests.
  static func event(_ fields: [String: Any]) throws -> HelperEvent {
    try JSONDecoder().decode(HelperEvent.self, from: JSONSerialization.data(withJSONObject: fields))
  }

  /// State creates a wanted-profile transition for a specific tunnel generation.
  static func state(_ state: String, attempt: UInt64) throws -> HelperEvent {
    try event([
      "type": "state", "profile": "work", "attempt": attempt, "state": state,
      "detail": "", "wanted": state != "disconnected", "initiated": true, "cleanup_pending": false,
    ])
  }

  /// Challenge creates a password or code prompt with a generation-specific challenge ID.
  static func challenge(attempt: UInt64, kind: String = "password") throws -> HelperEvent {
    try event([
      "type": "challenge", "profile": "work", "attempt": attempt,
      "challenge_id": "challenge-\(attempt)", "kind": kind, "prompt": "Synthetic prompt",
    ])
  }

  /// Certificate supplies a synthetic rejected fingerprint for trust-binding tests.
  static func certificate(attempt: UInt64) throws -> HelperEvent {
    try event([
      "type": "cert", "profile": "work", "attempt": attempt,
      "digest": String(repeating: "a", count: 64), "subject": "Synthetic subject",
      "issuer": "Synthetic issuer",
    ])
  }

  /// Log creates an already-redacted diagnostic without secret-bearing input.
  static func log(_ line: String) throws -> HelperEvent {
    try event(["type": "log", "profile": "work", "attempt": 0, "line": line])
  }
}

/// AppTransport answers requests deterministically without sockets, privileges, or network mutation.
private actor AppTransport: HelperTransport {
  /// Queue retains complete replies until the core reader requests them.
  private var queue: [Data] = []
  /// Waiter is the single outstanding duplex reader.
  private var waiter: CheckedContinuation<Data, Error>?
  /// Closed makes future reads fail immediately.
  private var closed = false
  /// Requests permit assertions on emitted operations without retaining secret diagnostics.
  private var requests: [String] = []
  /// Stopped changes the authoritative snapshot only after a down request.
  private var stopped = false
  /// Configurations retain helper-owned profiles so rejected drafts can be checked for data loss.
  private var configurations: [String: VPNProfile]

  /// Creates an isolated helper store with the supplied synthetic profiles and no transport side effects.
  init(profiles: [VPNProfile] = [Fixture.profile]) {
    configurations = Dictionary(uniqueKeysWithValues: profiles.map { ($0.id, $0) })
  }

  /// Read suspends until a deterministic response or explicit close wakes it.
  func read() async throws -> Data {
    if closed { throw CoreError.disconnected }
    if !queue.isEmpty { return queue.removeFirst() }
    return try await withCheckedThrowingContinuation { waiter = $0 }
  }

  /// Write creates the same response shape as the helper for each tested operation.
  func write(_ data: Data) async throws {
    let request = try JSONDecoder().decode(HelperRequest.self, from: data)
    requests.append(request.op)
    var response: [String: Any] = ["type": "result", "id": request.id, "ok": true]
    switch request.op {
    case "hello": response["data"] = ["protocol": 1]
    case "status":
      response["data"] = [
        [
          "wanted": !stopped, "initiated": true, "cleanup_pending": false,
          "profile": "work", "state": stopped ? "disconnected" : "connected", "detail": "",
          "attempt": 0,
          "interface": "", "local_ip": "", "since": "0001-01-01T00:00:00Z",
        ]
      ]
    case "profile.list":
      response["data"] = configurations.keys.sorted().map {
        ["profile": $0, "state": "disconnected"]
      }
    case "profile.get":
      guard let id = request.profile, let profile = configurations[id] else {
        throw CoreError.invalidProfile
      }
      response["data"] = try JSONSerialization.jsonObject(with: JSONEncoder().encode(profile))
    case "profile.put":
      guard let data = request.profileJSON else { throw CoreError.invalidProfile }
      store(try data.decode(VPNProfile.self))
    case "down": stopped = true
    case "logs": response["data"] = ["redacted diagnostic"]
    default: break
    }
    var bytes = try JSONSerialization.data(withJSONObject: response)
    bytes.append(10)
    if let waiter {
      self.waiter = nil
      waiter.resume(returning: bytes)
    } else {
      queue.append(bytes)
    }
  }

  /// Close wakes the actor's suspended reader without touching a real descriptor.
  nonisolated func close() { Task { await finish() } }

  /// Finish ensures the single pending read is completed exactly once on closure.
  private func finish() {
    closed = true
    waiter?.resume(throwing: CoreError.disconnected)
    waiter = nil
  }

  /// Store simulates helper upsert or another client's write without changing the app's cached profiles.
  func store(_ profile: VPNProfile) { configurations[profile.id] = profile }

  /// StoredProfiles returns sorted configurations so tests can detect accidental replacement.
  func storedProfiles() -> [VPNProfile] {
    configurations.keys.sorted().compactMap { configurations[$0] }
  }

  /// Operations returns only operation names, not credentials or shell arguments.
  func operations() -> [String] { requests }
}

/// AppConnections creates a fresh fake socket for each connection attempt in lifecycle tests.
private actor AppConnections {
  /// Transports retain each fake helper connection for handshake and no-replay assertions.
  private(set) var transports: [AppTransport] = []

  /// Connect records a new transport, never reusing one that a previous uninstall closed.
  func connect() -> AppTransport {
    let transport = AppTransport()
    transports.append(transport)
    return transport
  }
}

/// MemoryKeychain provides isolated secure-store semantics without accessing the machine's Keychain.
private final class MemoryKeychain: KeychainProvider, @unchecked Sendable {
  /// Lock protects the test store across helper and credential tasks.
  private let lock = NSLock()
  /// Values contain only explicitly supplied synthetic credentials.
  private var values: [String: Data] = [:]
  /// Count reports the number of persisted entries without revealing their contents.
  var count: Int {
    lock.lock()
    defer { lock.unlock() }
    return values.count
  }

  /// Read returns one stored value or the same typed missing error as the system provider.
  func read(service: String, account: String) throws -> Data {
    lock.lock()
    defer { lock.unlock() }
    guard let value = values[service + account] else { throw KeychainError.notFound }
    return value
  }

  /// Write atomically records synthetic encoded data under the bound identity.
  func write(service: String, account: String, data: Data) throws {
    lock.lock()
    defer { lock.unlock() }
    values[service + account] = data
  }

  /// Delete removes only one identity and retains the missing-entry error behavior.
  func delete(service: String, account: String) throws {
    lock.lock()
    defer { lock.unlock() }
    guard values.removeValue(forKey: service + account) != nil else { throw KeychainError.notFound }
  }
}

/// RecordingRunner captures explicit administrator command construction without executing anything.
private actor RecordingRunner: CommandRunner {
  /// Calls contain executable and argument vectors for quoting and privilege-boundary assertions.
  private(set) var calls: [(URL, [String])] = []
  /// Failure optionally simulates an unsuccessful command without running a privileged executable.
  private let failure: CoreError?

  /// Creates a recording runner that succeeds unless a fixed synthetic failure is supplied.
  init(failure: CoreError? = nil) { self.failure = failure }

  /// Run records a synthetic invocation and returns empty output or the injected failure without privileges.
  func run(executable: URL, arguments: [String], timeout: TimeInterval, maxOutput: Int) async throws
    -> CommandOutput
  {
    calls.append((executable, arguments))
    if let failure { throw failure }
    return CommandOutput()
  }
}
