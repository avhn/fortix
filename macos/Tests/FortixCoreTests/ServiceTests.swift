import Darwin
import Foundation
import XCTest

@testable import FortixCore

/// ServiceTests verifies user-privilege preview, safe installation quoting, and helper-backed profiles.
final class ServiceTests: XCTestCase {
  /// TestImporterPreview uses the bundled executable directly without --apply or elevated execution.
  func testImporterPreview() async throws {
    let requests = try Fixtures.lines("protocol.requests.ndjson")
    let request = try JSONDecoder().decode(
      HelperRequest.self,
      from: requests.first {
        String(decoding: $0, as: UTF8.self).contains("put-omitted")
      }!)
    let data = try JSONEncoder().encode(JSONValue.array([request.profileJSON!]))
    let runner = FakeCommandRunner(output: CommandOutput(stdout: data))
    let executable = URL(
      fileURLWithPath: "/Applications/Fortix.app/Contents/Resources/libexec/fortix")
    let importer = FortiClientImporter(executable: executable, runner: runner)
    let drafts = try await importer.preview(
      plist: URL(fileURLWithPath: "/tmp/source 'quoted';.plist"))
    XCTAssertEqual(drafts.count, 1)
    XCTAssertNil(drafts[0].backend)
    let invocations = await runner.invocations
    XCTAssertEqual(invocations[0].executable, executable)
    XCTAssertEqual(
      invocations[0].arguments, ["import", "forticlient", "--plist", "/tmp/source 'quoted';.plist"])
    XCTAssertEqual(invocations[0].timeout, 15)
    XCTAssertFalse(invocations[0].arguments.contains("--apply"))
  }

  /// TestImporterEmptyPreview accepts only an entire top-level null or an ordinary empty array.
  func testImporterEmptyPreview() async throws {
    for text in ["null", " \t\r\nnull\n\r\t ", "[]"] {
      let runner = FakeCommandRunner(output: CommandOutput(stdout: Data(text.utf8)))
      let importer = FortiClientImporter(
        executable: URL(fileURLWithPath: "/tmp/fortix"), runner: runner)
      let drafts = try await importer.preview()
      XCTAssertTrue(drafts.isEmpty)
    }
    for text in ["[null]", "{\"profile\":null}", "null []", "nullx", "\u{00A0}null"] {
      let runner = FakeCommandRunner(output: CommandOutput(stdout: Data(text.utf8)))
      let importer = FortiClientImporter(
        executable: URL(fileURLWithPath: "/tmp/fortix"), runner: runner)
      do {
        _ = try await importer.preview()
        XCTFail("Expected invalid preview output")
      } catch { XCTAssertEqual(error as? CoreError, .invalidMessage) }
    }
    XCTAssertThrowsError(try StrictJSON.decode(Data("null".utf8)))
  }

  /// TestImporterEmptyPlists exercises the real CLI with empty and unsupported-only plist fixtures.
  /// Set FORTIX_TEST_CLI to a built CLI to verify conversion without installing or changing profiles.
  func testImporterEmptyPlists() async throws {
    guard let path = ProcessInfo.processInfo.environment["FORTIX_TEST_CLI"] else {
      throw XCTSkip("FORTIX_TEST_CLI is required for real CLI preview fixtures")
    }
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(
      "fortix-empty-import-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
    defer { try? FileManager.default.removeItem(at: directory) }
    let fixtures = [
      "empty.plist": "<dict/>",
      "skipped.plist": """
      <dict><key>profiles</key><array>
        <dict><key>Name</key><string>Unsupported VPN</string>
          <key>VpnType</key><integer>1</integer></dict>
        <dict><key>Name</key><string>Incomplete SSL VPN</string>
          <key>VpnType</key><integer>0</integer></dict>
      </array></dict>
      """,
    ]
    let importer = FortiClientImporter(executable: URL(fileURLWithPath: path))
    for (name, body) in fixtures {
      let plist = directory.appendingPathComponent(name)
      try "<?xml version=\"1.0\"?><plist version=\"1.0\">\(body)</plist>".write(
        to: plist, atomically: true, encoding: .utf8)
      let drafts = try await importer.preview(plist: plist)
      XCTAssertTrue(drafts.isEmpty, name)
    }
  }

  /// TestImporterRejectsSecrets refuses unknown or secret-bearing CLI output instead of ignoring it.
  func testImporterRejectsSecrets() async throws {
    let data = Data("[{\"id\":\"work\",\"password\":\"synthetic\"}]".utf8)
    let runner = FakeCommandRunner(output: CommandOutput(stdout: data))
    let importer = FortiClientImporter(
      executable: URL(fileURLWithPath: "/tmp/fortix"), runner: runner)
    do {
      _ = try await importer.preview()
      XCTFail("Expected secret-free profile boundary")
    } catch { XCTAssertEqual(error as? CoreError, .invalidProfile) }
  }

  /// TestInstallerQuotesEachArgument uses a fixed AppleScript operation even with shell metacharacters.
  func testInstallerQuotesEachArgument() async throws {
    let runner = FakeCommandRunner()
    let path =
      "/Applications/Fortix 'test' \"quoted\";.app/Contents/Resources/libexec/fortix-helper"
    let installer = HelperInstaller(executable: URL(fileURLWithPath: path), runner: runner)
    let source = try installer.script(user: "test'user;$HOME")
    XCTAssertTrue(source.hasPrefix("do shell script \"'"))
    XCTAssertTrue(source.hasSuffix("\" with administrator privileges"))
    XCTAssertTrue(source.contains("'install' '--app-bundle' '--user' 'test'\\\\''user;$HOME'"))
    XCTAssertTrue(source.contains("\\\"quoted\\\""))
    try await installer.install(user: "test'user;$HOME")
    let invocation = await runner.invocations[0]
    XCTAssertEqual(invocation.executable.path, "/usr/bin/osascript")
    XCTAssertEqual(invocation.arguments, ["-e", source])
    XCTAssertEqual(invocation.timeout, 120)
    XCTAssertThrowsError(try installer.script(user: "root"))
    XCTAssertThrowsError(try installer.script(user: "user\nname"))
    XCTAssertThrowsError(try installer.script(user: "-option"))
  }

  /// TestSystemRunnerDrainsBoundsAndTimesOut exercises unprivileged synthetic commands only.
  func testSystemRunnerDrainsBoundsAndTimesOut() async throws {
    let runner = SystemCommandRunner()
    let output = try await runner.run(
      executable: URL(fileURLWithPath: "/usr/bin/printf"),
      arguments: ["%s", "synthetic"], timeout: 2, maxOutput: 64)
    XCTAssertEqual(String(decoding: output.stdout, as: UTF8.self), "synthetic")
    do {
      _ = try await runner.run(
        executable: URL(fileURLWithPath: "/usr/bin/printf"),
        arguments: ["%s", String(repeating: "x", count: 2000)], timeout: 2, maxOutput: 1000)
      XCTFail("Expected output bound")
    } catch { XCTAssertEqual(error as? CoreError, .commandFailed) }
    do {
      _ = try await runner.run(
        executable: URL(fileURLWithPath: "/bin/sleep"), arguments: ["2"],
        timeout: 0.03, maxOutput: 64)
      XCTFail("Expected process deadline")
    } catch { XCTAssertEqual(error as? CoreError, .timeout) }
  }

  /// TestSystemRunnerCancellation kills and reaps its own sleeping child instead of waiting for its deadline.
  func testSystemRunnerCancellation() async throws {
    let runner = SystemCommandRunner()
    let started = ProcessInfo.processInfo.systemUptime
    let task = Task {
      try await runner.run(
        executable: URL(fileURLWithPath: "/bin/sleep"), arguments: ["5"], timeout: 10, maxOutput: 64
      )
    }
    try await Task.sleep(nanoseconds: 50_000_000)
    task.cancel()
    do {
      _ = try await task.value
      XCTFail("Expected canceled child")
    } catch { XCTAssertTrue(error is CancellationError) }
    XCTAssertLessThan(ProcessInfo.processInfo.systemUptime - started, 2)
  }

  /// TestSystemRunnerTimeoutStopsDescendants prevents an interrupted CLI from orphaning its converter.
  func testSystemRunnerTimeoutStopsDescendants() async throws {
    let pidFile = FileManager.default.temporaryDirectory.appendingPathComponent(
      "fortix-child-" + UUID().uuidString)
    var child: Int32?
    defer {
      if let child { Darwin.kill(child, SIGKILL) }
      try? FileManager.default.removeItem(at: pidFile)
    }
    let runner = SystemCommandRunner()
    do {
      _ = try await runner.run(
        executable: URL(fileURLWithPath: "/bin/sh"),
        arguments: [
          "-c", "/bin/sleep 30 & printf '%s' \"$!\" > \"$1\"; wait", "fortix-test", pidFile.path,
        ],
        timeout: 0.2, maxOutput: 64)
      XCTFail("Expected bounded command group")
    } catch { XCTAssertEqual(error as? CoreError, .timeout) }
    let text = try String(contentsOf: pidFile, encoding: .utf8)
    child = try XCTUnwrap(Int32(text))
    let deadline = ProcessInfo.processInfo.systemUptime + 2
    while Darwin.kill(child!, 0) == 0, ProcessInfo.processInfo.systemUptime < deadline {
      try await Task.sleep(nanoseconds: 10_000_000)
    }
    XCTAssertEqual(
      Darwin.kill(child!, 0), -1, "Converter descendant must not outlive the command deadline")
  }

  /// TestSystemRunnerTimeoutStopsOrphanedDescendants kills inherited pipe holders after their leader exits.
  func testSystemRunnerTimeoutStopsOrphanedDescendants() async throws {
    try await assertOrphanedDescendantCleanup(cancel: false)
  }

  /// TestSystemRunnerCancellationStopsOrphanedDescendants cleans the retained group on caller cancellation.
  func testSystemRunnerCancellationStopsOrphanedDescendants() async throws {
    try await assertOrphanedDescendantCleanup(cancel: true)
  }

  /// AssertOrphanedDescendantCleanup starts a shell that exits without waiting for its pipe-holding child.
  /// Cancel selects caller cancellation after the leader is reaped, otherwise the runner deadline applies.
  private func assertOrphanedDescendantCleanup(cancel: Bool) async throws {
    let pidFile = FileManager.default.temporaryDirectory.appendingPathComponent(
      "fortix-orphan-" + UUID().uuidString)
    let runner = SystemCommandRunner()
    let task = Task {
      try await runner.run(
        executable: URL(fileURLWithPath: "/bin/sh"),
        arguments: [
          "-c", "/bin/sleep 30 & printf '%s %s' \"$!\" \"$$\" > \"$1\"; exit 0",
          "fortix-test", pidFile.path,
        ], timeout: cancel ? 10 : 0.5, maxOutput: 64)
    }
    var child: pid_t?
    defer {
      task.cancel()
      if let child { Darwin.kill(child, SIGKILL) }
      try? FileManager.default.removeItem(at: pidFile)
    }
    // Wait only long enough for the synthetic shell to publish both process identities.
    let startupDeadline = ProcessInfo.processInfo.systemUptime + 2
    var identities: [pid_t] = []
    repeat {
      if let text = try? String(contentsOf: pidFile, encoding: .utf8) {
        identities = text.split(separator: " ").compactMap { pid_t($0) }
      }
      if identities.count == 2 { break }
      try await Task.sleep(nanoseconds: 10_000_000)
    } while ProcessInfo.processInfo.systemUptime < startupDeadline
    XCTAssertEqual(identities.count, 2)
    guard identities.count == 2 else { return }
    child = identities[0]
    let leader = identities[1]
    while Darwin.kill(leader, 0) == 0, ProcessInfo.processInfo.systemUptime < startupDeadline {
      try await Task.sleep(nanoseconds: 10_000_000)
    }
    XCTAssertEqual(Darwin.kill(leader, 0), -1, "The leader must exit before interruption")
    XCTAssertEqual(Darwin.kill(child!, 0), 0, "The descendant must still retain the capture pipes")
    let interrupted = ProcessInfo.processInfo.systemUptime
    if cancel { task.cancel() }
    do {
      _ = try await task.value
      XCTFail("Expected interrupted command group")
    } catch {
      if cancel {
        XCTAssertTrue(error is CancellationError)
      } else {
        XCTAssertEqual(error as? CoreError, .timeout)
      }
    }
    let cleanupDeadline = ProcessInfo.processInfo.systemUptime + 2
    while Darwin.kill(child!, 0) == 0, ProcessInfo.processInfo.systemUptime < cleanupDeadline {
      try await Task.sleep(nanoseconds: 10_000_000)
    }
    XCTAssertEqual(Darwin.kill(child!, 0), -1, "The orphaned pipe holder must be terminated")
    XCTAssertLessThan(ProcessInfo.processInfo.systemUptime - interrupted, 3)
  }

  /// TestProfileStoreUsesHelperOperations sends objects rather than privileged configuration files.
  func testProfileStoreUsesHelperOperations() async throws {
    let transport = FakeTransport()
    let client = HelperClient(connector: { _ in transport })
    _ = try await client.connect()
    let store = ProfileStore(client: client)
    let profile = VPNProfile(
      id: "work", name: "Work", gateway: .init(host: "vpn.example.com"), username: "user")
    try await store.put(profile)
    try await store.delete("work")
    let requests = await transport.requests
    XCTAssertEqual(requests.suffix(2).map(\.op), ["profile.put", "profile.delete"])
    XCTAssertEqual(try VPNProfile.decode(requests[3].profileJSON!), profile)
    do {
      try await store.delete("../work")
      XCTFail("Expected safe identifier")
    } catch { XCTAssertEqual(error as? CoreError, .invalidProfile) }
    await client.close()
  }

  /// TestProfileStoreRejectsWrongIdentity prevents a mismatched profile.get from selecting credentials.
  func testProfileStoreRejectsWrongIdentity() async throws {
    let transport = FakeTransport()
    let client = HelperClient(connector: { _ in transport })
    _ = try await client.connect()
    await transport.hold(["profile.get"])
    let store = ProfileStore(client: client)
    let task = Task { try await store.get("work") }
    let deadline = ProcessInfo.processInfo.systemUptime + 2
    while await transport.requests.count < 4, ProcessInfo.processInfo.systemUptime < deadline {
      try await Task.sleep(nanoseconds: 1_000_000)
    }
    let request = await transport.requests.last!
    let wrong = VPNProfile(
      id: "other", name: "Other", gateway: .init(host: "vpn.example.com"), username: "user")
    try await transport.reply(id: request.id, data: JSONValue.make(wrong))
    do {
      _ = try await task.value
      XCTFail("Expected exact identity")
    } catch { XCTAssertEqual(error as? CoreError, .invalidMessage) }
    await client.close()
  }
}
