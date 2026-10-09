import Foundation
import XCTest

@testable import FortixCore

/// HelperClientTests validates concurrency, reconnect, bounded notifications, and clean down semantics.
final class HelperClientTests: XCTestCase {
  /// Client constructs a socket-free client with a synthetic transport.
  private func client(_ transport: FakeTransport) -> HelperClient {
    HelperClient(socketPath: "/tmp/fortix-test.sock", connector: { _ in transport })
  }

  /// WaitRequests bounds test synchronization instead of sleeping for an assumed scheduling delay.
  private func waitRequests(_ transport: FakeTransport, count: Int) async throws -> [HelperRequest]
  {
    let deadline = ProcessInfo.processInfo.systemUptime + 2
    while ProcessInfo.processInfo.systemUptime < deadline {
      let requests = await transport.requests
      if requests.count >= count { return requests }
      try await Task.sleep(nanoseconds: 1_000_000)
    }
    throw CoreError.timeout
  }

  /// Snapshot creates full synthetic helper status payloads with explicit cleanup and generation fields.
  private func snapshot(
    state: String, wanted: Bool = false, attempt: UInt64 = 1,
    cleanup: Bool = false, detail: String = ""
  ) -> JSONValue {
    .array([
      .object([
        "profile": .string("work"), "state": .string(state), "wanted": .bool(wanted),
        "initiated": .bool(true), "cleanup_pending": .bool(cleanup), "attempt": .unsigned(attempt),
        "detail": .string(detail), "interface": .string(""), "local_ip": .string(""),
        "since": .string("2026-01-02T03:04:05Z"),
      ])
    ])
  }

  /// TestSubscribeBeforeStatusAndReconnect verifies handshake ordering and no replayed up operations.
  func testSubscribeBeforeStatusAndReconnect() async throws {
    let transport = FakeTransport()
    let client = client(transport)
    _ = try await client.connect(logs: true)
    let requests = await transport.requests
    XCTAssertEqual(requests.map(\.op), ["hello", "subscribe", "status"])
    XCTAssertEqual(requests[1].logs, true)
    XCTAssertEqual(Set(requests.map(\.id)).count, requests.count)
    await client.close()
    let fresh = FakeTransport()
    let sources = TransportSources([FakeTransport(), fresh])
    let reconnecting = HelperClient(connector: { _ in try await sources.next() })
    _ = try await reconnecting.connect()
    _ = try await reconnecting.call(HelperRequest(op: "up", profile: "work"))
    _ = try await reconnecting.reconnect()
    let replayed = await fresh.requests
    XCTAssertEqual(replayed.map(\.op), ["hello", "subscribe", "status"])
    let reachable = await reconnecting.reachable
    XCTAssertTrue(reachable)
    await reconnecting.close()
  }

  /// TestOutOfOrderCorrelation keeps concurrent profile calls separate when replies arrive reversed.
  func testOutOfOrderCorrelation() async throws {
    let transport = FakeTransport()
    let active = client(transport)
    _ = try await active.connect()
    await transport.hold(["profile.get"])
    let first = Task { try await active.call(HelperRequest(op: "profile.get", profile: "first")) }
    let second = Task { try await active.call(HelperRequest(op: "profile.get", profile: "second")) }
    let requests = try await waitRequests(transport, count: 5).filter { $0.op == "profile.get" }
    for request in requests.reversed() {
      try await transport.reply(id: request.id, data: .string(request.profile!))
    }
    let a = try await first.value
    let b = try await second.value
    XCTAssertEqual(a.data, .string("first"))
    XCTAssertEqual(b.data, .string("second"))
    await active.close()
  }

  /// TestTimeoutCancellationAndLateResult verifies abandoned IDs cannot complete a later request.
  func testTimeoutCancellationAndLateResult() async throws {
    let transport = FakeTransport()
    let client = client(transport)
    _ = try await client.connect()
    await transport.hold(["profile.get"])
    do {
      _ = try await client.call(HelperRequest(op: "profile.get", profile: "work"), timeout: 0.02)
      XCTFail("Expected deadline")
    } catch { XCTAssertEqual(error as? CoreError, .timeout) }
    let timedOut = try await waitRequests(transport, count: 4).last!
    try await transport.reply(id: timedOut.id, data: .string("late"))
    let canceled = Task { try await client.call(HelperRequest(op: "profile.get", profile: "work")) }
    _ = try await waitRequests(transport, count: 5)
    canceled.cancel()
    do {
      _ = try await canceled.value
      XCTFail("Expected cancellation")
    } catch { XCTAssertTrue(error is CancellationError) }
    let snapshots = try await client.status()
    XCTAssertTrue(snapshots.isEmpty)
    await client.close()
  }

  /// TestEventsAndTransportLoss delivers partial frames then fails outstanding requests on EOF.
  func testEventsAndTransportLoss() async throws {
    let transport = FakeTransport()
    let client = client(transport)
    _ = try await client.connect()
    let stream = try await client.events()
    let eventTask = Task { () throws -> HelperEvent in
      var iterator = stream.makeAsyncIterator()
      guard let event = try await iterator.next() else { throw CoreError.disconnected }
      return event
    }
    let frame = try Fixtures.lines("protocol.events.ndjson")[0]
    await transport.push(Data(frame.prefix(8)))
    await transport.push(Data(frame.dropFirst(8)))
    let event = try await eventTask.value
    XCTAssertEqual(event.type, "state")
    XCTAssertEqual(event.state, "disconnected")
    await transport.hold(["profile.get"])
    let pending = Task { try await client.call(HelperRequest(op: "profile.get", profile: "work")) }
    _ = try await waitRequests(transport, count: 4)
    await transport.push(Data())
    do {
      _ = try await pending.value
      XCTFail("Expected socket loss")
    } catch { XCTAssertEqual(error as? CoreError, .disconnected) }
    let reachable = await client.reachable
    XCTAssertFalse(reachable)
    await client.close()
  }

  /// TestProtocolMismatch closes the stream before subscribe or any mutation.
  func testProtocolMismatch() async throws {
    let transport = FakeTransport()
    await transport.setProtocol(2)
    let client = client(transport)
    do {
      _ = try await client.connect()
      XCTFail("Expected incompatible helper")
    } catch { XCTAssertEqual(error as? CoreError, .incompatibleProtocol) }
    let operations = await transport.requests.map(\.op)
    XCTAssertEqual(operations, ["hello"])
  }

  /// TestEventOverflow fails the connection instead of losing unread password or state notifications.
  func testEventOverflow() async throws {
    let transport = FakeTransport()
    let client = client(transport)
    _ = try await client.connect()
    let frame = try Fixtures.lines("protocol.events.ndjson")[0]
    for _ in 0..<257 { await transport.push(frame) }
    let deadline = ProcessInfo.processInfo.systemUptime + 2
    while await client.reachable, ProcessInfo.processInfo.systemUptime < deadline {
      try await Task.sleep(nanoseconds: 1_000_000)
    }
    let reachable = await client.reachable
    XCTAssertFalse(reachable)
    await client.close()
  }

  /// TestDownWaitsForCleanSnapshot ensures an asynchronous down acknowledgement is not completion.
  func testDownWaitsForCleanSnapshot() async throws {
    let transport = FakeTransport()
    await transport.setStatus(snapshot(state: "connected", wanted: true))
    await transport.setDownSnapshots([snapshot(state: "stopping"), snapshot(state: "disconnected")])
    let client = client(transport)
    _ = try await client.connect()
    try await client.down(all: true, timeout: 2)
    let requests = await transport.requests
    XCTAssertEqual(requests.filter { $0.op == "down" }.count, 1)
    XCTAssertGreaterThanOrEqual(requests.filter { $0.op == "status" }.count, 4)
    await client.close()
  }

  /// TestDownRejectsCleanupCompetingStartAndMissingTarget never treats failed or incomplete status as clean.
  func testDownRejectsCleanupCompetingStartAndMissingTarget() async throws {
    let failures = [
      snapshot(state: "failed", cleanup: true), snapshot(state: "disconnected", attempt: 2),
      snapshot(state: "disconnected", wanted: true), JSONValue.array([]),
      snapshot(state: "stopping", detail: "network cleanup failed; retrying"),
    ]
    for failure in failures {
      let transport = FakeTransport()
      await transport.setStatus(snapshot(state: "connected", wanted: true))
      await transport.setDownSnapshots([failure])
      let client = client(transport)
      _ = try await client.connect()
      do {
        try await client.down(profile: "work", timeout: 1)
        XCTFail("Expected unsafe stop failure")
      } catch { XCTAssertEqual(error as? CoreError, .stopFailed) }
      await client.close()
    }
  }

  /// TestConcurrentDownReservesItsWait rejects another stop before the first status call completes.
  func testConcurrentDownReservesItsWait() async throws {
    let transport = FakeTransport()
    let client = client(transport)
    _ = try await client.connect()
    await transport.hold(["status"])
    let first = Task { try await client.down(all: true, timeout: 2) }
    _ = try await waitRequests(transport, count: 4)
    do {
      try await client.down(all: true)
      XCTFail("Expected exclusive stop wait")
    } catch { XCTAssertEqual(error as? CoreError, .invalidMessage) }
    first.cancel()
    do {
      try await first.value
      XCTFail("Expected canceled wait")
    } catch { XCTAssertTrue(error is CancellationError) }
    await client.close()
  }

  /// TestMalformedAndOversizedTransportFrames fail all callers instead of resynchronizing unsafe input.
  func testMalformedAndOversizedTransportFrames() async throws {
    let cases: [(Data, CoreError)] = [
      (Data("{\"type\":\"unknown\"}\n".utf8), .invalidMessage),
      (Data(repeating: 97, count: HelperProtocol.maxLine), .oversizedFrame),
    ]
    for (frame, expected) in cases {
      let transport = FakeTransport()
      let client = client(transport)
      _ = try await client.connect()
      await transport.hold(["profile.get"])
      let call = Task { try await client.call(HelperRequest(op: "profile.get", profile: "work")) }
      _ = try await waitRequests(transport, count: 4)
      await transport.push(frame)
      do {
        _ = try await call.value
        XCTFail("Expected terminal frame error")
      } catch { XCTAssertEqual(error as? CoreError, expected) }
      await client.close()
    }
  }

  /// TestPartialFrameDeadline closes a stalled record while allowing idle subscriptions.
  func testPartialFrameDeadline() async throws {
    let transport = FakeTransport()
    let client = client(transport)
    _ = try await client.connect()
    await transport.hold(["profile.get"])
    let call = Task {
      try await client.call(HelperRequest(op: "profile.get", profile: "work"), timeout: 12)
    }
    _ = try await waitRequests(transport, count: 4)
    await transport.push(Data("{".utf8))
    do {
      _ = try await call.value
      XCTFail("Expected bounded partial frame assembly")
    } catch { XCTAssertEqual(error as? CoreError, .timeout) }
    let reachable = await client.reachable
    XCTAssertFalse(reachable)
    await client.close()
  }

  /// TestHelperFailure preserves stable error categories for a correlated request.
  func testHelperFailure() async throws {
    let transport = FakeTransport()
    let client = client(transport)
    _ = try await client.connect()
    await transport.hold(["up"])
    let call = Task { try await client.call(HelperRequest(op: "up", profile: "work")) }
    let request = try await waitRequests(transport, count: 4).last!
    let frame =
      "{\"type\":\"result\",\"id\":\"\(request.id)\",\"ok\":false,\"error\":{\"code\":\"CONFLICT\",\"message\":\"Synthetic failure\"}}\n"
    await transport.push(Data(frame.utf8))
    do {
      _ = try await call.value
      XCTFail("Expected operation failure")
    } catch { XCTAssertEqual((error as? HelperFailure)?.code, "CONFLICT") }
    await client.close()
  }

  /// TestDownTimeout retains a finite deadline when the helper never reaches disconnected.
  func testDownTimeout() async throws {
    let transport = FakeTransport()
    await transport.setStatus(snapshot(state: "connected", wanted: true))
    await transport.setDownSnapshots([snapshot(state: "stopping")])
    let client = client(transport)
    _ = try await client.connect()
    do {
      try await client.down(all: true, timeout: 0.05)
      XCTFail("Expected bounded stop")
    } catch { XCTAssertEqual(error as? CoreError, .timeout) }
    await client.close()
  }
}

/// TransportSources returns a finite series of fake transports for reconnect tests.
private actor TransportSources {
  /// Transports contains one replacement stream per expected connection.
  private var transports: [FakeTransport]
  /// Creates a source without invoking a real connector.
  init(_ transports: [FakeTransport]) { self.transports = transports }
  /// Next returns one unused fake or fails if the client reconnects unexpectedly.
  func next() throws -> FakeTransport {
    guard !transports.isEmpty else { throw CoreError.disconnected }
    return transports.removeFirst()
  }
}
