import Foundation

@testable import FortixCore

/// Fixtures reads synthetic interoperability vectors shared with the Go client tests.
enum Fixtures {
  /// Data returns one fixture without duplicating protocol or credential vectors in Swift.
  static func data(_ name: String) throws -> Data {
    var root = URL(fileURLWithPath: #filePath)
    for _ in 0..<4 { root.deleteLastPathComponent() }
    return try Data(contentsOf: root.appendingPathComponent("testdata/interop/" + name))
  }

  /// Lines preserves the required newline for every synthetic NDJSON record.
  static func lines(_ name: String) throws -> [Data] {
    try data(name).split(separator: 10).map { Data($0) + Data([10]) }
  }
}

/// FakeTransport is an in-memory duplex stream with automatic handshake replies and controllable data.
actor FakeTransport: HelperTransport {
  /// Requests retains only synthetic test traffic for correlation and ordering assertions.
  private(set) var requests: [HelperRequest] = []
  /// Queue stores pending chunks until the reader asks for them.
  private var queue: [Data] = []
  /// Waiter is the single active client read continuation.
  private var waiter: CheckedContinuation<Data, Error>?
  /// Closed prevents new writes and wakes idle readers.
  private var closed = false
  /// StatusData controls the authoritative snapshot payload.
  var statusData: JSONValue = .array([])
  /// HeldOperations identifies operations whose result the test will supply explicitly.
  var heldOperations = Set<String>()
  /// ProtocolVersion allows handshake mismatch tests.
  var protocolVersion = 1
  /// DownSnapshots supplies a queued sequence of snapshots after a down request.
  var downSnapshots: [JSONValue] = []
  /// DownIssued switches snapshot sequencing on after the helper acknowledges down.
  private var downIssued = false

  /// SetStatus configures the snapshot before connection or a stop wait.
  func setStatus(_ data: JSONValue) { statusData = data }
  /// Hold prevents automatic replies for selected operations.
  func hold(_ operations: Set<String>) { heldOperations = operations }
  /// SetProtocol changes the synthetic negotiated protocol version.
  func setProtocol(_ version: Int) { protocolVersion = version }
  /// SetDownSnapshots queues snapshots used only after down is acknowledged.
  func setDownSnapshots(_ snapshots: [JSONValue]) { downSnapshots = snapshots }

  /// Read consumes a chunk or suspends until push or close without polling.
  func read() async throws -> Data {
    if !queue.isEmpty { return queue.removeFirst() }
    if closed { throw CoreError.disconnected }
    return try await withCheckedThrowingContinuation { waiter = $0 }
  }

  /// Write records a request and replies automatically unless the operation is held.
  func write(_ data: Data) async throws {
    guard !closed else { throw CoreError.disconnected }
    let request = try JSONDecoder().decode(HelperRequest.self, from: data)
    requests.append(request)
    if heldOperations.contains(request.op) { return }
    var payload: JSONValue?
    switch request.op {
    case "hello":
      payload = .object([
        "protocol": .integer(Int64(protocolVersion)), "helper_version": .string("0.2.0"),
      ])
    case "status":
      if downIssued, !downSnapshots.isEmpty { statusData = downSnapshots.removeFirst() }
      payload = statusData
    case "down": downIssued = true
    default: break
    }
    try reply(id: request.id, data: payload)
  }

  /// Reply emits a successful correlated response with optional operation-specific payload.
  func reply(id: String, data: JSONValue? = nil) throws {
    var object: [String: JSONValue] = [
      "type": .string("result"), "id": .string(id), "ok": .bool(true),
    ]
    if let data { object["data"] = data }
    var encoded = try JSONEncoder().encode(JSONValue.object(object))
    encoded.append(10)
    push(encoded)
  }

  /// Push emits exactly the bytes requested by a test, including partial or malformed frames.
  func push(_ data: Data) {
    if let waiter {
      self.waiter = nil
      waiter.resume(returning: data)
    } else {
      queue.append(data)
    }
  }

  /// Close schedules actor-isolated shutdown and never accesses a real socket.
  nonisolated func close() { Task { await finish() } }

  /// Finish marks this stream closed and wakes its pending reader.
  func finish() {
    closed = true
    waiter?.resume(throwing: CoreError.disconnected)
    waiter = nil
  }
}

/// FakeCommandRunner records executable invocations without starting children or requesting privileges.
actor FakeCommandRunner: CommandRunner {
  /// Invocation retains the exact synthetic executable and argv selected by the core service.
  struct Invocation: Sendable {
    /// Executable is an absolute file URL.
    let executable: URL
    /// Arguments are passed separately, never parsed through a shell by the runner.
    let arguments: [String]
    /// Timeout is the requested finite process deadline.
    let timeout: TimeInterval
    /// MaxOutput is the total capture limit.
    let maxOutput: Int
  }
  /// Output is the synthetic command result supplied by the test.
  let output: CommandOutput
  /// Invocations records each call in arrival order.
  private(set) var invocations: [Invocation] = []

  /// Creates a fake that always returns the given bounded output.
  init(output: CommandOutput = CommandOutput()) { self.output = output }

  /// Run records parameters and returns the configured synthetic result without I/O.
  func run(executable: URL, arguments: [String], timeout: TimeInterval, maxOutput: Int) async throws
    -> CommandOutput
  {
    invocations.append(
      Invocation(
        executable: executable, arguments: arguments, timeout: timeout, maxOutput: maxOutput))
    return output
  }
}
