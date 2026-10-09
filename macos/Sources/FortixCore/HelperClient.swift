import Darwin
import Foundation

/// HelperTransport is an injectable duplex byte stream; close must wake outstanding reads and writes.
public protocol HelperTransport: Sendable {
  /// Read returns a bounded chunk, or empty data at EOF, without interpreting helper JSON.
  func read() async throws -> Data
  /// Write transmits an entire record without interleaving concurrent writes.
  func write(_ data: Data) async throws
  /// Close is idempotent and interrupts pending I/O.
  func close()
}

/// UnixSocketTransport performs nonblocking AF_UNIX I/O off the cooperative actor executor.
public final class UnixSocketTransport: HelperTransport, @unchecked Sendable {
  /// Descriptor remains owned until deinit so shutdown cannot race with descriptor reuse.
  private let descriptor: Int32
  /// Lock protects the closed flag shared by I/O queues and close callers.
  private let lock = NSLock()
  /// Closed is set before shutdown wakes poll and recv.
  private var closed = false
  /// ReadQueue allows one idle reader without blocking writes or actor execution.
  private let readQueue = DispatchQueue(label: "fortix.socket.read")
  /// WriteQueue prevents concurrent records from interleaving on the socket.
  private let writeQueue = DispatchQueue(label: "fortix.socket.write")

  /// Creates a transport around one connected, nonblocking socket owned by this object.
  private init(descriptor: Int32) { self.descriptor = descriptor }

  /// Releases the descriptor only after every queued operation releases its transport reference.
  deinit { Darwin.close(descriptor) }

  /// Connect bounds address length and connection time; it never starts or installs a helper.
  public static func connect(path: String) async throws -> UnixSocketTransport {
    try Task.checkCancellation()
    return try await withCheckedThrowingContinuation { continuation in
      DispatchQueue.global(qos: .userInitiated).async {
        do {
          var address = sockaddr_un()
          address.sun_family = sa_family_t(AF_UNIX)
          address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
          let bytes = Array(path.utf8)
          guard !bytes.contains(0), !bytes.isEmpty, path.hasPrefix("/"),
            bytes.count < MemoryLayout.size(ofValue: address.sun_path)
          else { throw CoreError.invalidMessage }
          withUnsafeMutableBytes(of: &address.sun_path) { target in
            target.initializeMemory(as: UInt8.self, repeating: 0)
            target.copyBytes(from: bytes)
          }
          let fd = socket(AF_UNIX, SOCK_STREAM, 0)
          guard fd >= 0 else { throw CoreError.disconnected }
          var accepted = false
          defer { if !accepted { Darwin.close(fd) } }
          guard fcntl(fd, F_SETFL, O_NONBLOCK) == 0, fcntl(fd, F_SETFD, FD_CLOEXEC) == 0 else {
            throw CoreError.disconnected
          }
          var noSignal: Int32 = 1
          guard
            setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size))
              == 0
          else {
            throw CoreError.disconnected
          }
          let result = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
              Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
          }
          if result != 0 {
            guard errno == EINPROGRESS else { throw CoreError.disconnected }
            var descriptor = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
            let ready = poll(&descriptor, 1, 10_000)
            guard ready > 0 else { throw ready == 0 ? CoreError.timeout : CoreError.disconnected }
            var error: Int32 = 0
            var size = socklen_t(MemoryLayout<Int32>.size)
            guard getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size) == 0, error == 0 else {
              throw CoreError.disconnected
            }
          }
          accepted = true
          continuation.resume(returning: UnixSocketTransport(descriptor: fd))
        } catch { continuation.resume(throwing: error) }
      }
    }
  }

  /// IsClosed reads the shutdown flag without retaining a descriptor that another object can reuse.
  private var isClosed: Bool {
    lock.lock()
    defer { lock.unlock() }
    return closed
  }

  /// Read waits interruptibly for at most 8 KiB of bytes; idle subscriptions stay open until close.
  public func read() async throws -> Data {
    try await withCheckedThrowingContinuation { continuation in
      readQueue.async { [self] in
        do {
          var buffer = [UInt8](repeating: 0, count: 8192)
          while !isClosed {
            var item = pollfd(fd: descriptor, events: Int16(POLLIN), revents: 0)
            let ready = poll(&item, 1, 1000)
            if ready < 0 && errno == EINTR { continue }
            guard ready >= 0 else { throw CoreError.disconnected }
            if ready == 0 { continue }
            let count = recv(descriptor, &buffer, buffer.count, 0)
            if count < 0 && [EAGAIN, EINTR].contains(errno) { continue }
            guard count >= 0 else { throw CoreError.disconnected }
            continuation.resume(returning: Data(buffer.prefix(count)))
            return
          }
          throw CoreError.disconnected
        } catch { continuation.resume(throwing: error) }
      }
    }
  }

  /// Write handles short writes under a ten-second deadline and never signals the process on peer loss.
  public func write(_ data: Data) async throws {
    try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
      writeQueue.async { [self] in
        do {
          let deadline = ProcessInfo.processInfo.systemUptime + 10
          try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
              guard !isClosed else { throw CoreError.disconnected }
              guard ProcessInfo.processInfo.systemUptime < deadline else { throw CoreError.timeout }
              let count = send(
                descriptor, bytes.baseAddress!.advanced(by: offset), bytes.count - offset, 0)
              if count > 0 {
                offset += count
                continue
              }
              if count < 0 && errno == EINTR { continue }
              guard count < 0 && errno == EAGAIN else { throw CoreError.disconnected }
              var item = pollfd(fd: descriptor, events: Int16(POLLOUT), revents: 0)
              let ready = poll(&item, 1, 100)
              if ready < 0 && errno != EINTR { throw CoreError.disconnected }
            }
          }
          continuation.resume()
        } catch { continuation.resume(throwing: error) }
      }
    }
  }

  /// Close interrupts idle reads and queued writes without closing a descriptor still in use.
  public func close() {
    lock.lock()
    if !closed {
      closed = true
      shutdown(descriptor, SHUT_RDWR)
    }
    lock.unlock()
  }
}

/// HelperClient correlates requests and delivers bounded notifications over one helper connection.
public actor HelperClient {
  /// Connector permits fake byte streams while production connects only to a local Unix socket.
  public typealias Connector = @Sendable (String) async throws -> any HelperTransport
  /// SocketPath is fixed by the caller and is never derived from helper event data.
  private let socketPath: String
  /// Connector creates one fresh transport per connection or reconnect.
  private let connector: Connector
  /// Transport is nil while unreachable; no request is automatically replayed after reconnect.
  private var transport: (any HelperTransport)?
  /// Reader owns frame assembly independently of outstanding calls.
  private var reader: Task<Void, Never>?
  /// AssemblyDeadline bounds one partial frame while permitting idle subscriptions.
  private var assemblyDeadline: Task<Void, Never>?
  /// AssemblyToken invalidates an expired timer when its frame has already completed.
  private var assemblyToken: UUID?
  /// Generation prevents an old reader or write from affecting a replacement connection.
  private var generation = UUID()
  /// Pending maps correlation identifiers to exactly-once continuations.
  private var pending: [String: CheckedContinuation<HelperResult, Error>] = [:]
  /// Deadlines bounds calls even when the helper does not reply.
  private var deadlines: [String: Task<Void, Never>] = [:]
  /// Stream is replaced on reconnect so prior consumers can detect transport loss.
  private var stream: AsyncThrowingStream<HelperEvent, Error>?
  /// EventSink terminates on overflow instead of silently dropping challenges or state changes.
  private var eventSink: AsyncThrowingStream<HelperEvent, Error>.Continuation?
  /// Reachable becomes true only after hello, subscribe, and initial status complete.
  public private(set) var reachable = false
  /// StopTargets records the generation of each profile currently being stopped.
  private var stopTargets: [String: UInt64]?
  /// StopError retains any transient cleanup or superseding-start failure during a stop wait.
  private var stopError: CoreError?

  /// Creates an offline client; connecting never invokes an up operation or a privileged command.
  public init(
    socketPath: String = "/var/run/fortix/fortix.sock",
    connector: @escaping Connector = { try await UnixSocketTransport.connect(path: $0) }
  ) {
    self.socketPath = socketPath
    self.connector = connector
  }

  /// Connect performs hello, subscribes before status, and returns the authoritative initial snapshots.
  /// A failed handshake closes the transport and wakes every outstanding caller with a fixed error.
  @discardableResult
  public func connect(version: String = "0.2.0", logs: Bool = false) async throws -> [SessionStatus]
  {
    guard transport == nil else { throw CoreError.disconnected }
    let token = UUID()
    generation = token
    let connection = try await connector(socketPath)
    guard generation == token else {
      connection.close()
      throw CoreError.disconnected
    }
    transport = connection
    stream = AsyncThrowingStream(bufferingPolicy: .bufferingOldest(256)) { eventSink = $0 }
    reader = Task { [weak self] in
      var framer = NDJSONFramer()
      do {
        while !Task.isCancelled {
          let chunk = try await connection.read()
          if chunk.isEmpty {
            try framer.finish()
            throw CoreError.disconnected
          }
          guard chunk.count <= HelperProtocol.maxLine else { throw CoreError.oversizedFrame }
          let records = try framer.append(chunk)
          for record in records {
            await self?.receive(try HelperProtocol.decode(record), generation: token)
          }
          await self?.updateAssembly(
            partial: framer.hasPartialRecord, completed: !records.isEmpty,
            generation: token)
        }
      } catch { await self?.fail(error, generation: token) }
    }
    do {
      let hello = try await call(HelperRequest(op: "hello", version: version))
      guard case .object(let fields) = hello.data,
        fields["protocol"] == .integer(Int64(HelperProtocol.version))
      else {
        throw CoreError.incompatibleProtocol
      }
      _ = try await call(HelperRequest(op: "subscribe", logs: logs))
      let snapshots = try await status()
      guard generation == token, transport != nil else { throw CoreError.disconnected }
      reachable = true
      return snapshots
    } catch {
      fail(error, generation: token)
      throw error
    }
  }

  /// Reconnect discards stale pending operations and resubscribes without issuing or replaying up.
  @discardableResult
  public func reconnect(version: String = "0.2.0", logs: Bool = false) async throws
    -> [SessionStatus]
  {
    close()
    return try await connect(version: version, logs: logs)
  }

  /// Events returns this connection's ordered notification stream; acquire again after reconnect.
  public func events() throws -> AsyncThrowingStream<HelperEvent, Error> {
    guard let stream, transport != nil else { throw CoreError.disconnected }
    return stream
  }

  /// Close interrupts I/O and fails pending requests; it does not disconnect any helper-owned tunnel.
  public func close() {
    fail(CoreError.disconnected, generation: generation)
    generation = UUID()
  }

  /// Call replaces the caller's ID and waits for the correlated result under a finite deadline.
  /// Cancellation removes only this waiter; already-sent mutations are never replayed or undone.
  public func call(_ request: HelperRequest, timeout: TimeInterval = 10) async throws
    -> HelperResult
  {
    try Task.checkCancellation()
    guard let connection = transport else { throw CoreError.disconnected }
    guard pending.count < 128, timeout.isFinite, timeout > 0, timeout <= 120 else {
      throw CoreError.invalidMessage
    }
    var request = request
    let id = UUID().uuidString
    request.id = id
    let data = try HelperProtocol.encode(request)
    let token = generation
    return try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { continuation in
        pending[id] = continuation
        deadlines[id] = Task { [weak self] in
          do { try await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000)) } catch { return }
          await self?.complete(id, error: CoreError.timeout)
        }
        Task { [weak self] in
          guard await self?.isPending(id, generation: token) == true else { return }
          do { try await connection.write(data) } catch {
            await self?.fail(error, generation: token)
          }
        }
      }
    } onCancel: {
      Task { await self.complete(id, error: CancellationError()) }
    }
  }

  /// Status returns complete typed helper snapshots and rejects duplicate profile entries.
  public func status(timeout: TimeInterval = 10) async throws -> [SessionStatus] {
    let result = try await call(HelperRequest(op: "status"), timeout: timeout)
    guard let data = result.data else { throw CoreError.invalidMessage }
    let snapshots: [SessionStatus] = try data.decode([SessionStatus].self)
    guard Set(snapshots.map(\.profile)).count == snapshots.count else {
      throw CoreError.invalidMessage
    }
    return snapshots
  }

  /// Down captures target attempts, issues down, then verifies stopped, unwanted, clean snapshots.
  /// Missing targets, transport loss, cleanup errors, competing starts, and deadline expiry fail closed.
  public func down(profile: String? = nil, all: Bool = false, timeout: TimeInterval = 30)
    async throws
  {
    guard reachable, stopTargets == nil, timeout.isFinite, timeout > 0, timeout <= 30,
      all ? profile == nil : profile.map(VPNProfile.validID) == true
    else { throw CoreError.invalidMessage }
    // Reserve the wait before suspension so a second caller cannot overwrite its generation targets.
    stopTargets = [:]
    stopError = nil
    defer {
      stopTargets = nil
      stopError = nil
    }
    let deadline = ProcessInfo.processInfo.systemUptime + timeout
    let before = try await status(timeout: min(10, timeout))
    let selected = before.filter { all || $0.profile == profile }
    guard all || !selected.isEmpty else { throw CoreError.stopFailed }
    let targets = Dictionary(uniqueKeysWithValues: selected.map { ($0.profile, $0.attempt) })
    stopTargets = targets
    let beforeDown = deadline - ProcessInfo.processInfo.systemUptime
    guard beforeDown > 0 else { throw CoreError.timeout }
    _ = try await call(
      HelperRequest(op: "down", profile: profile, all: all), timeout: min(10, beforeDown))
    while true {
      try Task.checkCancellation()
      if let stopError { throw stopError }
      let remaining = deadline - ProcessInfo.processInfo.systemUptime
      guard remaining > 0 else { throw CoreError.timeout }
      let snapshots = try await status(timeout: min(10, remaining))
      if let stopError { throw stopError }
      var clean = true
      for (id, attempt) in targets {
        guard let snapshot = snapshots.first(where: { $0.profile == id }),
          snapshot.attempt == attempt,
          !snapshot.wanted, !snapshot.cleanupPending, snapshot.state != "failed",
          !snapshot.detail.hasPrefix("network cleanup failed")
        else { throw CoreError.stopFailed }
        clean = clean && snapshot.state == "disconnected"
      }
      if clean { return }
      let sleepTime = min(0.1, max(0, deadline - ProcessInfo.processInfo.systemUptime))
      try await Task.sleep(nanoseconds: UInt64(sleepTime * 1_000_000_000))
    }
  }

  /// UpdateAssembly starts a deadline only for partial frames and invalidates completed-frame timers.
  private func updateAssembly(partial: Bool, completed: Bool, generation token: UUID) {
    guard token == generation, transport != nil else { return }
    if completed || !partial {
      assemblyDeadline?.cancel()
      assemblyDeadline = nil
      assemblyToken = nil
    }
    if partial && assemblyToken == nil {
      let record = UUID()
      assemblyToken = record
      assemblyDeadline = Task { [weak self] in
        do { try await Task.sleep(nanoseconds: 10_000_000_000) } catch { return }
        await self?.expireAssembly(record: record, generation: token)
      }
    }
  }

  /// ExpireAssembly closes only the still-incomplete frame whose timer actually expired.
  private func expireAssembly(record: UUID, generation token: UUID) {
    guard token == generation, assemblyToken == record else { return }
    fail(CoreError.timeout, generation: token)
  }

  /// IsPending prevents a canceled queued request from being newly sent to a replacement transport.
  private func isPending(_ id: String, generation token: UUID) -> Bool {
    token == generation && pending[id] != nil
  }

  /// Complete resumes one pending continuation at most once and releases its deadline task.
  private func complete(_ id: String, error: Error) {
    deadlines.removeValue(forKey: id)?.cancel()
    pending.removeValue(forKey: id)?.resume(throwing: error)
  }

  /// Receive routes replies and records stop failures before publishing ordered events.
  private func receive(_ message: HelperMessage, generation token: UUID) {
    guard token == generation, transport != nil else { return }
    switch message {
    case .result(let result):
      deadlines.removeValue(forKey: result.id)?.cancel()
      guard let continuation = pending.removeValue(forKey: result.id) else { return }
      if result.ok {
        continuation.resume(returning: result)
      } else {
        continuation.resume(
          throwing: result.error ?? HelperFailure(code: "INTERNAL", message: "Operation failed"))
      }
    case .event(let event):
      if let attempt = stopTargets?[event.profile], event.type == "state", event.attempt >= attempt
      {
        if event.attempt > attempt || event.cleanupPending == true
          || (event.detail ?? "").hasPrefix("network cleanup failed")
          || (event.wanted == true && ["stopping", "disconnected"].contains(event.state ?? ""))
        {
          stopError = .stopFailed
        }
      }
      if case .dropped = eventSink?.yield(event) {
        fail(CoreError.eventOverflow, generation: token)
      }
    }
  }

  /// Fail atomically marks stale snapshots unreachable, closes transport, and wakes every waiter.
  private func fail(_ error: Error, generation token: UUID) {
    guard token == generation else { return }
    reachable = false
    if stopTargets != nil { stopError = .stopFailed }
    transport?.close()
    transport = nil
    reader?.cancel()
    reader = nil
    assemblyDeadline?.cancel()
    assemblyDeadline = nil
    assemblyToken = nil
    eventSink?.finish(throwing: error)
    eventSink = nil
    for id in Array(pending.keys) { complete(id, error: error) }
  }
}
