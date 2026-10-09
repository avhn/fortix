import Darwin
import Foundation
import XCTest

@testable import FortixCore

/// UnixSocketTests exercises the production AF_UNIX transport against a bounded unprivileged fake.
final class UnixSocketTests: XCTestCase {
  /// TestLocalSocketHandshake verifies real duplex framing and that closing the client wakes the server.
  func testLocalSocketHandshake() async throws {
    let server = try LocalHelper()
    let worker = Task.detached { try server.serve() }
    let client = HelperClient(socketPath: server.path)
    do {
      let snapshots = try await client.connect()
      XCTAssertTrue(snapshots.isEmpty)
      _ = try await client.call(HelperRequest(op: "profile.list"))
      await client.close()
      let operations = try await worker.value
      XCTAssertEqual(operations, ["hello", "subscribe", "status", "profile.list"])
    } catch {
      await client.close()
      _ = try? await worker.value
      throw error
    }
  }

  /// TestSocketAddressValidation rejects paths that cannot safely fit sockaddr_un before dialing.
  func testSocketAddressValidation() async throws {
    for path in ["relative", "/tmp/zero\0byte", "/" + String(repeating: "x", count: 200)] {
      do {
        _ = try await UnixSocketTransport.connect(path: path)
        XCTFail("Expected invalid socket path")
      } catch { XCTAssertEqual(error as? CoreError, .invalidMessage) }
    }
  }
}

/// LocalHelper is a temporary Unix-domain listener; it never opens a VPN or requests privileges.
private final class LocalHelper: @unchecked Sendable {
  /// Path is unique and short enough for the macOS Unix-domain address limit.
  let path = "/tmp/fortix-" + UUID().uuidString + ".sock"
  /// Listener owns only this test's Unix socket.
  private let listener: Int32

  /// Creates a bounded fake helper listener and removes its path if binding fails.
  init() throws {
    listener = socket(AF_UNIX, SOCK_STREAM, 0)
    guard listener >= 0 else { throw CoreError.disconnected }
    var address = sockaddr_un()
    address.sun_family = sa_family_t(AF_UNIX)
    address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
    withUnsafeMutableBytes(of: &address.sun_path) { target in
      target.initializeMemory(as: UInt8.self, repeating: 0)
      target.copyBytes(from: Array(path.utf8))
    }
    let bound = withUnsafePointer(to: &address) { pointer in
      pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
        bind(listener, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
      }
    }
    guard bound == 0, listen(listener, 1) == 0 else {
      Darwin.close(listener)
      unlink(path)
      throw CoreError.disconnected
    }
  }

  /// Releases only the temporary socket and pathname created by this fixture.
  deinit {
    Darwin.close(listener)
    unlink(path)
  }

  /// Serve replies to typed requests until EOF, using two-second polls to bound every read.
  func serve() throws -> [String] {
    var item = pollfd(fd: listener, events: Int16(POLLIN), revents: 0)
    guard poll(&item, 1, 2000) > 0 else { throw CoreError.timeout }
    let connection = accept(listener, nil, nil)
    guard connection >= 0 else { throw CoreError.disconnected }
    defer { Darwin.close(connection) }
    var noSignal: Int32 = 1
    guard
      setsockopt(
        connection, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size)) == 0
    else {
      throw CoreError.disconnected
    }
    var operations: [String] = []
    var framer = NDJSONFramer()
    while true {
      item = pollfd(fd: connection, events: Int16(POLLIN), revents: 0)
      guard poll(&item, 1, 2000) > 0 else { throw CoreError.timeout }
      var bytes = [UInt8](repeating: 0, count: 4096)
      let count = recv(connection, &bytes, bytes.count, 0)
      if count == 0 {
        try framer.finish()
        return operations
      }
      guard count > 0 else { throw CoreError.disconnected }
      for frame in try framer.append(Data(bytes.prefix(count))) {
        let request = try JSONDecoder().decode(HelperRequest.self, from: frame)
        operations.append(request.op)
        var fields: [String: JSONValue] = [
          "type": .string("result"), "id": .string(request.id), "ok": .bool(true),
        ]
        if request.op == "hello" {
          fields["data"] = .object(["helper_version": .string("0.2.0"), "protocol": .integer(1)])
        } else if ["status", "profile.list"].contains(request.op) {
          fields["data"] = .array([])
        }
        var data = try JSONEncoder().encode(JSONValue.object(fields))
        data.append(10)
        try data.withUnsafeBytes { encoded in
          guard send(connection, encoded.baseAddress, encoded.count, 0) == encoded.count else {
            throw CoreError.disconnected
          }
        }
      }
    }
  }
}
