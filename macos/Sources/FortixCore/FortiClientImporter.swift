import Darwin
import Foundation

/// CommandOutput contains bounded child output, never automatically rendered as diagnostics.
public struct CommandOutput: Sendable {
  /// Stdout is the expected machine-readable result.
  public let stdout: Data
  /// Stderr contains optional public warnings; callers must explicitly decide what to display.
  public let stderr: Data

  /// Creates captured output for a runner or a test fake.
  public init(stdout: Data = Data(), stderr: Data = Data()) {
    self.stdout = stdout
    self.stderr = stderr
  }
}

/// CommandRunner is an injectable executable boundary used by previews and explicit installation.
public protocol CommandRunner: Sendable {
  /// Run invokes an absolute executable directly with bounded time and total captured bytes.
  /// Implementations must sanitize child failures and never log output or command arguments.
  func run(executable: URL, arguments: [String], timeout: TimeInterval, maxOutput: Int) async throws
    -> CommandOutput
}

/// SystemCommandRunner captures nonblocking pipes outside the cooperative executor with finite bounds.
public struct SystemCommandRunner: CommandRunner {
  /// Creates a runner without starting any process.
  public init() {}

  /// Run closes stdin, drains both pipes, and interrupts its owned command group on timeout or excess output.
  public func run(executable: URL, arguments: [String], timeout: TimeInterval, maxOutput: Int)
    async throws -> CommandOutput
  {
    guard executable.isFileURL, executable.path.hasPrefix("/"), timeout.isFinite,
      timeout > 0, timeout <= 120, maxOutput > 0, maxOutput <= 4 * 1024 * 1024,
      !arguments.contains(where: { $0.utf8.contains(0) })
    else { throw CoreError.commandFailed }
    try Task.checkCancellation()
    let cancellation = CommandCancellation()
    return try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { continuation in
        DispatchQueue.global(qos: .userInitiated).async {
          do {
            let process = Process()
            let exited = DispatchSemaphore(value: 0)
            process.terminationHandler = { _ in exited.signal() }
            process.executableURL = executable
            process.arguments = arguments
            process.standardInput = FileHandle.nullDevice
            let output = Pipe()
            let errors = Pipe()
            process.standardOutput = output
            process.standardError = errors
            let pipes = [output, errors]
            let readFDs = pipes.map { $0.fileHandleForReading.fileDescriptor }
            defer {
              for pipe in pipes {
                try? pipe.fileHandleForReading.close()
                try? pipe.fileHandleForWriting.close()
              }
            }
            for fd in readFDs {
              guard fcntl(fd, F_SETFL, O_NONBLOCK) == 0 else { throw CoreError.commandFailed }
            }
            guard !cancellation.isCancelled else { throw CancellationError() }
            do { try process.run() } catch { throw CoreError.commandFailed }
            let child = process.processIdentifier
            // Retain the isolated group before its leader is reaped. A group can still exist
            // after a fast-exiting leader disappears if descendants retain the capture pipes.
            let ownedGroup: pid_t? =
              child > 0 && child != getpgrp()
                && (getpgid(child) == child || Darwin.kill(-child, 0) == 0) ? child : nil
            // Closing parent writers ensures EOF when the child closes its own descriptors.
            for pipe in pipes { try? pipe.fileHandleForWriting.close() }
            let deadline = ProcessInfo.processInfo.systemUptime + timeout
            var captured = [Data(), Data()]
            var open: Set<Int> = [0, 1]
            var failure: CoreError?
            while process.isRunning || !open.isEmpty {
              if cancellation.isCancelled {
                failure = .commandFailed
                break
              }
              if ProcessInfo.processInfo.systemUptime >= deadline {
                failure = .timeout
                break
              }
              var items = readFDs.enumerated().map {
                pollfd(
                  fd: open.contains($0.offset) ? $0.element : -1, events: Int16(POLLIN), revents: 0)
              }
              let ready = poll(&items, nfds_t(items.count), 20)
              if ready < 0 && errno == EINTR { continue }
              if ready < 0 {
                failure = .commandFailed
                break
              }
              var buffer = [UInt8](repeating: 0, count: 8192)
              for index in Array(open) where items[index].revents != 0 {
                let count = Darwin.read(readFDs[index], &buffer, buffer.count)
                if count == 0 {
                  open.remove(index)
                  continue
                }
                if count < 0 && [EAGAIN, EINTR].contains(errno) { continue }
                if count < 0 {
                  failure = .commandFailed
                  break
                }
                guard captured[0].count + captured[1].count + count <= maxOutput else {
                  failure = .commandFailed
                  break
                }
                captured[index].append(contentsOf: buffer.prefix(count))
              }
              if failure != nil { break }
            }
            if let failure {
              if let ownedGroup {
                // Inherited pipes can outlive the leader, so group cleanup must not depend on isRunning.
                Darwin.kill(-ownedGroup, SIGKILL)
              } else if process.isRunning {
                Darwin.kill(child, SIGKILL)
              }
              // Reaping is bounded even if the operating system delays child termination.
              _ = exited.wait(timeout: .now() + 1)
              if cancellation.isCancelled { throw CancellationError() }
              throw failure
            }
            guard exited.wait(timeout: .now() + 1) == .success else { throw CoreError.timeout }
            guard process.terminationStatus == 0 else { throw CoreError.commandFailed }
            continuation.resume(returning: CommandOutput(stdout: captured[0], stderr: captured[1]))
          } catch { continuation.resume(throwing: error) }
        }
      }
    } onCancel: {
      cancellation.cancel()
    }
  }
}

/// CommandCancellation bridges caller cancellation to the bounded synchronous pipe-draining loop.
private final class CommandCancellation: @unchecked Sendable {
  /// Lock serializes the flag shared by the caller and the worker task.
  private let lock = NSLock()
  /// Cancelled is retained until the worker has killed and reaped its child.
  private var cancelled = false
  /// IsCancelled reads cancellation without invoking process APIs from another thread.
  var isCancelled: Bool {
    lock.lock()
    defer { lock.unlock() }
    return cancelled
  }
  /// Cancel requests interruption at the next pipe poll, which is at most twenty milliseconds away.
  func cancel() {
    lock.lock()
    defer { lock.unlock() }
    cancelled = true
  }
}

/// FortiClientImporter runs the bundled CLI's read-only preview at the current user's privilege.
public struct FortiClientImporter: Sendable {
  /// Executable is the bundled fortix CLI, never a shell or a PATH lookup.
  private let executable: URL
  /// Runner permits tests to verify arguments without touching installed VPN configuration.
  private let runner: any CommandRunner

  /// Creates an importer with a fixed CLI path and an optional fake process runner.
  public init(executable: URL, runner: any CommandRunner = SystemCommandRunner()) {
    self.executable = executable
    self.runner = runner
  }

  /// Preview returns secret-free drafts and never includes --apply or any privileged invocation.
  /// A successful top-level null is an empty draft list; nested nulls remain invalid.
  /// Unknown configuration fields, oversized output, and subprocess failures are rejected.
  public func preview(plist: URL? = nil) async throws -> [VPNProfile] {
    var arguments = ["import", "forticlient"]
    if let plist {
      guard plist.isFileURL, !plist.path.utf8.contains(0) else { throw CoreError.commandFailed }
      arguments += ["--plist", plist.path]
    }
    let output = try await runner.run(
      executable: executable, arguments: arguments, timeout: 15,
      maxOutput: 4 * 1024 * 1024)
    guard output.stdout.count + output.stderr.count <= 4 * 1024 * 1024 else {
      throw CoreError.commandFailed
    }
    // The CLI encodes its nil draft slice as null when every candidate is absent or skipped.
    let result = output.stdout.drop(while: { [9, 10, 13, 32].contains($0) })
      .reversed().drop(while: { [9, 10, 13, 32].contains($0) }).reversed()
    if result.elementsEqual("null".utf8) { return [] }
    guard case .array(let values) = try StrictJSON.decode(output.stdout), values.count <= 4096
    else {
      throw CoreError.invalidProfile
    }
    let drafts = try values.map(VPNProfile.decode)
    guard Set(drafts.map(\.id)).count == drafts.count else { throw CoreError.invalidProfile }
    return drafts
  }
}
