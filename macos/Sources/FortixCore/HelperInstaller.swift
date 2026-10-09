import Foundation

/// HelperInstaller requests one administrator prompt for a fixed bundled-helper installation command.
public struct HelperInstaller: Sendable {
  /// Executable is the bundled helper, never a discovered PATH executable.
  private let executable: URL
  /// Runner is injectable so tests never request administrator privileges or modify networking.
  private let runner: any CommandRunner

  /// Creates an installer without requesting privileges or starting an executable.
  public init(executable: URL, runner: any CommandRunner = SystemCommandRunner()) {
    self.executable = executable
    self.runner = runner
  }

  /// Script quotes each shell argument, then quotes the complete command as an AppleScript literal.
  /// User is explicit because the administrator process does not inherit a reliable desktop-user identity.
  public func script(user: String) throws -> String {
    guard executable.isFileURL, executable.path.hasPrefix("/"),
      executable.lastPathComponent == "fortix-helper", !user.isEmpty, user != "root",
      !user.hasPrefix("-"), user.utf8.count <= 256,
      !user.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }),
      !executable.path.unicodeScalars.contains(where: {
        CharacterSet.controlCharacters.contains($0)
      })
    else {
      throw CoreError.commandFailed
    }
    let command = [executable.path, "install", "--app-bundle", "--user", user].map(Self.shellQuote)
      .joined(separator: " ")
    let literal = command.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(
      of: "\"", with: "\\\"")
    return "do shell script \"\(literal)\" with administrator privileges"
  }

  /// Install runs only the fixed AppleScript command and returns no raw privileged child output.
  public func install(user: String = NSUserName()) async throws {
    let source = try script(user: user)
    _ = try await runner.run(
      executable: URL(fileURLWithPath: "/usr/bin/osascript"), arguments: ["-e", source],
      timeout: 120, maxOutput: 4096)
  }

  /// ShellQuote encloses an individual argument and safely represents embedded single quotes.
  private static func shellQuote(_ value: String) -> String {
    "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
  }
}
