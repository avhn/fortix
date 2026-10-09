import FortixCore
import Foundation

/// AppInstallation performs explicit installation actions using only the bundled helper and core runner.
struct AppInstallation: Sendable {
  /// BundleURL locates the running application, not a user-selected helper executable.
  let bundleURL: URL
  /// Runner permits tests to inspect commands without requesting privileges or changing networking.
  let runner: any CommandRunner

  /// Creates installation services without running processes or prompting for administrator approval.
  init(bundleURL: URL = Bundle.main.bundleURL, runner: any CommandRunner = SystemCommandRunner()) {
    self.bundleURL = bundleURL
    self.runner = runner
  }

  /// IsInApplications refuses disk images, build output, and symlinks that resolve outside Applications.
  var isInApplications: Bool {
    let path = bundleURL.resolvingSymlinksInPath().standardizedFileURL.path
    return path.hasPrefix("/Applications/") && bundleURL.pathExtension == "app"
  }

  /// Executable returns only a known bundled binary, failing before privilege escalation if misplaced.
  func executable(_ name: String) throws -> URL {
    guard isInApplications, ["fortix", "fortix-helper"].contains(name) else {
      throw CoreError.commandFailed
    }
    return bundleURL.appendingPathComponent("Contents/Resources/libexec/\(name)")
  }

  /// Install invokes the core installer's single administrator prompt with an explicit desktop user.
  func install(user: String = NSUserName()) async throws {
    try await HelperInstaller(executable: executable("fortix-helper"), runner: runner).install(
      user: user)
  }

  /// Preview performs a read-only FortiClient import through the fixed bundled CLI.
  func preview(plist: URL? = nil) async throws -> [VPNProfile] {
    try await FortiClientImporter(executable: executable("fortix"), runner: runner).preview(
      plist: plist)
  }

  /// AddMFASupport vendors an explicitly chosen openfortivpn installation without restarting the helper.
  func addMFASupport(binary: URL) async throws {
    guard binary.isFileURL, binary.path.hasPrefix("/"), binary.lastPathComponent == "openfortivpn",
      !binary.path.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) })
    else { throw CoreError.commandFailed }
    try await privileged(arguments: [
      "install", "--add-openfortivpn", "--openfortivpn", binary.path,
    ])
  }

  /// Uninstall removes services and binaries but deliberately preserves profiles and Keychain passwords.
  /// The caller must first verify clean tunnel shutdown; this service never silently requests purge.
  func uninstall() async throws { try await privileged(arguments: ["uninstall"]) }

  /// Privileged executes a fixed helper operation after independently quoting every shell argument.
  private func privileged(arguments: [String]) async throws {
    let command = ([try executable("fortix-helper").path] + arguments)
      .map(Self.shellQuote).joined(separator: " ")
    let literal = command.replacingOccurrences(of: "\\", with: "\\\\")
      .replacingOccurrences(of: "\"", with: "\\\"")
    _ = try await runner.run(
      executable: URL(fileURLWithPath: "/usr/bin/osascript"),
      arguments: ["-e", "do shell script \"\(literal)\" with administrator privileges"],
      timeout: 120, maxOutput: 4096)
  }

  /// ShellQuote prevents spaces, quotes, and shell metacharacters from changing argument boundaries.
  private static func shellQuote(_ value: String) -> String {
    "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
  }
}
