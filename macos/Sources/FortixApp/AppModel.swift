import FortixCore
import Foundation
import SwiftUI

/// ProfilePresentation retains only public state for one helper-owned profile.
struct ProfilePresentation: Equatable {
  /// Attempt prevents late events from modifying a newer connection.
  var attempt: UInt64 = 0
  /// State is a textual connection phase, not a color-only indicator.
  var state = "disconnected"
  /// Detail explains the last transition without credentials.
  var detail = ""
  /// Wanted records the helper's desired connectivity.
  var wanted = false
  /// CleanupPending prevents dirty teardown from appearing successful.
  var cleanupPending = false
}

/// PendingPrompt binds a sheet to the precise helper event that requested human input.
struct PendingPrompt: Identifiable {
  /// Event retains the profile, attempt, challenge, and rejected certificate identity.
  let event: HelperEvent
  /// ID separates successive challenges even when they belong to the same profile.
  var id: String { "\(event.profile):\(event.attempt):\(event.challengeID ?? event.digest ?? "")" }
  /// IsCertificate selects explicit certificate verification rather than credential entry.
  var isCertificate: Bool { event.type == "cert" }
}

/// SavedPassword retains an opt-in password only until its matching attempt succeeds or terminates.
private struct SavedPassword {
  /// Attempt binds the candidate to the connection that used it.
  let attempt: UInt64
  /// Key retains the exact identity loaded before answering the challenge.
  let key: CredentialKey
  /// Secret never enters published state, logs, or configuration.
  let secret: String
}

/// AppModel coordinates user-privilege services while the helper owns every tunnel and configuration.
@MainActor
final class AppModel: ObservableObject {
  /// Profiles are authoritative configurations loaded from the helper.
  @Published private(set) var profiles: [VPNProfile] = []
  /// States contain public snapshots and ordered state transitions.
  @Published private(set) var states: [String: ProfilePresentation] = [:]
  /// Reachable invalidates stale connection information when the socket closes.
  @Published private(set) var reachable = false
  /// Busy serializes explicit UI mutations, including clean disconnect waits.
  @Published private(set) var busy = false
  /// Message is a fixed or helper-redacted operation failure suitable for display.
  @Published var message: String?
  /// Prompts are queued rather than replacing a challenge from another profile.
  @Published private(set) var prompts: [PendingPrompt] = []
  /// Logs retain at most five hundred already-redacted helper records.
  @Published private(set) var logs: [String] = []
  /// ImportDrafts are read-only preview results until individually approved.
  @Published var importDrafts: [VPNProfile] = []
  /// Client provides correlated requests, subscriptions, and bounded shutdown waits.
  private let client: HelperClient
  /// Store keeps profile writes behind the helper's validation boundary.
  private let store: ProfileStore
  /// Keychain stores only explicitly approved passwords after authentication succeeds.
  private let keychain: KeychainStore
  /// ConnectionTask is the sole reconnect loop and event consumer.
  private var connectionTask: Task<Void, Never>?
  /// Candidates are cleared on failure, generation changes, and transport loss.
  private var candidates: [String: SavedPassword] = [:]
  /// LookingUp distinguishes automatic secure-store access from a human password prompt.
  @Published private var lookingUp: Set<String> = []

  /// SaveError reports app-side safeguards before any helper-owned configuration is changed.
  enum SaveError: Error, Equatable {
    /// DuplicateID requires an explicit existing-profile edit instead of replacing a new draft's namesake.
    case duplicateID
  }

  /// Creates an offline model with injectable services; construction never prompts or connects.
  init(client: HelperClient = HelperClient(), keychain: KeychainStore = KeychainStore()) {
    self.client = client
    self.store = ProfileStore(client: client)
    self.keychain = keychain
  }

  /// CurrentPrompt excludes automatic Keychain lookups so a user cannot answer the same challenge concurrently.
  var currentPrompt: PendingPrompt? {
    prompts.first { !lookingUp.contains($0.event.profile) }
  }

  /// Aggregate applies the same wanted-profile precedence as the CLI tray model.
  var aggregate: AggregateStatus {
    AggregateStatus.build(
      profiles: states.map { id, value in
        AggregateProfile(
          id: id, state: value.state, wanted: value.wanted,
          pendingPassword: prompts.contains {
            $0.event.profile == id && $0.event.kind == "password"
          }
            && !lookingUp.contains(id), cleanupPending: value.cleanupPending)
      }, reachable: reachable)
  }

  /// StatusText supplies an accessible label independent of icon geometry and tint.
  var statusText: String {
    guard reachable else { return "Helper unavailable" }
    switch aggregate {
    case .notConnected: return "Not connected"
    case .connecting: return "Connecting"
    case .connected: return "Connected"
    case .partial: return "Partially connected"
    case .attention: return "Needs attention"
    }
  }

  /// Start reconnects without replaying up or secret-bearing operations and refreshes authoritative state.
  func start() {
    guard connectionTask == nil else { return }
    connectionTask = Task { [weak self] in
      guard let self else { return }
      while !Task.isCancelled {
        do {
          try await connectHelper()
          let events = try await client.events()
          for try await event in events { await receive(event) }
        } catch {
          invalidate()
        }
        do { try await Task.sleep(nanoseconds: 3_000_000_000) } catch { break }
      }
    }
  }

  /// InstallHelper restarts UI connectivity only after the supplied installer succeeds.
  /// The idempotent start also restores a reconnect loop previously stopped by uninstall in this session.
  func installHelper(_ installation: AppInstallation) async throws {
    try await installation.install()
    start()
  }

  /// ConnectHelper refreshes one local connection without requesting any tunnel start or credential replay.
  func connectHelper() async throws {
    do {
      let snapshots = try await client.reconnect(logs: true)
      apply(snapshots)
      try await refreshProfiles()
      reachable = true
    } catch {
      await client.close()
      invalidate()
      throw error
    }
  }

  /// Stop closes only the UI connection; helper-owned tunnels deliberately remain running.
  func stop() async {
    connectionTask?.cancel()
    connectionTask = nil
    await client.close()
    invalidate()
  }

  /// Invalidate removes prompts and retained passwords instead of trusting stale snapshots.
  private func invalidate() {
    reachable = false
    prompts.removeAll()
    candidates.removeAll()
    lookingUp.removeAll()
  }

  /// Apply replaces public snapshots after a handshake or explicit status refresh.
  private func apply(_ snapshots: [SessionStatus]) {
    states = Dictionary(
      uniqueKeysWithValues: snapshots.map {
        (
          $0.profile,
          ProfilePresentation(
            attempt: $0.attempt, state: $0.state, detail: $0.detail,
            wanted: $0.wanted, cleanupPending: $0.cleanupPending)
        )
      })
  }

  /// RefreshProfiles reloads identities sequentially and never writes a local configuration mirror.
  private func refreshProfiles() async throws { profiles = try await store.all() }

  /// Receive ignores old generations and clears terminal challenges before saving approved credentials.
  func receive(_ event: HelperEvent) async {
    guard event.attempt >= (states[event.profile]?.attempt ?? 0) else { return }
    if event.type == "log", let line = event.line {
      logs.append("\(event.profile): \(line)")
      if logs.count > 500 { logs.removeFirst(logs.count - 500) }
      return
    }
    if event.type == "state" {
      states[event.profile] = ProfilePresentation(
        attempt: event.attempt, state: event.state ?? "unknown", detail: event.detail ?? "",
        wanted: event.wanted ?? false, cleanupPending: event.cleanupPending ?? false)
      prompts.removeAll {
        $0.event.profile == event.profile
          && ($0.event.attempt != event.attempt
            || !Self.matchesPrompt($0, state: event.state ?? ""))
      }
      if let candidate = candidates[event.profile] {
        if candidate.attempt == event.attempt && event.state == "connected" {
          candidates.removeValue(forKey: event.profile)
          do { try await keychain.set(candidate.secret, for: candidate.key) } catch {
            message = "Connected, but the password could not be saved in Keychain."
          }
        } else if candidate.attempt != event.attempt
          || ["failed", "disconnected", "stopping", "backoff"].contains(event.state ?? "")
        {
          candidates.removeValue(forKey: event.profile)
        }
      }
      return
    }
    guard event.type == "challenge" || event.type == "cert" else { return }
    let prompt = PendingPrompt(event: event)
    guard !prompts.contains(where: { $0.id == prompt.id }) else { return }
    prompts.removeAll { $0.event.profile == event.profile }
    prompts.append(prompt)
    if event.type == "challenge", event.kind == "password" {
      lookingUp.insert(event.profile)
      defer { lookingUp.remove(event.profile) }
      do {
        let profile = try await store.get(event.profile)
        let password = try await keychain.get(CredentialKey(profile: profile))
        guard isCurrent(prompt) else { return }
        try await answer(prompt, secret: password, remember: false)
      } catch {
        // A missing or locked item leaves the challenge visible for explicit human entry.
      }
    }
  }

  /// IsCurrent verifies the sheet is still queued for the active connection and generation.
  func isCurrent(_ prompt: PendingPrompt) -> Bool {
    reachable && prompts.contains { $0.id == prompt.id }
      && states[prompt.event.profile]?.attempt == prompt.event.attempt
      && Self.matchesPrompt(prompt, state: states[prompt.event.profile]?.state ?? "")
  }

  /// MatchesPrompt rejects a password sheet after the helper has advanced to a code or trust phase.
  private static func matchesPrompt(_ prompt: PendingPrompt, state: String) -> Bool {
    if prompt.isCertificate { return state == "waiting_trust" }
    return prompt.event.kind == "password" ? state == "waiting_password" : state == "waiting_code"
  }

  /// Perform serializes explicit operations and renders failures without child output or secrets.
  func perform(_ operation: @escaping @MainActor () async throws -> Void) {
    guard !busy else { return }
    busy = true
    message = nil
    Task {
      defer { busy = false }
      do { try await operation() } catch { message = Self.failureText(error) }
    }
  }

  /// FailureText permits stable helper codes but never reflects arbitrary error descriptions.
  static func failureText(_ error: Error) -> String {
    if error as? SaveError == .duplicateID {
      return "This profile ID already exists. Edit the existing profile instead."
    }
    if let failure = error as? HelperFailure { return "\(failure.code): \(failure.message)" }
    if error as? CoreError == .stopFailed {
      return "Disconnect did not finish cleanly. Check the profile status before quitting."
    }
    if error as? CoreError == .timeout {
      return "The operation timed out. Check the helper and try again."
    }
    return
      "The operation could not be completed. Check the helper and configuration, then try again."
  }

  /// Connect requests one profile without changing the stored backend or replaying after failure.
  func connect(_ id: String) async throws {
    _ = try await client.call(HelperRequest(op: "up", profile: id))
  }

  /// ConnectAll starts each configured profile sequentially through the normal helper boundary.
  func connectAll() async throws {
    for profile in profiles { try await connect(profile.id) }
  }

  /// Disconnect waits for stopped, unwanted, clean authoritative snapshots before reporting success.
  func disconnect(_ id: String? = nil) async throws {
    try await client.down(profile: id, all: id == nil)
    apply(try await client.status())
  }

  /// Save validates a secret-free profile and writes it through the helper, then reloads configurations.
  /// Existing is true only for an existing-profile editor; new drafts reject stored IDs before upsert.
  /// A fresh helper list catches configurations created since the UI last refreshed and may fail offline.
  func save(_ profile: VPNProfile, existing: Bool) async throws {
    try profile.validate()
    if !existing {
      guard !(try await store.list()).contains(where: { $0.profile == profile.id }) else {
        throw SaveError.duplicateID
      }
    }
    try await store.put(profile)
    try await refreshProfiles()
  }

  /// Delete removes an idle configuration after the helper checks active-profile restrictions.
  func delete(_ id: String) async throws {
    try await store.delete(id)
    try await refreshProfiles()
    states.removeValue(forKey: id)
  }

  /// Forget removes only the exact currently stored profile's password and accepts an absent item.
  func forget(_ id: String) async throws {
    let profile = try await store.get(id)
    do { try await keychain.delete(CredentialKey(profile: profile)) } catch KeychainError.notFound {
    }
    candidates.removeValue(forKey: id)
  }

  /// Answer reloads credential identity and rechecks the bound challenge after every suspension.
  /// An opted-in password is persisted only on the matching connected event, never on answer success.
  func answer(_ prompt: PendingPrompt, secret: String, remember: Bool) async throws {
    guard isCurrent(prompt), !prompt.isCertificate, let challenge = prompt.event.challengeID,
      ["password", "code"].contains(prompt.event.kind ?? ""),
      !secret.isEmpty
    else { throw CoreError.invalidMessage }
    let profile = try await store.get(prompt.event.profile)
    guard isCurrent(prompt) else { throw CoreError.invalidMessage }
    if remember && prompt.event.kind == "password" {
      candidates[profile.id] = SavedPassword(
        attempt: prompt.event.attempt, key: try CredentialKey(profile: profile), secret: secret)
    }
    do {
      _ = try await client.call(HelperRequest(op: "answer", challengeID: challenge, secret: secret))
      prompts.removeAll { $0.id == prompt.id }
    } catch {
      candidates.removeValue(forKey: profile.id)
      throw error
    }
  }

  /// Trust rechecks the active rejection and sends only its captured digest, never an editable pin.
  func trust(_ prompt: PendingPrompt) async throws {
    guard isCurrent(prompt), prompt.isCertificate, let digest = prompt.event.digest else {
      throw CoreError.invalidMessage
    }
    let snapshots = try await client.status()
    guard isCurrent(prompt),
      snapshots.contains(where: {
        $0.profile == prompt.event.profile && $0.attempt == prompt.event.attempt
          && $0.state == "waiting_trust"
      })
    else { throw CoreError.invalidMessage }
    _ = try await client.call(
      HelperRequest(op: "trust", profile: prompt.event.profile, digest: digest))
    prompts.removeAll { $0.id == prompt.id }
  }

  /// Cancel stops the bound attempt; closing a sheet cannot silently leave a credential request running.
  func cancel(_ prompt: PendingPrompt) async throws {
    guard isCurrent(prompt) else { return }
    if let challenge = prompt.event.challengeID {
      _ = try await client.call(HelperRequest(op: "cancel", challengeID: challenge))
    }
    try await disconnect(prompt.event.profile)
    prompts.removeAll { $0.id == prompt.id }
  }

  /// LoadLogs requests a bounded redacted tail rather than reading privileged files directly.
  func loadLogs(_ id: String) async throws {
    let result = try await client.call(HelperRequest(op: "logs", profile: id, lines: 500))
    guard let data = result.data else { throw CoreError.invalidMessage }
    logs = try data.decode([String].self).suffix(500).map { "\(id): \($0)" }
  }
}
