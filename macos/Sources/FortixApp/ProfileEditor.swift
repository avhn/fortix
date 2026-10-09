import FortixCore
import SwiftUI

/// ProfileDraft exposes secret-free editable fields while retaining helper-owned certificate trust.
struct ProfileDraft {
  /// Profile retains unedited fields such as existing TOTP settings and certificate trust.
  var profile: VPNProfile
  /// Port uses text editing so invalid input cannot silently become the default TLS port.
  var port: String
  /// RoutesText is a newline-separated list of requested IPv4 prefixes.
  var routesText: String
  /// DomainsText is a newline-separated list of explicitly scoped DNS domains.
  var domainsText: String

  /// Creates a draft preserving omitted backend choices and all stored configuration defaults.
  init(profile: VPNProfile) {
    self.profile = profile
    port = String(profile.gateway.resolvedPort)
    routesText = (profile.routes.include ?? []).joined(separator: "\n")
    domainsText = (profile.dns.domains ?? []).joined(separator: "\n")
  }

  /// NewProfile provides a neutral draft without real endpoints, usernames, or credentials.
  static var newProfile: VPNProfile {
    VPNProfile(id: "", name: "", gateway: .init(host: ""), username: "")
  }

  /// Value validates port text and backend compatibility before asking the helper for full validation.
  func value() throws -> VPNProfile {
    guard let parsedPort = Int(port), (1...65535).contains(parsedPort) else {
      throw CoreError.invalidProfile
    }
    var result = profile
    result.gateway.port = parsedPort
    // Switching policy modes omits fields that the helper forbids in the newly selected mode.
    result.routes.include = result.routes.mode == "custom" ? Self.entries(routesText) : nil
    result.dns.domains = result.dns.mode == "split" ? Self.entries(domainsText) : nil
    if result.mfa.mode != "totp" {
      result.mfa.digits = nil
      result.mfa.period = nil
      result.mfa.algorithm = nil
    }
    guard ["none", "push", "prompt", "totp", "static"].contains(result.mfa.mode) else {
      throw CoreError.invalidProfile
    }
    try result.validate()
    return result
  }

  /// Entries accepts newline or comma separators without broadening an empty DNS or route policy.
  private static func entries(_ text: String) -> [String]? {
    let entries = text.components(separatedBy: CharacterSet(charactersIn: ",\n"))
      .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
    return entries.isEmpty ? nil : entries
  }
}

/// ProfileEditor edits one secret-free draft; all persistence and active-profile rules remain helper-owned.
struct ProfileEditor: View {
  /// Model coordinates validated helper writes and explicit password removal.
  @ObservedObject var model: AppModel
  /// Draft separates unsaved input from authoritative profile state.
  @State private var draft: ProfileDraft
  /// Existing prevents editing an ID into a different stored profile.
  private let existing: Bool
  /// Dismiss closes the sheet after confirmed save, never before the helper responds.
  @Environment(\.dismiss) private var dismiss

  /// Creates a new or existing-profile sheet while copying all editable fields into local state.
  init(model: AppModel, profile: VPNProfile?) {
    self.model = model
    existing = profile != nil
    _draft = State(initialValue: ProfileDraft(profile: profile ?? ProfileDraft.newProfile))
  }

  /// Body presents native labeled form controls and a read-only certificate identity.
  var body: some View {
    VStack(alignment: .leading, spacing: AppTheme.spacing) {
      Text(existing ? "Edit profile" : "New profile").font(.title2)
      Form {
        Section("Connection") {
          TextField("Profile ID", text: $draft.profile.id).disabled(existing)
          TextField("Name", text: $draft.profile.name)
          TextField("Gateway", text: $draft.profile.gateway.host)
          TextField("TLS port", text: $draft.port)
          TextField("Realm", text: optionalText($draft.profile.realm))
          TextField("Username", text: $draft.profile.username)
          Picker("Backend", selection: backend) {
            Text("Automatic").tag("automatic")
            Text("Native (password only)").tag("native")
            Text("openfortivpn (2FA support)").tag("openfortivpn")
          }
          Picker("Second factor", selection: $draft.profile.mfa.mode) {
            Text("None").tag("none")
            Text("Push").tag("push")
            Text("Code prompt").tag("prompt")
            Text("TOTP").tag("totp")
            Text("Static code").tag("static")
          }
          if draft.profile.mfa.mode == "totp" {
            TextField("TOTP digits", value: $draft.profile.mfa.digits, format: .number)
            TextField("TOTP period (seconds)", value: $draft.profile.mfa.period, format: .number)
            Picker("TOTP algorithm", selection: optionalText($draft.profile.mfa.algorithm)) {
              Text("Default (SHA1)").tag("")
              Text("SHA1").tag("SHA1")
              Text("SHA256").tag("SHA256")
              Text("SHA512").tag("SHA512")
            }
          }
          if draft.profile.resolvedBackend == "native" && draft.profile.mfa.mode != "none" {
            Text("Native does not support a second factor. Select Automatic or openfortivpn.")
              .foregroundStyle(.secondary)
          }
        }
        Section("Routes") {
          Picker("Routing", selection: $draft.profile.routes.mode) {
            Text("Gateway routes").tag("gateway")
            Text("Custom routes").tag("custom")
            Text("Full tunnel").tag("full")
          }
          if draft.profile.routes.mode == "custom" {
            TextField(
              "IPv4 prefixes (comma or newline separated)", text: $draft.routesText, axis: .vertical
            )
          }
          Toggle(
            "Preserve local network",
            isOn: Binding(
              get: { draft.profile.routes.preserveLAN ?? true },
              set: { draft.profile.routes.preserveLAN = $0 }))
          if draft.profile.routes.mode == "full" {
            Text("Full tunnel sends all IPv4 traffic through this VPN.").foregroundStyle(.secondary)
          }
        }
        Section("DNS") {
          Picker("DNS policy", selection: $draft.profile.dns.mode) {
            Text("Unmanaged").tag("none")
            Text("Split DNS").tag("split")
          }
          if draft.profile.dns.mode == "split" {
            TextField(
              "DNS domains (comma or newline separated)", text: $draft.domainsText, axis: .vertical)
          }
        }
        Section("Certificate trust") {
          Text(draft.profile.trustedCert ?? "System certificate validation; no stored pin.")
            .font(.caption.monospaced()).textSelection(.enabled)
          Text("A certificate pin can only be changed by verifying an active rejected certificate.")
            .foregroundStyle(.secondary)
        }
      }.formStyle(.grouped)
      if let message = model.message { Text(message).foregroundStyle(.secondary) }
      HStack {
        if existing {
          Button("Forget password") { model.perform { try await model.forget(draft.profile.id) } }
        }
        Spacer()
        Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
        Button("Save") {
          model.perform {
            try await model.save(draft.value(), existing: existing)
            dismiss()
          }
        }.keyboardShortcut(.defaultAction)
      }.disabled(model.busy)
    }
    .padding()
    .frame(width: AppTheme.windowWidth, height: AppTheme.windowHeight)
  }

  /// Backend preserves omission instead of silently rewriting an Automatic profile on edit.
  private var backend: Binding<String> {
    Binding(
      get: { draft.profile.backend ?? "automatic" },
      set: {
        draft.profile.backend = $0 == "automatic" ? nil : $0
      })
  }

  /// OptionalText maps an empty field to omission without normalizing a nonempty credential identity.
  private func optionalText(_ binding: Binding<String?>) -> Binding<String> {
    Binding(
      get: { binding.wrappedValue ?? "" },
      set: {
        binding.wrappedValue = $0.isEmpty ? nil : $0
      })
  }
}
