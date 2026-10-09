import AppKit
import FortixCore
import ServiceManagement
import SwiftUI

/// EditorSelection gives a stable identity to a new or existing profile editor sheet.
private struct EditorSelection: Identifiable {
  /// Profile is absent only for a new configuration.
  let profile: VPNProfile?
  /// ID prevents changing draft identity when authoritative profile state refreshes.
  let id = UUID()
}

/// ManagementView groups profile control, bounded diagnostics, and explicit installation settings.
struct ManagementView: View {
  /// Model is the shared user-privilege coordinator used by the menu bar.
  @ObservedObject var model: AppModel
  /// Editor identifies the current unsaved profile sheet.
  @State private var editor: EditorSelection?
  /// ShowImport reveals read-only drafts before any helper write.
  @State private var showImport = false
  /// Deleting retains the exact configuration selected for an explicit delete confirmation.
  @State private var deleting: VPNProfile?
  /// Tab remembers the currently visible management area.
  @State private var tab = "profiles"
  /// Installation uses only the app's fixed bundled executables.
  private let installation = AppInstallation()

  /// Body keeps unavailable state visible and binds prompt sheets to their original challenge identity.
  var body: some View {
    VStack(alignment: .leading, spacing: AppTheme.spacing) {
      HStack {
        RingIcon(status: model.aggregate, label: model.statusText)
        Text(model.statusText).font(.headline)
        Spacer()
        if model.busy {
          ProgressView().controlSize(.small).accessibilityLabel("Operation in progress")
        }
      }
      if let message = model.message { Text(message).textSelection(.enabled) }
      TabView(selection: $tab) {
        profiles.tabItem { Text("Profiles") }.tag("profiles")
        LogView(model: model).tabItem { Text("Logs") }.tag("logs")
        SettingsView(model: model).tabItem { Text("Settings and installation") }.tag("settings")
      }
    }
    .padding()
    .frame(minWidth: AppTheme.windowWidth, minHeight: AppTheme.windowHeight)
    .onAppear { if !model.reachable { tab = "settings" } }
    .onReceive(model.$prompts) { prompts in
      if !prompts.isEmpty {
        editor = nil
        showImport = false
      }
    }
    .sheet(item: $editor) { selection in ProfileEditor(model: model, profile: selection.profile) }
    .sheet(isPresented: $showImport) { ImportPreview(model: model) }
    .sheet(
      item: Binding(
        get: { model.currentPrompt }, set: { _ in })
    ) { prompt in
      ChallengeSheet(model: model, prompt: prompt).id(prompt.id).interactiveDismissDisabled()
    }
    .confirmationDialog(
      "Delete \(deleting?.name ?? "profile")?",
      isPresented: Binding(
        get: { deleting != nil }, set: { if !$0 { deleting = nil } })
    ) {
      if let selected = deleting {
        Button("Delete profile", role: .destructive) {
          model.perform { try await model.delete(selected.id) }
          deleting = nil
        }
      }
    } message: {
      Text(
        "This removes the idle profile. Its saved Keychain password is not removed automatically.")
    }
  }

  /// Profiles presents configuration identity, textual phase, cleanup warnings, and explicit controls.
  private var profiles: some View {
    VStack(alignment: .leading, spacing: AppTheme.spacing) {
      HStack {
        Button("New profile") { editor = EditorSelection(profile: nil) }
        Button("Import FortiClient...") {
          model.perform {
            model.importDrafts = try await installation.preview()
            showImport = true
          }
        }
        Spacer()
        Button("Connect all") { model.perform { try await model.connectAll() } }
        Button("Disconnect all") { model.perform { try await model.disconnect() } }
      }.disabled(!model.reachable || model.busy)
      if model.profiles.isEmpty {
        Text("No profiles. Create a profile or preview a FortiClient import.").foregroundStyle(
          .secondary)
      }
      List(model.profiles) { profile in
        let state = model.states[profile.id]
        VStack(alignment: .leading, spacing: AppTheme.spacing) {
          HStack {
            Text(profile.name).font(.headline)
            Spacer()
            Text(model.reachable ? (state?.state ?? "unknown") : "Status unavailable")
          }
          Text(
            "\(profile.gateway.host):\(profile.gateway.resolvedPort) | \(profile.resolvedBackend)"
          )
          .font(.caption).foregroundStyle(.secondary)
          if let detail = state?.detail, !detail.isEmpty { Text(detail).font(.caption) }
          if state?.cleanupPending == true {
            Text("Network cleanup pending. Disconnect has not completed.")
          }
          HStack {
            Button("Connect") { model.perform { try await model.connect(profile.id) } }
              .disabled(state?.wanted == true)
            Button("Disconnect") { model.perform { try await model.disconnect(profile.id) } }
            Button("Edit") { editor = EditorSelection(profile: profile) }
              .disabled(
                !["disconnected", "failed"].contains(state?.state ?? "disconnected")
                  || state?.cleanupPending == true)
            Button("Forget password") { model.perform { try await model.forget(profile.id) } }
            Button("Delete", role: .destructive) { deleting = profile }
          }.disabled(!model.reachable || model.busy)
        }.padding(.vertical)
      }
    }.padding()
  }
}

/// ChallengeSheet requires explicit certificate verification or hidden credential entry for one live event.
private struct ChallengeSheet: View {
  /// Model checks profile and attempt identity again before every answer or trust decision.
  @ObservedObject var model: AppModel
  /// Prompt is immutable so a new event cannot silently replace a certificate under a pending decision.
  let prompt: PendingPrompt
  /// Secret is transient sheet state and is cleared immediately on submit or dismissal.
  @State private var secret = ""
  /// Remember defaults off and applies only to passwords after a successful connection.
  @State private var remember = false
  /// Verified requires the user to compare the fingerprint through an independent trusted source.
  @State private var verified = false

  /// Body never provides editable certificate trust or stores second-factor codes in Keychain.
  var body: some View {
    VStack(alignment: .leading, spacing: AppTheme.spacing) {
      Text(prompt.isCertificate ? "Verify certificate" : "Credential required").font(.title2)
      Text("Profile: \(prompt.event.profile), attempt \(prompt.event.attempt)")
      if prompt.isCertificate {
        Text(
          "The certificate could not be verified. Compare this SHA-256 fingerprint with your administrator before trusting it."
        )
        Text("Subject: \(prompt.event.subject ?? "")")
        Text("Issuer: \(prompt.event.issuer ?? "")")
        Text(prompt.event.digest ?? "").font(.body.monospaced()).textSelection(.enabled)
        Toggle("I verified this fingerprint independently", isOn: $verified)
      } else {
        Text(prompt.event.prompt ?? "Enter the requested credential.")
        SecureField(
          prompt.event.kind == "password" ? "Password" : "Second-factor code", text: $secret)
        if prompt.event.kind == "password" {
          Toggle("Save password in Keychain after connecting", isOn: $remember)
        }
      }
      if let message = model.message { Text(message) }
      HStack {
        Button("Cancel and disconnect", role: .cancel) {
          secret = ""
          model.perform { try await model.cancel(prompt) }
        }
        Spacer()
        Button(prompt.isCertificate ? "Trust and reconnect" : "Continue") {
          let submitted = secret
          secret = ""
          model.perform {
            if prompt.isCertificate {
              try await model.trust(prompt)
            } else {
              try await model.answer(prompt, secret: submitted, remember: remember)
            }
          }
        }
        .keyboardShortcut(.defaultAction)
        .disabled(prompt.isCertificate ? !verified : secret.isEmpty)
      }.disabled(model.busy || !model.isCurrent(prompt))
    }
    .padding()
    .frame(width: AppTheme.windowWidth)
    .onDisappear { secret = "" }
  }
}

/// ImportPreview requires a separate approval for each secret-free draft and refuses silent overwrites.
private struct ImportPreview: View {
  /// Model retains drafts independently of helper-owned configuration.
  @ObservedObject var model: AppModel
  /// Dismiss closes the preview without applying any remaining draft.
  @Environment(\.dismiss) private var dismiss

  /// Body shows routing and DNS policy before an explicit per-profile import.
  var body: some View {
    VStack(alignment: .leading, spacing: AppTheme.spacing) {
      Text("FortiClient import preview").font(.title2)
      Text(
        "No passwords, seeds, or certificate trust are imported. Existing IDs are not overwritten.")
      if model.importDrafts.isEmpty { Text("No importable profiles remain.") }
      List(model.importDrafts) { draft in
        VStack(alignment: .leading, spacing: AppTheme.spacing) {
          Text("\(draft.name) (\(draft.id))").font(.headline)
          Text("\(draft.gateway.host):\(draft.gateway.resolvedPort), username: \(draft.username)")
          Text("Backend: \(draft.resolvedBackend), MFA: \(draft.mfa.mode)")
          Text(
            "Routes: \(draft.routes.mode) \((draft.routes.include ?? []).joined(separator: ", "))")
          Text("DNS: \(draft.dns.mode) \((draft.dns.domains ?? []).joined(separator: ", "))")
          if model.profiles.contains(where: { $0.id == draft.id }) {
            Text("This ID already exists. Edit the existing profile instead.")
          } else {
            Button("Import this profile") {
              model.perform {
                try await model.save(draft, existing: false)
                model.importDrafts.removeAll { $0.id == draft.id }
              }
            }.disabled(model.busy || !model.reachable)
          }
        }.padding(.vertical)
      }
      if let message = model.message { Text(message) }
      Button("Done") { dismiss() }.disabled(model.busy)
    }.padding().frame(width: AppTheme.windowWidth, height: AppTheme.windowHeight)
  }
}

/// LogView displays only bounded, already-redacted helper diagnostics, not privileged log files.
private struct LogView: View {
  /// Model owns the subscription and explicit log-tail operation.
  @ObservedObject var model: AppModel
  /// Selected identifies the profile whose diagnostic tail is requested.
  @State private var selected = ""

  /// Body preserves selectable diagnostic text while disabling requests for a missing profile.
  var body: some View {
    VStack(alignment: .leading, spacing: AppTheme.spacing) {
      HStack {
        Picker("Profile", selection: $selected) {
          Text("Select a profile").tag("")
          ForEach(model.profiles) { Text($0.name).tag($0.id) }
        }
        Button("Load recent logs") { model.perform { try await model.loadLogs(selected) } }
          .disabled(selected.isEmpty || model.busy || !model.reachable)
      }
      ScrollView {
        Text(model.logs.joined(separator: "\n")).font(.caption.monospaced())
          .frame(maxWidth: .infinity, alignment: .leading).textSelection(.enabled)
      }
      Text("Shows up to 500 redacted lines. Credentials are never included.").foregroundStyle(
        .secondary)
    }.padding()
  }
}

/// SettingsView makes installation, optional 2FA support, login-item enrollment, and removal explicit.
private struct SettingsView: View {
  /// Model enforces serialized operations and verified clean shutdown before uninstall.
  @ObservedObject var model: AppModel
  /// Animate controls only the connecting ring; reduced motion still overrides this preference.
  @AppStorage("animateIcon") private var animate = true
  /// LoginEnabled reflects the operating system's actual login-item registration status.
  @State private var loginEnabled = SMAppService.mainApp.status == .enabled
  /// ConfirmUninstall separates the destructive action from ordinary settings navigation.
  @State private var confirmUninstall = false
  /// Installation provides the fixed bundled executable and an injectable core command runner.
  private let installation = AppInstallation()

  /// Body requires Applications placement before any administrator prompt and never changes networking directly.
  var body: some View {
    Form {
      Section("Appearance and startup") {
        Toggle("Animate connecting icon", isOn: $animate)
        Toggle(
          "Launch Fortix at login",
          isOn: Binding(
            get: { loginEnabled },
            set: { enabled in
              model.perform {
                guard installation.isInApplications else { throw CoreError.commandFailed }
                if enabled {
                  try SMAppService.mainApp.register()
                } else {
                  try await SMAppService.mainApp.unregister()
                }
                loginEnabled = SMAppService.mainApp.status == .enabled
                if SMAppService.mainApp.status == .requiresApproval {
                  model.message = "Approve Fortix in System Settings > General > Login Items."
                }
              }
            }))
      }
      Section("First-launch installation") {
        if !installation.isInApplications {
          Text(
            "Move Fortix.app to /Applications, then launch it from there before installing the helper."
          )
        } else {
          Text(
            "Install the privileged helper once. It owns the tunnels, so quitting this app does not disconnect them."
          )
          Button("Install helper...") {
            model.perform {
              try await model.installHelper(installation)
              UserDefaults.standard.set(true, forKey: "setupCompleted")
              model.message = "Helper installed. Waiting for its local connection."
            }
          }.disabled(model.busy)
        }
      }
      Section("Optional 2FA support") {
        Text(
          "Password-only profiles use the native backend. To use push or codes, install openfortivpn separately, then choose its binary to add 2FA support."
        )
        Button("Add 2FA support...") { chooseBackend() }
          .disabled(!installation.isInApplications || !model.reachable || model.busy)
      }
      Section("Uninstall") {
        Text(
          "Disconnect all tunnels and remove the helper. Profiles and Keychain passwords are retained. Fortix.app can then be moved to the Trash."
        )
        Button("Uninstall helper...", role: .destructive) { confirmUninstall = true }
          .disabled(!installation.isInApplications || !model.reachable || model.busy)
      }
    }
    .formStyle(.grouped)
    .confirmationDialog(
      "Disconnect all tunnels and uninstall the helper?", isPresented: $confirmUninstall
    ) {
      Button("Disconnect and uninstall", role: .destructive) {
        model.perform {
          try await model.disconnect()
          if SMAppService.mainApp.status == .enabled { try await SMAppService.mainApp.unregister() }
          try await installation.uninstall()
          UserDefaults.standard.set(false, forKey: "setupCompleted")
          await model.stop()
          model.message = "Helper removed. Profiles and saved passwords were retained."
          loginEnabled = false
        }
      }
    }
  }

  /// ChooseBackend requires an explicit local executable choice rather than searching or executing PATH entries.
  private func chooseBackend() {
    let panel = NSOpenPanel()
    panel.title = "Choose the installed openfortivpn binary"
    panel.canChooseDirectories = false
    panel.allowsMultipleSelection = false
    panel.begin { response in
      guard response == .OK, let url = panel.url else { return }
      model.perform {
        try await installation.addMFASupport(binary: url)
        model.message =
          "2FA backend installed. Select openfortivpn or Automatic in the profile editor."
      }
    }
  }
}
