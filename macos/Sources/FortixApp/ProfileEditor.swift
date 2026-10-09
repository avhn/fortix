import FortixCore
import SwiftUI

/// EntryRow is one editable list entry with a stable identity for row-level validation messages.
struct EntryRow: Identifiable, Equatable {
  /// ID keeps a row's message attached to it while other rows are added or removed.
  let id = UUID()
  /// Text is the raw entry as typed, normalized only when the draft is read.
  var text: String
}

/// ProfileDraft exposes secret-free editable fields while retaining helper-owned certificate trust.
struct ProfileDraft {
  /// Profile retains unedited fields such as existing TOTP settings and certificate trust.
  var profile: VPNProfile
  /// Port uses text editing so invalid input cannot silently become the default TLS port.
  var port: String
  /// RouteRows holds requested IPv4 prefixes, one per row.
  var routeRows: [EntryRow]
  /// ExcludeRows holds ranges removed from gateway-pushed routes, one per row.
  var excludeRows: [EntryRow]
  /// DomainRows holds explicitly scoped split DNS domains, one per row.
  var domainRows: [EntryRow]

  /// Creates a draft preserving omitted backend choices and all stored configuration defaults.
  init(profile: VPNProfile) {
    self.profile = profile
    port = String(profile.gateway.resolvedPort)
    routeRows = Self.rows(profile.routes.include)
    excludeRows = Self.rows(profile.routes.exclude)
    domainRows = Self.rows(profile.dns.domains)
  }

  /// Creates a new-profile draft from a shared file; absent required fields stay empty.
  /// The file's certificate pin is not copied into the profile because pins are helper-owned.
  init(shared: SharedProfileDraft) {
    var profile = Self.showingLists(shared).apply(to: Self.newProfile)
    profile.trustedCert = nil
    self.init(profile: profile)
  }

  /// Creates a draft that merges a shared file into an existing profile, keeping its ID,
  /// username, and stored certificate pin while replacing supplied route and domain lists whole.
  init(shared: SharedProfileDraft, merging existing: VPNProfile) {
    var profile = Self.showingLists(shared).merge(into: existing)
    profile.trustedCert = existing.trustedCert
    self.init(profile: profile)
  }

  /// NewProfile provides a neutral draft without real endpoints, usernames, or credentials.
  static var newProfile: VPNProfile {
    VPNProfile(id: "", name: "", gateway: .init(host: ""), username: "")
  }

  /// RouteEntries lists trimmed, non-empty prefixes with the row each one came from.
  var routeEntries: [(row: UUID, value: String)] {
    routeRows.compactMap { row in
      let value = row.text.trimmingCharacters(in: .whitespacesAndNewlines)
      return value.isEmpty ? nil : (row.id, value)
    }
  }

  /// ExcludeEntries lists trimmed, non-empty excluded prefixes with their source rows.
  var excludeEntries: [(row: UUID, value: String)] {
    excludeRows.compactMap { row in
      let value = row.text.trimmingCharacters(in: .whitespacesAndNewlines)
      return value.isEmpty ? nil : (row.id, value)
    }
  }

  /// DomainEntries lists trimmed, non-empty domains with one leading wildcard label removed.
  var domainEntries: [(row: UUID, value: String)] {
    domainRows.compactMap { row in
      let value = row.text.trimmingCharacters(in: .whitespacesAndNewlines)
      return value.isEmpty ? nil : (row.id, ProfileRules.normalizeDomain(value))
    }
  }

  /// RouteProblems maps each invalid custom-route row to its first validation message.
  var routeProblems: [UUID: String] {
    guard profile.routes.mode == "custom" else { return [:] }
    let entries = routeEntries
    return Self.rowProblems(
      ProfileRules.routeProblems(entries.map(\.value)), rows: entries.map(\.row))
  }

  /// ExcludeProblems maps each invalid excluded-range row to its first validation message.
  var excludeProblems: [UUID: String] {
    guard profile.routes.mode != "custom" else { return [:] }
    let entries = excludeEntries
    return Self.rowProblems(
      ProfileRules.routeProblems(entries.map(\.value)), rows: entries.map(\.row))
  }

  /// ExcludeCountInvalid reports more excluded ranges than the helper accepts.
  var excludeCountInvalid: Bool {
    profile.routes.mode != "custom" && excludeEntries.count > ProfileRules.maxExclude
  }

  /// DomainProblems maps each invalid split DNS row to its first validation message.
  var domainProblems: [UUID: String] {
    guard profile.dns.mode == "split" else { return [:] }
    let entries = domainEntries
    return Self.rowProblems(
      ProfileRules.domainProblems(entries.map(\.value)), rows: entries.map(\.row))
  }

  /// RoutesEmpty reports custom routing without any prefix, which the helper rejects.
  var routesEmpty: Bool { profile.routes.mode == "custom" && routeEntries.isEmpty }

  /// DomainCountInvalid reports split DNS outside the helper's 1 to 32 domain range.
  var domainCountInvalid: Bool {
    profile.dns.mode == "split" && !(1...32).contains(domainEntries.count)
  }

  /// HasListProblems blocks saving while any route or domain row is invalid or a list is empty.
  var hasListProblems: Bool {
    routesEmpty || domainCountInvalid || excludeCountInvalid || !routeProblems.isEmpty
      || !excludeProblems.isEmpty || !domainProblems.isEmpty
  }

  /// Value validates port text, lists, and backend compatibility before the helper's full validation.
  func value() throws -> VPNProfile {
    guard let parsedPort = Int(port), (1...65535).contains(parsedPort), !hasListProblems else {
      throw CoreError.invalidProfile
    }
    var result = profile
    result.gateway.port = parsedPort
    // Switching policy modes omits fields that the helper forbids in the newly selected mode.
    result.routes.include = result.routes.mode == "custom" ? routeEntries.map(\.value) : nil
    let excluded = excludeEntries.map(\.value)
    result.routes.exclude = result.routes.mode == "custom" || excluded.isEmpty ? nil : excluded
    result.dns.domains = result.dns.mode == "split" ? domainEntries.map(\.value) : nil
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

  /// Rows converts a stored list to editable rows, offering one empty row for an empty list.
  private static func rows(_ entries: [String]?) -> [EntryRow] {
    let rows = (entries ?? []).map { EntryRow(text: $0) }
    return rows.isEmpty ? [EntryRow(text: "")] : rows
  }

  /// RowProblems keeps the first message per list index and attaches it to the source row.
  private static func rowProblems(_ problems: [(index: Int, message: String)], rows: [UUID])
    -> [UUID: String]
  {
    var result: [UUID: String] = [:]
    for problem in problems where result[rows[problem.index]] == nil {
      result[rows[problem.index]] =
        problem.message.prefix(1).uppercased()
        + problem.message.dropFirst()
    }
    return result
  }

  /// ShowingLists selects custom routing or split DNS when a file supplies a list without its mode,
  /// so the supplied entries are visible for review instead of silently dropped on save.
  private static func showingLists(_ shared: SharedProfileDraft) -> SharedProfileDraft {
    var result = shared
    if result.routes?.mode == nil, result.routes?.include != nil { result.routes?.mode = "custom" }
    if result.dns?.mode == nil, result.dns?.domains != nil { result.dns?.mode = "split" }
    return result
  }
}

/// SharedImport carries one parsed file profile and its position within a multi-profile import.
struct SharedImport {
  /// Draft holds only the fields the file supplied.
  let draft: SharedProfileDraft
  /// Position is the one-based index of this profile in the file.
  let position: Int
  /// Count is the number of profiles in the file.
  let count: Int
}

/// ImportTarget chooses whether a shared profile becomes a new profile or updates an existing one.
enum ImportTarget: Hashable {
  /// New creates a profile; required fields absent from the file must be filled in.
  case new
  /// Merge overlays supplied fields onto a chosen existing profile.
  case merge
}

/// ProfileEditor edits one secret-free draft; all persistence and active-profile rules remain helper-owned.
struct ProfileEditor: View {
  /// Model coordinates validated helper writes and explicit password removal.
  @ObservedObject var model: AppModel
  /// Draft separates unsaved input from authoritative profile state.
  @State private var draft: ProfileDraft
  /// EditingExisting prevents editing an ID into a different stored profile.
  private let editingExisting: Bool
  /// Shared is the imported file profile being reviewed, or nil for ordinary editing.
  private let shared: SharedImport?
  /// OnStopImport discards the remaining profiles of a multi-profile import.
  private let onStopImport: (() -> Void)?
  /// Target is the current import choice between a new profile and a merge.
  @State private var target: ImportTarget
  /// MergeID identifies the existing profile a merge updates.
  @State private var mergeID: String
  /// Dismiss closes the sheet after confirmed save, never before the helper responds.
  @Environment(\.dismiss) private var dismiss

  /// Creates a new or existing-profile sheet while copying all editable fields into local state.
  init(model: AppModel, profile: VPNProfile?) {
    self.model = model
    editingExisting = profile != nil
    shared = nil
    onStopImport = nil
    _target = State(initialValue: .new)
    _mergeID = State(initialValue: "")
    _draft = State(initialValue: ProfileDraft(profile: profile ?? ProfileDraft.newProfile))
  }

  /// Creates an import review sheet as a new profile. A merge is always an explicit choice,
  /// preselecting the existing profile with the file's ID, because a merge can change the
  /// gateway that profile connects to.
  init(model: AppModel, shared: SharedImport, onStopImport: @escaping () -> Void) {
    self.model = model
    editingExisting = false
    self.shared = shared
    self.onStopImport = onStopImport
    let match = model.profiles.first { $0.id == shared.draft.id }
    _target = State(initialValue: .new)
    _mergeID = State(initialValue: match?.id ?? model.profiles.first?.id ?? "")
    _draft = State(initialValue: ProfileDraft(shared: shared.draft))
  }

  /// Existing is true for ordinary edits and for merges, which must keep the chosen ID.
  private var existing: Bool { editingExisting || (shared != nil && target == .merge) }

  /// Missing lists required fields the file did not supply; merges keep the existing values.
  private var missing: Set<String> {
    guard let shared, target == .new else { return [] }
    return Set(shared.draft.missing)
  }

  /// ImportedPin is the certificate pin carried by the file under review, if any.
  private var importedPin: String? { shared?.draft.trustedCert.flatMap { $0.isEmpty ? nil : $0 } }

  /// Title names the sheet's purpose, including the position within a multi-profile import.
  private var title: String {
    if let shared {
      return shared.count > 1
        ? "Import profile \(shared.position) of \(shared.count)" : "Import profile"
    }
    return existing ? "Edit profile" : "New profile"
  }

  /// Body presents native labeled form controls and a read-only certificate identity.
  var body: some View {
    VStack(alignment: .leading, spacing: AppTheme.spacing) {
      Text(title).font(.title2)
      Form {
        if shared != nil { importSection }
        Section("Connection") {
          TextField("Profile ID", text: $draft.profile.id).disabled(existing)
          requiredNote("id", empty: draft.profile.id.isEmpty)
          if shared != nil, !existing, model.profiles.contains(where: { $0.id == draft.profile.id })
          {
            note("This ID already exists. Choose another ID or merge into the existing profile.")
          }
          TextField("Name", text: $draft.profile.name)
          requiredNote("name", empty: draft.profile.name.isEmpty)
          TextField("Gateway", text: $draft.profile.gateway.host)
          requiredNote("gateway.host", empty: draft.profile.gateway.host.isEmpty)
          TextField("TLS port", text: $draft.port)
          TextField("Realm", text: optionalText($draft.profile.realm))
          TextField("Username", text: $draft.profile.username)
          if missing.contains("username"), draft.profile.username.isEmpty {
            note("Required. Shared profile files never include a username.")
          }
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
            EntryListEditor(
              title: "IPv4 prefix", placeholder: "192.0.2.0/24", rows: $draft.routeRows,
              problems: draft.routeProblems,
              listProblem: draft.routesEmpty
                ? listNote("routes.include", fallback: "Add at least one IPv4 prefix.") : nil)
          }
          if draft.profile.routes.mode != "custom" {
            Text("Excluded routes")
            EntryListEditor(
              title: "Excluded route", placeholder: "192.0.2.0/24", rows: $draft.excludeRows,
              problems: draft.excludeProblems,
              listProblem: draft.excludeCountInvalid
                ? listNote("routes.exclude", fallback: "Exclude at most 64 ranges.") : nil)
            Text(
              "Ranges left out of the routes this VPN's gateway sends, for example a network another VPN uses, so both can connect at once. Requires the native backend."
            )
            .font(.footnote).foregroundStyle(.secondary)
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
            EntryListEditor(
              title: "DNS domain", placeholder: "*.example.com", rows: $draft.domainRows,
              problems: draft.domainProblems,
              listProblem: draft.domainCountInvalid
                ? listNote("dns.domains", fallback: "Add 1 to 32 domains.") : nil)
            Text("A leading *. is removed: *.example.com covers example.com and its subdomains.")
              .font(.footnote).foregroundStyle(.secondary)
          }
        }
        Section("Certificate trust") {
          if let importedPin {
            Text("Unverified fingerprint from the imported file").font(.headline)
            Text(importedPin).font(.caption.monospaced()).textSelection(.enabled)
            Text(
              "Whoever made this file supplied this SHA-256 fingerprint, and it is not saved. A matching fingerprint proves nothing if the file itself was tampered with. If the gateway certificate cannot be verified when you connect, confirm its fingerprint with your administrator over a separate channel before trusting it."
            ).foregroundStyle(.secondary)
          }
          Text(draft.profile.trustedCert ?? "System certificate validation; no stored pin.")
            .font(.caption.monospaced()).textSelection(.enabled)
          Text("A certificate pin can only be changed by verifying an active rejected certificate.")
            .foregroundStyle(.secondary)
        }
      }.formStyle(.grouped)
      if let message = model.message { Text(message).foregroundStyle(.secondary) }
      HStack {
        if existing && shared == nil {
          Button("Forget password") { model.perform { try await model.forget(draft.profile.id) } }
        }
        if let shared, shared.position < shared.count {
          Button("Stop import") {
            onStopImport?()
            dismiss()
          }
        }
        Spacer()
        Button(shared.map { $0.position < $0.count ? "Skip" : "Cancel" } ?? "Cancel") { dismiss() }
          .keyboardShortcut(.cancelAction)
        Button("Save") {
          model.perform {
            try await model.save(draft.value(), existing: existing)
            dismiss()
          }
        }
        .keyboardShortcut(.defaultAction)
        .disabled(draft.hasListProblems)
      }.disabled(model.busy)
    }
    .padding()
    .frame(width: AppTheme.windowWidth, height: AppTheme.windowHeight)
    .onChange(of: target) { _ in reloadImport() }
    .onChange(of: mergeID) { _ in reloadImport() }
  }

  /// ImportSection offers a new profile or a merge into a chosen existing profile.
  @ViewBuilder private var importSection: some View {
    Section("Import") {
      if model.profiles.isEmpty {
        Text("Fields marked as not in the imported file must be filled in before saving.")
          .font(.footnote).foregroundStyle(.secondary)
      } else {
        Picker("Import", selection: $target) {
          Text("Import as new profile").tag(ImportTarget.new)
          Text("Merge into existing profile").tag(ImportTarget.merge)
        }.pickerStyle(.radioGroup)
        if target == .merge {
          Picker("Existing profile", selection: $mergeID) {
            ForEach(model.profiles) { Text("\($0.name) (\($0.id))").tag($0.id) }
          }
          Text(
            "Only fields in the file replace this profile's values. Its ID and username are kept, and routes and DNS domains in the file replace those lists as a whole."
          ).font(.footnote).foregroundStyle(.secondary)
          if let change = gatewayChange {
            Label(
              "This file changes the gateway from \(change.from) to \(change.to). Your password would be sent to the new gateway. Confirm the change with your administrator before saving.",
              systemImage: "exclamationmark.triangle.fill"
            ).foregroundStyle(.orange)
          }
        } else {
          Text("Fields marked as not in the imported file must be filled in before saving.")
            .font(.footnote).foregroundStyle(.secondary)
        }
      }
    }
  }

  /// GatewayChange describes a merge that would point an existing profile at another gateway.
  private var gatewayChange: (from: String, to: String)? {
    guard let shared, target == .merge,
      let base = model.profiles.first(where: { $0.id == mergeID })
    else { return nil }
    let host = shared.draft.gateway?.host ?? base.gateway.host
    let port = shared.draft.gateway?.port ?? base.gateway.resolvedPort
    guard host != base.gateway.host || port != base.gateway.resolvedPort else { return nil }
    return ("\(base.gateway.host):\(base.gateway.resolvedPort)", "\(host):\(port)")
  }

  /// ReloadImport rebuilds the draft from the file whenever the import target changes.
  private func reloadImport() {
    guard let shared else { return }
    if target == .merge, let base = model.profiles.first(where: { $0.id == mergeID }) {
      draft = ProfileDraft(shared: shared.draft, merging: base)
    } else {
      draft = ProfileDraft(shared: shared.draft)
    }
  }

  /// RequiredNote marks an empty required field that the imported file did not supply.
  @ViewBuilder private func requiredNote(_ field: String, empty: Bool) -> some View {
    if missing.contains(field), empty { note("Required. Not in the imported file.") }
  }

  /// ListNote explains an empty required list, naming the file when it omitted the list.
  private func listNote(_ field: String, fallback: String) -> String {
    missing.contains(field) ? "Required. Not in the imported file." : fallback
  }

  /// Note renders a short attention footnote beneath the field it describes.
  private func note(_ text: String) -> some View {
    Text(text).font(.footnote).foregroundStyle(.orange)
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

/// EntryListEditor edits one ordered list as removable text rows with per-row validation messages.
private struct EntryListEditor: View {
  /// Title names one entry for labels and accessibility.
  let title: String
  /// Placeholder shows a documentation-only example value.
  let placeholder: String
  /// Rows is the editable list, including empty rows that are dropped on save.
  @Binding var rows: [EntryRow]
  /// Problems maps invalid rows to their validation messages.
  let problems: [UUID: String]
  /// ListProblem explains a list-level problem such as a required list being empty.
  let listProblem: String?

  /// Body shows one text field per entry with a remove button, then an add button.
  var body: some View {
    ForEach($rows) { $row in
      VStack(alignment: .leading, spacing: AppTheme.spacing / 3) {
        HStack {
          TextField(title, text: $row.text, prompt: Text(placeholder)).labelsHidden()
          Button {
            rows.removeAll { $0.id == row.id }
          } label: {
            Image(systemName: "minus.circle")
          }
          .buttonStyle(.borderless)
          .help("Remove this \(title)")
          .accessibilityLabel("Remove \(title) \(row.text)")
        }
        if let problem = problems[row.id] {
          Text(problem).font(.footnote).foregroundStyle(.red)
        }
      }
    }
    HStack {
      Button {
        rows.append(EntryRow(text: ""))
      } label: {
        Label("Add \(title)", systemImage: "plus")
      }
      .buttonStyle(.borderless)
      Spacer()
      if let listProblem { Text(listProblem).font(.footnote).foregroundStyle(.orange) }
    }
  }
}
