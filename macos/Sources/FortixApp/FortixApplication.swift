import AppKit
import FortixCore
import SwiftUI

/// FortixApplication offers a menu bar utility and one shared management window without tunnel ownership.
@MainActor
struct FortixApplication: App {
  /// Model shares one socket subscription across menus, sheets, and windows.
  @StateObject private var model = AppModel()

  /// Body leaves tunnels running on ordinary quit and exposes clean disconnect as a separate action.
  var body: some Scene {
    MenuBarExtra {
      FortixMenu(model: model)
    } label: {
      MenuLabel(model: model)
    }
    Window("Fortix", id: "management") {
      ManagementView(model: model)
    }
    .defaultSize(width: AppTheme.windowWidth, height: AppTheme.windowHeight)
    .commands {
      CommandGroup(replacing: .appTermination) {
        Button("Quit Fortix (leave tunnels running)") { NSApplication.shared.terminate(nil) }
          .keyboardShortcut("q")
        Button("Disconnect all and quit") {
          model.perform {
            try await model.disconnect()
            NSApplication.shared.terminate(nil)
          }
        }.disabled(!model.reachable || model.busy)
      }
    }
  }
}

/// MenuLabel owns the always-present startup hook and reveals new challenges in the management window.
struct MenuLabel: View {
  /// Model provides aggregate status and queued human decisions.
  @ObservedObject var model: AppModel
  /// OpenWindow activates the existing management window rather than creating duplicate sheets.
  @Environment(\.openWindow) private var openWindow

  /// Body starts one bounded reconnect loop and shows initial setup on first launch.
  var body: some View {
    RingIcon(status: model.aggregate, label: "Fortix: \(model.statusText)")
      .task {
        model.start()
        if !UserDefaults.standard.bool(forKey: "setupCompleted") { reveal() }
      }
      .onReceive(model.$prompts) { prompts in
        if !prompts.isEmpty { reveal() }
      }
  }

  /// Reveal brings explicit prompts and installation instructions in front of other applications.
  private func reveal() {
    openWindow(id: "management")
    NSApplication.shared.activate(ignoringOtherApps: true)
  }
}

/// FortixMenu presents textual state and explicit single-profile or all-profile operations.
struct FortixMenu: View {
  /// Model provides authoritative state and serialized user actions.
  @ObservedObject var model: AppModel
  /// OpenWindow reveals the profile editor, diagnostics, and pending prompts.
  @Environment(\.openWindow) private var openWindow

  /// Body never derives connectivity from the icon alone and disables unavailable helper operations.
  var body: some View {
    Text(model.statusText)
    if let message = model.message { Text(message) }
    Divider()
    ForEach(model.profiles) { profile in
      let state = model.states[profile.id]
      Menu("\(profile.name): \(state?.state ?? "unknown")") {
        Button("Connect") { model.perform { try await model.connect(profile.id) } }
          .disabled(!model.reachable || model.busy || state?.wanted == true)
        Button("Disconnect") { model.perform { try await model.disconnect(profile.id) } }
          .disabled(!model.reachable || model.busy)
      }
    }
    Button("Connect all") { model.perform { try await model.connectAll() } }
      .disabled(!model.reachable || model.busy || model.profiles.isEmpty)
    Button("Disconnect all") { model.perform { try await model.disconnect() } }
      .disabled(!model.reachable || model.busy)
    Divider()
    Button(model.prompts.isEmpty ? "Profiles, logs and settings..." : "Review pending request...") {
      openWindow(id: "management")
      NSApplication.shared.activate(ignoringOtherApps: true)
    }
    Divider()
    Button("Quit Fortix (leave tunnels running)") { NSApplication.shared.terminate(nil) }
    Button("Disconnect all and quit") {
      model.perform {
        try await model.disconnect()
        NSApplication.shared.terminate(nil)
      }
    }.disabled(!model.reachable || model.busy)
  }
}
