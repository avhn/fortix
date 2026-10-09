import AppKit
import Combine
import FortixCore
import SwiftUI

/// FortixApplication keeps only the app menu commands in SwiftUI. The status item and the
/// management window are owned by AppKit through the delegate, so no SwiftUI update can
/// resize the status item and feed its own layout back into another update.
@MainActor
struct FortixApplication: App {
  /// Delegate owns the shared model, the status item, and the management window.
  @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate

  /// Body leaves tunnels running on ordinary quit and exposes clean disconnect as a separate action.
  var body: some Scene {
    Settings { EmptyView() }
      .commands {
        CommandGroup(replacing: .appSettings) {}
        CommandGroup(replacing: .appInfo) {
          Button("About Fortix") { showAboutPanel() }
        }
        CommandGroup(replacing: .appTermination) {
          Button("Quit Fortix (leave tunnels running)") { NSApplication.shared.terminate(nil) }
            .keyboardShortcut("q")
          Button("Disconnect all and quit") { delegate.disconnectAllAndQuit() }
        }
      }
  }
}

/// AppDelegate starts the helper subscription once and wires the AppKit status controller.
@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
  /// Model shares one socket subscription across the menu, sheets, and the window.
  private(set) lazy var model = AppModel()
  /// Status owns the menu bar item for the whole application lifetime.
  private var status: StatusController?

  /// ApplicationDidFinishLaunching connects to the helper and shows setup on first launch.
  func applicationDidFinishLaunching(_ notification: Notification) {
    let controller = StatusController(model: model)
    status = controller
    model.start()
    if !UserDefaults.standard.bool(forKey: "setupCompleted") { controller.showWindow() }
  }

  /// DisconnectAllAndQuit stops every tunnel before terminating, when the helper is reachable.
  func disconnectAllAndQuit() {
    guard model.reachable, !model.busy else { return }
    model.perform {
      try await self.model.disconnect()
      NSApplication.shared.terminate(nil)
    }
  }
}

/// StatusController draws the ring in a fixed-width status item and builds the menu natively.
/// The image is replaced only when the visible glyph changes, and the menu is rebuilt each time
/// it opens, so model updates never block the main thread or the menu.
@MainActor
final class StatusController: NSObject, NSMenuDelegate, NSWindowDelegate {
  /// Model provides authoritative state and serialized user actions.
  private let model: AppModel
  /// Item is fixed at square length so a new image never changes the menu bar layout.
  private let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
  /// Shown remembers the glyph on screen to skip redundant image updates.
  private var shown: (status: AggregateStatus, frame: Int)?
  /// Frame advances the connecting animation while it runs.
  private var frame = 0
  /// Animation ticks only while the aggregate status is connecting and motion is allowed.
  private var animation: Timer?
  /// Window hosts the SwiftUI management view and is reused after it is closed.
  private var window: NSWindow?
  /// Subscriptions keep the model observers alive for the controller's lifetime.
  private var subscriptions: Set<AnyCancellable> = []

  /// Init draws the initial glyph and observes the model and the motion preferences.
  init(model: AppModel) {
    self.model = model
    super.init()
    let menu = NSMenu()
    menu.delegate = self
    item.menu = menu
    refresh()
    // objectWillChange fires before the new value is stored, so read it on the next turn.
    model.objectWillChange
      .receive(on: RunLoop.main)
      .sink { [weak self] _ in self?.refresh() }
      .store(in: &subscriptions)
    model.$prompts
      .receive(on: RunLoop.main)
      .sink { [weak self] prompts in if !prompts.isEmpty { self?.showWindow() } }
      .store(in: &subscriptions)
    NotificationCenter.default.publisher(for: UserDefaults.didChangeNotification)
      .receive(on: RunLoop.main)
      .sink { [weak self] _ in self?.refresh() }
      .store(in: &subscriptions)
    NSWorkspace.shared.notificationCenter
      .publisher(for: NSWorkspace.accessibilityDisplayOptionsDidChangeNotification)
      .receive(on: RunLoop.main)
      .sink { [weak self] _ in self?.refresh() }
      .store(in: &subscriptions)
  }

  /// Animates is true when the connecting ring should rotate under the current preferences.
  private var animates: Bool {
    let enabled = UserDefaults.standard.object(forKey: "animateIcon") as? Bool ?? true
    return model.aggregate == .connecting && enabled
      && !NSWorkspace.shared.accessibilityDisplayShouldReduceMotion
  }

  /// Refresh starts or stops the animation and redraws the glyph only if it changed.
  private func refresh() {
    if animates {
      if animation == nil {
        animation = Timer.scheduledTimer(withTimeInterval: AppTheme.frameInterval, repeats: true) {
          [weak self] _ in
          MainActor.assumeIsolated {
            guard let self else { return }
            self.frame = (self.frame + 1) % AppTheme.frames
            self.draw()
          }
        }
      }
    } else {
      animation?.invalidate()
      animation = nil
      frame = 0
    }
    draw()
  }

  /// Draw replaces the status image and accessibility label when the visible glyph changed.
  private func draw() {
    let status = model.aggregate
    let current = animates ? frame : 0
    guard let button = item.button else { return }
    button.setAccessibilityLabel("Fortix: \(model.statusText)")
    button.toolTip = "Fortix: \(model.statusText)"
    if let shown, shown.status == status, shown.frame == current { return }
    shown = (status, current)
    button.image = RingRenderer.image(status: status, frame: current)
  }

  /// MenuNeedsUpdate rebuilds the menu from current state each time it opens.
  func menuNeedsUpdate(_ menu: NSMenu) {
    menu.removeAllItems()
    let idle = model.reachable && !model.busy
    menu.addItem(disabled(model.statusText))
    if let message = model.message { menu.addItem(disabled(message)) }
    menu.addItem(.separator())
    for profile in model.profiles {
      let state = model.states[profile.id]
      let entry = NSMenuItem(title: "\(profile.name): \(state?.state ?? "unknown")", action: nil, keyEquivalent: "")
      let submenu = NSMenu()
      let id = profile.id
      submenu.addItem(action("Connect", enabled: idle && state?.wanted != true) { model in
        model.perform { try await model.connect(id) }
      })
      submenu.addItem(action("Disconnect", enabled: idle) { model in
        model.perform { try await model.disconnect(id) }
      })
      entry.submenu = submenu
      menu.addItem(entry)
    }
    menu.addItem(action("Connect all", enabled: idle && !model.profiles.isEmpty) { model in
      model.perform { try await model.connectAll() }
    })
    menu.addItem(action("Disconnect all", enabled: idle) { model in
      model.perform { try await model.disconnect() }
    })
    menu.addItem(.separator())
    let open = model.prompts.isEmpty ? "Profiles, logs and settings..." : "Review pending request..."
    menu.addItem(action(open, enabled: true) { [weak self] _ in self?.showWindow() })
    menu.addItem(.separator())
    menu.addItem(action("About Fortix", enabled: true) { _ in showAboutPanel() })
    menu.addItem(action("Quit Fortix (leave tunnels running)", enabled: true) { _ in
      NSApplication.shared.terminate(nil)
    })
    menu.addItem(action("Disconnect all and quit", enabled: idle) { model in
      model.perform {
        try await model.disconnect()
        NSApplication.shared.terminate(nil)
      }
    })
  }

  /// Disabled returns a non-interactive informational menu row.
  private func disabled(_ title: String) -> NSMenuItem {
    let item = NSMenuItem(title: title, action: nil, keyEquivalent: "")
    item.isEnabled = false
    return item
  }

  /// Action returns a menu row that runs the handler with the shared model when chosen.
  private func action(_ title: String, enabled: Bool, _ handler: @escaping (AppModel) -> Void)
    -> NSMenuItem
  {
    let item = MenuAction(title: title) { [model] in handler(model) }
    item.isEnabled = enabled
    return item
  }

  /// ShowWindow brings the management window forward with a Dock icon while it is open.
  func showWindow() {
    if window == nil {
      let window = NSWindow(contentViewController: NSHostingController(rootView: ManagementView(model: model)))
      window.title = "Fortix"
      window.setContentSize(NSSize(width: AppTheme.windowWidth, height: AppTheme.windowHeight))
      window.isReleasedWhenClosed = false
      window.delegate = self
      window.center()
      self.window = window
    }
    NSApplication.shared.setActivationPolicy(.regular)
    NSApplication.shared.activate(ignoringOtherApps: true)
    window?.makeKeyAndOrderFront(nil)
  }

  /// WindowWillClose returns the app to a menu bar accessory without a Dock icon.
  func windowWillClose(_ notification: Notification) {
    NSApplication.shared.setActivationPolicy(.accessory)
  }
}

/// MenuAction is a menu item that runs a closure, keeping menu wiring next to the menu layout.
final class MenuAction: NSMenuItem {
  /// Handler runs on the main thread when the item is chosen.
  private let handler: @MainActor () -> Void

  /// Init targets the item at itself so no responder chain lookup is involved.
  init(title: String, handler: @escaping @MainActor () -> Void) {
    self.handler = handler
    super.init(title: title, action: #selector(run), keyEquivalent: "")
    target = self
  }

  /// Coder initialization is unsupported because items are only built in code.
  required init(coder: NSCoder) { fatalError("MenuAction is built in code only") }

  /// Run invokes the handler for a chosen item.
  @objc private func run() {
    MainActor.assumeIsolated { handler() }
  }
}

/// ShowAboutPanel presents the standard About panel with the license and trademark notice.
/// The app is an accessory without a Dock icon, so it activates first to bring the panel forward.
@MainActor
func showAboutPanel() {
  let notice =
    "Free software under the GNU General Public License, version 3 or later.\n"
    + "Not affiliated with or endorsed by Fortinet. FortiGate and FortiClient are "
    + "trademarks of Fortinet, Inc."
  NSApplication.shared.activate(ignoringOtherApps: true)
  NSApplication.shared.orderFrontStandardAboutPanel(options: [
    .credits: NSAttributedString(
      string: notice,
      attributes: [
        .font: NSFont.systemFont(ofSize: NSFont.smallSystemFontSize),
        .foregroundColor: NSColor.secondaryLabelColor,
      ])
  ])
}
