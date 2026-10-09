import AppKit
import FortixCore
import SwiftUI

/// AppTheme centralizes native semantic styling and ring animation timing.
enum AppTheme {
  /// IconSize follows the desktop tray's twenty-two-point design grid.
  static let iconSize: CGFloat = 22
  /// Frames completes one clockwise rotation in twelve discrete steps.
  static let frames = 12
  /// FrameInterval completes a connecting cycle in exactly one second.
  static let frameInterval = 1.0 / Double(frames)
  /// Spacing separates controls consistently while native forms handle field layout.
  static let spacing: CGFloat = 12
  /// WindowWidth keeps profile details readable without a large utility window.
  static let windowWidth: CGFloat = 740
  /// WindowHeight leaves space for editable network policy and diagnostics.
  static let windowHeight: CGFloat = 620
}

/// RingRenderer ports the tray's geometry to a template image without relying on status colors.
enum RingRenderer {
  /// Frame returns a stable zero under reduced motion or a disabled animation setting.
  static func frame(time: TimeInterval, animate: Bool, reduceMotion: Bool) -> Int {
    guard animate, !reduceMotion, time.isFinite, time >= 0 else { return 0 }
    return Int((time.truncatingRemainder(dividingBy: 1) * Double(AppTheme.frames)).rounded(.down))
  }

  /// Coverage evaluates one sample on the shared ring design grid, with clockwise arc progression.
  static func coverage(x: Double, y: Double, status: AggregateStatus, frame: Int) -> Double {
    let radius = hypot(x, y)
    let ring = radius >= 7 && radius <= 9
    var angle = atan2(y, x) + .pi / 2
    if angle < 0 { angle += 2 * .pi }
    switch status {
    case .connecting:
      guard ring else { return 0 }
      let position = (angle - Double(frame) * 2 * .pi / 12 + 2 * .pi)
        .truncatingRemainder(dividingBy: 2 * .pi)
      return position < .pi / 2 ? 1 : 0.35
    case .connected: return ring || radius <= 5 ? 1 : 0
    case .partial: return ring || (radius <= 5 && x <= 0) ? 1 : 0
    case .attention:
      return hypot(x - 8, y) <= 1.6 || (ring && (x < 0 || abs(y) > 3.5)) ? 1 : 0
    case .notConnected: return ring ? 1 : 0
    }
  }

  /// Cache holds one image per status and frame, so each glyph is rendered only once.
  @MainActor private static var cache: [String: NSImage] = [:]

  /// Image returns the cached glyph for a status and frame, rendering it once on first use.
  @MainActor static func image(status: AggregateStatus, frame: Int) -> NSImage {
    let key = "\(status)-\(frame)"
    if let cached = cache[key] { return cached }
    let image = render(status: status, frame: frame)
    cache[key] = image
    return image
  }

  /// Render samples a forty-four-pixel monochrome glyph for crisp retina template rendering.
  static func render(status: AggregateStatus, frame: Int) -> NSImage {
    let size = 44
    let bitmap = NSBitmapImageRep(
      bitmapDataPlanes: nil, pixelsWide: size, pixelsHigh: size, bitsPerSample: 8,
      samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB,
      bytesPerRow: size * 4, bitsPerPixel: 32)!
    let pixels = bitmap.bitmapData!
    for y in 0..<size {
      for x in 0..<size {
        var alpha = 0.0
        for sy in 0..<4 {
          for sx in 0..<4 {
            alpha += coverage(
              x: (Double(x) + (Double(sx) + 0.5) / 4) / 2 - 11,
              y: (Double(y) + (Double(sy) + 0.5) / 4) / 2 - 11,
              status: status, frame: frame)
          }
        }
        let offset = (y * size + x) * 4
        pixels[offset] = 0
        pixels[offset + 1] = 0
        pixels[offset + 2] = 0
        pixels[offset + 3] = UInt8((alpha * 255 / 16).rounded())
      }
    }
    let image = NSImage(size: NSSize(width: AppTheme.iconSize, height: AppTheme.iconSize))
    image.addRepresentation(bitmap)
    image.isTemplate = true
    return image
  }
}

/// RingIcon animates only a connecting state and responds live to the accessibility motion preference.
struct RingIcon: View {
  /// Status determines shape independently of any display tint.
  let status: AggregateStatus
  /// Label supplies the equivalent textual meaning to VoiceOver.
  let label: String
  /// ReduceMotion disables the repeating timeline rather than hiding status feedback.
  @Environment(\.accessibilityReduceMotion) private var reduceMotion
  /// Animate is persisted as a user-controllable menu icon preference.
  @AppStorage("animateIcon") private var animate = true

  /// Body uses native template tinting for accessible light and dark menu bars.
  var body: some View {
    if status == .connecting && animate && !reduceMotion {
      TimelineView(.periodic(from: .now, by: AppTheme.frameInterval)) { context in
        glyph(
          frame: RingRenderer.frame(
            time: context.date.timeIntervalSinceReferenceDate, animate: true, reduceMotion: false))
      }
    } else {
      glyph(frame: 0)
    }
  }

  /// Glyph applies native template tinting and a textual accessibility label to a single discrete frame.
  /// The image already carries its 22-point size and is not resized here: a resizable, framed
  /// label made AppKit refit the status item on every update, and that layout pass scheduled
  /// the next SwiftUI update, spinning the main thread and freezing the app.
  private func glyph(frame: Int) -> some View {
    Image(nsImage: RingRenderer.image(status: status, frame: frame))
      .accessibilityLabel(label)
  }
}
