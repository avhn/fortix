import AppKit
import Foundation

/// BigEndian encodes an ICNS byte count as the format's required four-byte unsigned integer.
func bigEndian(_ value: Int) -> Data {
  var number = UInt32(value).bigEndian
  return withUnsafeBytes(of: &number) { Data($0) }
}

/// IconPNG renders the original ring mark at the requested pixel size using a transparent bitmap.
/// Returns PNG bytes or throws when the graphics context or encoder cannot allocate its output.
func iconPNG(size: Int) throws -> Data {
  guard
    let bitmap = NSBitmapImageRep(
      bitmapDataPlanes: nil, pixelsWide: size, pixelsHigh: size, bitsPerSample: 8,
      samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB,
      bytesPerRow: size * 4, bitsPerPixel: 32),
    let context = NSGraphicsContext(bitmapImageRep: bitmap)
  else { throw CocoaError(.fileWriteUnknown) }
  NSGraphicsContext.saveGraphicsState()
  defer { NSGraphicsContext.restoreGraphicsState() }
  NSGraphicsContext.current = context
  context.cgContext.scaleBy(x: CGFloat(size) / 1024, y: CGFloat(size) / 1024)
  NSColor(srgbRed: 25 / 255, green: 35 / 255, blue: 51 / 255, alpha: 1).setFill()
  NSBezierPath(
    roundedRect: NSRect(x: 32, y: 32, width: 960, height: 960), xRadius: 216, yRadius: 216
  ).fill()
  NSColor.white.setStroke()
  let ring = NSBezierPath(ovalIn: NSRect(x: 202, y: 202, width: 620, height: 620))
  ring.lineWidth = 72
  ring.stroke()
  NSColor.white.setFill()
  NSBezierPath(ovalIn: NSRect(x: 344, y: 344, width: 336, height: 336)).fill()
  guard let data = bitmap.representation(using: .png, properties: [:]) else {
    throw CocoaError(.fileWriteUnknown)
  }
  return data
}

/// WriteIcon assembles the PNG icon representations into one ICNS file at the explicit output path.
/// It never touches application installation, network settings, or an existing executable.
func writeIcon(to output: URL) throws {
  let representations = [
    ("icp4", 16), ("icp5", 32), ("icp6", 64), ("ic07", 128),
    ("ic08", 256), ("ic09", 512), ("ic10", 1024),
  ]
  var elements = Data()
  for (type, size) in representations {
    let png = try iconPNG(size: size)
    elements.append(Data(type.utf8))
    elements.append(bigEndian(png.count + 8))
    elements.append(png)
  }
  var icon = Data("icns".utf8)
  icon.append(bigEndian(elements.count + 8))
  icon.append(elements)
  try icon.write(to: output, options: .atomic)
}

// The explicit output argument keeps generation separate from the process's current directory.
guard CommandLine.arguments.count == 2 else {
  fputs("usage: generate-icon output.icns\n", stderr)
  exit(2)
}
do { try writeIcon(to: URL(fileURLWithPath: CommandLine.arguments[1])) } catch {
  fputs("could not generate icon\n", stderr)
  exit(1)
}
