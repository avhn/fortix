// swift-tools-version: 5.9
import PackageDescription

/// The package separates testable user-privilege services from the application entry point.
let package = Package(
  name: "Fortix",
  platforms: [.macOS(.v13)],
  products: [
    .library(name: "FortixCore", targets: ["FortixCore"]),
    .executable(name: "FortixApp", targets: ["FortixApp"]),
  ],
  targets: [
    .target(name: "FortixCore", linkerSettings: [.linkedFramework("Security")]),
    .executableTarget(name: "FortixApp", dependencies: ["FortixCore"]),
    .testTarget(name: "FortixCoreTests", dependencies: ["FortixCore"]),
    .testTarget(name: "FortixAppTests", dependencies: ["FortixApp", "FortixCore"]),
  ]
)
