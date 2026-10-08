// Package buildinfo exposes release metadata without requiring runtime discovery.
package buildinfo

// Version is the printable release identifier, defaulting to dev for local builds.
// Set it at link time with -ldflags '-X github.com/avhn/fortix/internal/buildinfo.Version=...'.
var Version = "dev"
