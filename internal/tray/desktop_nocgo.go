//go:build darwin && !cgo

// Package tray remains testable without macOS native GUI linking.
package tray

import (
	"context"
	"errors"
)

// runDesktop rejects a macOS desktop launch when compiled without native support.
// Headless controller tests and autostart commands remain available without cgo.
func runDesktop(context.Context, Options) error {
	return errors.New("the macOS tray requires a native build with CGO_ENABLED=1")
}
