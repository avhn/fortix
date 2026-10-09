//go:build darwin || linux

// Command fortix-tray runs the unprivileged desktop controller or configures
// next-login autostart. Connection and UI behavior live in internal packages.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/avhn/fortix/internal/tray"
)

// main wires termination signals and diagnostics without handling any credentials.
// Startup failures produce a nonzero exit status; normal Quit returns successfully.
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	if err := tray.Command(ctx, os.Args[1:], os.Stderr); err != nil {
		stop()
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	stop()
}
