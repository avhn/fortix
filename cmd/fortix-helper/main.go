// Command fortix-helper runs the privileged local service or its private pinentry
// responder. All command parsing and lifecycle implementation live in internal packages.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/avhn/fortix/internal/helpercmd"
)

// main wires process streams and termination signals to the helper dispatcher.
// Startup failures are printed without request data and produce a nonzero exit code.
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	if err := helpercmd.Run(ctx, os.Args, os.Stdin, os.Stdout, os.Stderr); err != nil {
		stop()
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	stop()
}
