// Command fortix-helper hosts the Windows service and explicit elevated installation commands.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/avhn/fortix/internal/helpercmd"
)

// main leaves SCM stop handling to helpercmd and reports failures without secret data.
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := helpercmd.Run(ctx, os.Args, os.Stdin, os.Stdout, os.Stderr); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
