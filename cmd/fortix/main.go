// Package main wires the fortix CLI to process arguments, output streams, and exit status.
package main

import (
	"os"

	"github.com/avhn/fortix/internal/cli"
)

// main delegates command handling and exits with success, invalid-input, or usage status.
// It contains no profile or VPN logic; diagnostics are written by cli.Run.
func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
