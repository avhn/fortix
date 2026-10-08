// Package helpercmd also dispatches explicit installation and removal commands.
package helpercmd

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"

	"github.com/avhn/fortix/internal/install"
)

// installationOptions parses only installation flags before any privileged work.
// The CLI source is the sibling of the running helper; positional arguments and
// flags belonging to the opposite operation fail without filesystem changes.
func installationOptions(args []string, executable string, diagnostics io.Writer) (install.Options, error) {
	if len(args) == 0 || (args[0] != "install" && args[0] != "uninstall") {
		return install.Options{}, errors.New("unknown installation command")
	}
	flags := flag.NewFlagSet("fortix-helper "+args[0], flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	opts := install.Options{Helper: executable, CLI: filepath.Join(filepath.Dir(executable), "fortix"), Warn: func(message string) { _, _ = fmt.Fprintln(diagnostics, message) }}
	if args[0] == "install" {
		flags.StringVar(&opts.OpenFortiVPN, "openfortivpn", "", "macOS openfortivpn binary to vendor with its libraries")
	} else {
		flags.BoolVar(&opts.Purge, "purge", false, "also remove stored profiles")
	}
	if err := flags.Parse(args[1:]); err != nil {
		return install.Options{}, err
	}
	if flags.NArg() != 0 {
		return install.Options{}, errors.New("unexpected installation arguments")
	}
	// Package managers expose binaries through symlinks such as Homebrew's bin/.
	// Resolve the operator's path once so the installer opens the canonical file
	// with O_NOFOLLOW; the vendored copy is verified and re-owned regardless.
	if opts.OpenFortiVPN != "" {
		resolved, err := filepath.EvalSymlinks(opts.OpenFortiVPN)
		if err != nil {
			return install.Options{}, fmt.Errorf("resolve openfortivpn: %w", err)
		}
		opts.OpenFortiVPN = resolved
	}
	return opts, nil
}
