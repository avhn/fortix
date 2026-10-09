//go:build darwin || linux

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

// canonicalExecutable resolves the helper's own path when it was started through a
// package-manager symlink such as Homebrew's bin/fortix-helper. macOS reports the
// invoked path, while the installer opens its sources with O_NOFOLLOW, so the
// canonical file (and its sibling CLI) must be named directly.
func canonicalExecutable(path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("resolve helper executable: %w", err)
	}
	return resolved, nil
}

// installationOptions parses only installation flags before any privileged work.
// The CLI source is the sibling of the running helper, or all three sources come
// from its app bundle's Resources/libexec. Explicit users are resolved by install
// before enrollment. Positional arguments and flags for the opposite operation
// fail without filesystem changes; optional backend updates reuse the installer.
func installationOptions(args []string, executable string, diagnostics io.Writer) (install.Options, error) {
	if len(args) == 0 || (args[0] != "install" && args[0] != "uninstall") {
		return install.Options{}, errors.New("unknown installation command")
	}
	flags := flag.NewFlagSet("fortix-helper "+args[0], flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	opts := install.Options{Helper: executable, CLI: filepath.Join(filepath.Dir(executable), "fortix"), Warn: func(message string) { _, _ = fmt.Fprintln(diagnostics, message) }}
	if args[0] == "install" {
		flags.StringVar(&opts.User, "user", "", "existing non-root account to grant helper access, overriding SUDO_USER")
		flags.BoolVar(&opts.AppBundle, "app-bundle", false, "copy executables from this helper's Contents/Resources/libexec")
		flags.StringVar(&opts.OpenFortiVPN, "openfortivpn", "", "optional macOS openfortivpn binary to vendor with its libraries")
		flags.BoolVar(&opts.AddOpenFortiVPN, "add-openfortivpn", false, "add or update only --openfortivpn in an existing install without restarting the helper")
	} else {
		flags.BoolVar(&opts.Purge, "purge", false, "also remove stored profiles")
	}
	if err := flags.Parse(args[1:]); err != nil {
		return install.Options{}, err
	}
	if flags.NArg() != 0 {
		return install.Options{}, errors.New("unexpected installation arguments")
	}
	var emptyUser bool
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "user" && opts.User == "" {
			emptyUser = true
		}
	})
	if emptyUser {
		return install.Options{}, errors.New("--user requires an account name")
	}
	if opts.AddOpenFortiVPN && (opts.OpenFortiVPN == "" || opts.AppBundle || opts.User != "") {
		return install.Options{}, errors.New("--add-openfortivpn requires --openfortivpn and cannot combine with --app-bundle or --user")
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
