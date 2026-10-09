// Package helpercmd provides helper command parsing without embedding privileged
// lifecycle logic in the executable entry point. Errors contain no credential data.
package helpercmd

import (
	"context"
	"errors"
	"flag"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/avhn/fortix/internal/helper"
	"github.com/avhn/fortix/internal/install"
	"github.com/avhn/fortix/internal/paths"
	"github.com/avhn/fortix/internal/pinentry"
)

// Run dispatches pinentry by executable basename or starts the helper service.
// Development roots are accepted only for non-root callers and contain every path,
// including the pinentry executable, and disable host networking and native device
// allocation. Normal service execution requires root, selects each profile's backend,
// and uses owned route/DNS transactions. External executables are verified only when
// an openfortivpn attempt starts; password-only native service needs neither of them.
func Run(ctx context.Context, argv []string, in io.Reader, out, diagnostics io.Writer) error {
	if len(argv) == 0 {
		return errors.New("missing executable name")
	}
	if filepath.Base(argv[0]) == "fortix-pinentry" {
		config := pinentry.Config{Socket: os.Getenv("FORTIX_PINENTRY_SOCKET"), Token: os.Getenv("FORTIX_ATTEMPT_TOKEN")}
		return pinentry.Run(ctx, config, in, out)
	}
	args := argv[1:]
	if len(args) > 0 {
		switch args[0] {
		case "serve":
			args = args[1:]
		case "install", "uninstall":
			// Installation has separate dispatch so service flags cannot alter system setup.
			executable, err := os.Executable()
			if err != nil {
				return err
			}
			opts, err := installationOptions(args, executable, diagnostics)
			if err != nil {
				return err
			}
			if args[0] == "install" {
				return install.Install(ctx, opts)
			}
			return install.Uninstall(ctx, opts)
		}
	}
	flags := flag.NewFlagSet("fortix-helper", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	root := flags.String("dev-root", "", "isolated non-root directory; provide libexec/fortix-pinentry (helper link/copy) and platform openfortivpn: usr/bin/openfortivpn on Linux, Library/Application Support/fortix/libexec/openfortivpn on macOS")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unknown helper command")
	}
	override := paths.Override{Service: true}
	if *root != "" {
		if os.Geteuid() == 0 {
			return errors.New("--dev-root is forbidden for root")
		}
		if !filepath.IsAbs(*root) || filepath.Clean(*root) != *root || *root == "/" {
			return errors.New("--dev-root must be a clean isolated absolute directory")
		}
		override = paths.Override{RootDir: *root, SkipTrust: true, HelperPath: "/libexec/fortix-helper", HomeDir: "/home/development", ConfigHome: "/config",
			ControlSocket: filepath.Join(*root, "run/fortix.sock"), PinentrySocket: filepath.Join(*root, "run/private/pinentry.sock")}
	} else if os.Geteuid() != 0 {
		return errors.New("helper service requires root or --dev-root")
	}
	p, err := paths.Resolve(override)
	if err != nil {
		return err
	}
	opts := helper.Options{Paths: p, Logger: slog.New(slog.NewJSONHandler(diagnostics, nil))}
	if *root != "" {
		// Development fixtures must never execute host route or DNS commands.
		opts.Network = helper.NoNetwork{}
		// The private development root belongs to this user, never a production group.
		opts.Authorize = func(peer helper.Peer) error {
			if peer.UID == uint32(os.Geteuid()) {
				return nil
			}
			return errors.New("unauthorized development peer")
		}
	}
	server, err := helper.New(opts)
	if err != nil {
		return err
	}
	return server.Serve(ctx)
}
