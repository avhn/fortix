package helpercmd

import (
	"errors"
	"flag"
	"io"
	"path/filepath"
	"strings"

	"github.com/avhn/fortix/internal/install"
	"github.com/avhn/fortix/internal/winfs"
)

// canonicalExecutable rejects aliases instead of following untrusted reparse points.
func canonicalExecutable(path string) (string, error) {
	if !winfs.ValidPath(path) {
		return "", errors.New("helper executable must have a canonical local path")
	}
	return path, nil
}

// installationOptions accepts only Windows enrollment and explicit purge flags before elevation.
func installationOptions(args []string, executable string, diagnostics io.Writer) (install.Options, error) {
	if len(args) == 0 || (args[0] != "install" && args[0] != "uninstall") {
		return install.Options{}, errors.New("unknown installation command")
	}
	for _, arg := range args[1:] {
		name := strings.SplitN(strings.TrimLeft(arg, "-"), "=", 2)[0]
		if strings.HasPrefix(arg, "-") && (name == "pinentry" || name == "app-bundle" || name == "openfortivpn" || name == "add-openfortivpn" || name == "dev-root") {
			return install.Options{}, errors.New("pinentry, app bundles, openfortivpn and development modes are not available on Windows")
		}
	}
	executable, err := canonicalExecutable(executable)
	if err != nil {
		return install.Options{}, err
	}
	opts := install.Options{Helper: executable, CLI: filepath.Join(filepath.Dir(executable), "fortix.exe")}
	flags := flag.NewFlagSet("fortix-helper "+args[0], flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	if args[0] == "install" {
		flags.StringVar(&opts.User, "user", "", "existing user account to grant helper access")
	} else {
		flags.BoolVar(&opts.Purge, "purge", false, "also remove stored profiles and the fortix group")
	}
	if err := flags.Parse(args[1:]); err != nil {
		return install.Options{}, err
	}
	if flags.NArg() != 0 {
		return install.Options{}, errors.New("unexpected installation arguments")
	}
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "user" && opts.User == "" {
			err = errors.New("--user requires an account name")
		}
	})
	return opts, err
}
