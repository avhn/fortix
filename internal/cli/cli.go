// Package cli implements testable command dispatch without launching VPN processes.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/avhn/fortix/internal/buildinfo"
	"github.com/avhn/fortix/internal/profile"
)

// Run handles args, writes results to stdout and diagnostics to stderr, and returns
// 0 for success, 1 for invalid input or I/O failure, and 2 for incorrect usage.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return usage(stderr)
	}
	switch args[0] {
	case "version":
		if _, code := parse("version", args[1:], 0, stderr); code != 0 {
			return code
		}
		if _, err := fmt.Fprintln(stdout, buildinfo.Version); err != nil {
			return diagnostic(stderr, err)
		}
		return 0
	case "profile":
		if len(args) < 2 || args[1] != "validate" {
			return usage(stderr)
		}
		files, code := parse("profile validate", args[2:], 1, stderr)
		if code != 0 {
			return code
		}
		return validateFile(files[0], stdout, stderr)
	default:
		return usage(stderr)
	}
}

// parse uses a non-exiting standard flag set and requires exactly count positional arguments.
// It returns arguments and status 0, or status 2 after flag or usage diagnostics.
func parse(name string, args []string, count int, stderr io.Writer) ([]string, int) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() { _ = usage(stderr) }
	if err := flags.Parse(args); err != nil {
		return nil, 2
	}
	if flags.NArg() != count {
		return nil, usage(stderr)
	}
	return flags.Args(), 0
}

// validateFile opens path, decodes its profile, and writes the validated ID to stdout.
// Read, close, validation, and output failures produce diagnostics and status 1.
func validateFile(path string, stdout, stderr io.Writer) int {
	file, err := os.Open(path)
	if err != nil {
		return diagnostic(stderr, err)
	}
	p, decodeErr := profile.Decode(file)
	if err := errors.Join(decodeErr, file.Close()); err != nil {
		return diagnostic(stderr, err)
	}
	if _, err := fmt.Fprintf(stdout, "ok: %s\n", p.ID); err != nil {
		return diagnostic(stderr, err)
	}
	return 0
}

// usage writes the supported syntax to stderr and returns usage status 2.
// Output failures cannot change the usage status because no command was executed.
func usage(stderr io.Writer) int {
	_, _ = fmt.Fprintln(stderr, "usage: fortix version | fortix profile validate <file>")
	return 2
}

// diagnostic attempts to print err and returns failure status 1 even if stderr fails.
// It does not include profile contents, credentials, or executable options.
func diagnostic(stderr io.Writer, err error) int {
	_, _ = fmt.Fprintln(stderr, err)
	return 1
}
