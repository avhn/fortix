// Package cli implements testable command dispatch without launching VPN processes.
package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/avhn/fortix/internal/buildinfo"
	"github.com/avhn/fortix/internal/profile"
)

// Run handles args, writes results to stdout and diagnostics to stderr, and returns
// 0 for success, 1 for invalid input or I/O failure, and 2 for incorrect usage.
func Run(args []string, stdout, stderr io.Writer) int {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return RunContext(ctx, args, stdout, stderr, Options{})
}

// runLocal handles offline version and validation commands without contacting the helper.
// Incorrect flags return 2; file and output failures return 1.
func runLocal(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return usage(stderr)
	}
	switch args[0] {
	case "version":
		if _, code := parse("version", args[1:], 0, stdout, stderr); code != 0 {
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
		files, code := parse("profile validate", args[2:], 1, stdout, stderr)
		if code != 0 {
			return code
		}
		return validateFile(files[0], stdout, stderr)
	default:
		return usage(stderr)
	}
}

// parse uses a non-exiting standard flag set and requires exactly count positional arguments.
// It returns arguments and status 0, status -1 for help, or status 2 for incorrect usage.
func parse(name string, args []string, count int, stdout, stderr io.Writer) ([]string, int) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	var output bytes.Buffer
	flags.SetOutput(&output)
	flags.Usage = func() {
		operand := ""
		if count == 1 {
			operand = " <file>"
		}
		_, _ = fmt.Fprintf(&output, "usage: fortix %s%s\n", name, operand)
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = io.Copy(stdout, &output)
			return nil, -1
		}
		_, _ = io.Copy(stderr, &output)
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
	_, _ = fmt.Fprintln(stderr, "usage: fortix <command>\n  version\n  profile validate|list|show|add|rm|remove\n  import forticlient\n  password set|clear <id>\n  up <id>...|--all\n  down <id>...|--all\n  status [--json]\n  logs <id>\n  trust <id>")
	return 2
}

// diagnostic attempts to print err and returns failure status 1 even if stderr fails.
// It does not include profile contents, credentials, or executable options.
func diagnostic(stderr io.Writer, err error) int {
	_, _ = fmt.Fprintln(stderr, err)
	return 1
}
