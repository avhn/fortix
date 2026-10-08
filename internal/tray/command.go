// Package tray also provides unprivileged desktop command dispatch.
package tray

import (
	"context"
	"errors"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/avhn/fortix/internal/client"
	"github.com/avhn/fortix/internal/paths"
	"github.com/avhn/fortix/internal/profile"
	"github.com/avhn/fortix/internal/prompt"
	"github.com/avhn/fortix/internal/secrets"
	"github.com/avhn/fortix/internal/tray/autostart"
	"github.com/avhn/fortix/internal/userconfig"
)

// Command runs the native tray or enables/disables next-login autostart. It refuses
// root execution and malformed arguments before reading preferences or starting UI.
// Diagnostics are sanitized; installation and networking are never performed here.
func Command(ctx context.Context, args []string, diagnostics io.Writer) error {
	if os.Geteuid() == 0 {
		return errors.New("fortix-tray must not run as root")
	}
	action, err := autostartAction(args)
	if err != nil {
		return err
	}
	p, err := paths.Resolve(paths.Override{})
	if err != nil {
		return err
	}
	if action != "" {
		if action == "disable" {
			return autostart.Disable(ctx, runtime.GOOS, p)
		}
		executable, err := os.Executable()
		if err != nil {
			return err
		}
		return autostart.Enable(ctx, runtime.GOOS, p, executable)
	}
	cfg, err := userconfig.Load(ctx, p)
	if err != nil {
		return err
	}
	// Keep viewer snapshots private and available until the tray exits.
	cache, err := os.MkdirTemp("", "fortix-logs-")
	if err != nil {
		return errors.New("private log directory could not be created")
	}
	defer func() { _ = os.RemoveAll(cache) }()
	native := prompt.Native{}
	options := Options{Paths: p, Preferences: cfg, Store: secrets.Keyring{}, Dialog: native, Notify: native.Notify,
		Dial: func(ctx context.Context) (Connection, error) {
			return client.Dial(ctx, client.Options{DiscardLogs: true})
		},
		OpenLog: func(ctx context.Context, id string, lines []string) error {
			return openLog(ctx, cache, id, lines, prompt.ExecRunner{})
		},
		Report: func(message string) { _, _ = io.WriteString(diagnostics, message+"\n") },
	}
	return runDesktop(ctx, options)
}

// autostartAction parses the exact desktop command grammar without performing I/O.
// An empty action selects the tray; malformed or extra arguments return usage errors.
func autostartAction(args []string) (string, error) {
	if len(args) == 0 {
		return "", nil
	}
	if len(args) != 2 || args[0] != "autostart" || (args[1] != "enable" && args[1] != "disable") {
		return "", errors.New("usage: fortix-tray [autostart enable|disable]")
	}
	return args[1], nil
}

// openLog writes a bounded, helper-redacted snapshot to a private user directory
// and opens it with the platform viewer. The caller owns directory cleanup after
// viewers have been launched; invalid IDs, I/O and process failures return errors.
func openLog(ctx context.Context, dir, id string, lines []string, runner prompt.Runner) error {
	if !profile.ValidID(id) || len(lines) > 500 {
		return errors.New("invalid log snapshot")
	}
	file, err := os.CreateTemp(dir, id+"-*.log")
	if err != nil {
		return errors.New("profile log snapshot could not be created")
	}
	name := file.Name()
	_, writeErr := io.WriteString(file, strings.Join(lines, "\n")+"\n")
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		_ = os.Remove(name)
		return errors.New("profile log snapshot could not be written")
	}
	program := "xdg-open"
	if runtime.GOOS == "darwin" {
		program = "/usr/bin/open"
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, err := runner.Run(ctx, program, []string{name}, strings.NewReader("")); err != nil {
		_ = os.Remove(name)
		return errors.New("profile log could not be opened")
	}
	return nil
}
