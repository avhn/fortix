//go:build darwin || linux

// Package tray tests desktop command parsing without native or privileged side effects.
package tray

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/avhn/fortix/internal/prompt"
)

// TestAutostartAction verifies exact arity and command spelling before filesystem work.
func TestAutostartAction(t *testing.T) {
	cases := []struct {
		name   string
		args   []string
		action string
		bad    bool
	}{
		{name: "tray"},
		{name: "enable", args: []string{"autostart", "enable"}, action: "enable"},
		{name: "disable", args: []string{"autostart", "disable"}, action: "disable"},
		{name: "missing action", args: []string{"autostart"}, bad: true},
		{name: "unknown action", args: []string{"autostart", "start"}, bad: true},
		{name: "extra", args: []string{"autostart", "enable", "extra"}, bad: true},
		{name: "unknown command", args: []string{"other", "enable"}, bad: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			action, err := autostartAction(tc.args)
			if (err != nil) != tc.bad || action != tc.action {
				t.Fatalf("action = %q, error = %v", action, err)
			}
		})
	}
	if openLog(context.Background(), t.TempDir(), "../etc/passwd", nil, prompt.ExecRunner{}) == nil {
		t.Fatal("unsafe log ID accepted")
	}
}

// FuzzAutostartAction exercises the pure grammar without starting a desktop or
// writing login configuration. Successful actions must use the exact vocabulary.
func FuzzAutostartAction(f *testing.F) {
	f.Add("autostart\x00enable")
	f.Add("autostart\x00disable")
	f.Add("")
	f.Fuzz(func(t *testing.T, input string) {
		args := strings.Split(input, "\x00")
		action, err := autostartAction(args)
		if err == nil && action != "enable" && action != "disable" {
			t.Fatalf("unexpected action %q", action)
		}
	})
}

// logRunner reads a user snapshot as the viewer would, without launching a GUI.
// It captures mode, contents and arguments and can inject a sanitized process failure.
type logRunner struct {
	path string
	data string
	mode os.FileMode
	fail bool
}

// Run verifies a deadline and a single literal file argument, then reads the snapshot.
// Failures return errors to the opener; no privileged log directory is accessible.
func (r *logRunner) Run(ctx context.Context, _ string, args []string, _ io.Reader) ([]byte, error) {
	if _, ok := ctx.Deadline(); !ok || len(args) != 1 {
		return nil, errors.New("invalid viewer invocation")
	}
	r.path = args[0]
	info, err := os.Stat(r.path)
	if err != nil {
		return nil, err
	}
	r.mode = info.Mode().Perm()
	data, err := os.ReadFile(r.path)
	r.data = string(data)
	if r.fail {
		return nil, errors.New("viewer unavailable")
	}
	return nil, err
}

// TestLogSnapshot verifies private files, literal names, bounds, and failure cleanup.
func TestLogSnapshot(t *testing.T) {
	for _, tc := range []struct {
		name          string
		fail, missing bool
	}{
		{name: "success"}, {name: "viewer failure", fail: true}, {name: "missing directory", missing: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.missing {
				dir = filepath.Join(dir, "missing")
			}
			runner := &logRunner{fail: tc.fail}
			err := openLog(context.Background(), dir, "work", []string{"redacted line", "next line"}, runner)
			if (err != nil) != (tc.fail || tc.missing) {
				t.Fatalf("error = %v", err)
			}
			if tc.missing {
				return
			}
			if runner.mode != 0600 || runner.data != "redacted line\nnext line\n" || filepath.Dir(runner.path) != dir {
				t.Fatal("snapshot was not a private user-readable copy")
			}
			if tc.fail {
				if _, err := os.Stat(runner.path); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("failed snapshot retained")
				}
			}
		})
	}
	if openLog(context.Background(), t.TempDir(), "work", make([]string, 501), &logRunner{}) == nil {
		t.Fatal("oversized snapshot accepted")
	}
}
