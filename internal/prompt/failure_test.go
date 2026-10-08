package prompt

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"strings"
	"testing"
)

// exitError simulates a native process status without running a real dialog.
type exitError int

// Error returns a fixed non-secret diagnostic for the fake process failure.
func (e exitError) Error() string { return "synthetic dialog exit" }

// ExitCode returns the scripted native process status for cancellation classification.
func (e exitError) ExitCode() int { return int(e) }

// TestDialogFailures exercises cancellation, missing executables, other failures, and context rejection.
func TestDialogFailures(t *testing.T) {
	for _, tc := range []struct {
		name          string
		failure, want error
	}{
		{"cancel", exitError(1), ErrCancelled},
		{"failed", exitError(2), ErrFailed},
		{"missing", exec.ErrNotFound, ErrUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &fakeRunner{err: tc.failure, output: []byte("test-password")}
			n := Native{Runner: r, platform: "linux", LookPath: func(string) (string, error) { return "/usr/bin/zenity", nil }}
			if got, err := n.Password(context.Background(), "title", "message"); got != "" || !errors.Is(err, tc.want) {
				t.Fatalf("password: %q %v", got, err)
			}
			if got, err := n.Confirm(context.Background(), "title", "message"); got || !errors.Is(err, tc.want) {
				t.Fatalf("confirm: %v %v", got, err)
			}
		})
	}
	r := &fakeRunner{}
	n := Native{Runner: r, platform: "darwin"}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := n.Password(ctx, "title", "message"); !errors.Is(err, context.Canceled) || r.calls != 0 {
		t.Fatal(err)
	}
	r.output = []byte(strings.Repeat("x", maxInput+17))
	if got, err := n.Password(context.Background(), "title", "message"); got != "" || !errors.Is(err, ErrFailed) {
		t.Fatal(err)
	}
}

// failingIO returns a synthetic I/O failure for both reads and writes.
type failingIO struct{}

// Read reports a synthetic reader failure without retaining or echoing input.
func (failingIO) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

// Write reports a synthetic output failure without recording prompt data.
func (failingIO) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

// stalledReader simulates a broken Reader that never makes progress.
type stalledReader struct{}

// Read returns no bytes and no error to exercise the line reader's progress guard.
func (stalledReader) Read([]byte) (int, error) { return 0, nil }

// TestTerminalFailures verifies input/output errors cannot produce a password or consent.
func TestTerminalFailures(t *testing.T) {
	term := Terminal{Output: failingIO{}, Reader: strings.NewReader("test-password\n")}
	if got, err := term.Password(context.Background(), "Password: ", true); got != "" || !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
	if got, err := term.Confirm(context.Background(), "Continue?"); got || !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(err)
	}
	term.Output, term.Reader = io.Discard, failingIO{}
	if got, err := term.Password(context.Background(), "Password: ", true); got != "" || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
	if got, err := term.Confirm(context.Background(), "Continue?"); got || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
	if got, err := readLine(stalledReader{}); got != "" || !errors.Is(err, io.ErrNoProgress) {
		t.Fatal(err)
	}
}
