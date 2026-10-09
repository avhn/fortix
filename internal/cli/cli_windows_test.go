// Package cli tests dispatch, usage, file validation, and output failures.
package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/avhn/fortix/internal/buildinfo"
)

// TestRun verifies exit codes and output for all supported commands and usage errors.
// Fixtures use temporary files; no command launches a VPN or requires privileged access.
func TestRun(t *testing.T) {
	dir := t.TempDir()
	invalid := filepath.Join(dir, "invalid.json")
	if err := os.WriteFile(invalid, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	valid := filepath.Join("..", "profile", "testdata", "valid.json")
	tests := []struct {
		name            string
		args            []string
		code            int
		out, diagnostic string
	}{
		{"version", []string{"version"}, 0, buildinfo.Version + "\n", ""},
		{"valid", []string{"profile", "validate", valid}, 0, "ok: work\n", ""},
		{"invalid", []string{"profile", "validate", invalid}, 1, "", "schema_version: must be 1"},
		{"missing file", []string{"profile", "validate", filepath.Join(dir, "missing.json")}, 1, "", "read profile"},
		{"directory", []string{"profile", "validate", dir}, 1, "", "read profile"},
		{"empty", nil, 2, "", "usage:"},
		{"unknown", []string{"connect"}, 2, "", "usage:"},
		{"profile missing subcommand", []string{"profile"}, 2, "", "usage:"},
		{"profile unknown", []string{"profile", "unknown"}, 2, "", "usage:"},
		{"validate no file", []string{"profile", "validate"}, 2, "", "usage:"},
		{"validate extra file", []string{"profile", "validate", valid, valid}, 2, "", "usage:"},
		{"version extra argument", []string{"version", "extra"}, 2, "", "usage:"},
		{"version unknown flag", []string{"version", "-unknown"}, 2, "", "flag provided but not defined"},
		{"validate unknown flag", []string{"profile", "validate", "-unknown"}, 2, "", "flag provided but not defined"},
		{"help", []string{"version", "-h"}, 0, "usage: fortix version\n", ""},
		{"validate flag terminator", []string{"profile", "validate", "--", valid}, 0, "ok: work\n", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := Run(tc.args, &stdout, &stderr); code != tc.code {
				t.Fatalf("status %d, want %d; %s", code, tc.code, stderr.String())
			}
			if stdout.String() != tc.out {
				t.Fatalf("stdout %q, want %q", stdout.String(), tc.out)
			}
			if tc.diagnostic == "" {
				if stderr.Len() != 0 {
					t.Fatalf("unexpected diagnostics: %s", &stderr)
				}
			} else if !strings.Contains(stderr.String(), tc.diagnostic) {
				t.Fatalf("stderr %q, want %q", stderr.String(), tc.diagnostic)
			}
		})
	}
}

// brokenWriter deterministically simulates an output stream that rejects every write.
type brokenWriter struct{}

// Write returns no written bytes and io.ErrClosedPipe regardless of its input.
func (brokenWriter) Write(_ []byte) (int, error) { return 0, io.ErrClosedPipe }

// TestOutputFailures verifies success output errors become status 1, not false success.
// Failed stderr still preserves the appropriate invalid or usage exit code.
func TestOutputFailures(t *testing.T) {
	for _, args := range [][]string{{"version"}, {"profile", "validate", "../profile/testdata/valid.json"}} {
		var stderr bytes.Buffer
		if Run(args, brokenWriter{}, &stderr) != 1 || !strings.Contains(stderr.String(), "closed pipe") {
			t.Fatalf("output failure lost: %s", &stderr)
		}
	}
	if Run(nil, io.Discard, brokenWriter{}) != 2 {
		t.Fatal("usage status changed")
	}
	if Run([]string{"profile", "validate", "missing.json"}, io.Discard, brokenWriter{}) != 1 {
		t.Fatal("failure status changed")
	}
}

// TestVersionOverride verifies Run uses link-time metadata rather than a copied default.
// The temporary value is restored before the test returns, including on failure.
func TestVersionOverride(t *testing.T) {
	original := buildinfo.Version
	t.Cleanup(func() { buildinfo.Version = original })
	buildinfo.Version = "v0.1.0"
	var stdout bytes.Buffer
	if Run([]string{"version"}, &stdout, io.Discard) != 0 || stdout.String() != "v0.1.0\n" {
		t.Fatalf("version override lost: %s", &stdout)
	}
}
