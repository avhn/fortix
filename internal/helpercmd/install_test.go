// Package helpercmd tests installation dispatch without invoking privileged operations.
package helpercmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestInstallationOptions verifies operation-specific flags and sibling binary
// selection without invoking root operations or touching system directories.
func TestInstallationOptions(t *testing.T) {
	cases := []struct {
		name   string
		args   []string
		purge  bool
		source string
		bad    bool
	}{
		{name: "install", args: []string{"install"}},
		{name: "vendor missing", args: []string{"install", "--openfortivpn", "/nonexistent/openfortivpn"}, bad: true},
		{name: "uninstall", args: []string{"uninstall"}},
		{name: "purge", args: []string{"uninstall", "--purge"}, purge: true},
		{name: "purge on install", args: []string{"install", "--purge"}, bad: true},
		{name: "vendor on uninstall", args: []string{"uninstall", "--openfortivpn", "/tmp/openfortivpn"}, bad: true},
		{name: "positional", args: []string{"install", "extra"}, bad: true},
		{name: "missing path", args: []string{"install", "--openfortivpn"}, bad: true},
		{name: "service flag", args: []string{"install", "--dev-root", "/tmp/fortix"}, bad: true},
		{name: "unknown", args: []string{"other"}, bad: true},
		{name: "empty", bad: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var diagnostics bytes.Buffer
			opts, err := installationOptions(tc.args, "/tmp/bin/fortix-helper", &diagnostics)
			if (err != nil) != tc.bad {
				t.Fatalf("error = %v, bad = %v", err, tc.bad)
			}
			if tc.bad {
				return
			}
			if opts.Helper != "/tmp/bin/fortix-helper" || opts.CLI != "/tmp/bin/fortix" || opts.Purge != tc.purge || opts.OpenFortiVPN != tc.source {
				t.Fatalf("incorrect options: %+v", opts)
			}
			opts.Warn("warning")
			if diagnostics.String() != "warning\n" {
				t.Fatalf("warning output = %q", diagnostics.String())
			}
		})
	}
}

// TestInstallationOptionsResolvesSymlink verifies that a package-manager symlink
// such as Homebrew's bin/openfortivpn is replaced by its canonical target, which
// the installer then opens without following links.
func TestInstallationOptionsResolvesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "Cellar", "openfortivpn")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "openfortivpn")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatal(err)
	}
	var diagnostics bytes.Buffer
	opts, err := installationOptions([]string{"install", "--openfortivpn", link}, "/tmp/bin/fortix-helper", &diagnostics)
	if err != nil {
		t.Fatal(err)
	}
	if opts.OpenFortiVPN != want {
		t.Fatalf("openfortivpn = %q, want %q", opts.OpenFortiVPN, want)
	}
}

// FuzzInstallationOptions ensures arbitrary argument strings cannot panic or
// escape operation-specific flag parsing. No fuzz input invokes the installer.
func FuzzInstallationOptions(f *testing.F) {
	f.Add("install", "--openfortivpn", "/tmp/openfortivpn")
	f.Add("uninstall", "--purge", "")
	f.Fuzz(func(t *testing.T, operation, flag, value string) {
		args := []string{operation, flag}
		if value != "" {
			args = append(args, value)
		}
		var output bytes.Buffer
		_, _ = installationOptions(args, "/tmp/bin/fortix-helper", &output)
	})
}
