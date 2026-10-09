//go:build darwin || linux

// Package helpercmd tests installation dispatch without invoking privileged operations.
package helpercmd

import (
	"bytes"
	"io"
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
		{name: "empty user", args: []string{"install", "--user="}, bad: true},
		{name: "missing user", args: []string{"install", "--user"}, bad: true},
		{name: "user on uninstall", args: []string{"uninstall", "--user", "jane"}, bad: true},
		{name: "bundle on uninstall", args: []string{"uninstall", "--app-bundle"}, bad: true},
		{name: "add without source", args: []string{"install", "--add-openfortivpn"}, bad: true},
		{name: "add and bundle", args: []string{"install", "--add-openfortivpn", "--app-bundle", "--openfortivpn", "/tmp/source"}, bad: true},
		{name: "add and user", args: []string{"install", "--add-openfortivpn", "--user", "jane", "--openfortivpn", "/tmp/source"}, bad: true},
		{name: "add on uninstall", args: []string{"uninstall", "--add-openfortivpn"}, bad: true},
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

// TestInstallationOptionsAppBundle carries the explicit account and bundle mode
// from a bundled executable without resolving users or executing source programs.
func TestInstallationOptionsAppBundle(t *testing.T) {
	helper := "/Applications/Fortix.app/Contents/Resources/libexec/fortix-helper"
	var diagnostics bytes.Buffer
	opts, err := installationOptions([]string{"install", "--app-bundle", "--user", "selected.user"}, helper, &diagnostics)
	if err != nil || !opts.AppBundle || opts.User != "selected.user" || opts.Helper != helper || opts.OpenFortiVPN != "" {
		t.Fatalf("app bundle options = %+v, %v", opts, err)
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
	for _, add := range []bool{false, true} {
		args := []string{"install", "--openfortivpn", link}
		if add {
			args = append(args, "--add-openfortivpn")
		}
		opts, err := installationOptions(args, "/tmp/bin/fortix-helper", &diagnostics)
		if err != nil {
			t.Fatal(err)
		}
		if opts.OpenFortiVPN != want || opts.AddOpenFortiVPN != add {
			t.Fatalf("openfortivpn options = %+v", opts)
		}
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

// TestCanonicalExecutableFollowsPackageLink mirrors a Homebrew layout: the helper
// runs through bin/fortix-helper, and installation must name the Cellar files so
// the no-follow source opens succeed and the CLI sibling is the packaged one.
func TestCanonicalExecutableFollowsPackageLink(t *testing.T) {
	dir := t.TempDir()
	cellar := filepath.Join(dir, "Cellar", "fortix", "0.2.0", "bin")
	if err := os.MkdirAll(cellar, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"fortix-helper", "fortix"} {
		if err := os.WriteFile(filepath.Join(cellar, name), nil, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(bin, "fortix-helper")
	if err := os.Symlink(filepath.Join("..", "Cellar", "fortix", "0.2.0", "bin", "fortix-helper"), link); err != nil {
		t.Fatal(err)
	}
	executable, err := canonicalExecutable(link)
	if err != nil {
		t.Fatal(err)
	}
	opts, err := installationOptions([]string{"install"}, executable, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(cellar)
	if err != nil {
		t.Fatal(err)
	}
	if opts.Helper != filepath.Join(want, "fortix-helper") || opts.CLI != filepath.Join(want, "fortix") {
		t.Fatalf("helper %q, cli %q", opts.Helper, opts.CLI)
	}
	if _, err := canonicalExecutable(filepath.Join(bin, "missing")); err == nil {
		t.Fatal("missing executable resolved")
	}
}
