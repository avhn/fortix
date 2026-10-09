package helpercmd

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
)

// TestWindowsInstallationOptions retains grammar and opposite-operation rejection without elevation.
func TestWindowsInstallationOptions(t *testing.T) {
	executable := `C:\release\fortix-helper.exe`
	for _, args := range [][]string{{"install"}, {"install", "--user", "example-user"}, {"uninstall"}, {"uninstall", "--purge"}} {
		opts, err := installationOptions(args, executable, io.Discard)
		if err != nil || opts.Helper != executable || opts.CLI != `C:\release\fortix.exe` {
			t.Fatalf("%v: %+v %v", args, opts, err)
		}
	}
	for _, args := range [][]string{nil, {"status"}, {"install", "--user="}, {"install", "--purge"}, {"uninstall", "--user", "example-user"}, {"install", "extra"}, {"install", "--app-bundle"}, {"install", "--openfortivpn", "backend"}, {"install", "--add-openfortivpn"}, {"install", "--dev-root", "root"}} {
		if _, err := installationOptions(args, executable, io.Discard); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}

// TestWindowsInteractiveUsageAndRefusals proves a console invocation cannot start the service loop.
func TestWindowsInteractiveUsageAndRefusals(t *testing.T) {
	var out bytes.Buffer
	if err := Run(context.Background(), []string{"fortix-helper.exe"}, nil, &out, io.Discard); err != nil || !strings.Contains(out.String(), "usage:") {
		t.Fatalf("%v %s", err, &out)
	}
	for _, args := range [][]string{nil, {"fortix-pinentry.exe"}, {"fortix-helper.exe", "serve"}, {"fortix-helper.exe", "--dev-root", "root"}, {"fortix-helper.exe", "status", "extra"}} {
		if Run(context.Background(), args, nil, io.Discard, io.Discard) == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}

// TestStagedUninstallOptions limits the handoff flag to canonical uninstall paths.
func TestStagedUninstallOptions(t *testing.T) {
	original := `C:\Program Files\Fortix\fortix-helper.exe`
	copy := `C:\ProgramData\Fortix\staging\fixture\fortix-helper.exe`
	opts, err := installationOptions([]string{"uninstall", "--purge", "--uninstall-original", original}, copy, io.Discard)
	if err != nil || opts.Original != original || !opts.Purge {
		t.Fatalf("staged options: %+v %v", opts, err)
	}
	for _, args := range [][]string{
		{"install", "--uninstall-original", original},
		{"uninstall", "--uninstall-original="},
		{"uninstall", "--uninstall-original", `C:\unsafe\..\fortix-helper.exe`},
		{"uninstall", "--uninstall-original", `\\server\share\fortix-helper.exe`},
	} {
		if _, err := installationOptions(args, copy, io.Discard); err == nil {
			t.Fatalf("unsafe handoff accepted: %v", args)
		}
	}
}
