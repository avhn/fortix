//go:build darwin || linux

package install

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// optionalBackendSource creates inert Mach-O data with a non-system dependency.
// Recording runners capture rewriting and signing without executing the data.
func optionalBackendSource(t *testing.T, dir string) string {
	t.Helper()
	executable := filepath.Join(dir, "optional-openfortivpn")
	for path, data := range map[string][]byte{
		executable:                              machoFixture([]string{"@rpath/liboptional.dylib"}, []string{"@executable_path"}),
		filepath.Join(dir, "liboptional.dylib"): machoFixture(nil, nil),
	} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return executable
}

// TestAddOptionalBackend installs native-only support, then adds openfortivpn
// without core sources or a service restart, preserving profiles and all core files.
// Signing failure retains the previous backend, and a later native reinstall keeps it.
func TestAddOptionalBackend(t *testing.T) {
	o, runner := bundleOptions(t)
	if err := Install(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	p := resolvedPaths(t, o)
	profile := filepath.Join(p.Profiles, "work.json")
	if err := os.WriteFile(profile, []byte("unchanged profile"), 0640); err != nil {
		t.Fatal(err)
	}
	before := map[string][]byte{}
	for _, path := range []string{p.ServiceFile, filepath.Join(p.BinaryDir, "fortix-helper"), filepath.Join(p.BinaryDir, "fortix"), p.Pinentry, profile} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		before[path] = data
	}
	runner.calls = nil
	o.AppBundle, o.AddOpenFortiVPN = false, true
	o.Helper, o.CLI = "", ""
	o.OpenFortiVPN = optionalBackendSource(t, t.TempDir())
	if err := Install(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	var rewrites, signatures, verifies int
	for _, call := range runner.calls {
		switch call[0] {
		case "/usr/bin/install_name_tool":
			if call[1] == "-change" {
				rewrites++
				if call[2] != "@rpath/liboptional.dylib" || call[3] != "@loader_path/liboptional.dylib" {
					t.Fatalf("rewrite = %v", call)
				}
			}
		case "/usr/bin/codesign":
			switch call[1] {
			case "--force":
				signatures++
			case "--verify":
				verifies++
			}
		default:
			t.Fatalf("unexpected service or enrollment command: %v", call)
		}
	}
	if rewrites != 1 || signatures != 2 || verifies != 2 {
		t.Fatalf("rewrites=%d signatures=%d verifies=%d", rewrites, signatures, verifies)
	}
	for path, want := range before {
		data, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(data, want) {
			t.Fatalf("changed core file %s = %q, %v", path, data, err)
		}
	}
	backend := filepath.Join(p.VPNDir, "openfortivpn")
	previous, err := os.ReadFile(backend)
	if err != nil {
		t.Fatal(err)
	}
	runner.fail = "codesign --force"
	if err := Install(context.Background(), o); err == nil || !strings.Contains(err.Error(), "injected diagnostic") {
		t.Fatalf("signing failure = %v", err)
	}
	data, err := os.ReadFile(backend)
	if err != nil || !bytes.Equal(data, previous) {
		t.Fatalf("changed previous backend after failed signing: %v", err)
	}
	runner.fail = ""
	o.AddOpenFortiVPN, o.OpenFortiVPN = false, ""
	o.Helper, o.CLI = filepath.Join(p.BinaryDir, "fortix-helper"), filepath.Join(p.BinaryDir, "fortix")
	if err := Install(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(backend)
	if err != nil || !bytes.Equal(data, previous) {
		t.Fatalf("native reinstall removed optional backend: %v", err)
	}
}

// TestAddOptionalBackendFailures rejects absent or unsafe installs, incompatible
// options, malformed source data and cancellation without issuing any commands.
func TestAddOptionalBackendFailures(t *testing.T) {
	for _, name := range []string{"not installed", "missing pinentry", "symlink service", "symlink helper", "no backend source", "invalid backend source", "app bundle", "explicit user", "linux", "canceled"} {
		t.Run(name, func(t *testing.T) {
			o, runner := testOptions(t, "darwin")
			p := resolvedPaths(t, o)
			if name != "not installed" {
				if err := Install(context.Background(), o); err != nil {
					t.Fatal(err)
				}
			}
			runner.calls = nil
			o.AddOpenFortiVPN = true
			o.OpenFortiVPN = optionalBackendSource(t, t.TempDir())
			ctx := context.Background()
			switch name {
			case "missing pinentry":
				if err := os.Remove(p.Pinentry); err != nil {
					t.Fatal(err)
				}
			case "symlink service", "symlink helper":
				path := p.ServiceFile
				if name == "symlink helper" {
					path = filepath.Join(p.BinaryDir, "fortix-helper")
				}
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(o.Helper, path); err != nil {
					t.Fatal(err)
				}
			case "no backend source":
				o.OpenFortiVPN = ""
			case "invalid backend source":
				o.OpenFortiVPN = o.Helper
			case "app bundle":
				o.AppBundle = true
			case "explicit user":
				o.User = "selected"
				o.UserID = func(string) (int, error) { return 501, nil }
			case "linux":
				o.Platform = "linux"
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if err := Install(ctx, o); err == nil {
				t.Fatal("accepted invalid optional backend update")
			}
			if len(runner.calls) != 0 {
				t.Fatalf("commands before validation: %v", runner.calls)
			}
			if _, err := os.Stat(p.VPNDir); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("published backend before validation: %v", err)
			}
		})
	}
}
