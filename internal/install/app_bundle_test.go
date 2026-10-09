//go:build darwin || linux

package install

import (
	"context"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// bundleOptions creates inert app executables under the supported libexec layout.
// Privileged commands and ownership changes remain injected by testOptions.
func bundleOptions(t *testing.T) (Options, *recordingRunner) {
	t.Helper()
	o, runner := testOptions(t, "darwin")
	libexec := filepath.Join(filepath.Dir(o.Helper), "Fortix Test.app", "Contents", "Resources", "libexec")
	if err := os.MkdirAll(libexec, 0755); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{"fortix-helper": "bundled helper", "fortix": "bundled CLI", "fortix-pinentry": "bundled pinentry"} {
		if err := os.WriteFile(filepath.Join(libexec, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	o.Helper, o.CLI, o.AppBundle = filepath.Join(libexec, "fortix-helper"), "", true
	return o, runner
}

// TestAppBundleInstall checks native-only installation copies all three sources,
// requests root ownership and uses only installed paths in service configuration.
// Source files remain unchanged, and uninstall preserves profiles unless purged.
func TestAppBundleInstall(t *testing.T) {
	for _, purge := range []bool{false, true} {
		t.Run(map[bool]string{false: "preserve", true: "purge"}[purge], func(t *testing.T) {
			o, runner := bundleOptions(t)
			o.Purge = purge
			p := resolvedPaths(t, o)
			var owned []string
			o.Chown = func(path string, uid, gid int) error {
				if uid == 0 && gid == 0 {
					owned = append(owned, path)
				}
				return nil
			}
			if err := Install(context.Background(), o); err != nil {
				t.Fatal(err)
			}
			for name, content := range map[string]string{"fortix-helper": "bundled helper", "fortix": "bundled CLI", "fortix-pinentry": "bundled pinentry"} {
				installed := filepath.Join(p.BinaryDir, name)
				data, err := os.ReadFile(installed)
				if err != nil || string(data) != content {
					t.Fatalf("installed %s = %q, %v", name, data, err)
				}
				info, err := os.Stat(installed)
				if err != nil || info.Mode().Perm() != 0755 {
					t.Fatalf("installed mode %s = %v, %v", name, info, err)
				}
				found := false
				for _, path := range owned {
					if filepath.Base(path) == name {
						found = true
					}
				}
				if !found {
					t.Fatalf("no root ownership request for %s", name)
				}
				original, err := os.ReadFile(filepath.Join(filepath.Dir(o.Helper), name))
				if err != nil || string(original) != content {
					t.Fatalf("changed bundled source %s: %q, %v", name, original, err)
				}
			}
			service, err := os.ReadFile(p.ServiceFile)
			if err != nil || strings.Contains(string(service), ".app/") || !strings.Contains(string(service), p.BinaryDir) {
				t.Fatalf("service paths = %q, %v", service, err)
			}
			if _, err := os.Stat(p.VPNDir); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("native-only install created backend directory: %v", err)
			}
			for _, call := range runner.calls {
				if strings.Contains(strings.Join(call, " "), ".app/") || call[0] == "/usr/bin/codesign" || call[0] == "/usr/bin/install_name_tool" {
					t.Fatalf("executed bundle or optional backend command: %v", call)
				}
			}
			profile := filepath.Join(p.Profiles, "work.json")
			if err := os.WriteFile(profile, []byte("retained profile"), 0640); err != nil {
				t.Fatal(err)
			}
			if err := Uninstall(context.Background(), o); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(profile)
			if purge && !errors.Is(err, os.ErrNotExist) || !purge && (err != nil || string(data) != "retained profile") {
				t.Fatalf("profile after uninstall = %q, %v", data, err)
			}
		})
	}
}

// TestAppBundleInvalidSources rejects incomplete bundles, final-component symlinks
// and unsupported layouts before any account command or destination creation.
func TestAppBundleInvalidSources(t *testing.T) {
	for _, name := range []string{"missing CLI", "missing pinentry", "symlink pinentry", "directory pinentry", "wrong layout", "linux"} {
		t.Run(name, func(t *testing.T) {
			o, runner := bundleOptions(t)
			pinentry := filepath.Join(filepath.Dir(o.Helper), "fortix-pinentry")
			switch name {
			case "missing CLI":
				if err := os.Remove(filepath.Join(filepath.Dir(o.Helper), "fortix")); err != nil {
					t.Fatal(err)
				}
			case "missing pinentry", "symlink pinentry", "directory pinentry":
				if err := os.Remove(pinentry); err != nil {
					t.Fatal(err)
				}
				switch name {
				case "symlink pinentry":
					if err := os.Symlink(o.Helper, pinentry); err != nil {
						t.Fatal(err)
					}
				case "directory pinentry":
					if err := os.Mkdir(pinentry, 0755); err != nil {
						t.Fatal(err)
					}
				}
			case "wrong layout":
				o.Helper = filepath.Join(filepath.Dir(o.Helper), "..", "bin", "fortix-helper")
			case "linux":
				o.Platform = "linux"
			}
			if err := Install(context.Background(), o); err == nil {
				t.Fatal("accepted invalid bundle")
			}
			if len(runner.calls) != 0 {
				t.Fatalf("commands before bundle validation: %v", runner.calls)
			}
			if _, err := os.Stat(o.Paths.RootDir); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("created destination before bundle validation: %v", err)
			}
		})
	}
}

// TestExplicitInstallUser validates explicit account names and resolved UIDs before
// privileged operations, including UID-zero aliases and account lookup failures.
func TestExplicitInstallUser(t *testing.T) {
	for _, tc := range []struct {
		name   string
		uid    int
		lookup bool
	}{
		{"root", 0, false}, {"--root", 501, false}, {"two words", 501, false},
		{"jane\n", 501, false}, {"501", 501, false}, {strings.Repeat("a", 257), 501, false},
		{"root-alias", 0, true}, {"bad-uid", -1, true}, {"missing", 501, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o, runner := testOptions(t, "darwin")
			o.User = tc.name
			lookedUp := false
			o.UserID = func(name string) (int, error) {
				lookedUp = true
				if name == "missing" {
					return 0, errors.New("account absent")
				}
				return tc.uid, nil
			}
			if err := Install(context.Background(), o); err == nil {
				t.Fatal("accepted invalid explicit user")
			}
			if lookedUp != tc.lookup || len(runner.calls) != 0 {
				t.Fatalf("lookup = %v, commands = %v", lookedUp, runner.calls)
			}
			if _, err := os.Stat(o.Paths.RootDir); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("created destination before user validation: %v", err)
			}
		})
	}
}

// TestExplicitUserEnrollment checks the selected account overrides SUDO_USER and
// works with no sudo environment on both platforms, retaining argument boundaries.
func TestExplicitUserEnrollment(t *testing.T) {
	for _, platform := range []string{"darwin", "linux"} {
		for _, sudo := range []string{"", "other-user"} {
			t.Run(platform+"/sudo="+sudo, func(t *testing.T) {
				t.Setenv("SUDO_USER", sudo)
				o, runner := testOptions(t, platform)
				o.User, o.SudoUser = "selected.user", ""
				o.UserID = func(name string) (int, error) {
					if name != o.User {
						t.Fatalf("looked up %q", name)
					}
					return 501, nil
				}
				if err := Install(context.Background(), o); err != nil {
					t.Fatal(err)
				}
				want := []string{"/usr/sbin/dseditgroup", "-o", "edit", "-a", o.User, "-t", "user", "fortix"}
				if platform == "linux" {
					want = []string{"/usr/sbin/usermod", "-a", "-G", "fortix", o.User}
				}
				if !reflect.DeepEqual(runner.calls[0], want) {
					t.Fatalf("enrollment = %v, want %v", runner.calls[0], want)
				}
			})
		}
	}
}

// TestLookupUserID checks the production resolver against the current OS account
// without enrolling it or issuing any privileged command.
func TestLookupUserID(t *testing.T) {
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	uid, err := lookupUserID(account.Username)
	if err != nil || uid != os.Getuid() {
		t.Fatalf("current account UID = %d, %v", uid, err)
	}
	if _, err := lookupUserID("fortix-test-account-that-does-not-exist"); err == nil {
		t.Fatal("resolved nonexistent account")
	}
	if uid != 0 && userName.MatchString(account.Username) {
		o, _ := testOptions(t, "darwin")
		o.User = account.Username
		i, err := prepare(o)
		if err != nil || i.options.SudoUser != account.Username {
			t.Fatalf("default account resolution = %v, %v", i, err)
		}
	}
}

// TestAppBundlePublicationFailures checks staged pinentry copy failures and unsafe
// destinations stop publication without starting a service or replacing sources.
func TestAppBundlePublicationFailures(t *testing.T) {
	for _, name := range []string{"pinentry ownership", "pinentry destination", "CLI link"} {
		t.Run(name, func(t *testing.T) {
			o, runner := bundleOptions(t)
			p := resolvedPaths(t, o)
			switch name {
			case "pinentry ownership":
				o.Chown = func(path string, _, _ int) error {
					if filepath.Base(path) == "fortix-pinentry" {
						return errors.New("pinentry ownership failure")
					}
					return nil
				}
			case "pinentry destination":
				if err := os.MkdirAll(p.BinaryDir, 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(o.Helper, p.Pinentry); err != nil {
					t.Fatal(err)
				}
			case "CLI link":
				if err := os.MkdirAll(filepath.Dir(p.CLILink), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p.CLILink, []byte("foreign CLI"), 0755); err != nil {
					t.Fatal(err)
				}
			}
			if err := Install(context.Background(), o); err == nil {
				t.Fatal("published installation after unsafe destination or copy failure")
			}
			if _, err := os.Stat(p.ServiceFile); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("published service after copy failure: %v", err)
			}
			for _, call := range runner.calls {
				if call[0] == "/bin/launchctl" {
					t.Fatalf("service command after copy failure: %v", call)
				}
			}
			data, err := os.ReadFile(o.Helper)
			if err != nil || string(data) != "bundled helper" {
				t.Fatalf("modified bundled helper: %q, %v", data, err)
			}
		})
	}
}
