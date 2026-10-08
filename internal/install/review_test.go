package install

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// runnerFunc adapts a test callback to Runner without executing host commands.
// The callback controls output, exit status and cancellation for each operation.
type runnerFunc func(context.Context, string, ...string) (string, error)

// Run delegates the executable and argument list unchanged to the test callback.
func (r runnerFunc) Run(ctx context.Context, program string, args ...string) (string, error) {
	return r(ctx, program, args...)
}

// exitStatus models an external command's unsuccessful exit for NSS lookup tests.
type exitStatus int

// Error returns a non-sensitive diagnostic for the simulated command failure.
func (e exitStatus) Error() string { return "command failed" }

// ExitCode returns the simulated process status used to distinguish group absence.
func (e exitStatus) ExitCode() int { return int(e) }

// TestLinuxNSSGroup verifies NSS-backed GIDs, creation only on status 2, diagnostic
// preservation and cancellation. No failure may accidentally create a local group.
func TestLinuxNSSGroup(t *testing.T) {
	for _, name := range []string{"existing", "absent", "lookup failure", "malformed", "canceled"} {
		t.Run(name, func(t *testing.T) {
			o, recording := testOptions(t, "linux")
			o.GroupID = nil
			o.SudoUser = "root"
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			lookups := 0
			o.Runner = runnerFunc(func(ctx context.Context, program string, args ...string) (string, error) {
				if program != "/usr/bin/getent" {
					return recording.Run(ctx, program, args...)
				}
				if !reflect.DeepEqual(args, []string{"group", "fortix"}) {
					t.Fatalf("getent arguments: %v", args)
				}
				lookups++
				switch name {
				case "absent":
					if lookups == 1 {
						return "", exitStatus(2)
					}
				case "lookup failure":
					return "NSS unavailable", exitStatus(1)
				case "malformed":
					return "fortix:x:not-a-gid:\n", nil
				case "canceled":
					cancel()
					return "", exitStatus(2)
				}
				return "fortix:x:4242:jane.doe\n", nil
			})
			i, err := prepare(o)
			if err != nil {
				t.Fatal(err)
			}
			err = i.group(ctx)
			wantFailure := name != "existing" && name != "absent"
			if (err != nil) != wantFailure {
				t.Fatalf("group lookup: %v", err)
			}
			if name == "lookup failure" && !strings.Contains(err.Error(), "NSS unavailable") {
				t.Fatalf("lost diagnostic: %v", err)
			}
			if name == "canceled" && !errors.Is(err, context.Canceled) {
				t.Fatalf("lost cancellation: %v", err)
			}
			if !wantFailure && i.gid != 4242 {
				t.Fatalf("NSS GID: %d", i.gid)
			}
			if name == "absent" {
				if !reflect.DeepEqual(recording.calls, [][]string{{"/usr/sbin/groupadd", "--system", "fortix"}}) {
					t.Fatalf("creation: %v", recording.calls)
				}
			} else if len(recording.calls) != 0 {
				t.Fatalf("unexpected creation: %v", recording.calls)
			}
		})
	}
}

// TestParseGroup rejects ambiguous output and malformed ownership values while
// accepting valid getent records with or without a final newline.
func TestParseGroup(t *testing.T) {
	for _, test := range []struct {
		input string
		valid bool
	}{
		{"fortix:x:42:jane.doe\n", true}, {"fortix:x:0:", true},
		{"", false}, {"other:x:42:\n", false}, {"fortix:x:-1:\n", false},
		{"fortix:x:4294967295:\n", false}, {"fortix:x:42:\nfortix:x:43:\n", false},
		{"fortix:x:42:\r\n", false}, {"fortix:x:42", false},
	} {
		_, err := parseGroup(test.input)
		if (err == nil) != test.valid {
			t.Fatalf("parse %q: %v", test.input, err)
		}
	}
}

// FuzzParseGroup exercises untrusted NSS output; malformed records may error but
// must never panic or produce a negative ownership value.
func FuzzParseGroup(f *testing.F) {
	f.Add("fortix:x:42:jane.doe\n")
	f.Add("")
	f.Fuzz(func(t *testing.T, input string) {
		gid, err := parseGroup(input)
		if err == nil && gid < 0 {
			t.Fatalf("negative GID: %d", gid)
		}
	})
}

// TestUninstallStoppedLaunchDaemon checks unloaded jobs and cancellation during
// launchctl print. Only registered jobs should receive bootout.
func TestUninstallStoppedLaunchDaemon(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		t.Run(map[bool]string{false: "stopped", true: "canceled"}[canceled], func(t *testing.T) {
			o, runner := testOptions(t, "darwin")
			if err := Install(context.Background(), o); err != nil {
				t.Fatal(err)
			}
			runner.calls = nil
			runner.fail = "launchctl print"
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if canceled {
				o.Runner = runnerFunc(func(ctx context.Context, program string, args ...string) (string, error) {
					cancel()
					return runner.Run(ctx, program, args...)
				})
			}
			err := Uninstall(ctx, o)
			if canceled {
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("cancellation: %v", err)
				}
				if _, err := os.Stat(resolvedPaths(t, o).ServiceFile); err != nil {
					t.Fatal("removed service despite cancellation")
				}
			} else if err != nil {
				t.Fatal(err)
			}
			for _, call := range runner.calls {
				if call[1] == "bootout" {
					t.Fatal("stopped daemon received bootout")
				}
			}
		})
	}
}

// TestOptionalCLILink leaves user-controlled parents untouched with a warning for
// creation and removal, while preserving strict checks for privileged binary paths.
func TestOptionalCLILink(t *testing.T) {
	o, _ := testOptions(t, "darwin")
	p := resolvedPaths(t, o)
	if err := os.MkdirAll(filepath.Dir(p.CLILink), 0777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(p.CLILink), 0777); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(p.BinaryDir, "fortix"), p.CLILink); err != nil {
		t.Fatal(err)
	}
	var warnings []string
	o.Warn = func(message string) { warnings = append(warnings, message) }
	i, err := prepare(o)
	if err != nil {
		t.Fatal(err)
	}
	i.paths.SkipTrust = false
	allowed, err := i.cliLinkAllowed(true)
	if err != nil || allowed {
		t.Fatalf("unsafe link creation: %v %v", allowed, err)
	}
	if err := i.removeLink(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Readlink(p.CLILink); err != nil || len(warnings) != 2 {
		t.Fatalf("link changed or warning missing: %v %v", err, warnings)
	}
	if err := os.MkdirAll(p.BinaryDir, 0777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p.BinaryDir, 0777); err != nil {
		t.Fatal(err)
	}
	if err := i.checkDirectory(p.BinaryDir); !errors.Is(err, errUnsafeOwnership) {
		t.Fatalf("privileged directory trust relaxed: %v", err)
	}
}

// TestUninstallResolvers removes only first-line marked regular resolver files,
// preserving foreign files, symlinks and the resolver directory itself.
func TestUninstallResolvers(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "cleanup", true: "unsafe directory"}[fail], func(t *testing.T) {
			o, _ := testOptions(t, "darwin")
			if err := Install(context.Background(), o); err != nil {
				t.Fatal(err)
			}
			p := resolvedPaths(t, o)
			if err := os.MkdirAll(p.ResolverDir, 0755); err != nil {
				t.Fatal(err)
			}
			for name, content := range map[string]string{
				"corp.example.com":    "# managed by fortix profile=work\nnameserver 10.20.0.1\n",
				"foreign.example.com": "nameserver 10.20.0.2\n# managed by fortix profile=work\n",
				"similar.example.com": "# managed by fortix profile=\nnameserver 10.20.0.2\n",
			} {
				if err := os.WriteFile(filepath.Join(p.ResolverDir, name), []byte(content), 0644); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink(o.CLI, filepath.Join(p.ResolverDir, "link.example.com")); err != nil {
				t.Fatal(err)
			}
			if fail {
				if err := os.Rename(p.ResolverDir, p.ResolverDir+"-real"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(p.ResolverDir+"-real", p.ResolverDir); err != nil {
					t.Fatal(err)
				}
			}
			err := Uninstall(context.Background(), o)
			if fail {
				if err == nil {
					t.Fatal("followed unsafe resolver directory")
				}
				if _, err := os.Stat(p.State); err != nil {
					t.Fatal("lost state on cleanup failure")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(filepath.Join(p.ResolverDir, "corp.example.com")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("owned resolver retained")
			}
			for _, name := range []string{"foreign.example.com", "similar.example.com", "link.example.com"} {
				if _, err := os.Lstat(filepath.Join(p.ResolverDir, name)); err != nil {
					t.Fatalf("foreign entry removed: %s: %v", name, err)
				}
			}
		})
	}
}

// TestLinuxUninstallPreservesUnmanagedVPNBinary ensures a locally placed executable
// is not mistaken for a private macOS bundle or recursively removed on Linux.
func TestLinuxUninstallPreservesUnmanagedVPNBinary(t *testing.T) {
	o, _ := testOptions(t, "linux")
	if err := Install(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	p := resolvedPaths(t, o)
	unmanaged := filepath.Join(p.BinaryDir, "openfortivpn")
	if err := os.WriteFile(unmanaged, []byte("unmanaged executable"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := Uninstall(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(unmanaged)
	if err != nil || string(data) != "unmanaged executable" {
		t.Fatalf("unmanaged executable removed: %q %v", data, err)
	}
	for _, path := range []string{p.State, p.Logs, p.ServiceFile} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("uninstall stopped before removing %s: %v", path, err)
		}
	}
}
