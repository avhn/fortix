package install

import (
	"context"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/avhn/fortix/internal/paths"
)

// recordingRunner records argument boundaries and can fail a selected command.
// It never executes a system command or changes the host's service configuration.
type recordingRunner struct {
	calls [][]string
	fail  string
}

// Run saves the executable and arguments and returns a deterministic injected error.
func (r *recordingRunner) Run(_ context.Context, program string, args ...string) (string, error) {
	r.calls = append(r.calls, append([]string{program}, args...))
	if strings.Contains(strings.Join(append([]string{program}, args...), " "), r.fail) && r.fail != "" {
		return "injected diagnostic", errors.New("injected failure")
	}
	return "", nil
}

// testOptions makes isolated sources, paths and fake root operations for platform.
// Every privileged ownership request is accepted without changing actual ownership.
func testOptions(t *testing.T, platform string) (Options, *recordingRunner) {
	t.Helper()
	base := t.TempDir()
	helper, cli := filepath.Join(base, "helper-source"), filepath.Join(base, "cli-source")
	for path, content := range map[string]string{helper: "helper bytes", cli: "CLI bytes"} {
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	runner := &recordingRunner{}
	return Options{Helper: helper, CLI: cli, Platform: platform, SudoUser: "jane.doe", Paths: paths.Override{RootDir: filepath.Join(base, "root"), SkipTrust: true}, Runner: runner,
		EUID: func() int { return 0 }, GroupID: func(string) (int, error) { return 42, nil }, Chown: func(string, int, int) error { return nil }}, runner
}

// resolvedPaths resolves fixture machine paths and fails the test on bad options.
func resolvedPaths(t *testing.T, o Options) paths.Paths {
	t.Helper()
	p, err := paths.Installation(o.Platform, o.Paths)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestInstallUninstall checks both service managers, exact commands, hard links,
// file contents and modes, requested ownership, and profile preservation or purge.
func TestInstallUninstall(t *testing.T) {
	for _, platform := range []string{"darwin", "linux"} {
		for _, purge := range []bool{false, true} {
			t.Run(platform+map[bool]string{false: "/preserve", true: "/purge"}[purge], func(t *testing.T) {
				o, runner := testOptions(t, platform)
				o.Purge = purge
				p := resolvedPaths(t, o)
				var ownership [][]any
				o.Chown = func(path string, uid, gid int) error {
					ownership = append(ownership, []any{path, uid, gid})
					return nil
				}
				if err := Install(context.Background(), o); err != nil {
					t.Fatal(err)
				}
				for path, mode := range map[string]os.FileMode{p.BinaryDir: 0755, p.Profiles: 0750, p.State: 0700, p.Logs: 0700, filepath.Dir(p.ControlSocket): 0755, filepath.Dir(p.PinentrySocket): 0700, p.ServiceFile: 0644, p.Pinentry: 0755} {
					info, err := os.Stat(path)
					if err != nil || info.Mode().Perm() != mode {
						t.Fatalf("%s mode: %v %v", path, info, err)
					}
				}
				helper, err := os.Stat(filepath.Join(p.BinaryDir, "fortix-helper"))
				if err != nil {
					t.Fatal(err)
				}
				pinentry, err := os.Stat(p.Pinentry)
				if err != nil || !os.SameFile(helper, pinentry) {
					t.Fatalf("pinentry not a hard link: %v", err)
				}
				content, err := os.ReadFile(p.Pinentry)
				if err != nil || string(content) != "helper bytes" {
					t.Fatalf("pinentry content: %q %v", content, err)
				}
				link, err := os.Readlink(p.CLILink)
				if err != nil || link != filepath.Join(p.BinaryDir, "fortix") {
					t.Fatalf("CLI link: %q %v", link, err)
				}
				found := false
				for _, entry := range ownership {
					if reflect.DeepEqual(entry, []any{p.Logs, 0, 0}) {
						found = true
					}
				}
				if !found {
					t.Fatal("logs did not receive root:fortix ownership")
				}
				profile := filepath.Join(p.Profiles, "work.json")
				if err := os.WriteFile(profile, []byte("preserved"), 0644); err != nil {
					t.Fatal(err)
				}
				if err := Uninstall(context.Background(), o); err != nil {
					t.Fatal(err)
				}
				for _, path := range []string{p.BinaryDir, p.CLILink, p.ServiceFile, p.State, p.Logs, filepath.Dir(p.ControlSocket)} {
					if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("left behind %s: %v", path, err)
					}
				}
				_, err = os.Stat(profile)
				if purge && !errors.Is(err, os.ErrNotExist) || !purge && err != nil {
					t.Fatalf("profile preservation: %v", err)
				}
				var want [][]string
				if platform == "darwin" {
					want = [][]string{{"/usr/sbin/dseditgroup", "-o", "edit", "-a", "jane.doe", "-t", "user", "fortix"}, {"/bin/launchctl", "bootstrap", "system", p.ServiceFile}, {"/bin/launchctl", "print", "system/com.github.avhn.fortix.helper"}, {"/bin/launchctl", "bootout", "system", p.ServiceFile}, {"/usr/sbin/dseditgroup", "-o", "delete", "fortix"}}
				} else {
					want = [][]string{{"/usr/sbin/usermod", "-a", "-G", "fortix", "jane.doe"}, {"/bin/systemctl", "daemon-reload"}, {"/bin/systemctl", "enable", "--now", "fortix-helper.service"}, {"/bin/systemctl", "disable", "--now", "fortix-helper.service"}, {"/bin/systemctl", "daemon-reload"}, {"/usr/sbin/groupdel", "fortix"}}
				}
				if !reflect.DeepEqual(runner.calls, want) {
					t.Fatalf("commands: got %v want %v", runner.calls, want)
				}
			})
		}
	}
}

// TestInstallerFailures ensures invalid authority, inputs, paths and command errors
// fail without starting the helper or following attacker-controlled symlinks.
func TestInstallerFailures(t *testing.T) {
	for _, name := range []string{"uid", "source symlink", "destination symlink", "directory symlink", "account", "group failure", "ownership failure", "service failure", "canceled"} {
		t.Run(name, func(t *testing.T) {
			o, runner := testOptions(t, "linux")
			p := resolvedPaths(t, o)
			ctx := context.Background()
			switch name {
			case "uid":
				o.EUID = func() int { return 1000 }
			case "source symlink":
				link := filepath.Join(filepath.Dir(o.Helper), "source-link")
				if err := os.Symlink(o.Helper, link); err != nil {
					t.Fatal(err)
				}
				o.Helper = link
			case "destination symlink", "directory symlink":
				if err := os.MkdirAll(p.BinaryDir, 0755); err != nil {
					t.Fatal(err)
				}
				target := filepath.Join(p.BinaryDir, "fortix-helper")
				if name == "directory symlink" {
					target = p.State
					if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.Symlink(o.Helper, target); err != nil {
					t.Fatal(err)
				}
			case "account":
				o.SudoUser = "--root"
			case "group failure":
				runner.fail = "groupadd"
				o.GroupID = func(string) (int, error) { return 0, errGroupAbsent }
			case "ownership failure":
				o.Chown = func(string, int, int) error { return errors.New("chown failed") }
			case "service failure":
				runner.fail = "daemon-reload"
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			err := Install(ctx, o)
			if err == nil {
				t.Fatal("installation unexpectedly succeeded")
			}
			for _, call := range runner.calls {
				if strings.Contains(strings.Join(call, " "), "enable --now") {
					t.Fatalf("started service after failure: %v", call)
				}
			}
			if strings.Contains(name, "symlink") {
				content, err := os.ReadFile(filepath.Join(filepath.Dir(o.CLI), "helper-source"))
				if err != nil || string(content) != "helper bytes" {
					t.Fatal("source was modified")
				}
			}
			if name == "group failure" || name == "service failure" {
				if !strings.Contains(err.Error(), "injected diagnostic") {
					t.Fatalf("lost command diagnostic: %v", err)
				}
			}
		})
	}
}

// TestGroupCreation verifies platform-specific creation and root-user suppression.
func TestGroupCreation(t *testing.T) {
	for _, platform := range []string{"darwin", "linux"} {
		t.Run(platform, func(t *testing.T) {
			o, runner := testOptions(t, platform)
			o.SudoUser = "root"
			lookups := 0
			o.GroupID = func(string) (int, error) {
				lookups++
				if lookups == 1 {
					return 0, errGroupAbsent
				}
				return 42, nil
			}
			if err := Install(context.Background(), o); err != nil {
				t.Fatal(err)
			}
			want := []string{"/usr/sbin/groupadd", "--system", "fortix"}
			if platform == "darwin" {
				want = []string{"/usr/sbin/dseditgroup", "-o", "create", "fortix"}
			}
			if !reflect.DeepEqual(runner.calls[0], want) {
				t.Fatalf("group command: %v", runner.calls[0])
			}
			if lookups != 2 {
				t.Fatalf("group lookups: %d", lookups)
			}
		})
	}
}

// TestUninstallRefusesReplacement protects unrelated CLI links and installation
// directories and ensures a service stop failure prevents any filesystem cleanup.
func TestUninstallRefusesReplacement(t *testing.T) {
	for _, name := range []string{"link", "stop"} {
		t.Run(name, func(t *testing.T) {
			o, runner := testOptions(t, "darwin")
			p := resolvedPaths(t, o)
			if err := Install(context.Background(), o); err != nil {
				t.Fatal(err)
			}
			if name == "stop" {
				runner.fail = "bootout"
			} else {
				if err := os.Remove(p.CLILink); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(o.CLI, p.CLILink); err != nil {
					t.Fatal(err)
				}
			}
			if err := Uninstall(context.Background(), o); err == nil {
				t.Fatal("unsafe uninstall succeeded")
			}
			if _, err := os.Stat(p.Pinentry); err != nil {
				t.Fatal("helper removed after failed uninstall")
			}
		})
	}
}

// TestServiceTemplates checks escaped XML, service hardening and parity between the
// embedded Linux template and the packaged unit with its different binary prefix.
func TestServiceTemplates(t *testing.T) {
	for _, platform := range []string{"darwin", "linux"} {
		t.Run(platform, func(t *testing.T) {
			p, err := paths.Installation(platform, paths.Override{})
			if err != nil {
				t.Fatal(err)
			}
			service, err := RenderService(platform, p)
			if err != nil {
				t.Fatal(err)
			}
			if platform == "linux" {
				p.BinaryDir = "/usr/libexec/fortix"
				rendered, err := RenderService(platform, p)
				if err != nil {
					t.Fatal(err)
				}
				packaged, err := os.ReadFile("../../packaging/fortix-helper.service")
				if err != nil || string(packaged) != rendered {
					t.Fatalf("packaged service drift: %v", err)
				}
				for _, directive := range []string{"Restart=on-failure", "RuntimeDirectory=fortix", "PrivateTmp=yes", "ProtectHome=yes", "ProtectSystem=strict", "ReadWritePaths="} {
					if !strings.Contains(service, directive) {
						t.Fatalf("missing %s", directive)
					}
				}
				if strings.Contains(service, "NoNewPrivileges=") {
					t.Fatal("pppd privileges disabled")
				}
			} else {
				p.BinaryDir = "/Library/Test & <helpers>"
				rendered, err := RenderService(platform, p)
				if err != nil || !strings.Contains(rendered, "&amp; &lt;helpers&gt;") {
					t.Fatalf("XML escape: %q %v", rendered, err)
				}
				decoder := xml.NewDecoder(strings.NewReader(rendered))
				for {
					_, err := decoder.Token()
					if errors.Is(err, io.EOF) {
						break
					}
					if err != nil {
						t.Fatal(err)
					}
				}
				if !strings.Contains(service, "<key>ProcessType</key><string>Standard</string>") {
					t.Fatal("launchd throttling enabled")
				}
				if !strings.Contains(service, "<key>KeepAlive</key><true/>") || !strings.Contains(service, "<key>RunAtLoad</key><true/>") {
					t.Fatal("launchd startup not configured")
				}
			}
			p.State = "/state\nExecStart=evil"
			if _, err := RenderService(platform, p); err == nil {
				t.Fatal("service accepted control bytes")
			}
		})
	}
}

// TestRootTrustAndAncestors verifies production trust rejects user-owned paths and
// that installation never changes the mode of pre-existing parent directories.
func TestRootTrustAndAncestors(t *testing.T) {
	o, _ := testOptions(t, "linux")
	if err := os.MkdirAll(o.Paths.RootDir, 0711); err != nil {
		t.Fatal(err)
	}
	if err := Install(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(o.Paths.RootDir)
	if err != nil || info.Mode().Perm() != 0711 {
		t.Fatalf("ancestor mode modified: %v %v", info, err)
	}
	i, err := prepare(o)
	if err != nil {
		t.Fatal(err)
	}
	i.paths.SkipTrust = false
	if os.Geteuid() != 0 {
		if err := i.checkDirectory(o.Paths.RootDir); err == nil {
			t.Fatal("accepted user-owned directory")
		}
	}
}
