//go:build darwin || linux

package install

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/avhn/fortix/internal/helper"
)

// TestInstalledStorageMatchesHelper verifies fresh installer directories can be
// opened by the real helper, and profile upgrades restrict files to the shared group.
func TestInstalledStorageMatchesHelper(t *testing.T) {
	for _, platform := range []string{"linux", "darwin"} {
		t.Run(platform, func(t *testing.T) {
			o, _ := testOptions(t, platform)
			p := resolvedPaths(t, o)
			if err := os.MkdirAll(p.Profiles, 0755); err != nil {
				t.Fatal(err)
			}
			stored := filepath.Join(p.Profiles, "work.json")
			if err := os.WriteFile(stored, []byte("preserved profile"), 0644); err != nil {
				t.Fatal(err)
			}
			ownership := make(map[string][2]int)
			o.Chown = func(path string, uid, gid int) error { ownership[path] = [2]int{uid, gid}; return nil }
			if err := Install(t.Context(), o); err != nil {
				t.Fatal(err)
			}
			for path, mode := range map[string]os.FileMode{p.Profiles: 0750, p.Logs: 0700, stored: 0640} {
				info, err := os.Stat(path)
				if err != nil || info.Mode().Perm() != mode {
					t.Fatalf("mode %s: %v %v", path, info, err)
				}
			}
			if ownership[p.Logs] != [2]int{0, 0} || ownership[p.Profiles] != [2]int{0, 42} || ownership[stored] != [2]int{0, 42} {
				t.Fatal("incorrect storage ownership requests")
			}
			if os.Geteuid() == 0 {
				t.Skip("relocated development helper requires an unprivileged user")
			}
			socketRoot, err := os.MkdirTemp("/tmp", "fi-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(socketRoot) })
			p.ControlSocket = filepath.Join(socketRoot, "control.sock")
			p.PinentrySocket = filepath.Join(socketRoot, "private", "pinentry.sock")
			server, err := helper.New(helper.Options{Paths: p, Network: helper.NoNetwork{}})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
			defer cancel()
			if err := server.Serve(ctx); err != nil {
				t.Fatalf("installer modes prevented helper startup: %v", err)
			}
		})
	}
}

// TestPackagedStorageModes keeps the package hook's private logs and group-readable
// profile modes aligned with the installer without executing privileged hook commands.
func TestPackagedStorageModes(t *testing.T) {
	raw, err := os.ReadFile("../../packaging/postinst")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"-o root -g root -m 0700 /var/log/fortix", "-o root -g fortix -m 0750 /etc/fortix/profiles", "chown root:fortix", "chmod 0640"} {
		if !strings.Contains(string(raw), required) {
			t.Fatalf("package storage policy lacks %s", required)
		}
	}
}
