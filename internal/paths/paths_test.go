//go:build darwin || linux

package paths

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// TestResolve checks every platform default using explicit user and helper locations.
// Any divergence from the platform table or unexpected resolution error fails the test.
func TestResolve(t *testing.T) {
	p, err := Resolve(Override{HomeDir: "/home/jane.doe", ConfigHome: "/home/jane.doe/.config", HelperPath: "/usr/local/libexec/fortix/fortix-helper"})
	if err != nil {
		t.Fatal(err)
	}
	want := Paths{Pinentry: "/usr/local/libexec/fortix/fortix-pinentry", BinaryDir: "/usr/local/libexec/fortix", CLILink: "/usr/local/bin/fortix", ResolverDir: "/etc/resolver"}
	if runtime.GOOS == "darwin" {
		want.ServiceFile = "/Library/LaunchDaemons/com.github.avhn.fortix.helper.plist"
		want.VPNDir = "/Library/Application Support/fortix/libexec"
		want.ControlSocket = "/var/run/fortix/fortix.sock"
		want.PinentrySocket = "/var/run/fortix/private/pinentry.sock"
		want.Profiles = "/Library/Application Support/fortix/profiles"
		want.State = "/Library/Application Support/fortix/state"
		want.Logs = "/Library/Logs/fortix"
		want.OpenFortiVPN = []string{"/Library/Application Support/fortix/libexec/openfortivpn"}
		want.Preferences = "/home/jane.doe/Library/Application Support/fortix/config.json"
		want.TrayAutostart = "/home/jane.doe/Library/LaunchAgents/com.github.avhn.fortix.tray.plist"
	} else {
		want.ServiceFile = "/etc/systemd/system/fortix-helper.service"
		want.ControlSocket = "/run/fortix/fortix.sock"
		want.PinentrySocket = "/run/fortix/private/pinentry.sock"
		want.Profiles = "/etc/fortix/profiles"
		want.State = "/var/lib/fortix/state"
		want.Logs = "/var/log/fortix"
		want.OpenFortiVPN = []string{"/usr/bin/openfortivpn", "/usr/sbin/openfortivpn"}
		want.Preferences = "/home/jane.doe/.config/fortix/config.json"
		want.TrayAutostart = "/home/jane.doe/.config/autostart/fortix-tray.desktop"
	}
	if !reflect.DeepEqual(p, want) {
		t.Fatalf("got %+v, want %+v", p, want)
	}
}

// TestOverrides proves all defaults stay below a temporary root and socket overrides
// take precedence verbatim. It also verifies defaults do not share mutable slices.
func TestOverrides(t *testing.T) {
	root := t.TempDir()
	o := Override{RootDir: root, HomeDir: "/home/jane.doe", ConfigHome: "/home/jane.doe/.config", HelperPath: "/usr/local/libexec/fortix/fortix-helper", SkipTrust: true}
	p, err := Resolve(o)
	if err != nil {
		t.Fatal(err)
	}
	all := make([]string, 0, 13+len(p.OpenFortiVPN))
	all = append(all, p.ControlSocket, p.PinentrySocket, p.Profiles, p.State, p.Logs, p.Pinentry, p.Preferences, p.BinaryDir, p.CLILink, p.ServiceFile, p.ResolverDir, p.VPNDir, p.TrayAutostart)
	all = append(all, p.OpenFortiVPN...)
	for _, path := range all {
		// Only macOS vendors openfortivpn; an unused location stays empty.
		if path == "" && p.VPNDir == "" {
			continue
		}
		if !strings.HasPrefix(path, root+string(filepath.Separator)) {
			t.Fatalf("escaped temporary root: %q", path)
		}
	}
	if !p.SkipTrust {
		t.Fatal("test trust override lost")
	}
	p.OpenFortiVPN[0] = "changed"
	o.ControlSocket = filepath.Join(root, "control.sock")
	o.PinentrySocket = filepath.Join(root, "relay.sock")
	again, err := Resolve(o)
	if err != nil || again.ControlSocket != o.ControlSocket || again.PinentrySocket != o.PinentrySocket || again.OpenFortiVPN[0] == "changed" {
		t.Fatalf("incorrect explicit override or shared state: %+v, %v", again, err)
	}
}

// TestInvalidOverrides rejects relative, unclean, and control-bearing paths and
// prevents a trust bypass with the real filesystem root. No paths are accessed.
func TestInvalidOverrides(t *testing.T) {
	for _, o := range []Override{
		{RootDir: "relative"}, {RootDir: "/tmp/../etc"}, {ControlSocket: "relative.sock"},
		{PinentrySocket: "/tmp/relay\n.sock"}, {HelperPath: "helper"}, {HomeDir: "home"},
		{ConfigHome: "/tmp/config/"}, {SkipTrust: true}, {RootDir: "/", SkipTrust: true},
	} {
		if p, err := Resolve(o); err == nil || !reflect.DeepEqual(p, Paths{}) {
			t.Fatalf("accepted %+v: %+v, %v", o, p, err)
		}
	}
}

// TestDiscoveredHelperRoot preserves a discovered helper's real sibling pinentry path
// when RootDir isolates other paths. An explicit helper is relocated beneath that root.
func TestDiscoveredHelperRoot(t *testing.T) {
	helper, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	for _, override := range []string{"", "/usr/local/libexec/fortix/fortix-helper"} {
		p, err := Resolve(Override{RootDir: root, HelperPath: override, HomeDir: "/home/jane.doe", ConfigHome: "/home/jane.doe/.config", SkipTrust: true})
		if err != nil {
			t.Fatal(err)
		}
		want := filepath.Join(filepath.Dir(helper), "fortix-pinentry")
		if override != "" {
			want = underRoot(root, filepath.Join(filepath.Dir(override), "fortix-pinentry"))
		}
		if p.Pinentry != want || !strings.HasPrefix(p.State, root+string(filepath.Separator)) {
			t.Fatalf("helper override %q: %+v, want pinentry %q", override, p, want)
		}
	}
}

// TestAmbientDefaults confirms real default discovery is read-only and absolute.
// Resolution errors fail the test rather than falling back to relative locations.
func TestAmbientDefaults(t *testing.T) {
	p, err := Resolve(Override{})
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(p.Pinentry) || !filepath.IsAbs(p.Preferences) || p.SkipTrust {
		t.Fatalf("unsafe ambient defaults: %+v", p)
	}
}

// TestServiceWithoutHome verifies that the root helper resolves its system paths
// when started by launchd or systemd without HOME or XDG variables, and that the
// per-user locations stay empty rather than pointing into an arbitrary directory.
func TestServiceWithoutHome(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	p, err := Resolve(Override{Service: true, HelperPath: "/usr/local/libexec/fortix/fortix-helper"})
	if err != nil {
		t.Fatal(err)
	}
	if p.ControlSocket == "" || p.Profiles == "" || p.State == "" || p.Logs == "" {
		t.Fatalf("missing system paths: %+v", p)
	}
	if p.Preferences != "" || p.TrayAutostart != "" {
		t.Fatalf("per-user paths set for service: %q %q", p.Preferences, p.TrayAutostart)
	}
	if p.Pinentry != "/usr/local/libexec/fortix/fortix-pinentry" {
		t.Fatalf("pinentry = %q", p.Pinentry)
	}
}
