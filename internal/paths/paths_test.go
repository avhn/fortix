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
	want := Paths{Pinentry: "/usr/local/libexec/fortix/fortix-pinentry"}
	if runtime.GOOS == "darwin" {
		want.ControlSocket = "/var/run/fortix/fortix.sock"
		want.PinentrySocket = "/var/run/fortix/private/pinentry.sock"
		want.Profiles = "/Library/Application Support/fortix/profiles"
		want.State = "/Library/Application Support/fortix/state"
		want.Logs = "/Library/Logs/fortix"
		want.OpenFortiVPN = []string{"/Library/Application Support/fortix/libexec/openfortivpn"}
		want.Preferences = "/home/jane.doe/Library/Application Support/fortix/config.json"
	} else {
		want.ControlSocket = "/run/fortix/fortix.sock"
		want.PinentrySocket = "/run/fortix/private/pinentry.sock"
		want.Profiles = "/etc/fortix/profiles"
		want.State = "/var/lib/fortix/state"
		want.Logs = "/var/log/fortix"
		want.OpenFortiVPN = []string{"/usr/bin/openfortivpn", "/usr/sbin/openfortivpn"}
		want.Preferences = "/home/jane.doe/.config/fortix/config.json"
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
	all := make([]string, 0, 7+len(p.OpenFortiVPN))
	all = append(all, p.ControlSocket, p.PinentrySocket, p.Profiles, p.State, p.Logs, p.Pinentry, p.Preferences)
	all = append(all, p.OpenFortiVPN...)
	for _, path := range all {
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
