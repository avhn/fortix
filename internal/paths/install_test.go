package paths

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestInstallationPaths checks both machine layouts and relocates every installer
// target beneath an isolated root without consulting user homes or executables.
func TestInstallationPaths(t *testing.T) {
	for _, platform := range []string{"darwin", "linux"} {
		t.Run(platform, func(t *testing.T) {
			root := t.TempDir()
			p, err := Installation(platform, Override{RootDir: root, SkipTrust: true})
			if err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{p.BinaryDir, p.CLILink, p.ServiceFile, p.VPNDir, p.Profiles, p.State, p.Logs, p.ControlSocket, p.PinentrySocket, p.Pinentry, p.ResolverDir} {
				if path != "" && !strings.HasPrefix(path, root+string(filepath.Separator)) {
					t.Fatalf("escaped root: %s", path)
				}
			}
			if platform == "linux" && p.VPNDir != "" {
				t.Fatal("Linux must use the distribution openfortivpn executable")
			}
			if !p.SkipTrust || p.Preferences != "" {
				t.Fatal("machine-only paths used user state")
			}
			if p.Pinentry != filepath.Join(p.BinaryDir, "fortix-pinentry") {
				t.Fatal("pinentry not beside installed helper")
			}
			control, relay := filepath.Join(root, "control.sock"), filepath.Join(root, "relay.sock")
			explicit, err := Installation(platform, Override{RootDir: root, ControlSocket: control, PinentrySocket: relay})
			if err != nil || explicit.ControlSocket != control || explicit.PinentrySocket != relay {
				t.Fatalf("socket overrides: %+v %v", explicit, err)
			}
		})
	}
	for _, test := range []struct {
		platform string
		override Override
	}{
		{"windows", Override{}}, {"linux", Override{RootDir: "relative"}},
		{"linux", Override{RootDir: "/tmp/../etc"}}, {"linux", Override{SkipTrust: true}},
		{"darwin", Override{RootDir: "/", SkipTrust: true}}, {"darwin", Override{ControlSocket: "/socket\n"}},
	} {
		if _, err := Installation(test.platform, test.override); err == nil {
			t.Fatalf("accepted %+v", test)
		}
	}
}
