//go:build darwin

package paths

import "path/filepath"

// platformPaths returns macOS defaults for home; configHome is unused on macOS.
// It does not access any path and cannot fail for a validated absolute home.
func platformPaths(home, _ string) (Paths, error) {
	return Paths{
		ControlSocket:  "/var/run/fortix/fortix.sock",
		PinentrySocket: "/var/run/fortix/private/pinentry.sock",
		Profiles:       "/Library/Application Support/fortix/profiles",
		State:          "/Library/Application Support/fortix/state",
		Logs:           "/Library/Logs/fortix",
		OpenFortiVPN:   []string{"/Library/Application Support/fortix/libexec/openfortivpn"},
		Preferences:    filepath.Join(home, "Library/Application Support/fortix/config.json"),
	}, nil
}
