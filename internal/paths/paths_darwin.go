//go:build darwin

package paths

import "path/filepath"

// platformPaths returns macOS defaults for home; configHome is unused on macOS.
// It does not access any path and cannot fail for a validated absolute home.
func platformPaths(home, _ string) (Paths, error) {
	p, err := systemPaths("darwin")
	p.Preferences = filepath.Join(home, "Library/Application Support/fortix/config.json")
	p.TrayAutostart = filepath.Join(home, "Library/LaunchAgents/com.github.avhn.fortix.tray.plist")
	return p, err
}
