//go:build linux

package paths

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// platformPaths returns Linux defaults using configHome, or the user's XDG config dir.
// home is supplied for API symmetry. Invalid XDG locations or resolution failures
// return an error instead of producing relative paths for a privileged caller.
func platformPaths(_ string, configHome string) (Paths, error) {
	if configHome == "" {
		var err error
		configHome, err = os.UserConfigDir()
		if err != nil {
			return Paths{}, fmt.Errorf("resolve user configuration directory: %w", err)
		}
	}
	if !validPath(configHome) {
		return Paths{}, errors.New("paths: user configuration directory must be a clean absolute path")
	}
	p, err := systemPaths("linux")
	p.Preferences = filepath.Join(configHome, "fortix/config.json")
	return p, err
}
