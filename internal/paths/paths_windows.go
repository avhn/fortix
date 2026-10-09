//go:build windows

package paths

import (
	"errors"
	"fmt"
	"path/filepath"

	"golang.org/x/sys/windows"

	"github.com/avhn/fortix/internal/winfs"
)

// Override supplies canonical local drive locations instead of Windows known folders.
// RootDir relocates file locations, never the fixed control pipe. ConfigHome overrides
// LocalAppData; HomeDir derives AppData\Local only when ConfigHome is absent. SkipTrust
// requires an isolated non-drive root and remains reserved for tests.
type Override struct {
	RootDir        string
	ControlSocket  string
	PinentrySocket string
	HelperPath     string
	HomeDir        string
	ConfigHome     string
	SkipTrust      bool
	// Service omits per-user locations so LocalSystem does not consult user preferences.
	Service bool
}

// Paths mirrors runtime and installation locations across platforms.
// Unsupported pinentry, openfortivpn, Unix service files and tray paths remain empty.
type Paths struct {
	ControlSocket  string
	PinentrySocket string
	Profiles       string
	State          string
	Logs           string
	OpenFortiVPN   []string
	Pinentry       string
	Preferences    string
	TrayAutostart  string
	SkipTrust      bool
	BinaryDir      string
	CLILink        string
	ServiceFile    string
	ResolverDir    string
	VPNDir         string
}

// Resolve discovers Windows known folders and applies validated overrides without writes.
// Filesystem overrides cannot contain remote, device, stream or normalization aliases.
func Resolve(o Override) (Paths, error) {
	if err := validateOverride(o); err != nil {
		return Paths{}, err
	}
	p, err := systemPaths("windows")
	if err != nil {
		return Paths{}, err
	}
	if !o.Service {
		config := o.ConfigHome
		if config == "" && o.HomeDir != "" {
			config = filepath.Join(o.HomeDir, "AppData", "Local")
		}
		if config == "" {
			config, err = knownFolder(windows.FOLDERID_LocalAppData)
			if err != nil {
				return Paths{}, err
			}
		}
		p.Preferences = filepath.Join(config, "Fortix", "config.json")
	}
	applyOverride(&p, o)
	return p, nil
}

// validateOverride prevents aliases and ensures trust bypasses have an isolated root.
func validateOverride(o Override) error {
	for _, path := range []string{o.RootDir, o.ControlSocket, o.PinentrySocket, o.HelperPath, o.HomeDir, o.ConfigHome} {
		if path != "" && !validPath(path) {
			return errors.New("paths: overrides must be canonical local drive paths without controls")
		}
	}
	if o.SkipTrust && (o.RootDir == "" || len(o.RootDir) == 3) {
		return errors.New("paths: skipping trust requires an isolated root directory")
	}
	return nil
}

// validPath validates Windows spelling without consulting or changing its target.
func validPath(path string) bool { return winfs.ValidPath(path) }

// underRoot strips a validated drive prefix and retains the remaining hierarchy.
// Empty unsupported locations stay empty rather than turning into the root directory.
func underRoot(root, path string) string {
	if path == "" {
		return ""
	}
	return filepath.Join(root, path[3:])
}

// applyOverride relocates file targets while leaving the control pipe namespace intact.
func applyOverride(p *Paths, o Override) {
	if o.RootDir != "" {
		for _, target := range []*string{&p.Profiles, &p.State, &p.Logs, &p.BinaryDir, &p.CLILink, &p.Preferences, &p.VPNDir} {
			*target = underRoot(o.RootDir, *target)
		}
	}
	if o.ControlSocket != "" {
		p.ControlSocket = o.ControlSocket
	}
	if o.PinentrySocket != "" {
		p.PinentrySocket = o.PinentrySocket
	}
	p.SkipTrust = o.SkipTrust
}

// knownFolder uses the shell's authoritative folder mapping and rejects unsafe redirection.
func knownFolder(id *windows.KNOWNFOLDERID) (string, error) {
	path, err := windows.KnownFolderPath(id, windows.KF_FLAG_DONT_VERIFY)
	if err != nil {
		return "", fmt.Errorf("resolve known folder: %w", err)
	}
	if !validPath(path) {
		return "", errors.New("paths: known folder must be a canonical local drive path")
	}
	return path, nil
}
