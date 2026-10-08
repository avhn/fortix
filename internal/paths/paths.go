package paths

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

// Override supplies optional absolute locations instead of platform defaults.
// RootDir prefixes machine and user defaults and an explicit HelperPath's sibling
// pinentry path. A discovered executable's sibling is not relocated. Explicit socket
// paths are used verbatim. HelperPath identifies the helper, not a program to run.
// HomeDir and ConfigHome avoid ambient user configuration in tests. SkipTrust is
// reserved for tests and requires a non-root RootDir; production must leave it false.
type Override struct {
	RootDir        string
	ControlSocket  string
	PinentrySocket string
	HelperPath     string
	HomeDir        string
	ConfigHome     string
	SkipTrust      bool
}

// Paths contains resolved absolute locations and the test-only trust override.
// OpenFortiVPN lists candidates in preference order. Consumers must verify executable
// trust before execution; resolving a path does not authorize or access its target.
type Paths struct {
	ControlSocket  string
	PinentrySocket string
	Profiles       string
	State          string
	Logs           string
	OpenFortiVPN   []string
	Pinentry       string
	Preferences    string
	SkipTrust      bool
}

// Resolve returns this platform's paths with o applied, without filesystem writes.
// Empty home and helper overrides use os.UserHomeDir and os.Executable. On Linux an
// empty ConfigHome uses os.UserConfigDir. Invalid or unavailable locations fail.
func Resolve(o Override) (Paths, error) {
	for _, path := range []string{o.RootDir, o.ControlSocket, o.PinentrySocket, o.HelperPath, o.HomeDir, o.ConfigHome} {
		if path != "" && !validPath(path) {
			return Paths{}, errors.New("paths: overrides must be clean absolute paths without controls")
		}
	}
	if o.SkipTrust && (o.RootDir == "" || o.RootDir == "/") {
		return Paths{}, errors.New("paths: skipping executable trust requires an isolated root directory")
	}
	home := o.HomeDir
	if home == "" {
		var err error
		home, err = os.UserHomeDir()
		if err != nil {
			return Paths{}, fmt.Errorf("resolve home directory: %w", err)
		}
	}
	helper := o.HelperPath
	if helper == "" {
		var err error
		helper, err = os.Executable()
		if err != nil {
			return Paths{}, fmt.Errorf("resolve helper executable: %w", err)
		}
	}
	if !validPath(home) || !validPath(helper) {
		return Paths{}, errors.New("paths: discovered home and helper locations must be clean absolute paths")
	}
	p, err := platformPaths(home, o.ConfigHome)
	if err != nil {
		return Paths{}, err
	}
	p.Pinentry = filepath.Join(filepath.Dir(helper), "fortix-pinentry")
	p.SkipTrust = o.SkipTrust
	if o.RootDir != "" {
		p.ControlSocket = underRoot(o.RootDir, p.ControlSocket)
		p.PinentrySocket = underRoot(o.RootDir, p.PinentrySocket)
		p.Profiles = underRoot(o.RootDir, p.Profiles)
		p.State = underRoot(o.RootDir, p.State)
		p.Logs = underRoot(o.RootDir, p.Logs)
		if o.HelperPath != "" {
			// Keep a discovered executable's sibling usable outside the isolated root.
			p.Pinentry = underRoot(o.RootDir, p.Pinentry)
		}
		p.Preferences = underRoot(o.RootDir, p.Preferences)
		for i, candidate := range p.OpenFortiVPN {
			p.OpenFortiVPN[i] = underRoot(o.RootDir, candidate)
		}
	}
	if o.ControlSocket != "" {
		p.ControlSocket = o.ControlSocket
	}
	if o.PinentrySocket != "" {
		p.PinentrySocket = o.PinentrySocket
	}
	return p, nil
}

// validPath checks the absolute, canonical spelling of path without accessing it.
// It rejects controls and traversal so a root prefix cannot be escaped by normalization.
func validPath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.ContainsFunc(path, unicode.IsControl)
}

// underRoot relocates absolute path beneath root, retaining its directory hierarchy.
// Both arguments are validated absolute paths; no filesystem access or errors occur.
func underRoot(root, path string) string {
	return filepath.Join(root, strings.TrimPrefix(path, string(filepath.Separator)))
}
