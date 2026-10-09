//go:build windows

package paths

import (
	"errors"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// Installation returns Windows machine paths without consulting per-user known folders.
// Other platform layouts are unsupported in a Windows process.
func Installation(platform string, o Override) (Paths, error) {
	if err := validateOverride(o); err != nil {
		return Paths{}, err
	}
	p, err := systemPaths(platform)
	if err != nil {
		return Paths{}, err
	}
	applyOverride(&p, o)
	return p, nil
}

// BundledBinaries preserves the cross-platform source-copy contract.
// Windows has no macOS app bundle and never populates these fields.
type BundledBinaries struct {
	Helper   string
	CLI      string
	Pinentry string
}

// AppBundleBinaries refuses macOS bundle discovery on Windows without accessing helper.
func AppBundleBinaries(_ string) (BundledBinaries, error) {
	return BundledBinaries{}, errors.New("paths: app bundles are unsupported on Windows")
}

// systemPaths maps protected binaries and shared state to authoritative known folders.
// SCM service registration and NRPT rules have no filesystem service or resolver path.
func systemPaths(platform string) (Paths, error) {
	if platform != "windows" {
		return Paths{}, errors.New("paths: unsupported installation platform")
	}
	programFiles, err := knownFolder(windows.FOLDERID_ProgramFiles)
	if err != nil {
		return Paths{}, err
	}
	programData, err := knownFolder(windows.FOLDERID_ProgramData)
	if err != nil {
		return Paths{}, err
	}
	binary := filepath.Join(programFiles, "Fortix")
	data := filepath.Join(programData, "Fortix")
	return Paths{
		ControlSocket: `\\.\pipe\Fortix.Control.v1`,
		Profiles:      filepath.Join(data, "profiles"), State: filepath.Join(data, "state"), Logs: filepath.Join(data, "logs"),
		BinaryDir: binary, CLILink: filepath.Join(binary, "fortix.exe"),
	}, nil
}
