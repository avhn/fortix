package paths

import (
	"errors"
	"path/filepath"
	"strings"
)

// Installation returns machine-only paths for platform, applying the same root and
// socket overrides as Resolve. It performs no I/O and rejects unsupported platforms
// or unsafe overrides. No ambient user configuration or executable is consulted.
func Installation(platform string, o Override) (Paths, error) {
	for _, path := range []string{o.RootDir, o.ControlSocket, o.PinentrySocket} {
		if path != "" && !validPath(path) {
			return Paths{}, errors.New("paths: installation overrides must be clean absolute paths")
		}
	}
	if o.SkipTrust && (o.RootDir == "" || o.RootDir == "/") {
		return Paths{}, errors.New("paths: skipping trust requires an isolated root")
	}
	p, err := systemPaths(platform)
	if err != nil {
		return Paths{}, err
	}
	if o.RootDir != "" {
		for _, path := range []*string{&p.ControlSocket, &p.PinentrySocket, &p.Profiles, &p.State, &p.Logs, &p.BinaryDir, &p.CLILink, &p.ServiceFile, &p.ResolverDir, &p.VPNDir} {
			if *path != "" {
				*path = underRoot(o.RootDir, *path)
			}
		}
		for i := range p.OpenFortiVPN {
			p.OpenFortiVPN[i] = underRoot(o.RootDir, p.OpenFortiVPN[i])
		}
	}
	if o.ControlSocket != "" {
		p.ControlSocket = o.ControlSocket
	}
	if o.PinentrySocket != "" {
		p.PinentrySocket = o.PinentrySocket
	}
	p.Pinentry = filepath.Join(p.BinaryDir, "fortix-pinentry")
	p.SkipTrust = o.SkipTrust
	return p, nil
}

// BundledBinaries holds source executables in an application's Resources/libexec.
// These paths are inputs for copying only, never runtime or service locations.
type BundledBinaries struct {
	Helper   string
	CLI      string
	Pinentry string
}

// AppBundleBinaries derives the three bundled sources from an absolute helper path.
// It performs no I/O and rejects controls, noncanonical paths and layouts other than
// an .app directory containing Contents/Resources/libexec/fortix-helper. The caller
// must validate and copy each source into trusted installation locations.
func AppBundleBinaries(helper string) (BundledBinaries, error) {
	if !validPath(helper) || filepath.Base(helper) != "fortix-helper" {
		return BundledBinaries{}, errors.New("paths: invalid bundled helper path")
	}
	libexec := filepath.Dir(helper)
	resources := filepath.Dir(libexec)
	contents := filepath.Dir(resources)
	app := filepath.Dir(contents)
	if filepath.Base(libexec) != "libexec" || filepath.Base(resources) != "Resources" ||
		filepath.Base(contents) != "Contents" || !strings.HasSuffix(filepath.Base(app), ".app") {
		return BundledBinaries{}, errors.New("paths: helper must be in an app's Contents/Resources/libexec")
	}
	return BundledBinaries{Helper: helper, CLI: filepath.Join(libexec, "fortix"), Pinentry: filepath.Join(libexec, "fortix-pinentry")}, nil
}

// systemPaths defines machine paths once for both runtime and installation callers.
// It returns an error for platforms without a supported privileged service manager.
func systemPaths(platform string) (Paths, error) {
	p := Paths{BinaryDir: "/usr/local/libexec/fortix", CLILink: "/usr/local/bin/fortix", ResolverDir: "/etc/resolver"}
	switch platform {
	case "darwin":
		p.ControlSocket = "/var/run/fortix/fortix.sock"
		p.PinentrySocket = "/var/run/fortix/private/pinentry.sock"
		p.Profiles = "/Library/Application Support/fortix/profiles"
		p.State = "/Library/Application Support/fortix/state"
		p.Logs = "/Library/Logs/fortix"
		p.VPNDir = "/Library/Application Support/fortix/libexec"
		p.OpenFortiVPN = []string{filepath.Join(p.VPNDir, "openfortivpn")}
		p.ServiceFile = "/Library/LaunchDaemons/com.github.avhn.fortix.helper.plist"
	case "linux":
		p.ControlSocket = "/run/fortix/fortix.sock"
		p.PinentrySocket = "/run/fortix/private/pinentry.sock"
		p.Profiles = "/etc/fortix/profiles"
		p.State = "/var/lib/fortix/state"
		p.Logs = "/var/log/fortix"
		p.OpenFortiVPN = []string{"/usr/bin/openfortivpn", "/usr/sbin/openfortivpn"}
		p.ServiceFile = "/etc/systemd/system/fortix-helper.service"
	default:
		return Paths{}, errors.New("paths: unsupported installation platform")
	}
	return p, nil
}
