//go:build windows

package paths

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// TestWindowsDefaults compares machine and user paths with the shell's folder mapping.
func TestWindowsDefaults(t *testing.T) {
	p, err := Resolve(Override{})
	if err != nil {
		t.Fatal(err)
	}
	files, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, windows.KF_FLAG_DONT_VERIFY)
	if err != nil {
		t.Fatal(err)
	}
	data, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DONT_VERIFY)
	if err != nil {
		t.Fatal(err)
	}
	local, err := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, windows.KF_FLAG_DONT_VERIFY)
	if err != nil {
		t.Fatal(err)
	}
	want := Paths{ControlSocket: `\\.\pipe\Fortix.Control.v1`, BinaryDir: filepath.Join(files, "Fortix"),
		CLILink: filepath.Join(files, "Fortix", "fortix.exe"), Profiles: filepath.Join(data, "Fortix", "profiles"),
		State: filepath.Join(data, "Fortix", "state"), Logs: filepath.Join(data, "Fortix", "logs"),
		Preferences: filepath.Join(local, "Fortix", "config.json")}
	if !reflect.DeepEqual(p, want) {
		t.Fatalf("paths = %+v, want %+v", p, want)
	}
	service, err := Resolve(Override{Service: true})
	if err != nil || service.Preferences != "" || service.TrayAutostart != "" {
		t.Fatalf("service consulted user locations: %+v %v", service, err)
	}
	installed, err := Installation("windows", Override{})
	if err != nil || !reflect.DeepEqual(service, installed) {
		t.Fatalf("runtime/install divergence: %+v %v", installed, err)
	}
}

// TestWindowsOverrides relocates only files and preserves the default pipe namespace.
func TestWindowsOverrides(t *testing.T) {
	root := t.TempDir()
	p, err := Resolve(Override{RootDir: root, ConfigHome: `C:\prefs`, SkipTrust: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{p.BinaryDir, p.CLILink, p.Profiles, p.State, p.Logs, p.Preferences} {
		if !strings.HasPrefix(path, root+`\`) {
			t.Fatalf("escaped root: %q", path)
		}
	}
	if p.ControlSocket != `\\.\pipe\Fortix.Control.v1` || !p.SkipTrust || p.Pinentry != "" || len(p.OpenFortiVPN) != 0 {
		t.Fatalf("unsupported paths or pipe relocation: %+v", p)
	}
	p, err = Resolve(Override{HomeDir: `C:\home`})
	if err != nil || p.Preferences != `C:\home\AppData\Local\Fortix\config.json` {
		t.Fatalf("home override: %+v %v", p, err)
	}
	p, err = Resolve(Override{ControlSocket: `C:\test\control`, PinentrySocket: `C:\test\relay`, ConfigHome: `C:\config`})
	if err != nil || p.ControlSocket != `C:\test\control` || p.PinentrySocket != `C:\test\relay` || p.Preferences != `C:\config\Fortix\config.json` {
		t.Fatalf("explicit override: %+v %v", p, err)
	}
}

// TestWindowsInvalidPaths exercises each override against device, stream and alias inputs.
func TestWindowsInvalidPaths(t *testing.T) {
	for _, bad := range []string{`relative`, `C:relative`, `\rooted`, `\\server\share`, `\\?\C:\file`, `\\.\pipe\custom`,
		`C:\a:stream`, `C:\a\..\b`, `C:\a\.\b`, `C:\a\`, `C:/a`, "C:\\a\n", `C:\NUL.json`, `C:\COM¹`, `C:\name.`, "C:\\invalid\xff"} {
		for _, o := range []Override{{RootDir: bad}, {ControlSocket: bad}, {PinentrySocket: bad}, {HelperPath: bad}, {HomeDir: bad}, {ConfigHome: bad}} {
			if got, err := Resolve(o); err == nil || !reflect.DeepEqual(got, Paths{}) {
				t.Fatalf("accepted %+v: %+v %v", o, got, err)
			}
			if _, err := Installation("windows", o); err == nil {
				t.Fatalf("installer accepted %+v", o)
			}
		}
	}
	for _, o := range []Override{{SkipTrust: true}, {RootDir: `C:\`, SkipTrust: true}} {
		if _, err := Resolve(o); err == nil {
			t.Fatalf("unsafe trust override: %+v", o)
		}
	}
	if _, err := Installation("linux", Override{}); err == nil {
		t.Fatal("accepted unsupported installation platform")
	}
	if got, err := AppBundleBinaries(`C:\Fortix\fortix-helper.exe`); err == nil || got != (BundledBinaries{}) {
		t.Fatal("accepted app bundle")
	}
}
