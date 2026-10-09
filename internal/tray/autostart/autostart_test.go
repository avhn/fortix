//go:build darwin || linux

// Package autostart tests registration rendering and isolated user filesystem writes.
package autostart

import (
	"context"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/avhn/fortix/internal/paths"
)

// TestRender validates XML arguments and desktop escaping, including reserved Exec bytes.
func TestRender(t *testing.T) {
	executable := "/Applications/fortix & tools/fortix-tray"
	data, err := Render("darwin", executable)
	if err != nil {
		t.Fatal(err)
	}
	decoder := xml.NewDecoder(strings.NewReader(string(data)))
	var values []string
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if element, ok := token.(xml.StartElement); ok && element.Name.Local == "string" {
			var value string
			if err := decoder.DecodeElement(&value, &element); err != nil {
				t.Fatal(err)
			}
			values = append(values, value)
		}
	}
	if len(values) != 2 || values[0] != "com.github.avhn.fortix.tray" || values[1] != executable || !strings.Contains(string(data), "<key>RunAtLoad</key><true/>") {
		t.Fatal(string(data))
	}
	for _, tc := range []struct{ executable, exec string }{
		{"/opt/fortix tray/fortix-tray", `Exec="/opt/fortix tray/fortix-tray"`},
		{"/opt/percent%/fortix-tray", `Exec="/opt/percent%%/fortix-tray"`},
		{"/opt/quote\"/fortix-tray", `Exec="/opt/quote\\"/fortix-tray"`},
		{"/opt/$`/fortix-tray", `Exec="/opt/\\$\\` + "`" + `/fortix-tray"`},
		{"/opt/back\\slash/fortix-tray", `Exec="/opt/back\\\\slash/fortix-tray"`},
	} {
		data, err := Render("linux", tc.executable)
		if err != nil || !strings.Contains(string(data), tc.exec+"\n") {
			t.Fatalf("desktop %q: %q, %v", tc.executable, data, err)
		}
	}
	for _, platform := range []string{"darwin", "linux", "other"} {
		for _, path := range []string{"", "relative", "/opt/../fortix-tray", "/opt/fortix\ntray", "/opt/fortix\x00tray", "/opt/fortix\xfftray"} {
			if _, err := Render(platform, path); err == nil {
				t.Fatalf("accepted %q/%q", platform, path)
			}
		}
	}
	if _, err := Render("other", "/opt/fortix-tray"); err == nil {
		t.Fatal("unsupported platform accepted")
	}
}

// TestEnableDisable checks atomic creation, replacement, removal, and path overrides.
func TestEnableDisable(t *testing.T) {
	for _, platform := range []string{"darwin", "linux"} {
		name := "fortix-tray.desktop"
		if platform == "darwin" {
			name = "com.github.avhn.fortix.tray.plist"
		}
		p := paths.Paths{TrayAutostart: filepath.Join(t.TempDir(), "autostart", name)}
		for _, executable := range []string{"/opt/fortix-tray", "/opt/new tray/fortix-tray"} {
			if err := Enable(context.Background(), platform, p, executable); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(p.TrayAutostart)
			if err != nil {
				t.Fatal(err)
			}
			want, err := Render(platform, executable)
			if err != nil || string(got) != string(want) {
				t.Fatal("registration mismatch", err)
			}
			info, err := os.Stat(p.TrayAutostart)
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatal("unsafe file mode", err)
			}
			entries, err := os.ReadDir(filepath.Dir(p.TrayAutostart))
			if err != nil || len(entries) != 1 {
				t.Fatal("temporary file leaked", err)
			}
		}
		for range 2 {
			if err := Disable(context.Background(), platform, p); err != nil {
				t.Fatal(err)
			}
		}
	}
	home := t.TempDir()
	config := filepath.Join(home, "custom-config")
	t.Setenv("XDG_CONFIG_HOME", config)
	p, err := paths.Resolve(paths.Override{HomeDir: home, ConfigHome: config, HelperPath: "/opt/fortix-helper"})
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(home, "Library/LaunchAgents/com.github.avhn.fortix.tray.plist")
	if runtime.GOOS == "linux" {
		want = filepath.Join(config, "autostart/fortix-tray.desktop")
	}
	if p.TrayAutostart != want {
		t.Fatalf("location = %s, want %s", p.TrayAutostart, want)
	}
	rooted, err := paths.Resolve(paths.Override{HomeDir: home, ConfigHome: config, HelperPath: "/opt/fortix-helper", RootDir: "/isolated"})
	if err != nil || rooted.TrayAutostart != filepath.Join("/isolated", want) {
		t.Fatal("root override lost", err)
	}
}

// TestRefuseUnsafeWrites checks foreign files, symlinks, directories, and cancellation.
func TestRefuseUnsafeWrites(t *testing.T) {
	for _, kind := range []string{"foreign", "symlink", "directory", "parent symlink", "parent file"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			p := paths.Paths{TrayAutostart: filepath.Join(root, "autostart", "fortix-tray.desktop")}
			if err := os.Mkdir(filepath.Dir(p.TrayAutostart), 0700); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "foreign":
				if err := os.WriteFile(p.TrayAutostart, []byte("unrelated"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(filepath.Join(root, "missing"), p.TrayAutostart); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(p.TrayAutostart, 0700); err != nil {
					t.Fatal(err)
				}
			case "parent symlink":
				p.TrayAutostart = filepath.Join(root, "link", "fortix-tray.desktop")
				if err := os.Symlink(filepath.Join(root, "autostart"), filepath.Dir(p.TrayAutostart)); err != nil {
					t.Fatal(err)
				}
			case "parent file":
				p.TrayAutostart = filepath.Join(root, "file", "fortix-tray.desktop")
				if err := os.WriteFile(filepath.Dir(p.TrayAutostart), []byte("unrelated"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := Enable(context.Background(), "linux", p, "/opt/fortix-tray"); err == nil {
				t.Fatal("unsafe enable succeeded")
			}
			if err := Disable(context.Background(), "linux", p); err == nil {
				t.Fatal("unsafe disable succeeded")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p := paths.Paths{TrayAutostart: filepath.Join(t.TempDir(), "fortix-tray.desktop")}
	if err := Enable(ctx, "linux", p, "/opt/fortix-tray"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := Disable(ctx, "linux", p); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, path := range []string{"relative", "/opt/wrong.desktop"} {
		p.TrayAutostart = path
		if err := Enable(context.Background(), "linux", p, "/opt/fortix-tray"); err == nil {
			t.Fatal("bad destination accepted")
		}
		if err := Disable(context.Background(), "linux", p); err == nil {
			t.Fatal("bad destination accepted")
		}
	}
}
