//go:build windows

package userconfig

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/avhn/fortix/internal/paths"
	"github.com/avhn/fortix/internal/winfs"
)

// TestWindowsDecode exercises the verbatim strict decoder's defaults and rejection cases.
func TestWindowsDecode(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  Config
		bad   bool
	}{
		{`{}`, Defaults(), false},
		{`{"animate_icon":false}`, Config{true, false, true}, false},
		{`{"remember_passwords":false,"animate_icon":false,"notifications":false}`, Config{}, false},
		{`{"unknown":true}`, Config{}, true},
		{`{"animate_icon":true,"animate_icon":false}`, Config{}, true},
		{`{"animate_icon":true,"animate_\u0069con":false}`, Config{}, true},
		{`{"notifications":null}`, Config{}, true},
		{`{"notifications":"true"}`, Config{}, true},
		{`{"notifications":1}`, Config{}, true},
		{`{"notifications":{}}`, Config{}, true},
		{`null`, Config{}, true}, {`[]`, Config{}, true},
		{`{} {}`, Config{}, true}, {`{"notifications":`, Config{}, true},
		{strings.Repeat(" ", maxBytes+1), Config{}, true},
		{`{}` + strings.Repeat(" ", maxBytes-2), Defaults(), false},
	} {
		got, err := Decode(strings.NewReader(tc.input))
		if (err != nil) != tc.bad || got != tc.want {
			t.Fatalf("decode %q: %+v %v", tc.input, got, err)
		}
	}
	if _, err := Decode(failingReader{}); err == nil {
		t.Fatal("ignored reader failure")
	}
}

// failingReader verifies I/O failures do not yield a partially decoded configuration.
type failingReader struct{}

// Read returns a deterministic input failure without any preference bytes.
func (failingReader) Read([]byte) (int, error) { return 0, errors.New("test read failure") }

// windowsConfigPaths isolates preferences under a missing protected product directory.
func windowsConfigPaths(t *testing.T) paths.Paths {
	t.Helper()
	p, err := paths.Resolve(paths.Override{ConfigHome: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestWindowsPersistence checks defaults, explicit false, protected ACLs and stage cleanup.
func TestWindowsPersistence(t *testing.T) {
	ctx, p := context.Background(), windowsConfigPaths(t)
	if got, err := Load(ctx, p); err != nil || got != Defaults() {
		t.Fatalf("missing preferences: %+v %v", got, err)
	}
	policy, err := winfs.UserPolicy()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []Config{Defaults(), {}, {false, true, false}} {
		if err := Save(ctx, p, want); err != nil {
			t.Fatal(err)
		}
		got, err := Load(ctx, p)
		if err != nil || got != want {
			t.Fatalf("round trip: %+v %v", got, err)
		}
		root, err := winfs.OpenRoot(filepath.Dir(p.Preferences))
		if err != nil {
			t.Fatal(err)
		}
		if err := winfs.CheckSecurity(root.Handle(), policy, true); err != nil {
			t.Fatal(err)
		}
		f, err := root.Open(filepath.Base(p.Preferences), policy)
		if err != nil {
			t.Fatal(err)
		}
		if err := winfs.CheckSecurity(windows.Handle(f.Fd()), policy, false); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		if err := root.Close(); err != nil {
			t.Fatal(err)
		}
		files, err := os.ReadDir(filepath.Dir(p.Preferences))
		if err != nil || len(files) != 1 {
			t.Fatalf("temporary files remain: %v %v", files, err)
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := Save(cancelled, p, Defaults()); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := Load(cancelled, p); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if got, err := Load(ctx, p); err != nil || got != (Config{false, true, false}) {
		t.Fatal("cancelled write changed preferences")
	}
}

// TestWindowsSaveWithOpenReader keeps Load's verified file handle open across a separate Save.
// The reader must retain its snapshot while subsequent loads see the replacement preferences.
func TestWindowsSaveWithOpenReader(t *testing.T) {
	ctx, p := context.Background(), windowsConfigPaths(t)
	original, replacement := Defaults(), Config{false, true, false}
	if err := Save(ctx, p, original); err != nil {
		t.Fatal(err)
	}
	policy, err := winfs.UserPolicy()
	if err != nil {
		t.Fatal(err)
	}
	root, err := winfs.OpenRoot(filepath.Dir(p.Preferences))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err := winfs.CheckSecurity(root.Handle(), policy, true); err != nil {
		t.Fatal(err)
	}
	reader, err := root.Open(filepath.Base(p.Preferences), policy)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	if err := Save(ctx, p, replacement); err != nil {
		t.Fatal(err)
	}
	if got, err := Decode(reader); err != nil || got != original {
		t.Fatalf("open reader: %+v %v, want %+v", got, err, original)
	}
	if got, err := Load(ctx, p); err != nil || got != replacement {
		t.Fatalf("replacement preferences: %+v %v, want %+v", got, err, replacement)
	}
}

// TestWindowsUnsafePreferences refuses hard links, foreign directories and path aliases.
func TestWindowsUnsafePreferences(t *testing.T) {
	ctx, p := context.Background(), windowsConfigPaths(t)
	if err := Save(ctx, p, Defaults()); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(filepath.Dir(p.Preferences), "alias")
	if err := os.Link(p.Preferences, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(ctx, p); err == nil {
		t.Fatal("loaded hard-linked preferences")
	}
	if err := Save(ctx, p, Config{}); err == nil {
		t.Fatal("replaced hard-linked preferences")
	}
	foreign := paths.Paths{Preferences: filepath.Join(t.TempDir(), "config.json")}
	if err := os.WriteFile(foreign.Preferences, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(ctx, foreign); err == nil {
		t.Fatal("accepted inherited directory security")
	}
	if err := Save(ctx, foreign, Defaults()); err == nil {
		t.Fatal("adopted inherited directory")
	}
	for _, bad := range []string{`relative`, `\\server\share\config.json`, `\\?\C:\config.json`, `C:\config.json:stream`, `C:\a\..\config.json`} {
		p := paths.Paths{Preferences: bad}
		if _, err := Load(ctx, p); err == nil {
			t.Fatalf("loaded unsafe path %q", bad)
		}
		if err := Save(ctx, p, Defaults()); err == nil {
			t.Fatalf("saved unsafe path %q", bad)
		}
	}
}

// FuzzWindowsDecode ensures accepted preference objects retain exact boolean values.
func FuzzWindowsDecode(f *testing.F) {
	for _, input := range []string{`{}`, `{"notifications":false}`, `null`, `{"animate_icon":true,"animate_icon":false}`} {
		f.Add(input)
	}
	f.Fuzz(func(t *testing.T, input string) {
		cfg, err := Decode(strings.NewReader(input))
		if err != nil {
			return
		}
		data, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Decode(strings.NewReader(string(data)))
		if err != nil || got != cfg {
			t.Fatalf("round trip: %+v %v", got, err)
		}
	})
}
