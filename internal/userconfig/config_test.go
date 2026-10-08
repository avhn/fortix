package userconfig

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/avhn/fortix/internal/paths"
)

// TestDecode checks defaults, explicit false, strict fields, and malformed JSON.
func TestDecode(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		want        Config
		invalid     bool
	}{
		{"defaults", `{}`, Defaults(), false},
		{"partial", `{"animate_icon":false}`, Config{true, false, true}, false},
		{"all false", `{"remember_passwords":false,"animate_icon":false,"notifications":false}`, Config{}, false},
		{"unknown", `{"password":"test-password"}`, Config{}, true},
		{"duplicate", `{"animate_icon":true,"animate_icon":false}`, Config{}, true},
		{"escaped duplicate", `{"animate_icon":true,"animate_icon":false}`, Config{}, true},
		{"null field", `{"notifications":null}`, Config{}, true},
		{"null", `null`, Config{}, true},
		{"array", `[]`, Config{}, true},
		{"string", `{"notifications":"true"}`, Config{}, true},
		{"nested", `{"notifications":{}}`, Config{}, true},
		{"number", `{"notifications":1}`, Config{}, true},
		{"trailing", `{} {}`, Config{}, true},
		{"truncated", `{"notifications":`, Config{}, true},
		{"large", strings.Repeat(" ", maxBytes+1), Config{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Decode(strings.NewReader(tc.input))
			if (err != nil) != tc.invalid {
				t.Fatalf("error: %v", err)
			}
			if !tc.invalid && got != tc.want {
				t.Fatalf("got %+v want %+v", got, tc.want)
			}
		})
	}
}

// configPaths resolves the production preferences layout under an isolated home and config root.
func configPaths(t *testing.T) paths.Paths {
	t.Helper()
	root := t.TempDir()
	p, err := paths.Resolve(paths.Override{HomeDir: root, ConfigHome: root, HelperPath: filepath.Join(root, "fortix-helper")})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestPersistence verifies default reads, private permissions, replacement, and temporary cleanup.
func TestPersistence(t *testing.T) {
	ctx, p := context.Background(), configPaths(t)
	if got, err := Load(ctx, p); err != nil || got != Defaults() {
		t.Fatalf("missing: %+v %v", got, err)
	}
	for _, want := range []Config{Defaults(), {}, {false, true, false}} {
		if err := Save(ctx, p, want); err != nil {
			t.Fatal(err)
		}
		got, err := Load(ctx, p)
		if err != nil || got != want {
			t.Fatalf("round trip: %+v %v", got, err)
		}
		for path, mode := range map[string]os.FileMode{p.Preferences: 0600, filepath.Dir(p.Preferences): 0700} {
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != mode {
				t.Fatalf("permissions: %v %v", info, err)
			}
		}
		files, err := os.ReadDir(filepath.Dir(p.Preferences))
		if err != nil || len(files) != 1 {
			t.Fatalf("temporary files: %v %v", files, err)
		}
	}
}

// TestUnsafePaths rejects symlinks, directories, bad permissions, and cancelled writes.
func TestUnsafePaths(t *testing.T) {
	ctx, p := context.Background(), configPaths(t)
	if err := Save(ctx, p, Defaults()); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p.Preferences, 0666); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(ctx, p); err == nil {
		t.Fatal("accepted writable preferences")
	}
	if err := Save(ctx, p, Config{}); err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := Save(cancelled, p, Defaults()); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := Load(cancelled, p); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(p.Preferences); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, p.Preferences); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(ctx, p); err == nil {
		t.Fatal("accepted symlink")
	}
	if err := Save(ctx, p, Defaults()); err == nil {
		t.Fatal("replaced symlink")
	}
	if data, err := os.ReadFile(outside); err != nil || string(data) != "unchanged" {
		t.Fatal("changed external file")
	}
	if err := os.Remove(p.Preferences); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(p.Preferences, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(ctx, p); err == nil {
		t.Fatal("accepted directory")
	}
	if err := Save(ctx, p, Defaults()); err == nil {
		t.Fatal("replaced directory")
	}
	if err := Save(ctx, paths.Paths{Preferences: "relative.json"}, Defaults()); err == nil {
		t.Fatal("accepted relative path")
	}
	if _, err := Load(ctx, paths.Paths{Preferences: "relative.json"}); err == nil {
		t.Fatal("accepted relative path")
	}
}

// FuzzDecode verifies strict preferences never panic and accepted values round-trip.
func FuzzDecode(f *testing.F) {
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
			t.Fatalf("round trip: %v", err)
		}
	})
}

// TestReadableModes allows hand-made read-only sharing but still rejects shared write access.
func TestReadableModes(t *testing.T) {
	ctx, p := context.Background(), configPaths(t)
	if err := Save(ctx, p, Defaults()); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		dir, file os.FileMode
		invalid   bool
	}{
		{0755, 0644, false}, {0700, 0600, false}, {0775, 0600, true}, {0700, 0664, true},
	} {
		if err := os.Chmod(filepath.Dir(p.Preferences), tc.dir); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p.Preferences, tc.file); err != nil {
			t.Fatal(err)
		}
		cfg, err := Load(ctx, p)
		if (err != nil) != tc.invalid || (!tc.invalid && cfg != Defaults()) {
			t.Fatalf("modes %o %o: %+v %v", tc.dir, tc.file, cfg, err)
		}
	}
	if err := Save(ctx, p, Defaults()); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]os.FileMode{filepath.Dir(p.Preferences): 0700, p.Preferences: 0600} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != want {
			t.Fatalf("save permissions: %v %v", info, err)
		}
	}
}
