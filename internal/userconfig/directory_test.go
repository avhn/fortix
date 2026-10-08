package userconfig

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/avhn/fortix/internal/paths"
)

// TestPrivateDirectory rejects shared-writable and symlink preference directories without following them.
func TestPrivateDirectory(t *testing.T) {
	ctx, p := context.Background(), configPaths(t)
	if err := Save(ctx, p, Defaults()); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(p.Preferences)
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(ctx, p); err == nil {
		t.Fatal("accepted shared-writable directory")
	}
	if err := Save(ctx, p, Defaults()); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "linked-directory")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	linked := paths.Paths{Preferences: filepath.Join(link, "config.json")}
	if _, err := Load(ctx, linked); err == nil {
		t.Fatal("followed directory symlink")
	}
	if err := Save(ctx, linked, Config{}); err == nil {
		t.Fatal("wrote through directory symlink")
	}
	if got, err := Load(ctx, p); err != nil || got != Defaults() {
		t.Fatalf("external config changed: %+v %v", got, err)
	}
}
