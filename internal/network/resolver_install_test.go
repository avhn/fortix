package network

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// TestInstallResolverRename verifies publication by no-replace rename: the final file
// holds the bytes, no staging name remains, and an existing entry is never replaced.
func TestInstallResolverRename(t *testing.T) {
	root := t.TempDir()
	dir, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dir.Close() }()
	if err := installResolver(dir, "example.com", ".stage-one", []byte("nameserver 192.0.2.1\n")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, "example.com"))
	if err != nil || string(data) != "nameserver 192.0.2.1\n" {
		t.Fatalf("published resolver: %q %v", data, err)
	}
	if info, err := os.Stat(filepath.Join(root, "example.com")); err != nil || info.Mode().Perm() != 0644 {
		t.Fatalf("published resolver mode: %v %v", info, err)
	}
	if _, err := os.Stat(filepath.Join(root, ".stage-one")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staging file remained: %v", err)
	}
	err = installResolver(dir, "example.com", ".stage-two", []byte("nameserver 198.51.100.1\n"))
	if !errors.Is(err, unix.EEXIST) {
		t.Fatalf("existing resolver must not be replaced: %v", err)
	}
	data, _ = os.ReadFile(filepath.Join(root, "example.com"))
	if string(data) != "nameserver 192.0.2.1\n" {
		t.Fatalf("existing resolver changed: %q", data)
	}
	if _, err := os.Stat(filepath.Join(root, ".stage-two")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed staging file remained: %v", err)
	}
}
