package install

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// machoFixture encodes a minimal little-endian 64-bit image with dylib and rpath
// commands. It is inert data, never a program executed by an installation test.
func machoFixture(libraries, rpaths []string) []byte {
	var commands []byte
	for _, item := range []struct {
		names   []string
		command uint32
		offset  int
	}{{libraries, 0xc, 24}, {rpaths, 0x8000001c, 12}} {
		for _, name := range item.names {
			size := (item.offset + len(name) + 1 + 7) &^ 7
			command := make([]byte, size)
			binary.LittleEndian.PutUint32(command, item.command)
			binary.LittleEndian.PutUint32(command[4:], uint32(size))
			binary.LittleEndian.PutUint32(command[8:], uint32(item.offset))
			copy(command[item.offset:], name)
			commands = append(commands, command...)
		}
	}
	header := make([]byte, 32, 32+len(commands))
	for offset, value := range map[int]uint32{0: 0xfeedfacf, 4: 0x01000007, 8: 3, 12: 2, 16: uint32(len(libraries) + len(rpaths)), 20: uint32(len(commands))} {
		binary.LittleEndian.PutUint32(header[offset:], value)
	}
	return append(header, commands...)
}

// TestMachOResolution covers dyld placeholders, missing imports, malformed images,
// system-library boundaries, and no-follow source file handling.
func TestMachOResolution(t *testing.T) {
	base := t.TempDir()
	library := filepath.Join(base, "libcrypto.dylib")
	if err := os.WriteFile(library, machoFixture(nil, nil), 0600); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(base, "openfortivpn")
	for _, test := range []struct {
		name   string
		rpaths []string
		want   string
		fail   bool
	}{
		{library, nil, library, false}, {"@loader_path/libcrypto.dylib", nil, library, false},
		{"@executable_path/libcrypto.dylib", nil, library, false}, {"@rpath/libcrypto.dylib", []string{base}, library, false},
		{"/usr/lib/libSystem.B.dylib", nil, "/usr/lib/libSystem.B.dylib", false},
		{"@rpath/missing.dylib", []string{base}, "", true}, {"relative.dylib", nil, "", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := resolveLibrary(test.name, executable, executable, test.rpaths)
			if (err != nil) != test.fail || got != test.want {
				t.Fatalf("resolve: %q %v", got, err)
			}
		})
	}
	for _, path := range []string{"/usr/library/libevil.dylib", "/Systematic/libevil.dylib", "/opt/libevil.dylib"} {
		if systemLibrary(path) {
			t.Fatalf("trusted %s", path)
		}
	}
	if _, err := readImage(bytes.NewReader([]byte("not Mach-O"))); err == nil {
		t.Fatal("accepted invalid binary")
	}
	link := filepath.Join(base, "symlink.dylib")
	if err := os.Symlink(library, link); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectMachO(link); err == nil {
		t.Fatal("followed source symlink")
	}
	if _, err := openSource(base); err == nil {
		t.Fatal("accepted directory source")
	}
}

// TestBundle recursively packages dylibs, asserts exact rewrite and signing argument
// boundaries, and verifies failed signing leaves a previous bundle unchanged.
func TestBundle(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "signing failure"}[fail], func(t *testing.T) {
			o, runner := testOptions(t, "darwin")
			base := filepath.Dir(o.Helper)
			executable := filepath.Join(base, "openfortivpn")
			crypto := filepath.Join(base, "libcrypto.dylib")
			ssl := filepath.Join(base, "libssl.dylib")
			for path, data := range map[string][]byte{
				executable: machoFixture([]string{"@rpath/libssl.dylib", "/usr/lib/libSystem.B.dylib"}, []string{"@executable_path"}),
				ssl:        machoFixture([]string{"@loader_path/libcrypto.dylib"}, nil), crypto: machoFixture(nil, nil),
			} {
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			o.OpenFortiVPN = executable
			p := resolvedPaths(t, o)
			if err := os.MkdirAll(p.VPNDir, 0755); err != nil {
				t.Fatal(err)
			}
			previous := filepath.Join(p.VPNDir, "previous")
			if err := os.WriteFile(previous, []byte("retain"), 0600); err != nil {
				t.Fatal(err)
			}
			if fail {
				runner.fail = "codesign --force"
				if err := os.MkdirAll(p.BinaryDir, 0755); err != nil {
					t.Fatal(err)
				}
				for _, name := range []string{"fortix-helper", "fortix-pinentry", "fortix"} {
					if err := os.WriteFile(filepath.Join(p.BinaryDir, name), []byte("old executable"), 0755); err != nil {
						t.Fatal(err)
					}
				}
			}
			err := Install(context.Background(), o)
			if fail {
				if err == nil || !strings.Contains(err.Error(), "injected diagnostic") {
					t.Fatalf("signing failure: %v", err)
				}
				for _, name := range []string{"fortix-helper", "fortix-pinentry", "fortix"} {
					content, err := os.ReadFile(filepath.Join(p.BinaryDir, name))
					if err != nil || string(content) != "old executable" {
						t.Fatalf("replaced %s despite bundle failure: %q %v", name, content, err)
					}
				}
				content, err := os.ReadFile(previous)
				if err != nil || string(content) != "retain" {
					t.Fatal("previous bundle was changed")
				}
				if _, err := os.Stat(p.ServiceFile); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("service installed after failed bundle")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"openfortivpn", "libssl.dylib", "libcrypto.dylib"} {
				info, err := os.Stat(filepath.Join(p.VPNDir, name))
				if err != nil || info.Mode().Perm() != 0755 {
					t.Fatalf("bundled %s: %v %v", name, info, err)
				}
			}
			if _, err := os.Stat(previous); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("old bundle retained")
			}
			var rewrites, signatures, verifies int
			for _, call := range runner.calls {
				if call[0] == "/usr/bin/install_name_tool" && call[1] == "-change" {
					rewrites++
					if call[3] != "@loader_path/libssl.dylib" && call[3] != "@loader_path/libcrypto.dylib" {
						t.Fatalf("unsafe rewrite: %v", call)
					}
				}
				if call[0] == "/usr/bin/codesign" && call[1] == "--force" {
					signatures++
					if len(call) != 5 || call[2] != "-s" || call[3] != "-" {
						t.Fatalf("sign command: %v", call)
					}
				}
				if call[0] == "/usr/bin/codesign" && call[1] == "--verify" {
					verifies++
				}
			}
			if rewrites != 2 || signatures != 3 || verifies != 3 {
				t.Fatalf("commands: rewrite=%d sign=%d verify=%d", rewrites, signatures, verifies)
			}
			entries, err := os.ReadDir(filepath.Dir(p.VPNDir))
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), ".fortix-install-") {
					t.Fatal("staging directory leaked")
				}
			}
		})
	}
}

// TestBundleRejectsCollisionsAndMissingDependencies refuses flattened basename
// collisions and unresolved imports without writing service configuration.
func TestBundleRejectsCollisionsAndMissingDependencies(t *testing.T) {
	for _, name := range []string{"collision", "missing", "cycle"} {
		t.Run(name, func(t *testing.T) {
			o, _ := testOptions(t, "darwin")
			base := filepath.Dir(o.Helper)
			a, b := filepath.Join(base, "a", "libsame.dylib"), filepath.Join(base, "b", "libsame.dylib")
			for _, path := range []string{a, b} {
				if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, machoFixture(nil, nil), 0600); err != nil {
					t.Fatal(err)
				}
			}
			o.OpenFortiVPN = filepath.Join(base, "openfortivpn")
			libraries := []string{a, b}
			if name == "missing" {
				libraries = []string{filepath.Join(base, "missing.dylib")}
			}
			if name == "cycle" {
				libraries = []string{a}
				if err := os.WriteFile(a, machoFixture([]string{a}, nil), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(o.OpenFortiVPN, machoFixture(libraries, nil), 0600); err != nil {
				t.Fatal(err)
			}
			err := Install(context.Background(), o)
			if name == "cycle" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil {
				t.Fatal("unsafe bundle accepted")
			}
			if _, err := os.Stat(resolvedPaths(t, o).ServiceFile); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("service written for rejected bundle")
			}
		})
	}
}

// FuzzMachO exercises thin and universal load-command decoding on arbitrary bytes.
// Inputs are bounded to 64 KiB; malformed images may error but must never panic.
func FuzzMachO(f *testing.F) {
	f.Add(machoFixture([]string{"@loader_path/libssl.dylib"}, []string{"@executable_path"}))
	f.Add([]byte("not Mach-O"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65536 {
			t.Skip()
		}
		_, _ = readImage(bytes.NewReader(data))
	})
}

// TestBundleDirectoryAliases deduplicates a dylib imported through both a symlinked
// opt directory and its physical Cellar location. Both imports must be rewritten
// without a false basename collision, while each image is bundled only once.
func TestBundleDirectoryAliases(t *testing.T) {
	o, runner := testOptions(t, "darwin")
	base := filepath.Dir(o.Helper)
	cellar := filepath.Join(base, "Cellar", "openssl", "version", "lib")
	opt := filepath.Join(base, "opt")
	if err := os.MkdirAll(cellar, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Dir(cellar), opt); err != nil {
		t.Fatal(err)
	}
	crypto, ssl := filepath.Join(cellar, "libcrypto.3.dylib"), filepath.Join(cellar, "libssl.3.dylib")
	o.OpenFortiVPN = filepath.Join(base, "openfortivpn")
	for path, data := range map[string][]byte{
		crypto: machoFixture(nil, nil), ssl: machoFixture([]string{crypto}, nil),
		o.OpenFortiVPN: machoFixture([]string{filepath.Join(opt, "lib", "libcrypto.3.dylib"), filepath.Join(opt, "lib", "libssl.3.dylib")}, nil),
	} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := Install(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(resolvedPaths(t, o).VPNDir)
	if err != nil || len(entries) != 3 {
		t.Fatalf("bundle images: %v %v", entries, err)
	}
	var rewritten, signed int
	for _, call := range runner.calls {
		if call[0] == "/usr/bin/install_name_tool" && call[1] == "-change" {
			rewritten++
			if call[3] != "@loader_path/libcrypto.3.dylib" && call[3] != "@loader_path/libssl.3.dylib" {
				t.Fatalf("unsafe rewrite: %v", call)
			}
		}
		if call[0] == "/usr/bin/codesign" && call[1] == "--force" {
			signed++
		}
	}
	if rewritten != 3 || signed != 3 {
		t.Fatalf("duplicate processing: rewrites=%d signatures=%d", rewritten, signed)
	}
}
