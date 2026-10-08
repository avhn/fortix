//go:build darwin

package helper

import (
	"debug/macho"
	"encoding/binary"
	"testing"
)

// TestDarwinSystemTrust checks real root-owned runtime ancestors and system Mach-O
// imports, including dyld shared-cache libraries, without writing to system paths.
func TestDarwinSystemTrust(t *testing.T) {
	if err := trustedAncestor("/private/var/run"); err != nil {
		t.Fatalf("system runtime parent rejected: %v", err)
	}
	if err := trustedLibraries("/bin/ls"); err != nil {
		t.Fatalf("system imports rejected: %v", err)
	}
	for _, lib := range []string{
		"/missing-fortix-library.dylib",
		"/usr/lib/../missing-fortix-library.dylib",
		"@loader_path/missing-fortix-library.dylib",
		"@executable_path/missing-fortix-library.dylib",
		"@rpath/missing-fortix-library.dylib",
	} {
		if trustedLibrary(lib, "/usr/lib/program") == nil {
			t.Errorf("unresolved non-cache import accepted: %s", lib)
		}
	}
}

// TestMachOLibraryPaths exercises synthetic load commands without executing files or
// writing system paths. Search directories must be root-owned, non-writable directories;
// a missing candidate may be skipped, but an unsafe search path always fails closed.
func TestMachOLibraryPaths(t *testing.T) {
	for _, tc := range []struct {
		name, library string
		rpaths        []string
		valid         bool
	}{
		{"system shared cache", "/usr/lib/libSystem.B.dylib", nil, true},
		{"loader relative", "@loader_path/ls", nil, true},
		{"executable relative", "@executable_path/ls", nil, true},
		{"trusted search", "@rpath/ls", []string{"/bin"}, true},
		{"skip missing candidate", "@rpath/ls", []string{"/usr/lib", "/bin"}, true},
		{"absent search", "@rpath/ls", nil, false},
		{"missing candidate", "@rpath/missing-fortix-library", []string{"/bin"}, false},
		{"sticky search", "@rpath/ls", []string{"/tmp", "/bin"}, false},
		{"file as search directory", "@rpath/ls", []string{"/bin/ls"}, false},
		{"relative search directory", "@rpath/ls", []string{"relative"}, false},
		{"relative import", "relative.dylib", nil, false},
		{"missing absolute import", "/missing-fortix-library.dylib", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &macho.File{Loads: []macho.Load{&macho.Dylib{Name: tc.library}}}
			for _, path := range tc.rpaths {
				f.Loads = append(f.Loads, &macho.Rpath{Path: path})
			}
			if err := checkMachO(f, "/bin/ls"); (err == nil) != tc.valid {
				t.Fatalf("library trust result: %v", err)
			}
		})
	}
}

// dylibFixture encodes a complete dylib command with its name offset and terminator.
// It creates bytes only; no fixture library is executed or installed on the host.
func dylibFixture(command uint32, name string) macho.LoadBytes {
	data := make([]byte, 24+len(name)+1)
	binary.LittleEndian.PutUint32(data[:4], command)
	binary.LittleEndian.PutUint32(data[4:8], uint32(len(data)))
	binary.LittleEndian.PutUint32(data[8:12], 24)
	copy(data[24:], name)
	return macho.LoadBytes(data)
}

// TestDylibLoadVariants proves weak, reexport, upward and lazy imports receive the
// same trust checks as ordinary imports, including failure for unresolved libraries.
func TestDylibLoadVariants(t *testing.T) {
	for _, command := range []uint32{0xc, 0x80000018, 0x8000001f, 0x80000023, 0x20} {
		for _, name := range []string{"/usr/lib/libSystem.B.dylib", "/missing-fortix-library.dylib", "@rpath/missing-fortix-library.dylib"} {
			f := &macho.File{ByteOrder: binary.LittleEndian, Loads: []macho.Load{dylibFixture(command, name)}}
			err := checkMachO(f, "/bin/ls")
			if (err == nil) != (name == "/usr/lib/libSystem.B.dylib") {
				t.Fatalf("load %x %s: %v", command, name, err)
			}
		}
	}
	for _, offset := range []uint32{0, 23, 9999} {
		load := dylibFixture(0x80000018, "/usr/lib/libSystem.B.dylib")
		binary.LittleEndian.PutUint32(load[8:12], offset)
		if _, _, err := dylibName(load, binary.LittleEndian); err == nil {
			t.Fatalf("invalid name offset %d accepted", offset)
		}
	}
}

// TestRecursiveMachOInspection confirms accepted non-system dependencies are actually
// opened and checked, cycles reuse the visited set, and executable-relative tokens
// retain the original program's location instead of the current library's location.
func TestRecursiveMachOInspection(t *testing.T) {
	visited := make(map[string]bool)
	f := &macho.File{ByteOrder: binary.LittleEndian, Loads: []macho.Load{dylibFixture(0x8000001f, "/bin/ls")}}
	if err := walkMachO(f, "/usr/local/libexec/program", "/usr/local/libexec/program", visited); err != nil {
		t.Fatal(err)
	}
	if !visited["/bin/ls"] {
		t.Fatal("non-system dependency was not recursively inspected")
	}
	if err := walkMachO(f, "/usr/local/libexec/program", "/usr/local/libexec/program", visited); err != nil || len(visited) != 1 {
		t.Fatalf("visited dependency was inspected again: %v", err)
	}
	if got := expandMachOPath("@executable_path/libcrypto.dylib", "/usr/local/libexec/libraries/libssl.dylib", "/usr/local/libexec/program"); got != "/usr/local/libexec/libcrypto.dylib" {
		t.Fatalf("wrong executable-relative path: %s", got)
	}
}

// FuzzDylibName exercises arbitrary raw Mach-O dependency commands and bounds-checks
// name parsing. Successful names must be nonempty and round trip through a valid load.
func FuzzDylibName(f *testing.F) {
	f.Add([]byte(dylibFixture(0xc, "/usr/lib/libSystem.B.dylib")))
	f.Add([]byte(dylibFixture(0x80000018, "@rpath/libssl.dylib")))
	f.Add([]byte{0xc, 0, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		name, present, err := dylibName(macho.LoadBytes(data), binary.LittleEndian)
		if err != nil || !present {
			return
		}
		if name == "" {
			t.Fatal("empty dependency name")
		}
		again, ok, err := dylibName(dylibFixture(0xc, name), binary.LittleEndian)
		if err != nil || !ok || again != name {
			t.Fatal("dependency name changed")
		}
	})
}
